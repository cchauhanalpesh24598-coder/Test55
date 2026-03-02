package com.mknotes.app;

import android.app.Activity;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.mknotes.app.cloud.CloudSyncManager;
import com.mknotes.app.cloud.FirebaseAuthManager;
import com.mknotes.app.crypto.CryptoManager;
import com.mknotes.app.crypto.KeyManager;
import com.mknotes.app.crypto.MigrationManager;
import com.mknotes.app.db.NotesRepository;
import com.mknotes.app.util.CryptoUtils;
import com.mknotes.app.util.PrefsManager;
import com.mknotes.app.util.SessionManager;

/**
 * Gatekeeper activity: master password CREATE or UNLOCK.
 *
 * Flow:
 * 1. If vault initialized + unlocked + session valid -> skip to main
 * 2. If vault initialized locally -> UNLOCK mode
 * 3. If logged in -> fetch vault from Firestore
 *    a. Vault found -> cache locally, UNLOCK mode
 *    b. No vault + no notes -> CREATE mode (fresh user)
 *    c. No vault + notes exist -> LEGACY RECOVERY mode
 * 4. If not logged in -> CREATE mode (offline use)
 *
 * REINSTALL PROOF: Vault metadata stored in Firestore at
 * users/{uid}/crypto_metadata/vault. On reinstall, fetched and cached locally.
 */
public class MasterPasswordActivity extends Activity {

    private static final String TAG = "MasterPasswordActivity";
    private static final int MODE_CREATE = 0;
    private static final int MODE_UNLOCK = 1;
    private static final int MODE_LEGACY_RECOVERY = 2;

    private int currentMode;
    private SessionManager sessionManager;
    private KeyManager keyManager;

    private TextView toolbarTitle;
    private TextView textSubtitle;
    private EditText editPassword;
    private EditText editConfirmPassword;
    private TextView textError;
    private TextView textStrengthHint;
    private Button btnAction;
    private CheckBox cbShowPassword;

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        sessionManager = SessionManager.getInstance(this);
        keyManager = KeyManager.getInstance(this);

        // If vault is initialized, unlocked, and session valid -> skip
        if (keyManager.isVaultInitialized() && keyManager.isVaultUnlocked()
                && sessionManager.isSessionValid()) {
            sessionManager.updateSessionTimestamp();
            launchMain();
            return;
        }

        // Also check old system for backward compat
        if (!keyManager.isVaultInitialized() && sessionManager.isPasswordSet()
                && sessionManager.hasKey() && sessionManager.isSessionValid()) {
            sessionManager.updateSessionTimestamp();
            launchMain();
            return;
        }

        setContentView(R.layout.activity_master_password);
        setupStatusBar();
        initViews();

        // Check if coming from FirebaseLoginActivity with legacy recovery flag
        boolean isLegacyRecovery = getIntent().getBooleanExtra("legacy_recovery", false);

        if (isLegacyRecovery) {
            Log.d(TAG, "[LEGACY_RECOVERY] Intent flag detected");
            setupLegacyRecoveryMode();
        } else if (keyManager.isVaultInitialized()) {
            // Vault exists locally (either from previous use or fetched from Firestore)
            setupUnlockMode();
        } else if (sessionManager.isPasswordSet()) {
            // Old system password exists -- needs migration
            setupUnlockMode();
        } else {
            // Check Firestore for vault (reinstall scenario)
            checkFirestoreVault();
        }
    }

    private void setupStatusBar() {
        if (Build.VERSION.SDK_INT >= 21) {
            Window window = getWindow();
            window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
            window.setStatusBarColor(getResources().getColor(R.color.colorPrimaryDark));
        }
    }

    private void initViews() {
        toolbarTitle = (TextView) findViewById(R.id.toolbar_title);
        textSubtitle = (TextView) findViewById(R.id.text_subtitle);
        editPassword = (EditText) findViewById(R.id.edit_password);
        editConfirmPassword = (EditText) findViewById(R.id.edit_confirm_password);
        textError = (TextView) findViewById(R.id.text_error);
        textStrengthHint = (TextView) findViewById(R.id.text_strength_hint);
        btnAction = (Button) findViewById(R.id.btn_action);
        cbShowPassword = (CheckBox) findViewById(R.id.cb_show_password);

        if (cbShowPassword != null) {
            cbShowPassword.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                    if (isChecked) {
                        editPassword.setTransformationMethod(HideReturnsTransformationMethod.getInstance());
                        if (editConfirmPassword.getVisibility() == View.VISIBLE) {
                            editConfirmPassword.setTransformationMethod(HideReturnsTransformationMethod.getInstance());
                        }
                    } else {
                        editPassword.setTransformationMethod(PasswordTransformationMethod.getInstance());
                        if (editConfirmPassword.getVisibility() == View.VISIBLE) {
                            editConfirmPassword.setTransformationMethod(PasswordTransformationMethod.getInstance());
                        }
                    }
                    editPassword.setSelection(editPassword.getText().length());
                    if (editConfirmPassword.getVisibility() == View.VISIBLE) {
                        editConfirmPassword.setSelection(editConfirmPassword.getText().length());
                    }
                }
            });
        }
    }

    // ======================== FIRESTORE VAULT CHECK ========================

    /**
     * Check Firestore for vault metadata (reinstall scenario).
     * FIX v2.2: Uses 3-state callback to distinguish "no vault" from "network error".
     * On NETWORK_ERROR: shows retry message, NEVER allows vault creation.
     * This prevents accidental DEK regeneration on poor/slow network.
     */
    private void checkFirestoreVault() {
        if (keyManager.isVaultInitialized()) {
            setupUnlockMode();
            return;
        }

        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(this);
        if (authManager.isLoggedIn()) {
            btnAction.setEnabled(false);
            textSubtitle.setText("Fetching vault from cloud...");

            keyManager.fetchVaultFromFirestoreWithResult(new KeyManager.VaultFetchResultCallback() {
                public void onResult(final KeyManager.VaultFetchResult result) {
                    runOnUiThread(new Runnable() {
                        public void run() {
                            btnAction.setEnabled(true);
                            switch (result) {
                                case VAULT_FOUND:
                                    Log.d(TAG, "[VAULT_FETCH] Vault found, switching to UNLOCK");
                                    setupUnlockMode();
                                    break;
                                case NO_VAULT_EXISTS:
                                    Log.d(TAG, "[VAULT_FETCH] Server confirms no vault, checking for orphan notes...");
                                    checkCloudNotesBeforeCreate();
                                    break;
                                case NETWORK_ERROR:
                                    Log.w(TAG, "[VAULT_FETCH] NETWORK_ERROR -- blocking vault creation");
                                    setupNetworkErrorMode();
                                    break;
                            }
                        }
                    });
                }
            });
        } else {
            Log.d(TAG, "Not logged in, allowing CREATE mode");
            setupCreateMode();
        }
    }

    /**
     * SAFETY: Check if notes exist before allowing vault creation.
     * FIX v2.2: Uses 3-state callback. NETWORK_ERROR blocks vault creation.
     */
    private void checkCloudNotesBeforeCreate() {
        keyManager.checkCloudNotesExistWithResult(new KeyManager.VaultFetchResultCallback() {
            public void onResult(final KeyManager.VaultFetchResult result) {
                runOnUiThread(new Runnable() {
                    public void run() {
                        switch (result) {
                            case VAULT_FOUND:
                                // VAULT_FOUND here means "notes exist but vault missing"
                                Log.d(TAG, "[LEGACY_DETECTED] Notes exist but vault missing");
                                setupLegacyRecoveryMode();
                                break;
                            case NO_VAULT_EXISTS:
                                // Server confirms: no notes AND no vault -- truly fresh user
                                Log.d(TAG, "[FRESH_USER] No notes, no vault, allowing CREATE");
                                setupCreateMode();
                                break;
                            case NETWORK_ERROR:
                                // Cannot confirm state -- block vault creation
                                Log.w(TAG, "[NOTES_CHECK] NETWORK_ERROR -- blocking vault creation");
                                setupNetworkErrorMode();
                                break;
                        }
                    }
                });
            }
        });
    }

    /**
     * FIX v2.2: Network error mode -- shown when we cannot reach Firestore
     * to confirm whether a vault exists. NEVER allows vault creation.
     * User must connect to internet and retry.
     */
    private void setupNetworkErrorMode() {
        toolbarTitle.setText(R.string.vault_network_error_title);
        textSubtitle.setText(R.string.vault_network_error_subtitle);
        editPassword.setVisibility(View.GONE);
        editConfirmPassword.setVisibility(View.GONE);
        if (textStrengthHint != null) textStrengthHint.setVisibility(View.GONE);
        if (cbShowPassword != null) cbShowPassword.setVisibility(View.GONE);
        textError.setText(R.string.vault_network_error_detail);
        textError.setVisibility(View.VISIBLE);
        btnAction.setText(R.string.vault_network_error_retry);
        btnAction.setEnabled(true);
        btnAction.setVisibility(View.VISIBLE);

        btnAction.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                // Reset UI and retry
                editPassword.setVisibility(View.VISIBLE);
                textError.setVisibility(View.GONE);
                if (cbShowPassword != null) cbShowPassword.setVisibility(View.VISIBLE);
                checkFirestoreVault();
            }
        });
    }

    // ======================== MODE SETUP ========================

    private void setupCreateMode() {
        currentMode = MODE_CREATE;
        toolbarTitle.setText(R.string.master_password_title_create);
        textSubtitle.setText(R.string.master_password_subtitle_create);
        editConfirmPassword.setVisibility(View.VISIBLE);
        textStrengthHint.setVisibility(View.VISIBLE);
        btnAction.setText(R.string.master_password_btn_create);
        textError.setVisibility(View.GONE);
        btnAction.setEnabled(true);

        btnAction.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                handleCreate();
            }
        });
    }

    private void setupUnlockMode() {
        currentMode = MODE_UNLOCK;
        toolbarTitle.setText(R.string.master_password_title_unlock);
        textSubtitle.setText(R.string.master_password_subtitle_unlock);
        editConfirmPassword.setVisibility(View.GONE);
        textStrengthHint.setVisibility(View.GONE);
        btnAction.setText(R.string.master_password_btn_unlock);
        textError.setVisibility(View.GONE);
        btnAction.setEnabled(true);

        btnAction.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                handleUnlock();
            }
        });
    }

    private void setupLegacyRecoveryMode() {
        currentMode = MODE_LEGACY_RECOVERY;
        toolbarTitle.setText(R.string.legacy_recovery_title);
        textSubtitle.setText(R.string.legacy_recovery_subtitle);
        editPassword.setVisibility(View.VISIBLE);
        editPassword.setHint(R.string.legacy_recovery_password_hint);
        editConfirmPassword.setVisibility(View.GONE);
        if (textStrengthHint != null) textStrengthHint.setVisibility(View.GONE);
        if (cbShowPassword != null) cbShowPassword.setVisibility(View.VISIBLE);
        btnAction.setText(R.string.legacy_recovery_btn);
        btnAction.setVisibility(View.VISIBLE);
        btnAction.setEnabled(true);
        textError.setVisibility(View.GONE);

        btnAction.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                handleLegacyRecovery();
            }
        });
    }

    // ======================== HANDLE CREATE ========================

    private void handleCreate() {
        String password = editPassword.getText().toString();
        String confirm = editConfirmPassword.getText().toString();

        if (password.length() < 8) {
            showError(getString(R.string.master_password_error_short));
            return;
        }
        if (!password.equals(confirm)) {
            showError(getString(R.string.master_password_error_mismatch));
            return;
        }

        // SAFETY: If vault already exists, switch to unlock
        if (keyManager.isVaultInitialized()) {
            Log.w(TAG, "[SAFETY] Vault already exists, switching to UNLOCK");
            setupUnlockMode();
            return;
        }

        btnAction.setEnabled(false);
        textSubtitle.setText("Creating vault...");
        textError.setVisibility(View.GONE);

        // Double-check Firestore before creating (prevent race conditions)
        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(this);
        if (authManager.isLoggedIn()) {
            final String pwd = password;
            keyManager.fetchVaultFromFirestoreWithResult(new KeyManager.VaultFetchResultCallback() {
                public void onResult(final KeyManager.VaultFetchResult result) {
                    runOnUiThread(new Runnable() {
                        public void run() {
                            switch (result) {
                                case VAULT_FOUND:
                                    Log.w(TAG, "[SAFETY] Vault appeared in Firestore, switching to UNLOCK");
                                    btnAction.setEnabled(true);
                                    setupUnlockMode();
                                    break;
                                case NO_VAULT_EXISTS:
                                    // Server confirms no vault -- safe to create
                                    performVaultCreation(pwd);
                                    break;
                                case NETWORK_ERROR:
                                    // Cannot confirm -- block creation
                                    Log.w(TAG, "[SAFETY] Network error during pre-create check -- blocking");
                                    btnAction.setEnabled(true);
                                    textSubtitle.setText(R.string.master_password_subtitle_create);
                                    showError(getString(R.string.vault_network_error_detail));
                                    break;
                            }
                        }
                    });
                }
            });
        } else {
            performVaultCreation(password);
        }
    }

    private void performVaultCreation(final String password) {
        Log.d(TAG, "[VAULT_CREATED] Starting vault creation...");

        keyManager.initializeVault(password, new KeyManager.VaultCallback() {
            public void onSuccess() {
                runOnUiThread(new Runnable() {
                    public void run() {
                        Log.d(TAG, "[VAULT_CREATED] SUCCESS");
                        sessionManager.setPasswordSetFlag(true);
                        sessionManager.updateSessionTimestamp();
                        sessionManager.setEncryptionMigrated(true);

                        // Migrate existing plaintext notes if any
                        migrateExistingPlaintextNotes();

                        Toast.makeText(MasterPasswordActivity.this,
                                R.string.master_password_set_success, Toast.LENGTH_SHORT).show();
                        launchMain();
                    }
                });
            }

            public void onError(final String error) {
                runOnUiThread(new Runnable() {
                    public void run() {
                        Log.e(TAG, "[VAULT_CREATED] FAILED: " + error);
                        btnAction.setEnabled(true);
                        textSubtitle.setText(R.string.master_password_subtitle_create);
                        showError(getString(R.string.master_password_error_generic));
                    }
                });
            }
        });
    }

    // ======================== HANDLE UNLOCK ========================

    private void handleUnlock() {
        final String password = editPassword.getText().toString();

        if (password.length() == 0) {
            showError(getString(R.string.master_password_error_empty));
            return;
        }

        btnAction.setEnabled(false);
        textError.setVisibility(View.GONE);
        if (textSubtitle != null) {
            textSubtitle.setText("Unlocking vault...");
        }

        // New v2 vault system
        if (keyManager.isVaultInitialized()) {
            Log.d(TAG, "Attempting unlock with v2 vault system");

            // Run unlock on background thread (PBKDF2 is CPU-intensive)
            new Thread(new Runnable() {
                public void run() {
                    final boolean valid = keyManager.unlockVault(password);
                    runOnUiThread(new Runnable() {
                        public void run() {
                            if (valid) {
                                Log.d(TAG, "[VAULT_UNLOCK_SUCCESS]");

                                // CRITICAL FIX: Set session state SYNCHRONOUSLY before
                                // anything else. updateSessionTimestamp() now uses .commit()
                                // so the timestamp is guaranteed to be persisted before
                                // we launch MainActivity. This eliminates the race condition
                                // where isSessionValid() returned false on first launch.
                                sessionManager.setPasswordSetFlag(true);
                                sessionManager.updateSessionTimestamp();
                                sessionManager.setEncryptionMigrated(true);

                                // Verify DEK is actually in memory before proceeding
                                if (!keyManager.isVaultUnlocked()) {
                                    Log.e(TAG, "[VAULT_UNLOCK] CRITICAL: DEK not in memory after unlock!");
                                    btnAction.setEnabled(true);
                                    showError("Vault unlock verification failed. Please try again.");
                                    return;
                                }

                                Log.d(TAG, "[VAULT_UNLOCK] DEK verified in memory, session set");

                                // Ensure vault is uploaded to Firestore
                                keyManager.ensureVaultUploaded();

                                launchMain();
                            } else {
                                Log.w(TAG, "[VAULT_UNLOCK_FAILED] Wrong password");
                                btnAction.setEnabled(true);
                                if (textSubtitle != null) {
                                    textSubtitle.setText(R.string.master_password_subtitle_unlock);
                                }
                                showError(getString(R.string.master_password_error_wrong));
                                editPassword.setText("");
                            }
                        }
                    });
                }
            }).start();

        } else if (sessionManager.hasOldSystemCredentials()) {
            // Old system: verify + migrate
            Log.d(TAG, "Attempting unlock with old system + migration");
            handleOldSystemUnlock(password);

        } else if (currentMode == MODE_LEGACY_RECOVERY) {
            handleLegacyRecovery();

        } else {
            btnAction.setEnabled(true);
            showError(getString(R.string.master_password_error_generic));
        }
    }

    // ======================== OLD SYSTEM MIGRATION ========================

    private void handleOldSystemUnlock(String password) {
        String saltHex = sessionManager.getOldSaltHex();
        String verifyToken = sessionManager.getOldVerifyToken();

        if (saltHex == null || verifyToken == null) {
            btnAction.setEnabled(true);
            showError(getString(R.string.master_password_error_generic));
            return;
        }

        byte[] oldSalt = CryptoUtils.hexToBytes(saltHex);
        byte[] tempKey = CryptoUtils.deriveKey(password, oldSalt);

        if (tempKey == null) {
            btnAction.setEnabled(true);
            showError(getString(R.string.master_password_error_generic));
            return;
        }

        boolean valid = CryptoUtils.verifyKeyWithToken(tempKey, verifyToken);
        CryptoManager.zeroFill(tempKey);

        if (!valid) {
            btnAction.setEnabled(true);
            showError(getString(R.string.master_password_error_wrong));
            editPassword.setText("");
            return;
        }

        // Old password verified -- migrate to new system
        sessionManager.updateSessionTimestamp();
        int oldIterations = sessionManager.getOldIterations();

        boolean migrated = MigrationManager.migrate(this, password, oldSalt, oldIterations);
        if (migrated) {
            sessionManager.clearOldCredentials();
            sessionManager.setEncryptionMigrated(true);
            // Ensure vault is uploaded after migration
            keyManager.ensureVaultUploaded();
            Toast.makeText(this, R.string.master_password_set_success, Toast.LENGTH_SHORT).show();
            launchMain();
        } else {
            btnAction.setEnabled(true);
            showError("Migration failed. Please try again.");
        }
    }

    // ======================== LEGACY RECOVERY ========================

    private void handleLegacyRecovery() {
        final String password = editPassword.getText().toString();

        if (password.length() == 0) {
            showError(getString(R.string.master_password_error_empty));
            return;
        }

        btnAction.setEnabled(false);
        textError.setVisibility(View.GONE);
        textSubtitle.setText(R.string.legacy_recovery_verifying);

        MigrationManager.verifyLegacyPassword(this, password,
                new MigrationManager.LegacyMigrationCallback() {
                    public void onSuccess() {
                        runOnUiThread(new Runnable() {
                            public void run() {
                                textSubtitle.setText(R.string.legacy_recovery_migrating);
                                performLegacyMigration(password);
                            }
                        });
                    }

                    public void onFailure(final String error) {
                        runOnUiThread(new Runnable() {
                            public void run() {
                                btnAction.setEnabled(true);
                                textSubtitle.setText(R.string.legacy_recovery_subtitle);
                                showError(getString(R.string.legacy_recovery_wrong_password));
                                editPassword.setText("");
                            }
                        });
                    }
                });
    }

    private void performLegacyMigration(final String password) {
        MigrationManager.migrateLegacyCloudNotes(this, password,
                new MigrationManager.LegacyMigrationCallback() {
                    public void onSuccess() {
                        runOnUiThread(new Runnable() {
                            public void run() {
                                sessionManager.setPasswordSetFlag(true);
                                sessionManager.updateSessionTimestamp();
                                sessionManager.setEncryptionMigrated(true);
                                sessionManager.clearOldCredentials();

                                Toast.makeText(MasterPasswordActivity.this,
                                        R.string.legacy_recovery_success, Toast.LENGTH_LONG).show();
                                launchMain();
                            }
                        });
                    }

                    public void onFailure(final String error) {
                        runOnUiThread(new Runnable() {
                            public void run() {
                                btnAction.setEnabled(true);
                                textSubtitle.setText(R.string.legacy_recovery_subtitle);
                                showError(getString(R.string.legacy_recovery_migration_failed) + "\n" + error);
                            }
                        });
                    }
                });
    }

    // ======================== UTILITY ========================

    private void migrateExistingPlaintextNotes() {
        try {
            byte[] dek = keyManager.getDEK();
            if (dek == null) return;
            NotesRepository repo = NotesRepository.getInstance(this);
            repo.migrateToEncrypted(dek);
            CryptoManager.zeroFill(dek);
        } catch (Exception e) {
            Log.e(TAG, "Plaintext migration failed: " + e.getMessage());
        }
    }

    private void showError(String message) {
        textError.setText(message);
        textError.setVisibility(View.VISIBLE);
    }

    /**
     * CRITICAL FIX v3: Perform cloud sync BEFORE launching MainActivity.
     * This ensures that after reinstall, notes are already in local DB
     * and DEK is fully ready when MainActivity.loadNotes() runs.
     *
     * ARCHITECTURE FIX: Uses keyManager.isVaultUnlocked() instead of
     * sessionManager.isSessionValid() to decide whether sync is possible.
     * The vault unlock state (DEK in memory) is the authoritative check.
     * Session timestamp is secondary and can have timing issues.
     */
    private void launchMain() {
        PrefsManager prefs = PrefsManager.getInstance(this);
        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(this);

        if (!authManager.isLoggedIn() && !prefs.isCloudSyncEnabled()
                && authManager.getUid() == null) {
            Intent intent = new Intent(this, FirebaseLoginActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(intent);
            finish();
            return;
        }

        // CRITICAL: If logged in and cloud sync enabled, perform sync HERE
        // before going to MainActivity. This guarantees notes are in local DB
        // with DEK fully ready. No race condition possible.
        // FIX v3: Check keyManager.isVaultUnlocked() instead of session timestamp
        if (authManager.isLoggedIn() && prefs.isCloudSyncEnabled()
                && keyManager.isVaultUnlocked()) {
            Log.d(TAG, "[LAUNCH] Performing pre-launch cloud sync...");
            if (textSubtitle != null) {
                textSubtitle.setText("Syncing notes...");
            }
            if (btnAction != null) {
                btnAction.setEnabled(false);
            }

            CloudSyncManager.getInstance(this).syncOnAppStart(
                    new CloudSyncManager.SyncCallback() {
                        public void onSyncComplete(final boolean success) {
                            runOnUiThread(new Runnable() {
                                public void run() {
                                    Log.d(TAG, "[LAUNCH] Pre-launch sync complete, success=" + success);
                                    goToMainActivity();
                                }
                            });
                        }
                    });

            // Safety timeout: if sync takes too long (>10s), go to Main anyway
            new android.os.Handler().postDelayed(new Runnable() {
                public void run() {
                    if (!isFinishing()) {
                        Log.w(TAG, "[LAUNCH] Sync timeout, proceeding to MainActivity");
                        goToMainActivity();
                    }
                }
            }, 10000);
        } else {
            goToMainActivity();
        }
    }

    /** Flag to prevent double-launch from timeout + callback race */
    private boolean hasLaunched = false;

    private void goToMainActivity() {
        if (hasLaunched) return;
        hasLaunched = true;

        Intent intent = new Intent(MasterPasswordActivity.this, MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        startActivity(intent);
        finish();
    }

    public void onBackPressed() {
        moveTaskToBack(true);
    }
}
