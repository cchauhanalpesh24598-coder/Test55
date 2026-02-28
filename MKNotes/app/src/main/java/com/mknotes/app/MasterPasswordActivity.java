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

import com.google.firebase.firestore.FirebaseFirestore;

import com.mknotes.app.cloud.FirebaseAuthManager;
import com.mknotes.app.crypto.CryptoManager;
import com.mknotes.app.crypto.KeyManager;
import com.mknotes.app.crypto.MigrationManager;
import com.mknotes.app.db.NotesRepository;
import com.mknotes.app.util.CryptoUtils;
import com.mknotes.app.util.PrefsManager;
import com.mknotes.app.util.SessionManager;

/**
 * Gatekeeper activity that requires master password before allowing app access.
 * Two modes: CREATE (first launch) and UNLOCK (subsequent launches after session expiry).
 *
 * Now supports:
 * - New 2-layer DEK vault system via KeyManager
 * - Migration from old single-layer system via MigrationManager
 * - Vault fetch from Firestore on reinstall/new device
 * - HMAC-based password verification (no encrypted-plaintext oracle)
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

        // If vault is initialized, unlocked, and session is valid -- skip to main
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
            Log.d(TAG, "[LEGACY_RECOVERY] Intent flag detected, setting up legacy recovery mode");
            setupLegacyRecoveryMode();
        } else if (sessionManager.isPasswordSet()) {
            setupUnlockMode();
        } else {
            // Check if vault exists in Firestore (reinstall scenario)
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

        // Show/Hide password toggle
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
                    // Move cursor to end
                    editPassword.setSelection(editPassword.getText().length());
                    if (editConfirmPassword.getVisibility() == View.VISIBLE) {
                        editConfirmPassword.setSelection(editConfirmPassword.getText().length());
                    }
                }
            });
        }
    }

    /**
     * Check if vault exists in Firestore (for reinstall/new device scenario).
     * If found, switch to unlock mode. If not, check for orphan notes safety.
     * SAFETY: Always tries Firestore before allowing create mode.
     * If notes exist in cloud but vault metadata is missing, BLOCK vault creation.
     */
    private void checkFirestoreVault() {
        // SAFETY: If vault already exists locally (e.g. partial fetch), go to unlock
        if (keyManager.isVaultInitialized()) {
            Log.d(TAG, "[VAULT_CHECK] Vault already initialized locally, going to unlock mode");
            setupUnlockMode();
            return;
        }

        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(this);
        if (authManager.isLoggedIn()) {
            // Show loading state
            btnAction.setEnabled(false);
            textSubtitle.setText("Fetching vault from cloud...");

            keyManager.fetchVaultFromFirestore(new KeyManager.VaultFetchCallback() {
                public void onResult(final boolean vaultFound) {
                    runOnUiThread(new Runnable() {
                        public void run() {
                            if (vaultFound) {
                                Log.d(TAG, "[VAULT_EXISTS] Vault found in Firestore, switching to UNLOCK mode");
                                btnAction.setEnabled(true);
                                setupUnlockMode();
                            } else {
                                Log.d(TAG, "[VAULT_MISSING] No vault in Firestore, checking for orphan notes...");
                                // SAFETY CHECK: Before allowing create, check if notes exist
                                checkCloudNotesBeforeCreate();
                            }
                        }
                    });
                }
            });
        } else {
            // Not logged in -- show create mode (offline use)
            Log.d(TAG, "[VAULT_CHECK] Not logged in, allowing create mode");
            setupCreateMode();
        }
    }

    /**
     * SAFETY: Check if notes exist in Firestore BEFORE allowing vault creation.
     * If notes exist but vault metadata is missing, creating a new vault
     * would generate a new salt/DEK, making all existing notes permanently undecryptable.
     */
    private void checkCloudNotesBeforeCreate() {
        keyManager.checkCloudNotesExist(new KeyManager.VaultFetchCallback() {
            public void onResult(final boolean notesExist) {
                runOnUiThread(new Runnable() {
                    public void run() {
                        btnAction.setEnabled(true);
                        if (notesExist) {
                            // Notes exist but vault metadata is missing
                            // Instead of blocking, offer legacy recovery mode
                            Log.d(TAG, "[LEGACY_DETECTED] Notes exist in Firestore but vault metadata is MISSING. "
                                    + "Offering legacy recovery mode.");
                            setupLegacyRecoveryMode();
                        } else {
                            // No notes, no vault -- truly fresh user, allow create
                            Log.d(TAG, "[FRESH_USER] No notes and no vault in Firestore, allowing create mode");
                            setupCreateMode();
                        }
                    }
                });
            }
        });
    }

    /**
     * Legacy Recovery Mode: Notes exist in Firestore but vault metadata is missing.
     * Instead of blocking the user, allow them to enter their old master password
     * to attempt migration from legacy direct-key encryption to new DEK system.
     */
    private void setupLegacyRecoveryMode() {
        currentMode = MODE_LEGACY_RECOVERY;
        Log.d(TAG, "[LEGACY_RECOVERY] Setting up legacy recovery mode");

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

    /**
     * Handle legacy recovery: verify master password against a sample cloud note,
     * then migrate all notes to new DEK encryption system.
     */
    private void handleLegacyRecovery() {
        final String password = editPassword.getText().toString();

        if (password.length() == 0) {
            showError(getString(R.string.master_password_error_empty));
            return;
        }

        btnAction.setEnabled(false);
        textError.setVisibility(View.GONE);
        textSubtitle.setText(R.string.legacy_recovery_verifying);

        Log.d(TAG, "[LEGACY_RECOVERY] Verifying legacy master password...");

        // Step 1: Verify the password can decrypt a sample note
        MigrationManager.verifyLegacyPassword(this, password,
                new MigrationManager.LegacyMigrationCallback() {
                    public void onSuccess() {
                        runOnUiThread(new Runnable() {
                            public void run() {
                                Log.d(TAG, "[LEGACY_RECOVERY] Password verified, starting migration...");
                                textSubtitle.setText(R.string.legacy_recovery_migrating);
                                performLegacyMigration(password);
                            }
                        });
                    }

                    public void onFailure(final String error) {
                        runOnUiThread(new Runnable() {
                            public void run() {
                                Log.e(TAG, "[LEGACY_RECOVERY] Password verification failed: " + error);
                                btnAction.setEnabled(true);
                                textSubtitle.setText(R.string.legacy_recovery_subtitle);
                                showError(getString(R.string.legacy_recovery_wrong_password));
                                editPassword.setText("");
                            }
                        });
                    }
                });
    }

    /**
     * Perform the actual legacy migration after password verification.
     */
    private void performLegacyMigration(final String password) {
        MigrationManager.migrateLegacyCloudNotes(this, password,
                new MigrationManager.LegacyMigrationCallback() {
                    public void onSuccess() {
                        runOnUiThread(new Runnable() {
                            public void run() {
                                Log.d(TAG, "[MIGRATION_SUCCESS] Legacy cloud migration completed");
                                sessionManager.setPasswordSetFlag(true);
                                sessionManager.updateSessionTimestamp();
                                sessionManager.setEncryptionMigrated(true);
                                // Clear old credentials if any
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
                                Log.e(TAG, "[MIGRATION_FAILED] Legacy migration failed: " + error);
                                btnAction.setEnabled(true);
                                textSubtitle.setText(R.string.legacy_recovery_subtitle);
                                showError(getString(R.string.legacy_recovery_migration_failed) + "\n" + error);
                            }
                        });
                    }
                });
    }

    private void setupCreateMode() {
        currentMode = MODE_CREATE;
        toolbarTitle.setText(R.string.master_password_title_create);
        textSubtitle.setText(R.string.master_password_subtitle_create);
        editConfirmPassword.setVisibility(View.VISIBLE);
        textStrengthHint.setVisibility(View.VISIBLE);
        btnAction.setText(R.string.master_password_btn_create);
        textError.setVisibility(View.GONE);

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

        btnAction.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                handleUnlock();
            }
        });
    }

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

        // SAFETY CHECK: If vault already exists locally, do NOT create new one
        if (keyManager.isVaultInitialized()) {
            Log.w(TAG, "[SAFETY_BLOCK] handleCreate() blocked: vault already exists locally. Switching to unlock mode.");
            setupUnlockMode();
            return;
        }

        btnAction.setEnabled(false);
        textSubtitle.setText("Creating vault...");

        // SAFETY CHECK: Double-check Firestore before creating vault
        // This prevents race conditions where vault was uploaded between fetch and create
        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(this);
        if (authManager.isLoggedIn()) {
            Log.d(TAG, "[VAULT_CREATE] Double-checking Firestore before vault creation...");
            final String pwd = password;
            keyManager.fetchVaultFromFirestore(new KeyManager.VaultFetchCallback() {
                public void onResult(final boolean vaultFound) {
                    runOnUiThread(new Runnable() {
                        public void run() {
                            if (vaultFound) {
                                // Vault appeared in Firestore -- switch to unlock, do NOT create
                                Log.w(TAG, "[SAFETY_BLOCK] Vault found in Firestore during create! Switching to unlock mode.");
                                btnAction.setEnabled(true);
                                textSubtitle.setText(R.string.master_password_subtitle_unlock);
                                setupUnlockMode();
                            } else {
                                // Also check if notes exist (orphan notes safety)
                                keyManager.checkCloudNotesExist(new KeyManager.VaultFetchCallback() {
                                    public void onResult(final boolean notesExist) {
                                        runOnUiThread(new Runnable() {
                                            public void run() {
                                                if (notesExist) {
                                                    // Notes exist without vault metadata
                                                    // Switch to legacy recovery instead of blocking
                                                    Log.d(TAG, "[LEGACY_DETECTED] Notes exist in cloud but no vault metadata. "
                                                            + "Switching to legacy recovery mode.");
                                                    setupLegacyRecoveryMode();
                                                } else {
                                                    // All clear -- proceed with vault creation
                                                    performVaultCreation(pwd);
                                                }
                                            }
                                        });
                                    }
                                });
                            }
                        }
                    });
                }
            });
        } else {
            // Not logged in -- safe to create locally
            Log.d(TAG, "[VAULT_CREATE] Not logged in, creating vault locally");
            performVaultCreation(password);
        }
    }

    /**
     * Actually create the vault after all safety checks have passed.
     */
    private void performVaultCreation(String password) {
        Log.d(TAG, "[VAULT_CREATE] All safety checks passed, initializing vault...");
        boolean success = keyManager.initializeVault(password);
        if (success) {
            Log.d(TAG, "[VAULT_CREATE] Vault initialized successfully");
            sessionManager.setPasswordSetFlag(true);
            sessionManager.updateSessionTimestamp();
            sessionManager.setEncryptionMigrated(true);

            // Migrate existing plaintext notes if any
            migrateExistingPlaintextNotes();

            Toast.makeText(this, R.string.master_password_set_success, Toast.LENGTH_SHORT).show();
            launchMain();
        } else {
            Log.e(TAG, "[VAULT_CREATE] initializeVault() returned false");
            btnAction.setEnabled(true);
            showError(getString(R.string.master_password_error_generic));
        }
    }

    private void handleUnlock() {
        String password = editPassword.getText().toString();

        if (password.length() == 0) {
            showError(getString(R.string.master_password_error_empty));
            return;
        }

        btnAction.setEnabled(false);

        // Check if this is new 2-layer system or old system needing migration
        if (keyManager.isVaultInitialized() && keyManager.getVaultVersion() >= KeyManager.CURRENT_VAULT_VERSION) {
            // New system: unlock via KeyManager (HMAC verification)
            Log.d(TAG, "Attempting unlock with new 2-layer system");
            boolean valid = keyManager.unlockVault(password);
            if (valid) {
                sessionManager.setPasswordSetFlag(true);
                sessionManager.updateSessionTimestamp();
                sessionManager.setEncryptionMigrated(true);
                launchMain();
            } else {
                btnAction.setEnabled(true);
                showError(getString(R.string.master_password_error_wrong));
                editPassword.setText("");
            }
        } else if (sessionManager.hasOldSystemCredentials()) {
            // Old system: verify with old method, then migrate to new system
            Log.d(TAG, "Attempting unlock with old system + migration");
            handleOldSystemUnlock(password);
        } else if (keyManager.isVaultInitialized()) {
            // Vault from Firestore (reinstall) -- try unlock
            Log.d(TAG, "Attempting unlock with Firestore vault (reinstall scenario)");
            boolean valid = keyManager.unlockVault(password);
            if (valid) {
                sessionManager.setPasswordSetFlag(true);
                sessionManager.updateSessionTimestamp();
                sessionManager.setEncryptionMigrated(true);
                launchMain();
            } else {
                btnAction.setEnabled(true);
                showError(getString(R.string.master_password_error_wrong));
                editPassword.setText("");
            }
        } else if (currentMode == MODE_LEGACY_RECOVERY) {
            // Legacy recovery mode -- handle through legacy recovery path
            Log.d(TAG, "handleUnlock called in LEGACY_RECOVERY mode, redirecting to handleLegacyRecovery");
            handleLegacyRecovery();
        } else {
            btnAction.setEnabled(true);
            showError(getString(R.string.master_password_error_generic));
        }
    }

    /**
     * Handle unlock with old single-layer system, then migrate to new DEK system.
     */
    private void handleOldSystemUnlock(String password) {
        // Verify with old CryptoUtils system
        String saltHex = sessionManager.getOldSaltHex();
        String verifyToken = sessionManager.getOldVerifyToken();
        int oldIterations = sessionManager.getOldIterations();

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

        // Old password verified -- now migrate to new 2-layer DEK system
        sessionManager.updateSessionTimestamp();

        boolean migrated = MigrationManager.migrate(this, password, oldSalt, oldIterations);
        if (migrated) {
            // Migration successful -- clear old credentials
            sessionManager.clearOldCredentials();
            sessionManager.setEncryptionMigrated(true);
            Toast.makeText(this, R.string.master_password_set_success, Toast.LENGTH_SHORT).show();
            launchMain();
        } else {
            // Migration failed -- old data preserved via backup restore
            // Still allow access with old system for now
            btnAction.setEnabled(true);
            showError("Migration failed. Please try again.");
        }
    }

    /**
     * Migrate existing plaintext notes to encrypted format (for first-time setup).
     * Uses new DEK from KeyManager.
     */
    private void migrateExistingPlaintextNotes() {
        try {
            byte[] dek = keyManager.getDEK();
            if (dek == null) {
                return;
            }
            NotesRepository repo = NotesRepository.getInstance(this);
            repo.migrateToEncrypted(dek);
            CryptoManager.zeroFill(dek);
        } catch (Exception e) {
            // Migration failed -- will retry on next unlock
        }
    }

    private void showError(String message) {
        textError.setText(message);
        textError.setVisibility(View.VISIBLE);
    }

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

        Intent intent = new Intent(this, MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        startActivity(intent);
        finish();
    }

    public void onBackPressed() {
        moveTaskToBack(true);
    }
}
