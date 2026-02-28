package com.mknotes.app;

import android.app.Activity;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

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

    private static final int MODE_CREATE = 0;
    private static final int MODE_UNLOCK = 1;

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

        if (sessionManager.isPasswordSet()) {
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
    }

    /**
     * Check if vault exists in Firestore (for reinstall/new device scenario).
     * If found, switch to unlock mode. If not, switch to create mode.
     */
    private void checkFirestoreVault() {
        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(this);
        if (authManager.isLoggedIn()) {
            // Show loading state
            btnAction.setEnabled(false);
            textSubtitle.setText("Fetching vault from cloud...");

            keyManager.fetchVaultFromFirestore(new KeyManager.VaultFetchCallback() {
                public void onResult(final boolean vaultFound) {
                    runOnUiThread(new Runnable() {
                        public void run() {
                            btnAction.setEnabled(true);
                            if (vaultFound) {
                                // Vault found in Firestore -- show unlock mode
                                setupUnlockMode();
                            } else {
                                // No vault in Firestore -- fresh user
                                setupCreateMode();
                            }
                        }
                    });
                }
            });
        } else {
            // Not logged in -- show create mode
            setupCreateMode();
        }
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

        btnAction.setEnabled(false);

        // Initialize new 2-layer vault via KeyManager
        boolean success = keyManager.initializeVault(password);
        if (success) {
            sessionManager.setPasswordSetFlag(true);
            sessionManager.updateSessionTimestamp();
            sessionManager.setEncryptionMigrated(true);

            // Migrate existing plaintext notes if any
            migrateExistingPlaintextNotes();

            Toast.makeText(this, R.string.master_password_set_success, Toast.LENGTH_SHORT).show();
            launchMain();
        } else {
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
            boolean valid = keyManager.unlockVault(password);
            if (valid) {
                sessionManager.updateSessionTimestamp();
                launchMain();
            } else {
                btnAction.setEnabled(true);
                showError(getString(R.string.master_password_error_wrong));
                editPassword.setText("");
            }
        } else if (sessionManager.hasOldSystemCredentials()) {
            // Old system: verify with old method, then migrate to new system
            handleOldSystemUnlock(password);
        } else if (keyManager.isVaultInitialized()) {
            // Vault from Firestore (reinstall) -- try unlock
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
