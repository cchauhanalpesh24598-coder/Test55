package com.mknotes.app;

import android.content.Intent;
import android.os.Bundle;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.mknotes.app.cloud.FirebaseAuthManager;
import com.mknotes.app.crypto.KeyManager;
import com.mknotes.app.util.PrefsManager;

/**
 * Firebase Email/Password login/register screen.
 *
 * After successful Firebase login:
 * 1. Fetch vault from Firestore (users/{uid}/crypto_metadata/vault)
 * 2. If vault found -> MasterPasswordActivity (UNLOCK mode)
 * 3. If no vault + notes exist -> MasterPasswordActivity (LEGACY RECOVERY)
 * 4. If no vault + no notes -> MasterPasswordActivity (CREATE mode)
 *
 * REINSTALL PROOF: Vault metadata fetched from Firestore after login.
 */
public class FirebaseLoginActivity extends AppCompatActivity {

    private static final String TAG = "FirebaseLoginActivity";
    private static final int MODE_LOGIN = 0;
    private static final int MODE_REGISTER = 1;

    private int currentMode = MODE_LOGIN;

    private EditText etEmail;
    private EditText etPassword;
    private TextView tvError;
    private TextView tvModeTitle;
    private Button btnAction;
    private TextView tvToggleMode;
    private TextView btnSkip;
    private CheckBox cbShowPassword;

    private FirebaseAuthManager authManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_firebase_login);

        authManager = FirebaseAuthManager.getInstance(this);

        initViews();
        setupLoginMode();
    }

    private void initViews() {
        etEmail = findViewById(R.id.et_firebase_email);
        etPassword = findViewById(R.id.et_firebase_password);
        tvError = findViewById(R.id.tv_firebase_error);
        tvModeTitle = findViewById(R.id.tv_mode_title);
        btnAction = findViewById(R.id.btn_firebase_action);
        tvToggleMode = findViewById(R.id.tv_toggle_mode);
        btnSkip = findViewById(R.id.btn_skip);
        cbShowPassword = findViewById(R.id.cb_firebase_show_password);

        btnAction.setOnClickListener(v -> handleAction());

        if (cbShowPassword != null) {
            cbShowPassword.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                    if (isChecked) {
                        etPassword.setTransformationMethod(HideReturnsTransformationMethod.getInstance());
                    } else {
                        etPassword.setTransformationMethod(PasswordTransformationMethod.getInstance());
                    }
                    etPassword.setSelection(etPassword.getText().length());
                }
            });
        }

        tvToggleMode.setOnClickListener(v -> toggleMode());

        btnSkip.setOnClickListener(v -> {
            PrefsManager.getInstance(FirebaseLoginActivity.this).setCloudSyncEnabled(false);
            launchMain();
        });
    }

    private void setupLoginMode() {
        currentMode = MODE_LOGIN;
        tvModeTitle.setText(R.string.firebase_login_subtitle);
        btnAction.setText(R.string.firebase_btn_login);
        tvToggleMode.setText(R.string.firebase_no_account);
        tvError.setVisibility(View.GONE);
    }

    private void setupRegisterMode() {
        currentMode = MODE_REGISTER;
        tvModeTitle.setText(R.string.firebase_register_subtitle);
        btnAction.setText(R.string.firebase_btn_register);
        tvToggleMode.setText(R.string.firebase_has_account);
        tvError.setVisibility(View.GONE);
    }

    private void toggleMode() {
        if (currentMode == MODE_LOGIN) {
            setupRegisterMode();
        } else {
            setupLoginMode();
        }
    }

    private void handleAction() {
        String email = etEmail.getText().toString().trim();
        String password = etPassword.getText().toString().trim();

        if (email.length() == 0) {
            showError(getString(R.string.firebase_error_email_empty));
            return;
        }
        if (password.length() < 6) {
            showError(getString(R.string.firebase_error_password_short));
            return;
        }

        btnAction.setEnabled(false);
        tvError.setVisibility(View.GONE);

        FirebaseAuthManager.AuthCallback callback = new FirebaseAuthManager.AuthCallback() {
            @Override
            public void onSuccess() {
                runOnUiThread(() -> {
                    PrefsManager.getInstance(FirebaseLoginActivity.this).setCloudSyncEnabled(true);
                    fetchVaultAndProceed();
                });
            }

            @Override
            public void onFailure(final String errorMessage) {
                runOnUiThread(() -> {
                    btnAction.setEnabled(true);
                    showError(errorMessage);
                });
            }
        };

        if (currentMode == MODE_LOGIN) {
            authManager.login(email, password, callback);
        } else {
            authManager.register(email, password, callback);
        }
    }

    /**
     * After Firebase login, fetch vault metadata from Firestore.
     *
     * Path: users/{uid}/crypto_metadata/vault
     *
     * FIX v2.2: Uses 3-state callback to distinguish "no vault" from "network error".
     * On NETWORK_ERROR: shows error and blocks progression to prevent accidental vault creation.
     */
    private void fetchVaultAndProceed() {
        final KeyManager km = KeyManager.getInstance(this);

        Log.d(TAG, "[VAULT_FETCH] Starting vault fetch after Firebase login");

        km.fetchVaultFromFirestoreWithResult(new KeyManager.VaultFetchResultCallback() {
            public void onResult(final KeyManager.VaultFetchResult result) {
                runOnUiThread(new Runnable() {
                    public void run() {
                        switch (result) {
                            case VAULT_FOUND:
                                Log.d(TAG, "[VAULT_FETCH] Vault found, going to UNLOCK");
                                goToMasterPassword(false);
                                break;
                            case NO_VAULT_EXISTS:
                                Log.d(TAG, "[VAULT_FETCH] Server confirms no vault, checking for notes...");
                                checkNotesBeforeCreate(km);
                                break;
                            case NETWORK_ERROR:
                                Log.w(TAG, "[VAULT_FETCH] NETWORK_ERROR -- cannot proceed safely");
                                showError(getString(R.string.vault_network_error_detail));
                                break;
                        }
                    }
                });
            }
        });
    }

    /**
     * Check if notes exist in Firestore before allowing vault creation.
     * FIX v2.2: Uses 3-state callback. On NETWORK_ERROR, blocks progression.
     */
    private void checkNotesBeforeCreate(final KeyManager km) {
        km.checkCloudNotesExistWithResult(new KeyManager.VaultFetchResultCallback() {
            public void onResult(final KeyManager.VaultFetchResult result) {
                runOnUiThread(new Runnable() {
                    public void run() {
                        switch (result) {
                            case VAULT_FOUND:
                                // VAULT_FOUND here = "notes exist but vault missing"
                                Log.d(TAG, "[LEGACY_DETECTED] Notes exist, vault missing. Legacy recovery.");
                                goToMasterPassword(true);
                                break;
                            case NO_VAULT_EXISTS:
                                // Server confirms no notes AND no vault -- fresh user
                                Log.d(TAG, "[FRESH_USER] No vault, no notes. CREATE mode.");
                                goToMasterPassword(false);
                                break;
                            case NETWORK_ERROR:
                                Log.w(TAG, "[NOTES_CHECK] NETWORK_ERROR -- cannot proceed safely");
                                showError(getString(R.string.vault_network_error_detail));
                                break;
                        }
                    }
                });
            }
        });
    }

    /**
     * Helper to launch MasterPasswordActivity with optional legacy_recovery flag.
     */
    private void goToMasterPassword(boolean legacyRecovery) {
        Intent intent = new Intent(FirebaseLoginActivity.this, MasterPasswordActivity.class);
        if (legacyRecovery) {
            intent.putExtra("legacy_recovery", true);
        }
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        startActivity(intent);
        finish();
    }

    private void showError(String message) {
        tvError.setText(message);
        tvError.setVisibility(View.VISIBLE);
    }

    private void launchMain() {
        Intent intent = new Intent(this, MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        startActivity(intent);
        finish();
    }

    @SuppressWarnings("MissingSuperCall")
    @Override
    public void onBackPressed() {
        PrefsManager.getInstance(this).setCloudSyncEnabled(false);
        launchMain();
    }
}
