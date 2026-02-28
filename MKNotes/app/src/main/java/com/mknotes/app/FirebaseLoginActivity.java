package com.mknotes.app;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.mknotes.app.cloud.FirebaseAuthManager;
import com.mknotes.app.crypto.KeyManager;
import com.mknotes.app.util.PrefsManager;

/**
 * Firebase Email/Password login/register screen.
 * Separate from MasterPassword - this is for cloud sync authentication.
 *
 * After successful Firebase login, attempts to fetch vault metadata from Firestore.
 * - If vault exists: store locally, redirect to MasterPasswordActivity (unlock mode)
 * - If no vault: redirect to MasterPasswordActivity (create mode) or straight to MainActivity
 */
public class FirebaseLoginActivity extends AppCompatActivity {

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

        btnAction.setOnClickListener(v -> handleAction());

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
                    // After successful Firebase login, fetch vault metadata from Firestore
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
     * After Firebase login, attempt to fetch vault metadata from Firestore.
     * If vault exists: user has an existing account with encryption set up.
     *   -> Redirect to MasterPasswordActivity (unlock mode)
     * If no vault: new user, go to MainActivity (master password will be set up later).
     */
    private void fetchVaultAndProceed() {
        KeyManager km = KeyManager.getInstance(this);
        km.fetchVaultFromFirestore(new KeyManager.VaultFetchCallback() {
            public void onResult(final boolean vaultFound) {
                runOnUiThread(new Runnable() {
                    public void run() {
                        if (vaultFound) {
                            // Vault found -- redirect to master password unlock
                            // since user needs to enter their master password to decrypt
                            Intent intent = new Intent(FirebaseLoginActivity.this, MasterPasswordActivity.class);
                            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
                            startActivity(intent);
                            finish();
                        } else {
                            // No vault -- proceed to main (master password setup happens there)
                            launchMain();
                        }
                    }
                });
            }
        });
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
