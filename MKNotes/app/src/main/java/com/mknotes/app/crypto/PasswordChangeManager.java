package com.mknotes.app.crypto;

import android.content.Context;
import android.util.Log;

/**
 * Handles secure password change flow for the 2-layer DEK system.
 *
 * Password change does NOT re-encrypt any notes because:
 * - Notes are encrypted with DEK (which doesn't change)
 * - Only the DEK wrapper (encryptedDEK) changes because master key changes
 *
 * Flow:
 * 1. Verify old password by attempting to decrypt DEK
 * 2. Generate new salt
 * 3. Derive new master key with FIXED 120,000 iterations
 * 4. Re-encrypt DEK with new master key (new IV, new tag)
 * 5. Update Firestore + local storage
 * 6. Zero-fill all intermediate key material
 */
public class PasswordChangeManager {

    private static final String TAG = "PasswordChangeManager";

    /**
     * Change the master password asynchronously.
     * Delegates to KeyManager.changePassword() which runs on background thread.
     *
     * @param context     application context
     * @param oldPassword current master password
     * @param newPassword new master password
     * @param callback    result callback (called on background thread)
     */
    public static void changePassword(Context context, String oldPassword, String newPassword,
                                       KeyManager.VaultCallback callback) {
        if (oldPassword == null || newPassword == null) {
            if (callback != null) callback.onError("Passwords cannot be null");
            return;
        }
        if (newPassword.length() < 8) {
            Log.e(TAG, "New password too short");
            if (callback != null) callback.onError("New password must be at least 8 characters");
            return;
        }

        KeyManager km = KeyManager.getInstance(context);
        if (!km.isVaultInitialized()) {
            Log.e(TAG, "Cannot change password: vault not initialized");
            if (callback != null) callback.onError("Vault not initialized");
            return;
        }

        km.changePassword(oldPassword, newPassword, callback);
    }
}
