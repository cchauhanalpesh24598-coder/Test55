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
 * 1. Verify old password via HMAC
 * 2. Decrypt DEK with old master key
 * 3. Generate new salt
 * 4. Derive new master key with same/upgraded iterations
 * 5. Re-encrypt DEK with new master key
 * 6. Compute new HMAC verifyTag
 * 7. Update Firestore + local storage
 * 8. Zero-fill all intermediate key material
 */
public class PasswordChangeManager {

    private static final String TAG = "PasswordChangeManager";

    /**
     * Change the master password. Delegates to KeyManager.changePassword().
     *
     * @param context     application context
     * @param oldPassword current master password
     * @param newPassword new master password
     * @return true on success, false on failure (wrong old password, crypto error)
     */
    public static boolean changePassword(Context context, String oldPassword, String newPassword) {
        if (oldPassword == null || newPassword == null) {
            return false;
        }
        if (newPassword.length() < 8) {
            Log.e(TAG, "New password too short");
            return false;
        }

        KeyManager km = KeyManager.getInstance(context);
        if (!km.isVaultInitialized()) {
            Log.e(TAG, "Cannot change password: vault not initialized");
            return false;
        }

        boolean success = km.changePassword(oldPassword, newPassword);
        if (success) {
            Log.d(TAG, "Password changed successfully via KeyManager");
        } else {
            Log.e(TAG, "Password change failed");
        }
        return success;
    }
}
