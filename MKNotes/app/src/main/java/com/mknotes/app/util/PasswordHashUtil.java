package com.mknotes.app.util;

import java.security.MessageDigest;

/**
 * Utility for SHA-256 password hashing.
 * Converts plain text passwords to hex-encoded SHA-256 hashes.
 * Used for secure note lock/unlock without storing plain text passwords.
 */
public class PasswordHashUtil {

    /**
     * Hash a plain text password using SHA-256.
     * Returns lowercase hex string, or null on failure.
     */
    public static String hashPassword(String password) {
        if (password == null || password.length() == 0) {
            return null;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(password.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hashBytes.length; i++) {
                String hex = Integer.toHexString(0xff & hashBytes[i]);
                if (hex.length() == 1) {
                    sb.append('0');
                }
                sb.append(hex);
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Verify a plain text password against a stored hash or plain text.
     * Supports migration: if stored password is not a 64-char hex string (SHA-256),
     * it is treated as plain text for backwards compatibility.
     *
     * @param enteredPassword the password the user typed
     * @param storedPassword the password stored in the database (hash or plain text)
     * @return true if password matches
     */
    public static boolean verifyPassword(String enteredPassword, String storedPassword) {
        if (enteredPassword == null || storedPassword == null) {
            return false;
        }
        if (isHashed(storedPassword)) {
            // Stored password is a hash - compare hash of entered password
            String enteredHash = hashPassword(enteredPassword);
            return storedPassword.equals(enteredHash);
        } else {
            // Stored password is plain text (legacy) - compare directly
            return storedPassword.equals(enteredPassword);
        }
    }

    /**
     * Check if a stored password is already a SHA-256 hash.
     * SHA-256 hex strings are exactly 64 characters of hex digits.
     */
    public static boolean isHashed(String password) {
        if (password == null || password.length() != 64) {
            return false;
        }
        for (int i = 0; i < password.length(); i++) {
            char c = password.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }
}
