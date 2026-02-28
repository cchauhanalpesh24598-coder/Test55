package com.mknotes.app.util;

import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Cryptographic utility for master password key derivation, verification,
 * and AES-256-GCM encryption/decryption of note data.
 * Uses only built-in Android crypto APIs -- no external libraries.
 *
 * Security model:
 * - PBKDF2WithHmacSHA256 with 15000 iterations for key derivation
 * - AES-256-GCM with random 12-byte IV per encryption call
 * - Verification token approach (no key hash stored on disk)
 * - Derived key NEVER persisted -- only cached in memory during active session
 */
public class CryptoUtils {

    private static final int SALT_LENGTH = 16;
    private static final int KEY_LENGTH = 256;
    private static final int ITERATIONS = 15000;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128; // bits

    /** Known plaintext token used for password verification. */
    private static final String VERIFY_TOKEN_PLAINTEXT = "MKNOTES_VERIFY_TOKEN_V2";

    /** Single static SecureRandom instance to avoid repeated object creation. */
    private static final SecureRandom sRandom = new SecureRandom();

    /**
     * Generate a random 16-byte salt.
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        sRandom.nextBytes(salt);
        return salt;
    }

    /**
     * Generate a random 12-byte IV for AES-GCM.
     */
    public static byte[] generateIV() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        sRandom.nextBytes(iv);
        return iv;
    }

    /**
     * Derive a 256-bit key from password + salt using PBKDF2WithHmacSHA256.
     * Available on API 26+ (our minSdk).
     *
     * @return derived key bytes, or null on failure
     */
    public static byte[] deriveKey(String password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(
                    password.toCharArray(),
                    salt,
                    ITERATIONS,
                    KEY_LENGTH
            );
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] key = factory.generateSecret(spec).getEncoded();
            spec.clearPassword();
            return key;
        } catch (Exception e) {
            return null;
        }
    }

    // ======================== AES-256-GCM ENCRYPTION ========================

    /**
     * Encrypt plaintext using AES-256-GCM.
     * Returns hex string in format: ivHex + ":" + ciphertextHex
     * The GCM authentication tag is appended to ciphertext by the Cipher.
     *
     * @param plaintext the text to encrypt
     * @param keyBytes  the 256-bit derived key
     * @return encrypted string (iv:ciphertext), or null on failure
     */
    public static String encrypt(String plaintext, byte[] keyBytes) {
        if (plaintext == null || plaintext.length() == 0) {
            return "";
        }
        if (keyBytes == null) {
            return null;
        }
        try {
            byte[] iv = generateIV();
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));
            return bytesToHex(iv) + ":" + bytesToHex(ciphertext);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Decrypt ciphertext using AES-256-GCM.
     * Input format: ivHex + ":" + ciphertextHex
     *
     * @param encryptedData the encrypted string (iv:ciphertext)
     * @param keyBytes      the 256-bit derived key
     * @return decrypted plaintext, or null on failure
     */
    public static String decrypt(String encryptedData, byte[] keyBytes) {
        if (encryptedData == null || encryptedData.length() == 0) {
            return "";
        }
        if (keyBytes == null) {
            return null;
        }
        try {
            int colonIdx = encryptedData.indexOf(':');
            if (colonIdx <= 0) {
                // Not encrypted data, return as-is (migration support)
                return encryptedData;
            }
            String ivHex = encryptedData.substring(0, colonIdx);
            String cipherHex = encryptedData.substring(colonIdx + 1);

            // Validate IV length (12 bytes = 24 hex chars)
            if (ivHex.length() != GCM_IV_LENGTH * 2) {
                // Not encrypted data, return as-is (migration support)
                return encryptedData;
            }

            byte[] iv = hexToBytes(ivHex);
            byte[] ciphertext = hexToBytes(cipherHex);

            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] plainBytes = cipher.doFinal(ciphertext);
            return new String(plainBytes, "UTF-8");
        } catch (Exception e) {
            // Decryption failed - could be unencrypted legacy data
            return encryptedData;
        }
    }

    // ======================== VERIFICATION TOKEN ========================

    /**
     * Encrypt the known verification token with the given key.
     * Used during password setup to create a verifiable token
     * that proves the correct key was derived.
     *
     * @param key the 256-bit derived key
     * @return encrypted token string (iv:ciphertext hex), or null on failure
     */
    public static String encryptVerificationToken(byte[] key) {
        if (key == null) {
            return null;
        }
        return encrypt(VERIFY_TOKEN_PLAINTEXT, key);
    }

    /**
     * Verify a derived key by decrypting the stored verification token.
     * If the decrypted result matches the known plaintext, the key is correct.
     *
     * On AEADBadTagException or any failure, returns false (never crashes).
     *
     * @param key            the 256-bit derived key to verify
     * @param encryptedToken the stored encrypted verification token
     * @return true if the key correctly decrypts the token
     */
    public static boolean verifyKeyWithToken(byte[] key, String encryptedToken) {
        if (key == null || encryptedToken == null || encryptedToken.length() == 0) {
            return false;
        }
        try {
            int colonIdx = encryptedToken.indexOf(':');
            if (colonIdx <= 0) {
                return false;
            }
            String ivHex = encryptedToken.substring(0, colonIdx);
            String cipherHex = encryptedToken.substring(colonIdx + 1);

            if (ivHex.length() != GCM_IV_LENGTH * 2) {
                return false;
            }

            byte[] iv = hexToBytes(ivHex);
            byte[] ciphertext = hexToBytes(cipherHex);

            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] plainBytes = cipher.doFinal(ciphertext);
            String decrypted = new String(plainBytes, "UTF-8");
            return constantTimeEquals(decrypted, VERIFY_TOKEN_PLAINTEXT);
        } catch (Exception e) {
            // AEADBadTagException (wrong key) or any other failure
            return false;
        }
    }

    // ======================== UTILITY ========================

    /**
     * Constant-time string comparison to prevent timing attacks.
     */
    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        if (a.length() != b.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    /**
     * Convert byte array to lowercase hex string.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(0xff & bytes[i]);
            if (hex.length() == 1) {
                sb.append('0');
            }
            sb.append(hex);
        }
        return sb.toString();
    }

    /**
     * Convert hex string to byte array.
     */
    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Check if a string looks like encrypted data (iv:ciphertext format).
     */
    public static boolean isEncrypted(String data) {
        if (data == null || data.length() == 0) {
            return false;
        }
        int colonIdx = data.indexOf(':');
        if (colonIdx != GCM_IV_LENGTH * 2) {
            return false;
        }
        // Check if IV part is valid hex
        String ivPart = data.substring(0, colonIdx);
        for (int i = 0; i < ivPart.length(); i++) {
            char c = ivPart.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }
}
