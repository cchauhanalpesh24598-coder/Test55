package com.mknotes.app.crypto;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Core 2-layer encryption engine for PRO-LEVEL security.
 *
 * Architecture:
 * - PBKDF2WithHmacSHA256 with DYNAMIC iterations (read from metadata, never hardcoded)
 * - AES-256-GCM with 12-byte random IV, 128-bit auth tag
 * - HMAC-SHA256 based password verification (no encrypted-plaintext oracle)
 * - DEK/KEK separation: master password derives KEK, KEK wraps DEK, DEK encrypts notes
 *
 * DEFAULT_ITERATIONS (150,000) is used ONLY when creating a brand-new vault.
 * All subsequent derivations read iterations from stored metadata.
 *
 * Memory safety:
 * - Key material is byte[], never String
 * - zeroFill() overwrites with 0x00
 * - No unnecessary Base64 encoding in memory
 */
public final class CryptoManager {

    /** Used ONLY for brand-new vault creation. Existing vaults read from metadata. */
    public static final int DEFAULT_ITERATIONS = 150_000;

    private static final int SALT_LENGTH = 16;
    private static final int KEY_LENGTH_BITS = 256;
    private static final int KEY_LENGTH_BYTES = 32;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128; // bits

    /** Constant string used for HMAC-based password verification. */
    private static final String VERIFY_CONSTANT = "MKNOTES_VAULT_VERIFY";

    private static final SecureRandom sRandom = new SecureRandom();

    private CryptoManager() {
        // Static utility class
    }

    // ======================== KEY DERIVATION ========================

    /**
     * Generate a random 16-byte salt.
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        sRandom.nextBytes(salt);
        return salt;
    }

    /**
     * Generate a random 256-bit DEK (Data Encryption Key).
     *
     * @return byte[32] random DEK
     */
    public static byte[] generateDEK() {
        byte[] dek = new byte[KEY_LENGTH_BYTES];
        sRandom.nextBytes(dek);
        return dek;
    }

    /**
     * Derive a 256-bit master key from password + salt using PBKDF2WithHmacSHA256.
     * Iterations is ALWAYS a parameter -- never read from a constant internally.
     *
     * @param password   user's master password
     * @param salt       16-byte salt
     * @param iterations PBKDF2 iteration count (from stored metadata)
     * @return byte[32] derived master key, or null on failure
     */
    public static byte[] deriveKey(String password, byte[] salt, int iterations) {
        if (password == null || salt == null || iterations <= 0) {
            return null;
        }
        PBEKeySpec spec = null;
        try {
            spec = new PBEKeySpec(password.toCharArray(), salt, iterations, KEY_LENGTH_BITS);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] key = factory.generateSecret(spec).getEncoded();
            return key;
        } catch (Exception e) {
            return null;
        } finally {
            if (spec != null) {
                spec.clearPassword();
            }
        }
    }

    // ======================== DEK WRAPPING (KEK encrypts DEK) ========================

    /**
     * Encrypt DEK with master key (KEK) using AES-256-GCM.
     *
     * @param dek       byte[32] data encryption key
     * @param masterKey byte[32] key encryption key (derived from password)
     * @return "ivHex:ciphertextHex" string for storage, or null on failure
     */
    public static String encryptDEK(byte[] dek, byte[] masterKey) {
        if (dek == null || masterKey == null) {
            return null;
        }
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            sRandom.nextBytes(iv);

            SecretKeySpec keySpec = new SecretKeySpec(masterKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] ciphertext = cipher.doFinal(dek);

            return bytesToHex(iv) + ":" + bytesToHex(ciphertext);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Decrypt DEK from stored encryptedDEK string using master key (KEK).
     *
     * @param encryptedDEK "ivHex:ciphertextHex" from storage
     * @param masterKey    byte[32] key encryption key
     * @return byte[32] DEK, or null on failure (wrong password / tampered data)
     */
    public static byte[] decryptDEK(String encryptedDEK, byte[] masterKey) {
        if (encryptedDEK == null || masterKey == null) {
            return null;
        }
        try {
            int colonIdx = encryptedDEK.indexOf(':');
            if (colonIdx <= 0) {
                return null;
            }
            String ivHex = encryptedDEK.substring(0, colonIdx);
            String cipherHex = encryptedDEK.substring(colonIdx + 1);

            if (ivHex.length() != GCM_IV_LENGTH * 2) {
                return null;
            }

            byte[] iv = hexToBytes(ivHex);
            byte[] ciphertext = hexToBytes(cipherHex);

            SecretKeySpec keySpec = new SecretKeySpec(masterKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] dek = cipher.doFinal(ciphertext);

            if (dek.length != KEY_LENGTH_BYTES) {
                zeroFill(dek);
                return null;
            }
            return dek;
        } catch (Exception e) {
            // AEADBadTagException = wrong password. Return null, no crash.
            return null;
        }
    }

    // ======================== NOTE ENCRYPTION (DEK encrypts notes) ========================

    /**
     * Encrypt plaintext using AES-256-GCM with DEK.
     *
     * @param plaintext text to encrypt
     * @param dek       byte[32] data encryption key
     * @return "ivHex:ciphertextHex", or empty string for null/empty input, or null on failure
     */
    public static String encrypt(String plaintext, byte[] dek) {
        if (plaintext == null || plaintext.length() == 0) {
            return "";
        }
        if (dek == null) {
            return null;
        }
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            sRandom.nextBytes(iv);

            SecretKeySpec keySpec = new SecretKeySpec(dek, "AES");
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
     * Decrypt ciphertext using AES-256-GCM with DEK.
     *
     * @param encryptedData "ivHex:ciphertextHex"
     * @param dek           byte[32] data encryption key
     * @return decrypted plaintext, or original data if not encrypted format, or null on decrypt failure
     */
    public static String decrypt(String encryptedData, byte[] dek) {
        if (encryptedData == null || encryptedData.length() == 0) {
            return "";
        }
        if (dek == null) {
            return null;
        }
        try {
            int colonIdx = encryptedData.indexOf(':');
            if (colonIdx <= 0) {
                return encryptedData; // Not encrypted, return as-is (plain text)
            }
            String ivHex = encryptedData.substring(0, colonIdx);
            String cipherHex = encryptedData.substring(colonIdx + 1);

            if (ivHex.length() != GCM_IV_LENGTH * 2) {
                return encryptedData; // Not encrypted format, return as-is
            }

            // Validate hex chars in IV part
            for (int i = 0; i < ivHex.length(); i++) {
                char c = ivHex.charAt(i);
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                    return encryptedData; // Not valid hex, treat as plain text
                }
            }

            byte[] iv = hexToBytes(ivHex);
            byte[] ciphertext = hexToBytes(cipherHex);

            SecretKeySpec keySpec = new SecretKeySpec(dek, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] plainBytes = cipher.doFinal(ciphertext);

            return new String(plainBytes, "UTF-8");
        } catch (Exception e) {
            // Decryption failed -- key mismatch or corrupted data
            // Return null so caller knows decryption FAILED (not plain text)
            return null;
        }
    }

    /**
     * Safe decrypt: tries DEK first, on failure returns "[Decryption Failed]" marker.
     * UI should check for null and show "Wrong Master Password" message.
     *
     * @param encryptedData "ivHex:ciphertextHex"
     * @param dek           byte[32] data encryption key
     * @return decrypted text, or DECRYPT_FAILED_MARKER on failure
     */
    public static final String DECRYPT_FAILED_MARKER = "[DECRYPTION_FAILED]";

    public static String decryptSafe(String encryptedData, byte[] dek) {
        if (encryptedData == null || encryptedData.length() == 0) {
            return "";
        }
        if (dek == null) {
            // No key available
            if (isEncrypted(encryptedData)) {
                return DECRYPT_FAILED_MARKER;
            }
            return encryptedData;
        }
        String result = decrypt(encryptedData, dek);
        if (result == null) {
            // Decryption failed -- wrong key
            return DECRYPT_FAILED_MARKER;
        }
        return result;
    }

    // ======================== HMAC VERIFICATION ========================

    /**
     * Compute HMAC-SHA256 verification tag over constant "MKNOTES_VAULT_VERIFY".
     *
     * @param masterKey byte[32] derived master key
     * @return hex string of HMAC tag, or null on failure
     */
    public static String computeVerifyTag(byte[] masterKey) {
        if (masterKey == null) {
            return null;
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(masterKey, "HmacSHA256");
            mac.init(keySpec);
            byte[] hmacBytes = mac.doFinal(VERIFY_CONSTANT.getBytes("UTF-8"));
            return bytesToHex(hmacBytes);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Verify master key by comparing HMAC tag with stored tag.
     * Uses constant-time comparison via MessageDigest.isEqual().
     *
     * @param masterKey byte[32] derived master key
     * @param storedTag hex string of stored HMAC tag
     * @return true if master key is correct
     */
    public static boolean verifyTag(byte[] masterKey, String storedTag) {
        if (masterKey == null || storedTag == null || storedTag.length() == 0) {
            return false;
        }
        try {
            String computedTag = computeVerifyTag(masterKey);
            if (computedTag == null) {
                return false;
            }
            // Constant-time comparison
            byte[] computed = hexToBytes(computedTag);
            byte[] stored = hexToBytes(storedTag);
            return MessageDigest.isEqual(computed, stored);
        } catch (Exception e) {
            return false;
        }
    }

    // ======================== MEMORY SAFETY ========================

    /**
     * Zero-fill a byte array to prevent key material from lingering in memory.
     */
    public static void zeroFill(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }

    // ======================== HEX UTILITY ========================

    /**
     * Convert byte array to lowercase hex string.
     */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
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
        if (hex == null || hex.length() == 0) return new byte[0];
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Check if a string looks like encrypted data (ivHex:ciphertextHex format).
     */
    public static boolean isEncrypted(String data) {
        if (data == null || data.length() == 0) {
            return false;
        }
        int colonIdx = data.indexOf(':');
        if (colonIdx != GCM_IV_LENGTH * 2) {
            return false;
        }
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
