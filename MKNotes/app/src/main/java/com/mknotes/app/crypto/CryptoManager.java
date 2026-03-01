package com.mknotes.app.crypto;

import android.util.Base64;
import android.util.Log;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Core 2-layer encryption engine -- FRESH CLEAN production-ready system.
 *
 * Architecture:
 * - PBKDF2WithHmacSHA256 with FIXED 120,000 iterations
 * - 16-byte random salt for key derivation
 * - 256-bit Master Key (KEK) derived from password
 * - 256-bit random Data Encryption Key (DEK)
 * - DEK wrapped with Master Key using AES-256-GCM (12-byte IV, 128-bit tag)
 * - Notes encrypted with DEK using AES-256-GCM (random IV per note)
 *
 * Storage format:
 * - Firestore vault: salt, encryptedDEK, iv, tag -- all Base64 encoded
 * - Note encryption: "ivHex:ciphertextHex" (hex for local SQLite compat)
 *
 * Memory safety:
 * - Key material is byte[], never String
 * - zeroFill() overwrites with 0x00
 *
 * REINSTALL PROOF: Salt, iterations, encryptedDEK, IV, tag stored in Firestore.
 * On reinstall, fetch from Firestore, derive Master Key from password, decrypt DEK.
 */
public final class CryptoManager {

    private static final String TAG = "CryptoManager";

    /** FIXED iteration count -- NEVER change this. */
    public static final int FIXED_ITERATIONS = 120_000;

    /** Legacy iteration count for old CryptoUtils migration ONLY. */
    public static final int LEGACY_ITERATIONS = 15_000;

    private static final int SALT_LENGTH = 16;        // 16 bytes = 128 bits
    private static final int KEY_LENGTH_BITS = 256;
    private static final int KEY_LENGTH_BYTES = 32;    // 256 / 8
    private static final int GCM_IV_LENGTH = 12;       // 12 bytes per NIST recommendation
    private static final int GCM_TAG_LENGTH_BITS = 128; // 128-bit auth tag

    private static final SecureRandom sRandom = new SecureRandom();

    private CryptoManager() {
        // Static utility class
    }

    // ======================== SALT & DEK GENERATION ========================

    /**
     * Generate a cryptographically random 16-byte salt.
     * Called ONCE during vault creation. NEVER regenerated after.
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        sRandom.nextBytes(salt);
        return salt;
    }

    /**
     * Generate a cryptographically random 256-bit DEK (Data Encryption Key).
     * Called ONCE during vault creation. NEVER regenerated unless vault is deleted.
     *
     * @return byte[32] random DEK
     */
    public static byte[] generateDEK() {
        byte[] dek = new byte[KEY_LENGTH_BYTES];
        sRandom.nextBytes(dek);
        return dek;
    }

    // ======================== KEY DERIVATION ========================

    /**
     * Derive a 256-bit master key from password + salt using PBKDF2WithHmacSHA256.
     * Iteration count is ALWAYS 120,000 -- no dynamic reading.
     *
     * @param password user's master password
     * @param salt     16-byte salt (from vault metadata)
     * @return byte[32] derived master key, or null on failure
     */
    public static byte[] deriveMasterKey(String password, byte[] salt) {
        if (password == null || password.length() == 0 || salt == null || salt.length == 0) {
            Log.e(TAG, "deriveMasterKey: invalid input");
            return null;
        }
        PBEKeySpec spec = null;
        try {
            spec = new PBEKeySpec(password.toCharArray(), salt, FIXED_ITERATIONS, KEY_LENGTH_BITS);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] key = factory.generateSecret(spec).getEncoded();
            return key;
        } catch (Exception e) {
            Log.e(TAG, "deriveMasterKey failed: " + e.getMessage());
            return null;
        } finally {
            if (spec != null) {
                spec.clearPassword();
            }
        }
    }

    /**
     * Derive legacy key for migration ONLY. Uses old 15,000 iterations.
     */
    public static byte[] deriveLegacyKey(String password, byte[] salt) {
        if (password == null || salt == null) return null;
        PBEKeySpec spec = null;
        try {
            spec = new PBEKeySpec(password.toCharArray(), salt, LEGACY_ITERATIONS, KEY_LENGTH_BITS);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            return null;
        } finally {
            if (spec != null) spec.clearPassword();
        }
    }

    // ======================== DEK WRAPPING (Master Key encrypts DEK) ========================

    /**
     * Encrypt DEK with Master Key using AES-256-GCM.
     * Returns a VaultBundle containing encryptedDEK, IV, and tag -- all Base64 encoded.
     *
     * The GCM output includes ciphertext + appended auth tag.
     * We split them for explicit storage in Firestore.
     *
     * @param dek       byte[32] data encryption key
     * @param masterKey byte[32] key encryption key (derived from password)
     * @return VaultBundle with Base64 encoded fields, or null on failure
     */
    public static VaultBundle encryptDEK(byte[] dek, byte[] masterKey) {
        if (dek == null || masterKey == null) {
            Log.e(TAG, "encryptDEK: null input");
            return null;
        }
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            sRandom.nextBytes(iv);

            SecretKeySpec keySpec = new SecretKeySpec(masterKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] ciphertextWithTag = cipher.doFinal(dek);

            // Java GCM appends the 16-byte auth tag to the ciphertext
            // Split: ciphertext = first (len - 16) bytes, tag = last 16 bytes
            int tagBytes = GCM_TAG_LENGTH_BITS / 8; // 16
            int cipherLen = ciphertextWithTag.length - tagBytes;
            byte[] ciphertext = new byte[cipherLen];
            byte[] tag = new byte[tagBytes];
            System.arraycopy(ciphertextWithTag, 0, ciphertext, 0, cipherLen);
            System.arraycopy(ciphertextWithTag, cipherLen, tag, 0, tagBytes);

            VaultBundle bundle = new VaultBundle();
            bundle.encryptedDEK = Base64.encodeToString(ciphertext, Base64.NO_WRAP);
            bundle.iv = Base64.encodeToString(iv, Base64.NO_WRAP);
            bundle.tag = Base64.encodeToString(tag, Base64.NO_WRAP);
            return bundle;

        } catch (Exception e) {
            Log.e(TAG, "encryptDEK failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Decrypt DEK from vault metadata using Master Key.
     *
     * @param encryptedDEKBase64 Base64 encoded ciphertext (without tag)
     * @param ivBase64           Base64 encoded IV
     * @param tagBase64          Base64 encoded GCM auth tag
     * @param masterKey          byte[32] derived master key
     * @return byte[32] DEK on success, null on failure (wrong password / tampered)
     */
    public static byte[] decryptDEK(String encryptedDEKBase64, String ivBase64,
                                     String tagBase64, byte[] masterKey) {
        if (encryptedDEKBase64 == null || ivBase64 == null || tagBase64 == null || masterKey == null) {
            Log.e(TAG, "decryptDEK: null input");
            return null;
        }
        try {
            byte[] ciphertext = Base64.decode(encryptedDEKBase64, Base64.NO_WRAP);
            byte[] iv = Base64.decode(ivBase64, Base64.NO_WRAP);
            byte[] tag = Base64.decode(tagBase64, Base64.NO_WRAP);

            if (iv.length != GCM_IV_LENGTH) {
                Log.e(TAG, "decryptDEK: invalid IV length=" + iv.length);
                return null;
            }

            // Reassemble ciphertext + tag for Java GCM decryption
            byte[] ciphertextWithTag = new byte[ciphertext.length + tag.length];
            System.arraycopy(ciphertext, 0, ciphertextWithTag, 0, ciphertext.length);
            System.arraycopy(tag, 0, ciphertextWithTag, ciphertext.length, tag.length);

            SecretKeySpec keySpec = new SecretKeySpec(masterKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] dek = cipher.doFinal(ciphertextWithTag);

            if (dek.length != KEY_LENGTH_BYTES) {
                Log.e(TAG, "decryptDEK: unexpected DEK length=" + dek.length);
                zeroFill(dek);
                return null;
            }
            return dek;

        } catch (javax.crypto.AEADBadTagException e) {
            // Wrong password -- auth tag mismatch
            Log.w(TAG, "decryptDEK: AEADBadTagException -- wrong password");
            return null;
        } catch (Exception e) {
            Log.e(TAG, "decryptDEK failed: " + e.getMessage());
            return null;
        }
    }

    // ======================== NOTE ENCRYPTION (DEK encrypts notes) ========================

    /**
     * Encrypt plaintext note field using AES-256-GCM with DEK.
     * Each call uses a RANDOM IV.
     *
     * @param plaintext text to encrypt
     * @param dek       byte[32] data encryption key
     * @return "ivHex:ciphertextHex" for SQLite storage, or "" for null/empty, or null on failure
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
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));

            // Store as ivHex:ciphertextHex (includes appended GCM tag)
            return bytesToHex(iv) + ":" + bytesToHex(ciphertext);
        } catch (Exception e) {
            Log.e(TAG, "encrypt note failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Decrypt note field using AES-256-GCM with DEK.
     *
     * @param encryptedData "ivHex:ciphertextHex"
     * @param dek           byte[32] data encryption key
     * @return decrypted plaintext, original data if not encrypted format, null on decrypt failure
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
                return encryptedData; // Not encrypted, return as-is
            }
            String ivHex = encryptedData.substring(0, colonIdx);
            String cipherHex = encryptedData.substring(colonIdx + 1);

            if (ivHex.length() != GCM_IV_LENGTH * 2) {
                return encryptedData; // Not encrypted format
            }

            // Validate hex chars
            for (int i = 0; i < ivHex.length(); i++) {
                char c = ivHex.charAt(i);
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                    return encryptedData;
                }
            }

            byte[] iv = hexToBytes(ivHex);
            byte[] ciphertext = hexToBytes(cipherHex);

            SecretKeySpec keySpec = new SecretKeySpec(dek, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] plainBytes = cipher.doFinal(ciphertext);

            return new String(plainBytes, "UTF-8");
        } catch (Exception e) {
            // Decryption failed -- wrong key or corrupted
            return null;
        }
    }

    /**
     * Safe decrypt with fallback marker for UI display.
     */
    public static final String DECRYPT_FAILED_MARKER = "[DECRYPTION_FAILED]";

    public static String decryptSafe(String encryptedData, byte[] dek) {
        if (encryptedData == null || encryptedData.length() == 0) {
            return "";
        }
        if (dek == null) {
            if (isEncrypted(encryptedData)) {
                return DECRYPT_FAILED_MARKER;
            }
            return encryptedData;
        }
        String result = decrypt(encryptedData, dek);
        if (result == null) {
            return DECRYPT_FAILED_MARKER;
        }
        return result;
    }

    // ======================== LEGACY DECRYPTION ========================

    /**
     * Decrypt data using a legacy key (old CryptoUtils single-layer system).
     * Same AES-256-GCM format (ivHex:ciphertextHex).
     */
    public static String decryptWithLegacyKey(String encryptedData, byte[] legacyKey) {
        return decrypt(encryptedData, legacyKey);
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

    // ======================== VAULT BUNDLE ========================

    /**
     * Holds the result of DEK encryption for Firestore storage.
     * All fields are Base64 encoded strings.
     */
    public static class VaultBundle {
        public String encryptedDEK; // Base64 ciphertext (without tag)
        public String iv;           // Base64 IV
        public String tag;          // Base64 GCM auth tag
    }
}
