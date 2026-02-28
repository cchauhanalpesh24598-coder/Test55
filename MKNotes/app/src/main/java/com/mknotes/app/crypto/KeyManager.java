package com.mknotes.app.crypto;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import com.google.firebase.firestore.FirebaseFirestore;
import com.google.firebase.firestore.SetOptions;

import com.mknotes.app.cloud.FirebaseAuthManager;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Singleton that manages the entire 2-layer key lifecycle.
 *
 * Internal state: private byte[] cachedDEK -- the only in-memory copy of DEK.
 *
 * - initializeVault(): first-time setup (generates salt, DEK, encrypts DEK, HMAC tag)
 * - unlockVault(): derives master key, HMAC-verifies, decrypts DEK
 * - lockVault(): zeros DEK byte[], nullifies reference
 * - getDEK(): returns COPY of cached DEK (caller must zero their copy when done)
 * - changePassword(): re-wraps DEK with new master key, notes NOT re-encrypted
 *
 * Vault metadata stored in:
 * - Firestore: users/{uid}/vault/crypto_metadata
 * - Local: SharedPreferences (cache for fast offline access)
 *
 * PBKDF2 iterations are ALWAYS read from stored metadata, never hardcoded.
 * DEFAULT_ITERATIONS is used ONLY when creating a brand-new vault.
 */
public class KeyManager {

    private static final String TAG = "KeyManager";
    private static final String PREFS_NAME = "mknotes_vault";
    private static final String KEY_SALT = "vault_salt";
    private static final String KEY_ENCRYPTED_DEK = "vault_encrypted_dek";
    private static final String KEY_VERIFY_TAG = "vault_verify_tag";
    private static final String KEY_ITERATIONS = "vault_iterations";
    private static final String KEY_KEY_VERSION = "vault_key_version";
    private static final String KEY_VAULT_VERSION = "vault_version";
    private static final String KEY_CREATED_AT = "vault_created_at";
    private static final String KEY_UPDATED_AT = "vault_updated_at";

    /** Vault version 2 = new 2-layer DEK system. Version 1 or absent = old single-layer. */
    public static final int CURRENT_VAULT_VERSION = 2;

    private static KeyManager sInstance;

    private final SharedPreferences prefs;
    private final Context appContext;

    /**
     * In-memory cached DEK. This is the ONLY copy in memory.
     * NEVER stored as String. Zeroed on lockVault().
     */
    private byte[] cachedDEK;

    public static synchronized KeyManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new KeyManager(context.getApplicationContext());
        }
        return sInstance;
    }

    private KeyManager(Context context) {
        this.appContext = context;
        this.prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        this.cachedDEK = null;
    }

    // ======================== STATE CHECKS ========================

    /**
     * Check if vault has been initialized (crypto_metadata exists locally).
     */
    public boolean isVaultInitialized() {
        String salt = prefs.getString(KEY_SALT, null);
        String encDEK = prefs.getString(KEY_ENCRYPTED_DEK, null);
        String tag = prefs.getString(KEY_VERIFY_TAG, null);
        return salt != null && encDEK != null && tag != null;
    }

    /**
     * Check if vault is currently unlocked (DEK is in memory).
     */
    public boolean isVaultUnlocked() {
        return cachedDEK != null;
    }

    /**
     * Get stored iteration count from local metadata.
     * Falls back to DEFAULT_ITERATIONS only when no metadata exists (impossible after init).
     */
    public int getIterations() {
        return prefs.getInt(KEY_ITERATIONS, CryptoManager.DEFAULT_ITERATIONS);
    }

    /**
     * Get the current vault version. 0 or 1 = old system, 2 = new DEK system.
     */
    public int getVaultVersion() {
        return prefs.getInt(KEY_VAULT_VERSION, 0);
    }

    /**
     * Check if migration from old system is needed.
     */
    public boolean needsMigration() {
        return getVaultVersion() < CURRENT_VAULT_VERSION;
    }

    // ======================== VAULT INITIALIZATION ========================

    /**
     * First-time vault setup: generate salt, DEK, encrypt DEK, compute HMAC tag.
     * Uses DEFAULT_ITERATIONS for the brand-new vault.
     *
     * @param password user's chosen master password
     * @return true on success
     */
    public boolean initializeVault(String password) {
        if (password == null || password.length() == 0) {
            return false;
        }

        byte[] salt = null;
        byte[] masterKey = null;
        byte[] dek = null;

        try {
            // Generate fresh salt and DEK
            salt = CryptoManager.generateSalt();
            dek = CryptoManager.generateDEK();

            int iterations = CryptoManager.DEFAULT_ITERATIONS;

            // Derive master key (KEK)
            masterKey = CryptoManager.deriveKey(password, salt, iterations);
            if (masterKey == null) {
                return false;
            }

            // Encrypt DEK with master key
            String encryptedDEK = CryptoManager.encryptDEK(dek, masterKey);
            if (encryptedDEK == null) {
                return false;
            }

            // Compute HMAC verification tag
            String verifyTag = CryptoManager.computeVerifyTag(masterKey);
            if (verifyTag == null) {
                return false;
            }

            // Zero-fill master key IMMEDIATELY after use
            CryptoManager.zeroFill(masterKey);
            masterKey = null;

            String saltHex = CryptoManager.bytesToHex(salt);
            long now = System.currentTimeMillis();

            // Store locally
            prefs.edit()
                    .putString(KEY_SALT, saltHex)
                    .putString(KEY_ENCRYPTED_DEK, encryptedDEK)
                    .putString(KEY_VERIFY_TAG, verifyTag)
                    .putInt(KEY_ITERATIONS, iterations)
                    .putInt(KEY_KEY_VERSION, 1)
                    .putInt(KEY_VAULT_VERSION, CURRENT_VAULT_VERSION)
                    .putLong(KEY_CREATED_AT, now)
                    .putLong(KEY_UPDATED_AT, now)
                    .commit();

            // Upload to Firestore
            uploadVaultToFirestore();

            // Cache DEK in memory (byte[], not String)
            cachedDEK = dek;
            dek = null; // Prevent zeroFill in finally

            Log.d(TAG, "Vault initialized successfully with " + iterations + " iterations");
            return true;

        } catch (Exception e) {
            Log.e(TAG, "Vault initialization failed: " + e.getMessage());
            return false;
        } finally {
            CryptoManager.zeroFill(masterKey);
            CryptoManager.zeroFill(salt);
            // Only zero dek if it wasn't cached
            if (dek != null) {
                CryptoManager.zeroFill(dek);
            }
        }
    }

    // ======================== VAULT UNLOCK ========================

    /**
     * Unlock vault: derive master key, HMAC-verify, decrypt DEK.
     * Reads iterations from locally-cached metadata.
     *
     * @param password user's master password
     * @return true if password is correct and DEK is now cached
     */
    public boolean unlockVault(String password) {
        if (password == null || password.length() == 0) {
            return false;
        }
        if (!isVaultInitialized()) {
            return false;
        }

        byte[] masterKey = null;
        try {
            String saltHex = prefs.getString(KEY_SALT, null);
            String encryptedDEK = prefs.getString(KEY_ENCRYPTED_DEK, null);
            String storedTag = prefs.getString(KEY_VERIFY_TAG, null);
            int iterations = getIterations();

            if (saltHex == null || encryptedDEK == null || storedTag == null) {
                return false;
            }

            byte[] salt = CryptoManager.hexToBytes(saltHex);

            // Derive master key with stored iterations
            masterKey = CryptoManager.deriveKey(password, salt, iterations);
            if (masterKey == null) {
                return false;
            }

            // HMAC verification (constant-time)
            boolean verified = CryptoManager.verifyTag(masterKey, storedTag);
            if (!verified) {
                // Wrong password -- zero-fill and return false, no crash
                CryptoManager.zeroFill(masterKey);
                masterKey = null;
                return false;
            }

            // Decrypt DEK
            byte[] dek = CryptoManager.decryptDEK(encryptedDEK, masterKey);
            if (dek == null) {
                CryptoManager.zeroFill(masterKey);
                masterKey = null;
                return false;
            }

            // Zero-fill master key IMMEDIATELY
            CryptoManager.zeroFill(masterKey);
            masterKey = null;

            // Cache DEK
            cachedDEK = dek;

            Log.d(TAG, "Vault unlocked successfully");
            return true;

        } catch (Exception e) {
            Log.e(TAG, "Vault unlock failed: " + e.getMessage());
            return false;
        } finally {
            CryptoManager.zeroFill(masterKey);
        }
    }

    // ======================== VAULT LOCK ========================

    /**
     * Lock vault: zero-fill DEK byte[], nullify reference.
     * Called on session timeout (5 min background).
     */
    public void lockVault() {
        if (cachedDEK != null) {
            Arrays.fill(cachedDEK, (byte) 0);
            cachedDEK = null;
        }
        Log.d(TAG, "Vault locked, DEK zeroed");
    }

    // ======================== DEK ACCESS ========================

    /**
     * Get a COPY of the cached DEK. Caller must zero their copy when done.
     * Returns null if vault is locked.
     *
     * NEVER returns direct reference to internal cachedDEK.
     */
    public byte[] getDEK() {
        if (cachedDEK == null) {
            return null;
        }
        byte[] copy = new byte[cachedDEK.length];
        System.arraycopy(cachedDEK, 0, copy, 0, cachedDEK.length);
        return copy;
    }

    // ======================== PASSWORD CHANGE ========================

    /**
     * Change master password. Re-wraps DEK with new master key.
     * Notes are NOT re-encrypted (they use DEK, which doesn't change).
     *
     * @param oldPassword current master password
     * @param newPassword new master password
     * @return true on success
     */
    public boolean changePassword(String oldPassword, String newPassword) {
        if (oldPassword == null || newPassword == null) {
            return false;
        }
        if (!isVaultInitialized()) {
            return false;
        }

        byte[] oldMasterKey = null;
        byte[] newMasterKey = null;

        try {
            String saltHex = prefs.getString(KEY_SALT, null);
            String encryptedDEK = prefs.getString(KEY_ENCRYPTED_DEK, null);
            String storedTag = prefs.getString(KEY_VERIFY_TAG, null);
            int currentIterations = getIterations();

            if (saltHex == null || encryptedDEK == null || storedTag == null) {
                return false;
            }

            byte[] oldSalt = CryptoManager.hexToBytes(saltHex);

            // Step 1: Verify old password
            oldMasterKey = CryptoManager.deriveKey(oldPassword, oldSalt, currentIterations);
            if (oldMasterKey == null) {
                return false;
            }

            boolean verified = CryptoManager.verifyTag(oldMasterKey, storedTag);
            if (!verified) {
                CryptoManager.zeroFill(oldMasterKey);
                return false;
            }

            // Step 2: Decrypt DEK with old master key
            byte[] dek = CryptoManager.decryptDEK(encryptedDEK, oldMasterKey);
            if (dek == null) {
                CryptoManager.zeroFill(oldMasterKey);
                return false;
            }

            // Zero-fill old master key immediately
            CryptoManager.zeroFill(oldMasterKey);
            oldMasterKey = null;

            // Step 3: Generate new salt, derive new master key
            byte[] newSalt = CryptoManager.generateSalt();
            // Use same iterations or optionally upgrade to DEFAULT_ITERATIONS
            int newIterations = Math.max(currentIterations, CryptoManager.DEFAULT_ITERATIONS);

            newMasterKey = CryptoManager.deriveKey(newPassword, newSalt, newIterations);
            if (newMasterKey == null) {
                CryptoManager.zeroFill(dek);
                return false;
            }

            // Step 4: Re-encrypt DEK with new master key
            String newEncryptedDEK = CryptoManager.encryptDEK(dek, newMasterKey);
            if (newEncryptedDEK == null) {
                CryptoManager.zeroFill(dek);
                CryptoManager.zeroFill(newMasterKey);
                return false;
            }

            // Step 5: Compute new HMAC verify tag
            String newVerifyTag = CryptoManager.computeVerifyTag(newMasterKey);
            if (newVerifyTag == null) {
                CryptoManager.zeroFill(dek);
                CryptoManager.zeroFill(newMasterKey);
                return false;
            }

            // Zero-fill new master key immediately
            CryptoManager.zeroFill(newMasterKey);
            newMasterKey = null;

            String newSaltHex = CryptoManager.bytesToHex(newSalt);
            long now = System.currentTimeMillis();
            int keyVersion = prefs.getInt(KEY_KEY_VERSION, 1) + 1;

            // Step 6: Update local storage
            prefs.edit()
                    .putString(KEY_SALT, newSaltHex)
                    .putString(KEY_ENCRYPTED_DEK, newEncryptedDEK)
                    .putString(KEY_VERIFY_TAG, newVerifyTag)
                    .putInt(KEY_ITERATIONS, newIterations)
                    .putInt(KEY_KEY_VERSION, keyVersion)
                    .putLong(KEY_UPDATED_AT, now)
                    .commit();

            // Step 7: Upload to Firestore
            uploadVaultToFirestore();

            // DEK stays the same -- keep cached
            // But update the cached copy just in case
            if (cachedDEK != null) {
                Arrays.fill(cachedDEK, (byte) 0);
            }
            cachedDEK = dek;

            Log.d(TAG, "Password changed successfully, keyVersion=" + keyVersion);
            return true;

        } catch (Exception e) {
            Log.e(TAG, "Password change failed: " + e.getMessage());
            return false;
        } finally {
            CryptoManager.zeroFill(oldMasterKey);
            CryptoManager.zeroFill(newMasterKey);
        }
    }

    // ======================== FIRESTORE SYNC ========================

    /**
     * Upload vault metadata to Firestore: users/{uid}/vault/crypto_metadata
     */
    public void uploadVaultToFirestore() {
        try {
            FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(appContext);
            if (!authManager.isLoggedIn()) {
                Log.w(TAG, "Cannot upload vault: not logged in");
                return;
            }
            String uid = authManager.getUid();
            if (uid == null) {
                return;
            }

            Map<String, Object> data = new HashMap<String, Object>();
            data.put("salt", prefs.getString(KEY_SALT, ""));
            data.put("encryptedDEK", prefs.getString(KEY_ENCRYPTED_DEK, ""));
            data.put("verifyTag", prefs.getString(KEY_VERIFY_TAG, ""));
            data.put("iterations", Integer.valueOf(getIterations()));
            data.put("keyVersion", Integer.valueOf(prefs.getInt(KEY_KEY_VERSION, 1)));
            data.put("createdAt", Long.valueOf(prefs.getLong(KEY_CREATED_AT, System.currentTimeMillis())));
            data.put("updatedAt", Long.valueOf(System.currentTimeMillis()));

            FirebaseFirestore.getInstance()
                    .collection("users").document(uid)
                    .collection("vault").document("crypto_metadata")
                    .set(data, SetOptions.merge())
                    .addOnSuccessListener(unused ->
                            Log.d(TAG, "Vault metadata uploaded to Firestore"))
                    .addOnFailureListener(e ->
                            Log.e(TAG, "Vault upload failed: " + e.getMessage()));

        } catch (Exception e) {
            Log.e(TAG, "Vault upload exception: " + e.getMessage());
        }
    }

    /**
     * Fetch vault metadata from Firestore and cache locally.
     * Used on reinstall/new device after Firebase login.
     *
     * @param callback called with true if vault found & cached, false otherwise
     */
    public void fetchVaultFromFirestore(final VaultFetchCallback callback) {
        try {
            FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(appContext);
            if (!authManager.isLoggedIn()) {
                if (callback != null) callback.onResult(false);
                return;
            }
            String uid = authManager.getUid();
            if (uid == null) {
                if (callback != null) callback.onResult(false);
                return;
            }

            FirebaseFirestore.getInstance()
                    .collection("users").document(uid)
                    .collection("vault").document("crypto_metadata")
                    .get()
                    .addOnSuccessListener(doc -> {
                        if (doc.exists()) {
                            Map<String, Object> data = doc.getData();
                            if (data != null) {
                                String salt = getStringFromMap(data, "salt");
                                String encDEK = getStringFromMap(data, "encryptedDEK");
                                String tag = getStringFromMap(data, "verifyTag");
                                int iterations = getIntFromMap(data, "iterations");
                                int keyVer = getIntFromMap(data, "keyVersion");
                                long createdAt = getLongFromMap(data, "createdAt");
                                long updatedAt = getLongFromMap(data, "updatedAt");

                                if (salt.length() > 0 && encDEK.length() > 0 && tag.length() > 0) {
                                    if (iterations <= 0) {
                                        iterations = CryptoManager.DEFAULT_ITERATIONS;
                                    }
                                    if (keyVer <= 0) {
                                        keyVer = 1;
                                    }

                                    prefs.edit()
                                            .putString(KEY_SALT, salt)
                                            .putString(KEY_ENCRYPTED_DEK, encDEK)
                                            .putString(KEY_VERIFY_TAG, tag)
                                            .putInt(KEY_ITERATIONS, iterations)
                                            .putInt(KEY_KEY_VERSION, keyVer)
                                            .putInt(KEY_VAULT_VERSION, CURRENT_VAULT_VERSION)
                                            .putLong(KEY_CREATED_AT, createdAt)
                                            .putLong(KEY_UPDATED_AT, updatedAt)
                                            .commit();

                                    Log.d(TAG, "Vault metadata fetched from Firestore, iterations=" + iterations);
                                    if (callback != null) callback.onResult(true);
                                    return;
                                }
                            }
                        }
                        Log.d(TAG, "No vault metadata found in Firestore");
                        if (callback != null) callback.onResult(false);
                    })
                    .addOnFailureListener(e -> {
                        Log.e(TAG, "Vault fetch failed: " + e.getMessage());
                        if (callback != null) callback.onResult(false);
                    });

        } catch (Exception e) {
            Log.e(TAG, "Vault fetch exception: " + e.getMessage());
            if (callback != null) callback.onResult(false);
        }
    }

    // ======================== MIGRATION SUPPORT ========================

    /**
     * Store vault metadata locally after migration.
     * Called by MigrationManager after successful migration.
     */
    public void storeVaultLocally(String saltHex, String encryptedDEK, String verifyTag,
                                  int iterations, int keyVersion) {
        long now = System.currentTimeMillis();
        prefs.edit()
                .putString(KEY_SALT, saltHex)
                .putString(KEY_ENCRYPTED_DEK, encryptedDEK)
                .putString(KEY_VERIFY_TAG, verifyTag)
                .putInt(KEY_ITERATIONS, iterations)
                .putInt(KEY_KEY_VERSION, keyVersion)
                .putInt(KEY_VAULT_VERSION, CURRENT_VAULT_VERSION)
                .putLong(KEY_CREATED_AT, now)
                .putLong(KEY_UPDATED_AT, now)
                .commit();
    }

    /**
     * Set cached DEK directly. Used by MigrationManager after migration.
     */
    public void setCachedDEK(byte[] dek) {
        if (cachedDEK != null) {
            Arrays.fill(cachedDEK, (byte) 0);
        }
        cachedDEK = dek;
    }

    // ======================== LOCAL METADATA ACCESS ========================

    /**
     * Get stored salt hex from local cache.
     */
    public String getSaltHex() {
        return prefs.getString(KEY_SALT, null);
    }

    /**
     * Get stored encrypted DEK from local cache.
     */
    public String getEncryptedDEK() {
        return prefs.getString(KEY_ENCRYPTED_DEK, null);
    }

    /**
     * Get stored verify tag from local cache.
     */
    public String getVerifyTag() {
        return prefs.getString(KEY_VERIFY_TAG, null);
    }

    // ======================== HELPERS ========================

    private String getStringFromMap(Map<String, Object> map, String key) {
        Object val = map.get(key);
        if (val instanceof String) return (String) val;
        return "";
    }

    private int getIntFromMap(Map<String, Object> map, String key) {
        Object val = map.get(key);
        if (val instanceof Integer) return ((Integer) val).intValue();
        if (val instanceof Long) return ((Long) val).intValue();
        if (val instanceof Number) return ((Number) val).intValue();
        return 0;
    }

    private long getLongFromMap(Map<String, Object> map, String key) {
        Object val = map.get(key);
        if (val instanceof Long) return ((Long) val).longValue();
        if (val instanceof Number) return ((Number) val).longValue();
        return 0;
    }

    // ======================== ASYNC PASSWORD CHANGE ========================

    /**
     * Change master password asynchronously. Re-wraps DEK with new master key.
     * Notes are NOT re-encrypted (they use DEK, which doesn't change).
     * Runs PBKDF2 derivation on a background thread to avoid blocking UI.
     *
     * @param oldPassword current master password
     * @param newPassword new master password
     * @param callback    called on main thread with success or error
     */
    public void changePassword(final String oldPassword, final String newPassword,
                                final VaultCallback callback) {
        new Thread(new Runnable() {
            public void run() {
                boolean success = changePassword(oldPassword, newPassword);
                if (callback != null) {
                    if (success) {
                        callback.onSuccess();
                    } else {
                        // Determine error type
                        // If old password failed HMAC, it's "Old password"
                        callback.onError("Old password incorrect or crypto error");
                    }
                }
            }
        }).start();
    }

    // ======================== BACKUP/RESTORE SUPPORT ========================

    /**
     * Restore vault metadata from a backup file (JSON import).
     * Stores salt, encryptedDEK, verifyTag, iterations locally.
     * User still needs to enter master password to unlock.
     */
    public void restoreVaultFromBackup(String saltHex, String encryptedDEK,
                                        String verifyTag, int iterations) {
        if (iterations <= 0) {
            iterations = CryptoManager.DEFAULT_ITERATIONS;
        }
        long now = System.currentTimeMillis();
        prefs.edit()
                .putString(KEY_SALT, saltHex)
                .putString(KEY_ENCRYPTED_DEK, encryptedDEK)
                .putString(KEY_VERIFY_TAG, verifyTag)
                .putInt(KEY_ITERATIONS, iterations)
                .putInt(KEY_KEY_VERSION, 1)
                .putInt(KEY_VAULT_VERSION, CURRENT_VAULT_VERSION)
                .putLong(KEY_CREATED_AT, now)
                .putLong(KEY_UPDATED_AT, now)
                .commit();
    }

    // ======================== LOCAL METADATA ALIASES ========================

    /**
     * Alias for getSaltHex() - used by SettingsActivity backup.
     */
    public String getLocalSalt() {
        return prefs.getString(KEY_SALT, null);
    }

    /**
     * Alias for getEncryptedDEK() - used by SettingsActivity backup.
     */
    public String getLocalEncryptedDEK() {
        return prefs.getString(KEY_ENCRYPTED_DEK, null);
    }

    /**
     * Alias for getVerifyTag() - used by SettingsActivity backup.
     */
    public String getLocalVerifyTag() {
        return prefs.getString(KEY_VERIFY_TAG, null);
    }

    // ======================== CALLBACKS ========================

    public interface VaultFetchCallback {
        void onResult(boolean vaultFound);
    }

    /**
     * Callback for async vault operations (password change, etc).
     */
    public interface VaultCallback {
        void onSuccess();
        void onError(String error);
    }
}
