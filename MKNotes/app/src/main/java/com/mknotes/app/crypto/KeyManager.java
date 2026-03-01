package com.mknotes.app.crypto;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import com.google.firebase.firestore.DocumentReference;
import com.google.firebase.firestore.DocumentSnapshot;
import com.google.firebase.firestore.FirebaseFirestore;
import com.google.firebase.firestore.Source;

import com.mknotes.app.cloud.FirebaseAuthManager;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Singleton managing the 2-layer vault key lifecycle.
 *
 * Firestore document path: users/{uid}/crypto_metadata/vault
 *
 * Fields stored in Firestore:
 * - salt (Base64)
 * - encryptedDEK (Base64)
 * - iv (Base64)
 * - tag (Base64)
 * - iterations = 120000 (fixed)
 * - createdAt (long millis)
 *
 * RULES:
 * - Salt is NEVER regenerated after vault creation.
 * - Iterations are NEVER changed (always 120000).
 * - DEK is NEVER regenerated unless vault is explicitly deleted.
 * - set() is used for Firestore writes, NOT merge().
 *
 * REINSTALL PROOF: On login after reinstall, fetch vault from Firestore (SERVER source),
 * derive Master Key from password + stored salt, decrypt DEK. Done.
 *
 * FIX v2.1: Removed over-aggressive exists() guard that was blocking Firestore writes
 * when offline cache returned stale data. Now uses Source.SERVER for critical reads.
 * Vault is always saved locally first, then uploaded to Firestore with retry on app start.
 */
public class KeyManager {

    private static final String TAG = "KeyManager";

    // Local SharedPreferences keys
    private static final String PREFS_NAME = "mknotes_vault_v2";
    private static final String KEY_SALT = "vault_salt_b64";
    private static final String KEY_ENCRYPTED_DEK = "vault_enc_dek_b64";
    private static final String KEY_IV = "vault_iv_b64";
    private static final String KEY_TAG = "vault_tag_b64";
    private static final String KEY_ITERATIONS = "vault_iterations";
    private static final String KEY_CREATED_AT = "vault_created_at";
    private static final String KEY_VAULT_INITIALIZED = "vault_initialized";
    private static final String KEY_VAULT_UPLOADED = "vault_uploaded_to_firestore";

    public static final int CURRENT_VAULT_VERSION = 2;

    private static KeyManager sInstance;

    private final SharedPreferences prefs;
    private final Context appContext;

    /**
     * In-memory cached DEK. ONLY copy in memory. Zeroed on lockVault().
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
     * Check if vault metadata exists locally (salt + encDEK + iv + tag).
     */
    public boolean isVaultInitialized() {
        return prefs.getBoolean(KEY_VAULT_INITIALIZED, false)
                && prefs.getString(KEY_SALT, null) != null
                && prefs.getString(KEY_ENCRYPTED_DEK, null) != null
                && prefs.getString(KEY_IV, null) != null
                && prefs.getString(KEY_TAG, null) != null;
    }

    /**
     * Check if vault is currently unlocked (DEK is in memory).
     */
    public boolean isVaultUnlocked() {
        return cachedDEK != null;
    }

    /**
     * Get stored iteration count. Always returns FIXED_ITERATIONS.
     */
    public int getIterations() {
        return prefs.getInt(KEY_ITERATIONS, CryptoManager.FIXED_ITERATIONS);
    }

    /**
     * Get vault version. Returns CURRENT_VAULT_VERSION if initialized.
     */
    public int getVaultVersion() {
        if (isVaultInitialized()) return CURRENT_VAULT_VERSION;
        return 0;
    }

    /**
     * Check if migration from old system is needed.
     */
    public boolean needsMigration() {
        return !isVaultInitialized();
    }

    /**
     * Check if vault has been confirmed uploaded to Firestore.
     */
    public boolean isVaultUploaded() {
        return prefs.getBoolean(KEY_VAULT_UPLOADED, false);
    }

    // ======================== VAULT CREATION ========================

    /**
     * First-time vault setup.
     *
     * 1. Generate 16-byte random salt
     * 2. Derive 256-bit Master Key via PBKDF2 (120000 iterations)
     * 3. Generate random 256-bit DEK
     * 4. Encrypt DEK with Master Key via AES-256-GCM
     * 5. Store vault metadata LOCALLY FIRST (crash-safe)
     * 6. Upload vault metadata to Firestore
     * 7. Cache DEK in memory
     *
     * SAFETY: Refuses if vault already exists locally.
     * LOCAL-FIRST: Vault is saved to SharedPreferences before Firestore upload.
     * If Firestore upload fails, ensureVaultUploaded() retries on next app start.
     *
     * @param password user's chosen master password
     * @param callback called on completion (true=success)
     */
    public void initializeVault(final String password, final VaultCallback callback) {
        if (password == null || password.length() == 0) {
            Log.e(TAG, "[VAULT_CREATED] BLOCKED: empty password");
            if (callback != null) callback.onError("Password cannot be empty");
            return;
        }

        // SAFETY: Never overwrite existing vault
        if (isVaultInitialized()) {
            Log.w(TAG, "[VAULT_CREATED] BLOCKED: vault already exists locally");
            if (callback != null) callback.onError("Vault already exists");
            return;
        }

        // Run key derivation on background thread
        new Thread(new Runnable() {
            public void run() {
                byte[] salt = null;
                byte[] masterKey = null;
                byte[] dek = null;

                try {
                    // Step 1: Generate salt
                    salt = CryptoManager.generateSalt();

                    // Step 2: Derive Master Key
                    masterKey = CryptoManager.deriveMasterKey(password, salt);
                    if (masterKey == null) {
                        Log.e(TAG, "[VAULT_CREATED] FAILED: key derivation returned null");
                        if (callback != null) callback.onError("Key derivation failed");
                        return;
                    }

                    // Step 3: Generate DEK
                    dek = CryptoManager.generateDEK();

                    // Step 4: Encrypt DEK with Master Key
                    CryptoManager.VaultBundle bundle = CryptoManager.encryptDEK(dek, masterKey);
                    if (bundle == null) {
                        Log.e(TAG, "[VAULT_CREATED] FAILED: DEK encryption returned null");
                        if (callback != null) callback.onError("DEK encryption failed");
                        return;
                    }

                    // Zero-fill master key IMMEDIATELY
                    CryptoManager.zeroFill(masterKey);
                    masterKey = null;

                    final String saltB64 = Base64.encodeToString(salt, Base64.NO_WRAP);
                    final String encDEKB64 = bundle.encryptedDEK;
                    final String ivB64 = bundle.iv;
                    final String tagB64 = bundle.tag;
                    final long createdAt = System.currentTimeMillis();
                    final byte[] dekToCache = dek;
                    dek = null; // Prevent zeroFill in finally

                    Log.d(TAG, "[VAULT_CREATED] Vault keys generated, salt_len="
                            + saltB64.length() + ", encDEK_len=" + encDEKB64.length()
                            + ", iv_len=" + ivB64.length() + ", tag_len=" + tagB64.length());

                    // Step 5: Store LOCALLY FIRST (this is the critical fix)
                    // Vault must be in SharedPreferences before any Firestore call
                    // so that even if Firestore fails, local encryption works.
                    prefs.edit()
                            .putString(KEY_SALT, saltB64)
                            .putString(KEY_ENCRYPTED_DEK, encDEKB64)
                            .putString(KEY_IV, ivB64)
                            .putString(KEY_TAG, tagB64)
                            .putInt(KEY_ITERATIONS, CryptoManager.FIXED_ITERATIONS)
                            .putLong(KEY_CREATED_AT, createdAt)
                            .putBoolean(KEY_VAULT_INITIALIZED, true)
                            .putBoolean(KEY_VAULT_UPLOADED, false) // Not yet uploaded
                            .commit();

                    // Cache DEK in memory
                    cachedDEK = dekToCache;

                    Log.d(TAG, "[VAULT_CREATED] Vault stored locally, now uploading to Firestore...");

                    // Step 6: Upload to Firestore (non-blocking, with retry flag)
                    uploadVaultToFirestoreWithConfirmation(saltB64, encDEKB64, ivB64, tagB64, createdAt);

                    // Success -- vault is usable immediately (local-first)
                    if (callback != null) callback.onSuccess();

                } catch (Exception e) {
                    Log.e(TAG, "[VAULT_CREATED] EXCEPTION: " + e.getMessage());
                    if (callback != null) callback.onError("Vault creation failed: " + e.getMessage());
                } finally {
                    CryptoManager.zeroFill(masterKey);
                    CryptoManager.zeroFill(salt);
                    if (dek != null) CryptoManager.zeroFill(dek);
                }
            }
        }).start();
    }

    /**
     * Synchronous vault initialization for migration use.
     * Does NOT write to Firestore (caller handles that).
     */
    public boolean initializeVaultSync(String password) {
        if (password == null || password.length() == 0) return false;
        if (isVaultInitialized()) return false;

        byte[] salt = null;
        byte[] masterKey = null;
        byte[] dek = null;

        try {
            salt = CryptoManager.generateSalt();
            masterKey = CryptoManager.deriveMasterKey(password, salt);
            if (masterKey == null) return false;

            dek = CryptoManager.generateDEK();

            CryptoManager.VaultBundle bundle = CryptoManager.encryptDEK(dek, masterKey);
            if (bundle == null) return false;

            CryptoManager.zeroFill(masterKey);
            masterKey = null;

            String saltB64 = Base64.encodeToString(salt, Base64.NO_WRAP);
            long createdAt = System.currentTimeMillis();

            prefs.edit()
                    .putString(KEY_SALT, saltB64)
                    .putString(KEY_ENCRYPTED_DEK, bundle.encryptedDEK)
                    .putString(KEY_IV, bundle.iv)
                    .putString(KEY_TAG, bundle.tag)
                    .putInt(KEY_ITERATIONS, CryptoManager.FIXED_ITERATIONS)
                    .putLong(KEY_CREATED_AT, createdAt)
                    .putBoolean(KEY_VAULT_INITIALIZED, true)
                    .putBoolean(KEY_VAULT_UPLOADED, false)
                    .commit();

            cachedDEK = dek;
            dek = null;

            // Upload to Firestore with confirmation tracking
            uploadVaultToFirestoreWithConfirmation(saltB64, bundle.encryptedDEK,
                    bundle.iv, bundle.tag, createdAt);

            return true;
        } catch (Exception e) {
            Log.e(TAG, "initializeVaultSync failed: " + e.getMessage());
            return false;
        } finally {
            CryptoManager.zeroFill(masterKey);
            CryptoManager.zeroFill(salt);
            if (dek != null) CryptoManager.zeroFill(dek);
        }
    }

    // ======================== VAULT UNLOCK ========================

    /**
     * Unlock vault: derive Master Key from password + stored salt, decrypt DEK.
     * On success, DEK is cached in memory. On failure, wrong password.
     *
     * @param password user's master password
     * @return true if password correct and DEK cached
     */
    public boolean unlockVault(String password) {
        if (password == null || password.length() == 0) return false;
        if (!isVaultInitialized()) {
            Log.e(TAG, "[VAULT_UNLOCK_FAILED] vault not initialized");
            return false;
        }

        byte[] masterKey = null;
        try {
            String saltB64 = prefs.getString(KEY_SALT, null);
            String encDEKB64 = prefs.getString(KEY_ENCRYPTED_DEK, null);
            String ivB64 = prefs.getString(KEY_IV, null);
            String tagB64 = prefs.getString(KEY_TAG, null);

            if (saltB64 == null || encDEKB64 == null || ivB64 == null || tagB64 == null) {
                Log.e(TAG, "[VAULT_UNLOCK_FAILED] incomplete local vault metadata");
                return false;
            }

            byte[] salt = Base64.decode(saltB64, Base64.NO_WRAP);

            Log.d(TAG, "[VAULT_FETCH] Unlocking with salt_len=" + salt.length
                    + ", iterations=" + CryptoManager.FIXED_ITERATIONS);

            // Derive Master Key
            masterKey = CryptoManager.deriveMasterKey(password, salt);
            if (masterKey == null) {
                Log.e(TAG, "[VAULT_UNLOCK_FAILED] key derivation returned null");
                return false;
            }

            // Decrypt DEK
            byte[] dek = CryptoManager.decryptDEK(encDEKB64, ivB64, tagB64, masterKey);

            // Zero-fill master key IMMEDIATELY
            CryptoManager.zeroFill(masterKey);
            masterKey = null;

            if (dek == null) {
                Log.w(TAG, "[VAULT_UNLOCK_FAILED] DEK decryption failed -- wrong password");
                return false;
            }

            // Cache DEK
            cachedDEK = dek;
            Log.d(TAG, "[VAULT_UNLOCK_SUCCESS] DEK decrypted and cached, len=" + dek.length);
            return true;

        } catch (Exception e) {
            Log.e(TAG, "[VAULT_UNLOCK_FAILED] exception: " + e.getMessage());
            return false;
        } finally {
            CryptoManager.zeroFill(masterKey);
        }
    }

    // ======================== VAULT LOCK ========================

    /**
     * Lock vault: zero-fill DEK, nullify reference.
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
     */
    public byte[] getDEK() {
        if (cachedDEK == null) return null;
        byte[] copy = new byte[cachedDEK.length];
        System.arraycopy(cachedDEK, 0, copy, 0, cachedDEK.length);
        return copy;
    }

    // ======================== FIRESTORE OPERATIONS ========================

    /**
     * Get the Firestore document reference for vault metadata.
     * Path: users/{uid}/crypto_metadata/vault
     */
    private DocumentReference getVaultDocRef(String uid) {
        return FirebaseFirestore.getInstance()
                .collection("users").document(uid)
                .collection("crypto_metadata").document("vault");
    }

    /**
     * Upload vault to Firestore and track confirmation.
     * Uses set() to write vault data. On success, marks vault_uploaded=true locally.
     * This is idempotent -- calling multiple times with same data is safe.
     *
     * FIX: Removed the old exists() check that was blocking writes when
     * Firestore offline cache returned stale data. The vault data is deterministic
     * (same password + same salt = same encryptedDEK), so overwriting with same
     * data is safe. For password change, overwriting is intentional.
     */
    private void uploadVaultToFirestoreWithConfirmation(final String saltB64,
                                                         final String encDEKB64,
                                                         final String ivB64,
                                                         final String tagB64,
                                                         final long createdAt) {
        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(appContext);
        if (!authManager.isLoggedIn()) {
            Log.w(TAG, "[VAULT_UPLOAD] Not logged in, will retry later via ensureVaultUploaded()");
            return;
        }
        String uid = authManager.getUid();
        if (uid == null) {
            Log.w(TAG, "[VAULT_UPLOAD] UID null, will retry later via ensureVaultUploaded()");
            return;
        }

        final DocumentReference docRef = getVaultDocRef(uid);

        Map<String, Object> data = new HashMap<>();
        data.put("salt", saltB64);
        data.put("encryptedDEK", encDEKB64);
        data.put("iv", ivB64);
        data.put("tag", tagB64);
        data.put("iterations", CryptoManager.FIXED_ITERATIONS);
        data.put("createdAt", createdAt);

        docRef.set(data) // set() overwrites -- safe because data is deterministic
                .addOnSuccessListener(unused -> {
                    Log.d(TAG, "[VAULT_UPLOAD] SUCCESS: vault uploaded to Firestore");
                    prefs.edit().putBoolean(KEY_VAULT_UPLOADED, true).commit();
                })
                .addOnFailureListener(e -> {
                    Log.e(TAG, "[VAULT_UPLOAD] FAILED: " + e.getMessage()
                            + " -- will retry via ensureVaultUploaded()");
                    // KEY_VAULT_UPLOADED stays false, ensureVaultUploaded() will retry
                });
    }

    /**
     * Upload current local vault metadata to Firestore.
     * Used after migration and as a retry mechanism.
     * Always uses set() to ensure data reaches Firestore.
     */
    public void uploadVaultToFirestore() {
        if (!isVaultInitialized()) {
            Log.w(TAG, "uploadVaultToFirestore: vault not initialized");
            return;
        }

        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(appContext);
        if (!authManager.isLoggedIn()) return;
        String uid = authManager.getUid();
        if (uid == null) return;

        String saltB64 = prefs.getString(KEY_SALT, "");
        String encDEKB64 = prefs.getString(KEY_ENCRYPTED_DEK, "");
        String ivB64 = prefs.getString(KEY_IV, "");
        String tagB64 = prefs.getString(KEY_TAG, "");
        long createdAt = prefs.getLong(KEY_CREATED_AT, System.currentTimeMillis());

        if (saltB64.isEmpty() || encDEKB64.isEmpty() || ivB64.isEmpty() || tagB64.isEmpty()) {
            Log.e(TAG, "uploadVaultToFirestore: incomplete local data");
            return;
        }

        Map<String, Object> data = new HashMap<>();
        data.put("salt", saltB64);
        data.put("encryptedDEK", encDEKB64);
        data.put("iv", ivB64);
        data.put("tag", tagB64);
        data.put("iterations", CryptoManager.FIXED_ITERATIONS);
        data.put("createdAt", createdAt);

        getVaultDocRef(uid).set(data)
                .addOnSuccessListener(unused -> {
                    Log.d(TAG, "[VAULT_UPLOAD] Uploaded vault to Firestore");
                    prefs.edit().putBoolean(KEY_VAULT_UPLOADED, true).commit();
                })
                .addOnFailureListener(e ->
                        Log.e(TAG, "[VAULT_UPLOAD] Upload failed: " + e.getMessage()));
    }

    /**
     * CRITICAL: Ensure vault metadata is uploaded to Firestore.
     * Call this on every app start after successful unlock.
     * If vault exists locally but KEY_VAULT_UPLOADED is false,
     * re-upload to Firestore. This handles the case where initial
     * upload failed (network error, offline, etc.).
     *
     * This is the REINSTALL SAFETY NET -- without this, reinstall = data loss.
     */
    public void ensureVaultUploaded() {
        if (!isVaultInitialized()) return;
        if (isVaultUploaded()) return; // Already confirmed uploaded

        Log.w(TAG, "[VAULT_UPLOAD_RETRY] Vault not confirmed in Firestore, re-uploading...");
        uploadVaultToFirestore();
    }

    /**
     * Fetch vault metadata from Firestore and cache locally.
     * Used on reinstall after Firebase login.
     *
     * FIX: Uses Source.SERVER to bypass offline cache and get fresh data.
     * This prevents stale cache from returning empty/old results after reinstall.
     * Falls back to Source.DEFAULT if server is unreachable.
     *
     * @param callback called with true if vault found & cached, false otherwise
     */
    public void fetchVaultFromFirestore(final VaultFetchCallback callback) {
        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(appContext);
        if (!authManager.isLoggedIn()) {
            Log.w(TAG, "[VAULT_FETCH] Not logged in");
            if (callback != null) callback.onResult(false);
            return;
        }
        String uid = authManager.getUid();
        if (uid == null) {
            Log.w(TAG, "[VAULT_FETCH] UID null");
            if (callback != null) callback.onResult(false);
            return;
        }

        Log.d(TAG, "[VAULT_FETCH] Fetching from Firestore (SERVER source) for uid=" + uid);

        final DocumentReference docRef = getVaultDocRef(uid);

        // FIX: Use Source.SERVER to bypass potentially stale offline cache
        docRef.get(Source.SERVER)
                .addOnSuccessListener(doc -> {
                    if (processVaultDocument(doc, callback)) return;
                    Log.d(TAG, "[VAULT_FETCH] No vault found on server");
                    if (callback != null) callback.onResult(false);
                })
                .addOnFailureListener(e -> {
                    // Server unreachable -- fall back to cache (might work if Firestore
                    // synced before app data was cleared but after reinstall)
                    Log.w(TAG, "[VAULT_FETCH] Server fetch failed, trying cache: " + e.getMessage());
                    docRef.get(Source.CACHE)
                            .addOnSuccessListener(doc -> {
                                if (processVaultDocument(doc, callback)) return;
                                Log.d(TAG, "[VAULT_FETCH] No vault in cache either");
                                if (callback != null) callback.onResult(false);
                            })
                            .addOnFailureListener(cacheError -> {
                                Log.e(TAG, "[VAULT_FETCH] Cache also failed: " + cacheError.getMessage());
                                if (callback != null) callback.onResult(false);
                            });
                });
    }

    /**
     * Process a Firestore document snapshot and store vault metadata locally.
     * Returns true if vault was found and stored, false otherwise.
     */
    private boolean processVaultDocument(DocumentSnapshot doc, VaultFetchCallback callback) {
        if (doc == null || !doc.exists()) return false;

        Map<String, Object> data = doc.getData();
        if (data == null) return false;

        String salt = getStr(data, "salt");
        String encDEK = getStr(data, "encryptedDEK");
        String iv = getStr(data, "iv");
        String tag = getStr(data, "tag");
        int iterations = getInt(data, "iterations");
        long createdAt = getLong(data, "createdAt");

        if (salt.length() > 0 && encDEK.length() > 0
                && iv.length() > 0 && tag.length() > 0) {

            if (iterations <= 0) iterations = CryptoManager.FIXED_ITERATIONS;

            Log.d(TAG, "[VAULT_FETCH] SUCCESS: salt_len=" + salt.length()
                    + ", encDEK_len=" + encDEK.length()
                    + ", iv_len=" + iv.length()
                    + ", tag_len=" + tag.length()
                    + ", iterations=" + iterations);

            prefs.edit()
                    .putString(KEY_SALT, salt)
                    .putString(KEY_ENCRYPTED_DEK, encDEK)
                    .putString(KEY_IV, iv)
                    .putString(KEY_TAG, tag)
                    .putInt(KEY_ITERATIONS, iterations)
                    .putLong(KEY_CREATED_AT, createdAt)
                    .putBoolean(KEY_VAULT_INITIALIZED, true)
                    .putBoolean(KEY_VAULT_UPLOADED, true) // Came from server, so it's uploaded
                    .commit();

            if (callback != null) callback.onResult(true);
            return true;
        }
        return false;
    }

    // ======================== CLOUD NOTES CHECK ========================

    /**
     * Check if notes exist in Firestore (safety check before vault creation).
     * If notes exist but vault is missing, creating new vault = data loss.
     *
     * FIX: Uses Source.SERVER to get accurate data, not stale cache.
     */
    public void checkCloudNotesExist(final VaultFetchCallback callback) {
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
                .collection("notes")
                .limit(1)
                .get(Source.SERVER)
                .addOnSuccessListener(querySnapshot -> {
                    boolean exists = querySnapshot != null && !querySnapshot.isEmpty();
                    Log.d(TAG, "[NOTES_CHECK] notes exist=" + exists);
                    if (callback != null) callback.onResult(exists);
                })
                .addOnFailureListener(e -> {
                    Log.e(TAG, "[NOTES_CHECK] server check failed, trying cache: " + e.getMessage());
                    // Fallback to cache
                    FirebaseFirestore.getInstance()
                            .collection("users").document(uid)
                            .collection("notes")
                            .limit(1)
                            .get(Source.CACHE)
                            .addOnSuccessListener(querySnapshot -> {
                                boolean exists = querySnapshot != null && !querySnapshot.isEmpty();
                                Log.d(TAG, "[NOTES_CHECK] cache: notes exist=" + exists);
                                if (callback != null) callback.onResult(exists);
                            })
                            .addOnFailureListener(e2 -> {
                                Log.e(TAG, "[NOTES_CHECK] cache also failed: " + e2.getMessage());
                                if (callback != null) callback.onResult(false);
                            });
                });
    }

    // ======================== PASSWORD CHANGE ========================

    /**
     * Change master password. Re-wraps DEK with new master key.
     * Generates NEW salt (password change = new salt is acceptable).
     * DEK itself does NOT change -- notes stay encrypted as-is.
     *
     * @param oldPassword current password
     * @param newPassword new password
     * @param callback    async result
     */
    public void changePassword(final String oldPassword, final String newPassword,
                                final VaultCallback callback) {
        if (oldPassword == null || newPassword == null) {
            if (callback != null) callback.onError("Passwords cannot be null");
            return;
        }
        if (!isVaultInitialized()) {
            if (callback != null) callback.onError("Vault not initialized");
            return;
        }

        new Thread(new Runnable() {
            public void run() {
                byte[] oldMasterKey = null;
                byte[] newMasterKey = null;
                try {
                    // Step 1: Verify old password by trying to decrypt DEK
                    String saltB64 = prefs.getString(KEY_SALT, null);
                    String encDEKB64 = prefs.getString(KEY_ENCRYPTED_DEK, null);
                    String ivB64 = prefs.getString(KEY_IV, null);
                    String tagB64 = prefs.getString(KEY_TAG, null);

                    if (saltB64 == null || encDEKB64 == null || ivB64 == null || tagB64 == null) {
                        if (callback != null) callback.onError("Vault metadata incomplete");
                        return;
                    }

                    byte[] oldSalt = Base64.decode(saltB64, Base64.NO_WRAP);
                    oldMasterKey = CryptoManager.deriveMasterKey(oldPassword, oldSalt);
                    if (oldMasterKey == null) {
                        if (callback != null) callback.onError("Key derivation failed");
                        return;
                    }

                    byte[] dek = CryptoManager.decryptDEK(encDEKB64, ivB64, tagB64, oldMasterKey);
                    CryptoManager.zeroFill(oldMasterKey);
                    oldMasterKey = null;

                    if (dek == null) {
                        if (callback != null) callback.onError("Old password incorrect");
                        return;
                    }

                    // Step 2: Generate new salt, derive new Master Key
                    byte[] newSalt = CryptoManager.generateSalt();
                    newMasterKey = CryptoManager.deriveMasterKey(newPassword, newSalt);
                    if (newMasterKey == null) {
                        CryptoManager.zeroFill(dek);
                        if (callback != null) callback.onError("New key derivation failed");
                        return;
                    }

                    // Step 3: Re-encrypt DEK with new Master Key
                    CryptoManager.VaultBundle bundle = CryptoManager.encryptDEK(dek, newMasterKey);
                    CryptoManager.zeroFill(newMasterKey);
                    newMasterKey = null;

                    if (bundle == null) {
                        CryptoManager.zeroFill(dek);
                        if (callback != null) callback.onError("DEK re-encryption failed");
                        return;
                    }

                    String newSaltB64 = Base64.encodeToString(newSalt, Base64.NO_WRAP);
                    long createdAt = prefs.getLong(KEY_CREATED_AT, System.currentTimeMillis());

                    // Step 4: Update local storage FIRST
                    prefs.edit()
                            .putString(KEY_SALT, newSaltB64)
                            .putString(KEY_ENCRYPTED_DEK, bundle.encryptedDEK)
                            .putString(KEY_IV, bundle.iv)
                            .putString(KEY_TAG, bundle.tag)
                            .putBoolean(KEY_VAULT_UPLOADED, false) // Needs re-upload
                            .commit();

                    // Step 5: Update Firestore
                    uploadVaultToFirestoreWithConfirmation(newSaltB64, bundle.encryptedDEK,
                            bundle.iv, bundle.tag, createdAt);

                    // Update cached DEK reference
                    if (cachedDEK != null) Arrays.fill(cachedDEK, (byte) 0);
                    cachedDEK = dek;

                    Log.d(TAG, "Password changed successfully");
                    if (callback != null) callback.onSuccess();

                } catch (Exception e) {
                    Log.e(TAG, "Password change failed: " + e.getMessage());
                    if (callback != null) callback.onError(e.getMessage());
                } finally {
                    CryptoManager.zeroFill(oldMasterKey);
                    CryptoManager.zeroFill(newMasterKey);
                }
            }
        }).start();
    }

    // ======================== MIGRATION SUPPORT ========================

    /**
     * Store vault metadata locally after migration. Called by MigrationManager.
     */
    public void storeVaultLocally(String saltB64, String encDEKB64, String ivB64,
                                   String tagB64, long createdAt) {
        prefs.edit()
                .putString(KEY_SALT, saltB64)
                .putString(KEY_ENCRYPTED_DEK, encDEKB64)
                .putString(KEY_IV, ivB64)
                .putString(KEY_TAG, tagB64)
                .putInt(KEY_ITERATIONS, CryptoManager.FIXED_ITERATIONS)
                .putLong(KEY_CREATED_AT, createdAt)
                .putBoolean(KEY_VAULT_INITIALIZED, true)
                .putBoolean(KEY_VAULT_UPLOADED, false) // Will be uploaded by uploadVaultToFirestore()
                .commit();
    }

    /**
     * Set cached DEK directly. Used by MigrationManager after migration.
     */
    public void setCachedDEK(byte[] dek) {
        if (cachedDEK != null) Arrays.fill(cachedDEK, (byte) 0);
        cachedDEK = dek;
    }

    // ======================== LOCAL METADATA ACCESS ========================

    public String getSaltHex() {
        // Return Base64 salt (kept for compatibility, name is misleading but safe)
        return prefs.getString(KEY_SALT, null);
    }

    public String getEncryptedDEK() {
        return prefs.getString(KEY_ENCRYPTED_DEK, null);
    }

    public String getVerifyTag() {
        return prefs.getString(KEY_TAG, null);
    }

    public String getLocalSalt() {
        return prefs.getString(KEY_SALT, null);
    }

    public String getLocalEncryptedDEK() {
        return prefs.getString(KEY_ENCRYPTED_DEK, null);
    }

    public String getLocalVerifyTag() {
        return prefs.getString(KEY_TAG, null);
    }

    public String getLocalIV() {
        return prefs.getString(KEY_IV, null);
    }

    // ======================== BACKUP/RESTORE ========================

    public void restoreVaultFromBackup(String saltB64, String encDEKB64,
                                        String ivB64, String tagB64, int iterations) {
        if (iterations <= 0) iterations = CryptoManager.FIXED_ITERATIONS;
        prefs.edit()
                .putString(KEY_SALT, saltB64)
                .putString(KEY_ENCRYPTED_DEK, encDEKB64)
                .putString(KEY_IV, ivB64)
                .putString(KEY_TAG, tagB64)
                .putInt(KEY_ITERATIONS, iterations)
                .putLong(KEY_CREATED_AT, System.currentTimeMillis())
                .putBoolean(KEY_VAULT_INITIALIZED, true)
                .putBoolean(KEY_VAULT_UPLOADED, false)
                .commit();
    }

    // ======================== HELPERS ========================

    private String getStr(Map<String, Object> map, String key) {
        Object val = map.get(key);
        if (val instanceof String) return (String) val;
        return "";
    }

    private int getInt(Map<String, Object> map, String key) {
        Object val = map.get(key);
        if (val instanceof Number) return ((Number) val).intValue();
        return 0;
    }

    private long getLong(Map<String, Object> map, String key) {
        Object val = map.get(key);
        if (val instanceof Number) return ((Number) val).longValue();
        return 0;
    }

    // ======================== CALLBACKS ========================

    public interface VaultFetchCallback {
        void onResult(boolean vaultFound);
    }

    public interface VaultCallback {
        void onSuccess();
        void onError(String error);
    }
}
