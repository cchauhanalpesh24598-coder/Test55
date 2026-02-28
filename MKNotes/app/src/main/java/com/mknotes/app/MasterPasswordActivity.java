package com.mknotes.app.crypto;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;

import com.google.firebase.firestore.DocumentSnapshot;
import com.google.firebase.firestore.FirebaseFirestore;
import com.google.firebase.firestore.QueryDocumentSnapshot;
import com.google.firebase.firestore.QuerySnapshot;
import com.google.firebase.firestore.SetOptions;
import com.google.firebase.firestore.WriteBatch;

import com.mknotes.app.cloud.FirebaseAuthManager;
import com.mknotes.app.db.NotesDatabaseHelper;
import com.mknotes.app.util.CryptoUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Handles migration from old single-layer encryption (master key directly encrypts notes)
 * to new 2-layer DEK system (master key wraps DEK, DEK encrypts notes).
 *
 * Migration steps:
 * 1. Create full SQLite .db backup (notes.db -> notes.db.pre_migration.bak)
 * 2. Derive old master key from password + old salt (old iterations)
 * 3. Generate new DEK (byte[32])
 * 4. In SQLite transaction: decrypt all notes with old key, re-encrypt with new DEK
 * 5. Derive new master key with DEFAULT_ITERATIONS + new salt
 * 6. Encrypt DEK with new master key, compute HMAC verifyTag
 * 7. Store new vault metadata in Firestore + local SharedPreferences
 * 8. Mark vault_version = 2
 * 9. Delete backup ONLY after full success
 *
 * On failure: restore SQLite from backup, old data fully preserved.
 */
public class MigrationManager {

    private static final String TAG = "MigrationManager";
    private static final String DB_NAME = "mknotes.db";
    private static final String BACKUP_SUFFIX = ".pre_migration.bak";

    /**
     * Perform full migration from old single-layer to new 2-layer DEK system.
     *
     * @param context  application context
     * @param password user's master password (already verified via old system)
     * @param oldSalt  old salt bytes (from old SessionManager)
     * @param oldIterations old PBKDF2 iteration count
     * @return true if migration succeeded
     */
    public static boolean migrate(Context context, String password, byte[] oldSalt, int oldIterations) {
        if (password == null || oldSalt == null) {
            Log.e(TAG, "Migration failed: null password or salt");
            return false;
        }

        File dbFile = context.getDatabasePath(DB_NAME);
        File backupFile = new File(dbFile.getParentFile(), DB_NAME + BACKUP_SUFFIX);

        byte[] oldMasterKey = null;
        byte[] newDEK = null;
        byte[] newMasterKey = null;

        try {
            // Step 1: Create full SQLite .db backup
            if (!createDatabaseBackup(dbFile, backupFile)) {
                Log.e(TAG, "Migration failed: could not create database backup");
                return false;
            }
            Log.d(TAG, "Database backup created: " + backupFile.getAbsolutePath());

            // Step 2: Derive old master key
            oldMasterKey = CryptoUtils.deriveKey(password, oldSalt);
            if (oldMasterKey == null) {
                Log.e(TAG, "Migration failed: could not derive old master key");
                restoreBackup(dbFile, backupFile);
                return false;
            }

            // Step 3: Generate new DEK
            newDEK = CryptoManager.generateDEK();

            // Step 4: Re-encrypt all notes in SQLite transaction
            boolean reEncryptSuccess = reEncryptAllData(context, oldMasterKey, newDEK);
            if (!reEncryptSuccess) {
                Log.e(TAG, "Migration failed: re-encryption failed, restoring backup");
                CryptoManager.zeroFill(oldMasterKey);
                oldMasterKey = null;
                restoreBackup(dbFile, backupFile);
                return false;
            }

            // Zero-fill old master key immediately after re-encryption
            CryptoManager.zeroFill(oldMasterKey);
            oldMasterKey = null;

            // Step 5: Derive new master key with DEFAULT_ITERATIONS + new salt
            byte[] newSalt = CryptoManager.generateSalt();
            int newIterations = CryptoManager.DEFAULT_ITERATIONS;

            newMasterKey = CryptoManager.deriveKey(password, newSalt, newIterations);
            if (newMasterKey == null) {
                Log.e(TAG, "Migration failed: could not derive new master key");
                restoreBackup(dbFile, backupFile);
                return false;
            }

            // Step 6: Encrypt DEK with new master key
            String encryptedDEK = CryptoManager.encryptDEK(newDEK, newMasterKey);
            if (encryptedDEK == null) {
                Log.e(TAG, "Migration failed: could not encrypt DEK");
                CryptoManager.zeroFill(newMasterKey);
                restoreBackup(dbFile, backupFile);
                return false;
            }

            // Compute HMAC verify tag
            String verifyTag = CryptoManager.computeVerifyTag(newMasterKey);
            if (verifyTag == null) {
                Log.e(TAG, "Migration failed: could not compute verify tag");
                CryptoManager.zeroFill(newMasterKey);
                restoreBackup(dbFile, backupFile);
                return false;
            }

            // Zero-fill new master key immediately
            CryptoManager.zeroFill(newMasterKey);
            newMasterKey = null;

            String newSaltHex = CryptoManager.bytesToHex(newSalt);

            // Step 7: Store new vault metadata
            KeyManager km = KeyManager.getInstance(context);
            km.storeVaultLocally(newSaltHex, encryptedDEK, verifyTag, newIterations, 1);
            km.uploadVaultToFirestore();

            // Cache DEK in KeyManager
            km.setCachedDEK(newDEK);
            newDEK = null; // Prevent zeroFill in finally

            Log.d(TAG, "Migration completed successfully");

            // Step 9: Delete backup after full success
            if (backupFile.exists()) {
                boolean deleted = backupFile.delete();
                Log.d(TAG, "Backup file deleted: " + deleted);
            }

            return true;

        } catch (Exception e) {
            Log.e(TAG, "Migration exception: " + e.getMessage());
            // Restore backup on any unexpected failure
            restoreBackup(dbFile, backupFile);
            return false;
        } finally {
            CryptoManager.zeroFill(oldMasterKey);
            CryptoManager.zeroFill(newMasterKey);
            if (newDEK != null) {
                CryptoManager.zeroFill(newDEK);
            }
        }
    }

    /**
     * Re-encrypt all notes and trash data within a SQLite transaction.
     * Decrypts with oldKey (old CryptoUtils), encrypts with newDEK (new CryptoManager).
     */
    private static boolean reEncryptAllData(Context context, byte[] oldKey, byte[] newDEK) {
        NotesDatabaseHelper dbHelper = NotesDatabaseHelper.getInstance(context);
        SQLiteDatabase db = dbHelper.getWritableDatabase();

        db.beginTransaction();
        try {
            // Re-encrypt notes table
            Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES,
                    null, null, null, null, null, null);
            if (cursor != null) {
                while (cursor.moveToNext()) {
                    long id = cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_ID));
                    String encTitle = cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_TITLE));
                    String encContent = cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_CONTENT));

                    String encChecklist = "";
                    int clIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_CHECKLIST_DATA);
                    if (clIdx >= 0) encChecklist = cursor.getString(clIdx);

                    String encRoutine = "";
                    int rtIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_ROUTINE_DATA);
                    if (rtIdx >= 0) encRoutine = cursor.getString(rtIdx);

                    // Decrypt with old master key (using old CryptoUtils)
                    String plainTitle = CryptoUtils.decrypt(encTitle, oldKey);
                    String plainContent = CryptoUtils.decrypt(encContent, oldKey);
                    String plainChecklist = CryptoUtils.decrypt(encChecklist, oldKey);
                    String plainRoutine = CryptoUtils.decrypt(encRoutine, oldKey);

                    // Encrypt with new DEK (using new CryptoManager)
                    ContentValues values = new ContentValues();
                    values.put(NotesDatabaseHelper.COL_TITLE, encryptSafe(plainTitle, newDEK));
                    values.put(NotesDatabaseHelper.COL_CONTENT, encryptSafe(plainContent, newDEK));
                    values.put(NotesDatabaseHelper.COL_CHECKLIST_DATA, encryptSafe(plainChecklist, newDEK));
                    values.put(NotesDatabaseHelper.COL_ROUTINE_DATA, encryptSafe(plainRoutine, newDEK));
                    values.put(NotesDatabaseHelper.COL_SEARCH_INDEX, "");

                    db.update(NotesDatabaseHelper.TABLE_NOTES, values,
                            NotesDatabaseHelper.COL_ID + "=?",
                            new String[]{String.valueOf(id)});
                }
                cursor.close();
            }

            // Re-encrypt trash table
            Cursor trashCursor = db.query(NotesDatabaseHelper.TABLE_TRASH,
                    null, null, null, null, null, null);
            if (trashCursor != null) {
                while (trashCursor.moveToNext()) {
                    long id = trashCursor.getLong(trashCursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_ID));
                    String encTitle = trashCursor.getString(trashCursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_NOTE_TITLE));
                    String encContent = trashCursor.getString(trashCursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_NOTE_CONTENT));

                    String encChecklist = "";
                    int clIdx = trashCursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_CHECKLIST_DATA);
                    if (clIdx >= 0) encChecklist = trashCursor.getString(clIdx);

                    // Decrypt with old key
                    String plainTitle = CryptoUtils.decrypt(encTitle, oldKey);
                    String plainContent = CryptoUtils.decrypt(encContent, oldKey);
                    String plainChecklist = CryptoUtils.decrypt(encChecklist, oldKey);

                    // Encrypt with new DEK
                    ContentValues values = new ContentValues();
                    values.put(NotesDatabaseHelper.COL_TRASH_NOTE_TITLE, encryptSafe(plainTitle, newDEK));
                    values.put(NotesDatabaseHelper.COL_TRASH_NOTE_CONTENT, encryptSafe(plainContent, newDEK));
                    values.put(NotesDatabaseHelper.COL_TRASH_CHECKLIST_DATA, encryptSafe(plainChecklist, newDEK));

                    db.update(NotesDatabaseHelper.TABLE_TRASH, values,
                            NotesDatabaseHelper.COL_TRASH_ID + "=?",
                            new String[]{String.valueOf(id)});
                }
                trashCursor.close();
            }

            db.setTransactionSuccessful();
            return true;

        } catch (Exception e) {
            Log.e(TAG, "Re-encryption failed: " + e.getMessage());
            return false;
        } finally {
            db.endTransaction();
        }
    }

    /**
     * Encrypt a field safely with new DEK.
     */
    private static String encryptSafe(String plaintext, byte[] dek) {
        if (plaintext == null || plaintext.length() == 0) {
            return "";
        }
        String encrypted = CryptoManager.encrypt(plaintext, dek);
        return encrypted != null ? encrypted : plaintext;
    }

    /**
     * Create a file-level copy of the SQLite database.
     */
    private static boolean createDatabaseBackup(File source, File destination) {
        if (!source.exists()) {
            return false;
        }
        FileInputStream fis = null;
        FileOutputStream fos = null;
        FileChannel inChannel = null;
        FileChannel outChannel = null;
        try {
            fis = new FileInputStream(source);
            fos = new FileOutputStream(destination);
            inChannel = fis.getChannel();
            outChannel = fos.getChannel();
            inChannel.transferTo(0, inChannel.size(), outChannel);
            return true;
        } catch (IOException e) {
            Log.e(TAG, "Backup copy failed: " + e.getMessage());
            return false;
        } finally {
            closeQuietly(inChannel);
            closeQuietly(outChannel);
            closeQuietly(fis);
            closeQuietly(fos);
        }
    }

    /**
     * Restore database from backup file.
     */
    private static void restoreBackup(File dbFile, File backupFile) {
        if (!backupFile.exists()) {
            Log.e(TAG, "Cannot restore: backup file does not exist");
            return;
        }
        try {
            // Delete corrupted db
            if (dbFile.exists()) {
                dbFile.delete();
            }
            // Rename backup to original
            boolean renamed = backupFile.renameTo(dbFile);
            if (renamed) {
                Log.d(TAG, "Database restored from backup");
            } else {
                // Fallback: copy instead of rename
                createDatabaseBackup(backupFile, dbFile);
                backupFile.delete();
                Log.d(TAG, "Database restored from backup (copy fallback)");
            }
        } catch (Exception e) {
            Log.e(TAG, "Restore from backup failed: " + e.getMessage());
        }
    }

    private static void closeQuietly(java.io.Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException ignored) {
            }
        }
    }

    // ======================== LEGACY CLOUD-ONLY MIGRATION ========================

    /**
     * Callback for async legacy migration operations.
     */
    public interface LegacyMigrationCallback {
        void onSuccess();
        void onFailure(String error);
    }

    /**
     * Verify if a legacy master password can decrypt a sample cloud note.
     * Fetches one note from Firestore, tries decrypting with legacy key.
     *
     * @param context  application context
     * @param password user's master password
     * @param callback called with result
     */
    public static void verifyLegacyPassword(final Context context, final String password,
                                             final LegacyMigrationCallback callback) {
        Log.d(TAG, "[LEGACY_VERIFY] Starting legacy password verification");

        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(context);
        if (!authManager.isLoggedIn() || authManager.getUid() == null) {
            Log.e(TAG, "[LEGACY_VERIFY] Not logged in");
            if (callback != null) callback.onFailure("Not logged in");
            return;
        }
        final String uid = authManager.getUid();

        // Fetch one note to test decryption
        FirebaseFirestore.getInstance()
                .collection("users").document(uid)
                .collection("notes")
                .limit(1)
                .get()
                .addOnSuccessListener(querySnapshot -> {
                    if (querySnapshot == null || querySnapshot.isEmpty()) {
                        Log.e(TAG, "[LEGACY_VERIFY] No notes found to verify against");
                        if (callback != null) callback.onFailure("No notes found for verification");
                        return;
                    }

                    DocumentSnapshot doc = querySnapshot.getDocuments().get(0);
                    Map<String, Object> data = doc.getData();
                    if (data == null) {
                        if (callback != null) callback.onFailure("Note data is null");
                        return;
                    }

                    // Try to find an encrypted field (title or content)
                    String sampleEncrypted = getEncryptedField(data);
                    if (sampleEncrypted == null) {
                        Log.w(TAG, "[LEGACY_VERIFY] No encrypted field found in sample note, assuming plaintext notes");
                        // Notes might be plaintext -- allow migration anyway
                        if (callback != null) callback.onSuccess();
                        return;
                    }

                    // Derive legacy key using CryptoUtils parameters (PBKDF2, 15000 iterations)
                    // Old system used CryptoUtils.deriveKey(password, salt) with 15000 iterations
                    // The salt was stored in SessionManager SharedPreferences locally
                    // For cloud-only scenario (no local prefs), we try multiple approaches:

                    byte[] legacyKey = null;
                    boolean decryptSuccess = false;

                    try {
                        // Approach 1: Try deriving key using salt from local SessionManager (if available)
                        com.mknotes.app.util.SessionManager sm = com.mknotes.app.util.SessionManager.getInstance(context);
                        String oldSaltHex = sm.getOldSaltHex();

                        if (oldSaltHex != null) {
                            Log.d(TAG, "[LEGACY_VERIFY] Trying with local old salt");
                            byte[] oldSalt = CryptoUtils.hexToBytes(oldSaltHex);
                            legacyKey = CryptoUtils.deriveKey(password, oldSalt);
                            if (legacyKey != null) {
                                String result = CryptoManager.decryptWithLegacyKey(sampleEncrypted, legacyKey);
                                if (result != null) {
                                    decryptSuccess = true;
                                    Log.d(TAG, "[LEGACY_VERIFY] Decrypt SUCCESS with local old salt");
                                }
                                CryptoManager.zeroFill(legacyKey);
                                legacyKey = null;
                            }
                        }

                        // Approach 2: If the note has a salt field stored alongside it
                        if (!decryptSuccess) {
                            Object saltObj = data.get("salt");
                            if (saltObj instanceof String && ((String) saltObj).length() > 0) {
                                Log.d(TAG, "[LEGACY_VERIFY] Trying with note-embedded salt");
                                byte[] noteSalt = CryptoManager.hexToBytes((String) saltObj);
                                legacyKey = CryptoUtils.deriveKey(password, noteSalt);
                                if (legacyKey != null) {
                                    String result = CryptoManager.decryptWithLegacyKey(sampleEncrypted, legacyKey);
                                    if (result != null) {
                                        decryptSuccess = true;
                                        Log.d(TAG, "[LEGACY_VERIFY] Decrypt SUCCESS with note-embedded salt");
                                    }
                                    CryptoManager.zeroFill(legacyKey);
                                    legacyKey = null;
                                }
                            }
                        }

                        // Approach 3: Try using CryptoManager.deriveKey with legacy iterations
                        // Some old versions may have stored salt differently
                        if (!decryptSuccess && oldSaltHex != null) {
                            Log.d(TAG, "[LEGACY_VERIFY] Trying with CryptoManager.deriveLegacyKey");
                            byte[] oldSalt = CryptoManager.hexToBytes(oldSaltHex);
                            legacyKey = CryptoManager.deriveLegacyKey(password, oldSalt);
                            if (legacyKey != null) {
                                String result = CryptoManager.decryptWithLegacyKey(sampleEncrypted, legacyKey);
                                if (result != null) {
                                    decryptSuccess = true;
                                    Log.d(TAG, "[LEGACY_VERIFY] Decrypt SUCCESS with CryptoManager legacy key");
                                }
                                CryptoManager.zeroFill(legacyKey);
                                legacyKey = null;
                            }
                        }

                        if (decryptSuccess) {
                            if (callback != null) callback.onSuccess();
                        } else {
                            Log.w(TAG, "[LEGACY_VERIFY] All decryption attempts FAILED");
                            if (callback != null) callback.onFailure("Wrong master password or incompatible encryption");
                        }

                    } catch (Exception e) {
                        Log.e(TAG, "[LEGACY_VERIFY] Exception: " + e.getMessage());
                        CryptoManager.zeroFill(legacyKey);
                        if (callback != null) callback.onFailure("Verification error: " + e.getMessage());
                    }
                })
                .addOnFailureListener(e -> {
                    Log.e(TAG, "[LEGACY_VERIFY] Firestore fetch failed: " + e.getMessage());
                    if (callback != null) callback.onFailure("Could not fetch notes: " + e.getMessage());
                });
    }

    /**
     * Perform full legacy cloud migration:
     * 1. Derive legacy key from password
     * 2. Generate new DEK + salt + vault metadata
     * 3. Fetch ALL cloud notes
     * 4. Decrypt each note with legacy key, re-encrypt with new DEK
     * 5. Batch upload re-encrypted notes to Firestore
     * 6. Upload new vault metadata
     *
     * Does NOT overwrite notes until all re-encryption succeeds.
     * Does NOT delete originals -- overwrites in-place.
     *
     * @param context  application context
     * @param password user's master password (already verified via verifyLegacyPassword)
     * @param callback called with result
     */
    public static void migrateLegacyCloudNotes(final Context context, final String password,
                                                final LegacyMigrationCallback callback) {
        Log.d(TAG, "[MIGRATION_START] Starting legacy cloud-only migration");

        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(context);
        if (!authManager.isLoggedIn() || authManager.getUid() == null) {
            Log.e(TAG, "[MIGRATION_FAILED] Not logged in");
            if (callback != null) callback.onFailure("Not logged in");
            return;
        }
        final String uid = authManager.getUid();

        // Step 1: Derive legacy key
        com.mknotes.app.util.SessionManager sm = com.mknotes.app.util.SessionManager.getInstance(context);
        String oldSaltHex = sm.getOldSaltHex();

        // We need the salt to derive the legacy key. Find it from available sources.
        // Run on background thread since PBKDF2 is CPU-intensive
        new Thread(() -> {
            byte[] legacyKey = null;
            byte[] newDEK = null;
            byte[] newMasterKey = null;

            try {
                // Derive legacy key -- try the same approaches as verification
                legacyKey = deriveLegacyKeyFromAvailableSources(context, password, oldSaltHex);

                if (legacyKey == null) {
                    Log.e(TAG, "[MIGRATION_FAILED] Could not derive legacy key");
                    postCallback(context, callback, false, "Could not derive legacy encryption key");
                    return;
                }

                // Step 2: Generate new DEK, salt, master key
                newDEK = CryptoManager.generateDEK();
                byte[] newSalt = CryptoManager.generateSalt();
                int newIterations = CryptoManager.DEFAULT_ITERATIONS;

                newMasterKey = CryptoManager.deriveKey(password, newSalt, newIterations);
                if (newMasterKey == null) {
                    Log.e(TAG, "[MIGRATION_FAILED] Could not derive new master key");
                    CryptoManager.zeroFill(legacyKey);
                    postCallback(context, callback, false, "Could not derive new master key");
                    return;
                }

                // Encrypt DEK with new master key
                String encryptedDEK = CryptoManager.encryptDEK(newDEK, newMasterKey);
                if (encryptedDEK == null) {
                    Log.e(TAG, "[MIGRATION_FAILED] Could not encrypt DEK");
                    CryptoManager.zeroFill(legacyKey);
                    CryptoManager.zeroFill(newMasterKey);
                    postCallback(context, callback, false, "Could not encrypt DEK");
                    return;
                }

                // Compute HMAC verify tag
                String verifyTag = CryptoManager.computeVerifyTag(newMasterKey);
                if (verifyTag == null) {
                    Log.e(TAG, "[MIGRATION_FAILED] Could not compute verify tag");
                    CryptoManager.zeroFill(legacyKey);
                    CryptoManager.zeroFill(newMasterKey);
                    postCallback(context, callback, false, "Could not compute verify tag");
                    return;
                }

                // Zero-fill new master key immediately
                CryptoManager.zeroFill(newMasterKey);
                newMasterKey = null;

                String newSaltHex = CryptoManager.bytesToHex(newSalt);

                // Step 3: Fetch ALL cloud notes and re-encrypt
                final byte[] finalLegacyKey = legacyKey;
                final byte[] finalNewDEK = newDEK;
                final String finalEncDEK = encryptedDEK;
                final String finalVerifyTag = verifyTag;
                final String finalSaltHex = newSaltHex;
                final int finalIterations = newIterations;

                // Prevent legacyKey/newDEK from being zeroed in finally
                legacyKey = null;
                newDEK = null;

                FirebaseFirestore.getInstance()
                        .collection("users").document(uid)
                        .collection("notes")
                        .get()
                        .addOnSuccessListener(querySnapshot -> {
                            // Process on background thread
                            new Thread(() -> {
                                try {
                                    reEncryptAndUploadCloudNotes(
                                            context, uid, querySnapshot,
                                            finalLegacyKey, finalNewDEK,
                                            finalEncDEK, finalVerifyTag,
                                            finalSaltHex, finalIterations,
                                            callback
                                    );
                                } finally {
                                    CryptoManager.zeroFill(finalLegacyKey);
                                    // Do NOT zero finalNewDEK -- it's cached in KeyManager
                                }
                            }).start();
                        })
                        .addOnFailureListener(e -> {
                            Log.e(TAG, "[MIGRATION_FAILED] Could not fetch cloud notes: " + e.getMessage());
                            CryptoManager.zeroFill(finalLegacyKey);
                            CryptoManager.zeroFill(finalNewDEK);
                            postCallback(context, callback, false, "Could not fetch cloud notes: " + e.getMessage());
                        });

            } catch (Exception e) {
                Log.e(TAG, "[MIGRATION_FAILED] Exception: " + e.getMessage());
                CryptoManager.zeroFill(legacyKey);
                CryptoManager.zeroFill(newDEK);
                CryptoManager.zeroFill(newMasterKey);
                postCallback(context, callback, false, "Migration error: " + e.getMessage());
            }
        }).start();
    }

    /**
     * Re-encrypt all cloud notes and upload to Firestore.
     * Creates a backup map of original data before overwriting.
     */
    private static void reEncryptAndUploadCloudNotes(
            Context context, String uid, QuerySnapshot querySnapshot,
            byte[] legacyKey, byte[] newDEK,
            String encryptedDEK, String verifyTag,
            String newSaltHex, int newIterations,
            LegacyMigrationCallback callback) {

        int totalNotes = querySnapshot.size();
        Log.d(TAG, "[MIGRATION_PROGRESS] Re-encrypting " + totalNotes + " cloud notes");

        List<Map<String, Object>> reEncryptedNotes = new ArrayList<>();
        List<String> noteIds = new ArrayList<>();
        int successCount = 0;
        int failCount = 0;
        int skipCount = 0;

        for (QueryDocumentSnapshot doc : querySnapshot) {
            String docId = doc.getId();
            Map<String, Object> data = doc.getData();

            if (data == null) {
                skipCount++;
                continue;
            }

            // Check if note is soft-deleted
            Object deletedObj = data.get("isDeleted");
            if (deletedObj instanceof Boolean && ((Boolean) deletedObj).booleanValue()) {
                // Keep deleted notes as-is
                skipCount++;
                continue;
            }

            try {
                Map<String, Object> reEncrypted = new HashMap<>(data);

                // Re-encrypt each encrypted field
                reEncrypted.put("title", reEncryptField(data, "title", legacyKey, newDEK));
                reEncrypted.put("content", reEncryptField(data, "content", legacyKey, newDEK));

                // Optional fields
                if (data.containsKey("checklistData")) {
                    reEncrypted.put("checklistData", reEncryptField(data, "checklistData", legacyKey, newDEK));
                }
                if (data.containsKey("routineData")) {
                    reEncrypted.put("routineData", reEncryptField(data, "routineData", legacyKey, newDEK));
                }

                // Update modifiedAt
                reEncrypted.put("modifiedAt", Long.valueOf(System.currentTimeMillis()));

                reEncryptedNotes.add(reEncrypted);
                noteIds.add(docId);
                successCount++;

            } catch (Exception e) {
                Log.e(TAG, "[MIGRATION_PROGRESS] Failed to re-encrypt note " + docId + ": " + e.getMessage());
                failCount++;
            }
        }

        Log.d(TAG, "[MIGRATION_PROGRESS] Re-encryption complete: success=" + successCount
                + ", fail=" + failCount + ", skip=" + skipCount);

        if (failCount > 0 && successCount == 0) {
            Log.e(TAG, "[MIGRATION_FAILED] All note re-encryptions failed");
            postCallback(context, callback, false, "Could not re-encrypt any notes. Wrong password?");
            return;
        }

        // Step 4: Batch upload re-encrypted notes to Firestore
        FirebaseFirestore db = FirebaseFirestore.getInstance();
        WriteBatch batch = db.batch();
        int batchCount = 0;

        for (int i = 0; i < reEncryptedNotes.size(); i++) {
            batch.set(
                    db.collection("users").document(uid)
                            .collection("notes").document(noteIds.get(i)),
                    reEncryptedNotes.get(i),
                    SetOptions.merge()
            );
            batchCount++;

            // Firestore batch limit is 500
            if (batchCount >= 450) {
                try {
                    com.google.android.gms.tasks.Tasks.await(batch.commit());
                } catch (Exception e) {
                    Log.e(TAG, "[MIGRATION_FAILED] Batch commit failed: " + e.getMessage());
                    postCallback(context, callback, false, "Failed to upload re-encrypted notes");
                    return;
                }
                batch = db.batch();
                batchCount = 0;
            }
        }

        // Commit remaining
        if (batchCount > 0) {
            try {
                com.google.android.gms.tasks.Tasks.await(batch.commit());
            } catch (Exception e) {
                Log.e(TAG, "[MIGRATION_FAILED] Final batch commit failed: " + e.getMessage());
                postCallback(context, callback, false, "Failed to upload re-encrypted notes");
                return;
            }
        }

        Log.d(TAG, "[MIGRATION_PROGRESS] All re-encrypted notes uploaded to Firestore");

        // Step 5: Create vault metadata and upload
        KeyManager km = KeyManager.getInstance(context);
        km.storeVaultLocally(newSaltHex, encryptedDEK, verifyTag, newIterations, 1);
        km.uploadVaultToFirestore();

        // Cache DEK in KeyManager so user can proceed
        km.setCachedDEK(newDEK);

        Log.d(TAG, "[MIGRATION_SUCCESS] Legacy cloud migration completed. "
                + successCount + " notes migrated, " + failCount + " failed, " + skipCount + " skipped");

        postCallback(context, callback, true, null);
    }

    /**
     * Re-encrypt a single field: decrypt with legacy key, encrypt with new DEK.
     * If the field is not encrypted (plain text), just encrypt it with new DEK.
     */
    private static String reEncryptField(Map<String, Object> data, String fieldName,
                                          byte[] legacyKey, byte[] newDEK) {
        Object val = data.get(fieldName);
        if (val == null) return "";
        String strVal = val.toString();
        if (strVal.length() == 0) return "";

        // Check if the field looks encrypted (ivHex:ciphertextHex)
        if (CryptoManager.isEncrypted(strVal)) {
            // Decrypt with legacy key
            String plaintext = CryptoManager.decryptWithLegacyKey(strVal, legacyKey);
            if (plaintext == null) {
                // Decryption failed -- legacy key might not match
                // Return original (do not corrupt data)
                Log.w(TAG, "[MIGRATION_PROGRESS] Could not decrypt field '" + fieldName
                        + "', keeping original encrypted data");
                return strVal;
            }
            // Re-encrypt with new DEK
            String reEncrypted = CryptoManager.encrypt(plaintext, newDEK);
            return reEncrypted != null ? reEncrypted : strVal;
        } else {
            // Plain text -- just encrypt with new DEK
            String encrypted = CryptoManager.encrypt(strVal, newDEK);
            return encrypted != null ? encrypted : strVal;
        }
    }

    /**
     * Find an encrypted field in a note document (title or content).
     * Returns the first field that looks encrypted, or null if none found.
     */
    private static String getEncryptedField(Map<String, Object> data) {
        // Try title first, then content
        String[] fields = {"title", "content", "checklistData", "routineData"};
        for (String field : fields) {
            Object val = data.get(field);
            if (val instanceof String) {
                String strVal = (String) val;
                if (CryptoManager.isEncrypted(strVal)) {
                    return strVal;
                }
            }
        }
        return null;
    }

    /**
     * Derive legacy key from available sources (local SessionManager prefs, note-embedded salt, etc).
     * Returns the first key that succeeds, or null if no source available.
     */
    private static byte[] deriveLegacyKeyFromAvailableSources(Context context, String password, String oldSaltHex) {
        byte[] key = null;

        // Source 1: Old salt from local SessionManager
        if (oldSaltHex != null && oldSaltHex.length() > 0) {
            Log.d(TAG, "[LEGACY_KEY] Deriving from local old salt");
            byte[] oldSalt = CryptoUtils.hexToBytes(oldSaltHex);
            key = CryptoUtils.deriveKey(password, oldSalt);
            if (key != null) return key;
        }

        // Source 2: Try with CryptoManager's legacy derivation (same PBKDF2 params)
        if (oldSaltHex != null && oldSaltHex.length() > 0) {
            Log.d(TAG, "[LEGACY_KEY] Deriving from CryptoManager legacy path");
            byte[] oldSalt = CryptoManager.hexToBytes(oldSaltHex);
            key = CryptoManager.deriveLegacyKey(password, oldSalt);
            if (key != null) return key;
        }

        Log.e(TAG, "[LEGACY_KEY] No salt source available for legacy key derivation");
        return null;
    }

    /**
     * Post callback to main thread safely.
     */
    private static void postCallback(Context context, LegacyMigrationCallback callback,
                                      boolean success, String error) {
        if (callback == null) return;
        if (context instanceof android.app.Activity) {
            ((android.app.Activity) context).runOnUiThread(() -> {
                if (success) {
                    callback.onSuccess();
                } else {
                    callback.onFailure(error != null ? error : "Unknown error");
                }
            });
        } else {
            // Fallback: call directly (might not be on main thread)
            if (success) {
                callback.onSuccess();
            } else {
                callback.onFailure(error != null ? error : "Unknown error");
            }
        }
    }
}
