package com.mknotes.app.crypto;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.util.Base64;
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
 * Handles migration from old single-layer encryption to new 2-layer DEK system.
 *
 * Migration steps:
 * 1. Create full SQLite .db backup
 * 2. Derive old master key from password + old salt (old iterations)
 * 3. Generate new DEK
 * 4. In SQLite transaction: decrypt all notes with old key, re-encrypt with new DEK
 * 5. Derive new master key with 120000 iterations + new salt
 * 6. Encrypt DEK with new master key (AES-256-GCM, separate IV and tag)
 * 7. Store new vault metadata in Firestore + local SharedPreferences
 * 8. Delete backup ONLY after full success
 *
 * On failure: restore SQLite from backup, old data fully preserved.
 */
public class MigrationManager {

    private static final String TAG = "MigrationManager";
    private static final String DB_NAME = "mknotes.db";
    private static final String BACKUP_SUFFIX = ".pre_migration.bak";

    /**
     * Perform full migration from old single-layer to new 2-layer DEK system.
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
            // Step 1: Create SQLite backup
            if (!createDatabaseBackup(dbFile, backupFile)) {
                Log.e(TAG, "Migration failed: backup creation failed");
                return false;
            }

            // Step 2: Derive old master key
            oldMasterKey = CryptoUtils.deriveKey(password, oldSalt);
            if (oldMasterKey == null) {
                restoreBackup(dbFile, backupFile);
                return false;
            }

            // Step 3: Generate new DEK
            newDEK = CryptoManager.generateDEK();

            // Step 4: Re-encrypt all notes
            boolean reEncryptSuccess = reEncryptAllData(context, oldMasterKey, newDEK);
            if (!reEncryptSuccess) {
                CryptoManager.zeroFill(oldMasterKey);
                restoreBackup(dbFile, backupFile);
                return false;
            }

            CryptoManager.zeroFill(oldMasterKey);
            oldMasterKey = null;

            // Step 5: Derive new master key (FIXED 120000 iterations)
            byte[] newSalt = CryptoManager.generateSalt();
            newMasterKey = CryptoManager.deriveMasterKey(password, newSalt);
            if (newMasterKey == null) {
                restoreBackup(dbFile, backupFile);
                return false;
            }

            // Step 6: Encrypt DEK with new master key
            CryptoManager.VaultBundle bundle = CryptoManager.encryptDEK(newDEK, newMasterKey);
            if (bundle == null) {
                CryptoManager.zeroFill(newMasterKey);
                restoreBackup(dbFile, backupFile);
                return false;
            }

            CryptoManager.zeroFill(newMasterKey);
            newMasterKey = null;

            String saltB64 = Base64.encodeToString(newSalt, Base64.NO_WRAP);
            long createdAt = System.currentTimeMillis();

            // Step 7: Store vault metadata
            KeyManager km = KeyManager.getInstance(context);
            km.storeVaultLocally(saltB64, bundle.encryptedDEK, bundle.iv, bundle.tag, createdAt);
            km.uploadVaultToFirestore();
            km.setCachedDEK(newDEK);
            newDEK = null; // Prevent zeroFill

            Log.d(TAG, "[VAULT_CREATED] Migration completed successfully");

            // Step 8: Delete backup
            if (backupFile.exists()) backupFile.delete();
            return true;

        } catch (Exception e) {
            Log.e(TAG, "Migration exception: " + e.getMessage());
            restoreBackup(dbFile, backupFile);
            return false;
        } finally {
            CryptoManager.zeroFill(oldMasterKey);
            CryptoManager.zeroFill(newMasterKey);
            if (newDEK != null) CryptoManager.zeroFill(newDEK);
        }
    }

    /**
     * Re-encrypt all notes and trash data within a SQLite transaction.
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

                    String plainTitle = CryptoUtils.decrypt(encTitle, oldKey);
                    String plainContent = CryptoUtils.decrypt(encContent, oldKey);
                    String plainChecklist = CryptoUtils.decrypt(encChecklist, oldKey);
                    String plainRoutine = CryptoUtils.decrypt(encRoutine, oldKey);

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

                    String plainTitle = CryptoUtils.decrypt(encTitle, oldKey);
                    String plainContent = CryptoUtils.decrypt(encContent, oldKey);
                    String plainChecklist = CryptoUtils.decrypt(encChecklist, oldKey);

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

    private static String encryptSafe(String plaintext, byte[] dek) {
        if (plaintext == null || plaintext.length() == 0) return "";
        String encrypted = CryptoManager.encrypt(plaintext, dek);
        return encrypted != null ? encrypted : plaintext;
    }

    private static boolean createDatabaseBackup(File source, File destination) {
        if (!source.exists()) return false;
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
            return false;
        } finally {
            closeQuietly(inChannel);
            closeQuietly(outChannel);
            closeQuietly(fis);
            closeQuietly(fos);
        }
    }

    private static void restoreBackup(File dbFile, File backupFile) {
        if (!backupFile.exists()) return;
        try {
            if (dbFile.exists()) dbFile.delete();
            boolean renamed = backupFile.renameTo(dbFile);
            if (!renamed) {
                createDatabaseBackup(backupFile, dbFile);
                backupFile.delete();
            }
        } catch (Exception e) {
            Log.e(TAG, "Restore from backup failed: " + e.getMessage());
        }
    }

    private static void closeQuietly(java.io.Closeable closeable) {
        if (closeable != null) {
            try { closeable.close(); } catch (IOException ignored) {}
        }
    }

    // ======================== LEGACY CLOUD-ONLY MIGRATION ========================

    public interface LegacyMigrationCallback {
        void onSuccess();
        void onFailure(String error);
    }

    /**
     * Verify if a legacy master password can decrypt a sample cloud note.
     */
    public static void verifyLegacyPassword(final Context context, final String password,
                                             final LegacyMigrationCallback callback) {
        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(context);
        if (!authManager.isLoggedIn() || authManager.getUid() == null) {
            if (callback != null) callback.onFailure("Not logged in");
            return;
        }
        final String uid = authManager.getUid();

        FirebaseFirestore.getInstance()
                .collection("users").document(uid)
                .collection("notes")
                .limit(1)
                .get()
                .addOnSuccessListener(querySnapshot -> {
                    if (querySnapshot == null || querySnapshot.isEmpty()) {
                        if (callback != null) callback.onFailure("No notes found for verification");
                        return;
                    }

                    DocumentSnapshot doc = querySnapshot.getDocuments().get(0);
                    Map<String, Object> data = doc.getData();
                    if (data == null) {
                        if (callback != null) callback.onFailure("Note data is null");
                        return;
                    }

                    String sampleEncrypted = getEncryptedField(data);
                    if (sampleEncrypted == null) {
                        // Notes might be plaintext -- allow migration
                        if (callback != null) callback.onSuccess();
                        return;
                    }

                    byte[] legacyKey = null;
                    boolean decryptSuccess = false;

                    try {
                        com.mknotes.app.util.SessionManager sm =
                                com.mknotes.app.util.SessionManager.getInstance(context);
                        String oldSaltHex = sm.getOldSaltHex();

                        if (oldSaltHex != null) {
                            byte[] oldSalt = CryptoUtils.hexToBytes(oldSaltHex);
                            legacyKey = CryptoUtils.deriveKey(password, oldSalt);
                            if (legacyKey != null) {
                                String result = CryptoManager.decryptWithLegacyKey(sampleEncrypted, legacyKey);
                                if (result != null) decryptSuccess = true;
                                CryptoManager.zeroFill(legacyKey);
                                legacyKey = null;
                            }
                        }

                        if (!decryptSuccess) {
                            Object saltObj = data.get("salt");
                            if (saltObj instanceof String && ((String) saltObj).length() > 0) {
                                byte[] noteSalt = CryptoManager.hexToBytes((String) saltObj);
                                legacyKey = CryptoUtils.deriveKey(password, noteSalt);
                                if (legacyKey != null) {
                                    String result = CryptoManager.decryptWithLegacyKey(sampleEncrypted, legacyKey);
                                    if (result != null) decryptSuccess = true;
                                    CryptoManager.zeroFill(legacyKey);
                                    legacyKey = null;
                                }
                            }
                        }

                        if (!decryptSuccess && oldSaltHex != null) {
                            byte[] oldSalt = CryptoManager.hexToBytes(oldSaltHex);
                            legacyKey = CryptoManager.deriveLegacyKey(password, oldSalt);
                            if (legacyKey != null) {
                                String result = CryptoManager.decryptWithLegacyKey(sampleEncrypted, legacyKey);
                                if (result != null) decryptSuccess = true;
                                CryptoManager.zeroFill(legacyKey);
                                legacyKey = null;
                            }
                        }

                        if (decryptSuccess) {
                            if (callback != null) callback.onSuccess();
                        } else {
                            if (callback != null) callback.onFailure("Wrong master password");
                        }

                    } catch (Exception e) {
                        CryptoManager.zeroFill(legacyKey);
                        if (callback != null) callback.onFailure("Verification error: " + e.getMessage());
                    }
                })
                .addOnFailureListener(e -> {
                    if (callback != null) callback.onFailure("Could not fetch notes: " + e.getMessage());
                });
    }

    /**
     * Perform full legacy cloud migration.
     */
    public static void migrateLegacyCloudNotes(final Context context, final String password,
                                                final LegacyMigrationCallback callback) {
        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(context);
        if (!authManager.isLoggedIn() || authManager.getUid() == null) {
            if (callback != null) callback.onFailure("Not logged in");
            return;
        }
        final String uid = authManager.getUid();

        com.mknotes.app.util.SessionManager sm =
                com.mknotes.app.util.SessionManager.getInstance(context);
        final String oldSaltHex = sm.getOldSaltHex();

        new Thread(() -> {
            byte[] legacyKey = null;
            byte[] newDEK = null;
            byte[] newMasterKey = null;

            try {
                legacyKey = deriveLegacyKeyFromAvailableSources(context, password, oldSaltHex);
                if (legacyKey == null) {
                    postCallback(context, callback, false, "Could not derive legacy key");
                    return;
                }

                newDEK = CryptoManager.generateDEK();
                byte[] newSalt = CryptoManager.generateSalt();

                newMasterKey = CryptoManager.deriveMasterKey(password, newSalt);
                if (newMasterKey == null) {
                    CryptoManager.zeroFill(legacyKey);
                    postCallback(context, callback, false, "Could not derive new master key");
                    return;
                }

                CryptoManager.VaultBundle bundle = CryptoManager.encryptDEK(newDEK, newMasterKey);
                if (bundle == null) {
                    CryptoManager.zeroFill(legacyKey);
                    CryptoManager.zeroFill(newMasterKey);
                    postCallback(context, callback, false, "Could not encrypt DEK");
                    return;
                }

                CryptoManager.zeroFill(newMasterKey);
                newMasterKey = null;

                String saltB64 = Base64.encodeToString(newSalt, Base64.NO_WRAP);

                final byte[] finalLegacyKey = legacyKey;
                final byte[] finalNewDEK = newDEK;
                final String finalEncDEK = bundle.encryptedDEK;
                final String finalIV = bundle.iv;
                final String finalTag = bundle.tag;
                final String finalSaltB64 = saltB64;

                legacyKey = null;
                newDEK = null;

                FirebaseFirestore.getInstance()
                        .collection("users").document(uid)
                        .collection("notes")
                        .get()
                        .addOnSuccessListener(querySnapshot -> {
                            new Thread(() -> {
                                try {
                                    reEncryptAndUploadCloudNotes(
                                            context, uid, querySnapshot,
                                            finalLegacyKey, finalNewDEK,
                                            finalEncDEK, finalIV, finalTag,
                                            finalSaltB64, callback);
                                } finally {
                                    CryptoManager.zeroFill(finalLegacyKey);
                                }
                            }).start();
                        })
                        .addOnFailureListener(e -> {
                            CryptoManager.zeroFill(finalLegacyKey);
                            CryptoManager.zeroFill(finalNewDEK);
                            postCallback(context, callback, false, "Could not fetch notes: " + e.getMessage());
                        });

            } catch (Exception e) {
                CryptoManager.zeroFill(legacyKey);
                CryptoManager.zeroFill(newDEK);
                CryptoManager.zeroFill(newMasterKey);
                postCallback(context, callback, false, "Migration error: " + e.getMessage());
            }
        }).start();
    }

    private static void reEncryptAndUploadCloudNotes(
            Context context, String uid, QuerySnapshot querySnapshot,
            byte[] legacyKey, byte[] newDEK,
            String encDEKB64, String ivB64, String tagB64,
            String saltB64, LegacyMigrationCallback callback) {

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

            if (data == null) { skipCount++; continue; }

            Object deletedObj = data.get("isDeleted");
            if (deletedObj instanceof Boolean && ((Boolean) deletedObj).booleanValue()) {
                skipCount++;
                continue;
            }

            try {
                Map<String, Object> reEncrypted = new HashMap<>(data);
                reEncrypted.put("title", reEncryptField(data, "title", legacyKey, newDEK));
                reEncrypted.put("content", reEncryptField(data, "content", legacyKey, newDEK));
                if (data.containsKey("checklistData")) {
                    reEncrypted.put("checklistData", reEncryptField(data, "checklistData", legacyKey, newDEK));
                }
                if (data.containsKey("routineData")) {
                    reEncrypted.put("routineData", reEncryptField(data, "routineData", legacyKey, newDEK));
                }
                reEncrypted.put("modifiedAt", Long.valueOf(System.currentTimeMillis()));

                reEncryptedNotes.add(reEncrypted);
                noteIds.add(docId);
                successCount++;
            } catch (Exception e) {
                failCount++;
            }
        }

        if (failCount > 0 && successCount == 0) {
            postCallback(context, callback, false, "Could not re-encrypt any notes");
            return;
        }

        // Batch upload
        FirebaseFirestore db = FirebaseFirestore.getInstance();
        WriteBatch batch = db.batch();
        int batchCount = 0;

        for (int i = 0; i < reEncryptedNotes.size(); i++) {
            batch.set(
                    db.collection("users").document(uid)
                            .collection("notes").document(noteIds.get(i)),
                    reEncryptedNotes.get(i), SetOptions.merge());
            batchCount++;
            if (batchCount >= 450) {
                try {
                    com.google.android.gms.tasks.Tasks.await(batch.commit());
                } catch (Exception e) {
                    postCallback(context, callback, false, "Batch commit failed");
                    return;
                }
                batch = db.batch();
                batchCount = 0;
            }
        }

        if (batchCount > 0) {
            try {
                com.google.android.gms.tasks.Tasks.await(batch.commit());
            } catch (Exception e) {
                postCallback(context, callback, false, "Final batch commit failed");
                return;
            }
        }

        // Store vault metadata
        long createdAt = System.currentTimeMillis();
        KeyManager km = KeyManager.getInstance(context);
        km.storeVaultLocally(saltB64, encDEKB64, ivB64, tagB64, createdAt);
        km.uploadVaultToFirestore();
        km.setCachedDEK(newDEK);

        Log.d(TAG, "[VAULT_CREATED] Legacy migration completed: " + successCount + " notes migrated");
        postCallback(context, callback, true, null);
    }

    private static String reEncryptField(Map<String, Object> data, String fieldName,
                                          byte[] legacyKey, byte[] newDEK) {
        Object val = data.get(fieldName);
        if (val == null) return "";
        String strVal = val.toString();
        if (strVal.length() == 0) return "";

        if (CryptoManager.isEncrypted(strVal)) {
            String plaintext = CryptoManager.decryptWithLegacyKey(strVal, legacyKey);
            if (plaintext == null) return strVal;
            String reEncrypted = CryptoManager.encrypt(plaintext, newDEK);
            return reEncrypted != null ? reEncrypted : strVal;
        } else {
            String encrypted = CryptoManager.encrypt(strVal, newDEK);
            return encrypted != null ? encrypted : strVal;
        }
    }

    private static String getEncryptedField(Map<String, Object> data) {
        String[] fields = {"title", "content", "checklistData", "routineData"};
        for (String field : fields) {
            Object val = data.get(field);
            if (val instanceof String && CryptoManager.isEncrypted((String) val)) {
                return (String) val;
            }
        }
        return null;
    }

    private static byte[] deriveLegacyKeyFromAvailableSources(Context context, String password, String oldSaltHex) {
        byte[] key = null;
        if (oldSaltHex != null && oldSaltHex.length() > 0) {
            byte[] oldSalt = CryptoUtils.hexToBytes(oldSaltHex);
            key = CryptoUtils.deriveKey(password, oldSalt);
            if (key != null) return key;

            oldSalt = CryptoManager.hexToBytes(oldSaltHex);
            key = CryptoManager.deriveLegacyKey(password, oldSalt);
            if (key != null) return key;
        }
        return null;
    }

    private static void postCallback(Context context, LegacyMigrationCallback callback,
                                      boolean success, String error) {
        if (callback == null) return;
        if (context instanceof android.app.Activity) {
            ((android.app.Activity) context).runOnUiThread(() -> {
                if (success) callback.onSuccess();
                else callback.onFailure(error != null ? error : "Unknown error");
            });
        } else {
            if (success) callback.onSuccess();
            else callback.onFailure(error != null ? error : "Unknown error");
        }
    }
}
