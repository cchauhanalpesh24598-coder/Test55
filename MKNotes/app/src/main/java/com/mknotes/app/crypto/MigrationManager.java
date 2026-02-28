package com.mknotes.app.crypto;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;

import com.mknotes.app.db.NotesDatabaseHelper;
import com.mknotes.app.util.CryptoUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;

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
}
