package com.mknotes.app.db;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

import com.mknotes.app.crypto.CryptoManager;
import com.mknotes.app.model.Category;
import com.mknotes.app.model.Mantra;
import com.mknotes.app.model.Note;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

public class NotesRepository {

    private NotesDatabaseHelper dbHelper;
    private Context appContext;
    private static NotesRepository sInstance;

    public static synchronized NotesRepository getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new NotesRepository(context);
        }
        return sInstance;
    }

    private NotesRepository(Context context) {
        dbHelper = NotesDatabaseHelper.getInstance(context);
        appContext = context.getApplicationContext();
    }

    /**
     * Get the current encryption key.
     *
     * CRITICAL FIX v3: Get DEK directly from KeyManager, bypassing SessionManager.
     * Session timeout is a UI-level concern (lock screen redirect).
     * At the data layer, if the vault is unlocked (DEK in memory), the key
     * must ALWAYS be available for encrypt/decrypt operations.
     *
     * Previous bug: getKey() went through SessionManager.getCachedKey() which
     * checked isSessionValid(). After reinstall, the session timestamp wasn't
     * flushed yet when MainActivity loaded notes, causing null key and
     * [DECRYPTION_FAILED] for all notes on first launch.
     */
    private byte[] getKey() {
        return com.mknotes.app.crypto.KeyManager.getInstance(appContext).getDEK();
    }

    /**
     * Encrypt a string field using the current key.
     * Uses new CryptoManager (2-layer DEK system).
     * Returns encrypted string or empty string if input is null/empty.
     *
     * CRITICAL FIX: If key is null, throws IllegalStateException instead of
     * silently saving plaintext. This prevents unencrypted data from being
     * written to the database when the vault is locked or DEK not ready.
     * Callers must ensure vault is unlocked before any write operation.
     */
    private String encryptField(String plaintext, byte[] key) {
        if (plaintext == null || plaintext.length() == 0) {
            return "";
        }
        if (key == null) {
            android.util.Log.e("NotesRepository", "[ENCRYPT_BLOCKED] Key is null, refusing to save plaintext");
            throw new IllegalStateException("Encryption key not available. Vault must be unlocked before writing notes.");
        }
        String encrypted = CryptoManager.encrypt(plaintext, key);
        if (encrypted == null) {
            android.util.Log.e("NotesRepository", "[ENCRYPT_FAILED] CryptoManager.encrypt returned null");
            throw new IllegalStateException("Encryption failed for field data.");
        }
        return encrypted;
    }

    /**
     * Decrypt a string field using the current key.
     * Uses new CryptoManager (2-layer DEK system).
     * On failure: returns "[Decryption Failed]" marker so UI shows proper error.
     * NEVER returns raw encrypted hex to UI.
     *
     * CRITICAL FIX v3: Simplified -- getKey() already goes directly to KeyManager.
     * No need for redundant fallback. If key is null, vault is locked.
     */
    private String decryptField(String ciphertext, byte[] key) {
        if (ciphertext == null || ciphertext.length() == 0) {
            return "";
        }

        if (key == null) {
            // Vault is locked -- if data looks encrypted, show failure marker
            if (CryptoManager.isEncrypted(ciphertext)) {
                android.util.Log.w("NotesRepository", "[DECRYPT] Key unavailable (vault locked), encrypted data cannot be shown");
                return CryptoManager.DECRYPT_FAILED_MARKER;
            }
            return ciphertext;
        }
        String decrypted = CryptoManager.decrypt(ciphertext, key);
        if (decrypted == null) {
            // Decryption failed (wrong key / corrupted) -- show failure marker
            android.util.Log.w("NotesRepository", "[DECRYPT] Decryption returned null for encrypted data");
            return CryptoManager.DECRYPT_FAILED_MARKER;
        }
        return decrypted;
    }

    // ============ NOTES ============

    public long insertNote(Note note) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        byte[] key = getKey();
        // Generate cloudId if not already set
        if (note.getCloudId() == null || note.getCloudId().length() == 0) {
            note.setCloudId(UUID.randomUUID().toString());
        }
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_TITLE, encryptField(note.getTitle(), key));
        values.put(NotesDatabaseHelper.COL_CONTENT, encryptField(note.getContent(), key));
        values.put(NotesDatabaseHelper.COL_CREATED, note.getCreatedAt());
        values.put(NotesDatabaseHelper.COL_MODIFIED, note.getModifiedAt());
        values.put(NotesDatabaseHelper.COL_COLOR, note.getColor());
        values.put(NotesDatabaseHelper.COL_FAVORITE, note.isFavorite() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_LOCKED, note.isLocked() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_PASSWORD, note.getPassword());
        values.put(NotesDatabaseHelper.COL_CATEGORY_ID, note.getCategoryId());
        values.put(NotesDatabaseHelper.COL_HAS_CHECKLIST, note.hasChecklist() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_HAS_IMAGE, note.hasImage() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_CHECKLIST_DATA, encryptField(note.getChecklistData(), key));
        values.put(NotesDatabaseHelper.COL_IS_CHECKLIST_MODE, note.isChecklistMode() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_IMAGES_DATA, note.getImagesData());
        values.put(NotesDatabaseHelper.COL_FILES_DATA, note.getFilesData());
        values.put(NotesDatabaseHelper.COL_AUDIOS_DATA, note.getAudiosData());
        values.put(NotesDatabaseHelper.COL_LINKED_NOTE_IDS, note.getLinkedNoteIds());
        values.put(NotesDatabaseHelper.COL_IS_ROUTINE_MODE, note.isRoutineMode() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_ROUTINE_DATA, encryptField(note.getRoutineData(), key));
        values.put(NotesDatabaseHelper.COL_IS_ARCHIVED, note.isArchived() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_SEARCH_INDEX, "");
        values.put(NotesDatabaseHelper.COL_CLOUD_ID, note.getCloudId());
        values.put(NotesDatabaseHelper.COL_SYNC_STATUS, Note.SYNC_STATUS_PENDING);
        long id = db.insert(NotesDatabaseHelper.TABLE_NOTES, null, values);
        return id;
    }

    public int updateNote(Note note) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        byte[] key = getKey();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_TITLE, encryptField(note.getTitle(), key));
        values.put(NotesDatabaseHelper.COL_CONTENT, encryptField(note.getContent(), key));
        values.put(NotesDatabaseHelper.COL_MODIFIED, System.currentTimeMillis());
        values.put(NotesDatabaseHelper.COL_COLOR, note.getColor());
        values.put(NotesDatabaseHelper.COL_FAVORITE, note.isFavorite() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_LOCKED, note.isLocked() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_PASSWORD, note.getPassword());
        values.put(NotesDatabaseHelper.COL_CATEGORY_ID, note.getCategoryId());
        values.put(NotesDatabaseHelper.COL_HAS_CHECKLIST, note.hasChecklist() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_HAS_IMAGE, note.hasImage() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_CHECKLIST_DATA, encryptField(note.getChecklistData(), key));
        values.put(NotesDatabaseHelper.COL_IS_CHECKLIST_MODE, note.isChecklistMode() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_IMAGES_DATA, note.getImagesData());
        values.put(NotesDatabaseHelper.COL_FILES_DATA, note.getFilesData());
        values.put(NotesDatabaseHelper.COL_AUDIOS_DATA, note.getAudiosData());
        values.put(NotesDatabaseHelper.COL_LINKED_NOTE_IDS, note.getLinkedNoteIds());
        values.put(NotesDatabaseHelper.COL_IS_ROUTINE_MODE, note.isRoutineMode() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_ROUTINE_DATA, encryptField(note.getRoutineData(), key));
        values.put(NotesDatabaseHelper.COL_IS_ARCHIVED, note.isArchived() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_SEARCH_INDEX, "");
        values.put(NotesDatabaseHelper.COL_SYNC_STATUS, Note.SYNC_STATUS_PENDING);
        return db.update(NotesDatabaseHelper.TABLE_NOTES, values,
                NotesDatabaseHelper.COL_ID + "=?",
                new String[]{String.valueOf(note.getId())});
    }

    public int deleteNote(long id) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        return db.delete(NotesDatabaseHelper.TABLE_NOTES,
                NotesDatabaseHelper.COL_ID + "=?",
                new String[]{String.valueOf(id)});
    }

    public Note getNoteById(long id) {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES,
                null,
                NotesDatabaseHelper.COL_ID + "=?",
                new String[]{String.valueOf(id)},
                null, null, null);
        Note note = null;
        if (cursor != null && cursor.moveToFirst()) {
            note = cursorToNote(cursor);
            cursor.close();
        }
        return note;
    }

    public List getAllNotes(String sortBy) {
        List notes = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        String orderBy;
        boolean sortByTitleInJava = false;
        if ("created".equals(sortBy)) {
            orderBy = NotesDatabaseHelper.COL_CREATED + " DESC";
        } else if ("title".equals(sortBy)) {
            // Encrypted titles cannot be sorted in SQL -- fetch by modified, sort in Java
            orderBy = NotesDatabaseHelper.COL_MODIFIED + " DESC";
            sortByTitleInJava = true;
        } else {
            orderBy = NotesDatabaseHelper.COL_MODIFIED + " DESC";
        }
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES,
                null, NotesDatabaseHelper.COL_IS_ARCHIVED + "=0",
                null, null, null, orderBy);
        if (cursor != null) {
            while (cursor.moveToNext()) {
                notes.add(cursorToNote(cursor));
            }
            cursor.close();
        }
        if (sortByTitleInJava) {
            sortNotesByTitle(notes);
        }
        return notes;
    }

    public List getFavoriteNotes(String sortBy) {
        List notes = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        String orderBy = NotesDatabaseHelper.COL_MODIFIED + " DESC";
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES,
                null,
                NotesDatabaseHelper.COL_FAVORITE + "=1 AND " + NotesDatabaseHelper.COL_IS_ARCHIVED + "=0",
                null, null, null, orderBy);
        if (cursor != null) {
            while (cursor.moveToNext()) {
                notes.add(cursorToNote(cursor));
            }
            cursor.close();
        }
        return notes;
    }

    public List getNotesByCategory(long categoryId, String sortBy) {
        List notes = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        String orderBy = NotesDatabaseHelper.COL_MODIFIED + " DESC";
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES,
                null,
                NotesDatabaseHelper.COL_CATEGORY_ID + "=? AND " + NotesDatabaseHelper.COL_IS_ARCHIVED + "=0",
                new String[]{String.valueOf(categoryId)},
                null, null, orderBy);
        if (cursor != null) {
            while (cursor.moveToNext()) {
                notes.add(cursorToNote(cursor));
            }
            cursor.close();
        }
        return notes;
    }

    /**
     * Search notes by decrypting all notes and matching query words in-memory.
     * Supports partial matching: "medi" matches "meditation", "medical", etc.
     * All query words must appear in the note for a match (AND logic).
     *
     * @param query the search query string
     * @return matched notes sorted by modified date DESC
     */
    public List searchNotes(String query) {
        List results = new ArrayList();
        if (query == null || query.trim().length() == 0) {
            return results;
        }

        // Load all non-trashed, non-archived notes (auto-decrypted via cursorToNote)
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES,
                null,
                NotesDatabaseHelper.COL_IS_ARCHIVED + "=0",
                null, null, null,
                NotesDatabaseHelper.COL_MODIFIED + " DESC");

        List allNotes = new ArrayList();
        if (cursor != null) {
            while (cursor.moveToNext()) {
                allNotes.add(cursorToNote(cursor));
            }
            cursor.close();
        }

        // Split query into words (lowercased, trimmed)
        String queryLower = query.toLowerCase().trim();
        String[] queryWords = queryLower.split("\\s+");

        // Filter notes: all query words must appear in decrypted title+content
        for (int i = 0; i < allNotes.size(); i++) {
            Note note = (Note) allNotes.get(i);
            String title = note.getTitle() != null ? note.getTitle() : "";
            String content = note.getContent() != null ? note.getContent() : "";
            // Strip HTML tags from content for better matching
            String stripped = content.replaceAll("<[^>]*>", " ");
            String searchable = (title + " " + stripped).toLowerCase();

            boolean matchAll = true;
            for (int w = 0; w < queryWords.length; w++) {
                String word = queryWords[w].trim();
                if (word.length() == 0) {
                    continue;
                }
                if (!searchable.contains(word)) {
                    matchAll = false;
                    break;
                }
            }
            if (matchAll) {
                results.add(note);
            }
        }

        return results;
    }

    public void toggleFavorite(long noteId) {
        Note note = getNoteById(noteId);
        if (note != null) {
            note.setFavorite(!note.isFavorite());
            updateNote(note);
        }
    }

    private Note cursorToNote(Cursor cursor) {
        byte[] key = getKey();
        Note note = new Note();
        note.setId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_ID)));
        note.setTitle(decryptField(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_TITLE)), key));
        note.setContent(decryptField(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_CONTENT)), key));
        note.setCreatedAt(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_CREATED)));
        note.setModifiedAt(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_MODIFIED)));
        note.setColor(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_COLOR)));
        note.setFavorite(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_FAVORITE)) == 1);
        note.setLocked(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_LOCKED)) == 1);
        note.setPassword(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_PASSWORD)));
        note.setCategoryId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_CATEGORY_ID)));
        note.setHasChecklist(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_HAS_CHECKLIST)) == 1);
        note.setHasImage(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_HAS_IMAGE)) == 1);
        int clDataIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_CHECKLIST_DATA);
        if (clDataIdx >= 0) {
            note.setChecklistData(decryptField(cursor.getString(clDataIdx), key));
        }
        int clModeIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_IS_CHECKLIST_MODE);
        if (clModeIdx >= 0) {
            note.setChecklistMode(cursor.getInt(clModeIdx) == 1);
        }
        int imgIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_IMAGES_DATA);
        if (imgIdx >= 0) {
            note.setImagesData(cursor.getString(imgIdx));
        }
        int filesIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_FILES_DATA);
        if (filesIdx >= 0) {
            note.setFilesData(cursor.getString(filesIdx));
        }
        int audiosIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_AUDIOS_DATA);
        if (audiosIdx >= 0) {
            note.setAudiosData(cursor.getString(audiosIdx));
        }
        int linkedIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_LINKED_NOTE_IDS);
        if (linkedIdx >= 0) {
            note.setLinkedNoteIds(cursor.getString(linkedIdx));
        }
        int routineModeIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_IS_ROUTINE_MODE);
        if (routineModeIdx >= 0) {
            note.setRoutineMode(cursor.getInt(routineModeIdx) == 1);
        }
        int routineDataIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_ROUTINE_DATA);
        if (routineDataIdx >= 0) {
            note.setRoutineData(decryptField(cursor.getString(routineDataIdx), key));
        }
        int archivedIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_IS_ARCHIVED);
        if (archivedIdx >= 0) {
            note.setArchived(cursor.getInt(archivedIdx) == 1);
        }
        int cloudIdIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_CLOUD_ID);
        if (cloudIdIdx >= 0) {
            note.setCloudId(cursor.getString(cloudIdIdx));
        }
        int syncStatusIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_SYNC_STATUS);
        if (syncStatusIdx >= 0) {
            note.setSyncStatus(cursor.getInt(syncStatusIdx));
        }
        return note;
    }

    // ============ ARCHIVE ============

    public void archiveNote(long noteId) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_IS_ARCHIVED, 1);
        db.update(NotesDatabaseHelper.TABLE_NOTES, values,
                NotesDatabaseHelper.COL_ID + "=?",
                new String[]{String.valueOf(noteId)});
    }

    public void unarchiveNote(long noteId) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_IS_ARCHIVED, 0);
        db.update(NotesDatabaseHelper.TABLE_NOTES, values,
                NotesDatabaseHelper.COL_ID + "=?",
                new String[]{String.valueOf(noteId)});
    }

    public List getArchivedNotes() {
        List notes = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES,
                null,
                NotesDatabaseHelper.COL_IS_ARCHIVED + "=1",
                null, null, null,
                NotesDatabaseHelper.COL_MODIFIED + " DESC");
        if (cursor != null) {
            while (cursor.moveToNext()) {
                notes.add(cursorToNote(cursor));
            }
            cursor.close();
        }
        return notes;
    }

    // ============ CATEGORIES ============

    public long insertCategory(Category category) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_CAT_NAME, category.getName());
        values.put(NotesDatabaseHelper.COL_CAT_COLOR, category.getColor());
        values.put(NotesDatabaseHelper.COL_CAT_ORDER, category.getSortOrder());
        return db.insert(NotesDatabaseHelper.TABLE_CATEGORIES, null, values);
    }

    public int updateCategory(Category category) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_CAT_NAME, category.getName());
        values.put(NotesDatabaseHelper.COL_CAT_COLOR, category.getColor());
        values.put(NotesDatabaseHelper.COL_CAT_ORDER, category.getSortOrder());
        return db.update(NotesDatabaseHelper.TABLE_CATEGORIES, values,
                NotesDatabaseHelper.COL_CAT_ID + "=?",
                new String[]{String.valueOf(category.getId())});
    }

    public int deleteCategory(long id) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_CATEGORY_ID, -1);
        db.update(NotesDatabaseHelper.TABLE_NOTES, values,
                NotesDatabaseHelper.COL_CATEGORY_ID + "=?",
                new String[]{String.valueOf(id)});
        return db.delete(NotesDatabaseHelper.TABLE_CATEGORIES,
                NotesDatabaseHelper.COL_CAT_ID + "=?",
                new String[]{String.valueOf(id)});
    }

    public List getAllCategories() {
        List categories = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_CATEGORIES,
                null, null, null, null, null,
                NotesDatabaseHelper.COL_CAT_ORDER + " ASC");
        if (cursor != null) {
            while (cursor.moveToNext()) {
                Category cat = new Category();
                cat.setId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_CAT_ID)));
                cat.setName(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_CAT_NAME)));
                cat.setColor(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_CAT_COLOR)));
                cat.setSortOrder(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_CAT_ORDER)));
                categories.add(cat);
            }
            cursor.close();
        }
        return categories;
    }

    public Category getCategoryById(long id) {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_CATEGORIES,
                null,
                NotesDatabaseHelper.COL_CAT_ID + "=?",
                new String[]{String.valueOf(id)},
                null, null, null);
        Category category = null;
        if (cursor != null && cursor.moveToFirst()) {
            category = new Category();
            category.setId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_CAT_ID)));
            category.setName(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_CAT_NAME)));
            category.setColor(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_CAT_COLOR)));
            category.setSortOrder(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_CAT_ORDER)));
            cursor.close();
        }
        return category;
    }

    public int getNotesCountForCategory(long categoryId) {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.rawQuery("SELECT COUNT(*) FROM " + NotesDatabaseHelper.TABLE_NOTES +
                " WHERE " + NotesDatabaseHelper.COL_CATEGORY_ID + "=?",
                new String[]{String.valueOf(categoryId)});
        int count = 0;
        if (cursor != null && cursor.moveToFirst()) {
            count = cursor.getInt(0);
            cursor.close();
        }
        return count;
    }

    // ============ TRASH ============

    public long moveToTrash(Note note) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        byte[] key = getKey();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_TRASH_NOTE_TITLE, encryptField(note.getTitle(), key));
        values.put(NotesDatabaseHelper.COL_TRASH_NOTE_CONTENT, encryptField(note.getContent(), key));
        values.put(NotesDatabaseHelper.COL_TRASH_NOTE_COLOR, note.getColor());
        values.put(NotesDatabaseHelper.COL_TRASH_NOTE_CATEGORY, note.getCategoryId());
        values.put(NotesDatabaseHelper.COL_TRASH_DATE, System.currentTimeMillis());
        values.put(NotesDatabaseHelper.COL_TRASH_ORIGINAL_ID, note.getId());
        values.put(NotesDatabaseHelper.COL_TRASH_CHECKLIST_DATA, encryptField(note.getChecklistData(), key));
        values.put(NotesDatabaseHelper.COL_TRASH_IS_CHECKLIST_MODE, note.isChecklistMode() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_TRASH_IMAGES_DATA, note.getImagesData());
        values.put(NotesDatabaseHelper.COL_TRASH_FILES_DATA, note.getFilesData());
        values.put(NotesDatabaseHelper.COL_TRASH_AUDIOS_DATA, note.getAudiosData());
        values.put(NotesDatabaseHelper.COL_TRASH_LINKED_NOTE_IDS, note.getLinkedNoteIds());
        long trashId = db.insert(NotesDatabaseHelper.TABLE_TRASH, null, values);
        deleteNote(note.getId());
        return trashId;
    }

    public List getTrashNotes() {
        List notes = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        byte[] key = getKey();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_TRASH,
                null, null, null, null, null,
                NotesDatabaseHelper.COL_TRASH_DATE + " DESC");
        if (cursor != null) {
            while (cursor.moveToNext()) {
                Note note = new Note();
                note.setId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_ID)));
                note.setTitle(decryptField(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_NOTE_TITLE)), key));
                note.setContent(decryptField(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_NOTE_CONTENT)), key));
                note.setColor(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_NOTE_COLOR)));
                note.setCategoryId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_NOTE_CATEGORY)));
                note.setModifiedAt(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_DATE)));
                notes.add(note);
            }
            cursor.close();
        }
        return notes;
    }

    public void restoreFromTrash(long trashId) {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_TRASH,
                null,
                NotesDatabaseHelper.COL_TRASH_ID + "=?",
                new String[]{String.valueOf(trashId)},
                null, null, null);
        byte[] key = getKey();
        if (cursor != null && cursor.moveToFirst()) {
            Note note = new Note();
            note.setTitle(decryptField(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_NOTE_TITLE)), key));
            note.setContent(decryptField(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_NOTE_CONTENT)), key));
            note.setColor(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_NOTE_COLOR)));
            note.setCategoryId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_NOTE_CATEGORY)));
            note.setCreatedAt(System.currentTimeMillis());
            note.setModifiedAt(System.currentTimeMillis());
            int trashClIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_CHECKLIST_DATA);
            if (trashClIdx >= 0) {
                note.setChecklistData(decryptField(cursor.getString(trashClIdx), key));
            }
            int trashClModeIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_IS_CHECKLIST_MODE);
            if (trashClModeIdx >= 0) {
                note.setChecklistMode(cursor.getInt(trashClModeIdx) == 1);
            }
            int trashImgIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_IMAGES_DATA);
            if (trashImgIdx >= 0) {
                note.setImagesData(cursor.getString(trashImgIdx));
            }
            int trashFilesIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_FILES_DATA);
            if (trashFilesIdx >= 0) {
                note.setFilesData(cursor.getString(trashFilesIdx));
            }
            int trashAudiosIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_AUDIOS_DATA);
            if (trashAudiosIdx >= 0) {
                note.setAudiosData(cursor.getString(trashAudiosIdx));
            }
            int trashLinkedIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_LINKED_NOTE_IDS);
            if (trashLinkedIdx >= 0) {
                note.setLinkedNoteIds(cursor.getString(trashLinkedIdx));
            }
            insertNote(note);
            cursor.close();
        }
        deleteFromTrash(trashId);
    }

    public int deleteFromTrash(long trashId) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        return db.delete(NotesDatabaseHelper.TABLE_TRASH,
                NotesDatabaseHelper.COL_TRASH_ID + "=?",
                new String[]{String.valueOf(trashId)});
    }

    public void emptyTrash() {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        db.delete(NotesDatabaseHelper.TABLE_TRASH, null, null);
    }

    /**
     * Delete trash notes older than 30 days.
     * Called on app startup from NotesApplication.
     */
    public void cleanupOldTrash() {
        long thirtyDaysMs = 30L * 24 * 60 * 60 * 1000;
        long cutoff = System.currentTimeMillis() - thirtyDaysMs;
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        db.delete(NotesDatabaseHelper.TABLE_TRASH,
                NotesDatabaseHelper.COL_TRASH_DATE + "<?",
                new String[]{String.valueOf(cutoff)});
    }

    /**
     * Get all notes as a List for backup/export purposes.
     */
    public List getAllNotesForBackup() {
        List notes = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES,
                null, null, null, null, null,
                NotesDatabaseHelper.COL_ID + " ASC");
        if (cursor != null) {
            while (cursor.moveToNext()) {
                notes.add(cursorToNote(cursor));
            }
            cursor.close();
        }
        return notes;
    }

    // ============ MANTRAS ============

    public long insertMantra(Mantra mantra) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_MANTRA_NOTE_ID, mantra.getNoteId());
        values.put(NotesDatabaseHelper.COL_MANTRA_NAME, mantra.getName());
        values.put(NotesDatabaseHelper.COL_MANTRA_AUDIO_PATH, mantra.getAudioPath());
        values.put(NotesDatabaseHelper.COL_MANTRA_TODAY_COUNT, mantra.getTodayCount());
        values.put(NotesDatabaseHelper.COL_MANTRA_LAST_COUNT_DATE, mantra.getLastCountDate());
        values.put(NotesDatabaseHelper.COL_MANTRA_CREATED, mantra.getCreatedAt());
        values.put(NotesDatabaseHelper.COL_MANTRA_SPEED, mantra.getPlaybackSpeed());
        values.put(NotesDatabaseHelper.COL_MANTRA_RAW_RES_ID, mantra.getRawResId());
        values.put(NotesDatabaseHelper.COL_MANTRA_BUILT_IN, mantra.isBuiltIn() ? 1 : 0);
        return db.insert(NotesDatabaseHelper.TABLE_MANTRAS, null, values);
    }

    public int updateMantra(Mantra mantra) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_MANTRA_NOTE_ID, mantra.getNoteId());
        values.put(NotesDatabaseHelper.COL_MANTRA_NAME, mantra.getName());
        values.put(NotesDatabaseHelper.COL_MANTRA_AUDIO_PATH, mantra.getAudioPath());
        values.put(NotesDatabaseHelper.COL_MANTRA_TODAY_COUNT, mantra.getTodayCount());
        values.put(NotesDatabaseHelper.COL_MANTRA_LAST_COUNT_DATE, mantra.getLastCountDate());
        values.put(NotesDatabaseHelper.COL_MANTRA_SPEED, mantra.getPlaybackSpeed());
        values.put(NotesDatabaseHelper.COL_MANTRA_RAW_RES_ID, mantra.getRawResId());
        values.put(NotesDatabaseHelper.COL_MANTRA_BUILT_IN, mantra.isBuiltIn() ? 1 : 0);
        return db.update(NotesDatabaseHelper.TABLE_MANTRAS, values,
                NotesDatabaseHelper.COL_MANTRA_ID + "=?",
                new String[]{String.valueOf(mantra.getId())});
    }

    public int deleteMantra(long mantraId) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        return db.delete(NotesDatabaseHelper.TABLE_MANTRAS,
                NotesDatabaseHelper.COL_MANTRA_ID + "=?",
                new String[]{String.valueOf(mantraId)});
    }

    public List getMantrasByNoteId(long noteId) {
        List mantras = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_MANTRAS,
                null,
                NotesDatabaseHelper.COL_MANTRA_NOTE_ID + "=?",
                new String[]{String.valueOf(noteId)},
                null, null, NotesDatabaseHelper.COL_MANTRA_CREATED + " ASC");
        if (cursor != null) {
            while (cursor.moveToNext()) {
                mantras.add(cursorToMantra(cursor));
            }
            cursor.close();
        }
        return mantras;
    }

    public Mantra getMantraById(long mantraId) {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_MANTRAS,
                null,
                NotesDatabaseHelper.COL_MANTRA_ID + "=?",
                new String[]{String.valueOf(mantraId)},
                null, null, null);
        Mantra mantra = null;
        if (cursor != null && cursor.moveToFirst()) {
            mantra = cursorToMantra(cursor);
            cursor.close();
        }
        return mantra;
    }

    public Mantra getLastUsedMantra() {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_MANTRAS,
                null, null, null, null, null,
                NotesDatabaseHelper.COL_MANTRA_CREATED + " DESC",
                "1");
        Mantra mantra = null;
        if (cursor != null && cursor.moveToFirst()) {
            mantra = cursorToMantra(cursor);
            cursor.close();
        }
        return mantra;
    }

    private Mantra cursorToMantra(Cursor cursor) {
        Mantra mantra = new Mantra();
        mantra.setId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_MANTRA_ID)));
        mantra.setNoteId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_MANTRA_NOTE_ID)));
        mantra.setName(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_MANTRA_NAME)));
        mantra.setAudioPath(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_MANTRA_AUDIO_PATH)));
        mantra.setTodayCount(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_MANTRA_TODAY_COUNT)));
        mantra.setLastCountDate(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_MANTRA_LAST_COUNT_DATE)));
        mantra.setCreatedAt(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_MANTRA_CREATED)));
        int speedIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_MANTRA_SPEED);
        if (speedIdx >= 0) {
            mantra.setPlaybackSpeed(cursor.getFloat(speedIdx));
        }
        int delIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_MANTRA_IS_DELETED);
        if (delIdx >= 0) {
            mantra.setDeleted(cursor.getInt(delIdx) == 1);
        }
        int rawIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_MANTRA_RAW_RES_ID);
        if (rawIdx >= 0) {
            mantra.setRawResId(cursor.getInt(rawIdx));
        }
        int builtIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_MANTRA_BUILT_IN);
        if (builtIdx >= 0) {
            mantra.setBuiltIn(cursor.getInt(builtIdx) == 1);
        }
        return mantra;
    }

    /**
     * Get all mantras across all notes (master list).
     */
    public List getAllMantras() {
        List mantras = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_MANTRAS,
                null, null, null, null, null,
                NotesDatabaseHelper.COL_MANTRA_NAME + " ASC");
        if (cursor != null) {
            while (cursor.moveToNext()) {
                mantras.add(cursorToMantra(cursor));
            }
            cursor.close();
        }
        return mantras;
    }

    /**
     * Get all active (non-deleted) built-in mantras from the master library.
     * These are the 15 predefined mantras that ship with the app.
     */
    public List getAllBuiltInMantras() {
        List mantras = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_MANTRAS,
                null,
                NotesDatabaseHelper.COL_MANTRA_BUILT_IN + "=1 AND " +
                        NotesDatabaseHelper.COL_MANTRA_IS_DELETED + "=0",
                null, null, null,
                NotesDatabaseHelper.COL_MANTRA_NAME + " ASC");
        if (cursor != null) {
            while (cursor.moveToNext()) {
                mantras.add(cursorToMantra(cursor));
            }
            cursor.close();
        }
        return mantras;
    }

    /**
     * Get all active (non-deleted) user-added mantras from the master library.
     * These are mantras manually added by the user (built_in = 0).
     */
    public List getAllUserAddedMantras() {
        List mantras = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_MANTRAS,
                null,
                NotesDatabaseHelper.COL_MANTRA_BUILT_IN + "=0 AND " +
                        NotesDatabaseHelper.COL_MANTRA_IS_DELETED + "=0",
                null, null, null,
                NotesDatabaseHelper.COL_MANTRA_NAME + " ASC");
        if (cursor != null) {
            while (cursor.moveToNext()) {
                mantras.add(cursorToMantra(cursor));
            }
            cursor.close();
        }
        return mantras;
    }

    /**
     * Get all active mantras from master library (both built-in and user-added).
     * Built-in mantras listed first, then user-added mantras.
     * Both filtered by is_deleted = 0.
     */
    public List getAllActiveMantrasHybrid() {
        List result = new ArrayList();
        result.addAll(getAllBuiltInMantras());
        result.addAll(getAllUserAddedMantras());
        return result;
    }

    /**
     * Hard-delete a user-added mantra from the master table permanently.
     * Only works on non-built-in mantras. Built-in mantras are protected.
     * Does NOT affect DailySession or MantraHistory data.
     */
    public boolean hardDeleteUserMantra(long mantraId) {
        Mantra mantra = getMantraById(mantraId);
        if (mantra == null || mantra.isBuiltIn()) {
            return false;
        }
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        int rows = db.delete(NotesDatabaseHelper.TABLE_MANTRAS,
                NotesDatabaseHelper.COL_MANTRA_ID + "=? AND " +
                        NotesDatabaseHelper.COL_MANTRA_BUILT_IN + "=0",
                new String[]{String.valueOf(mantraId)});
        return rows > 0;
    }

    /**
     * Soft-delete a mantra from master list (set is_deleted = 1).
     * DailySession and MantraHistory data remain untouched.
     */
    public void softDeleteMantra(long mantraId) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_MANTRA_IS_DELETED, 1);
        db.update(NotesDatabaseHelper.TABLE_MANTRAS, values,
                NotesDatabaseHelper.COL_MANTRA_ID + "=?",
                new String[]{String.valueOf(mantraId)});
    }

    /**
     * Get active (non-deleted) mantras for a specific note.
     * Used in the master popup to show available mantras.
     */
    public List getActiveMantrasForNote(long noteId) {
        List mantras = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_MANTRAS,
                null,
                NotesDatabaseHelper.COL_MANTRA_NOTE_ID + "=? AND " +
                        NotesDatabaseHelper.COL_MANTRA_IS_DELETED + "=0",
                new String[]{String.valueOf(noteId)},
                null, null, NotesDatabaseHelper.COL_MANTRA_CREATED + " ASC");
        if (cursor != null) {
            while (cursor.moveToNext()) {
                mantras.add(cursorToMantra(cursor));
            }
            cursor.close();
        }
        return mantras;
    }

    /**
     * Get mantras that have a DailySession for the given date, for the card display.
     * JOINs mantras table to get master info including is_deleted flag.
     * Returns all mantras with sessions regardless of is_deleted, so the card
     * can show them but disable play for deleted ones.
     */
    public List getMantrasWithSessionForNoteAndDate(long noteId, String date) {
        List mantras = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.rawQuery(
                "SELECT m.*, ds." + NotesDatabaseHelper.COL_SESSION_COUNT +
                        " AS session_count, ds." + NotesDatabaseHelper.COL_SESSION_SPEED +
                        " AS session_speed FROM " +
                        NotesDatabaseHelper.TABLE_MANTRAS + " m INNER JOIN " +
                        NotesDatabaseHelper.TABLE_DAILY_SESSIONS + " ds ON m." +
                        NotesDatabaseHelper.COL_MANTRA_ID + " = ds." +
                        NotesDatabaseHelper.COL_SESSION_MANTRA_ID +
                        " WHERE m." + NotesDatabaseHelper.COL_MANTRA_NOTE_ID + "=?" +
                        " AND ds." + NotesDatabaseHelper.COL_SESSION_DATE + "=?" +
                        " ORDER BY m." + NotesDatabaseHelper.COL_MANTRA_NAME + " ASC",
                new String[]{String.valueOf(noteId), date});
        if (cursor != null) {
            while (cursor.moveToNext()) {
                Mantra m = cursorToMantra(cursor);
                int scIdx = cursor.getColumnIndex("session_count");
                if (scIdx >= 0) {
                    m.setTodayCount(cursor.getInt(scIdx));
                }
                mantras.add(m);
            }
            cursor.close();
        }
        return mantras;
    }

    // ============ DAILY SESSIONS ============

    /**
     * Get or create a daily session for a mantra on a specific date.
     * Returns the session count. If no session exists, creates one with count 0.
     */
    public long getOrCreateDailySession(long mantraId, String date) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_DAILY_SESSIONS,
                new String[]{NotesDatabaseHelper.COL_SESSION_ID, NotesDatabaseHelper.COL_SESSION_COUNT},
                NotesDatabaseHelper.COL_SESSION_MANTRA_ID + "=? AND " +
                        NotesDatabaseHelper.COL_SESSION_DATE + "=?",
                new String[]{String.valueOf(mantraId), date},
                null, null, null);
        if (cursor != null && cursor.moveToFirst()) {
            long sessionId = cursor.getLong(0);
            cursor.close();
            return sessionId;
        }
        if (cursor != null) cursor.close();
        // Create new session
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_SESSION_MANTRA_ID, mantraId);
        values.put(NotesDatabaseHelper.COL_SESSION_DATE, date);
        values.put(NotesDatabaseHelper.COL_SESSION_COUNT, 0);
        values.put(NotesDatabaseHelper.COL_SESSION_SPEED, 1.0f);
        return db.insert(NotesDatabaseHelper.TABLE_DAILY_SESSIONS, null, values);
    }

    /**
     * Get session count for a mantra on a specific date.
     */
    public int getSessionCount(long mantraId, String date) {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_DAILY_SESSIONS,
                new String[]{NotesDatabaseHelper.COL_SESSION_COUNT},
                NotesDatabaseHelper.COL_SESSION_MANTRA_ID + "=? AND " +
                        NotesDatabaseHelper.COL_SESSION_DATE + "=?",
                new String[]{String.valueOf(mantraId), date},
                null, null, null);
        int count = 0;
        if (cursor != null && cursor.moveToFirst()) {
            count = cursor.getInt(0);
            cursor.close();
        } else {
            if (cursor != null) cursor.close();
        }
        return count;
    }

    /**
     * Increment session count for a mantra on a date. Creates session if needed.
     * Returns the new count.
     */
    public int incrementSessionCount(long mantraId, String date) {
        getOrCreateDailySession(mantraId, date);
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        db.execSQL("UPDATE " + NotesDatabaseHelper.TABLE_DAILY_SESSIONS +
                " SET " + NotesDatabaseHelper.COL_SESSION_COUNT + " = " +
                NotesDatabaseHelper.COL_SESSION_COUNT + " + 1 WHERE " +
                NotesDatabaseHelper.COL_SESSION_MANTRA_ID + "=? AND " +
                NotesDatabaseHelper.COL_SESSION_DATE + "=?",
                new Object[]{Long.valueOf(mantraId), date});
        return getSessionCount(mantraId, date);
    }

    /**
     * Reset session count for a specific mantra on a date.
     */
    public void resetSessionCount(long mantraId, String date) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_SESSION_COUNT, 0);
        db.update(NotesDatabaseHelper.TABLE_DAILY_SESSIONS, values,
                NotesDatabaseHelper.COL_SESSION_MANTRA_ID + "=? AND " +
                        NotesDatabaseHelper.COL_SESSION_DATE + "=?",
                new String[]{String.valueOf(mantraId), date});
    }

    /**
     * Delete a specific day's session for a mantra (NoteEditor delete).
     */
    public void deleteSessionForDate(long mantraId, String date) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        db.delete(NotesDatabaseHelper.TABLE_DAILY_SESSIONS,
                NotesDatabaseHelper.COL_SESSION_MANTRA_ID + "=? AND " +
                        NotesDatabaseHelper.COL_SESSION_DATE + "=?",
                new String[]{String.valueOf(mantraId), date});
    }

    /**
     * Get all active sessions for today (for widget).
     * Returns mantras that have a session entry for today AND are not soft-deleted.
     */
    public List getMantrasWithSessionForDate(String date) {
        List mantras = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.rawQuery(
                "SELECT m.*, ds." + NotesDatabaseHelper.COL_SESSION_COUNT + " AS session_count FROM " +
                        NotesDatabaseHelper.TABLE_MANTRAS + " m INNER JOIN " +
                        NotesDatabaseHelper.TABLE_DAILY_SESSIONS + " ds ON m." +
                        NotesDatabaseHelper.COL_MANTRA_ID + " = ds." +
                        NotesDatabaseHelper.COL_SESSION_MANTRA_ID +
                        " WHERE ds." + NotesDatabaseHelper.COL_SESSION_DATE + "=?" +
                        " AND m." + NotesDatabaseHelper.COL_MANTRA_IS_DELETED + "=0" +
                        " ORDER BY m." + NotesDatabaseHelper.COL_MANTRA_NAME + " ASC",
                new String[]{date});
        if (cursor != null) {
            while (cursor.moveToNext()) {
                Mantra m = cursorToMantra(cursor);
                int scIdx = cursor.getColumnIndex("session_count");
                if (scIdx >= 0) {
                    m.setTodayCount(cursor.getInt(scIdx));
                }
                mantras.add(m);
            }
            cursor.close();
        }
        return mantras;
    }

    /**
     * Update session speed for a mantra on a date.
     */
    public void updateSessionSpeed(long mantraId, String date, float speed) {
        getOrCreateDailySession(mantraId, date);
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_SESSION_SPEED, speed);
        db.update(NotesDatabaseHelper.TABLE_DAILY_SESSIONS, values,
                NotesDatabaseHelper.COL_SESSION_MANTRA_ID + "=? AND " +
                        NotesDatabaseHelper.COL_SESSION_DATE + "=?",
                new String[]{String.valueOf(mantraId), date});
    }

    /**
     * Get session speed for a mantra on a date.
     */
    public float getSessionSpeed(long mantraId, String date) {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_DAILY_SESSIONS,
                new String[]{NotesDatabaseHelper.COL_SESSION_SPEED},
                NotesDatabaseHelper.COL_SESSION_MANTRA_ID + "=? AND " +
                        NotesDatabaseHelper.COL_SESSION_DATE + "=?",
                new String[]{String.valueOf(mantraId), date},
                null, null, null);
        float speed = 1.0f;
        if (cursor != null && cursor.moveToFirst()) {
            speed = cursor.getFloat(0);
            cursor.close();
        } else {
            if (cursor != null) cursor.close();
        }
        return speed;
    }

    /**
     * Delete all mantra history for a specific mantra ID.
     */
    public void deleteMantraHistory(long mantraId) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        db.delete(NotesDatabaseHelper.TABLE_MANTRA_HISTORY,
                NotesDatabaseHelper.COL_HIST_MANTRA_ID + "=?",
                new String[]{String.valueOf(mantraId)});
    }

    // ============ MANTRA COUNT LOG (Timestamp-based) ============

    /**
     * Insert a single count timestamp into the mantra_count_log table.
     * Called every time a mantra loop completes so we can build time-slot graphs.
     */
    public void insertMantraCountLog(long mantraId, String sessionDate, long timestamp) {
        try {
            SQLiteDatabase db = dbHelper.getWritableDatabase();
            ContentValues values = new ContentValues();
            values.put(NotesDatabaseHelper.COL_LOG_MANTRA_ID, mantraId);
            values.put(NotesDatabaseHelper.COL_LOG_SESSION_DATE, sessionDate);
            values.put(NotesDatabaseHelper.COL_LOG_TIMESTAMP, timestamp);
            db.insert(NotesDatabaseHelper.TABLE_MANTRA_COUNT_LOG, null, values);
        } catch (Exception e) {
            // Fail silently - don't break playback
        }
    }

    /**
     * Get count of log entries for a mantra+date within a time range (for time-slot graph).
     * startHour and endHour are 0-23 based.
     */
    public int getCountLogForTimeSlot(long mantraId, String sessionDate, int startHour, int endHour) {
        int count = 0;
        try {
            SQLiteDatabase db = dbHelper.getReadableDatabase();
            // Build the start/end timestamps for the slot on the given date
            // We filter by checking the hour extracted from timestamp
            // Since we store millis, we query all logs for the date and filter by hour range
            Cursor cursor = db.rawQuery(
                "SELECT COUNT(*) FROM " + NotesDatabaseHelper.TABLE_MANTRA_COUNT_LOG +
                " WHERE " + NotesDatabaseHelper.COL_LOG_MANTRA_ID + "=?" +
                " AND " + NotesDatabaseHelper.COL_LOG_SESSION_DATE + "=?" +
                " AND " + NotesDatabaseHelper.COL_LOG_TIMESTAMP + ">=?" +
                " AND " + NotesDatabaseHelper.COL_LOG_TIMESTAMP + "<?",
                new String[]{String.valueOf(mantraId), sessionDate,
                    String.valueOf(getSlotStartMillis(sessionDate, startHour)),
                    String.valueOf(getSlotStartMillis(sessionDate, endHour))});
            if (cursor != null) {
                if (cursor.moveToFirst()) {
                    count = cursor.getInt(0);
                }
                cursor.close();
            }
        } catch (Exception e) {
            // Fail silently
        }
        return count;
    }

    /**
     * Get all unique mantra IDs that have log entries for a given date.
     */
    public List<Long> getLoggedMantraIdsForDate(String sessionDate) {
        List<Long> ids = new ArrayList<Long>();
        try {
            SQLiteDatabase db = dbHelper.getReadableDatabase();
            Cursor cursor = db.rawQuery(
                "SELECT DISTINCT " + NotesDatabaseHelper.COL_LOG_MANTRA_ID +
                " FROM " + NotesDatabaseHelper.TABLE_MANTRA_COUNT_LOG +
                " WHERE " + NotesDatabaseHelper.COL_LOG_SESSION_DATE + "=?",
                new String[]{sessionDate});
            if (cursor != null) {
                while (cursor.moveToNext()) {
                    ids.add(Long.valueOf(cursor.getLong(0)));
                }
                cursor.close();
            }
        } catch (Exception e) {
            // Fail silently
        }
        return ids;
    }

    /**
     * Check if the mantra_count_log table has any entries for a given date.
     */
    public boolean hasCountLogForDate(String sessionDate) {
        boolean has = false;
        try {
            SQLiteDatabase db = dbHelper.getReadableDatabase();
            Cursor cursor = db.rawQuery(
                "SELECT COUNT(*) FROM " + NotesDatabaseHelper.TABLE_MANTRA_COUNT_LOG +
                " WHERE " + NotesDatabaseHelper.COL_LOG_SESSION_DATE + "=?",
                new String[]{sessionDate});
            if (cursor != null) {
                if (cursor.moveToFirst()) {
                    has = cursor.getInt(0) > 0;
                }
                cursor.close();
            }
        } catch (Exception e) {
            // Fail silently
        }
        return has;
    }

    /**
     * Helper: get millis for a specific hour on a given date (yyyy-MM-dd).
     */
    private long getSlotStartMillis(String dateYmd, int hour) {
        try {
            java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US);
            java.util.Date d = sdf.parse(dateYmd);
            if (d != null) {
                java.util.Calendar cal = java.util.Calendar.getInstance();
                cal.setTime(d);
                cal.set(java.util.Calendar.HOUR_OF_DAY, hour);
                cal.set(java.util.Calendar.MINUTE, 0);
                cal.set(java.util.Calendar.SECOND, 0);
                cal.set(java.util.Calendar.MILLISECOND, 0);
                return cal.getTimeInMillis();
            }
        } catch (Exception e) {
            // Fail silently
        }
        return 0;
    }

    // ============ MANTRA HISTORY ============

    /**
     * Insert a note with RAW data (no encryption applied).
     * Used when restoring encrypted backup data to avoid double-encryption.
     * The search index is rebuilt from decrypted content if key is available.
     */
    public long insertNoteRaw(Note note) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        // Generate cloudId if not already set
        if (note.getCloudId() == null || note.getCloudId().length() == 0) {
            note.setCloudId(UUID.randomUUID().toString());
        }
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_TITLE, note.getTitle());
        values.put(NotesDatabaseHelper.COL_CONTENT, note.getContent());
        values.put(NotesDatabaseHelper.COL_CREATED, note.getCreatedAt());
        values.put(NotesDatabaseHelper.COL_MODIFIED, note.getModifiedAt());
        values.put(NotesDatabaseHelper.COL_COLOR, note.getColor());
        values.put(NotesDatabaseHelper.COL_FAVORITE, note.isFavorite() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_LOCKED, note.isLocked() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_PASSWORD, note.getPassword());
        values.put(NotesDatabaseHelper.COL_CATEGORY_ID, note.getCategoryId());
        values.put(NotesDatabaseHelper.COL_HAS_CHECKLIST, note.hasChecklist() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_HAS_IMAGE, note.hasImage() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_CHECKLIST_DATA, note.getChecklistData());
        values.put(NotesDatabaseHelper.COL_IS_CHECKLIST_MODE, note.isChecklistMode() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_IMAGES_DATA, note.getImagesData());
        values.put(NotesDatabaseHelper.COL_FILES_DATA, note.getFilesData());
        values.put(NotesDatabaseHelper.COL_AUDIOS_DATA, note.getAudiosData());
        values.put(NotesDatabaseHelper.COL_LINKED_NOTE_IDS, note.getLinkedNoteIds());
        values.put(NotesDatabaseHelper.COL_IS_ROUTINE_MODE, note.isRoutineMode() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_ROUTINE_DATA, note.getRoutineData());
        values.put(NotesDatabaseHelper.COL_IS_ARCHIVED, note.isArchived() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_SEARCH_INDEX, "");
        values.put(NotesDatabaseHelper.COL_CLOUD_ID, note.getCloudId());
        values.put(NotesDatabaseHelper.COL_SYNC_STATUS, note.getSyncStatus());
        return db.insert(NotesDatabaseHelper.TABLE_NOTES, null, values);
    }

    /**
     * Get all notes with RAW (encrypted) data for backup purposes.
     * Does NOT decrypt -- reads directly from DB.
     */
    public List getAllNotesRaw() {
        List notes = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES,
                null, null, null, null, null,
                NotesDatabaseHelper.COL_ID + " ASC");
        if (cursor != null) {
            while (cursor.moveToNext()) {
                notes.add(cursorToNoteRaw(cursor));
            }
            cursor.close();
        }
        return notes;
    }

    /**
     * Read a note from cursor WITHOUT decryption (raw DB values).
     * Used for backup export -- encrypted data stays encrypted.
     */
    private Note cursorToNoteRaw(Cursor cursor) {
        Note note = new Note();
        note.setId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_ID)));
        note.setTitle(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_TITLE)));
        note.setContent(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_CONTENT)));
        note.setCreatedAt(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_CREATED)));
        note.setModifiedAt(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_MODIFIED)));
        note.setColor(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_COLOR)));
        note.setFavorite(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_FAVORITE)) == 1);
        note.setLocked(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_LOCKED)) == 1);
        note.setPassword(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_PASSWORD)));
        note.setCategoryId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_CATEGORY_ID)));
        note.setHasChecklist(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_HAS_CHECKLIST)) == 1);
        note.setHasImage(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_HAS_IMAGE)) == 1);
        int clDataIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_CHECKLIST_DATA);
        if (clDataIdx >= 0) note.setChecklistData(cursor.getString(clDataIdx));
        int clModeIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_IS_CHECKLIST_MODE);
        if (clModeIdx >= 0) note.setChecklistMode(cursor.getInt(clModeIdx) == 1);
        int imgIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_IMAGES_DATA);
        if (imgIdx >= 0) note.setImagesData(cursor.getString(imgIdx));
        int filesIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_FILES_DATA);
        if (filesIdx >= 0) note.setFilesData(cursor.getString(filesIdx));
        int audiosIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_AUDIOS_DATA);
        if (audiosIdx >= 0) note.setAudiosData(cursor.getString(audiosIdx));
        int linkedIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_LINKED_NOTE_IDS);
        if (linkedIdx >= 0) note.setLinkedNoteIds(cursor.getString(linkedIdx));
        int routineModeIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_IS_ROUTINE_MODE);
        if (routineModeIdx >= 0) note.setRoutineMode(cursor.getInt(routineModeIdx) == 1);
        int routineDataIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_ROUTINE_DATA);
        if (routineDataIdx >= 0) note.setRoutineData(cursor.getString(routineDataIdx));
        int archivedIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_IS_ARCHIVED);
        if (archivedIdx >= 0) note.setArchived(cursor.getInt(archivedIdx) == 1);
        int cloudIdIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_CLOUD_ID);
        if (cloudIdIdx >= 0) note.setCloudId(cursor.getString(cloudIdIdx));
        int syncStatusIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_SYNC_STATUS);
        if (syncStatusIdx >= 0) note.setSyncStatus(cursor.getInt(syncStatusIdx));
        return note;
    }

    // ============ CLOUD SYNC HELPERS ============

    /**
     * Get a note by its cloud UUID.
     * Returns null if not found.
     */
    public Note getNoteByCloudId(String cloudId) {
        if (cloudId == null || cloudId.length() == 0) return null;
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES,
                null,
                NotesDatabaseHelper.COL_CLOUD_ID + "=?",
                new String[]{cloudId},
                null, null, null);
        Note note = null;
        if (cursor != null && cursor.moveToFirst()) {
            note = cursorToNote(cursor);
            cursor.close();
        }
        return note;
    }

    /**
     * Get a note by cloudId with RAW (encrypted) data.
     * Used by CloudSyncManager to read encrypted values for upload.
     */
    public Note getNoteRawByCloudId(String cloudId) {
        if (cloudId == null || cloudId.length() == 0) return null;
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES,
                null,
                NotesDatabaseHelper.COL_CLOUD_ID + "=?",
                new String[]{cloudId},
                null, null, null);
        Note note = null;
        if (cursor != null && cursor.moveToFirst()) {
            note = cursorToNoteRaw(cursor);
            cursor.close();
        }
        return note;
    }

    /**
     * Get a note by local ID with RAW (encrypted) data.
     * Used by CloudSyncManager after insert/update to read encrypted values.
     */
    public Note getNoteRawById(long noteId) {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES,
                null,
                NotesDatabaseHelper.COL_ID + "=?",
                new String[]{String.valueOf(noteId)},
                null, null, null);
        Note note = null;
        if (cursor != null && cursor.moveToFirst()) {
            note = cursorToNoteRaw(cursor);
            cursor.close();
        }
        return note;
    }

    /**
     * Update sync status for a note by local ID.
     */
    public void updateSyncStatus(long noteId, int status) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_SYNC_STATUS, status);
        db.update(NotesDatabaseHelper.TABLE_NOTES, values,
                NotesDatabaseHelper.COL_ID + "=?",
                new String[]{String.valueOf(noteId)});
    }

    /**
     * Update a note with raw (already-encrypted) data from cloud sync.
     * Does NOT re-encrypt. Used when cloud has newer data.
     */
    public void updateNoteRaw(Note note) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_TITLE, note.getTitle());
        values.put(NotesDatabaseHelper.COL_CONTENT, note.getContent());
        values.put(NotesDatabaseHelper.COL_MODIFIED, note.getModifiedAt());
        values.put(NotesDatabaseHelper.COL_COLOR, note.getColor());
        values.put(NotesDatabaseHelper.COL_FAVORITE, note.isFavorite() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_LOCKED, note.isLocked() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_PASSWORD, note.getPassword());
        values.put(NotesDatabaseHelper.COL_CATEGORY_ID, note.getCategoryId());
        values.put(NotesDatabaseHelper.COL_HAS_CHECKLIST, note.hasChecklist() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_HAS_IMAGE, note.hasImage() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_CHECKLIST_DATA, note.getChecklistData());
        values.put(NotesDatabaseHelper.COL_IS_CHECKLIST_MODE, note.isChecklistMode() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_IMAGES_DATA, note.getImagesData());
        values.put(NotesDatabaseHelper.COL_FILES_DATA, note.getFilesData());
        values.put(NotesDatabaseHelper.COL_AUDIOS_DATA, note.getAudiosData());
        values.put(NotesDatabaseHelper.COL_LINKED_NOTE_IDS, note.getLinkedNoteIds());
        values.put(NotesDatabaseHelper.COL_IS_ROUTINE_MODE, note.isRoutineMode() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_ROUTINE_DATA, note.getRoutineData());
        values.put(NotesDatabaseHelper.COL_IS_ARCHIVED, note.isArchived() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_SEARCH_INDEX, "");
        values.put(NotesDatabaseHelper.COL_CLOUD_ID, note.getCloudId());
        values.put(NotesDatabaseHelper.COL_SYNC_STATUS, Note.SYNC_STATUS_SYNCED);
        db.update(NotesDatabaseHelper.TABLE_NOTES, values,
                NotesDatabaseHelper.COL_CLOUD_ID + "=?",
                new String[]{note.getCloudId()});
    }

    /**
     * Delete a note by its cloudId. Used during sync when cloud says isDeleted=true.
     */
    public void deleteNoteByCloudId(String cloudId) {
        if (cloudId == null || cloudId.length() == 0) return;
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        db.delete(NotesDatabaseHelper.TABLE_NOTES,
                NotesDatabaseHelper.COL_CLOUD_ID + "=?",
                new String[]{cloudId});
    }

    // ============ ENCRYPTION MIGRATION ============

    /**
     * Migrate all existing plaintext notes to encrypted format.
     * Wrapped in a DB transaction for crash safety -- if any note fails,
     * the entire migration rolls back (no partial encryption).
     * Idempotent: already-encrypted notes are skipped via isEncrypted() check.
     *
     * @param key the derived encryption key
     * @return true if migration succeeded, false on failure (rolled back)
     */
    public boolean migrateToEncrypted(byte[] key) {
        if (key == null) return false;
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        db.beginTransaction();
        try {
            // Migrate notes table
            Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES,
                    null, null, null, null, null, null);
            if (cursor != null) {
                while (cursor.moveToNext()) {
                    long id = cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_ID));
                    String rawTitle = cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_TITLE));
                    String rawContent = cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_CONTENT));
                    String rawChecklist = "";
                    int clIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_CHECKLIST_DATA);
                    if (clIdx >= 0) {
                        rawChecklist = cursor.getString(clIdx);
                    }
                    String rawRoutine = "";
                    int rtIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_ROUTINE_DATA);
                    if (rtIdx >= 0) {
                        rawRoutine = cursor.getString(rtIdx);
                    }

                    // Skip if already encrypted
                    if (rawTitle != null && CryptoManager.isEncrypted(rawTitle)) {
                        continue;
                    }

                    ContentValues values = new ContentValues();
                    values.put(NotesDatabaseHelper.COL_TITLE, encryptFieldWithKey(rawTitle, key));
                    values.put(NotesDatabaseHelper.COL_CONTENT, encryptFieldWithKey(rawContent, key));
                    values.put(NotesDatabaseHelper.COL_CHECKLIST_DATA, encryptFieldWithKey(rawChecklist, key));
                    values.put(NotesDatabaseHelper.COL_ROUTINE_DATA, encryptFieldWithKey(rawRoutine, key));
                    values.put(NotesDatabaseHelper.COL_SEARCH_INDEX, "");
                    db.update(NotesDatabaseHelper.TABLE_NOTES, values,
                            NotesDatabaseHelper.COL_ID + "=?",
                            new String[]{String.valueOf(id)});
                }
                cursor.close();
            }

            // Migrate trash table
            Cursor trashCursor = db.query(NotesDatabaseHelper.TABLE_TRASH,
                    null, null, null, null, null, null);
            if (trashCursor != null) {
                while (trashCursor.moveToNext()) {
                    long id = trashCursor.getLong(trashCursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_ID));
                    String rawTitle = trashCursor.getString(trashCursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_NOTE_TITLE));
                    String rawContent = trashCursor.getString(trashCursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_NOTE_CONTENT));
                    String rawChecklist = "";
                    int clIdx = trashCursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_CHECKLIST_DATA);
                    if (clIdx >= 0) {
                        rawChecklist = trashCursor.getString(clIdx);
                    }

                    // Skip if already encrypted
                    if (rawTitle != null && CryptoManager.isEncrypted(rawTitle)) {
                        continue;
                    }

                    ContentValues values = new ContentValues();
                    values.put(NotesDatabaseHelper.COL_TRASH_NOTE_TITLE, encryptFieldWithKey(rawTitle, key));
                    values.put(NotesDatabaseHelper.COL_TRASH_NOTE_CONTENT, encryptFieldWithKey(rawContent, key));
                    values.put(NotesDatabaseHelper.COL_TRASH_CHECKLIST_DATA, encryptFieldWithKey(rawChecklist, key));
                    db.update(NotesDatabaseHelper.TABLE_TRASH, values,
                            NotesDatabaseHelper.COL_TRASH_ID + "=?",
                            new String[]{String.valueOf(id)});
                }
                trashCursor.close();
            }

            db.setTransactionSuccessful();
            return true;
        } catch (Exception e) {
            // Transaction rolls back -- no partial encryption
            return false;
        } finally {
            db.endTransaction();
        }
    }

    /**
     * Re-encrypt all notes when master password is changed.
     * Decrypts with oldKey, encrypts with newKey.
     *
     * @param oldKey the previous derived encryption key
     * @param newKey the new derived encryption key
     */
    public void reEncryptAllNotes(byte[] oldKey, byte[] newKey) {
        if (oldKey == null || newKey == null) return;
        SQLiteDatabase db = dbHelper.getWritableDatabase();

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

                // Decrypt with old key
                String plainTitle = CryptoManager.decrypt(encTitle, oldKey);
                String plainContent = CryptoManager.decrypt(encContent, oldKey);
                String plainChecklist = CryptoManager.decrypt(encChecklist, oldKey);
                String plainRoutine = CryptoManager.decrypt(encRoutine, oldKey);

                // Encrypt with new key
                ContentValues values = new ContentValues();
                values.put(NotesDatabaseHelper.COL_TITLE, encryptFieldWithKey(plainTitle, newKey));
                values.put(NotesDatabaseHelper.COL_CONTENT, encryptFieldWithKey(plainContent, newKey));
                values.put(NotesDatabaseHelper.COL_CHECKLIST_DATA, encryptFieldWithKey(plainChecklist, newKey));
                values.put(NotesDatabaseHelper.COL_ROUTINE_DATA, encryptFieldWithKey(plainRoutine, newKey));
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
                String plainTitle = CryptoManager.decrypt(encTitle, oldKey);
                String plainContent = CryptoManager.decrypt(encContent, oldKey);
                String plainChecklist = CryptoManager.decrypt(encChecklist, oldKey);

                // Encrypt with new key
                ContentValues values = new ContentValues();
                values.put(NotesDatabaseHelper.COL_TRASH_NOTE_TITLE, encryptFieldWithKey(plainTitle, newKey));
                values.put(NotesDatabaseHelper.COL_TRASH_NOTE_CONTENT, encryptFieldWithKey(plainContent, newKey));
                values.put(NotesDatabaseHelper.COL_TRASH_CHECKLIST_DATA, encryptFieldWithKey(plainChecklist, newKey));
                db.update(NotesDatabaseHelper.TABLE_TRASH, values,
                        NotesDatabaseHelper.COL_TRASH_ID + "=?",
                        new String[]{String.valueOf(id)});
            }
            trashCursor.close();
        }
    }

    /**
     * Encrypt with a specific key (used during migration/re-encryption).
     * CRITICAL FIX: Never falls back to plaintext on encryption failure.
     */
    private String encryptFieldWithKey(String plaintext, byte[] key) {
        if (plaintext == null || plaintext.length() == 0) {
            return "";
        }
        if (key == null) {
            android.util.Log.e("NotesRepository", "[ENCRYPT_WITH_KEY] Key is null");
            throw new IllegalStateException("Cannot encrypt: key is null");
        }
        String encrypted = CryptoManager.encrypt(plaintext, key);
        if (encrypted == null) {
            android.util.Log.e("NotesRepository", "[ENCRYPT_WITH_KEY] Encryption returned null");
            throw new IllegalStateException("Encryption failed");
        }
        return encrypted;
    }

    /**
     * Sort a list of notes by decrypted title (case-insensitive, ascending).
     * Used for "Sort by title" preference since SQL ORDER BY on encrypted
     * ciphertext produces meaningless order.
     */
    private void sortNotesByTitle(List notes) {
        Collections.sort(notes, new Comparator() {
            public int compare(Object a, Object b) {
                String titleA = ((Note) a).getTitle() != null ? ((Note) a).getTitle() : "";
                String titleB = ((Note) b).getTitle() != null ? ((Note) b).getTitle() : "";
                return titleA.compareToIgnoreCase(titleB);
            }
        });
    }

    public void saveMantraHistory(long mantraId, String date, int count) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        // Check if entry exists for this date
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_MANTRA_HISTORY,
                null,
                NotesDatabaseHelper.COL_HIST_MANTRA_ID + "=? AND " +
                        NotesDatabaseHelper.COL_HIST_DATE + "=?",
                new String[]{String.valueOf(mantraId), date},
                null, null, null);
        if (cursor != null && cursor.moveToFirst()) {
            // Update existing
            ContentValues values = new ContentValues();
            values.put(NotesDatabaseHelper.COL_HIST_COUNT, count);
            db.update(NotesDatabaseHelper.TABLE_MANTRA_HISTORY, values,
                    NotesDatabaseHelper.COL_HIST_MANTRA_ID + "=? AND " +
                            NotesDatabaseHelper.COL_HIST_DATE + "=?",
                    new String[]{String.valueOf(mantraId), date});
            cursor.close();
        } else {
            // Insert new
            if (cursor != null) cursor.close();
            ContentValues values = new ContentValues();
            values.put(NotesDatabaseHelper.COL_HIST_MANTRA_ID, mantraId);
            values.put(NotesDatabaseHelper.COL_HIST_DATE, date);
            values.put(NotesDatabaseHelper.COL_HIST_COUNT, count);
            db.insert(NotesDatabaseHelper.TABLE_MANTRA_HISTORY, null, values);
        }
    }
}
