package com.mknotes.app.cloud;

import android.content.Context;
import android.util.Log;

import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.firestore.DocumentChange;
import com.google.firebase.firestore.EventListener;
import com.google.firebase.firestore.DocumentSnapshot;
import com.google.firebase.firestore.FirebaseFirestore;
import com.google.firebase.firestore.FirebaseFirestoreException;
import com.google.firebase.firestore.FirebaseFirestoreSettings;
import com.google.firebase.firestore.ListenerRegistration;
import com.google.firebase.firestore.QueryDocumentSnapshot;
import com.google.firebase.firestore.QuerySnapshot;
import com.google.firebase.firestore.SetOptions;
import com.google.firebase.firestore.WriteBatch;

import com.mknotes.app.db.NotesRepository;
import com.mknotes.app.model.Note;
import com.mknotes.app.util.PrefsManager;
import com.mknotes.app.util.SessionManager;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Core Cloud Sync Engine for Firebase Firestore.
 *
 * SECURITY: Only encrypted data from SQLite is uploaded to Firestore.
 * Reads raw (encrypted) values via NotesRepository.getAllNotesRaw() / getNoteRawById().
 * Plaintext NEVER touches Firestore.
 *
 * Firestore structure: users/{uid}/notes/{cloudId}
 *
 * Features:
 * - Full bidirectional sync on app start (syncOnAppStart)
 * - Real-time listener via addSnapshotListener (startRealtimeSync)
 * - Single note upload after local edit (uploadNote)
 * - Soft-delete propagation (deleteNoteFromCloud)
 * - Batch upload for password change re-encryption (uploadAllNotes)
 * - Offline persistence (Firestore default, confirmed in ensureOfflinePersistence)
 *
 * AndroidX + latest Firebase BOM. Java 17 bytecode.
 */
public class CloudSyncManager {

    private static final String TAG = "CloudSync";
    private static final String COLLECTION_USERS = "users";
    private static final String COLLECTION_NOTES = "notes";

    private static CloudSyncManager sInstance;
    private FirebaseFirestore firestore;
    private Context appContext;

    /** Active real-time listener registration. Null if not listening. */
    private ListenerRegistration realtimeListenerReg;

    /** Flag to prevent processing snapshot events while we are uploading. */
    private boolean isUploading = false;

    /** Callback for notifying UI about real-time changes from cloud. */
    private RealtimeChangeCallback realtimeCallback;

    public static synchronized CloudSyncManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new CloudSyncManager(context.getApplicationContext());
        }
        return sInstance;
    }

    private CloudSyncManager(Context context) {
        this.appContext = context;
        this.firestore = FirebaseFirestore.getInstance();
        ensureOfflinePersistence();
    }

    // ======================== OFFLINE PERSISTENCE ========================

    /**
     * Ensure Firestore offline persistence is enabled.
     * In modern Firebase SDK (21+), persistence is enabled by default via
     * PersistentCacheSettings. This method uses the new API when available
     * and falls back gracefully.
     *
     * Must be called BEFORE any Firestore read/write operations.
     */
    private void ensureOfflinePersistence() {
        try {
            FirebaseFirestoreSettings settings = new FirebaseFirestoreSettings.Builder()
                    .setLocalCacheSettings(com.google.firebase.firestore.PersistentCacheSettings.newBuilder().build())
                    .build();
            firestore.setFirestoreSettings(settings);
            Log.d(TAG, "Firestore offline persistence confirmed enabled (PersistentCacheSettings)");
        } catch (Exception e) {
            // Settings can only be set before any other Firestore call.
            // If this fails, persistence is already the default (enabled).
            Log.w(TAG, "Firestore settings already configured: " + e.getMessage());
        }
    }

    // ======================== PRE-CHECKS ========================

    /**
     * Check if cloud sync is possible right now.
     * Requires: sync enabled, Firebase logged in, session valid.
     */
    private boolean canSync() {
        if (!PrefsManager.getInstance(appContext).isCloudSyncEnabled()) {
            return false;
        }
        if (!FirebaseAuthManager.getInstance(appContext).isLoggedIn()) {
            return false;
        }
        if (!SessionManager.getInstance(appContext).isSessionValid()) {
            return false;
        }
        return true;
    }

    /**
     * Get the current Firebase user UID.
     */
    private String getUid() {
        return FirebaseAuthManager.getInstance(appContext).getUid();
    }

    // ======================== REAL-TIME SYNC (addSnapshotListener) ========================

    /**
     * Start real-time listening on the user's notes collection.
     * Any change on Firestore (from another device) will trigger local DB updates.
     *
     * Call this after successful login and session validation.
     * Call stopRealtimeSync() on logout or session expiry.
     *
     * @param callback optional callback to notify UI of changes
     */
    public void startRealtimeSync(RealtimeChangeCallback callback) {
        this.realtimeCallback = callback;

        if (!canSync()) {
            Log.w(TAG, "Cannot start realtime sync: pre-checks failed");
            return;
        }
        final String uid = getUid();
        if (uid == null) {
            Log.w(TAG, "Cannot start realtime sync: no UID");
            return;
        }

        // Stop any existing listener before starting a new one
        stopRealtimeSync();

        Log.d(TAG, "Starting real-time snapshot listener for uid=" + uid);

        realtimeListenerReg = firestore.collection(COLLECTION_USERS).document(uid)
                .collection(COLLECTION_NOTES)
                .addSnapshotListener(new EventListener<QuerySnapshot>() {
                    public void onEvent(QuerySnapshot snapshots, FirebaseFirestoreException error) {
                        if (error != null) {
                            Log.e(TAG, "Realtime listener error: " + error.getMessage());
                            return;
                        }
                        if (snapshots == null) {
                            return;
                        }
                        // Skip if we are currently uploading (to avoid feedback loop)
                        if (isUploading) {
                            return;
                        }
                        // Skip local-origin changes (from this device's cache)
                        if (snapshots.getMetadata().hasPendingWrites()) {
                            return;
                        }
                        // Re-check session before processing
                        if (!SessionManager.getInstance(appContext).isSessionValid()) {
                            Log.w(TAG, "Session expired during realtime event, skipping");
                            return;
                        }

                        try {
                            processRealtimeChanges(snapshots);
                        } catch (Exception e) {
                            Log.e(TAG, "Error processing realtime changes: " + e.getMessage());
                        }
                    }
                });
    }

    /**
     * Process document changes from the real-time listener.
     * Only processes ADDED and MODIFIED changes (not REMOVED, since we use soft-delete).
     */
    private void processRealtimeChanges(QuerySnapshot snapshots) {
        NotesRepository repo = NotesRepository.getInstance(appContext);
        boolean hasChanges = false;

        for (DocumentChange dc : snapshots.getDocumentChanges()) {
            String cloudId = dc.getDocument().getId();
            Map<String, Object> data = dc.getDocument().getData();

            boolean cloudDeleted = false;
            Object deletedObj = data.get("isDeleted");
            if (deletedObj instanceof Boolean) {
                cloudDeleted = ((Boolean) deletedObj).booleanValue();
            }

            long cloudModified = 0;
            Object modObj = data.get("modifiedAt");
            if (modObj instanceof Long) {
                cloudModified = ((Long) modObj).longValue();
            } else if (modObj instanceof Number) {
                cloudModified = ((Number) modObj).longValue();
            }

            switch (dc.getType()) {
                case ADDED:
                    // New note from another device
                    Note existing = repo.getNoteRawByCloudId(cloudId);
                    if (existing == null && !cloudDeleted) {
                        Note cloudNote = mapToNote(data, cloudId);
                        cloudNote.setSyncStatus(Note.SYNC_STATUS_SYNCED);
                        repo.insertNoteRaw(cloudNote);
                        hasChanges = true;
                        Log.d(TAG, "Realtime: inserted new note cloudId=" + cloudId);
                    }
                    break;

                case MODIFIED:
                    Note localNote = repo.getNoteRawByCloudId(cloudId);
                    if (localNote != null) {
                        if (cloudDeleted && cloudModified >= localNote.getModifiedAt()) {
                            // Soft-delete from another device
                            repo.deleteNoteByCloudId(cloudId);
                            hasChanges = true;
                            Log.d(TAG, "Realtime: deleted note cloudId=" + cloudId);
                        } else if (!cloudDeleted && cloudModified > localNote.getModifiedAt()) {
                            // Cloud is newer -- update local
                            Note cloudNote = mapToNote(data, cloudId);
                            repo.updateNoteRaw(cloudNote);
                            hasChanges = true;
                            Log.d(TAG, "Realtime: updated note cloudId=" + cloudId);
                        }
                        // If local is newer, skip (local will upload on next edit/sync)
                    } else if (!cloudDeleted) {
                        // Note doesn't exist locally but was modified in cloud -- insert
                        Note cloudNote = mapToNote(data, cloudId);
                        cloudNote.setSyncStatus(Note.SYNC_STATUS_SYNCED);
                        repo.insertNoteRaw(cloudNote);
                        hasChanges = true;
                        Log.d(TAG, "Realtime: inserted modified note cloudId=" + cloudId);
                    }
                    break;

                case REMOVED:
                    // Firestore REMOVED event (document actually deleted, not soft-delete)
                    repo.deleteNoteByCloudId(cloudId);
                    hasChanges = true;
                    Log.d(TAG, "Realtime: removed note cloudId=" + cloudId);
                    break;
            }
        }

        if (hasChanges && realtimeCallback != null) {
            realtimeCallback.onNotesChanged();
        }
    }

    /**
     * Stop the real-time snapshot listener.
     * Call on logout, session expiry, or when sync is disabled.
     */
    public void stopRealtimeSync() {
        if (realtimeListenerReg != null) {
            realtimeListenerReg.remove();
            realtimeListenerReg = null;
            Log.d(TAG, "Real-time listener stopped");
        }
        realtimeCallback = null;
    }

    /**
     * Check if real-time sync listener is currently active.
     */
    public boolean isRealtimeSyncActive() {
        return realtimeListenerReg != null;
    }

    // ======================== UPLOAD NOTE ========================

    /**
     * Upload a single note to Firestore using RAW encrypted data from local DB.
     * Called after insertNote / updateNote in NoteEditorActivity.
     *
     * @param noteId local SQLite note ID
     */
    public void uploadNote(final long noteId) {
        if (!canSync()) return;
        final String uid = getUid();
        if (uid == null) return;

        try {
            isUploading = true;
            NotesRepository repo = NotesRepository.getInstance(appContext);
            Note rawNote = repo.getNoteRawById(noteId);
            if (rawNote == null || rawNote.getCloudId() == null) {
                isUploading = false;
                return;
            }

            Map<String, Object> data = noteToMap(rawNote);

            firestore.collection(COLLECTION_USERS).document(uid)
                    .collection(COLLECTION_NOTES).document(rawNote.getCloudId())
                    .set(data, SetOptions.merge())
                    .addOnSuccessListener(new OnSuccessListener<Void>() {
                        public void onSuccess(Void unused) {
                            Log.d(TAG, "Upload success: noteId=" + noteId);
                            NotesRepository.getInstance(appContext)
                                    .updateSyncStatus(noteId, Note.SYNC_STATUS_SYNCED);
                            isUploading = false;
                        }
                    })
                    .addOnFailureListener(new OnFailureListener() {
                        public void onFailure(Exception e) {
                            Log.e(TAG, "Upload failed: noteId=" + noteId + " - " + e.getMessage());
                            isUploading = false;
                            // syncStatus stays PENDING, will retry on next syncOnAppStart
                        }
                    });
        } catch (Exception e) {
            Log.e(TAG, "Upload exception: " + e.getMessage());
            isUploading = false;
        }
    }

    // ======================== DELETE NOTE (SOFT) ========================

    /**
     * Soft-delete a note in Firestore by setting isDeleted=true.
     * Called when moveToTrash() is used.
     */
    public void deleteNoteFromCloud(final String cloudId) {
        if (!canSync()) return;
        if (cloudId == null || cloudId.length() == 0) return;
        final String uid = getUid();
        if (uid == null) return;

        try {
            isUploading = true;
            Map<String, Object> deleteData = new HashMap<String, Object>();
            deleteData.put("isDeleted", Boolean.TRUE);
            deleteData.put("modifiedAt", Long.valueOf(System.currentTimeMillis()));

            firestore.collection(COLLECTION_USERS).document(uid)
                    .collection(COLLECTION_NOTES).document(cloudId)
                    .set(deleteData, SetOptions.merge())
                    .addOnSuccessListener(new OnSuccessListener<Void>() {
                        public void onSuccess(Void unused) {
                            Log.d(TAG, "Cloud soft-delete success: " + cloudId);
                            isUploading = false;
                        }
                    })
                    .addOnFailureListener(new OnFailureListener() {
                        public void onFailure(Exception e) {
                            Log.e(TAG, "Cloud soft-delete failed: " + e.getMessage());
                            isUploading = false;
                        }
                    });
        } catch (Exception e) {
            Log.e(TAG, "Delete exception: " + e.getMessage());
            isUploading = false;
        }
    }

    // ======================== UPLOAD ALL NOTES ========================

    /**
     * Upload ALL notes to Firestore. Used after password change re-encryption.
     * Reads ALL raw encrypted notes and pushes to cloud.
     */
    public void uploadAllNotes() {
        if (!canSync()) return;
        final String uid = getUid();
        if (uid == null) return;

        try {
            isUploading = true;
            NotesRepository repo = NotesRepository.getInstance(appContext);
            List allRaw = repo.getAllNotesRaw();

            if (allRaw.isEmpty()) {
                isUploading = false;
                return;
            }

            WriteBatch batch = firestore.batch();
            int batchCount = 0;

            for (int i = 0; i < allRaw.size(); i++) {
                Note rawNote = (Note) allRaw.get(i);
                if (rawNote.getCloudId() == null || rawNote.getCloudId().length() == 0) {
                    continue;
                }

                Map<String, Object> data = noteToMap(rawNote);
                batch.set(
                        firestore.collection(COLLECTION_USERS).document(uid)
                                .collection(COLLECTION_NOTES).document(rawNote.getCloudId()),
                        data, SetOptions.merge()
                );
                batchCount++;

                // Firestore batch limit is 500, commit in chunks
                if (batchCount >= 450) {
                    batch.commit();
                    batch = firestore.batch();
                    batchCount = 0;
                }
            }

            if (batchCount > 0) {
                batch.commit()
                        .addOnSuccessListener(new OnSuccessListener<Void>() {
                            public void onSuccess(Void unused) {
                                Log.d(TAG, "Upload all notes success");
                                isUploading = false;
                            }
                        })
                        .addOnFailureListener(new OnFailureListener() {
                            public void onFailure(Exception e) {
                                Log.e(TAG, "Upload all notes failed: " + e.getMessage());
                                isUploading = false;
                            }
                        });
            } else {
                isUploading = false;
            }
        } catch (Exception e) {
            Log.e(TAG, "Upload all exception: " + e.getMessage());
            isUploading = false;
        }
    }

    // ======================== SYNC ON APP START ========================

    /**
     * Full bidirectional sync on app start.
     * 1. Fetch ALL cloud notes
     * 2. Fetch ALL local notes raw
     * 3. Compare modifiedAt timestamps
     * 4. Cloud newer -> update local
     * 5. Local newer -> update cloud
     * 6. Only in cloud -> insert local
     * 7. Only in local -> upload to cloud
     * 8. Cloud isDeleted=true -> delete local
     */
    public void syncOnAppStart(final SyncCallback callback) {
        if (!canSync()) {
            if (callback != null) callback.onSyncComplete(false);
            return;
        }
        final String uid = getUid();
        if (uid == null) {
            if (callback != null) callback.onSyncComplete(false);
            return;
        }

        try {
            isUploading = true;
            firestore.collection(COLLECTION_USERS).document(uid)
                    .collection(COLLECTION_NOTES)
                    .get()
                    .addOnCompleteListener(new OnCompleteListener<QuerySnapshot>() {
                        public void onComplete(Task<QuerySnapshot> task) {
                            if (!task.isSuccessful()) {
                                Log.e(TAG, "Sync fetch failed: " +
                                        (task.getException() != null ? task.getException().getMessage() : "unknown"));
                                isUploading = false;
                                if (callback != null) callback.onSyncComplete(false);
                                return;
                            }

                            try {
                                performSync(task.getResult(), uid);
                                isUploading = false;
                                if (callback != null) callback.onSyncComplete(true);
                            } catch (Exception e) {
                                Log.e(TAG, "Sync processing error: " + e.getMessage());
                                isUploading = false;
                                if (callback != null) callback.onSyncComplete(false);
                            }
                        }
                    });
        } catch (Exception e) {
            Log.e(TAG, "Sync exception: " + e.getMessage());
            isUploading = false;
            if (callback != null) callback.onSyncComplete(false);
        }
    }

    /**
     * Perform the actual sync logic after cloud data is fetched.
     */
    private void performSync(QuerySnapshot cloudSnapshot, String uid) {
        NotesRepository repo = NotesRepository.getInstance(appContext);

        // Build cloud map: cloudId -> document data
        Map<String, Map<String, Object>> cloudMap = new HashMap<String, Map<String, Object>>();
        if (cloudSnapshot != null) {
            for (QueryDocumentSnapshot doc : cloudSnapshot) {
                cloudMap.put(doc.getId(), doc.getData());
            }
        }

        // Build local map: cloudId -> Note (raw)
        List localRawList = repo.getAllNotesRaw();
        Map<String, Note> localMap = new HashMap<String, Note>();
        for (int i = 0; i < localRawList.size(); i++) {
            Note n = (Note) localRawList.get(i);
            if (n.getCloudId() != null && n.getCloudId().length() > 0) {
                localMap.put(n.getCloudId(), n);
            }
        }

        WriteBatch uploadBatch = firestore.batch();
        int batchCount = 0;

        // Process cloud notes
        for (Map.Entry<String, Map<String, Object>> entry : cloudMap.entrySet()) {
            String cloudId = entry.getKey();
            Map<String, Object> cloudData = entry.getValue();

            boolean cloudDeleted = false;
            Object deletedObj = cloudData.get("isDeleted");
            if (deletedObj instanceof Boolean) {
                cloudDeleted = ((Boolean) deletedObj).booleanValue();
            }

            long cloudModified = 0;
            Object modObj = cloudData.get("modifiedAt");
            if (modObj instanceof Long) {
                cloudModified = ((Long) modObj).longValue();
            } else if (modObj instanceof Number) {
                cloudModified = ((Number) modObj).longValue();
            }

            if (localMap.containsKey(cloudId)) {
                // Note exists in both cloud and local
                Note localNote = localMap.get(cloudId);
                long localModified = localNote.getModifiedAt();

                if (cloudDeleted && cloudModified >= localModified) {
                    // Cloud says deleted and is newer -- delete locally
                    repo.deleteNoteByCloudId(cloudId);
                } else if (!cloudDeleted && cloudModified > localModified) {
                    // Cloud is newer -- update local with cloud data
                    Note cloudNote = mapToNote(cloudData, cloudId);
                    repo.updateNoteRaw(cloudNote);
                } else if (localModified > cloudModified) {
                    // Local is newer -- upload to cloud
                    Note freshRaw = repo.getNoteRawByCloudId(cloudId);
                    if (freshRaw != null) {
                        Map<String, Object> data = noteToMap(freshRaw);
                        uploadBatch.set(
                                firestore.collection(COLLECTION_USERS).document(uid)
                                        .collection(COLLECTION_NOTES).document(cloudId),
                                data, SetOptions.merge()
                        );
                        batchCount++;
                        repo.updateSyncStatus(localNote.getId(), Note.SYNC_STATUS_SYNCED);
                    }
                }
                // If equal timestamps, skip (already in sync)
                localMap.remove(cloudId);
            } else {
                // Note only in cloud -- insert locally (if not deleted)
                if (!cloudDeleted) {
                    Note cloudNote = mapToNote(cloudData, cloudId);
                    cloudNote.setSyncStatus(Note.SYNC_STATUS_SYNCED);
                    repo.insertNoteRaw(cloudNote);
                }
            }
        }

        // Notes only in local -- upload to cloud
        for (Map.Entry<String, Note> entry : localMap.entrySet()) {
            String cloudId = entry.getKey();
            Note localNote = entry.getValue();

            Note freshRaw = repo.getNoteRawByCloudId(cloudId);
            if (freshRaw != null) {
                Map<String, Object> data = noteToMap(freshRaw);
                uploadBatch.set(
                        firestore.collection(COLLECTION_USERS).document(uid)
                                .collection(COLLECTION_NOTES).document(cloudId),
                        data, SetOptions.merge()
                );
                batchCount++;
                repo.updateSyncStatus(localNote.getId(), Note.SYNC_STATUS_SYNCED);
            }

            if (batchCount >= 450) {
                uploadBatch.commit();
                uploadBatch = firestore.batch();
                batchCount = 0;
            }
        }

        // Commit remaining batch
        if (batchCount > 0) {
            uploadBatch.commit()
                    .addOnSuccessListener(new OnSuccessListener<Void>() {
                        public void onSuccess(Void unused) {
                            Log.d(TAG, "Sync upload batch committed");
                        }
                    })
                    .addOnFailureListener(new OnFailureListener() {
                        public void onFailure(Exception e) {
                            Log.e(TAG, "Sync upload batch failed: " + e.getMessage());
                        }
                    });
        }

        Log.d(TAG, "Sync complete: cloud=" + cloudMap.size() + " local=" + localRawList.size());
    }

    // ======================== DATA CONVERSION ========================

    /**
     * Convert a raw Note to a Firestore document map.
     * All encrypted fields are uploaded AS-IS (no decryption).
     *
     * CRITICAL FIX: Also syncs categoryName so that after reinstall,
     * the category can be re-created from its name. categoryId is a local
     * auto-increment ID that is meaningless after reinstall.
     */
    private Map<String, Object> noteToMap(Note note) {
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("title", note.getTitle() != null ? note.getTitle() : "");
        map.put("content", note.getContent() != null ? note.getContent() : "");
        map.put("checklistData", note.getChecklistData() != null ? note.getChecklistData() : "");
        map.put("routineData", note.getRoutineData() != null ? note.getRoutineData() : "");
        map.put("createdAt", Long.valueOf(note.getCreatedAt()));
        map.put("modifiedAt", Long.valueOf(note.getModifiedAt()));
        map.put("isDeleted", Boolean.FALSE);
        map.put("color", Integer.valueOf(note.getColor()));
        map.put("favorite", Boolean.valueOf(note.isFavorite()));
        map.put("locked", Boolean.valueOf(note.isLocked()));
        map.put("password", note.getPassword() != null ? note.getPassword() : "");
        map.put("categoryId", Long.valueOf(note.getCategoryId()));
        map.put("hasChecklist", Boolean.valueOf(note.hasChecklist()));
        map.put("hasImage", Boolean.valueOf(note.hasImage()));
        map.put("isChecklistMode", Boolean.valueOf(note.isChecklistMode()));
        map.put("imagesData", note.getImagesData() != null ? note.getImagesData() : "");
        map.put("filesData", note.getFilesData() != null ? note.getFilesData() : "");
        map.put("audiosData", note.getAudiosData() != null ? note.getAudiosData() : "");
        map.put("linkedNoteIds", note.getLinkedNoteIds() != null ? note.getLinkedNoteIds() : "");
        map.put("isRoutineMode", Boolean.valueOf(note.isRoutineMode()));
        map.put("archived", Boolean.valueOf(note.isArchived()));
        map.put("cloudId", note.getCloudId() != null ? note.getCloudId() : "");

        // CRITICAL FIX: Sync category name for reinstall recovery
        // categoryId is a local-only auto-increment that is lost on reinstall.
        // By storing the category name, we can re-create the category after reinstall.
        String categoryName = "";
        if (note.getCategoryId() > 0) {
            try {
                NotesRepository repo = NotesRepository.getInstance(appContext);
                com.mknotes.app.model.Category cat = repo.getCategoryById(note.getCategoryId());
                if (cat != null && cat.getName() != null) {
                    categoryName = cat.getName();
                }
            } catch (Exception e) {
                Log.w(TAG, "Failed to resolve category name for sync: " + e.getMessage());
            }
        }
        map.put("categoryName", categoryName);

        return map;
    }

    /**
     * Convert a Firestore document map back to a Note with raw encrypted data.
     * Used when downloading from cloud.
     *
     * CRITICAL FIX: Resolves categoryName to local categoryId.
     * After reinstall, the old categoryId is meaningless (local auto-increment).
     * If categoryName is present in Firestore, we find or create the matching
     * local category and assign the correct local ID.
     */
    private Note mapToNote(Map<String, Object> data, String cloudId) {
        Note note = new Note();
        note.setCloudId(cloudId);
        note.setTitle(getStringFromMap(data, "title"));
        note.setContent(getStringFromMap(data, "content"));
        note.setChecklistData(getStringFromMap(data, "checklistData"));
        note.setRoutineData(getStringFromMap(data, "routineData"));
        note.setCreatedAt(getLongFromMap(data, "createdAt"));
        note.setModifiedAt(getLongFromMap(data, "modifiedAt"));
        note.setColor(getIntFromMap(data, "color"));
        note.setFavorite(getBoolFromMap(data, "favorite"));
        note.setLocked(getBoolFromMap(data, "locked"));
        note.setPassword(getStringFromMap(data, "password"));
        note.setHasChecklist(getBoolFromMap(data, "hasChecklist"));
        note.setHasImage(getBoolFromMap(data, "hasImage"));
        note.setChecklistMode(getBoolFromMap(data, "isChecklistMode"));
        note.setImagesData(getStringFromMap(data, "imagesData"));
        note.setFilesData(getStringFromMap(data, "filesData"));
        note.setAudiosData(getStringFromMap(data, "audiosData"));
        note.setLinkedNoteIds(getStringFromMap(data, "linkedNoteIds"));
        note.setRoutineMode(getBoolFromMap(data, "isRoutineMode"));
        note.setArchived(getBoolFromMap(data, "archived"));

        // CRITICAL FIX: Resolve category by name, not by stale local ID
        long cloudCategoryId = getLongFromMap(data, "categoryId");
        String categoryName = getStringFromMap(data, "categoryName");

        if (categoryName != null && categoryName.length() > 0) {
            // Find or create local category by name
            long localCatId = resolveOrCreateCategory(categoryName);
            note.setCategoryId(localCatId);
        } else {
            // Fallback: use cloud categoryId as-is (may not match local)
            note.setCategoryId(cloudCategoryId);
        }

        return note;
    }

    /**
     * Find a local category by name, or create it if it doesn't exist.
     * Returns the local category ID.
     */
    private long resolveOrCreateCategory(String categoryName) {
        if (categoryName == null || categoryName.length() == 0) return -1;

        try {
            NotesRepository repo = NotesRepository.getInstance(appContext);
            java.util.List allCats = repo.getAllCategories();
            for (int i = 0; i < allCats.size(); i++) {
                com.mknotes.app.model.Category cat = (com.mknotes.app.model.Category) allCats.get(i);
                if (categoryName.equals(cat.getName())) {
                    return cat.getId();
                }
            }
            // Category doesn't exist locally -- create it
            com.mknotes.app.model.Category newCat = new com.mknotes.app.model.Category();
            newCat.setName(categoryName);
            newCat.setColor(0);
            newCat.setSortOrder(allCats.size());
            long newId = repo.insertCategory(newCat);
            Log.d(TAG, "Created missing category '" + categoryName + "' with local id=" + newId);
            return newId;
        } catch (Exception e) {
            Log.e(TAG, "Failed to resolve category: " + e.getMessage());
            return -1;
        }
    }

    // ======================== MAP HELPERS ========================

    private String getStringFromMap(Map<String, Object> map, String key) {
        Object val = map.get(key);
        if (val instanceof String) return (String) val;
        return "";
    }

    private long getLongFromMap(Map<String, Object> map, String key) {
        Object val = map.get(key);
        if (val instanceof Long) return ((Long) val).longValue();
        if (val instanceof Number) return ((Number) val).longValue();
        return 0;
    }

    private int getIntFromMap(Map<String, Object> map, String key) {
        Object val = map.get(key);
        if (val instanceof Integer) return ((Integer) val).intValue();
        if (val instanceof Long) return ((Long) val).intValue();
        if (val instanceof Number) return ((Number) val).intValue();
        return 0;
    }

    private boolean getBoolFromMap(Map<String, Object> map, String key) {
        Object val = map.get(key);
        if (val instanceof Boolean) return ((Boolean) val).booleanValue();
        return false;
    }

    // ======================== VAULT METADATA SYNC ========================

    private static final String COLLECTION_CRYPTO_METADATA = "crypto_metadata";
    private static final String DOC_VAULT = "vault";

    /**
     * Upload vault metadata to Firestore: users/{uid}/crypto_metadata/vault
     * NOTE: Prefer using KeyManager.uploadVaultToFirestore() directly.
     * This is kept for backward compatibility.
     */
    public void uploadVaultMetadata(Map<String, Object> vaultData) {
        String uid = getUid();
        if (uid == null || vaultData == null) return;

        firestore.collection(COLLECTION_USERS).document(uid)
                .collection(COLLECTION_CRYPTO_METADATA).document(DOC_VAULT)
                .set(vaultData)
                .addOnSuccessListener(new OnSuccessListener<Void>() {
                    public void onSuccess(Void unused) {
                        Log.d(TAG, "Vault metadata uploaded to Firestore");
                    }
                })
                .addOnFailureListener(new OnFailureListener() {
                    public void onFailure(Exception e) {
                        Log.e(TAG, "Vault metadata upload failed: " + e.getMessage());
                    }
                });
    }

    /**
     * Fetch vault metadata from Firestore: users/{uid}/crypto_metadata/vault
     * NOTE: Prefer using KeyManager.fetchVaultFromFirestore() directly.
     */
    public void fetchVaultMetadata(final VaultMetadataCallback callback) {
        String uid = getUid();
        if (uid == null) {
            if (callback != null) callback.onResult(null);
            return;
        }

        firestore.collection(COLLECTION_USERS).document(uid)
                .collection(COLLECTION_CRYPTO_METADATA).document(DOC_VAULT)
                .get()
                .addOnSuccessListener(new OnSuccessListener<DocumentSnapshot>() {
                    public void onSuccess(DocumentSnapshot doc) {
                        if (doc != null && doc.exists()) {
                            Map<String, Object> data = doc.getData();
                            Log.d(TAG, "Vault metadata fetched from Firestore");
                            if (callback != null) callback.onResult(data);
                        } else {
                            Log.d(TAG, "No vault metadata found in Firestore");
                            if (callback != null) callback.onResult(null);
                        }
                    }
                })
                .addOnFailureListener(new OnFailureListener() {
                    public void onFailure(Exception e) {
                        Log.e(TAG, "Vault metadata fetch failed: " + e.getMessage());
                        if (callback != null) callback.onResult(null);
                    }
                });
    }

    // ======================== CALLBACKS ========================

    /**
     * Callback for one-time sync operations (syncOnAppStart).
     */
    public interface SyncCallback {
        void onSyncComplete(boolean success);
    }

    /**
     * Callback for real-time snapshot changes.
     * Called on main thread when cloud changes are applied to local DB.
     * UI should refresh its note list when this fires.
     */
    public interface RealtimeChangeCallback {
        void onNotesChanged();
    }

    /**
     * Callback for vault metadata fetch operations.
     */
    public interface VaultMetadataCallback {
        void onResult(Map<String, Object> data);
    }
}
