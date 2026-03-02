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

import com.google.firebase.storage.FirebaseStorage;
import com.google.firebase.storage.StorageReference;
import com.google.firebase.storage.UploadTask;

import com.mknotes.app.db.NotesDatabaseHelper;
import com.mknotes.app.db.NotesRepository;
import com.mknotes.app.model.Mantra;
import com.mknotes.app.model.Note;
import com.mknotes.app.util.PrefsManager;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;

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
    private static final String COLLECTION_MANTRAS = "mantras";
    private static final String COLLECTION_DAILY_SESSIONS = "daily_sessions";

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
     * Requires: sync enabled, Firebase logged in, vault unlocked (DEK in memory).
     *
     * CRITICAL FIX v3: Uses KeyManager.isVaultUnlocked() instead of
     * SessionManager.isSessionValid(). The vault unlock state is the
     * authoritative check for whether sync operations can proceed.
     * Session timestamp can have timing issues after reinstall.
     */
    private boolean canSync() {
        if (!PrefsManager.getInstance(appContext).isCloudSyncEnabled()) {
            return false;
        }
        if (!FirebaseAuthManager.getInstance(appContext).isLoggedIn()) {
            return false;
        }
        if (!com.mknotes.app.crypto.KeyManager.getInstance(appContext).isVaultUnlocked()) {
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
                        // Re-check vault unlock before processing
                        if (!com.mknotes.app.crypto.KeyManager.getInstance(appContext).isVaultUnlocked()) {
                            Log.w(TAG, "Vault locked during realtime event, skipping");
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

        // Notes only in local -- upload to cloud (including attachments)
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

                // Upload attachment files for local-only notes being synced for the first time
                boolean hasAttachments = (freshRaw.getImagesData() != null && freshRaw.getImagesData().length() > 0)
                        || (freshRaw.getFilesData() != null && freshRaw.getFilesData().length() > 0)
                        || (freshRaw.getAudiosData() != null && freshRaw.getAudiosData().length() > 0);
                if (hasAttachments) {
                    uploadAllAttachmentsForNote(localNote.getId());
                }
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

    // ======================== MANTRA SYNC ========================

    /**
     * Upload a single mantra to Firestore.
     * Path: users/{uid}/mantras/{cloudId}
     * Only syncs user-added mantras (not built-in).
     * Built-in mantras are seeded on every fresh install.
     */
    public void uploadMantra(final long mantraId) {
        if (!canSync()) return;
        final String uid = getUid();
        if (uid == null) return;

        try {
            NotesRepository repo = NotesRepository.getInstance(appContext);
            Mantra mantra = repo.getMantraById(mantraId);
            if (mantra == null || mantra.isBuiltIn()) return;

            String cloudId = repo.getMantraCloudId(mantraId);
            if (cloudId == null || cloudId.length() == 0) {
                cloudId = firestore.collection(COLLECTION_USERS).document(uid)
                        .collection(COLLECTION_MANTRAS).document().getId();
                repo.setMantraCloudId(mantraId, cloudId);
            }

            Map<String, Object> data = mantraToMap(mantra);

            firestore.collection(COLLECTION_USERS).document(uid)
                    .collection(COLLECTION_MANTRAS).document(cloudId)
                    .set(data, SetOptions.merge())
                    .addOnSuccessListener(new OnSuccessListener<Void>() {
                        public void onSuccess(Void unused) {
                            Log.d(TAG, "Mantra upload success: id=" + mantraId);
                        }
                    })
                    .addOnFailureListener(new OnFailureListener() {
                        public void onFailure(Exception e) {
                            Log.e(TAG, "Mantra upload failed: " + e.getMessage());
                        }
                    });
        } catch (Exception e) {
            Log.e(TAG, "Mantra upload exception: " + e.getMessage());
        }
    }

    /**
     * Upload a daily session to Firestore.
     * Path: users/{uid}/daily_sessions/{cloudId}
     */
    public void uploadDailySession(final long mantraId, final String date) {
        if (!canSync()) return;
        final String uid = getUid();
        if (uid == null) return;

        try {
            NotesRepository repo = NotesRepository.getInstance(appContext);
            int count = repo.getSessionCount(mantraId, date);
            float speed = repo.getSessionSpeed(mantraId, date);

            // Get or create cloud_id for this session
            String sessionCloudId = repo.getDailySessionCloudId(mantraId, date);
            if (sessionCloudId == null || sessionCloudId.length() == 0) {
                sessionCloudId = firestore.collection(COLLECTION_USERS).document(uid)
                        .collection(COLLECTION_DAILY_SESSIONS).document().getId();
                repo.setDailySessionCloudId(mantraId, date, sessionCloudId);
            }

            // Get mantra cloudId so we can link them on restore
            String mantraCloudId = repo.getMantraCloudId(mantraId);
            // For built-in mantras that don't have a cloud_id, use a stable key
            Mantra mantra = repo.getMantraById(mantraId);
            String mantraName = (mantra != null) ? mantra.getName() : "";
            boolean isBuiltIn = (mantra != null) && mantra.isBuiltIn();

            Map<String, Object> data = new HashMap<String, Object>();
            data.put("mantraCloudId", mantraCloudId != null ? mantraCloudId : "");
            data.put("mantraName", mantraName);
            data.put("isBuiltInMantra", Boolean.valueOf(isBuiltIn));
            data.put("date", date);
            data.put("count", Integer.valueOf(count));
            data.put("speed", Float.valueOf(speed));
            data.put("mantraLocalId", Long.valueOf(mantraId));

            firestore.collection(COLLECTION_USERS).document(uid)
                    .collection(COLLECTION_DAILY_SESSIONS).document(sessionCloudId)
                    .set(data, SetOptions.merge())
                    .addOnSuccessListener(new OnSuccessListener<Void>() {
                        public void onSuccess(Void unused) {
                            Log.d(TAG, "Session upload success: mantra=" + mantraId + " date=" + date);
                        }
                    })
                    .addOnFailureListener(new OnFailureListener() {
                        public void onFailure(Exception e) {
                            Log.e(TAG, "Session upload failed: " + e.getMessage());
                        }
                    });
        } catch (Exception e) {
            Log.e(TAG, "Session upload exception: " + e.getMessage());
        }
    }

    /**
     * Sync all mantras and daily sessions on app start.
     * Downloads mantras and sessions from Firestore, merges with local data.
     * Uploads local-only mantras/sessions to Firestore.
     */
    public void syncMantrasAndSessions(final SyncCallback callback) {
        if (!canSync()) {
            if (callback != null) callback.onSyncComplete(false);
            return;
        }
        final String uid = getUid();
        if (uid == null) {
            if (callback != null) callback.onSyncComplete(false);
            return;
        }

        // Step 1: Sync mantras
        firestore.collection(COLLECTION_USERS).document(uid)
                .collection(COLLECTION_MANTRAS)
                .get()
                .addOnCompleteListener(new OnCompleteListener<QuerySnapshot>() {
                    public void onComplete(Task<QuerySnapshot> task) {
                        if (task.isSuccessful() && task.getResult() != null) {
                            try {
                                performMantraSync(task.getResult(), uid);
                            } catch (Exception e) {
                                Log.e(TAG, "Mantra sync error: " + e.getMessage());
                            }
                        }

                        // Step 2: Sync daily sessions after mantras
                        syncDailySessions(uid, callback);
                    }
                });
    }

    private void performMantraSync(QuerySnapshot cloudSnapshot, String uid) {
        NotesRepository repo = NotesRepository.getInstance(appContext);

        // Build cloud map
        Map<String, Map<String, Object>> cloudMap = new HashMap<String, Map<String, Object>>();
        for (QueryDocumentSnapshot doc : cloudSnapshot) {
            cloudMap.put(doc.getId(), doc.getData());
        }

        // Build local map: cloud_id -> Mantra (user-added only)
        List allMantras = repo.getAllUserAddedMantras();
        Map<String, Mantra> localMap = new HashMap<String, Mantra>();
        for (int i = 0; i < allMantras.size(); i++) {
            Mantra m = (Mantra) allMantras.get(i);
            String cid = repo.getMantraCloudId(m.getId());
            if (cid != null && cid.length() > 0) {
                localMap.put(cid, m);
            }
        }

        WriteBatch batch = firestore.batch();
        int batchCount = 0;

        // Process cloud mantras
        for (Map.Entry<String, Map<String, Object>> entry : cloudMap.entrySet()) {
            String cloudId = entry.getKey();
            Map<String, Object> data = entry.getValue();

            if (!localMap.containsKey(cloudId)) {
                // Cloud mantra not in local -> insert
                Mantra newMantra = mapToMantra(data);

                // CRITICAL FIX: Resolve noteId from noteCloudId after reinstall.
                // The stored noteId is the OLD local auto-increment ID from the
                // original device. After reinstall, notes get new local IDs.
                // Use noteCloudId to find the correct current local note ID.
                String noteCloudId = getStringFromMap(data, "noteCloudId");
                if (noteCloudId != null && noteCloudId.length() > 0) {
                    Note localNote = repo.getNoteRawByCloudId(noteCloudId);
                    if (localNote != null) {
                        newMantra.setNoteId(localNote.getId());
                    }
                    // If note not found yet (sync ordering), keep cloud noteId
                    // It will be stale but the mantra still exists in master list
                }

                long newId = repo.insertMantra(newMantra);
                if (newId > 0) {
                    repo.setMantraCloudId(newId, cloudId);
                    Log.d(TAG, "Mantra sync: inserted '" + newMantra.getName() + "' from cloud, noteId=" + newMantra.getNoteId());
                }
            }
            localMap.remove(cloudId);
        }

        // Local-only mantras -> upload to cloud
        for (Map.Entry<String, Mantra> entry : localMap.entrySet()) {
            Mantra m = entry.getValue();
            String cloudId = entry.getKey();
            Map<String, Object> data = mantraToMap(m);
            batch.set(
                    firestore.collection(COLLECTION_USERS).document(uid)
                            .collection(COLLECTION_MANTRAS).document(cloudId),
                    data, SetOptions.merge()
            );
            batchCount++;
            if (batchCount >= 450) {
                batch.commit();
                batch = firestore.batch();
                batchCount = 0;
            }
        }
        if (batchCount > 0) {
            batch.commit();
        }
    }

    private void syncDailySessions(final String uid, final SyncCallback callback) {
        firestore.collection(COLLECTION_USERS).document(uid)
                .collection(COLLECTION_DAILY_SESSIONS)
                .get()
                .addOnCompleteListener(new OnCompleteListener<QuerySnapshot>() {
                    public void onComplete(Task<QuerySnapshot> task) {
                        if (task.isSuccessful() && task.getResult() != null) {
                            try {
                                performSessionSync(task.getResult(), uid);
                            } catch (Exception e) {
                                Log.e(TAG, "Session sync error: " + e.getMessage());
                            }
                        }
                        if (callback != null) callback.onSyncComplete(true);
                    }
                });
    }

    private void performSessionSync(QuerySnapshot cloudSnapshot, String uid) {
        NotesRepository repo = NotesRepository.getInstance(appContext);

        for (QueryDocumentSnapshot doc : cloudSnapshot) {
            String sessionCloudId = doc.getId();
            Map<String, Object> data = doc.getData();

            String mantraCloudId = getStringFromMap(data, "mantraCloudId");
            String mantraName = getStringFromMap(data, "mantraName");
            boolean isBuiltIn = getBoolFromMap(data, "isBuiltInMantra");
            String date = getStringFromMap(data, "date");
            int count = getIntFromMap(data, "count");
            float speed = 1.0f;
            Object speedObj = data.get("speed");
            if (speedObj instanceof Float) speed = ((Float) speedObj).floatValue();
            else if (speedObj instanceof Double) speed = ((Double) speedObj).floatValue();
            else if (speedObj instanceof Number) speed = ((Number) speedObj).floatValue();

            if (date == null || date.length() == 0) continue;

            // Resolve mantra local ID
            long localMantraId = resolveMantraId(repo, mantraCloudId, mantraName, isBuiltIn);
            if (localMantraId <= 0) continue;

            // Check if session already exists locally for this cloud_id
            String existingCloudId = repo.getDailySessionCloudId(localMantraId, date);
            if (existingCloudId != null && existingCloudId.equals(sessionCloudId)) {
                // Already synced - update count if cloud has more
                int localCount = repo.getSessionCount(localMantraId, date);
                if (count > localCount) {
                    repo.getOrCreateDailySession(localMantraId, date);
                    repo.setDailySessionCount(localMantraId, date, count);
                    repo.updateSessionSpeed(localMantraId, date, speed);
                }
                continue;
            }

            // New session from cloud
            int localCount = repo.getSessionCount(localMantraId, date);
            if (localCount == 0 && count > 0) {
                repo.getOrCreateDailySession(localMantraId, date);
                repo.setDailySessionCount(localMantraId, date, count);
                repo.updateSessionSpeed(localMantraId, date, speed);
                repo.setDailySessionCloudId(localMantraId, date, sessionCloudId);
                Log.d(TAG, "Session sync: restored session for '" + mantraName + "' date=" + date + " count=" + count);
            } else if (count > localCount) {
                repo.setDailySessionCount(localMantraId, date, count);
                repo.updateSessionSpeed(localMantraId, date, speed);
                repo.setDailySessionCloudId(localMantraId, date, sessionCloudId);
            }
        }
    }

    /**
     * Resolve a mantra's local ID from its cloud_id or name.
     * For built-in mantras, matches by name. For user mantras, matches by cloud_id.
     */
    private long resolveMantraId(NotesRepository repo, String mantraCloudId, String mantraName, boolean isBuiltIn) {
        if (isBuiltIn && mantraName != null && mantraName.length() > 0) {
            // Match built-in by name
            List allMantras = repo.getAllMantras();
            for (int i = 0; i < allMantras.size(); i++) {
                Mantra m = (Mantra) allMantras.get(i);
                if (m.isBuiltIn() && mantraName.equals(m.getName())) {
                    return m.getId();
                }
            }
        }
        if (mantraCloudId != null && mantraCloudId.length() > 0) {
            // Match user mantra by cloud_id
            long id = repo.getMantraIdByCloudId(mantraCloudId);
            if (id > 0) return id;
        }
        // Last resort: match any mantra by name
        if (mantraName != null && mantraName.length() > 0) {
            List allMantras = repo.getAllMantras();
            for (int i = 0; i < allMantras.size(); i++) {
                Mantra m = (Mantra) allMantras.get(i);
                if (mantraName.equals(m.getName())) {
                    return m.getId();
                }
            }
        }
        return -1;
    }

    private Map<String, Object> mantraToMap(Mantra mantra) {
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("name", mantra.getName());
        map.put("audioPath", mantra.getAudioPath());
        map.put("noteId", Long.valueOf(mantra.getNoteId()));
        map.put("todayCount", Integer.valueOf(mantra.getTodayCount()));
        map.put("lastCountDate", mantra.getLastCountDate());
        map.put("createdAt", Long.valueOf(mantra.getCreatedAt()));
        map.put("playbackSpeed", Float.valueOf(mantra.getPlaybackSpeed()));
        map.put("isDeleted", Boolean.valueOf(mantra.isDeleted()));
        map.put("builtIn", Boolean.valueOf(mantra.isBuiltIn()));

        // CRITICAL FIX: Store note's cloudId so after reinstall we can resolve
        // the correct local note ID. The local noteId is an auto-increment that
        // changes after reinstall, making it useless for cross-device linking.
        String noteCloudId = "";
        if (mantra.getNoteId() > 0) {
            try {
                NotesRepository repo = NotesRepository.getInstance(appContext);
                Note rawNote = repo.getNoteRawById(mantra.getNoteId());
                if (rawNote != null && rawNote.getCloudId() != null) {
                    noteCloudId = rawNote.getCloudId();
                }
            } catch (Exception e) {
                Log.w(TAG, "Failed to resolve note cloudId for mantra: " + e.getMessage());
            }
        }
        map.put("noteCloudId", noteCloudId);

        return map;
    }

    private Mantra mapToMantra(Map<String, Object> data) {
        Mantra m = new Mantra();
        m.setName(getStringFromMap(data, "name"));
        m.setAudioPath(getStringFromMap(data, "audioPath"));
        m.setNoteId(getLongFromMap(data, "noteId"));
        m.setTodayCount(getIntFromMap(data, "todayCount"));
        m.setLastCountDate(getStringFromMap(data, "lastCountDate"));
        m.setCreatedAt(getLongFromMap(data, "createdAt"));
        Object speedObj = data.get("playbackSpeed");
        if (speedObj instanceof Float) m.setPlaybackSpeed(((Float) speedObj).floatValue());
        else if (speedObj instanceof Double) m.setPlaybackSpeed(((Double) speedObj).floatValue());
        else if (speedObj instanceof Number) m.setPlaybackSpeed(((Number) speedObj).floatValue());
        else m.setPlaybackSpeed(1.0f);
        m.setDeleted(getBoolFromMap(data, "isDeleted"));
        m.setBuiltIn(false); // Only user mantras are synced
        return m;
    }

    // ======================== ATTACHMENT SYNC (Firebase Storage) ========================

    /**
     * Upload a single attachment file to Firebase Storage.
     * Path: users/{uid}/attachments/{noteCloudId}/{subDir}/{localName}
     *
     * @param noteCloudId the note's cloud ID
     * @param subDir      "images", "files", or "audios"
     * @param localName   the local file name
     * @param file        the local file to upload
     */
    public void uploadAttachment(final String noteCloudId, final String subDir,
                                  final String localName, final File file) {
        if (!canSync()) return;
        if (noteCloudId == null || noteCloudId.length() == 0) return;
        if (file == null || !file.exists()) return;
        final String uid = getUid();
        if (uid == null) return;

        try {
            FirebaseStorage storage = FirebaseStorage.getInstance();
            String storagePath = "users/" + uid + "/attachments/" + noteCloudId + "/" + subDir + "/" + localName;
            StorageReference ref = storage.getReference().child(storagePath);

            Uri fileUri = Uri.fromFile(file);
            ref.putFile(fileUri)
                    .addOnSuccessListener(new OnSuccessListener<UploadTask.TaskSnapshot>() {
                        public void onSuccess(UploadTask.TaskSnapshot snap) {
                            Log.d(TAG, "Attachment uploaded: " + subDir + "/" + localName);
                        }
                    })
                    .addOnFailureListener(new OnFailureListener() {
                        public void onFailure(Exception e) {
                            Log.e(TAG, "Attachment upload failed: " + e.getMessage());
                        }
                    });
        } catch (Exception e) {
            Log.e(TAG, "Attachment upload exception: " + e.getMessage());
        }
    }

    /**
     * Upload all attachments for a note by parsing its metadata fields.
     * Called after a note with attachments is saved.
     *
     * @param noteId local note ID
     */
    public void uploadAllAttachmentsForNote(final long noteId) {
        if (!canSync()) return;
        final String uid = getUid();
        if (uid == null) return;

        try {
            NotesRepository repo = NotesRepository.getInstance(appContext);
            Note rawNote = repo.getNoteRawById(noteId);
            if (rawNote == null || rawNote.getCloudId() == null) return;

            String noteCloudId = rawNote.getCloudId();
            File attachDir = new File(appContext.getFilesDir(), "attachments/" + noteId);

            // Upload images
            uploadAttachmentsFromDir(noteCloudId, "images", new File(attachDir, "images"));
            // Upload files
            uploadAttachmentsFromDir(noteCloudId, "files", new File(attachDir, "files"));
            // Upload audios
            uploadAttachmentsFromDir(noteCloudId, "audios", new File(attachDir, "audios"));

        } catch (Exception e) {
            Log.e(TAG, "Upload all attachments exception: " + e.getMessage());
        }
    }

    private void uploadAttachmentsFromDir(String noteCloudId, String subDir, File dir) {
        if (dir == null || !dir.exists() || !dir.isDirectory()) return;
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File f : files) {
            if (f.isFile() && f.length() > 0) {
                uploadAttachment(noteCloudId, subDir, f.getName(), f);
            }
        }
    }

    /**
     * Download all missing attachments for a note from Firebase Storage.
     * Parses imagesData/filesData/audiosData metadata to find expected files,
     * checks if they exist locally, and downloads missing ones.
     *
     * @param noteId      local note ID
     * @param noteCloudId the note's cloud ID
     * @param imagesData  encrypted/raw images metadata JSON
     * @param filesData   encrypted/raw files metadata JSON
     * @param audiosData  encrypted/raw audios metadata JSON
     */
    public void downloadMissingAttachments(final long noteId, final String noteCloudId,
                                            String imagesData, String filesData, String audiosData) {
        if (!canSync()) return;
        if (noteCloudId == null || noteCloudId.length() == 0) return;
        final String uid = getUid();
        if (uid == null) return;

        File attachDir = new File(appContext.getFilesDir(), "attachments/" + noteId);

        // Parse and download images
        downloadAttachmentFiles(uid, noteCloudId, "images", imagesData, new File(attachDir, "images"));
        // Parse and download files
        downloadAttachmentFiles(uid, noteCloudId, "files", filesData, new File(attachDir, "files"));
        // Parse and download audios
        downloadAttachmentFiles(uid, noteCloudId, "audios", audiosData, new File(attachDir, "audios"));
    }

    /**
     * Parse attachment metadata JSON and download files that are missing locally.
     * The metadata is a JSONArray of objects with "localName" field.
     * Data may be encrypted - try to parse, if it fails, try decrypting first.
     */
    private void downloadAttachmentFiles(final String uid, final String noteCloudId,
                                          final String subDir, String metadataStr, final File localDir) {
        if (metadataStr == null || metadataStr.length() == 0) return;

        try {
            // Try to parse directly (might be plaintext after decryption in the caller)
            String jsonStr = metadataStr;

            // Try decrypting if it's encrypted
            try {
                byte[] dek = com.mknotes.app.crypto.KeyManager.getInstance(appContext).getDEK();
                if (dek != null) {
                    String decrypted = com.mknotes.app.crypto.CryptoManager.decrypt(metadataStr, dek);
                    if (decrypted != null && decrypted.length() > 0 && decrypted.startsWith("[")) {
                        jsonStr = decrypted;
                    }
                }
            } catch (Exception e) {
                // Not encrypted or decrypt failed, try raw
            }

            if (!jsonStr.startsWith("[")) return;

            org.json.JSONArray arr = new org.json.JSONArray(jsonStr);
            for (int i = 0; i < arr.length(); i++) {
                org.json.JSONObject obj = arr.getJSONObject(i);
                final String localName = obj.optString("localName", "");
                if (localName.length() == 0) continue;

                final File localFile = new File(localDir, localName);
                if (localFile.exists() && localFile.length() > 0) continue;

                // File missing locally - download from Storage
                if (!localDir.exists()) {
                    localDir.mkdirs();
                }

                String storagePath = "users/" + uid + "/attachments/" + noteCloudId + "/" + subDir + "/" + localName;
                FirebaseStorage storage = FirebaseStorage.getInstance();
                StorageReference ref = storage.getReference().child(storagePath);

                ref.getFile(localFile)
                        .addOnSuccessListener(new OnSuccessListener<com.google.firebase.storage.FileDownloadTask.TaskSnapshot>() {
                            public void onSuccess(com.google.firebase.storage.FileDownloadTask.TaskSnapshot snap) {
                                Log.d(TAG, "Attachment downloaded: " + subDir + "/" + localName);
                            }
                        })
                        .addOnFailureListener(new OnFailureListener() {
                            public void onFailure(Exception e) {
                                Log.w(TAG, "Attachment download failed: " + subDir + "/" + localName + " - " + e.getMessage());
                                // Clean up empty file
                                if (localFile.exists() && localFile.length() == 0) {
                                    localFile.delete();
                                }
                            }
                        });
            }
        } catch (Exception e) {
            Log.e(TAG, "Download attachments parse error for " + subDir + ": " + e.getMessage());
        }
    }

    /**
     * After syncOnAppStart completes, scan all synced notes for missing attachments
     * and trigger downloads for any that are missing.
     */
    public void downloadAllMissingAttachments() {
        if (!canSync()) return;

        try {
            NotesRepository repo = NotesRepository.getInstance(appContext);
            List allRaw = repo.getAllNotesRaw();

            for (int i = 0; i < allRaw.size(); i++) {
                Note note = (Note) allRaw.get(i);
                if (note.getCloudId() == null || note.getCloudId().length() == 0) continue;

                boolean hasImages = note.getImagesData() != null && note.getImagesData().length() > 0;
                boolean hasFiles = note.getFilesData() != null && note.getFilesData().length() > 0;
                boolean hasAudios = note.getAudiosData() != null && note.getAudiosData().length() > 0;

                if (hasImages || hasFiles || hasAudios) {
                    downloadMissingAttachments(
                            note.getId(), note.getCloudId(),
                            note.getImagesData(), note.getFilesData(), note.getAudiosData()
                    );
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Download all missing attachments exception: " + e.getMessage());
        }
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
