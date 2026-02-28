package com.mknotes.app.model;

import java.io.Serializable;

public class Note implements Serializable {

    private long id;
    private String title;
    private String content;
    private long createdAt;
    private long modifiedAt;
    private int color;
    private boolean favorite;
    private boolean locked;
    private String password;
    private long categoryId;
    private boolean hasChecklist;
    private boolean hasImage;
    private String checklistData;
    private boolean isChecklistMode;
    private String imagesData;
    private String filesData;
    private String audiosData;
    private String linkedNoteIds;
    private boolean isRoutineMode;
    private String routineData;
    private boolean archived;
    private String cloudId;
    private int syncStatus; // 0=synced, 1=pending_upload, 2=pending_delete

    public static final int SYNC_STATUS_SYNCED = 0;
    public static final int SYNC_STATUS_PENDING = 1;
    public static final int SYNC_STATUS_PENDING_DELETE = 2;

    public Note() {
        this.id = -1;
        this.title = "";
        this.content = "";
        this.createdAt = System.currentTimeMillis();
        this.modifiedAt = System.currentTimeMillis();
        this.color = 0;
        this.favorite = false;
        this.locked = false;
        this.password = null;
        this.categoryId = -1;
        this.hasChecklist = false;
        this.hasImage = false;
        this.checklistData = "";
        this.isChecklistMode = false;
        this.imagesData = "";
        this.filesData = "";
        this.audiosData = "";
        this.linkedNoteIds = "";
        this.isRoutineMode = false;
        this.routineData = "";
        this.archived = false;
        this.cloudId = null;
        this.syncStatus = SYNC_STATUS_PENDING;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    public long getModifiedAt() {
        return modifiedAt;
    }

    public void setModifiedAt(long modifiedAt) {
        this.modifiedAt = modifiedAt;
    }

    public int getColor() {
        return color;
    }

    public void setColor(int color) {
        this.color = color;
    }

    public boolean isFavorite() {
        return favorite;
    }

    public void setFavorite(boolean favorite) {
        this.favorite = favorite;
    }

    public boolean isLocked() {
        return locked;
    }

    public void setLocked(boolean locked) {
        this.locked = locked;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public long getCategoryId() {
        return categoryId;
    }

    public void setCategoryId(long categoryId) {
        this.categoryId = categoryId;
    }

    public boolean hasChecklist() {
        return hasChecklist;
    }

    public void setHasChecklist(boolean hasChecklist) {
        this.hasChecklist = hasChecklist;
    }

    public boolean hasImage() {
        return hasImage;
    }

    public void setHasImage(boolean hasImage) {
        this.hasImage = hasImage;
    }

    public String getChecklistData() {
        return checklistData;
    }

    public void setChecklistData(String checklistData) {
        this.checklistData = checklistData != null ? checklistData : "";
    }

    public boolean isChecklistMode() {
        return isChecklistMode;
    }

    public void setChecklistMode(boolean isChecklistMode) {
        this.isChecklistMode = isChecklistMode;
    }

    public String getImagesData() {
        return imagesData;
    }

    public void setImagesData(String imagesData) {
        this.imagesData = imagesData != null ? imagesData : "";
    }

    public String getFilesData() {
        return filesData;
    }

    public void setFilesData(String filesData) {
        this.filesData = filesData != null ? filesData : "";
    }

    public String getAudiosData() {
        return audiosData;
    }

    public void setAudiosData(String audiosData) {
        this.audiosData = audiosData != null ? audiosData : "";
    }

    public String getLinkedNoteIds() {
        return linkedNoteIds;
    }

    public void setLinkedNoteIds(String linkedNoteIds) {
        this.linkedNoteIds = linkedNoteIds != null ? linkedNoteIds : "";
    }

    public boolean isRoutineMode() {
        return isRoutineMode;
    }

    public void setRoutineMode(boolean isRoutineMode) {
        this.isRoutineMode = isRoutineMode;
    }

    public String getRoutineData() {
        return routineData;
    }

    public void setRoutineData(String routineData) {
        this.routineData = routineData != null ? routineData : "";
    }

    public boolean isArchived() {
        return archived;
    }

    public void setArchived(boolean archived) {
        this.archived = archived;
    }

    public String getCloudId() {
        return cloudId;
    }

    public void setCloudId(String cloudId) {
        this.cloudId = cloudId;
    }

    public int getSyncStatus() {
        return syncStatus;
    }

    public void setSyncStatus(int syncStatus) {
        this.syncStatus = syncStatus;
    }

    public String getPreview() {
        // For checklist notes, show checklist summary
        if (isChecklistMode && checklistData != null && checklistData.length() > 2) {
            // Plain text content already has the checklist items as text
            if (content != null && content.length() > 0) {
                if (content.length() > 150) {
                    return content.substring(0, 150) + "...";
                }
                return content;
            }
        }
        if (content == null || content.length() == 0) {
            return "";
        }
        if (content.length() > 150) {
            return content.substring(0, 150) + "...";
        }
        return content;
    }
}
