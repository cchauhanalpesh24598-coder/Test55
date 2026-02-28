package com.mknotes.app.model;

import java.io.Serializable;

/**
 * Model class representing a Mantra for the Meditation system.
 * Stores mantra name, audio path, daily count, and metadata.
 * Pure Java, no AndroidX, no lambda - AIDE compatible.
 */
public class Mantra implements Serializable {

    private long id;
    private long noteId;
    private String name;
    private String audioPath;
    private int todayCount;
    private String lastCountDate;
    private long createdAt;
    private float playbackSpeed;
    private boolean isDeleted;
    private int rawResId;
    private boolean builtIn;

    public Mantra() {
        this.id = -1;
        this.noteId = -1;
        this.name = "";
        this.audioPath = "";
        this.todayCount = 0;
        this.lastCountDate = "";
        this.createdAt = System.currentTimeMillis();
        this.playbackSpeed = 1.0f;
        this.isDeleted = false;
        this.rawResId = 0;
        this.builtIn = false;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public long getNoteId() {
        return noteId;
    }

    public void setNoteId(long noteId) {
        this.noteId = noteId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name != null ? name : "";
    }

    public String getAudioPath() {
        return audioPath;
    }

    public void setAudioPath(String audioPath) {
        this.audioPath = audioPath != null ? audioPath : "";
    }

    public int getTodayCount() {
        return todayCount;
    }

    public void setTodayCount(int todayCount) {
        this.todayCount = todayCount;
    }

    public String getLastCountDate() {
        return lastCountDate;
    }

    public void setLastCountDate(String lastCountDate) {
        this.lastCountDate = lastCountDate != null ? lastCountDate : "";
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    public float getPlaybackSpeed() {
        return playbackSpeed;
    }

    public void setPlaybackSpeed(float playbackSpeed) {
        this.playbackSpeed = playbackSpeed;
    }

    public boolean isDeleted() {
        return isDeleted;
    }

    public void setDeleted(boolean deleted) {
        this.isDeleted = deleted;
    }

    public int getRawResId() {
        return rawResId;
    }

    public void setRawResId(int rawResId) {
        this.rawResId = rawResId;
    }

    public boolean isBuiltIn() {
        return builtIn;
    }

    public void setBuiltIn(boolean builtIn) {
        this.builtIn = builtIn;
    }

    /**
     * Returns formatted count string.
     * When count reaches 108, shows mala count.
     * e.g. "108" -> "1 Mala", "216" -> "2 Mala", "250" -> "2 Mala + 34"
     */
    public String getFormattedCount() {
        if (todayCount < 108) {
            return String.valueOf(todayCount);
        }
        int malas = todayCount / 108;
        int remainder = todayCount % 108;
        if (remainder == 0) {
            return malas + " Mala";
        }
        return malas + " Mala + " + remainder;
    }
}
