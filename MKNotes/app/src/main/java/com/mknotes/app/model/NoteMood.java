package com.mknotes.app.model;

import java.io.Serializable;

/**
 * Represents a single mood entry attached to a note.
 * Each note can have multiple moods with different intensities.
 */
public class NoteMood implements Serializable {

    private long id;
    private long noteId;
    private String date;
    private long timestamp;
    private String emojiUnicode;
    private String moodName;
    private int intensityLevel; // 1=Very Low, 2=Low, 3=Medium, 4=High, 5=Extreme

    public static final int INTENSITY_VERY_LOW = 1;
    public static final int INTENSITY_LOW = 2;
    public static final int INTENSITY_MEDIUM = 3;
    public static final int INTENSITY_HIGH = 4;
    public static final int INTENSITY_EXTREME = 5;

    // Predefined moods
    public static final String[][] PREDEFINED_MOODS = {
        {"\uD83D\uDE0A", "Happy"},
        {"\uD83D\uDE22", "Sad"},
        {"\uD83D\uDE21", "Angry"},
        {"\uD83D\uDE10", "Neutral"},
        {"\uD83D\uDE36", "Silent"},
        {"\uD83D\uDE4F", "Spiritual"},
        {"\uD83D\uDE1E", "Mood Off"},
        {"\uD83D\uDE34", "Tired"},
        {"\uD83D\uDE0D", "Romantic"},
        {"\uD83E\uDD14", "Research"}
    };

    // Intensity labels and dot colors (color hex for canvas drawing)
    public static final String[] INTENSITY_LABELS = {
        "Very Low", "Low", "Medium", "High", "Extreme"
    };

    public static final int[] INTENSITY_COLORS = {
        0xFF8D6E63, // Brown - Very Low
        0xFF4CAF50, // Green - Low
        0xFFFFEB3B, // Yellow - Medium
        0xFFFF9800, // Orange - High
        0xFFF44336  // Red - Extreme
    };

    public NoteMood() {
        this.id = -1;
        this.noteId = -1;
        this.date = "";
        this.timestamp = System.currentTimeMillis();
        this.emojiUnicode = "";
        this.moodName = "";
        this.intensityLevel = INTENSITY_MEDIUM;
    }

    public NoteMood(long noteId, String date, String emojiUnicode, String moodName, int intensityLevel) {
        this.id = -1;
        this.noteId = noteId;
        this.date = date;
        this.timestamp = System.currentTimeMillis();
        this.emojiUnicode = emojiUnicode;
        this.moodName = moodName;
        this.intensityLevel = intensityLevel;
    }

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }

    public long getNoteId() { return noteId; }
    public void setNoteId(long noteId) { this.noteId = noteId; }

    public String getDate() { return date; }
    public void setDate(String date) { this.date = date; }

    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

    public String getEmojiUnicode() { return emojiUnicode; }
    public void setEmojiUnicode(String emojiUnicode) { this.emojiUnicode = emojiUnicode; }

    public String getMoodName() { return moodName; }
    public void setMoodName(String moodName) { this.moodName = moodName; }

    public int getIntensityLevel() { return intensityLevel; }
    public void setIntensityLevel(int intensityLevel) { this.intensityLevel = intensityLevel; }

    public String getIntensityLabel() {
        if (intensityLevel >= 1 && intensityLevel <= 5) {
            return INTENSITY_LABELS[intensityLevel - 1];
        }
        return "Medium";
    }

    public int getIntensityColor() {
        if (intensityLevel >= 1 && intensityLevel <= 5) {
            return INTENSITY_COLORS[intensityLevel - 1];
        }
        return INTENSITY_COLORS[2];
    }

    /**
     * Get the emoji for a given mood name from predefined list.
     */
    public static String getEmojiForMood(String moodName) {
        if (moodName == null) return "";
        for (int i = 0; i < PREDEFINED_MOODS.length; i++) {
            if (PREDEFINED_MOODS[i][1].equals(moodName)) {
                return PREDEFINED_MOODS[i][0];
            }
        }
        return "";
    }
}
