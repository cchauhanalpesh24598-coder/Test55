package com.mknotes.app.routine;

/**
 * Manages routine data serialization/deserialization.
 * Format: WAKE=06:45 AM|SLEEP=10:00 PM|ENTRIES=line1\nline2\nline3
 * Pure Java, no AndroidX, no lambda, AIDE compatible.
 */
public class RoutineManager {

    private static final String SEP = "|";
    private static final String WAKE_PREFIX = "WAKE=";
    private static final String SLEEP_PREFIX = "SLEEP=";
    private static final String ENTRIES_PREFIX = "ENTRIES=";

    private String wakeTime;
    private String sleepTime;
    private String entriesText;

    public RoutineManager() {
        this.wakeTime = "";
        this.sleepTime = "";
        this.entriesText = "";
    }

    public String getWakeTime() {
        return wakeTime;
    }

    public void setWakeTime(String wakeTime) {
        this.wakeTime = wakeTime != null ? wakeTime : "";
    }

    public String getSleepTime() {
        return sleepTime;
    }

    public void setSleepTime(String sleepTime) {
        this.sleepTime = sleepTime != null ? sleepTime : "";
    }

    public String getEntriesText() {
        return entriesText;
    }

    public void setEntriesText(String entriesText) {
        this.entriesText = entriesText != null ? entriesText : "";
    }

    /**
     * Serialize to a single string for DB storage.
     */
    public String serialize() {
        StringBuilder sb = new StringBuilder();
        sb.append(WAKE_PREFIX);
        sb.append(wakeTime != null ? wakeTime : "");
        sb.append(SEP);
        sb.append(SLEEP_PREFIX);
        sb.append(sleepTime != null ? sleepTime : "");
        sb.append(SEP);
        sb.append(ENTRIES_PREFIX);
        sb.append(entriesText != null ? entriesText : "");
        return sb.toString();
    }

    /**
     * Deserialize from DB string.
     */
    public void deserialize(String data) {
        wakeTime = "";
        sleepTime = "";
        entriesText = "";

        if (data == null || data.length() == 0) {
            return;
        }

        int wakeIdx = data.indexOf(WAKE_PREFIX);
        int sleepIdx = data.indexOf(SEP + SLEEP_PREFIX);
        int entriesIdx = data.indexOf(SEP + ENTRIES_PREFIX);

        if (wakeIdx >= 0 && sleepIdx > wakeIdx) {
            wakeTime = data.substring(wakeIdx + WAKE_PREFIX.length(), sleepIdx).trim();
        }

        if (sleepIdx >= 0 && entriesIdx > sleepIdx) {
            int start = sleepIdx + 1 + SLEEP_PREFIX.length();
            sleepTime = data.substring(start, entriesIdx).trim();
        }

        if (entriesIdx >= 0) {
            int start = entriesIdx + 1 + ENTRIES_PREFIX.length();
            if (start <= data.length()) {
                entriesText = data.substring(start);
            }
        }
    }

    /**
     * Format a 12-hour time string from hour (0-23) and minute.
     * Returns format like "07:00 AM" or "01:30 PM".
     */
    public static String formatTime12(int hour, int minute) {
        boolean isPm = hour >= 12;
        int displayHour = hour % 12;
        if (displayHour == 0) {
            displayHour = 12;
        }
        String amPm = isPm ? "PM" : "AM";
        String h = displayHour < 10 ? "0" + displayHour : String.valueOf(displayHour);
        String m = minute < 10 ? "0" + minute : String.valueOf(minute);
        return h + ":" + m + " " + amPm;
    }

    /**
     * Parse raw 4-digit input into formatted time string.
     * User always types exactly 4 digits. Example: "0700" -> "07:00 AM"
     *
     * AM/PM is determined by the currentlyPm flag which tracks the phase
     * of the previous entry. If no previous context, defaultPm is used.
     *
     * @param raw         raw digit string (exactly 4 digits)
     * @param defaultPm   if true, default AM/PM suffix is PM (e.g. Sleep field)
     * @param currentlyPm whether the current phase is PM (based on previous entries)
     * @return formatted string like "06:45 AM" or null if invalid
     */
    public static String parseDigitsToTime(String raw, boolean defaultPm, boolean currentlyPm) {
        if (raw == null) return null;
        raw = raw.trim();

        // Only accept exactly 4 digits
        if (!raw.matches("\\d{4}")) {
            return null;
        }

        int hour = Integer.parseInt(raw.substring(0, 2));
        int minute = Integer.parseInt(raw.substring(2, 4));

        if (minute > 59) return null;
        if (hour > 12) return null;
        if (hour == 0) hour = 12;

        String amPm;
        if (currentlyPm) {
            // We are in PM phase (after noon)
            if (hour == 12) {
                // 12:xx in PM phase -> could be midnight transition, keep as AM
                amPm = "AM";
            } else {
                amPm = "PM";
            }
        } else if (defaultPm) {
            // Default PM (used for Sleep field)
            amPm = "PM";
        } else {
            // Default AM (used for Wake field and early entries)
            if (hour == 12) {
                // 12:xx in AM phase -> noon = PM
                amPm = "PM";
            } else {
                amPm = "AM";
            }
        }

        String h = hour < 10 ? "0" + hour : String.valueOf(hour);
        String m = minute < 10 ? "0" + minute : String.valueOf(minute);
        return h + ":" + m + " " + amPm;
    }

    /**
     * Extract the last end time from a routine entry line.
     * Given "07:00 AM - 07:43 AM Walking", returns "07:43 AM".
     * Returns null if no end time found.
     */
    public static String extractLastEndTime(String line) {
        if (line == null || line.length() == 0) return null;

        int dashIdx = line.indexOf(" - ");
        if (dashIdx < 0) return null;

        String afterDash = line.substring(dashIdx + 3).trim();
        // Try to extract time portion (first 8 chars like "07:43 AM")
        if (afterDash.length() >= 8) {
            String candidate = afterDash.substring(0, 8);
            if (candidate.matches("\\d{2}:\\d{2} [AP]M")) {
                return candidate;
            }
        }
        return null;
    }

    /**
     * Check if a time string contains PM.
     */
    public static boolean isPmTime(String timeStr) {
        if (timeStr == null) return false;
        return timeStr.toUpperCase().contains("PM");
    }

    /**
     * Parse hour from formatted time like "07:43 AM".
     * Returns 24h hour or -1 on failure.
     */
    public static int parseHour24(String timeStr) {
        if (timeStr == null || timeStr.length() < 8) return -1;
        try {
            int h = Integer.parseInt(timeStr.substring(0, 2));
            boolean pm = timeStr.toUpperCase().contains("PM");
            if (pm && h != 12) h += 12;
            if (!pm && h == 12) h = 0;
            return h;
        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * Parse minute from formatted time like "07:43 AM".
     */
    public static int parseMinute(String timeStr) {
        if (timeStr == null || timeStr.length() < 5) return -1;
        try {
            return Integer.parseInt(timeStr.substring(3, 5));
        } catch (Exception e) {
            return -1;
        }
    }
}
