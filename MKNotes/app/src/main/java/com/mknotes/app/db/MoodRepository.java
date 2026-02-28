package com.mknotes.app.db;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

import com.mknotes.app.model.NoteMood;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Repository for mood data operations.
 * Thread-safe singleton. All heavy queries should be called from background thread
 * where possible; simple insert/delete are safe on main thread for responsiveness.
 */
public class MoodRepository {

    private NotesDatabaseHelper dbHelper;
    private static MoodRepository sInstance;

    public static synchronized MoodRepository getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new MoodRepository(context.getApplicationContext());
        }
        return sInstance;
    }

    private MoodRepository(Context context) {
        dbHelper = NotesDatabaseHelper.getInstance(context);
    }

    // ============ INSERT ============

    /**
     * Insert a mood for a note. Checks for duplicate mood names on same note and
     * replaces if found (upsert behavior).
     */
    public long insertOrUpdateMood(NoteMood mood) {
        if (mood == null) return -1;
        SQLiteDatabase db = dbHelper.getWritableDatabase();

        // Check if same mood name already exists for this note
        Cursor existing = db.query(NotesDatabaseHelper.TABLE_NOTE_MOODS,
                new String[]{NotesDatabaseHelper.COL_MOOD_ID},
                NotesDatabaseHelper.COL_MOOD_NOTE_ID + "=? AND " +
                        NotesDatabaseHelper.COL_MOOD_NAME + "=?",
                new String[]{String.valueOf(mood.getNoteId()), mood.getMoodName()},
                null, null, null);

        long resultId = -1;
        if (existing != null && existing.moveToFirst()) {
            // Update existing
            long existingId = existing.getLong(0);
            existing.close();
            ContentValues values = buildValues(mood);
            db.update(NotesDatabaseHelper.TABLE_NOTE_MOODS, values,
                    NotesDatabaseHelper.COL_MOOD_ID + "=?",
                    new String[]{String.valueOf(existingId)});
            resultId = existingId;
        } else {
            if (existing != null) existing.close();
            // Insert new
            ContentValues values = buildValues(mood);
            resultId = db.insert(NotesDatabaseHelper.TABLE_NOTE_MOODS, null, values);
        }
        return resultId;
    }

    private ContentValues buildValues(NoteMood mood) {
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_MOOD_NOTE_ID, mood.getNoteId());
        values.put(NotesDatabaseHelper.COL_MOOD_DATE, mood.getDate());
        values.put(NotesDatabaseHelper.COL_MOOD_TIMESTAMP, mood.getTimestamp());
        values.put(NotesDatabaseHelper.COL_MOOD_EMOJI, mood.getEmojiUnicode());
        values.put(NotesDatabaseHelper.COL_MOOD_NAME, mood.getMoodName());
        values.put(NotesDatabaseHelper.COL_MOOD_INTENSITY, mood.getIntensityLevel());
        return values;
    }

    // ============ DELETE ============

    public int deleteMood(long moodId) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        return db.delete(NotesDatabaseHelper.TABLE_NOTE_MOODS,
                NotesDatabaseHelper.COL_MOOD_ID + "=?",
                new String[]{String.valueOf(moodId)});
    }

    public int deleteMoodsForNote(long noteId) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        return db.delete(NotesDatabaseHelper.TABLE_NOTE_MOODS,
                NotesDatabaseHelper.COL_MOOD_NOTE_ID + "=?",
                new String[]{String.valueOf(noteId)});
    }

    public int deleteMoodByNoteAndName(long noteId, String moodName) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        return db.delete(NotesDatabaseHelper.TABLE_NOTE_MOODS,
                NotesDatabaseHelper.COL_MOOD_NOTE_ID + "=? AND " +
                        NotesDatabaseHelper.COL_MOOD_NAME + "=?",
                new String[]{String.valueOf(noteId), moodName});
    }

    // ============ QUERY ============

    /**
     * Get all moods for a note, sorted by intensity descending (highest first).
     */
    public List getMoodsForNote(long noteId) {
        List moods = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        try {
            Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTE_MOODS,
                    null,
                    NotesDatabaseHelper.COL_MOOD_NOTE_ID + "=?",
                    new String[]{String.valueOf(noteId)},
                    null, null,
                    NotesDatabaseHelper.COL_MOOD_INTENSITY + " DESC");
            if (cursor != null) {
                while (cursor.moveToNext()) {
                    moods.add(cursorToMood(cursor));
                }
                cursor.close();
            }
        } catch (Exception e) {
            // Table might not exist on very old installs
        }
        return moods;
    }

    /**
     * Get all moods for a specific date string (yyyy-MM-dd).
     */
    public List getMoodsForDate(String dateYmd) {
        List moods = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        try {
            Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTE_MOODS,
                    null,
                    NotesDatabaseHelper.COL_MOOD_DATE + "=?",
                    new String[]{dateYmd},
                    null, null,
                    NotesDatabaseHelper.COL_MOOD_INTENSITY + " DESC");
            if (cursor != null) {
                while (cursor.moveToNext()) {
                    moods.add(cursorToMood(cursor));
                }
                cursor.close();
            }
        } catch (Exception e) {
            // Table might not exist
        }
        return moods;
    }

    /**
     * Get the primary (highest intensity) mood for a date.
     * Returns null if no moods exist for that date.
     */
    public NoteMood getPrimaryMoodForDate(String dateYmd) {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        try {
            Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTE_MOODS,
                    null,
                    NotesDatabaseHelper.COL_MOOD_DATE + "=?",
                    new String[]{dateYmd},
                    null, null,
                    NotesDatabaseHelper.COL_MOOD_INTENSITY + " DESC",
                    "1");
            if (cursor != null && cursor.moveToFirst()) {
                NoteMood mood = cursorToMood(cursor);
                cursor.close();
                return mood;
            }
            if (cursor != null) cursor.close();
        } catch (Exception e) {
            // Table might not exist
        }
        return null;
    }

    /**
     * Get average intensity for a date across all moods.
     * Returns 0 if no data.
     */
    public float getAverageIntensityForDate(String dateYmd) {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        try {
            Cursor cursor = db.rawQuery(
                    "SELECT AVG(" + NotesDatabaseHelper.COL_MOOD_INTENSITY +
                            ") FROM " + NotesDatabaseHelper.TABLE_NOTE_MOODS +
                            " WHERE " + NotesDatabaseHelper.COL_MOOD_DATE + "=?",
                    new String[]{dateYmd});
            if (cursor != null && cursor.moveToFirst()) {
                float avg = cursor.getFloat(0);
                cursor.close();
                return avg;
            }
            if (cursor != null) cursor.close();
        } catch (Exception e) {
            // Table might not exist
        }
        return 0f;
    }

    /**
     * Check if any mood data exists for a given date.
     */
    public boolean hasMoodForDate(String dateYmd) {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        try {
            Cursor cursor = db.rawQuery(
                    "SELECT COUNT(*) FROM " + NotesDatabaseHelper.TABLE_NOTE_MOODS +
                            " WHERE " + NotesDatabaseHelper.COL_MOOD_DATE + "=?",
                    new String[]{dateYmd});
            if (cursor != null && cursor.moveToFirst()) {
                boolean has = cursor.getInt(0) > 0;
                cursor.close();
                return has;
            }
            if (cursor != null) cursor.close();
        } catch (Exception e) {
            // Table might not exist
        }
        return false;
    }

    // ============ ANALYTICS QUERIES ============

    /**
     * Get daily average intensities for a week (7 days).
     * Returns float[7] where index 0=Monday, 6=Sunday.
     * Input: startDate is the Monday of the week (yyyy-MM-dd).
     */
    public float[] getWeekIntensities(String startDateYmd) {
        float[] result = new float[7];
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
            Date start = sdf.parse(startDateYmd);
            if (start == null) return result;

            Calendar cal = Calendar.getInstance();
            cal.setTime(start);

            for (int i = 0; i < 7; i++) {
                String dayStr = sdf.format(cal.getTime());
                result[i] = getAverageIntensityForDate(dayStr);
                cal.add(Calendar.DAY_OF_MONTH, 1);
            }
        } catch (Exception e) {
            // parse error
        }
        return result;
    }

    /**
     * Get primary emoji for each day of the week.
     * Returns String[7] (emoji or empty string).
     */
    public String[] getWeekEmojis(String startDateYmd) {
        String[] result = new String[7];
        for (int i = 0; i < 7; i++) result[i] = "";
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
            Date start = sdf.parse(startDateYmd);
            if (start == null) return result;

            Calendar cal = Calendar.getInstance();
            cal.setTime(start);

            for (int i = 0; i < 7; i++) {
                String dayStr = sdf.format(cal.getTime());
                NoteMood primary = getPrimaryMoodForDate(dayStr);
                if (primary != null) {
                    result[i] = primary.getEmojiUnicode();
                }
                cal.add(Calendar.DAY_OF_MONTH, 1);
            }
        } catch (Exception e) {
            // parse error
        }
        return result;
    }

    /**
     * Get daily average intensities for a month.
     * Returns float[maxDays] where index 0=day 1.
     */
    public float[] getMonthIntensities(int year, int month) {
        Calendar cal = Calendar.getInstance();
        cal.set(year, month - 1, 1);
        int maxDay = cal.getActualMaximum(Calendar.DAY_OF_MONTH);
        float[] result = new float[maxDay];

        for (int d = 1; d <= maxDay; d++) {
            String dateStr = String.format(Locale.US, "%04d-%02d-%02d", year, month, d);
            result[d - 1] = getAverageIntensityForDate(dateStr);
        }
        return result;
    }

    /**
     * Get primary emoji for each day of the month.
     */
    public String[] getMonthEmojis(int year, int month) {
        Calendar cal = Calendar.getInstance();
        cal.set(year, month - 1, 1);
        int maxDay = cal.getActualMaximum(Calendar.DAY_OF_MONTH);
        String[] result = new String[maxDay];
        for (int i = 0; i < maxDay; i++) result[i] = "";

        for (int d = 1; d <= maxDay; d++) {
            String dateStr = String.format(Locale.US, "%04d-%02d-%02d", year, month, d);
            NoteMood primary = getPrimaryMoodForDate(dateStr);
            if (primary != null) {
                result[d - 1] = primary.getEmojiUnicode();
            }
        }
        return result;
    }

    /**
     * Get mood distribution for a date range (for pie/summary).
     * Returns map of moodName -> count.
     */
    public Map getMoodDistribution(String startDate, String endDate) {
        Map distribution = new HashMap();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        try {
            Cursor cursor = db.rawQuery(
                    "SELECT " + NotesDatabaseHelper.COL_MOOD_NAME +
                            ", COUNT(*) FROM " + NotesDatabaseHelper.TABLE_NOTE_MOODS +
                            " WHERE " + NotesDatabaseHelper.COL_MOOD_DATE + ">=? AND " +
                            NotesDatabaseHelper.COL_MOOD_DATE + "<=?" +
                            " GROUP BY " + NotesDatabaseHelper.COL_MOOD_NAME +
                            " ORDER BY COUNT(*) DESC",
                    new String[]{startDate, endDate});
            if (cursor != null) {
                while (cursor.moveToNext()) {
                    String name = cursor.getString(0);
                    int count = cursor.getInt(1);
                    distribution.put(name, Integer.valueOf(count));
                }
                cursor.close();
            }
        } catch (Exception e) {
            // Table might not exist
        }
        return distribution;
    }

    /**
     * Check if any mood data exists in the database at all.
     */
    public boolean hasAnyMoodData() {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        try {
            Cursor cursor = db.rawQuery(
                    "SELECT COUNT(*) FROM " + NotesDatabaseHelper.TABLE_NOTE_MOODS, null);
            if (cursor != null && cursor.moveToFirst()) {
                boolean has = cursor.getInt(0) > 0;
                cursor.close();
                return has;
            }
            if (cursor != null) cursor.close();
        } catch (Exception e) {
            // Table might not exist
        }
        return false;
    }

    // ============ CURSOR MAPPING ============

    private NoteMood cursorToMood(Cursor cursor) {
        NoteMood mood = new NoteMood();
        mood.setId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_MOOD_ID)));
        mood.setNoteId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_MOOD_NOTE_ID)));
        mood.setDate(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_MOOD_DATE)));
        mood.setTimestamp(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_MOOD_TIMESTAMP)));
        mood.setEmojiUnicode(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_MOOD_EMOJI)));
        mood.setMoodName(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_MOOD_NAME)));
        mood.setIntensityLevel(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_MOOD_INTENSITY)));
        return mood;
    }
}
