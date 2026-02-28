package com.mknotes.app.analysis;

import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

import com.mknotes.app.db.NotesDatabaseHelper;
import com.mknotes.app.model.Note;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Data provider for Calendar Analysis feature.
 * Queries existing database tables directly without modifying
 * NotesDatabaseHelper or NotesRepository.
 */
public class AnalysisDataProvider {

    private NotesDatabaseHelper dbHelper;

    public AnalysisDataProvider(Context context) {
        dbHelper = NotesDatabaseHelper.getInstance(context);
    }

    // ============ INNER MODEL CLASSES ============

    public static class MantraSummary {
        public long mantraId;
        public String mantraName;
        public int totalCount;
        public int malaCount;
        public int remainder;

        public MantraSummary(long id, String name, int count) {
            this.mantraId = id;
            this.mantraName = name;
            this.totalCount = count;
            this.malaCount = count / 108;
            this.remainder = count % 108;
        }
    }

    public static class DayTotal {
        public int day;
        public int totalCount;
        public Map perMantraCounts; // mantraName -> count

        public DayTotal(int day, int totalCount) {
            this.day = day;
            this.totalCount = totalCount;
            this.perMantraCounts = new HashMap();
        }
    }

    public static class MonthTotal {
        public int month;
        public int totalCount;

        public MonthTotal(int month, int totalCount) {
            this.month = month;
            this.totalCount = totalCount;
        }
    }

    public static class DateMantraData {
        public String date;
        public List summaries;
        public int grandTotal;
        public int grandMala;

        public DateMantraData(String date) {
            this.date = date;
            this.summaries = new ArrayList();
            this.grandTotal = 0;
            this.grandMala = 0;
        }

        public void compute() {
            grandTotal = 0;
            for (int i = 0; i < summaries.size(); i++) {
                grandTotal += ((MantraSummary) summaries.get(i)).totalCount;
            }
            grandMala = grandTotal / 108;
        }
    }

    public static class GraphDataSet {
        public String label;
        public int color;
        public List values; // Float values matching xLabels

        public GraphDataSet(String label, int color) {
            this.label = label;
            this.color = color;
            this.values = new ArrayList();
        }
    }

    // ============ NOTES QUERIES ============

    /**
     * Get non-routine notes created on a specific date (yyyy-MM-dd).
     */
    public List getNotesForDate(String dateYmd) {
        List notes = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        long[] range = getDateRange(dateYmd);
        if (range == null) return notes;

        Cursor cursor = db.rawQuery(
                "SELECT * FROM " + NotesDatabaseHelper.TABLE_NOTES +
                        " WHERE " + NotesDatabaseHelper.COL_CREATED + " >= ? AND " +
                        NotesDatabaseHelper.COL_CREATED + " < ? AND " +
                        NotesDatabaseHelper.COL_IS_ROUTINE_MODE + " = 0" +
                        " ORDER BY " + NotesDatabaseHelper.COL_CREATED + " DESC",
                new String[]{String.valueOf(range[0]), String.valueOf(range[1])});

        if (cursor != null) {
            while (cursor.moveToNext()) {
                notes.add(cursorToNote(cursor));
            }
            cursor.close();
        }
        return notes;
    }

    /**
     * Get non-routine notes for multiple dates.
     */
    public List getNotesForDates(List dates) {
        List notes = new ArrayList();
        for (int i = 0; i < dates.size(); i++) {
            notes.addAll(getNotesForDate((String) dates.get(i)));
        }
        return notes;
    }

    // ============ ROUTINE QUERIES ============

    /**
     * Get routine notes created/modified on a specific date.
     */
    public List getRoutineNotesForDate(String dateYmd) {
        List notes = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        long[] range = getDateRange(dateYmd);
        if (range == null) return notes;

        Cursor cursor = db.rawQuery(
                "SELECT * FROM " + NotesDatabaseHelper.TABLE_NOTES +
                        " WHERE " + NotesDatabaseHelper.COL_IS_ROUTINE_MODE + " = 1 AND (" +
                        NotesDatabaseHelper.COL_CREATED + " >= ? AND " +
                        NotesDatabaseHelper.COL_CREATED + " < ?)" +
                        " ORDER BY " + NotesDatabaseHelper.COL_CREATED + " DESC",
                new String[]{String.valueOf(range[0]), String.valueOf(range[1])});

        if (cursor != null) {
            while (cursor.moveToNext()) {
                notes.add(cursorToNote(cursor));
            }
            cursor.close();
        }
        return notes;
    }

    /**
     * Get routine notes for multiple dates.
     */
    public List getRoutineNotesForDates(List dates) {
        List notes = new ArrayList();
        for (int i = 0; i < dates.size(); i++) {
            notes.addAll(getRoutineNotesForDate((String) dates.get(i)));
        }
        return notes;
    }

    // ============ MEDITATION QUERIES ============

    /**
     * Get meditation data for a single date.
     * Returns per-mantra summaries with count and mala.
     */
    public DateMantraData getMeditationForDate(String dateYmd) {
        DateMantraData data = new DateMantraData(dateYmd);
        SQLiteDatabase db = dbHelper.getReadableDatabase();

        Cursor cursor = db.rawQuery(
                "SELECT m." + NotesDatabaseHelper.COL_MANTRA_ID +
                        ", m." + NotesDatabaseHelper.COL_MANTRA_NAME +
                        ", ds." + NotesDatabaseHelper.COL_SESSION_COUNT +
                        " FROM " + NotesDatabaseHelper.TABLE_DAILY_SESSIONS + " ds" +
                        " INNER JOIN " + NotesDatabaseHelper.TABLE_MANTRAS + " m" +
                        " ON ds." + NotesDatabaseHelper.COL_SESSION_MANTRA_ID +
                        " = m." + NotesDatabaseHelper.COL_MANTRA_ID +
                        " WHERE ds." + NotesDatabaseHelper.COL_SESSION_DATE + " = ?" +
                        " AND ds." + NotesDatabaseHelper.COL_SESSION_COUNT + " > 0" +
                        " ORDER BY ds." + NotesDatabaseHelper.COL_SESSION_COUNT + " DESC",
                new String[]{dateYmd});

        if (cursor != null) {
            while (cursor.moveToNext()) {
                long mantraId = cursor.getLong(0);
                String name = cursor.getString(1);
                int count = cursor.getInt(2);
                data.summaries.add(new MantraSummary(mantraId, name, count));
            }
            cursor.close();
        }
        data.compute();
        return data;
    }

    /**
     * Get combined meditation data for multiple dates.
     * Aggregates counts per mantra across all dates.
     */
    public DateMantraData getMeditationForDates(List dates) {
        DateMantraData data = new DateMantraData("multiple");
        if (dates == null || dates.isEmpty()) return data;

        Map mantraMap = new HashMap(); // mantraId -> MantraSummary
        for (int i = 0; i < dates.size(); i++) {
            DateMantraData dayData = getMeditationForDate((String) dates.get(i));
            for (int j = 0; j < dayData.summaries.size(); j++) {
                MantraSummary s = (MantraSummary) dayData.summaries.get(j);
                Long key = Long.valueOf(s.mantraId);
                if (mantraMap.containsKey(key)) {
                    MantraSummary existing = (MantraSummary) mantraMap.get(key);
                    existing.totalCount += s.totalCount;
                    existing.malaCount = existing.totalCount / 108;
                    existing.remainder = existing.totalCount % 108;
                } else {
                    mantraMap.put(key, new MantraSummary(s.mantraId, s.mantraName, s.totalCount));
                }
            }
        }
        data.summaries.addAll(mantraMap.values());
        data.compute();
        return data;
    }

    /**
     * Get per-mantra daily counts for a given date (for single date graph).
     * Returns a list of GraphDataSet where each dataset is a mantra.
     * X-axis represents mantras, Y-axis represents count.
     */
    public List getMantraGraphDataForDate(String dateYmd, int[] colors) {
        List datasets = new ArrayList();
        DateMantraData data = getMeditationForDate(dateYmd);
        for (int i = 0; i < data.summaries.size(); i++) {
            MantraSummary s = (MantraSummary) data.summaries.get(i);
            int color = colors[i % colors.length];
            GraphDataSet ds = new GraphDataSet(s.mantraName, color);
            ds.values.add(Float.valueOf((float) s.totalCount));
            datasets.add(ds);
        }
        return datasets;
    }

    /**
     * Get meditation data for a month: day-wise totals.
     * Returns DayTotal list for days 1-31.
     */
    public List getMeditationForMonth(int year, int month) {
        List result = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        String monthStr = String.format(Locale.US, "%04d-%02d", year, month);

        Cursor cursor = db.rawQuery(
                "SELECT ds." + NotesDatabaseHelper.COL_SESSION_DATE +
                        ", m." + NotesDatabaseHelper.COL_MANTRA_NAME +
                        ", ds." + NotesDatabaseHelper.COL_SESSION_COUNT +
                        " FROM " + NotesDatabaseHelper.TABLE_DAILY_SESSIONS + " ds" +
                        " INNER JOIN " + NotesDatabaseHelper.TABLE_MANTRAS + " m" +
                        " ON ds." + NotesDatabaseHelper.COL_SESSION_MANTRA_ID +
                        " = m." + NotesDatabaseHelper.COL_MANTRA_ID +
                        " WHERE ds." + NotesDatabaseHelper.COL_SESSION_DATE + " LIKE ?" +
                        " AND ds." + NotesDatabaseHelper.COL_SESSION_COUNT + " > 0" +
                        " ORDER BY ds." + NotesDatabaseHelper.COL_SESSION_DATE + " ASC",
                new String[]{monthStr + "%"});

        Map dayMap = new HashMap(); // day -> DayTotal

        if (cursor != null) {
            while (cursor.moveToNext()) {
                String dateStr = cursor.getString(0);
                String mantraName = cursor.getString(1);
                int count = cursor.getInt(2);

                int day = parseDayFromDate(dateStr);
                if (day < 1) continue;

                Integer dayKey = Integer.valueOf(day);
                DayTotal dt;
                if (dayMap.containsKey(dayKey)) {
                    dt = (DayTotal) dayMap.get(dayKey);
                } else {
                    dt = new DayTotal(day, 0);
                    dayMap.put(dayKey, dt);
                }
                dt.totalCount += count;
                Integer prev = (Integer) dt.perMantraCounts.get(mantraName);
                if (prev != null) {
                    dt.perMantraCounts.put(mantraName, Integer.valueOf(prev.intValue() + count));
                } else {
                    dt.perMantraCounts.put(mantraName, Integer.valueOf(count));
                }
            }
            cursor.close();
        }

        // Fill all days
        Calendar cal = Calendar.getInstance();
        cal.set(year, month - 1, 1);
        int maxDay = cal.getActualMaximum(Calendar.DAY_OF_MONTH);
        for (int d = 1; d <= maxDay; d++) {
            Integer key = Integer.valueOf(d);
            if (dayMap.containsKey(key)) {
                result.add(dayMap.get(key));
            } else {
                result.add(new DayTotal(d, 0));
            }
        }
        return result;
    }

    /**
     * Get meditation data for a year: month-wise totals.
     */
    public List getMeditationForYear(int year) {
        List result = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        String yearStr = String.format(Locale.US, "%04d", year);

        Cursor cursor = db.rawQuery(
                "SELECT substr(ds." + NotesDatabaseHelper.COL_SESSION_DATE + ", 6, 2) AS mn, " +
                        "SUM(ds." + NotesDatabaseHelper.COL_SESSION_COUNT + ") AS total" +
                        " FROM " + NotesDatabaseHelper.TABLE_DAILY_SESSIONS + " ds" +
                        " WHERE ds." + NotesDatabaseHelper.COL_SESSION_DATE + " LIKE ?" +
                        " AND ds." + NotesDatabaseHelper.COL_SESSION_COUNT + " > 0" +
                        " GROUP BY mn ORDER BY mn ASC",
                new String[]{yearStr + "%"});

        Map monthMap = new HashMap();
        if (cursor != null) {
            while (cursor.moveToNext()) {
                String mnStr = cursor.getString(0);
                int total = cursor.getInt(1);
                try {
                    int mn = Integer.parseInt(mnStr);
                    monthMap.put(Integer.valueOf(mn), new MonthTotal(mn, total));
                } catch (NumberFormatException e) {
                    // skip
                }
            }
            cursor.close();
        }

        for (int m = 1; m <= 12; m++) {
            Integer key = Integer.valueOf(m);
            if (monthMap.containsKey(key)) {
                result.add(monthMap.get(key));
            } else {
                result.add(new MonthTotal(m, 0));
            }
        }
        return result;
    }

    /**
     * Get per-mantra data for multiple dates (for multi-date graph).
     * Each date is a data point. Each mantra is a line series.
     */
    public List getMultiDateMantraGraph(List dates, int[] colors) {
        List datasets = new ArrayList();
        if (dates == null || dates.isEmpty()) return datasets;

        // Collect all mantra names across all dates
        Map mantraNames = new HashMap(); // id -> name
        Map mantraDateCounts = new HashMap(); // "id_date" -> count

        for (int i = 0; i < dates.size(); i++) {
            String d = (String) dates.get(i);
            DateMantraData dmd = getMeditationForDate(d);
            for (int j = 0; j < dmd.summaries.size(); j++) {
                MantraSummary s = (MantraSummary) dmd.summaries.get(j);
                mantraNames.put(Long.valueOf(s.mantraId), s.mantraName);
                mantraDateCounts.put(s.mantraId + "_" + d, Integer.valueOf(s.totalCount));
            }
        }

        // Build datasets
        int colorIdx = 0;
        for (Object entry : mantraNames.entrySet()) {
            Map.Entry e = (Map.Entry) entry;
            Long mantraId = (Long) e.getKey();
            String name = (String) e.getValue();
            int color = colors[colorIdx % colors.length];
            colorIdx++;

            GraphDataSet ds = new GraphDataSet(name, color);
            for (int i = 0; i < dates.size(); i++) {
                String d = (String) dates.get(i);
                String key = mantraId.longValue() + "_" + d;
                Integer c = (Integer) mantraDateCounts.get(key);
                ds.values.add(Float.valueOf(c != null ? c.floatValue() : 0f));
            }
            datasets.add(ds);
        }
        return datasets;
    }

    /**
     * Get per-mantra data for a single month (for month graph with mantra lines).
     * Each mantra is a line, X=day, Y=count.
     */
    public List getMonthMantraGraph(int year, int month, int[] colors) {
        List datasets = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        String monthStr = String.format(Locale.US, "%04d-%02d", year, month);

        Calendar cal = Calendar.getInstance();
        cal.set(year, month - 1, 1);
        int maxDay = cal.getActualMaximum(Calendar.DAY_OF_MONTH);

        // Get all mantra sessions for this month
        Cursor cursor = db.rawQuery(
                "SELECT m." + NotesDatabaseHelper.COL_MANTRA_ID +
                        ", m." + NotesDatabaseHelper.COL_MANTRA_NAME +
                        ", ds." + NotesDatabaseHelper.COL_SESSION_DATE +
                        ", ds." + NotesDatabaseHelper.COL_SESSION_COUNT +
                        " FROM " + NotesDatabaseHelper.TABLE_DAILY_SESSIONS + " ds" +
                        " INNER JOIN " + NotesDatabaseHelper.TABLE_MANTRAS + " m" +
                        " ON ds." + NotesDatabaseHelper.COL_SESSION_MANTRA_ID +
                        " = m." + NotesDatabaseHelper.COL_MANTRA_ID +
                        " WHERE ds." + NotesDatabaseHelper.COL_SESSION_DATE + " LIKE ?" +
                        " AND ds." + NotesDatabaseHelper.COL_SESSION_COUNT + " > 0" +
                        " ORDER BY m." + NotesDatabaseHelper.COL_MANTRA_NAME + " ASC",
                new String[]{monthStr + "%"});

        Map mantraMap = new HashMap(); // mantraId -> {name, day->count}
        if (cursor != null) {
            while (cursor.moveToNext()) {
                long mid = cursor.getLong(0);
                String name = cursor.getString(1);
                String dateStr = cursor.getString(2);
                int count = cursor.getInt(3);
                int day = parseDayFromDate(dateStr);

                Long key = Long.valueOf(mid);
                Object[] arr;
                if (mantraMap.containsKey(key)) {
                    arr = (Object[]) mantraMap.get(key);
                } else {
                    arr = new Object[]{name, new HashMap()};
                    mantraMap.put(key, arr);
                }
                Map dayCounts = (Map) arr[1];
                Integer prev = (Integer) dayCounts.get(Integer.valueOf(day));
                int newVal = (prev != null ? prev.intValue() : 0) + count;
                dayCounts.put(Integer.valueOf(day), Integer.valueOf(newVal));
            }
            cursor.close();
        }

        int colorIdx = 0;
        for (Object entry : mantraMap.entrySet()) {
            Map.Entry e = (Map.Entry) entry;
            Object[] arr = (Object[]) e.getValue();
            String name = (String) arr[0];
            Map dayCounts = (Map) arr[1];

            int color = colors[colorIdx % colors.length];
            colorIdx++;
            GraphDataSet ds = new GraphDataSet(name, color);

            for (int d = 1; d <= maxDay; d++) {
                Integer c = (Integer) dayCounts.get(Integer.valueOf(d));
                ds.values.add(Float.valueOf(c != null ? c.floatValue() : 0f));
            }
            datasets.add(ds);
        }
        return datasets;
    }

    /**
     * Get year-level data for a single year (total per month).
     * Returns a single GraphDataSet with 12 values.
     */
    public GraphDataSet getYearGraphData(int year, int color) {
        GraphDataSet ds = new GraphDataSet(String.valueOf(year), color);
        List months = getMeditationForYear(year);
        for (int i = 0; i < months.size(); i++) {
            ds.values.add(Float.valueOf((float) ((MonthTotal) months.get(i)).totalCount));
        }
        return ds;
    }

    // ============ TIME-SLOT GRAPH (Single Date) ============

    /**
     * Inner class for time-slot data (one mantra's counts across time slots).
     */
    public static class TimeSlotEntry {
        public long mantraId;
        public String mantraName;
        public int[] slotCounts; // 12 slots: 0-2,2-4,...,22-24

        public TimeSlotEntry(long id, String name) {
            this.mantraId = id;
            this.mantraName = name;
            this.slotCounts = new int[12];
        }
    }

    /**
     * Time slot labels for single-date graph.
     * 12 slots of 2 hours each covering full 24 hours (12AM to 12AM).
     */
    public static final String[] TIME_SLOT_LABELS = {
        "12-2AM", "2-4AM", "4-6AM", "6-8AM",
        "8-10AM", "10-12PM", "12-2PM", "2-4PM",
        "4-6PM", "6-8PM", "8-10PM", "10-12AM"
    };

    /**
     * Hour ranges for each slot: [startHour, endHour).
     * Slot 0 = 0:00-2:00, Slot 1 = 2:00-4:00, ..., Slot 11 = 22:00-24:00
     */
    public static final int[][] TIME_SLOT_HOURS = {
        {0, 2}, {2, 4}, {4, 6}, {6, 8},
        {8, 10}, {10, 12}, {12, 14}, {14, 16},
        {16, 18}, {18, 20}, {20, 22}, {22, 24}
    };

    /**
     * Get time-slot based graph data for a single date.
     * Uses mantra_count_log table for timestamp-based grouping.
     * Returns list of TimeSlotEntry (one per mantra that has data).
     */
    public List getTimeSlotDataForDate(String dateYmd) {
        List result = new ArrayList();
        SQLiteDatabase db = dbHelper.getReadableDatabase();

        try {
        // First, find all mantras that have log entries for this date
        Map mantraIdToName = new HashMap(); // Long -> String
        Cursor mantraCursor = db.rawQuery(
            "SELECT DISTINCT cl." + NotesDatabaseHelper.COL_LOG_MANTRA_ID +
            ", m." + NotesDatabaseHelper.COL_MANTRA_NAME +
            " FROM " + NotesDatabaseHelper.TABLE_MANTRA_COUNT_LOG + " cl" +
            " INNER JOIN " + NotesDatabaseHelper.TABLE_MANTRAS + " m" +
            " ON cl." + NotesDatabaseHelper.COL_LOG_MANTRA_ID +
            " = m." + NotesDatabaseHelper.COL_MANTRA_ID +
            " WHERE cl." + NotesDatabaseHelper.COL_LOG_SESSION_DATE + "=?",
            new String[]{dateYmd});

        if (mantraCursor != null) {
            while (mantraCursor.moveToNext()) {
                mantraIdToName.put(Long.valueOf(mantraCursor.getLong(0)),
                    mantraCursor.getString(1));
            }
            mantraCursor.close();
        }

        if (mantraIdToName.isEmpty()) return result;

        // Parse date to get base millis for time slot boundaries
        long baseDayMillis = 0;
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
            Date parsed = sdf.parse(dateYmd);
            if (parsed != null) {
                Calendar cal = Calendar.getInstance();
                cal.setTime(parsed);
                cal.set(Calendar.HOUR_OF_DAY, 0);
                cal.set(Calendar.MINUTE, 0);
                cal.set(Calendar.SECOND, 0);
                cal.set(Calendar.MILLISECOND, 0);
                baseDayMillis = cal.getTimeInMillis();
            }
        } catch (Exception e) {
            return result;
        }

        // For each mantra, count entries in each time slot
        for (Object entry : mantraIdToName.entrySet()) {
            Map.Entry e = (Map.Entry) entry;
            Long mantraId = (Long) e.getKey();
            String name = (String) e.getValue();
            TimeSlotEntry tse = new TimeSlotEntry(mantraId.longValue(), name);

            for (int s = 0; s < TIME_SLOT_HOURS.length; s++) {
                long slotStart = baseDayMillis + (long) TIME_SLOT_HOURS[s][0] * 3600000L;
                long slotEnd = baseDayMillis + (long) TIME_SLOT_HOURS[s][1] * 3600000L;

                Cursor countCursor = db.rawQuery(
                    "SELECT COUNT(*) FROM " + NotesDatabaseHelper.TABLE_MANTRA_COUNT_LOG +
                    " WHERE " + NotesDatabaseHelper.COL_LOG_MANTRA_ID + "=?" +
                    " AND " + NotesDatabaseHelper.COL_LOG_SESSION_DATE + "=?" +
                    " AND " + NotesDatabaseHelper.COL_LOG_TIMESTAMP + ">=?" +
                    " AND " + NotesDatabaseHelper.COL_LOG_TIMESTAMP + "<?",
                    new String[]{String.valueOf(mantraId.longValue()), dateYmd,
                        String.valueOf(slotStart), String.valueOf(slotEnd)});
                if (countCursor != null) {
                    if (countCursor.moveToFirst()) {
                        tse.slotCounts[s] = countCursor.getInt(0);
                    }
                    countCursor.close();
                }
            }
            result.add(tse);
        }
        } catch (Exception e) {
            // Table might not exist on very old installs
        }
        return result;
    }

    /**
     * Check if any time-slot log data exists for a date.
     */
    public boolean hasTimeSlotData(String dateYmd) {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        try {
            Cursor cursor = db.rawQuery(
                "SELECT COUNT(*) FROM " + NotesDatabaseHelper.TABLE_MANTRA_COUNT_LOG +
                " WHERE " + NotesDatabaseHelper.COL_LOG_SESSION_DATE + "=?",
                new String[]{dateYmd});
            if (cursor != null) {
                if (cursor.moveToFirst()) {
                    boolean has = cursor.getInt(0) > 0;
                    cursor.close();
                    return has;
                }
                cursor.close();
            }
        } catch (Exception e) {
            // Table might not exist on very old installs
        }
        return false;
    }

    // ============ YEAR-LEVEL NOTES / ROUTINE COUNT ============

    /**
     * Get note count per month for a given year (non-routine notes).
     * Returns int[12] where index 0=Jan, 11=Dec.
     */
    public int[] getNotesCountByMonth(int year) {
        int[] counts = new int[12];
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        try {
            Calendar cal = Calendar.getInstance();
            for (int m = 0; m < 12; m++) {
                cal.set(year, m, 1, 0, 0, 0);
                cal.set(Calendar.MILLISECOND, 0);
                long start = cal.getTimeInMillis();
                cal.add(Calendar.MONTH, 1);
                long end = cal.getTimeInMillis();

                Cursor cursor = db.rawQuery(
                    "SELECT COUNT(*) FROM " + NotesDatabaseHelper.TABLE_NOTES +
                    " WHERE " + NotesDatabaseHelper.COL_CREATED + ">=?" +
                    " AND " + NotesDatabaseHelper.COL_CREATED + "<?" +
                    " AND " + NotesDatabaseHelper.COL_IS_ROUTINE_MODE + "=0",
                    new String[]{String.valueOf(start), String.valueOf(end)});
                if (cursor != null) {
                    if (cursor.moveToFirst()) {
                        counts[m] = cursor.getInt(0);
                    }
                    cursor.close();
                }
            }
        } catch (Exception e) {
            // Fail silently
        }
        return counts;
    }

    /**
     * Get routine note count per month for a given year.
     * Returns int[12] where index 0=Jan, 11=Dec.
     */
    public int[] getRoutineCountByMonth(int year) {
        int[] counts = new int[12];
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        try {
            Calendar cal = Calendar.getInstance();
            for (int m = 0; m < 12; m++) {
                cal.set(year, m, 1, 0, 0, 0);
                cal.set(Calendar.MILLISECOND, 0);
                long start = cal.getTimeInMillis();
                cal.add(Calendar.MONTH, 1);
                long end = cal.getTimeInMillis();

                Cursor cursor = db.rawQuery(
                    "SELECT COUNT(*) FROM " + NotesDatabaseHelper.TABLE_NOTES +
                    " WHERE " + NotesDatabaseHelper.COL_CREATED + ">=?" +
                    " AND " + NotesDatabaseHelper.COL_CREATED + "<?" +
                    " AND " + NotesDatabaseHelper.COL_IS_ROUTINE_MODE + "=1",
                    new String[]{String.valueOf(start), String.valueOf(end)});
                if (cursor != null) {
                    if (cursor.moveToFirst()) {
                        counts[m] = cursor.getInt(0);
                    }
                    cursor.close();
                }
            }
        } catch (Exception e) {
            // Fail silently
        }
        return counts;
    }

    // ============ UTILITY ============

    /**
     * Get epoch millisecond range for a date string yyyy-MM-dd.
     * Returns [startMillis, endMillis) for that day.
     */
    private long[] getDateRange(String dateYmd) {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
            Date parsed = sdf.parse(dateYmd);
            if (parsed == null) return null;
            long start = parsed.getTime();
            long end = start + 86400000L; // 24 hours
            return new long[]{start, end};
        } catch (Exception e) {
            return null;
        }
    }

    private int parseDayFromDate(String dateStr) {
        // dateStr = yyyy-MM-dd
        if (dateStr == null || dateStr.length() < 10) return -1;
        try {
            return Integer.parseInt(dateStr.substring(8, 10));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private Note cursorToNote(Cursor cursor) {
        Note note = new Note();
        note.setId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_ID)));
        note.setTitle(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_TITLE)));
        note.setContent(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_CONTENT)));
        note.setCreatedAt(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_CREATED)));
        note.setModifiedAt(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_MODIFIED)));
        note.setColor(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_COLOR)));
        note.setFavorite(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_FAVORITE)) == 1);
        int routineModeIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_IS_ROUTINE_MODE);
        if (routineModeIdx >= 0) {
            note.setRoutineMode(cursor.getInt(routineModeIdx) == 1);
        }
        int routineDataIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_ROUTINE_DATA);
        if (routineDataIdx >= 0) {
            note.setRoutineData(cursor.getString(routineDataIdx));
        }
        int clModeIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_IS_CHECKLIST_MODE);
        if (clModeIdx >= 0) {
            note.setChecklistMode(cursor.getInt(clModeIdx) == 1);
        }
        int clDataIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_CHECKLIST_DATA);
        if (clDataIdx >= 0) {
            note.setChecklistData(cursor.getString(clDataIdx));
        }
        return note;
    }
}
