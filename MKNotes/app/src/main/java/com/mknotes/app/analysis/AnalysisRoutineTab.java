package com.mknotes.app.analysis;

import android.content.Context;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.mknotes.app.R;
import com.mknotes.app.model.Note;
import com.mknotes.app.routine.RoutineManager;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Builds the Routine tab content for Calendar Analysis.
 * Shows ONLY structured routine data (wake/sleep/entries) - never raw note content.
 * Pure Java, no AndroidX, no lambda, AIDE compatible.
 */
public class AnalysisRoutineTab {

    private Context context;
    private AnalysisDataProvider dataProvider;

    public AnalysisRoutineTab(Context context) {
        this.context = context;
        this.dataProvider = new AnalysisDataProvider(context);
    }

    /**
     * Build routine view for single or multiple dates.
     */
    public View buildForDates(List dates) {
        List routineNotes;
        if (dates.size() == 1) {
            routineNotes = dataProvider.getRoutineNotesForDate((String) dates.get(0));
        } else {
            routineNotes = dataProvider.getRoutineNotesForDates(dates);
        }

        if (routineNotes.isEmpty()) {
            return buildEmptyView(context.getString(R.string.analysis_no_routine));
        }

        LinearLayout container = new LinearLayout(context);
        container.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(4);
        container.setPadding(0, pad, 0, pad);

        for (int i = 0; i < routineNotes.size(); i++) {
            Note note = (Note) routineNotes.get(i);
            container.addView(buildRoutineCard(note));
        }

        return container;
    }

    /**
     * Build routine view for a single year.
     * Shows scrollable list of all routine entries for that year (no graph).
     * Year Routine tab = routine list only (content isolation).
     */
    public View buildForYear(int year) {
        java.util.List allDates = new java.util.ArrayList();
        for (int m = 1; m <= 12; m++) {
            java.util.Calendar cal = java.util.Calendar.getInstance();
            cal.set(year, m - 1, 1);
            int maxDay = cal.getActualMaximum(java.util.Calendar.DAY_OF_MONTH);
            for (int d = 1; d <= maxDay; d++) {
                allDates.add(String.format(Locale.US, "%04d-%02d-%02d", year, m, d));
            }
        }
        return buildForDates(allDates);
    }

    /**
     * Build routine view for multiple years.
     * Shows scrollable list of all routine entries from selected years (no graph).
     * Multi-year Routine tab = routine list only (content isolation).
     */
    public View buildForYears(List yearKeys) {
        if (yearKeys == null || yearKeys.isEmpty()) {
            return buildEmptyView("No years selected");
        }

        java.util.List allDates = new java.util.ArrayList();
        for (int i = 0; i < yearKeys.size(); i++) {
            String yk = (String) yearKeys.get(i);
            int year;
            try {
                year = Integer.parseInt(yk);
            } catch (NumberFormatException e) {
                continue;
            }
            for (int m = 1; m <= 12; m++) {
                java.util.Calendar cal = java.util.Calendar.getInstance();
                cal.set(year, m - 1, 1);
                int maxDay = cal.getActualMaximum(java.util.Calendar.DAY_OF_MONTH);
                for (int d = 1; d <= maxDay; d++) {
                    allDates.add(String.format(Locale.US, "%04d-%02d-%02d", year, m, d));
                }
            }
        }
        return buildForDates(allDates);
    }

    /**
     * Build routine view for multiple months.
     */
    public View buildForMonths(List monthKeys) {
        if (monthKeys == null || monthKeys.isEmpty()) {
            return buildEmptyView("No months selected");
        }

        java.util.List allDates = new java.util.ArrayList();
        for (int i = 0; i < monthKeys.size(); i++) {
            String key = (String) monthKeys.get(i);
            try {
                int year = Integer.parseInt(key.substring(0, 4));
                int month = Integer.parseInt(key.substring(5, 7));
                java.util.Calendar cal = java.util.Calendar.getInstance();
                cal.set(year, month - 1, 1);
                int maxDay = cal.getActualMaximum(java.util.Calendar.DAY_OF_MONTH);
                for (int d = 1; d <= maxDay; d++) {
                    allDates.add(String.format(Locale.US, "%04d-%02d-%02d", year, month, d));
                }
            } catch (Exception e) {
                // skip invalid
            }
        }
        return buildForDates(allDates);
    }

    /**
     * Build routine view for a month.
     * Shows routine notes for the month.
     */
    public View buildForMonth(int year, int month) {
        String monthStr = String.format(Locale.US, "%04d-%02d", year, month);
        // Get all dates in the month and load routine notes
        java.util.Calendar cal = java.util.Calendar.getInstance();
        cal.set(year, month - 1, 1);
        int maxDay = cal.getActualMaximum(java.util.Calendar.DAY_OF_MONTH);

        java.util.List allDates = new java.util.ArrayList();
        for (int d = 1; d <= maxDay; d++) {
            allDates.add(String.format(Locale.US, "%04d-%02d-%02d", year, month, d));
        }

        return buildForDates(allDates);
    }

    // ============ CARD BUILDERS ============

    private View buildRoutineCard(Note note) {
        LinearLayout card = new LinearLayout(context);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_analysis_note_card);
        int pad = dp(16);
        card.setPadding(pad, pad, pad, pad);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(10);
        card.setLayoutParams(lp);

        // Date header
        SimpleDateFormat sdf = new SimpleDateFormat("EEE, dd MMM yyyy", Locale.US);
        TextView dateHeader = new TextView(context);
        dateHeader.setText(sdf.format(new Date(note.getCreatedAt())));
        dateHeader.setTextColor(0xFF4A9EFF);
        dateHeader.setTextSize(12);
        dateHeader.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        card.addView(dateHeader);

        // Parse structured routine data using RoutineManager
        String routineData = note.getRoutineData();
        if (routineData != null && routineData.length() > 0) {
            RoutineManager rm = new RoutineManager();
            rm.deserialize(routineData);

            String wakeTime = rm.getWakeTime();
            String sleepTime = rm.getSleepTime();
            String entries = rm.getEntriesText();

            // Wake time
            if (wakeTime != null && wakeTime.length() > 0) {
                card.addView(buildRoutineField("Wake Time", wakeTime, 0xFF51CF66));
            }

            // Sleep time
            if (sleepTime != null && sleepTime.length() > 0) {
                card.addView(buildRoutineField("Sleep Time", sleepTime, 0xFF339AF0));
            }

            // Entries
            if (entries != null && entries.trim().length() > 0) {
                TextView entriesLabel = new TextView(context);
                entriesLabel.setText("Routine Entries:");
                entriesLabel.setTextColor(0xFFCC5DE8);
                entriesLabel.setTextSize(12);
                entriesLabel.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
                LinearLayout.LayoutParams elp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT);
                elp.topMargin = dp(8);
                entriesLabel.setLayoutParams(elp);
                card.addView(entriesLabel);

                // Split entries by newline and show each
                String[] lines = entries.split("\\n");
                for (int i = 0; i < lines.length; i++) {
                    String line = lines[i].trim();
                    if (line.length() == 0) continue;
                    TextView lineView = new TextView(context);
                    lineView.setText("  " + line);
                    lineView.setTextColor(0xFFCCCCDD);
                    lineView.setTextSize(13);
                    LinearLayout.LayoutParams llp = new LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT);
                    llp.topMargin = dp(2);
                    lineView.setLayoutParams(llp);
                    card.addView(lineView);
                }
            }
        } else {
            // No structured routine data
            TextView noData = new TextView(context);
            noData.setText("No routine data recorded");
            noData.setTextColor(0xFF555570);
            noData.setTextSize(13);
            LinearLayout.LayoutParams nlp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
            nlp.topMargin = dp(6);
            noData.setLayoutParams(nlp);
            card.addView(noData);
        }

        // IMPORTANT: We do NOT show note.getContent() here.
        // Only structured routine data (wake/sleep/entries) is displayed.

        return card;
    }

    private View buildRoutineField(String label, String value, int labelColor) {
        LinearLayout row = new LinearLayout(context);
        row.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams rlp = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT);
        rlp.topMargin = dp(6);
        row.setLayoutParams(rlp);

        TextView labelView = new TextView(context);
        labelView.setText(label + ": ");
        labelView.setTextColor(labelColor);
        labelView.setTextSize(13);
        labelView.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        row.addView(labelView);

        TextView valueView = new TextView(context);
        valueView.setText(value);
        valueView.setTextColor(0xFFEAEAF0);
        valueView.setTextSize(14);
        row.addView(valueView);

        return row;
    }

    private View buildSummaryCard(String title, String subtitle) {
        LinearLayout card = new LinearLayout(context);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_analysis_card);
        int pad = dp(14);
        card.setPadding(pad, pad, pad, pad);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(8);
        card.setLayoutParams(lp);

        TextView titleView = new TextView(context);
        titleView.setText(title);
        titleView.setTextColor(0xFFEAEAF0);
        titleView.setTextSize(15);
        titleView.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        card.addView(titleView);

        TextView subtitleView = new TextView(context);
        subtitleView.setText(subtitle);
        subtitleView.setTextColor(0xFF8888A0);
        subtitleView.setTextSize(13);
        LinearLayout.LayoutParams slp = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT);
        slp.topMargin = dp(4);
        subtitleView.setLayoutParams(slp);
        card.addView(subtitleView);

        return card;
    }

    private View buildEmptyView(String message) {
        TextView tv = new TextView(context);
        tv.setText(message);
        tv.setTextColor(0xFF555570);
        tv.setTextSize(14);
        tv.setGravity(Gravity.CENTER);
        tv.setPadding(dp(16), dp(40), dp(16), dp(40));
        return tv;
    }

    private int dp(float val) {
        return (int) (val * context.getResources().getDisplayMetrics().density + 0.5f);
    }
}
