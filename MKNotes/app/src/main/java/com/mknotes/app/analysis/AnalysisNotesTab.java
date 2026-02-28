package com.mknotes.app.analysis;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.mknotes.app.NoteEditorActivity;
import com.mknotes.app.R;
import com.mknotes.app.model.Note;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Builds the Notes tab content for Calendar Analysis.
 * Shows scrollable note cards with date/time and edit button.
 */
public class AnalysisNotesTab {

    private Context context;
    private AnalysisDataProvider dataProvider;

    public AnalysisNotesTab(Context context) {
        this.context = context;
        this.dataProvider = new AnalysisDataProvider(context);
    }

    /**
     * Build notes view for single or multiple dates.
     */
    public View buildForDates(List dates) {
        List notes;
        if (dates.size() == 1) {
            notes = dataProvider.getNotesForDate((String) dates.get(0));
        } else {
            notes = dataProvider.getNotesForDates(dates);
        }

        if (notes.isEmpty()) {
            return buildEmptyView(context.getString(R.string.analysis_no_notes));
        }

        LinearLayout container = new LinearLayout(context);
        container.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(4);
        container.setPadding(0, pad, 0, pad);

        for (int i = 0; i < notes.size(); i++) {
            Note note = (Note) notes.get(i);
            container.addView(buildNoteCard(note));
        }

        return container;
    }

    private View buildNoteCard(final Note note) {
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

        // Title
        String title = note.getTitle();
        if (title == null || title.trim().length() == 0) {
            title = context.getString(R.string.untitled);
        }
        TextView titleView = new TextView(context);
        titleView.setText(title);
        titleView.setTextColor(0xFFEAEAF0);
        titleView.setTextSize(15);
        titleView.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        titleView.setMaxLines(2);
        card.addView(titleView);

        // Content preview
        String preview = note.getPreview();
        if (preview != null && preview.length() > 0) {
            TextView contentView = new TextView(context);
            contentView.setText(preview);
            contentView.setTextColor(0xFF8888A0);
            contentView.setTextSize(13);
            contentView.setMaxLines(3);
            LinearLayout.LayoutParams clp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT);
            clp.topMargin = dp(4);
            contentView.setLayoutParams(clp);
            card.addView(contentView);
        }

        // Bottom row: date + edit button
        LinearLayout bottomRow = new LinearLayout(context);
        bottomRow.setOrientation(LinearLayout.HORIZONTAL);
        bottomRow.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        blp.topMargin = dp(10);
        bottomRow.setLayoutParams(blp);

        // Date/time
        TextView dateView = new TextView(context);
        SimpleDateFormat sdf = new SimpleDateFormat("dd MMM yyyy, hh:mm a", Locale.US);
        dateView.setText(sdf.format(new Date(note.getCreatedAt())));
        dateView.setTextColor(0xFF555570);
        dateView.setTextSize(11);
        LinearLayout.LayoutParams dlp = new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        dateView.setLayoutParams(dlp);
        bottomRow.addView(dateView);

        // Edit button
        TextView editBtn = new TextView(context);
        editBtn.setText(context.getString(R.string.analysis_edit));
        editBtn.setTextColor(0xFF4A9EFF);
        editBtn.setTextSize(13);
        editBtn.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        editBtn.setPadding(dp(12), dp(6), dp(12), dp(6));
        GradientDrawable editBg = new GradientDrawable();
        editBg.setCornerRadius(dp(8));
        editBg.setColor(0xFF1A2A40);
        editBtn.setBackground(editBg);
        editBtn.setGravity(Gravity.CENTER);
        editBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                Intent intent = new Intent(context, NoteEditorActivity.class);
                intent.putExtra("note_id", note.getId());
                if (context instanceof Activity) {
                    ((Activity) context).startActivity(intent);
                }
            }
        });
        bottomRow.addView(editBtn);

        card.addView(bottomRow);
        return card;
    }

    /**
     * Build notes view for a single month.
     */
    public View buildForMonth(int year, int month) {
        java.util.Calendar cal = java.util.Calendar.getInstance();
        cal.set(year, month - 1, 1);
        int maxDay = cal.getActualMaximum(java.util.Calendar.DAY_OF_MONTH);
        List dates = new java.util.ArrayList();
        for (int d = 1; d <= maxDay; d++) {
            dates.add(String.format(java.util.Locale.US, "%04d-%02d-%02d", year, month, d));
        }
        return buildForDates(dates);
    }

    /**
     * Build notes view for multiple months.
     */
    public View buildForMonths(List monthKeys) {
        List dates = new java.util.ArrayList();
        for (int i = 0; i < monthKeys.size(); i++) {
            String key = (String) monthKeys.get(i);
            try {
                int year = Integer.parseInt(key.substring(0, 4));
                int month = Integer.parseInt(key.substring(5, 7));
                java.util.Calendar cal = java.util.Calendar.getInstance();
                cal.set(year, month - 1, 1);
                int maxDay = cal.getActualMaximum(java.util.Calendar.DAY_OF_MONTH);
                for (int d = 1; d <= maxDay; d++) {
                    dates.add(String.format(java.util.Locale.US, "%04d-%02d-%02d", year, month, d));
                }
            } catch (Exception e) {
                // skip invalid
            }
        }
        return buildForDates(dates);
    }

    /**
     * Build notes view for a single year.
     * Shows scrollable list of all notes created in that year (no graph).
     * Year Notes tab = note list only (content isolation).
     */
    public View buildForYear(int year) {
        // Collect all dates in the year and get notes
        java.util.List allDates = new java.util.ArrayList();
        for (int m = 1; m <= 12; m++) {
            java.util.Calendar cal = java.util.Calendar.getInstance();
            cal.set(year, m - 1, 1);
            int maxDay = cal.getActualMaximum(java.util.Calendar.DAY_OF_MONTH);
            for (int d = 1; d <= maxDay; d++) {
                allDates.add(String.format(java.util.Locale.US, "%04d-%02d-%02d", year, m, d));
            }
        }
        return buildForDates(allDates);
    }

    /**
     * Build notes view for multiple years.
     * Shows scrollable list of all notes from selected years (no graph).
     * Multi-year Notes tab = note list only (content isolation).
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
                    allDates.add(String.format(java.util.Locale.US, "%04d-%02d-%02d", year, m, d));
                }
            }
        }
        return buildForDates(allDates);
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
