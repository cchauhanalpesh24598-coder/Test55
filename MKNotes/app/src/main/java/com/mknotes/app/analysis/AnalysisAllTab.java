package com.mknotes.app.analysis;

import android.content.Context;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.mknotes.app.R;
import com.mknotes.app.model.Note;

import java.util.ArrayList;
import java.util.List;

/**
 * Builds the "All" tab content for Calendar Analysis.
 * Shows stacked overview: Notes count, Routine summary,
 * Meditation graph, and combined summary.
 * Expandable for future features (Mood tracking, etc).
 */
public class AnalysisAllTab {

    private Context context;
    private AnalysisDataProvider dataProvider;
    private AnalysisMeditationTab meditationTab;

    private static final int[] GRAPH_COLORS = {
            0xFF4ADE80, 0xFF4A9EFF, 0xFFFF6B9D, 0xFFFFA04A,
            0xFF22D3EE, 0xFFFACC15, 0xFFA78BFA, 0xFF2DD4BF
    };

    public AnalysisAllTab(Context context) {
        this.context = context;
        this.dataProvider = new AnalysisDataProvider(context);
        this.meditationTab = new AnalysisMeditationTab(context);
    }

    // ============ DATE MODE ============

    public View buildForDates(List dates) {
        LinearLayout container = new LinearLayout(context);
        container.setOrientation(LinearLayout.VERTICAL);

        // Notes summary card
        List notes;
        if (dates.size() == 1) {
            notes = dataProvider.getNotesForDate((String) dates.get(0));
        } else {
            notes = dataProvider.getNotesForDates(dates);
        }
        container.addView(buildStatCard("Notes", String.valueOf(notes.size()),
                notes.size() > 0 ? "notes created" : "no notes", 0xFF4A9EFF));

        // Routine summary card
        List routines;
        if (dates.size() == 1) {
            routines = dataProvider.getRoutineNotesForDate((String) dates.get(0));
        } else {
            routines = dataProvider.getRoutineNotesForDates(dates);
        }
        container.addView(buildStatCard("Routine", String.valueOf(routines.size()),
                routines.size() > 0 ? "routine entries" : "no routine data", 0xFFFFA04A));

        // Meditation summary + graph
        AnalysisDataProvider.DateMantraData medData;
        if (dates.size() == 1) {
            medData = dataProvider.getMeditationForDate((String) dates.get(0));
        } else {
            medData = dataProvider.getMeditationForDates(dates);
        }

        container.addView(buildStatCard("Meditation",
                String.valueOf(medData.grandTotal),
                medData.grandMala > 0 ? medData.grandMala + " Mala" : "total count",
                0xFF4ADE80));

        // Meditation graph (reuse meditationTab for proper time-slot / multi-date graph)
        if (!medData.summaries.isEmpty()) {
            View medGraphView = meditationTab.buildForDates(dates);
            if (medGraphView != null) {
                LinearLayout.LayoutParams glp = new LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT);
                glp.topMargin = dp(12);
                medGraphView.setLayoutParams(glp);
                container.addView(medGraphView);
            }
        }

        // Combined summary card
        container.addView(buildCombinedSummary(notes.size(), routines.size(), medData));

        // Future expansion placeholder
        container.addView(buildFuturePlaceholder());

        return container;
    }

    // ============ MONTH MODE ============

    public View buildForMonth(int year, int month) {
        LinearLayout container = new LinearLayout(context);
        container.setOrientation(LinearLayout.VERTICAL);

        List dayTotals = dataProvider.getMeditationForMonth(year, month);
        int monthTotal = 0;
        int activeDays = 0;
        for (int i = 0; i < dayTotals.size(); i++) {
            int t = ((AnalysisDataProvider.DayTotal) dayTotals.get(i)).totalCount;
            monthTotal += t;
            if (t > 0) activeDays++;
        }

        container.addView(buildStatCard("Meditation", String.valueOf(monthTotal),
                activeDays + " active days", 0xFF4ADE80));

        // Graph
        View medView = meditationTab.buildForMonth(year, month);
        if (medView != null) {
            LinearLayout.LayoutParams mlp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT);
            mlp.topMargin = dp(8);
            medView.setLayoutParams(mlp);
            container.addView(medView);
        }

        return container;
    }

    public View buildForMonths(List monthKeys) {
        LinearLayout container = new LinearLayout(context);
        container.setOrientation(LinearLayout.VERTICAL);

        // Meditation comparison graph
        View medView = meditationTab.buildForMonths(monthKeys);
        if (medView != null) {
            LinearLayout.LayoutParams mlp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT);
            mlp.topMargin = dp(8);
            medView.setLayoutParams(mlp);
            container.addView(medView);
        }

        return container;
    }

    // ============ YEAR MODE ============

    public View buildForYear(int year) {
        LinearLayout container = new LinearLayout(context);
        container.setOrientation(LinearLayout.VERTICAL);

        // Notes count for year
        int[] notesCounts = dataProvider.getNotesCountByMonth(year);
        int totalNotes = 0;
        for (int i = 0; i < notesCounts.length; i++) {
            totalNotes += notesCounts[i];
        }
        container.addView(buildStatCard("Notes", String.valueOf(totalNotes),
                totalNotes > 0 ? "notes in " + year : "no notes", 0xFF4A9EFF));

        // Routine count for year
        int[] routineCounts = dataProvider.getRoutineCountByMonth(year);
        int totalRoutine = 0;
        for (int i = 0; i < routineCounts.length; i++) {
            totalRoutine += routineCounts[i];
        }
        container.addView(buildStatCard("Routine", String.valueOf(totalRoutine),
                totalRoutine > 0 ? "routine entries in " + year : "no routine data", 0xFFFFA04A));

        // Meditation total for year
        List monthTotals = dataProvider.getMeditationForYear(year);
        int yearMedTotal = 0;
        for (int i = 0; i < monthTotals.size(); i++) {
            yearMedTotal += ((AnalysisDataProvider.MonthTotal) monthTotals.get(i)).totalCount;
        }
        container.addView(buildStatCard("Meditation", String.valueOf(yearMedTotal),
                yearMedTotal > 0 ? (yearMedTotal / 108) + " Mala" : "no meditation data", 0xFF4ADE80));

        // Meditation graph
        if (yearMedTotal > 0) {
            View medView = meditationTab.buildForYear(year);
            if (medView != null) {
                LinearLayout.LayoutParams mlp = new LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT);
                mlp.topMargin = dp(8);
                medView.setLayoutParams(mlp);
                container.addView(medView);
            }
        }

        return container;
    }

    public View buildForYears(List yearKeys) {
        LinearLayout container = new LinearLayout(context);
        container.setOrientation(LinearLayout.VERTICAL);

        // Show summary for each year
        for (int i = 0; i < yearKeys.size(); i++) {
            String yk = (String) yearKeys.get(i);
            int year;
            try {
                year = Integer.parseInt(yk);
            } catch (NumberFormatException e) {
                continue;
            }
            int[] nc = dataProvider.getNotesCountByMonth(year);
            int[] rc = dataProvider.getRoutineCountByMonth(year);
            int tn = 0, tr = 0;
            for (int m = 0; m < 12; m++) { tn += nc[m]; tr += rc[m]; }
            container.addView(buildStatCard("Year " + year,
                    tn + " notes, " + tr + " routines", "overview", GRAPH_COLORS[i % GRAPH_COLORS.length]));
        }

        // Meditation comparison graph
        View medView = meditationTab.buildForYears(yearKeys);
        if (medView != null) {
            LinearLayout.LayoutParams mlp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT);
            mlp.topMargin = dp(8);
            medView.setLayoutParams(mlp);
            container.addView(medView);
        }

        return container;
    }

    // ============ UI BUILDERS ============

    private View buildStatCard(String label, String value, String subtitle, int accentColor) {
        LinearLayout card = new LinearLayout(context);
        card.setOrientation(LinearLayout.HORIZONTAL);
        card.setGravity(Gravity.CENTER_VERTICAL);
        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(14));
        bg.setColor(0xFF1C1C28);
        bg.setStroke(dp(1), 0xFF2A2A3A);
        card.setBackground(bg);
        int pad = dp(16);
        card.setPadding(pad, dp(14), pad, dp(14));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(8);
        card.setLayoutParams(lp);

        // Accent stripe
        View stripe = new View(context);
        GradientDrawable stripeBg = new GradientDrawable();
        stripeBg.setCornerRadius(dp(3));
        stripeBg.setColor(accentColor);
        stripe.setBackground(stripeBg);
        LinearLayout.LayoutParams sLp = new LinearLayout.LayoutParams(dp(4), dp(36));
        sLp.rightMargin = dp(14);
        stripe.setLayoutParams(sLp);
        card.addView(stripe);

        // Text section
        LinearLayout textSection = new LinearLayout(context);
        textSection.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams tsLp = new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        textSection.setLayoutParams(tsLp);

        TextView labelView = new TextView(context);
        labelView.setText(label);
        labelView.setTextColor(0xFF8888A0);
        labelView.setTextSize(12);
        textSection.addView(labelView);

        TextView subtitleView = new TextView(context);
        subtitleView.setText(subtitle);
        subtitleView.setTextColor(0xFF555570);
        subtitleView.setTextSize(11);
        LinearLayout.LayoutParams stLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        stLp.topMargin = dp(2);
        subtitleView.setLayoutParams(stLp);
        textSection.addView(subtitleView);

        card.addView(textSection);

        // Value
        TextView valueView = new TextView(context);
        valueView.setText(value);
        valueView.setTextColor(accentColor);
        valueView.setTextSize(26);
        valueView.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        card.addView(valueView);

        return card;
    }

    private View buildCombinedSummary(int notesCount, int routineCount,
                                       AnalysisDataProvider.DateMantraData medData) {
        LinearLayout card = new LinearLayout(context);
        card.setOrientation(LinearLayout.VERTICAL);
        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(14));
        bg.setColor(0xFF1C1C28);
        bg.setStroke(dp(1), 0xFF2A2A3A);
        card.setBackground(bg);
        int pad = dp(16);
        card.setPadding(pad, pad, pad, pad);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(12);
        card.setLayoutParams(lp);

        TextView header = new TextView(context);
        header.setText(context.getString(R.string.analysis_summary));
        header.setTextColor(0xFFEAEAF0);
        header.setTextSize(15);
        header.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        card.addView(header);

        // Divider
        View div = new View(context);
        div.setBackgroundColor(0xFF222233);
        LinearLayout.LayoutParams dlp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(1));
        dlp.topMargin = dp(8);
        dlp.bottomMargin = dp(8);
        div.setLayoutParams(dlp);
        card.addView(div);

        card.addView(makeSummaryRow("Total Notes", String.valueOf(notesCount)));
        card.addView(makeSummaryRow("Total Routines", String.valueOf(routineCount)));
        card.addView(makeSummaryRow("Total Meditation Count", String.valueOf(medData.grandTotal)));
        if (medData.grandMala > 0) {
            card.addView(makeSummaryRow("Total Mala", String.valueOf(medData.grandMala)));
        }
        card.addView(makeSummaryRow("Unique Mantras", String.valueOf(medData.summaries.size())));

        return card;
    }

    private View makeSummaryRow(String label, String value) {
        LinearLayout row = new LinearLayout(context);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setPadding(0, dp(4), 0, dp(4));

        TextView labelView = new TextView(context);
        labelView.setText(label);
        labelView.setTextColor(0xFF8888A0);
        labelView.setTextSize(13);
        LinearLayout.LayoutParams llp = new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        labelView.setLayoutParams(llp);
        row.addView(labelView);

        TextView valueView = new TextView(context);
        valueView.setText(value);
        valueView.setTextColor(0xFFEAEAF0);
        valueView.setTextSize(13);
        valueView.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        row.addView(valueView);

        return row;
    }

    private View buildFuturePlaceholder() {
        LinearLayout card = new LinearLayout(context);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setGravity(Gravity.CENTER);
        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(14));
        bg.setColor(0xFF151520);
        bg.setStroke(dp(1), 0x33555570);
        card.setBackground(bg);
        card.setPadding(dp(16), dp(20), dp(16), dp(20));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(12);
        lp.bottomMargin = dp(8);
        card.setLayoutParams(lp);

        TextView tv = new TextView(context);
        tv.setText("More insights coming soon");
        tv.setTextColor(0xFF444460);
        tv.setTextSize(12);
        tv.setGravity(Gravity.CENTER);
        card.addView(tv);

        return card;
    }

    private int dp(float val) {
        return (int) (val * context.getResources().getDisplayMetrics().density + 0.5f);
    }
}
