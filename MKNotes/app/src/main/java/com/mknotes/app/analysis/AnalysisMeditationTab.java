package com.mknotes.app.analysis;

import android.content.Context;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.mknotes.app.R;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Builds the Meditation tab content for Calendar Analysis.
 * Shows mantra summary table, graph, and legend.
 * Supports all 6 modes: single/multi date, single/multi month, single/multi year.
 *
 * SINGLE DATE: Time-slot based graph (2-hour slots, 12 slots covering full 24 hours).
 * MONTH: Day-based graph (1-31 continuous), scrollable.
 * YEAR: Month-based graph (Jan-Dec all 12 months).
 *
 * Pure Java, no AndroidX, no lambda, AIDE compatible.
 */
public class AnalysisMeditationTab {

    private Context context;
    private AnalysisDataProvider dataProvider;

    // Graph line colors for mantras
    private static final int[] GRAPH_COLORS = {
            0xFF4ADE80, // green
            0xFF4A9EFF, // blue
            0xFFFF6B9D, // pink
            0xFFFFA04A, // orange
            0xFF22D3EE, // cyan
            0xFFFACC15, // yellow
            0xFFA78BFA, // purple
            0xFF2DD4BF, // teal
            0xFFEF4444, // red
            0xFFFF8C00  // dark orange
    };

    public AnalysisMeditationTab(Context context) {
        this.context = context;
        this.dataProvider = new AnalysisDataProvider(context);
    }

    // ============ SINGLE/MULTI DATE ============

    /**
     * Build meditation view for single or multiple dates.
     * Single date uses time-slot graph (2-hour slots from 4AM-12AM).
     * Multi-date uses comparison graph with each mantra as a line.
     */
    public View buildForDates(List dates) {
        AnalysisDataProvider.DateMantraData data;
        if (dates.size() == 1) {
            data = dataProvider.getMeditationForDate((String) dates.get(0));
        } else {
            data = dataProvider.getMeditationForDates(dates);
        }

        if (data.summaries.isEmpty()) {
            return buildEmptyView(context.getString(R.string.analysis_no_meditation));
        }

        LinearLayout container = new LinearLayout(context);
        container.setOrientation(LinearLayout.VERTICAL);

        // Mantra Summary Table (always shown)
        container.addView(buildMantraTable(data));

        if (dates.size() == 1) {
            // SINGLE DATE: Time-slot based graph
            String dateYmd = (String) dates.get(0);
            container.addView(buildTimeSlotGraph(dateYmd, data));
        } else {
            // MULTI DATE: Each mantra is a line, each date is x-point
            String[] labels = new String[dates.size()];
            for (int i = 0; i < dates.size(); i++) {
                String d = (String) dates.get(i);
                labels[i] = d.length() >= 10 ? d.substring(5) : d; // MM-DD
            }
            List graphData = dataProvider.getMultiDateMantraGraph(dates, GRAPH_COLORS);
            String graphTitle = "Multi-Date Comparison";

            View graphView = createGraphWithScroll(graphData, labels, graphTitle,
                dates.size() > 12);
            LinearLayout.LayoutParams glp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
            glp.topMargin = dp(12);
            graphView.setLayoutParams(glp);
            container.addView(graphView);
        }

        return container;
    }

    /**
     * Build time-slot graph for a single date.
     * X-axis: 12 time slots (12-2AM, 2-4AM, ..., 10-12AM) covering full 24 hours.
     * Y-axis: Auto-scale count
     * Each mantra = separate colored line.
     * If no timestamp data exists (pre-migration), only show info message - no fallback graph.
     */
    private View buildTimeSlotGraph(String dateYmd, AnalysisDataProvider.DateMantraData fallbackData) {
        LinearLayout wrapper = new LinearLayout(context);
        wrapper.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams wlp = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT);
        wlp.topMargin = dp(12);
        wrapper.setLayoutParams(wlp);

        boolean hasTimeData = dataProvider.hasTimeSlotData(dateYmd);

        if (!hasTimeData) {
            // No timestamp data - show info message only, no fallback graph
            TextView info = new TextView(context);
            info.setText("Time-based tracking available only for new sessions.\n" +
                "Start a meditation session to see time-slot analysis.");
            info.setTextColor(0xFF8888A0);
            info.setTextSize(12);
            info.setPadding(dp(12), dp(8), dp(12), dp(8));
            wrapper.addView(info);
            return wrapper;
        }

        // Build time-slot graph with real timestamp data
        List timeSlots = dataProvider.getTimeSlotDataForDate(dateYmd);
        if (timeSlots.isEmpty()) {
            return wrapper; // Should not happen since hasTimeData was true
        }

        String[] labels = AnalysisDataProvider.TIME_SLOT_LABELS;
        List graphData = new ArrayList();

        for (int i = 0; i < timeSlots.size(); i++) {
            AnalysisDataProvider.TimeSlotEntry tse =
                (AnalysisDataProvider.TimeSlotEntry) timeSlots.get(i);
            int color = GRAPH_COLORS[i % GRAPH_COLORS.length];
            AnalysisDataProvider.GraphDataSet ds = new AnalysisDataProvider.GraphDataSet(
                tse.mantraName, color);
            for (int s = 0; s < tse.slotCounts.length; s++) {
                ds.values.add(Float.valueOf((float) tse.slotCounts[s]));
            }
            graphData.add(ds);
        }

        // 12 data points - needs scroll for readable labels
        View graphView = createGraphWithScroll(graphData, labels,
            "Time-Slot Activity", true);
        wrapper.addView(graphView);

        return wrapper;
    }

    // ============ SINGLE/MULTI MONTH ============

    /**
     * Build meditation view for a single month.
     * X-axis: 1-31 continuous dates.
     * Wrapped in HorizontalScrollView for readability.
     */
    public View buildForMonth(int year, int month) {
        List dayTotals = dataProvider.getMeditationForMonth(year, month);

        // Check if any data
        boolean hasData = false;
        for (int i = 0; i < dayTotals.size(); i++) {
            if (((AnalysisDataProvider.DayTotal) dayTotals.get(i)).totalCount > 0) {
                hasData = true;
                break;
            }
        }

        if (!hasData) {
            return buildEmptyView(context.getString(R.string.analysis_no_meditation));
        }

        LinearLayout container = new LinearLayout(context);
        container.setOrientation(LinearLayout.VERTICAL);

        // Summary card
        int monthTotal = 0;
        for (int i = 0; i < dayTotals.size(); i++) {
            monthTotal += ((AnalysisDataProvider.DayTotal) dayTotals.get(i)).totalCount;
        }
        container.addView(buildSummaryCard("Month Total", monthTotal));

        // Graph with per-mantra lines
        List graphData = dataProvider.getMonthMantraGraph(year, month, GRAPH_COLORS);
        String[] labels = new String[dayTotals.size()];
        for (int i = 0; i < dayTotals.size(); i++) {
            labels[i] = String.valueOf(((AnalysisDataProvider.DayTotal) dayTotals.get(i)).day);
        }

        String[] monthNames = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
        String graphTitle = monthNames[month - 1] + " " + year;

        // If no per-mantra data, create a total line
        if (graphData.isEmpty()) {
            AnalysisDataProvider.GraphDataSet totalDs =
                    new AnalysisDataProvider.GraphDataSet("Total", GRAPH_COLORS[0]);
            for (int i = 0; i < dayTotals.size(); i++) {
                totalDs.values.add(Float.valueOf(
                        (float) ((AnalysisDataProvider.DayTotal) dayTotals.get(i)).totalCount));
            }
            graphData.add(totalDs);
        }

        // Month has 28-31 data points -> always scrollable
        View graphView = createGraphWithScroll(graphData, labels, graphTitle, true);
        LinearLayout.LayoutParams glp = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT);
        glp.topMargin = dp(12);
        graphView.setLayoutParams(glp);
        container.addView(graphView);

        return container;
    }

    /**
     * Build meditation view for multiple months (comparison).
     */
    public View buildForMonths(List monthKeys) {
        // monthKeys: list of "yyyy-MM" strings
        if (monthKeys.isEmpty()) {
            return buildEmptyView(context.getString(R.string.analysis_no_meditation));
        }

        LinearLayout container = new LinearLayout(context);
        container.setOrientation(LinearLayout.VERTICAL);

        // Each month is a line, X=day (1-31), Y=count
        List graphData = new ArrayList();
        int maxDays = 0;

        for (int i = 0; i < monthKeys.size(); i++) {
            String key = (String) monthKeys.get(i);
            int year, month;
            try {
                year = Integer.parseInt(key.substring(0, 4));
                month = Integer.parseInt(key.substring(5, 7));
            } catch (Exception e) {
                continue;
            }

            List dayTotals = dataProvider.getMeditationForMonth(year, month);
            if (dayTotals.size() > maxDays) maxDays = dayTotals.size();

            String[] mNames = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
            String label = mNames[month - 1] + " " + year;
            int color = GRAPH_COLORS[i % GRAPH_COLORS.length];

            AnalysisDataProvider.GraphDataSet ds = new AnalysisDataProvider.GraphDataSet(label, color);
            for (int j = 0; j < dayTotals.size(); j++) {
                ds.values.add(Float.valueOf(
                        (float) ((AnalysisDataProvider.DayTotal) dayTotals.get(j)).totalCount));
            }
            graphData.add(ds);
        }

        String[] labels = new String[maxDays];
        for (int i = 0; i < maxDays; i++) {
            labels[i] = String.valueOf(i + 1);
        }

        // Multi-month with 28-31 data points -> scrollable
        View graphView = createGraphWithScroll(graphData, labels, "Month Comparison", true);
        LinearLayout.LayoutParams glp = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT);
        glp.topMargin = dp(8);
        graphView.setLayoutParams(glp);
        container.addView(graphView);

        return container;
    }

    // ============ SINGLE/MULTI YEAR ============

    /**
     * Build meditation view for a single year.
     * X-axis: All 12 months (Jan-Dec).
     */
    public View buildForYear(int year) {
        List monthTotals = dataProvider.getMeditationForYear(year);

        boolean hasData = false;
        int yearTotal = 0;
        for (int i = 0; i < monthTotals.size(); i++) {
            int t = ((AnalysisDataProvider.MonthTotal) monthTotals.get(i)).totalCount;
            yearTotal += t;
            if (t > 0) hasData = true;
        }

        if (!hasData) {
            return buildEmptyView(context.getString(R.string.analysis_no_meditation));
        }

        LinearLayout container = new LinearLayout(context);
        container.setOrientation(LinearLayout.VERTICAL);

        container.addView(buildSummaryCard("Year " + year + " Total", yearTotal));

        String[] labels = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

        AnalysisDataProvider.GraphDataSet ds = dataProvider.getYearGraphData(year, GRAPH_COLORS[0]);

        List graphData = new ArrayList();
        graphData.add(ds);

        AnalysisGraphView graph = new AnalysisGraphView(context);
        LinearLayout.LayoutParams glp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        glp.topMargin = dp(12);
        graph.setLayoutParams(glp);
        graph.setData(graphData, labels, String.valueOf(year));
        container.addView(graph);

        return container;
    }

    /**
     * Build meditation view for multiple years (comparison).
     * Each year = separate color line. X-axis: Jan-Dec (all 12 months).
     */
    public View buildForYears(List yearKeys) {
        if (yearKeys.isEmpty()) {
            return buildEmptyView(context.getString(R.string.analysis_no_meditation));
        }

        LinearLayout container = new LinearLayout(context);
        container.setOrientation(LinearLayout.VERTICAL);

        List graphData = new ArrayList();
        String[] labels = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

        for (int i = 0; i < yearKeys.size(); i++) {
            String key = (String) yearKeys.get(i);
            int year;
            try {
                year = Integer.parseInt(key);
            } catch (Exception e) {
                continue;
            }
            int color = GRAPH_COLORS[i % GRAPH_COLORS.length];
            AnalysisDataProvider.GraphDataSet ds = dataProvider.getYearGraphData(year, color);
            graphData.add(ds);
        }

        AnalysisGraphView graph = new AnalysisGraphView(context);
        LinearLayout.LayoutParams glp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        glp.topMargin = dp(8);
        graph.setLayoutParams(glp);
        graph.setData(graphData, labels, "Year Comparison");
        container.addView(graph);

        return container;
    }

    // ============ GRAPH HELPER ============

    /**
     * Create a graph view, optionally wrapped in a HorizontalScrollView.
     * When scrollable, sets minPointSpacing so graph expands beyond screen.
     */
    private View createGraphWithScroll(List datasets, String[] labels,
            String title, boolean scrollable) {
        AnalysisGraphView graph = new AnalysisGraphView(context);

        if (scrollable && labels.length > 7) {
            graph.setMinPointSpacing(40f); // 40dp per data point
            // Wrap in HorizontalScrollView
            HorizontalScrollView scrollView = new HorizontalScrollView(context);
            scrollView.setHorizontalScrollBarEnabled(true);
            scrollView.setFillViewport(false);
            LinearLayout.LayoutParams slp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
            scrollView.setLayoutParams(slp);

            graph.setData(datasets, labels, title);
            scrollView.addView(graph);
            return scrollView;
        } else {
            LinearLayout.LayoutParams glp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
            graph.setLayoutParams(glp);
            graph.setData(datasets, labels, title);
            return graph;
        }
    }

    // ============ UI BUILDERS ============

    private View buildMantraTable(AnalysisDataProvider.DateMantraData data) {
        LinearLayout card = new LinearLayout(context);
        card.setOrientation(LinearLayout.VERTICAL);
        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(16));
        bg.setColor(0xFF1C1C28);
        bg.setStroke(dp(1), 0xFF2A2A3A);
        card.setBackground(bg);
        int pad = dp(16);
        card.setPadding(pad, pad, pad, pad);

        // Header row
        LinearLayout headerRow = new LinearLayout(context);
        headerRow.setOrientation(LinearLayout.HORIZONTAL);
        headerRow.addView(makeHeaderCell("Mantra", 0.5f));
        headerRow.addView(makeHeaderCell("Count", 0.25f));
        headerRow.addView(makeHeaderCell("Mala", 0.25f));
        card.addView(headerRow);

        // Divider
        card.addView(makeDivider());

        // Data rows
        for (int i = 0; i < data.summaries.size(); i++) {
            AnalysisDataProvider.MantraSummary s =
                    (AnalysisDataProvider.MantraSummary) data.summaries.get(i);

            LinearLayout row = new LinearLayout(context);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setPadding(0, dp(6), 0, dp(6));

            // Colored dot + name
            LinearLayout nameCell = new LinearLayout(context);
            nameCell.setOrientation(LinearLayout.HORIZONTAL);
            nameCell.setGravity(Gravity.CENTER_VERTICAL);
            LinearLayout.LayoutParams ncLp = new LinearLayout.LayoutParams(
                    0, LinearLayout.LayoutParams.WRAP_CONTENT, 0.5f);
            nameCell.setLayoutParams(ncLp);

            View dot = new View(context);
            GradientDrawable dotBg = new GradientDrawable();
            dotBg.setShape(GradientDrawable.OVAL);
            dotBg.setColor(GRAPH_COLORS[i % GRAPH_COLORS.length]);
            dot.setBackground(dotBg);
            LinearLayout.LayoutParams dotLp = new LinearLayout.LayoutParams(dp(8), dp(8));
            dotLp.rightMargin = dp(8);
            dot.setLayoutParams(dotLp);
            nameCell.addView(dot);

            TextView nameView = new TextView(context);
            nameView.setText(s.mantraName);
            nameView.setTextColor(0xFFEAEAF0);
            nameView.setTextSize(13);
            nameView.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
            nameView.setMaxLines(1);
            nameCell.addView(nameView);

            row.addView(nameCell);
            row.addView(makeDataCell(String.valueOf(s.totalCount), 0.25f));

            String malaStr;
            if (s.malaCount > 0) {
                malaStr = s.remainder > 0 ?
                        s.malaCount + "+" + s.remainder : String.valueOf(s.malaCount);
            } else {
                malaStr = "-";
            }
            row.addView(makeDataCell(malaStr, 0.25f));

            card.addView(row);
        }

        // Total divider + total row
        card.addView(makeDivider());

        LinearLayout totalRow = new LinearLayout(context);
        totalRow.setOrientation(LinearLayout.HORIZONTAL);
        totalRow.setPadding(0, dp(8), 0, dp(4));

        TextView totalLabel = new TextView(context);
        totalLabel.setText(context.getString(R.string.analysis_total));
        totalLabel.setTextColor(0xFF4A9EFF);
        totalLabel.setTextSize(14);
        totalLabel.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        LinearLayout.LayoutParams tlp = new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 0.5f);
        totalLabel.setLayoutParams(tlp);
        totalRow.addView(totalLabel);

        totalRow.addView(makeTotalCell(String.valueOf(data.grandTotal), 0.25f));

        String totalMalaStr;
        if (data.grandMala > 0) {
            int rem = data.grandTotal % 108;
            totalMalaStr = rem > 0 ? data.grandMala + "+" + rem : String.valueOf(data.grandMala);
        } else {
            totalMalaStr = "-";
        }
        totalRow.addView(makeTotalCell(totalMalaStr, 0.25f));

        card.addView(totalRow);

        LinearLayout.LayoutParams cardLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        card.setLayoutParams(cardLp);

        return card;
    }

    private View buildSummaryCard(String label, int total) {
        LinearLayout card = new LinearLayout(context);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setGravity(Gravity.CENTER);
        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(16));
        bg.setColor(0xFF1C1C28);
        bg.setStroke(dp(1), 0xFF2A2A3A);
        card.setBackground(bg);
        int pad = dp(16);
        card.setPadding(pad, pad, pad, pad);

        TextView labelView = new TextView(context);
        labelView.setText(label);
        labelView.setTextColor(0xFF8888A0);
        labelView.setTextSize(13);
        labelView.setGravity(Gravity.CENTER);
        card.addView(labelView);

        TextView totalView = new TextView(context);
        totalView.setText(String.valueOf(total));
        totalView.setTextColor(0xFF4ADE80);
        totalView.setTextSize(28);
        totalView.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        totalView.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams tvLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        tvLp.topMargin = dp(4);
        totalView.setLayoutParams(tvLp);
        card.addView(totalView);

        int mala = total / 108;
        if (mala > 0) {
            int rem = total % 108;
            String malaStr = mala + " Mala" + (rem > 0 ? " + " + rem : "");
            TextView malaView = new TextView(context);
            malaView.setText(malaStr);
            malaView.setTextColor(0xFF555570);
            malaView.setTextSize(12);
            malaView.setGravity(Gravity.CENTER);
            LinearLayout.LayoutParams mlp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT);
            mlp.topMargin = dp(2);
            malaView.setLayoutParams(mlp);
            card.addView(malaView);
        }

        return card;
    }

    private TextView makeHeaderCell(String text, float weight) {
        TextView tv = new TextView(context);
        tv.setText(text);
        tv.setTextColor(0xFF555570);
        tv.setTextSize(11);
        tv.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, weight);
        tv.setLayoutParams(lp);
        if (weight < 0.5f) tv.setGravity(Gravity.CENTER);
        return tv;
    }

    private TextView makeDataCell(String text, float weight) {
        TextView tv = new TextView(context);
        tv.setText(text);
        tv.setTextColor(0xFFCCCCDD);
        tv.setTextSize(13);
        tv.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, weight);
        tv.setLayoutParams(lp);
        return tv;
    }

    private TextView makeTotalCell(String text, float weight) {
        TextView tv = new TextView(context);
        tv.setText(text);
        tv.setTextColor(0xFF4A9EFF);
        tv.setTextSize(14);
        tv.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        tv.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, weight);
        tv.setLayoutParams(lp);
        return tv;
    }

    private View makeDivider() {
        View div = new View(context);
        div.setBackgroundColor(0xFF222233);
        LinearLayout.LayoutParams dlp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(1));
        dlp.topMargin = dp(6);
        dlp.bottomMargin = dp(2);
        div.setLayoutParams(dlp);
        return div;
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

    private String shortenLabel(String name) {
        if (name == null) return "";
        if (name.length() <= 8) return name;
        return name.substring(0, 7) + "..";
    }

    private int dp(float val) {
        return (int) (val * context.getResources().getDisplayMetrics().density + 0.5f);
    }
}
