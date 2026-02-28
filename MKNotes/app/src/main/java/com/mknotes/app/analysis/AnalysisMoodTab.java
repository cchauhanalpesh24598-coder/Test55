package com.mknotes.app.analysis;

import android.content.Context;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.mknotes.app.R;
import com.mknotes.app.db.MoodRepository;
import com.mknotes.app.model.NoteMood;
import com.mknotes.app.mood.MoodBarChartView;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Builds the Mood tab content for Calendar Analysis.
 * Shows mood distribution summary cards + bar chart for intensity.
 * Week and Month mode with custom Canvas bar chart.
 * Pure Java, no lambda, no AndroidX, no external libraries.
 */
public class AnalysisMoodTab {

    private Context context;
    private MoodRepository moodRepo;

    public AnalysisMoodTab(Context context) {
        this.context = context;
        this.moodRepo = MoodRepository.getInstance(context);
    }

    // ============ DATE MODE ============

    /**
     * Build mood view for selected dates.
     */
    public View buildForDates(List dates) {
        if (dates == null || dates.isEmpty()) {
            return buildEmptyView();
        }

        LinearLayout container = new LinearLayout(context);
        container.setOrientation(LinearLayout.VERTICAL);
        container.setPadding(0, dp(4), 0, dp(4));

        // Summary card
        container.addView(buildDatesSummary(dates));

        // If single date or multiple, show week bar chart for context
        if (dates.size() == 1) {
            String date = (String) dates.get(0);
            container.addView(buildWeekChart(date));
        }

        // Mood entries list
        for (int i = 0; i < dates.size(); i++) {
            String date = (String) dates.get(i);
            List moods = moodRepo.getMoodsForDate(date);
            if (!moods.isEmpty()) {
                container.addView(buildDateMoodCards(date, moods));
            }
        }

        return container;
    }

    // ============ MONTH MODE ============

    public View buildForMonth(int year, int month) {
        LinearLayout container = new LinearLayout(context);
        container.setOrientation(LinearLayout.VERTICAL);
        container.setPadding(0, dp(4), 0, dp(4));

        // Month bar chart
        container.addView(buildMonthChart(year, month));

        // Month mood distribution
        String startDate = String.format(Locale.US, "%04d-%02d-01", year, month);
        Calendar cal = Calendar.getInstance();
        cal.set(year, month - 1, 1);
        int maxDay = cal.getActualMaximum(Calendar.DAY_OF_MONTH);
        String endDate = String.format(Locale.US, "%04d-%02d-%02d", year, month, maxDay);
        container.addView(buildDistributionCard(startDate, endDate));

        return container;
    }

    public View buildForMonths(List monthKeys) {
        LinearLayout container = new LinearLayout(context);
        container.setOrientation(LinearLayout.VERTICAL);
        container.setPadding(0, dp(4), 0, dp(4));

        for (int i = 0; i < monthKeys.size(); i++) {
            String key = (String) monthKeys.get(i);
            try {
                int year = Integer.parseInt(key.substring(0, 4));
                int month = Integer.parseInt(key.substring(5, 7));
                container.addView(buildMonthChart(year, month));
            } catch (Exception e) {
                // skip
            }
        }

        return container;
    }

    // ============ YEAR MODE ============

    public View buildForYear(int year) {
        LinearLayout container = new LinearLayout(context);
        container.setOrientation(LinearLayout.VERTICAL);
        container.setPadding(0, dp(4), 0, dp(4));

        // Monthly summary bar chart for the year
        container.addView(buildYearChart(year));

        String startDate = String.format(Locale.US, "%04d-01-01", year);
        String endDate = String.format(Locale.US, "%04d-12-31", year);
        container.addView(buildDistributionCard(startDate, endDate));

        return container;
    }

    public View buildForYears(List yearKeys) {
        LinearLayout container = new LinearLayout(context);
        container.setOrientation(LinearLayout.VERTICAL);
        container.setPadding(0, dp(4), 0, dp(4));

        for (int i = 0; i < yearKeys.size(); i++) {
            String key = (String) yearKeys.get(i);
            try {
                int year = Integer.parseInt(key);
                container.addView(buildYearChart(year));
            } catch (Exception e) {
                // skip
            }
        }

        return container;
    }

    // ============ CHART BUILDERS ============

    /**
     * Build a week bar chart showing 7 days with the selected date as center.
     */
    private View buildWeekChart(String dateYmd) {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
            Date date = sdf.parse(dateYmd);
            if (date == null) return buildEmptyView();

            Calendar cal = Calendar.getInstance();
            cal.setTime(date);
            // Go to Monday of the week
            int dow = cal.get(Calendar.DAY_OF_WEEK);
            int offset = (dow == Calendar.SUNDAY) ? -6 : (Calendar.MONDAY - dow);
            cal.add(Calendar.DAY_OF_MONTH, offset);

            String mondayDate = sdf.format(cal.getTime());
            float[] intensities = moodRepo.getWeekIntensities(mondayDate);
            String[] emojis = moodRepo.getWeekEmojis(mondayDate);

            String[] labels = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"};

            MoodBarChartView chart = new MoodBarChartView(context);
            chart.setData(intensities, emojis, labels, "Week Mood Intensity");
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, dp(260));
            lp.bottomMargin = dp(12);
            chart.setLayoutParams(lp);
            return chart;
        } catch (Exception e) {
            return buildEmptyView();
        }
    }

    /**
     * Build a month bar chart showing days 1-31.
     */
    private View buildMonthChart(int year, int month) {
        float[] intensities = moodRepo.getMonthIntensities(year, month);
        String[] emojis = moodRepo.getMonthEmojis(year, month);

        String[] labels = new String[intensities.length];
        for (int i = 0; i < labels.length; i++) {
            labels[i] = String.valueOf(i + 1);
        }

        String[] monthNames = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
        String chartTitle = monthNames[month - 1] + " " + year + " - Mood Intensity";

        // Wrap in HorizontalScrollView for month (can have 31 bars)
        HorizontalScrollView scroll = new HorizontalScrollView(context);
        scroll.setHorizontalScrollBarEnabled(false);
        LinearLayout.LayoutParams scrollLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(260));
        scrollLp.bottomMargin = dp(12);
        scroll.setLayoutParams(scrollLp);

        MoodBarChartView chart = new MoodBarChartView(context);
        chart.setMinBarSpacing(36);
        chart.setData(intensities, emojis, labels, chartTitle);
        scroll.addView(chart);

        return scroll;
    }

    /**
     * Build a year chart showing 12 months.
     */
    private View buildYearChart(int year) {
        float[] monthlyAvgs = new float[12];
        String[] monthEmojis = new String[12];
        String[] labels = {"J", "F", "M", "A", "M", "J", "J", "A", "S", "O", "N", "D"};

        for (int m = 1; m <= 12; m++) {
            float[] daily = moodRepo.getMonthIntensities(year, m);
            float sum = 0;
            int count = 0;
            for (int d = 0; d < daily.length; d++) {
                if (daily[d] > 0) {
                    sum += daily[d];
                    count++;
                }
            }
            monthlyAvgs[m - 1] = count > 0 ? sum / count : 0;

            // Get most common emoji for month (use first day that has data)
            String[] emojis = moodRepo.getMonthEmojis(year, m);
            monthEmojis[m - 1] = "";
            for (int d = 0; d < emojis.length; d++) {
                if (emojis[d] != null && emojis[d].length() > 0) {
                    monthEmojis[m - 1] = emojis[d];
                    break;
                }
            }
        }

        MoodBarChartView chart = new MoodBarChartView(context);
        chart.setData(monthlyAvgs, monthEmojis, labels, year + " - Monthly Mood");
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(260));
        lp.bottomMargin = dp(12);
        chart.setLayoutParams(lp);
        return chart;
    }

    // ============ SUMMARY BUILDERS ============

    private View buildDatesSummary(List dates) {
        LinearLayout card = new LinearLayout(context);
        card.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(14);
        card.setPadding(pad, pad, pad, pad);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(10);
        card.setLayoutParams(lp);

        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(14));
        bg.setColor(0xFF1C1C28);
        bg.setStroke(dp(1), 0xFF2A2A3A);
        card.setBackground(bg);

        // Title
        TextView title = new TextView(context);
        title.setText("Mood Summary");
        title.setTextSize(15);
        title.setTextColor(0xFFEAEAF0);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        title.setPadding(0, 0, 0, dp(8));
        card.addView(title);

        // Count moods across all dates
        int totalMoods = 0;
        float totalIntensity = 0;
        Map moodCounts = new HashMap(); // moodName -> count

        for (int i = 0; i < dates.size(); i++) {
            List moods = moodRepo.getMoodsForDate((String) dates.get(i));
            totalMoods += moods.size();
            for (int j = 0; j < moods.size(); j++) {
                NoteMood m = (NoteMood) moods.get(j);
                totalIntensity += m.getIntensityLevel();
                String name = m.getMoodName();
                Integer prev = (Integer) moodCounts.get(name);
                moodCounts.put(name, Integer.valueOf(prev != null ? prev.intValue() + 1 : 1));
            }
        }

        if (totalMoods == 0) {
            TextView noData = new TextView(context);
            noData.setText("No mood data for selected dates");
            noData.setTextSize(13);
            noData.setTextColor(0xFF555570);
            card.addView(noData);
            return card;
        }

        // Stats row
        LinearLayout statsRow = new LinearLayout(context);
        statsRow.setOrientation(LinearLayout.HORIZONTAL);
        statsRow.setGravity(Gravity.CENTER_VERTICAL);

        // Total moods
        statsRow.addView(buildStatChip("Total", String.valueOf(totalMoods), 0xFF4A9EFF));

        View spacer1 = new View(context);
        spacer1.setLayoutParams(new LinearLayout.LayoutParams(dp(8), dp(1)));
        statsRow.addView(spacer1);

        // Average intensity
        float avgIntensity = totalIntensity / totalMoods;
        int roundedAvg = Math.round(avgIntensity);
        if (roundedAvg < 1) roundedAvg = 1;
        if (roundedAvg > 5) roundedAvg = 5;
        String avgLabel = NoteMood.INTENSITY_LABELS[roundedAvg - 1];
        statsRow.addView(buildStatChip("Avg", avgLabel, NoteMood.INTENSITY_COLORS[roundedAvg - 1]));

        card.addView(statsRow);

        // Mood distribution
        if (!moodCounts.isEmpty()) {
            LinearLayout distRow = new LinearLayout(context);
            distRow.setOrientation(LinearLayout.HORIZONTAL);
            distRow.setGravity(Gravity.CENTER_VERTICAL);
            distRow.setPadding(0, dp(8), 0, 0);

            int count = 0;
            for (Object entry : moodCounts.entrySet()) {
                Map.Entry e = (Map.Entry) entry;
                String name = (String) e.getKey();
                int cnt = ((Integer) e.getValue()).intValue();
                String emoji = NoteMood.getEmojiForMood(name);

                if (count > 0) {
                    View sp = new View(context);
                    sp.setLayoutParams(new LinearLayout.LayoutParams(dp(6), dp(1)));
                    distRow.addView(sp);
                }

                TextView chip = new TextView(context);
                chip.setText(emoji + " " + cnt);
                chip.setTextSize(12);
                chip.setTextColor(0xFFEAEAF0);
                chip.setPadding(dp(8), dp(4), dp(8), dp(4));
                GradientDrawable chipBg = new GradientDrawable();
                chipBg.setCornerRadius(dp(8));
                chipBg.setColor(0xFF2A2A3A);
                chip.setBackground(chipBg);
                distRow.addView(chip);

                count++;
                if (count >= 6) break; // Max 6 chips
            }

            card.addView(distRow);
        }

        return card;
    }

    private View buildStatChip(String label, String value, int accentColor) {
        LinearLayout chip = new LinearLayout(context);
        chip.setOrientation(LinearLayout.VERTICAL);
        chip.setGravity(Gravity.CENTER);
        chip.setPadding(dp(14), dp(8), dp(14), dp(8));

        GradientDrawable chipBg = new GradientDrawable();
        chipBg.setCornerRadius(dp(10));
        chipBg.setColor((accentColor & 0x00FFFFFF) | 0x20000000);
        chip.setBackground(chipBg);

        TextView valueTv = new TextView(context);
        valueTv.setText(value);
        valueTv.setTextSize(16);
        valueTv.setTextColor(accentColor);
        valueTv.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        valueTv.setGravity(Gravity.CENTER);
        chip.addView(valueTv);

        TextView labelTv = new TextView(context);
        labelTv.setText(label);
        labelTv.setTextSize(10);
        labelTv.setTextColor(0xFF8888A0);
        labelTv.setGravity(Gravity.CENTER);
        chip.addView(labelTv);

        return chip;
    }

    private View buildDateMoodCards(String dateYmd, List moods) {
        LinearLayout card = new LinearLayout(context);
        card.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(12);
        card.setPadding(pad, pad, pad, pad);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(8);
        card.setLayoutParams(lp);

        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(12));
        bg.setColor(0xFF1C1C28);
        bg.setStroke(dp(1), 0xFF2A2A3A);
        card.setBackground(bg);

        // Date header
        TextView dateTv = new TextView(context);
        dateTv.setText(formatDateLabel(dateYmd));
        dateTv.setTextSize(12);
        dateTv.setTextColor(0xFF8888A0);
        dateTv.setPadding(0, 0, 0, dp(6));
        card.addView(dateTv);

        // Mood entries
        for (int i = 0; i < moods.size(); i++) {
            NoteMood mood = (NoteMood) moods.get(i);
            LinearLayout row = new LinearLayout(context);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(0, dp(3), 0, dp(3));

            // Emoji
            TextView emojiTv = new TextView(context);
            emojiTv.setText(mood.getEmojiUnicode());
            emojiTv.setTextSize(20);
            emojiTv.setPadding(0, 0, dp(10), 0);
            row.addView(emojiTv);

            // Name
            TextView nameTv = new TextView(context);
            nameTv.setText(mood.getMoodName());
            nameTv.setTextSize(14);
            nameTv.setTextColor(0xFFEAEAF0);
            nameTv.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL));
            LinearLayout.LayoutParams nameLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1);
            nameTv.setLayoutParams(nameLp);
            row.addView(nameTv);

            // Intensity badge
            TextView intensityTv = new TextView(context);
            intensityTv.setText(mood.getIntensityLabel());
            intensityTv.setTextSize(11);
            intensityTv.setTextColor(0xFFFFFFFF);
            intensityTv.setPadding(dp(8), dp(3), dp(8), dp(3));
            intensityTv.setGravity(Gravity.CENTER);
            GradientDrawable badgeBg = new GradientDrawable();
            badgeBg.setCornerRadius(dp(6));
            badgeBg.setColor(mood.getIntensityColor());
            intensityTv.setBackground(badgeBg);
            row.addView(intensityTv);

            card.addView(row);
        }

        return card;
    }

    private View buildDistributionCard(String startDate, String endDate) {
        Map distribution = moodRepo.getMoodDistribution(startDate, endDate);

        if (distribution.isEmpty()) {
            return buildEmptyView();
        }

        LinearLayout card = new LinearLayout(context);
        card.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(14);
        card.setPadding(pad, pad, pad, pad);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(10);
        card.setLayoutParams(lp);

        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(14));
        bg.setColor(0xFF1C1C28);
        bg.setStroke(dp(1), 0xFF2A2A3A);
        card.setBackground(bg);

        TextView title = new TextView(context);
        title.setText("Mood Distribution");
        title.setTextSize(15);
        title.setTextColor(0xFFEAEAF0);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        title.setPadding(0, 0, 0, dp(8));
        card.addView(title);

        // Find max count for proportional bars
        int maxCount = 1;
        for (Object entry : distribution.entrySet()) {
            int cnt = ((Integer) ((Map.Entry) entry).getValue()).intValue();
            if (cnt > maxCount) maxCount = cnt;
        }

        for (Object entry : distribution.entrySet()) {
            Map.Entry e = (Map.Entry) entry;
            String name = (String) e.getKey();
            int count = ((Integer) e.getValue()).intValue();
            String emoji = NoteMood.getEmojiForMood(name);

            LinearLayout row = new LinearLayout(context);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(0, dp(4), 0, dp(4));

            // Emoji + name
            TextView labelTv = new TextView(context);
            labelTv.setText(emoji + " " + name);
            labelTv.setTextSize(13);
            labelTv.setTextColor(0xFFEAEAF0);
            labelTv.setWidth(dp(100));
            row.addView(labelTv);

            // Progress bar
            LinearLayout barContainer = new LinearLayout(context);
            LinearLayout.LayoutParams barContLp = new LinearLayout.LayoutParams(0, dp(12), 1);
            barContLp.leftMargin = dp(8);
            barContLp.rightMargin = dp(8);
            barContainer.setLayoutParams(barContLp);

            GradientDrawable barContBg = new GradientDrawable();
            barContBg.setCornerRadius(dp(6));
            barContBg.setColor(0xFF2A2A3A);
            barContainer.setBackground(barContBg);

            View bar = new View(context);
            float ratio = (float) count / maxCount;
            LinearLayout.LayoutParams barLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT);
            barLp.weight = ratio;
            bar.setLayoutParams(barLp);
            GradientDrawable barBg = new GradientDrawable();
            barBg.setCornerRadius(dp(6));
            barBg.setColor(0xFF4A9EFF);
            bar.setBackground(barBg);
            barContainer.addView(bar);

            // Empty fill
            View empty = new View(context);
            LinearLayout.LayoutParams emptyLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT);
            emptyLp.weight = 1f - ratio;
            empty.setLayoutParams(emptyLp);
            barContainer.addView(empty);

            row.addView(barContainer);

            // Count
            TextView countTv = new TextView(context);
            countTv.setText(String.valueOf(count));
            countTv.setTextSize(12);
            countTv.setTextColor(0xFF8888A0);
            countTv.setWidth(dp(28));
            countTv.setGravity(Gravity.RIGHT);
            row.addView(countTv);

            card.addView(row);
        }

        return card;
    }

    // ============ UTILITY ============

    private View buildEmptyView() {
        TextView empty = new TextView(context);
        empty.setText("No mood data available");
        empty.setTextSize(14);
        empty.setTextColor(0xFF555570);
        empty.setGravity(Gravity.CENTER);
        empty.setPadding(dp(16), dp(40), dp(16), dp(40));
        return empty;
    }

    private String formatDateLabel(String dateYmd) {
        try {
            int day = Integer.parseInt(dateYmd.substring(8, 10));
            int month = Integer.parseInt(dateYmd.substring(5, 7));
            String[] months = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
            return day + " " + months[month - 1];
        } catch (Exception e) {
            return dateYmd;
        }
    }

    private int dp(float val) {
        return (int) (val * context.getResources().getDisplayMetrics().density + 0.5f);
    }
}
