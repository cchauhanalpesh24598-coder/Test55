package com.mknotes.app.analysis;

import android.app.Activity;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.HorizontalScrollView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.mknotes.app.R;
import com.mknotes.app.MasterPasswordActivity;
import com.mknotes.app.db.MoodRepository;
import com.mknotes.app.model.NoteMood;
import com.mknotes.app.mood.MoodBarChartView;
import com.mknotes.app.util.SessionManager;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Calendar Analysis Activity.
 * Provides time-based analysis of Notes, Routine, and Meditation data.
 * Always multi-select. Tap = toggle. Done = render.
 * Supports 3 modes (Date/Month/Year) with independent selection memory.
 * Pure Java, no AndroidX, no lambda, no external libraries.
 */
public class CalendarAnalysisActivity extends Activity {

    // Views
    private FrameLayout calendarContainer;
    private FrameLayout contentArea;
    private LinearLayout tabBar;
    private LinearLayout emptyState;
    private TextView emptyText;
    private ScrollView mainScroller;

    // Mode pills
    private TextView modeDate, modeMonth, modeYear;

    // Tabs
    private TextView tabNotes, tabRoutine, tabMeditation, tabMood, tabAll;

    // Selection controls
    private LinearLayout selectionControls;
    private TextView selectionCountLabel;
    private TextView btnClearAll;
    private TextView btnDone;
    private HorizontalScrollView chipsScrollView;
    private LinearLayout chipsContainer;

    // Calendar
    private AnalysisCalendarView calendarView;

    // Tab builders
    private AnalysisNotesTab notesTab;
    private AnalysisRoutineTab routineTab;
    private AnalysisMeditationTab meditationTab;
    private AnalysisMoodTab moodTab;
    private AnalysisAllTab allTab;

    // Mood mode switch and graph
    private LinearLayout moodSwitchContainer;
    private TextView moodSwitchLabel;
    private View moodSwitchTrack;
    private View moodSwitchThumb;
    private boolean moodModeOn = false;

    // Mood graph section (below calendar)
    private LinearLayout moodGraphSection;
    private TextView graphToggleWeek;
    private TextView graphToggleMonth;
    private FrameLayout graphContainer;
    private boolean isWeekGraph = true; // true=week, false=month

    private MoodRepository moodRepo;

    // State
    private int currentMode = AnalysisCalendarView.MODE_DATE;
    private int currentTab = 0; // 0=Notes, 1=Routine, 2=Meditation, 3=All

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        setContentView(R.layout.activity_calendar_analysis);

        // Status bar color
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
        getWindow().setStatusBarColor(0xFF0D0D12);

        moodRepo = MoodRepository.getInstance(this);

        initViews();
        initTabBuilders();
        initCalendar();
        initMoodSwitch();
        initMoodGraphSection();
        initListeners();
        updateSelectionUI();
    }

    protected void onResume() {
        super.onResume();
        // Refresh content if something was edited and we have content showing
        if (tabBar.getVisibility() == View.VISIBLE && hasSelection()) {
            refreshContent();
        }
    }

    private void initViews() {
        calendarContainer = (FrameLayout) findViewById(R.id.calendarContainer);
        contentArea = (FrameLayout) findViewById(R.id.contentArea);
        tabBar = (LinearLayout) findViewById(R.id.tabBar);
        emptyState = (LinearLayout) findViewById(R.id.emptyState);
        emptyText = (TextView) findViewById(R.id.emptyText);
        mainScroller = (ScrollView) findViewById(R.id.mainScroller);

        modeDate = (TextView) findViewById(R.id.modeDate);
        modeMonth = (TextView) findViewById(R.id.modeMonth);
        modeYear = (TextView) findViewById(R.id.modeYear);

        tabNotes = (TextView) findViewById(R.id.tabNotes);
        tabRoutine = (TextView) findViewById(R.id.tabRoutine);
        tabMeditation = (TextView) findViewById(R.id.tabMeditation);
        tabMood = (TextView) findViewById(R.id.tabMood);
        tabAll = (TextView) findViewById(R.id.tabAll);

        selectionControls = (LinearLayout) findViewById(R.id.selectionControls);
        selectionCountLabel = (TextView) findViewById(R.id.selectionCountLabel);
        btnClearAll = (TextView) findViewById(R.id.btnClearAll);
        btnDone = (TextView) findViewById(R.id.btnDone);
        chipsScrollView = (HorizontalScrollView) findViewById(R.id.chipsScrollView);
        chipsContainer = (LinearLayout) findViewById(R.id.chipsContainer);
    }

    private void initTabBuilders() {
        notesTab = new AnalysisNotesTab(this);
        routineTab = new AnalysisRoutineTab(this);
        meditationTab = new AnalysisMeditationTab(this);
        moodTab = new AnalysisMoodTab(this);
        allTab = new AnalysisAllTab(this);
    }

    private void initCalendar() {
        calendarView = new AnalysisCalendarView(this);
        calendarContainer.addView(calendarView);

        calendarView.setOnSelectionChangedListener(new AnalysisCalendarView.OnSelectionChangedListener() {
            public void onSelectionChanged(int count) {
                updateSelectionUI();
            }

            public void onSelectionLimitReached(int maxAllowed) {
                String msg;
                if (currentMode == AnalysisCalendarView.MODE_DATE) {
                    msg = String.format(getString(R.string.analysis_max_dates), maxAllowed);
                } else if (currentMode == AnalysisCalendarView.MODE_MONTH) {
                    msg = String.format(getString(R.string.analysis_max_months), maxAllowed);
                } else {
                    msg = String.format(getString(R.string.analysis_max_years), maxAllowed);
                }
                Toast.makeText(CalendarAnalysisActivity.this, msg, Toast.LENGTH_SHORT).show();
            }
        });

        calendarView.setOnNavigateListener(new AnalysisCalendarView.OnNavigateListener() {
            public void onCalendarNavigated() {
                if (moodModeOn) {
                    loadMoodEmojisForDisplayedMonth();
                }
            }
        });
    }

    private void initListeners() {
        // Back button
        findViewById(R.id.btnBack).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                finish();
            }
        });

        // Mode pills
        modeDate.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                setMode(AnalysisCalendarView.MODE_DATE);
            }
        });
        modeMonth.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                setMode(AnalysisCalendarView.MODE_MONTH);
            }
        });
        modeYear.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                setMode(AnalysisCalendarView.MODE_YEAR);
            }
        });

        // Tabs
        tabNotes.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                selectTab(0);
            }
        });
        tabRoutine.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                selectTab(1);
            }
        });
        tabMeditation.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                selectTab(2);
            }
        });
        tabMood.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                selectTab(3);
            }
        });
        tabAll.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                selectTab(4);
            }
        });

        // Done button
        btnDone.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                onDonePressed();
            }
        });

        // Clear All button
        btnClearAll.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                calendarView.clearCurrentModeSelection();
                hideContent();
                updateSelectionUI();
            }
        });
    }

    // ============ MOOD MODE SWITCH ============

    /**
     * Build the mood mode toggle switch programmatically.
     * Inserted into the layout between the calendar and selection controls.
     */
    private void initMoodSwitch() {
        // Create container
        moodSwitchContainer = new LinearLayout(this);
        moodSwitchContainer.setOrientation(LinearLayout.HORIZONTAL);
        moodSwitchContainer.setGravity(Gravity.CENTER_VERTICAL);
        moodSwitchContainer.setPadding(dpPx(16), dpPx(6), dpPx(16), dpPx(6));

        // Label
        moodSwitchLabel = new TextView(this);
        moodSwitchLabel.setText("Mood Mode");
        moodSwitchLabel.setTextSize(13);
        moodSwitchLabel.setTextColor(0xFFBBBBCC);
        moodSwitchLabel.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        moodSwitchContainer.addView(moodSwitchLabel);

        View spacer = new View(this);
        spacer.setLayoutParams(new LinearLayout.LayoutParams(0, dpPx(1), 1));
        moodSwitchContainer.addView(spacer);

        // Custom toggle track+thumb
        final FrameLayout toggle = new FrameLayout(this);
        LinearLayout.LayoutParams toggleLp = new LinearLayout.LayoutParams(dpPx(44), dpPx(24));
        toggle.setLayoutParams(toggleLp);

        moodSwitchTrack = new View(this);
        FrameLayout.LayoutParams trackLp = new FrameLayout.LayoutParams(dpPx(44), dpPx(24));
        moodSwitchTrack.setLayoutParams(trackLp);
        GradientDrawable trackBg = new GradientDrawable();
        trackBg.setCornerRadius(dpPx(12));
        trackBg.setColor(0xFF333348);
        moodSwitchTrack.setBackground(trackBg);
        toggle.addView(moodSwitchTrack);

        moodSwitchThumb = new View(this);
        FrameLayout.LayoutParams thumbLp = new FrameLayout.LayoutParams(dpPx(20), dpPx(20));
        thumbLp.leftMargin = dpPx(2);
        thumbLp.topMargin = dpPx(2);
        moodSwitchThumb.setLayoutParams(thumbLp);
        GradientDrawable thumbBg = new GradientDrawable();
        thumbBg.setShape(GradientDrawable.OVAL);
        thumbBg.setColor(0xFF888899);
        moodSwitchThumb.setBackground(thumbBg);
        toggle.addView(moodSwitchThumb);

        toggle.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                moodModeOn = !moodModeOn;
                updateMoodSwitchUI();
                calendarView.setMoodModeEnabled(moodModeOn);
                if (moodModeOn) {
                    loadMoodEmojisForDisplayedMonth();
                    moodGraphSection.setVisibility(View.VISIBLE);
                    refreshMoodGraph();
                } else {
                    calendarView.setMoodEmojiMap(null);
                    moodGraphSection.setVisibility(View.GONE);
                }
            }
        });

        moodSwitchContainer.addView(toggle);

        // Insert between calendar container and selection controls in the scrollable content
        ScrollView scroller = (ScrollView) findViewById(R.id.mainScroller);
        if (scroller != null && scroller.getChildCount() > 0) {
            LinearLayout scrollContent = (LinearLayout) scroller.getChildAt(0);
            // Find calendarContainer's index and insert after it
            int calIdx = -1;
            for (int i = 0; i < scrollContent.getChildCount(); i++) {
                if (scrollContent.getChildAt(i) == calendarContainer) {
                    calIdx = i;
                    break;
                }
            }
            if (calIdx >= 0) {
                scrollContent.addView(moodSwitchContainer, calIdx + 1);
            }
        }
    }

    private void updateMoodSwitchUI() {
        if (moodModeOn) {
            GradientDrawable trackOn = new GradientDrawable();
            trackOn.setCornerRadius(dpPx(12));
            trackOn.setColor(0xFF4A9EFF);
            moodSwitchTrack.setBackground(trackOn);

            FrameLayout.LayoutParams thumbLp = (FrameLayout.LayoutParams) moodSwitchThumb.getLayoutParams();
            thumbLp.leftMargin = dpPx(22);
            moodSwitchThumb.setLayoutParams(thumbLp);
            GradientDrawable thumbOn = new GradientDrawable();
            thumbOn.setShape(GradientDrawable.OVAL);
            thumbOn.setColor(0xFFFFFFFF);
            moodSwitchThumb.setBackground(thumbOn);
        } else {
            GradientDrawable trackOff = new GradientDrawable();
            trackOff.setCornerRadius(dpPx(12));
            trackOff.setColor(0xFF333348);
            moodSwitchTrack.setBackground(trackOff);

            FrameLayout.LayoutParams thumbLp = (FrameLayout.LayoutParams) moodSwitchThumb.getLayoutParams();
            thumbLp.leftMargin = dpPx(2);
            moodSwitchThumb.setLayoutParams(thumbLp);
            GradientDrawable thumbOff = new GradientDrawable();
            thumbOff.setShape(GradientDrawable.OVAL);
            thumbOff.setColor(0xFF888899);
            moodSwitchThumb.setBackground(thumbOff);
        }
    }

    private void loadMoodEmojisForDisplayedMonth() {
        int month = calendarView.getDisplayMonth() + 1; // 0-indexed to 1-indexed
        int year = calendarView.getDisplayYear();

        Calendar cal = Calendar.getInstance();
        cal.set(year, month - 1, 1);
        int maxDay = cal.getActualMaximum(Calendar.DAY_OF_MONTH);

        Map emojiMap = new HashMap();
        for (int d = 1; d <= maxDay; d++) {
            String dateStr = String.format(Locale.US, "%04d-%02d-%02d", year, month, d);
            NoteMood primary = moodRepo.getPrimaryMoodForDate(dateStr);
            if (primary != null && primary.getEmojiUnicode() != null && primary.getEmojiUnicode().length() > 0) {
                emojiMap.put(dateStr, primary.getEmojiUnicode());
            }
        }
        calendarView.setMoodEmojiMap(emojiMap);
    }

    // ============ MOOD GRAPH SECTION ============

    private void initMoodGraphSection() {
        moodGraphSection = new LinearLayout(this);
        moodGraphSection.setOrientation(LinearLayout.VERTICAL);
        moodGraphSection.setPadding(dpPx(12), dpPx(4), dpPx(12), dpPx(8));
        moodGraphSection.setVisibility(View.GONE); // Hidden by default

        // Week/Month toggle row
        LinearLayout toggleRow = new LinearLayout(this);
        toggleRow.setOrientation(LinearLayout.HORIZONTAL);
        toggleRow.setGravity(Gravity.CENTER);
        toggleRow.setPadding(dpPx(4), dpPx(4), dpPx(4), dpPx(8));

        graphToggleWeek = new TextView(this);
        graphToggleWeek.setText("Week");
        graphToggleWeek.setTextSize(13);
        graphToggleWeek.setGravity(Gravity.CENTER);
        graphToggleWeek.setPadding(dpPx(20), dpPx(6), dpPx(20), dpPx(6));
        LinearLayout.LayoutParams weekLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1);
        weekLp.rightMargin = dpPx(4);
        graphToggleWeek.setLayoutParams(weekLp);
        toggleRow.addView(graphToggleWeek);

        graphToggleMonth = new TextView(this);
        graphToggleMonth.setText("Month");
        graphToggleMonth.setTextSize(13);
        graphToggleMonth.setGravity(Gravity.CENTER);
        graphToggleMonth.setPadding(dpPx(20), dpPx(6), dpPx(20), dpPx(6));
        LinearLayout.LayoutParams monthLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1);
        graphToggleMonth.setLayoutParams(monthLp);
        toggleRow.addView(graphToggleMonth);

        moodGraphSection.addView(toggleRow);

        // Graph container
        graphContainer = new FrameLayout(this);
        LinearLayout.LayoutParams graphLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dpPx(200));
        graphContainer.setLayoutParams(graphLp);
        moodGraphSection.addView(graphContainer);

        // Style toggles
        updateGraphToggleUI();

        // Toggle listeners
        graphToggleWeek.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                isWeekGraph = true;
                updateGraphToggleUI();
                refreshMoodGraph();
            }
        });
        graphToggleMonth.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                isWeekGraph = false;
                updateGraphToggleUI();
                refreshMoodGraph();
            }
        });

        // Insert after mood switch in the scrollable content
        ScrollView scroller = (ScrollView) findViewById(R.id.mainScroller);
        if (scroller != null && scroller.getChildCount() > 0) {
            LinearLayout scrollContent = (LinearLayout) scroller.getChildAt(0);
            int switchIdx = -1;
            for (int i = 0; i < scrollContent.getChildCount(); i++) {
                if (scrollContent.getChildAt(i) == moodSwitchContainer) {
                    switchIdx = i;
                    break;
                }
            }
            if (switchIdx >= 0) {
                scrollContent.addView(moodGraphSection, switchIdx + 1);
            }
        }
    }

    private void updateGraphToggleUI() {
        if (isWeekGraph) {
            GradientDrawable weekBg = new GradientDrawable();
            weekBg.setCornerRadius(dpPx(10));
            weekBg.setColor(0xFF4A9EFF);
            graphToggleWeek.setBackground(weekBg);
            graphToggleWeek.setTextColor(0xFFFFFFFF);
            graphToggleWeek.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));

            GradientDrawable monthBg = new GradientDrawable();
            monthBg.setCornerRadius(dpPx(10));
            monthBg.setColor(0xFF1C1C28);
            graphToggleMonth.setBackground(monthBg);
            graphToggleMonth.setTextColor(0xFF8888A0);
            graphToggleMonth.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL));
        } else {
            GradientDrawable monthBg = new GradientDrawable();
            monthBg.setCornerRadius(dpPx(10));
            monthBg.setColor(0xFF4A9EFF);
            graphToggleMonth.setBackground(monthBg);
            graphToggleMonth.setTextColor(0xFFFFFFFF);
            graphToggleMonth.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));

            GradientDrawable weekBg = new GradientDrawable();
            weekBg.setCornerRadius(dpPx(10));
            weekBg.setColor(0xFF1C1C28);
            graphToggleWeek.setBackground(weekBg);
            graphToggleWeek.setTextColor(0xFF8888A0);
            graphToggleWeek.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL));
        }
    }

    private void refreshMoodGraph() {
        graphContainer.removeAllViews();

        if (isWeekGraph) {
            // Get start of current week (Monday)
            Calendar cal = Calendar.getInstance();
            cal.set(Calendar.DAY_OF_WEEK, Calendar.MONDAY);
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
            String startDate = sdf.format(cal.getTime());

            float[] intensities = moodRepo.getWeekIntensities(startDate);
            String[] emojis = moodRepo.getWeekEmojis(startDate);
            String[] labels = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"};

            MoodBarChartView chart = new MoodBarChartView(this);
            chart.setData(intensities, emojis, labels, "Week Mood Intensity");
            LinearLayout.LayoutParams chartLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, dpPx(220));
            chart.setLayoutParams(chartLp);
            graphContainer.addView(chart);
        } else {
            // Month graph
            int month = calendarView.getDisplayMonth() + 1;
            int year = calendarView.getDisplayYear();

            float[] intensities = moodRepo.getMonthIntensities(year, month);
            String[] emojis = moodRepo.getMonthEmojis(year, month);

            // Create day labels (1, 2, 3, ...)
            String[] labels = new String[intensities.length];
            for (int i = 0; i < labels.length; i++) {
                labels[i] = String.valueOf(i + 1);
            }

            String[] monthNames = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
            String chartTitle = monthNames[month - 1] + " " + year + " - Mood Intensity";

            MoodBarChartView chart = new MoodBarChartView(this);
            chart.setMinBarSpacing(36);
            chart.setData(intensities, emojis, labels, chartTitle);
            LinearLayout.LayoutParams chartLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, dpPx(220));
            chart.setLayoutParams(chartLp);
            graphContainer.addView(chart);
        }
    }

    // ============ MODE MANAGEMENT ============

    private void setMode(int mode) {
        currentMode = mode;
        calendarView.setMode(mode);
        updateModePills();
        hideContent();
        updateSelectionUI();

        // Mood mode: only available in DATE mode
        if (moodSwitchContainer != null) {
            moodSwitchContainer.setVisibility(mode == AnalysisCalendarView.MODE_DATE ? View.VISIBLE : View.GONE);
        }
        if (mode != AnalysisCalendarView.MODE_DATE && moodModeOn) {
            // Turn off mood mode when switching to month/year mode
            moodModeOn = false;
            updateMoodSwitchUI();
            calendarView.setMoodModeEnabled(false);
            calendarView.setMoodEmojiMap(null);
            if (moodGraphSection != null) {
                moodGraphSection.setVisibility(View.GONE);
            }
        }
        if (moodModeOn && mode == AnalysisCalendarView.MODE_DATE) {
            loadMoodEmojisForDisplayedMonth();
        }
    }

    private void updateModePills() {
        // Reset all
        modeDate.setBackgroundResource(R.drawable.bg_analysis_mode_pill);
        modeDate.setTextColor(getResources().getColor(R.color.analysis_tab_text));
        modeMonth.setBackgroundResource(R.drawable.bg_analysis_mode_pill);
        modeMonth.setTextColor(getResources().getColor(R.color.analysis_tab_text));
        modeYear.setBackgroundResource(R.drawable.bg_analysis_mode_pill);
        modeYear.setTextColor(getResources().getColor(R.color.analysis_tab_text));

        // Highlight active
        TextView active;
        if (currentMode == AnalysisCalendarView.MODE_MONTH) {
            active = modeMonth;
        } else if (currentMode == AnalysisCalendarView.MODE_YEAR) {
            active = modeYear;
        } else {
            active = modeDate;
        }
        active.setBackgroundResource(R.drawable.bg_analysis_mode_selected);
        active.setTextColor(getResources().getColor(R.color.analysis_tab_text_selected));
    }

    // ============ SELECTION UI ============

    private void updateSelectionUI() {
        int count = calendarView.getCurrentSelectionCount();
        int max = calendarView.getCurrentMaxSelection();

        // Update count label
        selectionCountLabel.setText(String.format(getString(R.string.analysis_selected_count), count, max));

        // Show/hide Clear All
        btnClearAll.setVisibility(count > 1 ? View.VISIBLE : View.GONE);

        // Build chips
        buildChips();
    }

    private void buildChips() {
        chipsContainer.removeAllViews();

        List keys;
        if (currentMode == AnalysisCalendarView.MODE_DATE) {
            keys = calendarView.getSelectedDates();
            Collections.sort(keys);
        } else if (currentMode == AnalysisCalendarView.MODE_MONTH) {
            keys = calendarView.getSelectedMonthKeys();
            Collections.sort(keys);
        } else {
            keys = calendarView.getSelectedYearKeys();
            Collections.sort(keys);
        }

        if (keys.isEmpty()) {
            chipsScrollView.setVisibility(View.GONE);
            return;
        }

        chipsScrollView.setVisibility(View.VISIBLE);

        for (int i = 0; i < keys.size(); i++) {
            final String key = (String) keys.get(i);
            String label = formatChipLabel(key);
            View chip = buildChipView(label, key);

            if (i > 0) {
                // Add spacing between chips
                LinearLayout.LayoutParams spacer = new LinearLayout.LayoutParams(dpPx(6), dpPx(1));
                View space = new View(this);
                space.setLayoutParams(spacer);
                chipsContainer.addView(space);
            }

            chipsContainer.addView(chip);
        }
    }

    private View buildChipView(String label, final String key) {
        // Chip container
        LinearLayout chip = new LinearLayout(this);
        chip.setOrientation(LinearLayout.HORIZONTAL);
        chip.setGravity(Gravity.CENTER_VERTICAL);
        chip.setBackgroundResource(R.drawable.bg_analysis_chip);
        LinearLayout.LayoutParams chipLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, dpPx(32));
        chip.setLayoutParams(chipLp);
        chip.setPadding(dpPx(10), 0, dpPx(4), 0);

        // Chip text
        TextView text = new TextView(this);
        text.setText(label);
        text.setTextColor(0xFFEAEAF0);
        text.setTextSize(12);
        text.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        text.setSingleLine(true);
        chip.addView(text);

        // Close button
        TextView close = new TextView(this);
        close.setText("x");
        close.setTextColor(0xFF8888A0);
        close.setTextSize(11);
        close.setTypeface(Typeface.DEFAULT_BOLD);
        close.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams closeLp = new LinearLayout.LayoutParams(dpPx(22), dpPx(22));
        closeLp.leftMargin = dpPx(4);
        close.setLayoutParams(closeLp);
        close.setBackgroundResource(R.drawable.bg_analysis_chip_close);
        close.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                calendarView.removeSelection(key);
                updateSelectionUI();
                // If content was showing and we removed last selection, hide content
                if (calendarView.getCurrentSelectionCount() == 0) {
                    hideContent();
                }
            }
        });
        chip.addView(close);

        return chip;
    }

    private String formatChipLabel(String key) {
        if (currentMode == AnalysisCalendarView.MODE_DATE) {
            // "yyyy-MM-dd" -> "15 Jan"
            try {
                int day = Integer.parseInt(key.substring(8, 10));
                int month = Integer.parseInt(key.substring(5, 7));
                String[] months = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
                return day + " " + months[month - 1];
            } catch (Exception e) {
                return key;
            }
        } else if (currentMode == AnalysisCalendarView.MODE_MONTH) {
            // "yyyy-MM" -> "Jan 2026"
            try {
                int year = Integer.parseInt(key.substring(0, 4));
                int month = Integer.parseInt(key.substring(5, 7));
                String[] months = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
                return months[month - 1] + " " + year;
            } catch (Exception e) {
                return key;
            }
        } else {
            // Year mode, key is just "yyyy"
            return key;
        }
    }

    // ============ DONE BUTTON ============

    private void onDonePressed() {
        int count = calendarView.getCurrentSelectionCount();
        if (count == 0) {
            String modeLabel;
            if (currentMode == AnalysisCalendarView.MODE_DATE) {
                modeLabel = "date";
            } else if (currentMode == AnalysisCalendarView.MODE_MONTH) {
                modeLabel = "month";
            } else {
                modeLabel = "year";
            }
            String msg = String.format(getString(R.string.analysis_select_at_least_one), modeLabel);
            Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
            return;
        }
        showTabsAndContent();
    }

    // ============ TAB MANAGEMENT ============

    private void selectTab(int tab) {
        currentTab = tab;
        updateTabUI();
        refreshContent();
    }

    private void updateTabUI() {
        // Reset all tabs
        tabNotes.setBackgroundResource(R.drawable.bg_analysis_tab);
        tabNotes.setTextColor(getResources().getColor(R.color.analysis_tab_text));
        tabRoutine.setBackgroundResource(R.drawable.bg_analysis_tab);
        tabRoutine.setTextColor(getResources().getColor(R.color.analysis_tab_text));
        tabMeditation.setBackgroundResource(R.drawable.bg_analysis_tab);
        tabMeditation.setTextColor(getResources().getColor(R.color.analysis_tab_text));
        tabMood.setBackgroundResource(R.drawable.bg_analysis_tab);
        tabMood.setTextColor(getResources().getColor(R.color.analysis_tab_text));
        tabAll.setBackgroundResource(R.drawable.bg_analysis_tab);
        tabAll.setTextColor(getResources().getColor(R.color.analysis_tab_text));

        // Highlight active tab
        TextView active;
        switch (currentTab) {
            case 1:
                active = tabRoutine;
                break;
            case 2:
                active = tabMeditation;
                break;
            case 3:
                active = tabMood;
                break;
            case 4:
                active = tabAll;
                break;
            default:
                active = tabNotes;
                break;
        }
        active.setBackgroundResource(R.drawable.bg_analysis_tab_selected);
        active.setTextColor(getResources().getColor(R.color.analysis_tab_text_selected));
    }

    // ============ CONTENT ============

    private void showTabsAndContent() {
        tabBar.setVisibility(View.VISIBLE);
        emptyState.setVisibility(View.GONE);
        selectTab(currentTab);
    }

    private void hideContent() {
        tabBar.setVisibility(View.GONE);
        contentArea.removeAllViews();
        emptyState.setVisibility(View.VISIBLE);
        emptyText.setText(getString(R.string.analysis_select_date));
    }

    private boolean hasSelection() {
        return calendarView.getCurrentSelectionCount() > 0;
    }

    private void refreshContent() {
        contentArea.removeAllViews();

        View content = null;

        if (currentMode == AnalysisCalendarView.MODE_DATE) {
            List dates = calendarView.getSelectedDates();
            if (dates.isEmpty()) {
                hideContent();
                return;
            }
            content = buildDateContent(dates);
        } else if (currentMode == AnalysisCalendarView.MODE_MONTH) {
            List monthKeys = calendarView.getSelectedMonthKeys();
            if (monthKeys.isEmpty()) {
                hideContent();
                return;
            }
            if (monthKeys.size() == 1) {
                // Single month -> single month content
                String key = (String) monthKeys.get(0);
                try {
                    int year = Integer.parseInt(key.substring(0, 4));
                    int month = Integer.parseInt(key.substring(5, 7));
                    content = buildMonthContent(year, month);
                } catch (Exception e) {
                    hideContent();
                    return;
                }
            } else {
                content = buildMultiMonthContent(monthKeys);
            }
        } else {
            List yearKeys = calendarView.getSelectedYearKeys();
            if (yearKeys.isEmpty()) {
                hideContent();
                return;
            }
            if (yearKeys.size() == 1) {
                // Single year -> single year content
                String key = (String) yearKeys.get(0);
                try {
                    int year = Integer.parseInt(key);
                    content = buildYearContent(year);
                } catch (Exception e) {
                    hideContent();
                    return;
                }
            } else {
                content = buildMultiYearContent(yearKeys);
            }
        }

        if (content != null) {
            contentArea.addView(content);
            emptyState.setVisibility(View.GONE);
        }
    }

    // ============ CONTENT BUILDERS BY MODE ============

    private View buildDateContent(List dates) {
        switch (currentTab) {
            case 0:
                return notesTab.buildForDates(dates);
            case 1:
                return routineTab.buildForDates(dates);
            case 2:
                return meditationTab.buildForDates(dates);
            case 3:
                return moodTab.buildForDates(dates);
            case 4:
                return allTab.buildForDates(dates);
            default:
                return notesTab.buildForDates(dates);
        }
    }

    private View buildMonthContent(int year, int month) {
        switch (currentTab) {
            case 0:
                return notesTab.buildForMonth(year, month);
            case 1:
                return routineTab.buildForMonth(year, month);
            case 2:
                return meditationTab.buildForMonth(year, month);
            case 3:
                return moodTab.buildForMonth(year, month);
            case 4:
                return allTab.buildForMonth(year, month);
            default:
                return notesTab.buildForMonth(year, month);
        }
    }

    private View buildMultiMonthContent(List monthKeys) {
        switch (currentTab) {
            case 0:
                return notesTab.buildForMonths(monthKeys);
            case 1:
                return routineTab.buildForMonths(monthKeys);
            case 2:
                return meditationTab.buildForMonths(monthKeys);
            case 3:
                return moodTab.buildForMonths(monthKeys);
            case 4:
                return allTab.buildForMonths(monthKeys);
            default:
                return notesTab.buildForMonths(monthKeys);
        }
    }

    private View buildYearContent(int year) {
        switch (currentTab) {
            case 0:
                return notesTab.buildForYear(year);
            case 1:
                return routineTab.buildForYear(year);
            case 2:
                return meditationTab.buildForYear(year);
            case 3:
                return moodTab.buildForYear(year);
            case 4:
                return allTab.buildForYear(year);
            default:
                return notesTab.buildForYear(year);
        }
    }

    private View buildMultiYearContent(List yearKeys) {
        switch (currentTab) {
            case 0:
                return notesTab.buildForYears(yearKeys);
            case 1:
                return routineTab.buildForYears(yearKeys);
            case 2:
                return meditationTab.buildForYears(yearKeys);
            case 3:
                return moodTab.buildForYears(yearKeys);
            case 4:
                return allTab.buildForYears(yearKeys);
            default:
                return notesTab.buildForYears(yearKeys);
        }
    }

    // ============ UTILITY ============

    private int dpPx(int dp) {
        return (int) (dp * getResources().getDisplayMetrics().density + 0.5f);
    }
}
