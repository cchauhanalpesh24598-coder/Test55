package com.mknotes.app.analysis;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Custom Calendar View for Calendar Analysis.
 * Supports 3 modes: DATE, MONTH, YEAR.
 * Always multi-select in all modes. Tap = toggle selection.
 * Each mode maintains independent selection memory.
 * Supports Mood Mode overlay: shows emoji instead of date numbers when enabled.
 */
public class AnalysisCalendarView extends View {

    public static final int MODE_DATE = 0;
    public static final int MODE_MONTH = 1;
    public static final int MODE_YEAR = 2;

    /** Maximum selections per mode to prevent graph overload. */
    public static final int MAX_DATE_SELECT = 7;
    public static final int MAX_MONTH_SELECT = 7;
    public static final int MAX_YEAR_SELECT = 5;

    private int currentMode = MODE_DATE;

    // Mood mode overlay
    private boolean moodModeEnabled = false;
    private Map moodEmojiMap; // "yyyy-MM-dd" -> emoji string
    private Paint emojiPaint;

    // Date mode state
    private Calendar displayMonth; // The month being displayed
    private Calendar today;
    private Set selectedDates; // "yyyy-MM-dd" strings

    // Month mode state
    private int displayYear;
    private Set selectedMonths; // "yyyy-MM" strings

    // Year mode state
    private int yearRangeStart;
    private Set selectedYears; // "yyyy" strings

    // Paints
    private Paint headerPaint;
    private Paint arrowPaint;
    private Paint dayLabelPaint;
    private Paint dayPaint;
    private Paint dayOtherPaint;
    private Paint dayTodayPaint;
    private Paint selectionPaint;
    private Paint selectionTextPaint;
    private Paint todayRingPaint;
    private Paint gridPaint;
    private Paint monthCellPaint;
    private Paint monthCellTextPaint;

    // Dimensions (calculated in onSizeChanged)
    private float cellW, cellH;
    private float headerH;
    private float dayLabelH;
    private float totalH;
    private float padding;

    // Arrow regions
    private RectF leftArrowRect;
    private RectF rightArrowRect;

    // Callback
    private OnSelectionChangedListener listener;

    // Day-of-week labels
    private static final String[] DAY_LABELS = {"Su", "Mo", "Tu", "We", "Th", "Fr", "Sa"};
    private static final String[] MONTH_NAMES = {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };

    public interface OnSelectionChangedListener {
        /** Called whenever selection count changes in any mode. */
        void onSelectionChanged(int count);
        /** Called when user tries to select beyond the limit. */
        void onSelectionLimitReached(int maxAllowed);
    }

    public interface OnNavigateListener {
        /** Called when user navigates prev/next month/year. */
        void onCalendarNavigated();
    }

    private OnNavigateListener navigateListener;

    public void setOnNavigateListener(OnNavigateListener l) {
        this.navigateListener = l;
    }

    public AnalysisCalendarView(Context context) {
        super(context);
        init();
    }

    public AnalysisCalendarView(Context context, AttributeSet attrs) {
        super(context, attrs);
        init();
    }

    private void init() {
        today = Calendar.getInstance();
        displayMonth = Calendar.getInstance();
        displayYear = today.get(Calendar.YEAR);
        yearRangeStart = displayYear - 5;

        selectedDates = new HashSet();
        selectedMonths = new HashSet();
        selectedYears = new HashSet();

        padding = dp(12);

        // Header paint (Month Year title)
        headerPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        headerPaint.setColor(0xFFEAEAF0);
        headerPaint.setTextSize(dp(17));
        headerPaint.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        headerPaint.setTextAlign(Paint.Align.CENTER);

        // Arrow paint
        arrowPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        arrowPaint.setColor(0xFF4A9EFF);
        arrowPaint.setStrokeWidth(dp(2.5f));
        arrowPaint.setStyle(Paint.Style.STROKE);
        arrowPaint.setStrokeCap(Paint.Cap.ROUND);

        // Day-of-week label paint
        dayLabelPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        dayLabelPaint.setColor(0xFF555570);
        dayLabelPaint.setTextSize(dp(11));
        dayLabelPaint.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        dayLabelPaint.setTextAlign(Paint.Align.CENTER);

        // Day number paint
        dayPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        dayPaint.setColor(0xFFCCCCDD);
        dayPaint.setTextSize(dp(14));
        dayPaint.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL));
        dayPaint.setTextAlign(Paint.Align.CENTER);

        // Other month day paint
        dayOtherPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        dayOtherPaint.setColor(0xFF333348);
        dayOtherPaint.setTextSize(dp(14));
        dayOtherPaint.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL));
        dayOtherPaint.setTextAlign(Paint.Align.CENTER);

        // Today text paint
        dayTodayPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        dayTodayPaint.setColor(0xFF4A9EFF);
        dayTodayPaint.setTextSize(dp(14));
        dayTodayPaint.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        dayTodayPaint.setTextAlign(Paint.Align.CENTER);

        // Selection circle paint
        selectionPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        selectionPaint.setColor(0xFF4A9EFF);
        selectionPaint.setStyle(Paint.Style.FILL);

        // Selection text paint (white on blue)
        selectionTextPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        selectionTextPaint.setColor(0xFFFFFFFF);
        selectionTextPaint.setTextSize(dp(14));
        selectionTextPaint.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        selectionTextPaint.setTextAlign(Paint.Align.CENTER);

        // Today ring paint
        todayRingPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        todayRingPaint.setColor(0xFF4A9EFF);
        todayRingPaint.setStyle(Paint.Style.STROKE);
        todayRingPaint.setStrokeWidth(dp(2));

        // Grid line paint
        gridPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        gridPaint.setColor(0xFF1A1A26);
        gridPaint.setStrokeWidth(dp(0.5f));

        // Month/Year cell paint
        monthCellPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        monthCellPaint.setColor(0xFF1C1C28);
        monthCellPaint.setStyle(Paint.Style.FILL);

        monthCellTextPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        monthCellTextPaint.setColor(0xFFCCCCDD);
        monthCellTextPaint.setTextSize(dp(15));
        monthCellTextPaint.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        monthCellTextPaint.setTextAlign(Paint.Align.CENTER);

        leftArrowRect = new RectF();
        rightArrowRect = new RectF();

        // Mood mode emoji paint
        emojiPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        emojiPaint.setTextSize(dp(18));
        emojiPaint.setTextAlign(Paint.Align.CENTER);
        moodEmojiMap = new HashMap();
    }

    // ============ PUBLIC API ============

    /**
     * Switch calendar mode. Does NOT clear other modes' selections
     * (independent memory per mode).
     */
    public void setMode(int mode) {
        this.currentMode = mode;
        // Do NOT clear selections - independent memory per mode
        requestLayout();
        invalidate();
    }

    public int getMode() {
        return currentMode;
    }

    public void setOnSelectionChangedListener(OnSelectionChangedListener l) {
        this.listener = l;
    }

    public List getSelectedDates() {
        return new ArrayList(selectedDates);
    }

    public List getSelectedMonthKeys() {
        return new ArrayList(selectedMonths);
    }

    public List getSelectedYearKeys() {
        return new ArrayList(selectedYears);
    }

    /** Get current mode's selection count. */
    public int getCurrentSelectionCount() {
        if (currentMode == MODE_DATE) {
            return selectedDates.size();
        } else if (currentMode == MODE_MONTH) {
            return selectedMonths.size();
        } else {
            return selectedYears.size();
        }
    }

    /** Get current mode's max selection limit. */
    public int getCurrentMaxSelection() {
        if (currentMode == MODE_DATE) {
            return MAX_DATE_SELECT;
        } else if (currentMode == MODE_MONTH) {
            return MAX_MONTH_SELECT;
        } else {
            return MAX_YEAR_SELECT;
        }
    }

    /** Clear only the current mode's selection set. */
    public void clearCurrentModeSelection() {
        if (currentMode == MODE_DATE) {
            selectedDates.clear();
        } else if (currentMode == MODE_MONTH) {
            selectedMonths.clear();
        } else {
            selectedYears.clear();
        }
        invalidate();
        notifySelectionChanged();
    }

    // ============ MOOD MODE ============

    /**
     * Enable or disable mood mode overlay.
     * When enabled, dates with mood data show emoji instead of number.
     */
    public void setMoodModeEnabled(boolean enabled) {
        this.moodModeEnabled = enabled;
        invalidate();
    }

    public boolean isMoodModeEnabled() {
        return moodModeEnabled;
    }

    /**
     * Set the emoji map for mood mode. Key = "yyyy-MM-dd", value = emoji string.
     * Called by CalendarAnalysisActivity after loading mood data.
     */
    public void setMoodEmojiMap(Map emojiMap) {
        if (emojiMap == null) {
            this.moodEmojiMap = new HashMap();
        } else {
            this.moodEmojiMap = emojiMap;
        }
        if (moodModeEnabled) {
            invalidate();
        }
    }

    /** Remove a specific item from the current mode's selection. */
    public void removeSelection(String key) {
        if (currentMode == MODE_DATE) {
            selectedDates.remove(key);
        } else if (currentMode == MODE_MONTH) {
            selectedMonths.remove(key);
        } else {
            selectedYears.remove(key);
        }
        invalidate();
        notifySelectionChanged();
    }

    // ============ MEASURE ============

    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int w = MeasureSpec.getSize(widthMeasureSpec);
        headerH = dp(44);
        dayLabelH = dp(28);

        if (currentMode == MODE_DATE) {
            cellW = (w - padding * 2) / 7f;
            cellH = dp(42);
            totalH = headerH + dayLabelH + cellH * 6 + dp(8);
        } else if (currentMode == MODE_MONTH) {
            cellW = (w - padding * 2) / 4f;
            cellH = dp(52);
            totalH = headerH + cellH * 3 + dp(8);
        } else {
            cellW = (w - padding * 2) / 3f;
            cellH = dp(52);
            totalH = headerH + cellH * 4 + dp(8);
        }

        setMeasuredDimension(w, (int) totalH);
    }

    // ============ DRAW ============

    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);

        if (currentMode == MODE_DATE) {
            drawDateMode(canvas);
        } else if (currentMode == MODE_MONTH) {
            drawMonthMode(canvas);
        } else {
            drawYearMode(canvas);
        }
    }

    private void drawDateMode(Canvas canvas) {
        float w = getWidth();
        float startX = padding;

        // Draw header: < February 2026 >
        SimpleDateFormat sdf = new SimpleDateFormat("MMMM yyyy", Locale.US);
        String title = sdf.format(displayMonth.getTime());
        float headerCY = headerH / 2f;

        canvas.drawText(title, w / 2f, headerCY + headerPaint.getTextSize() / 3f, headerPaint);

        // Left arrow
        float arrowSize = dp(8);
        float arrowX = startX + dp(16);
        leftArrowRect.set(startX, 0, startX + dp(44), headerH);
        canvas.drawLine(arrowX + arrowSize, headerCY - arrowSize, arrowX, headerCY, arrowPaint);
        canvas.drawLine(arrowX, headerCY, arrowX + arrowSize, headerCY + arrowSize, arrowPaint);

        // Right arrow
        float rightX = w - startX - dp(16);
        rightArrowRect.set(w - startX - dp(44), 0, w - startX, headerH);
        canvas.drawLine(rightX - arrowSize, headerCY - arrowSize, rightX, headerCY, arrowPaint);
        canvas.drawLine(rightX, headerCY, rightX - arrowSize, headerCY + arrowSize, arrowPaint);

        // Day-of-week labels
        float labelY = headerH + dayLabelH * 0.7f;
        for (int i = 0; i < 7; i++) {
            float cx = startX + cellW * i + cellW / 2f;
            canvas.drawText(DAY_LABELS[i], cx, labelY, dayLabelPaint);
        }

        // Days grid
        Calendar cal = (Calendar) displayMonth.clone();
        cal.set(Calendar.DAY_OF_MONTH, 1);
        int firstDow = cal.get(Calendar.DAY_OF_WEEK) - 1; // 0=Sun
        int daysInMonth = cal.getActualMaximum(Calendar.DAY_OF_MONTH);

        int todayDay = today.get(Calendar.DAY_OF_MONTH);
        int todayMonth = today.get(Calendar.MONTH);
        int todayYear = today.get(Calendar.YEAR);
        int dispMonth = displayMonth.get(Calendar.MONTH);
        int dispYear = displayMonth.get(Calendar.YEAR);

        float gridStartY = headerH + dayLabelH;

        for (int row = 0; row < 6; row++) {
            for (int col = 0; col < 7; col++) {
                int cellIndex = row * 7 + col;
                int dayNum = cellIndex - firstDow + 1;

                float cx = startX + cellW * col + cellW / 2f;
                float cy = gridStartY + cellH * row + cellH / 2f;

                if (dayNum < 1 || dayNum > daysInMonth) {
                    continue;
                }

                String dateStr = formatDate(dispYear, dispMonth + 1, dayNum);
                boolean isToday = (dayNum == todayDay && dispMonth == todayMonth && dispYear == todayYear);
                boolean isSelected = selectedDates.contains(dateStr);

                // Mood mode: show emoji if available for this date
                boolean hasMoodEmoji = false;
                String moodEmoji = null;
                if (moodModeEnabled && moodEmojiMap != null) {
                    moodEmoji = (String) moodEmojiMap.get(dateStr);
                    if (moodEmoji != null && moodEmoji.length() > 0) {
                        hasMoodEmoji = true;
                    }
                }

                if (isSelected) {
                    canvas.drawCircle(cx, cy, cellW * 0.38f, selectionPaint);
                    if (hasMoodEmoji) {
                        canvas.drawText(moodEmoji, cx, cy + emojiPaint.getTextSize() / 3f, emojiPaint);
                    } else {
                        canvas.drawText(String.valueOf(dayNum), cx, cy + selectionTextPaint.getTextSize() / 3f, selectionTextPaint);
                    }
                } else if (hasMoodEmoji) {
                    // Mood mode: draw emoji instead of number
                    canvas.drawText(moodEmoji, cx, cy + emojiPaint.getTextSize() / 3f, emojiPaint);
                } else if (isToday) {
                    canvas.drawCircle(cx, cy, cellW * 0.38f, todayRingPaint);
                    canvas.drawText(String.valueOf(dayNum), cx, cy + dayTodayPaint.getTextSize() / 3f, dayTodayPaint);
                } else {
                    canvas.drawText(String.valueOf(dayNum), cx, cy + dayPaint.getTextSize() / 3f, dayPaint);
                }
            }
        }
    }

    private void drawMonthMode(Canvas canvas) {
        float w = getWidth();
        float startX = padding;

        // Header: < 2026 >
        String title = String.valueOf(displayYear);
        float headerCY = headerH / 2f;
        canvas.drawText(title, w / 2f, headerCY + headerPaint.getTextSize() / 3f, headerPaint);

        // Arrows
        float arrowSize = dp(8);
        float arrowX = startX + dp(16);
        leftArrowRect.set(startX, 0, startX + dp(44), headerH);
        canvas.drawLine(arrowX + arrowSize, headerCY - arrowSize, arrowX, headerCY, arrowPaint);
        canvas.drawLine(arrowX, headerCY, arrowX + arrowSize, headerCY + arrowSize, arrowPaint);

        float rightX = w - startX - dp(16);
        rightArrowRect.set(w - startX - dp(44), 0, w - startX, headerH);
        canvas.drawLine(rightX - arrowSize, headerCY - arrowSize, rightX, headerCY, arrowPaint);
        canvas.drawLine(rightX, headerCY, rightX - arrowSize, headerCY + arrowSize, arrowPaint);

        // 3 rows x 4 cols of months
        float gridStartY = headerH;
        int currentMonth = today.get(Calendar.MONTH);
        int currentYear = today.get(Calendar.YEAR);

        for (int row = 0; row < 3; row++) {
            for (int col = 0; col < 4; col++) {
                int monthIdx = row * 4 + col; // 0-11
                float cx = startX + cellW * col + cellW / 2f;
                float cy = gridStartY + cellH * row + cellH / 2f;

                String key = String.format(Locale.US, "%04d-%02d", displayYear, monthIdx + 1);
                boolean isSelected = selectedMonths.contains(key);
                boolean isCurrent = (monthIdx == currentMonth && displayYear == currentYear);

                RectF rect = new RectF(cx - cellW * 0.4f, cy - cellH * 0.35f,
                        cx + cellW * 0.4f, cy + cellH * 0.35f);

                if (isSelected) {
                    Paint selRect = new Paint(Paint.ANTI_ALIAS_FLAG);
                    selRect.setColor(0xFF4A9EFF);
                    canvas.drawRoundRect(rect, dp(10), dp(10), selRect);
                    canvas.drawText(MONTH_NAMES[monthIdx], cx,
                            cy + selectionTextPaint.getTextSize() / 3f, selectionTextPaint);
                } else {
                    if (isCurrent) {
                        Paint curRect = new Paint(Paint.ANTI_ALIAS_FLAG);
                        curRect.setColor(0xFF4A9EFF);
                        curRect.setStyle(Paint.Style.STROKE);
                        curRect.setStrokeWidth(dp(1.5f));
                        canvas.drawRoundRect(rect, dp(10), dp(10), curRect);
                        canvas.drawText(MONTH_NAMES[monthIdx], cx,
                                cy + dayTodayPaint.getTextSize() / 3f, dayTodayPaint);
                    } else {
                        canvas.drawText(MONTH_NAMES[monthIdx], cx,
                                cy + monthCellTextPaint.getTextSize() / 3f, monthCellTextPaint);
                    }
                }
            }
        }
    }

    private void drawYearMode(Canvas canvas) {
        float w = getWidth();
        float startX = padding;

        // Header: < 2020-2031 >
        String title = yearRangeStart + " - " + (yearRangeStart + 11);
        float headerCY = headerH / 2f;
        canvas.drawText(title, w / 2f, headerCY + headerPaint.getTextSize() / 3f, headerPaint);

        // Arrows
        float arrowSize = dp(8);
        float arrowX = startX + dp(16);
        leftArrowRect.set(startX, 0, startX + dp(44), headerH);
        canvas.drawLine(arrowX + arrowSize, headerCY - arrowSize, arrowX, headerCY, arrowPaint);
        canvas.drawLine(arrowX, headerCY, arrowX + arrowSize, headerCY + arrowSize, arrowPaint);

        float rightX = w - startX - dp(16);
        rightArrowRect.set(w - startX - dp(44), 0, w - startX, headerH);
        canvas.drawLine(rightX - arrowSize, headerCY - arrowSize, rightX, headerCY, arrowPaint);
        canvas.drawLine(rightX, headerCY, rightX - arrowSize, headerCY + arrowSize, arrowPaint);

        // 4 rows x 3 cols of years
        float gridStartY = headerH;
        int currentYear = today.get(Calendar.YEAR);

        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 3; col++) {
                int yearVal = yearRangeStart + row * 3 + col;
                float cx = startX + cellW * col + cellW / 2f;
                float cy = gridStartY + cellH * row + cellH / 2f;

                String key = String.valueOf(yearVal);
                boolean isSelected = selectedYears.contains(key);
                boolean isCurrent = (yearVal == currentYear);

                RectF rect = new RectF(cx - cellW * 0.35f, cy - cellH * 0.35f,
                        cx + cellW * 0.35f, cy + cellH * 0.35f);

                if (isSelected) {
                    Paint selRect = new Paint(Paint.ANTI_ALIAS_FLAG);
                    selRect.setColor(0xFF4A9EFF);
                    canvas.drawRoundRect(rect, dp(10), dp(10), selRect);
                    canvas.drawText(key, cx, cy + selectionTextPaint.getTextSize() / 3f, selectionTextPaint);
                } else if (isCurrent) {
                    Paint curRect = new Paint(Paint.ANTI_ALIAS_FLAG);
                    curRect.setColor(0xFF4A9EFF);
                    curRect.setStyle(Paint.Style.STROKE);
                    curRect.setStrokeWidth(dp(1.5f));
                    canvas.drawRoundRect(rect, dp(10), dp(10), curRect);
                    canvas.drawText(key, cx, cy + dayTodayPaint.getTextSize() / 3f, dayTodayPaint);
                } else {
                    canvas.drawText(key, cx, cy + monthCellTextPaint.getTextSize() / 3f, monthCellTextPaint);
                }
            }
        }
    }

    // ============ TOUCH ============

    public boolean onTouchEvent(MotionEvent event) {
        if (event.getAction() != MotionEvent.ACTION_UP) {
            return true;
        }

        float x = event.getX();
        float y = event.getY();

        // Check arrow taps
        if (leftArrowRect.contains(x, y)) {
            navigatePrev();
            return true;
        }
        if (rightArrowRect.contains(x, y)) {
            navigateNext();
            return true;
        }

        if (currentMode == MODE_DATE) {
            handleDateTap(x, y);
        } else if (currentMode == MODE_MONTH) {
            handleMonthTap(x, y);
        } else {
            handleYearTap(x, y);
        }

        return true;
    }

    private void handleDateTap(float x, float y) {
        float startX = padding;
        float gridStartY = headerH + dayLabelH;

        if (y < gridStartY) return;

        int col = (int) ((x - startX) / cellW);
        int row = (int) ((y - gridStartY) / cellH);
        if (col < 0 || col > 6 || row < 0 || row > 5) return;

        Calendar cal = (Calendar) displayMonth.clone();
        cal.set(Calendar.DAY_OF_MONTH, 1);
        int firstDow = cal.get(Calendar.DAY_OF_WEEK) - 1;
        int cellIndex = row * 7 + col;
        int dayNum = cellIndex - firstDow + 1;
        int daysInMonth = cal.getActualMaximum(Calendar.DAY_OF_MONTH);

        if (dayNum < 1 || dayNum > daysInMonth) return;

        int dispMonth = displayMonth.get(Calendar.MONTH);
        int dispYear = displayMonth.get(Calendar.YEAR);
        String dateStr = formatDate(dispYear, dispMonth + 1, dayNum);

        if (selectedDates.contains(dateStr)) {
            selectedDates.remove(dateStr);
        } else {
            if (selectedDates.size() >= MAX_DATE_SELECT) {
                if (listener != null) listener.onSelectionLimitReached(MAX_DATE_SELECT);
                return;
            }
            selectedDates.add(dateStr);
        }
        invalidate();
        notifySelectionChanged();
    }

    private void handleMonthTap(float x, float y) {
        float startX = padding;
        float gridStartY = headerH;

        if (y < gridStartY) return;

        int col = (int) ((x - startX) / cellW);
        int row = (int) ((y - gridStartY) / cellH);
        if (col < 0 || col > 3 || row < 0 || row > 2) return;

        int monthIdx = row * 4 + col; // 0-11
        String key = String.format(Locale.US, "%04d-%02d", displayYear, monthIdx + 1);

        if (selectedMonths.contains(key)) {
            selectedMonths.remove(key);
        } else {
            if (selectedMonths.size() >= MAX_MONTH_SELECT) {
                if (listener != null) listener.onSelectionLimitReached(MAX_MONTH_SELECT);
                return;
            }
            selectedMonths.add(key);
        }
        invalidate();
        notifySelectionChanged();
    }

    private void handleYearTap(float x, float y) {
        float startX = padding;
        float gridStartY = headerH;

        if (y < gridStartY) return;

        int col = (int) ((x - startX) / cellW);
        int row = (int) ((y - gridStartY) / cellH);
        if (col < 0 || col > 2 || row < 0 || row > 3) return;

        int yearVal = yearRangeStart + row * 3 + col;
        String key = String.valueOf(yearVal);

        if (selectedYears.contains(key)) {
            selectedYears.remove(key);
        } else {
            if (selectedYears.size() >= MAX_YEAR_SELECT) {
                if (listener != null) listener.onSelectionLimitReached(MAX_YEAR_SELECT);
                return;
            }
            selectedYears.add(key);
        }
        invalidate();
        notifySelectionChanged();
    }

    private void navigatePrev() {
        if (currentMode == MODE_DATE) {
            displayMonth.add(Calendar.MONTH, -1);
        } else if (currentMode == MODE_MONTH) {
            displayYear--;
        } else {
            yearRangeStart -= 12;
        }
        invalidate();
        if (navigateListener != null) {
            navigateListener.onCalendarNavigated();
        }
    }

    private void navigateNext() {
        if (currentMode == MODE_DATE) {
            displayMonth.add(Calendar.MONTH, 1);
        } else if (currentMode == MODE_MONTH) {
            displayYear++;
        } else {
            yearRangeStart += 12;
        }
        invalidate();
        if (navigateListener != null) {
            navigateListener.onCalendarNavigated();
        }
    }

    // ============ DISPLAY STATE ACCESSORS ============

    /** Get the currently displayed month (0-11). */
    public int getDisplayMonth() {
        return displayMonth.get(Calendar.MONTH);
    }

    /** Get the currently displayed year. */
    public int getDisplayYear() {
        if (currentMode == MODE_DATE) {
            return displayMonth.get(Calendar.YEAR);
        } else {
            return displayYear;
        }
    }

    // ============ INTERNAL ============

    private void notifySelectionChanged() {
        if (listener != null) {
            listener.onSelectionChanged(getCurrentSelectionCount());
        }
    }

    // ============ UTILITY ============

    private String formatDate(int year, int month, int day) {
        return String.format(Locale.US, "%04d-%02d-%02d", year, month, day);
    }

    private float dp(float val) {
        return val * getResources().getDisplayMetrics().density;
    }
}
