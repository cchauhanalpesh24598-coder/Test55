package com.mknotes.app.mood;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.Typeface;
import android.view.View;
import android.view.animation.DecelerateInterpolator;

import com.mknotes.app.model.NoteMood;

/**
 * Custom Canvas-drawn bar chart for mood intensity analytics.
 * Displays vertical bars for each period (day/week/month).
 * Bars colored by intensity level. Emoji shown above bars.
 * Pure Java, no external libraries, no lambda, no AndroidX.
 */
public class MoodBarChartView extends View {

    // Data
    private float[] intensities;
    private String[] emojis;
    private String[] xLabels;
    private String title;

    // Animation
    private float animProgress = 0f;
    private ValueAnimator animator;

    // Paints
    private Paint bgPaint;
    private Paint gridPaint;
    private Paint axisLabelPaint;
    private Paint titlePaint;
    private Paint barPaint;
    private Paint emojiPaint;
    private Paint valuePaint;
    private Paint emptyPaint;

    // Layout constants
    private static final float PADDING_LEFT = 40f;
    private static final float PADDING_RIGHT = 16f;
    private static final float PADDING_TOP = 40f;
    private static final float PADDING_BOTTOM = 36f;
    private static final float MAX_INTENSITY = 5f;

    // Computed
    private float graphLeft, graphTop, graphRight, graphBottom;
    private float graphWidth, graphHeight;

    // Scroll support
    private float minBarSpacing = 0f;

    public MoodBarChartView(Context context) {
        super(context);
        init();
    }

    private void init() {
        intensities = new float[0];
        emojis = new String[0];
        xLabels = new String[0];

        bgPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        bgPaint.setColor(0xFF13131E);

        gridPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        gridPaint.setColor(0xFF222233);
        gridPaint.setStrokeWidth(dp(0.5f));
        gridPaint.setStyle(Paint.Style.STROKE);

        axisLabelPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        axisLabelPaint.setColor(0xFF555570);
        axisLabelPaint.setTextSize(dp(10));
        axisLabelPaint.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL));

        titlePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        titlePaint.setColor(0xFFEAEAF0);
        titlePaint.setTextSize(dp(14));
        titlePaint.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));

        barPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        barPaint.setStyle(Paint.Style.FILL);

        emojiPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        emojiPaint.setTextSize(dp(14));
        emojiPaint.setTextAlign(Paint.Align.CENTER);

        valuePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        valuePaint.setTextSize(dp(9));
        valuePaint.setTextAlign(Paint.Align.CENTER);
        valuePaint.setColor(0xFFAABBCC);
        valuePaint.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL));

        emptyPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        emptyPaint.setColor(0xFF555570);
        emptyPaint.setTextSize(dp(13));
        emptyPaint.setTextAlign(Paint.Align.CENTER);
        emptyPaint.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL));
    }

    // ============ PUBLIC API ============

    /**
     * Set the chart data.
     * @param intensities Array of intensity values (0-5). 0 means no data.
     * @param emojis Array of emoji strings for each bar (can be empty string).
     * @param xLabels Array of x-axis labels.
     * @param chartTitle Title text.
     */
    public void setData(float[] intensities, String[] emojis, String[] xLabels, String chartTitle) {
        this.intensities = intensities != null ? intensities : new float[0];
        this.emojis = emojis != null ? emojis : new String[0];
        this.xLabels = xLabels != null ? xLabels : new String[0];
        this.title = chartTitle;
        startAnimation();
        requestLayout();
        invalidate();
    }

    public void setMinBarSpacing(float spacingDp) {
        this.minBarSpacing = spacingDp;
    }

    // ============ MEASURE ============

    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int parentW = MeasureSpec.getSize(widthMeasureSpec);
        int w = parentW;

        if (minBarSpacing > 0 && intensities.length > 1) {
            float neededWidth = dp(PADDING_LEFT) + dp(PADDING_RIGHT)
                    + intensities.length * dp(minBarSpacing);
            if (neededWidth > w) {
                w = (int) neededWidth;
            }
        }

        int h = (int) (dp(PADDING_TOP) + dp(180) + dp(PADDING_BOTTOM) + dp(20));
        setMeasuredDimension(w, h);
    }

    // ============ ANIMATION ============

    private void startAnimation() {
        if (animator != null) {
            animator.cancel();
        }
        animProgress = 0f;
        animator = ValueAnimator.ofFloat(0f, 1f);
        animator.setDuration(700);
        animator.setInterpolator(new DecelerateInterpolator(2f));
        animator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
            public void onAnimationUpdate(ValueAnimator anim) {
                animProgress = ((Float) anim.getAnimatedValue()).floatValue();
                invalidate();
            }
        });
        animator.start();
    }

    // ============ DRAW ============

    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int w = getWidth();
        int h = getHeight();

        // Background
        RectF bgRect = new RectF(0, 0, w, h);
        canvas.drawRoundRect(bgRect, dp(16), dp(16), bgPaint);

        graphLeft = dp(PADDING_LEFT);
        graphTop = dp(PADDING_TOP);
        graphRight = w - dp(PADDING_RIGHT);
        graphBottom = h - dp(PADDING_BOTTOM) - dp(20);
        graphWidth = graphRight - graphLeft;
        graphHeight = graphBottom - graphTop;

        if (graphWidth <= 0 || graphHeight <= 0) return;

        // Title
        if (title != null && title.length() > 0) {
            canvas.drawText(title, graphLeft, dp(24), titlePaint);
        }

        // Check for empty data
        boolean hasAnyData = false;
        for (int i = 0; i < intensities.length; i++) {
            if (intensities[i] > 0) {
                hasAnyData = true;
                break;
            }
        }

        if (!hasAnyData || intensities.length == 0) {
            canvas.drawText("No mood data available",
                    w / 2f, graphTop + graphHeight / 2f, emptyPaint);
            return;
        }

        // Draw grid (5 horizontal lines for intensity 1-5)
        drawGrid(canvas);

        // Draw Y-axis labels
        drawYAxis(canvas);

        // Draw bars
        drawBars(canvas);

        // Draw X-axis labels
        drawXAxis(canvas);
    }

    private void drawGrid(Canvas canvas) {
        for (int i = 0; i <= 5; i++) {
            float y = graphBottom - (graphHeight * i / MAX_INTENSITY);
            canvas.drawLine(graphLeft, y, graphRight, y, gridPaint);
        }
    }

    private void drawYAxis(Canvas canvas) {
        axisLabelPaint.setTextAlign(Paint.Align.RIGHT);
        String[] yLabels = {"0", "1", "2", "3", "4", "5"};
        for (int i = 0; i <= 5; i++) {
            float y = graphBottom - (graphHeight * i / MAX_INTENSITY);
            canvas.drawText(yLabels[i], graphLeft - dp(6), y + dp(3), axisLabelPaint);
        }
    }

    private void drawBars(Canvas canvas) {
        if (intensities.length == 0) return;

        float barAreaWidth = graphWidth / intensities.length;
        float barWidth = Math.min(barAreaWidth * 0.6f, dp(28));

        for (int i = 0; i < intensities.length; i++) {
            float value = intensities[i] * animProgress;
            if (value <= 0) continue;

            float cx = graphLeft + barAreaWidth * i + barAreaWidth / 2f;
            float barHeight = (value / MAX_INTENSITY) * graphHeight;
            float barTop = graphBottom - barHeight;

            // Determine bar color based on intensity level
            int level = Math.round(intensities[i]);
            if (level < 1) level = 1;
            if (level > 5) level = 5;
            int barColor = NoteMood.INTENSITY_COLORS[level - 1];

            // Draw bar with gradient
            int topColor = barColor;
            int bottomColor = (barColor & 0x00FFFFFF) | 0x80000000;
            barPaint.setShader(new LinearGradient(cx, barTop, cx, graphBottom,
                    topColor, bottomColor, Shader.TileMode.CLAMP));

            RectF barRect = new RectF(cx - barWidth / 2f, barTop,
                    cx + barWidth / 2f, graphBottom);
            canvas.drawRoundRect(barRect, dp(4), dp(4), barPaint);
            barPaint.setShader(null);

            // Draw emoji above bar
            if (emojis != null && i < emojis.length && emojis[i] != null && emojis[i].length() > 0) {
                canvas.drawText(emojis[i], cx, barTop - dp(4), emojiPaint);
            }

            // Draw value label
            String valLabel = String.valueOf(Math.round(intensities[i]));
            canvas.drawText(valLabel, cx, barTop - dp(16), valuePaint);
        }
    }

    private void drawXAxis(Canvas canvas) {
        if (xLabels == null || xLabels.length == 0) return;

        axisLabelPaint.setTextAlign(Paint.Align.CENTER);
        float barAreaWidth = graphWidth / Math.max(1, intensities.length);

        // Calculate step to avoid overcrowding
        float avgLabelW = 0;
        for (int i = 0; i < xLabels.length; i++) {
            avgLabelW += axisLabelPaint.measureText(xLabels[i]);
        }
        avgLabelW = avgLabelW / Math.max(1, xLabels.length);

        int step = 1;
        if (barAreaWidth < avgLabelW + dp(2)) {
            step = (int) Math.ceil((avgLabelW + dp(2)) / barAreaWidth);
        }
        if (step < 1) step = 1;

        for (int i = 0; i < xLabels.length; i += step) {
            float cx = graphLeft + barAreaWidth * i + barAreaWidth / 2f;
            canvas.drawText(xLabels[i], cx, graphBottom + dp(14), axisLabelPaint);
        }
    }

    // ============ LIFECYCLE ============

    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (animator != null) {
            animator.cancel();
            animator = null;
        }
    }

    // ============ UTILITY ============

    private float dp(float val) {
        return val * getResources().getDisplayMetrics().density;
    }
}
