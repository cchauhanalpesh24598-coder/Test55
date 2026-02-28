package com.mknotes.app.analysis;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.Typeface;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.view.animation.DecelerateInterpolator;

import java.util.ArrayList;
import java.util.List;

/**
 * Custom Canvas-drawn graph view for Calendar Analysis.
 * Supports smooth cubic bezier curves, gradient fills, animated entry,
 * multi-line series with legends, and tap-to-inspect interaction.
 * Pure Java, no external libraries.
 */
public class AnalysisGraphView extends View {

    // Data
    private List dataSets; // List of GraphDataSet
    private String[] xLabels;
    private String title;

    // Animation
    private float animProgress = 0f;
    private ValueAnimator animator;

    // Tap inspection
    private int tappedIndex = -1;
    private OnPointTappedListener tapListener;

    // Paints
    private Paint bgPaint;
    private Paint gridPaint;
    private Paint axisLabelPaint;
    private Paint titlePaint;
    private Paint valuePaint;
    private Paint legendDotPaint;
    private Paint legendTextPaint;
    private Paint tooltipBgPaint;
    private Paint tooltipTextPaint;

    // Layout
    private float graphLeft, graphTop, graphRight, graphBottom;
    private float graphWidth, graphHeight;
    private float legendHeight;
    private static final float PADDING_LEFT = 48f;
    private static final float PADDING_RIGHT = 16f;
    private static final float PADDING_TOP = 40f;
    private static final float PADDING_BOTTOM = 36f;
    private static final float LEGEND_ITEM_H = 26f;

    // Scroll support
    private float minPointSpacing = 0f; // dp; if >0, graph can be wider than screen

    // Computed
    private float maxValue = 100;
    private int dataPointCount = 0;

    public interface OnPointTappedListener {
        void onPointTapped(int dataPointIndex, String xLabel);
    }

    public AnalysisGraphView(Context context) {
        super(context);
        init();
    }

    public AnalysisGraphView(Context context, AttributeSet attrs) {
        super(context, attrs);
        init();
    }

    private void init() {
        dataSets = new ArrayList();
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

        valuePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        valuePaint.setTextSize(dp(10));
        valuePaint.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL));

        legendDotPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        legendTextPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        legendTextPaint.setColor(0xFFAABBCC);
        legendTextPaint.setTextSize(dp(11));
        legendTextPaint.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL));

        tooltipBgPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        tooltipBgPaint.setColor(0xDD1C1C28);

        tooltipTextPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        tooltipTextPaint.setColor(0xFFFFFFFF);
        tooltipTextPaint.setTextSize(dp(11));
        tooltipTextPaint.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
    }

    // ============ PUBLIC API ============

    public void setData(List datasets, String[] labels, String graphTitle) {
        this.dataSets = datasets != null ? datasets : new ArrayList();
        this.xLabels = labels != null ? labels : new String[0];
        this.title = graphTitle;
        computeMetrics();
        startAnimation();
        invalidate();
    }

    public void setOnPointTappedListener(OnPointTappedListener l) {
        this.tapListener = l;
    }

    /**
     * Set minimum spacing between data points in dp.
     * If the calculated width exceeds parent width, the graph becomes scrollable
     * when placed inside a HorizontalScrollView.
     */
    public void setMinPointSpacing(float spacingDp) {
        this.minPointSpacing = spacingDp;
    }

    // ============ MEASURE ============

    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int parentW = MeasureSpec.getSize(widthMeasureSpec);
        int w = parentW;

        // If minPointSpacing is set and we have enough data points, expand width
        if (minPointSpacing > 0 && dataPointCount > 1) {
            float neededWidth = dp(PADDING_LEFT) + dp(PADDING_RIGHT)
                    + (dataPointCount - 1) * dp(minPointSpacing);
            if (neededWidth > w) {
                w = (int) neededWidth;
            }
        }

        int legendRows = (dataSets.size() + 2) / 3; // 3 items per row
        legendHeight = legendRows * dp(LEGEND_ITEM_H) + dp(8);
        int h = (int) (dp(PADDING_TOP) + dp(200) + dp(PADDING_BOTTOM) + legendHeight);
        setMeasuredDimension(w, h);
    }

    private void computeMetrics() {
        maxValue = 1;
        dataPointCount = 0;
        for (int i = 0; i < dataSets.size(); i++) {
            AnalysisDataProvider.GraphDataSet ds = (AnalysisDataProvider.GraphDataSet) dataSets.get(i);
            if (ds.values.size() > dataPointCount) {
                dataPointCount = ds.values.size();
            }
            for (int j = 0; j < ds.values.size(); j++) {
                float v = ((Float) ds.values.get(j)).floatValue();
                if (v > maxValue) maxValue = v;
            }
        }
        // Round up maxValue for nice grid
        maxValue = niceMax(maxValue);
    }

    private float niceMax(float val) {
        if (val <= 0) return 10;
        if (val <= 10) return 10;
        if (val <= 50) return (float) (Math.ceil(val / 10.0) * 10);
        if (val <= 100) return (float) (Math.ceil(val / 20.0) * 20);
        if (val <= 500) return (float) (Math.ceil(val / 50.0) * 50);
        if (val <= 1000) return (float) (Math.ceil(val / 100.0) * 100);
        return (float) (Math.ceil(val / 500.0) * 500);
    }

    // ============ ANIMATION ============

    private void startAnimation() {
        if (animator != null) {
            animator.cancel();
        }
        animProgress = 0f;
        animator = ValueAnimator.ofFloat(0f, 1f);
        animator.setDuration(800);
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

        // Background with rounded corners
        RectF bgRect = new RectF(0, 0, w, h);
        canvas.drawRoundRect(bgRect, dp(16), dp(16), bgPaint);

        graphLeft = dp(PADDING_LEFT);
        graphTop = dp(PADDING_TOP);
        graphRight = w - dp(PADDING_RIGHT);
        graphBottom = h - dp(PADDING_BOTTOM) - legendHeight;
        graphWidth = graphRight - graphLeft;
        graphHeight = graphBottom - graphTop;

        if (graphWidth <= 0 || graphHeight <= 0) return;

        // Title
        if (title != null && title.length() > 0) {
            canvas.drawText(title, graphLeft, dp(24), titlePaint);
        }

        // Draw grid lines (5 horizontal lines)
        drawGrid(canvas);

        // Draw Y axis labels
        drawYAxis(canvas);

        // Draw X axis labels
        drawXAxis(canvas);

        // Draw data lines
        for (int i = 0; i < dataSets.size(); i++) {
            drawDataLine(canvas, (AnalysisDataProvider.GraphDataSet) dataSets.get(i));
        }

        // Draw tap indicator
        if (tappedIndex >= 0 && tappedIndex < dataPointCount) {
            drawTapIndicator(canvas);
        }

        // Draw legend
        drawLegend(canvas);
    }

    private void drawGrid(Canvas canvas) {
        int gridLines = 5;
        for (int i = 0; i <= gridLines; i++) {
            float y = graphBottom - (graphHeight * i / gridLines);
            canvas.drawLine(graphLeft, y, graphRight, y, gridPaint);
        }
    }

    private void drawYAxis(Canvas canvas) {
        int gridLines = 5;
        axisLabelPaint.setTextAlign(Paint.Align.RIGHT);
        for (int i = 0; i <= gridLines; i++) {
            float y = graphBottom - (graphHeight * i / gridLines);
            float val = maxValue * i / gridLines;
            String label;
            if (val >= 1000) {
                label = String.format("%.0f", val);
            } else if (val == (int) val) {
                label = String.valueOf((int) val);
            } else {
                label = String.format("%.1f", val);
            }
            canvas.drawText(label, graphLeft - dp(6), y + dp(3), axisLabelPaint);
        }
    }

    private void drawXAxis(Canvas canvas) {
        if (xLabels == null || xLabels.length == 0 || dataPointCount == 0) return;

        axisLabelPaint.setTextAlign(Paint.Align.CENTER);

        // When scrollable (minPointSpacing > 0), show all labels since there's enough room
        if (minPointSpacing > 0) {
            for (int i = 0; i < xLabels.length; i++) {
                float x = getXForIndex(i);
                canvas.drawText(xLabels[i], x, graphBottom + dp(14), axisLabelPaint);
            }
            return;
        }

        // Non-scrollable: decide step to prevent overcrowding
        // Measure average label width
        float avgLabelW = 0;
        for (int i = 0; i < xLabels.length; i++) {
            avgLabelW += axisLabelPaint.measureText(xLabels[i]);
        }
        avgLabelW = avgLabelW / xLabels.length;

        float spacing = graphWidth / Math.max(1, dataPointCount - 1);
        int step = 1;
        if (spacing < avgLabelW + dp(4)) {
            step = (int) Math.ceil((avgLabelW + dp(4)) / spacing);
        }
        if (step < 1) step = 1;

        for (int i = 0; i < xLabels.length; i += step) {
            float x = getXForIndex(i);
            canvas.drawText(xLabels[i], x, graphBottom + dp(14), axisLabelPaint);
        }
    }

    private void drawDataLine(Canvas canvas, AnalysisDataProvider.GraphDataSet ds) {
        if (ds.values == null || ds.values.size() < 1) return;

        int count = ds.values.size();
        float[] px = new float[count];
        float[] py = new float[count];

        for (int i = 0; i < count; i++) {
            px[i] = getXForIndex(i);
            float val = ((Float) ds.values.get(i)).floatValue() * animProgress;
            py[i] = graphBottom - (val / maxValue) * graphHeight;
            py[i] = Math.max(graphTop, Math.min(graphBottom, py[i]));
        }

        // Line paint
        Paint linePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        linePaint.setColor(ds.color);
        linePaint.setStrokeWidth(dp(2.5f));
        linePaint.setStyle(Paint.Style.STROKE);
        linePaint.setStrokeCap(Paint.Cap.ROUND);
        linePaint.setStrokeJoin(Paint.Join.ROUND);

        if (count == 1) {
            // Single data point - draw a dot
            Paint dotPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
            dotPaint.setColor(ds.color);
            canvas.drawCircle(px[0], py[0], dp(5), dotPaint);
            return;
        }

        // Build smooth cubic bezier path
        Path path = new Path();
        path.moveTo(px[0], py[0]);

        for (int i = 0; i < count - 1; i++) {
            float cp1x, cp1y, cp2x, cp2y;
            float tension = 0.3f;

            if (i == 0) {
                cp1x = px[i] + (px[i + 1] - px[i]) * tension;
                cp1y = py[i] + (py[i + 1] - py[i]) * tension;
            } else {
                cp1x = px[i] + (px[i + 1] - px[i - 1]) * tension;
                cp1y = py[i] + (py[i + 1] - py[i - 1]) * tension;
            }

            if (i + 2 < count) {
                cp2x = px[i + 1] - (px[i + 2] - px[i]) * tension;
                cp2y = py[i + 1] - (py[i + 2] - py[i]) * tension;
            } else {
                cp2x = px[i + 1] - (px[i + 1] - px[i]) * tension;
                cp2y = py[i + 1] - (py[i + 1] - py[i]) * tension;
            }

            path.cubicTo(cp1x, cp1y, cp2x, cp2y, px[i + 1], py[i + 1]);
        }

        // Draw gradient fill below the curve
        Path fillPath = new Path(path);
        fillPath.lineTo(px[count - 1], graphBottom);
        fillPath.lineTo(px[0], graphBottom);
        fillPath.close();

        Paint fillPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        int fillColorTop = (ds.color & 0x00FFFFFF) | 0x40000000; // 25% alpha
        int fillColorBot = (ds.color & 0x00FFFFFF) | 0x05000000; // 2% alpha
        fillPaint.setShader(new LinearGradient(0, graphTop, 0, graphBottom,
                fillColorTop, fillColorBot, Shader.TileMode.CLAMP));
        canvas.drawPath(fillPath, fillPaint);

        // Draw the line on top
        canvas.drawPath(path, linePaint);

        // Draw data point dots
        Paint dotPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        dotPaint.setColor(ds.color);
        for (int i = 0; i < count; i++) {
            float val = ((Float) ds.values.get(i)).floatValue();
            if (val > 0) {
                canvas.drawCircle(px[i], py[i], dp(3), dotPaint);
            }
        }
    }

    private void drawTapIndicator(Canvas canvas) {
        float x = getXForIndex(tappedIndex);

        // Vertical indicator line
        Paint indicPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        indicPaint.setColor(0x554A9EFF);
        indicPaint.setStrokeWidth(dp(1));
        canvas.drawLine(x, graphTop, x, graphBottom, indicPaint);

        // Tooltip
        if (dataSets.isEmpty()) return;

        float tooltipW = dp(120);
        float lineH = dp(16);
        float tooltipH = dp(8) + dataSets.size() * lineH + dp(4);
        float tooltipX = x + dp(8);
        float tooltipY = graphTop + dp(4);

        // Flip if too close to right edge
        if (tooltipX + tooltipW > graphRight) {
            tooltipX = x - tooltipW - dp(8);
        }

        RectF tipRect = new RectF(tooltipX, tooltipY, tooltipX + tooltipW, tooltipY + tooltipH);
        canvas.drawRoundRect(tipRect, dp(8), dp(8), tooltipBgPaint);

        float textY = tooltipY + dp(14);
        for (int i = 0; i < dataSets.size(); i++) {
            AnalysisDataProvider.GraphDataSet ds = (AnalysisDataProvider.GraphDataSet) dataSets.get(i);
            float val = 0;
            if (tappedIndex < ds.values.size()) {
                val = ((Float) ds.values.get(tappedIndex)).floatValue();
            }

            // Colored dot
            Paint dot = new Paint(Paint.ANTI_ALIAS_FLAG);
            dot.setColor(ds.color);
            canvas.drawCircle(tooltipX + dp(10), textY - dp(3), dp(3), dot);

            // Text
            String text = ds.label + ": " + (int) val;
            tooltipTextPaint.setTextAlign(Paint.Align.LEFT);
            canvas.drawText(text, tooltipX + dp(18), textY, tooltipTextPaint);
            textY += lineH;
        }
    }

    private void drawLegend(Canvas canvas) {
        if (dataSets.isEmpty()) return;

        float startY = graphBottom + dp(PADDING_BOTTOM);
        float itemW = getWidth() / 3f;

        for (int i = 0; i < dataSets.size(); i++) {
            AnalysisDataProvider.GraphDataSet ds = (AnalysisDataProvider.GraphDataSet) dataSets.get(i);
            int row = i / 3;
            int col = i % 3;

            float x = col * itemW + dp(16);
            float y = startY + row * dp(LEGEND_ITEM_H);

            // Dot
            legendDotPaint.setColor(ds.color);
            canvas.drawCircle(x, y + dp(6), dp(4), legendDotPaint);

            // Label
            String label = ds.label;
            if (label.length() > 14) {
                label = label.substring(0, 12) + "..";
            }
            legendTextPaint.setTextAlign(Paint.Align.LEFT);
            canvas.drawText(label, x + dp(10), y + dp(10), legendTextPaint);
        }
    }

    // ============ TOUCH ============

    public boolean onTouchEvent(MotionEvent event) {
        if (event.getAction() == MotionEvent.ACTION_UP) {
            float x = event.getX();
            float y = event.getY();

            if (y >= graphTop && y <= graphBottom && x >= graphLeft && x <= graphRight && dataPointCount > 0) {
                // Find nearest data point
                float closestDist = Float.MAX_VALUE;
                int closestIdx = -1;
                for (int i = 0; i < dataPointCount; i++) {
                    float px = getXForIndex(i);
                    float dist = Math.abs(x - px);
                    if (dist < closestDist) {
                        closestDist = dist;
                        closestIdx = i;
                    }
                }
                if (closestDist < dp(30)) {
                    tappedIndex = closestIdx;
                    invalidate();
                    if (tapListener != null && closestIdx >= 0 && closestIdx < xLabels.length) {
                        tapListener.onPointTapped(closestIdx, xLabels[closestIdx]);
                    }
                } else {
                    tappedIndex = -1;
                    invalidate();
                }
            } else {
                tappedIndex = -1;
                invalidate();
            }
        }
        return true;
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

    private float getXForIndex(int index) {
        if (dataPointCount <= 1) return graphLeft + graphWidth / 2f;
        return graphLeft + (graphWidth * index) / (dataPointCount - 1);
    }

    private float dp(float val) {
        return val * getResources().getDisplayMetrics().density;
    }
}
