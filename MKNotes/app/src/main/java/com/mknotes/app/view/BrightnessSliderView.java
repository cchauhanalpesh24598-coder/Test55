package com.mknotes.app.view;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Shader;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;

/**
 * Custom horizontal brightness/value slider for HSV color selection.
 * Shows a gradient from black (left) to the full-saturation color (right).
 * Pure Canvas-based, no external libraries.
 */
public class BrightnessSliderView extends View {

    private Paint barPaint;
    private Paint thumbPaint;
    private Paint thumbStrokePaint;

    private float hue = 0f;
    private float saturation = 1f;
    private float value = 1f;

    private RectF barRect;
    private float cornerRadius;

    private OnBrightnessChangedListener listener;

    public interface OnBrightnessChangedListener {
        void onBrightnessChanged(float brightness);
        void onBrightnessChanging(float brightness);
    }

    public BrightnessSliderView(Context context) {
        super(context);
        init();
    }

    public BrightnessSliderView(Context context, AttributeSet attrs) {
        super(context, attrs);
        init();
    }

    public BrightnessSliderView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init();
    }

    private void init() {
        barPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        barRect = new RectF();
        cornerRadius = dpToPx(12);

        thumbPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        thumbPaint.setStyle(Paint.Style.FILL);

        thumbStrokePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        thumbStrokePaint.setStyle(Paint.Style.STROKE);
        thumbStrokePaint.setStrokeWidth(3f);
        thumbStrokePaint.setColor(Color.WHITE);
    }

    public void setOnBrightnessChangedListener(OnBrightnessChangedListener listener) {
        this.listener = listener;
    }

    public void setHueAndSaturation(float hue, float saturation) {
        this.hue = hue;
        this.saturation = saturation;
        invalidate();
    }

    public void setValue(float value) {
        this.value = Math.max(0f, Math.min(1f, value));
        invalidate();
    }

    public float getValue() {
        return value;
    }

    protected void onSizeChanged(int w, int h, int oldw, int oldh) {
        super.onSizeChanged(w, h, oldw, oldh);
        float padding = dpToPx(14);
        barRect.set(padding, h / 2f - dpToPx(12), w - padding, h / 2f + dpToPx(12));
    }

    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);

        if (barRect.width() <= 0) return;

        // Draw the gradient bar: Black -> Full brightness color
        int darkColor = Color.HSVToColor(new float[]{hue, saturation, 0f});
        int brightColor = Color.HSVToColor(new float[]{hue, saturation, 1f});

        LinearGradient gradient = new LinearGradient(
                barRect.left, 0, barRect.right, 0,
                darkColor, brightColor,
                Shader.TileMode.CLAMP);
        barPaint.setShader(gradient);

        canvas.drawRoundRect(barRect, cornerRadius, cornerRadius, barPaint);

        // Draw thumb at current value position
        float thumbX = barRect.left + value * barRect.width();
        float thumbY = getHeight() / 2f;
        float thumbRadius = dpToPx(11);

        // Shadow circle
        Paint shadowPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        shadowPaint.setColor(Color.argb(60, 0, 0, 0));
        canvas.drawCircle(thumbX, thumbY + 1f, thumbRadius + 1f, shadowPaint);

        // White outer ring
        thumbStrokePaint.setColor(Color.WHITE);
        thumbStrokePaint.setStrokeWidth(4f);
        canvas.drawCircle(thumbX, thumbY, thumbRadius, thumbStrokePaint);

        // Fill with current color
        int currentColor = Color.HSVToColor(new float[]{hue, saturation, value});
        thumbPaint.setColor(currentColor);
        canvas.drawCircle(thumbX, thumbY, thumbRadius - 3f, thumbPaint);
    }

    public boolean onTouchEvent(MotionEvent event) {
        float x = event.getX();

        // Map x to value (0.0 - 1.0)
        float newValue = (x - barRect.left) / barRect.width();
        newValue = Math.max(0f, Math.min(1f, newValue));
        value = newValue;

        switch (event.getAction()) {
            case MotionEvent.ACTION_DOWN:
            case MotionEvent.ACTION_MOVE:
                if (listener != null) {
                    listener.onBrightnessChanging(value);
                }
                invalidate();
                break;
            case MotionEvent.ACTION_UP:
                if (listener != null) {
                    listener.onBrightnessChanged(value);
                }
                invalidate();
                break;
        }

        return true;
    }

    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int widthMode = MeasureSpec.getMode(widthMeasureSpec);
        int widthSize = MeasureSpec.getSize(widthMeasureSpec);

        int width;
        if (widthMode == MeasureSpec.EXACTLY) {
            width = widthSize;
        } else {
            width = dpToPx(280);
            if (widthMode == MeasureSpec.AT_MOST) {
                width = Math.min(width, widthSize);
            }
        }

        int height = dpToPx(48);
        setMeasuredDimension(width, height);
    }

    private int dpToPx(int dp) {
        float density = getResources().getDisplayMetrics().density;
        return (int) (dp * density + 0.5f);
    }
}
