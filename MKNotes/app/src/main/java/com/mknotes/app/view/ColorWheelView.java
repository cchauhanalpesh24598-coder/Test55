package com.mknotes.app.view;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ComposeShader;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.RadialGradient;
import android.graphics.Shader;
import android.graphics.SweepGradient;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;

/**
 * Custom HSV Color Wheel View drawn entirely with Canvas.
 * Provides a circular hue wheel with saturation gradient.
 * No external libraries, no AndroidX, pure android.* only.
 */
public class ColorWheelView extends View {

    private Paint wheelPaint;
    private Paint selectorPaint;
    private Paint selectorStrokePaint;

    private float centerX;
    private float centerY;
    private float radius;

    private float selectedHue = 0f;
    private float selectedSat = 1f;
    private float currentValue = 1f;

    private Bitmap wheelBitmap;
    private boolean needsRedraw = true;

    private OnColorSelectedListener listener;

    public interface OnColorSelectedListener {
        void onColorSelected(int color);
        void onColorSelecting(int color);
    }

    public ColorWheelView(Context context) {
        super(context);
        init();
    }

    public ColorWheelView(Context context, AttributeSet attrs) {
        super(context, attrs);
        init();
    }

    public ColorWheelView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init();
    }

    private void init() {
        wheelPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

        selectorPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        selectorPaint.setStyle(Paint.Style.FILL);

        selectorStrokePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        selectorStrokePaint.setStyle(Paint.Style.STROKE);
        selectorStrokePaint.setStrokeWidth(3f);
        selectorStrokePaint.setColor(Color.WHITE);
    }

    public void setOnColorSelectedListener(OnColorSelectedListener listener) {
        this.listener = listener;
    }

    public void setValue(float value) {
        this.currentValue = value;
        needsRedraw = true;
        invalidate();
    }

    public float getSelectedHue() {
        return selectedHue;
    }

    public float getSelectedSaturation() {
        return selectedSat;
    }

    /**
     * Set the wheel to show a specific color. 
     * Extracts H and S from the color, V is controlled by the brightness slider.
     */
    public void setColor(int color) {
        float[] hsv = new float[3];
        Color.colorToHSV(color, hsv);
        selectedHue = hsv[0];
        selectedSat = hsv[1];
        currentValue = hsv[2];
        needsRedraw = true;
        invalidate();
    }

    public int getSelectedColor() {
        return Color.HSVToColor(new float[]{selectedHue, selectedSat, currentValue});
    }

    protected void onSizeChanged(int w, int h, int oldw, int oldh) {
        super.onSizeChanged(w, h, oldw, oldh);
        int size = Math.min(w, h);
        centerX = w / 2f;
        centerY = h / 2f;
        radius = size / 2f - 12f;
        needsRedraw = true;
    }

    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);

        if (radius <= 0) return;

        if (needsRedraw || wheelBitmap == null) {
            wheelBitmap = createWheelBitmap();
            needsRedraw = false;
        }

        // Draw the wheel bitmap centered
        canvas.drawBitmap(wheelBitmap,
                centerX - wheelBitmap.getWidth() / 2f,
                centerY - wheelBitmap.getHeight() / 2f, null);

        // Draw selector thumb at the selected position
        float angle = (float) Math.toRadians(selectedHue);
        float dist = selectedSat * radius;
        float thumbX = centerX + dist * (float) Math.cos(angle);
        float thumbY = centerY - dist * (float) Math.sin(angle);

        float thumbRadius = radius * 0.07f;
        if (thumbRadius < 8f) thumbRadius = 8f;
        if (thumbRadius > 16f) thumbRadius = 16f;

        // Outer white ring
        selectorStrokePaint.setColor(Color.WHITE);
        selectorStrokePaint.setStrokeWidth(4f);
        canvas.drawCircle(thumbX, thumbY, thumbRadius + 2f, selectorStrokePaint);

        // Inner dark ring
        selectorStrokePaint.setColor(Color.parseColor("#333333"));
        selectorStrokePaint.setStrokeWidth(2f);
        canvas.drawCircle(thumbX, thumbY, thumbRadius, selectorStrokePaint);

        // Fill with selected color
        selectorPaint.setColor(getSelectedColor());
        canvas.drawCircle(thumbX, thumbY, thumbRadius - 1f, selectorPaint);
    }

    private Bitmap createWheelBitmap() {
        int size = (int) (radius * 2);
        if (size <= 0) size = 1;
        Bitmap bmp = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888);
        Canvas c = new Canvas(bmp);

        float cx = size / 2f;
        float cy = size / 2f;
        float r = size / 2f;

        // Create hue sweep for the current brightness value
        int[] hueColors = new int[361];
        for (int i = 0; i <= 360; i++) {
            hueColors[i] = Color.HSVToColor(new float[]{(float) i, 1f, currentValue});
        }

        // Draw each pixel for perfect wheel
        // For performance, use sweep gradient + radial saturation
        SweepGradient sweepGradient = new SweepGradient(cx, cy, hueColors, null);

        // Rotate so red is at right (0 degrees)
        Matrix matrix = new Matrix();
        matrix.setRotate(0, cx, cy);
        sweepGradient.setLocalMatrix(matrix);

        // Radial gradient for saturation: white at center, transparent at edge
        int centerColor = Color.HSVToColor(new float[]{0f, 0f, currentValue});
        RadialGradient radialGradient = new RadialGradient(cx, cy, r,
                centerColor, Color.TRANSPARENT, Shader.TileMode.CLAMP);

        // First draw the hue wheel
        Paint huePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        huePaint.setShader(sweepGradient);
        c.drawCircle(cx, cy, r, huePaint);

        // Overlay saturation gradient
        Paint satPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        satPaint.setShader(radialGradient);
        c.drawCircle(cx, cy, r, satPaint);

        return bmp;
    }

    public boolean onTouchEvent(MotionEvent event) {
        float x = event.getX();
        float y = event.getY();

        float dx = x - centerX;
        float dy = y - centerY;
        float distance = (float) Math.sqrt(dx * dx + dy * dy);

        // Clamp to wheel radius
        if (distance > radius) {
            distance = radius;
        }

        // Calculate hue from angle (0-360)
        float angle = (float) Math.toDegrees(Math.atan2(-dy, dx));
        if (angle < 0) angle += 360f;

        selectedHue = angle;
        selectedSat = distance / radius;

        int color = getSelectedColor();

        switch (event.getAction()) {
            case MotionEvent.ACTION_DOWN:
            case MotionEvent.ACTION_MOVE:
                if (listener != null) {
                    listener.onColorSelecting(color);
                }
                invalidate();
                break;
            case MotionEvent.ACTION_UP:
                if (listener != null) {
                    listener.onColorSelected(color);
                }
                invalidate();
                break;
        }

        return true;
    }

    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int widthMode = MeasureSpec.getMode(widthMeasureSpec);
        int widthSize = MeasureSpec.getSize(widthMeasureSpec);
        int heightMode = MeasureSpec.getMode(heightMeasureSpec);
        int heightSize = MeasureSpec.getSize(heightMeasureSpec);

        int desiredSize = dpToPx(220);

        int width;
        if (widthMode == MeasureSpec.EXACTLY) {
            width = widthSize;
        } else if (widthMode == MeasureSpec.AT_MOST) {
            width = Math.min(desiredSize, widthSize);
        } else {
            width = desiredSize;
        }

        int height;
        if (heightMode == MeasureSpec.EXACTLY) {
            height = heightSize;
        } else if (heightMode == MeasureSpec.AT_MOST) {
            height = Math.min(desiredSize, heightSize);
        } else {
            height = desiredSize;
        }

        int size = Math.min(width, height);
        setMeasuredDimension(size, size);
    }

    private int dpToPx(int dp) {
        float density = getResources().getDisplayMetrics().density;
        return (int) (dp * density + 0.5f);
    }
}
