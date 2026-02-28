package com.mknotes.app.checklist;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.PixelFormat;
import android.graphics.Rect;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.ListView;

public class ChecklistDragHelper implements View.OnTouchListener {

    private Context context;
    private ListView listView;
    private ChecklistManager manager;
    private DragListener dragListener;
    private WindowManager windowManager;

    private boolean isDragging;
    private int dragStartPosition;
    private int dragCurrentPosition;
    private View dragShadow;
    private WindowManager.LayoutParams dragShadowParams;
    private int dragOffsetY;
    private int touchStartY;

    private Paint shadowPaint;

    public interface DragListener {
        void onDragStarted(int position);
        void onDragMoved(int fromPosition, int toPosition);
        void onDragEnded(int fromPosition, int toPosition);
    }

    public ChecklistDragHelper(Context context, ListView listView, ChecklistManager manager) {
        this.context = context;
        this.listView = listView;
        this.manager = manager;
        this.windowManager = (WindowManager) context.getSystemService(Context.WINDOW_SERVICE);
        this.isDragging = false;
        this.dragStartPosition = -1;
        this.dragCurrentPosition = -1;

        shadowPaint = new Paint();
        shadowPaint.setColor(Color.argb(30, 0, 0, 0));
    }

    public void setDragListener(DragListener listener) {
        this.dragListener = listener;
    }

    public void startDrag(int position, View itemView, int touchY) {
        if (isDragging) return;
        if (position < 0 || position >= manager.getItemCount()) return;

        isDragging = true;
        dragStartPosition = position;
        dragCurrentPosition = position;

        // Create shadow bitmap from the item view
        Bitmap bitmap = createDragBitmap(itemView);
        dragShadow = new ImageView(context);
        ((ImageView) dragShadow).setImageBitmap(bitmap);
        dragShadow.setAlpha(0.85f);

        // Window manager params for the floating view
        dragShadowParams = new WindowManager.LayoutParams();
        dragShadowParams.gravity = Gravity.TOP | Gravity.LEFT;
        dragShadowParams.x = 0;

        int[] listLocation = new int[2];
        listView.getLocationOnScreen(listLocation);
        int itemTop = getItemTop(position);
        dragShadowParams.y = listLocation[1] + itemTop;

        dragShadowParams.width = itemView.getWidth();
        dragShadowParams.height = itemView.getHeight();
        dragShadowParams.flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                | WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE
                | WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS;
        dragShadowParams.format = PixelFormat.TRANSLUCENT;
        dragShadowParams.type = WindowManager.LayoutParams.TYPE_APPLICATION;

        try {
            windowManager.addView(dragShadow, dragShadowParams);
        } catch (Exception e) {
            isDragging = false;
            return;
        }

        touchStartY = touchY;
        dragOffsetY = touchY - itemTop;

        if (dragListener != null) {
            dragListener.onDragStarted(position);
        }
    }

    public boolean onTouch(View v, MotionEvent event) {
        if (!isDragging) return false;

        int action = event.getActionMasked();
        int rawY = (int) event.getRawY();

        switch (action) {
            case MotionEvent.ACTION_MOVE:
                updateDragPosition(rawY);
                break;
            case MotionEvent.ACTION_UP:
            case MotionEvent.ACTION_CANCEL:
                endDrag();
                break;
        }
        return true;
    }

    private void updateDragPosition(int rawY) {
        if (dragShadow == null || dragShadowParams == null) return;

        // Update shadow position
        int[] listLocation = new int[2];
        listView.getLocationOnScreen(listLocation);
        dragShadowParams.y = rawY - dragOffsetY;

        try {
            windowManager.updateViewLayout(dragShadow, dragShadowParams);
        } catch (Exception e) {
            // View may have been removed
        }

        // Determine which position the drag is hovering over
        int localY = rawY - listLocation[1];
        int targetPosition = getPositionFromY(localY);

        if (targetPosition >= 0 && targetPosition < manager.getItemCount()
                && targetPosition != dragCurrentPosition) {
            manager.moveItem(dragCurrentPosition, targetPosition);
            dragCurrentPosition = targetPosition;
            if (dragListener != null) {
                dragListener.onDragMoved(dragCurrentPosition, targetPosition);
            }
        }

        // Auto-scroll if near edges
        int listHeight = listView.getHeight();
        int scrollZone = listHeight / 5;
        if (localY < scrollZone) {
            listView.smoothScrollBy(-20, 50);
        } else if (localY > listHeight - scrollZone) {
            listView.smoothScrollBy(20, 50);
        }
    }

    private void endDrag() {
        if (!isDragging) return;

        isDragging = false;

        if (dragShadow != null) {
            try {
                windowManager.removeView(dragShadow);
            } catch (Exception e) {
                // Already removed
            }
            dragShadow = null;
        }

        if (dragListener != null) {
            dragListener.onDragEnded(dragStartPosition, dragCurrentPosition);
        }

        dragStartPosition = -1;
        dragCurrentPosition = -1;
    }

    public boolean isDragging() {
        return isDragging;
    }

    public void cancelDrag() {
        if (isDragging) {
            if (dragCurrentPosition != dragStartPosition) {
                manager.moveItem(dragCurrentPosition, dragStartPosition);
            }
            endDrag();
        }
    }

    private Bitmap createDragBitmap(View view) {
        Bitmap bitmap = Bitmap.createBitmap(view.getWidth(), view.getHeight(), Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(bitmap);
        view.draw(canvas);
        // Draw a subtle shadow border
        canvas.drawRect(0, 0, bitmap.getWidth(), bitmap.getHeight(), shadowPaint);
        return bitmap;
    }

    private int getItemTop(int position) {
        int firstVisible = listView.getFirstVisiblePosition();
        int index = position - firstVisible;
        if (index >= 0 && index < listView.getChildCount()) {
            return listView.getChildAt(index).getTop();
        }
        return 0;
    }

    private int getPositionFromY(int y) {
        int firstVisible = listView.getFirstVisiblePosition();
        for (int i = 0; i < listView.getChildCount(); i++) {
            View child = listView.getChildAt(i);
            if (y >= child.getTop() && y < child.getBottom()) {
                return firstVisible + i;
            }
        }
        // If below all items
        if (y >= 0) {
            return Math.min(firstVisible + listView.getChildCount() - 1,
                    manager.getItemCount() - 1);
        }
        return firstVisible;
    }
}
