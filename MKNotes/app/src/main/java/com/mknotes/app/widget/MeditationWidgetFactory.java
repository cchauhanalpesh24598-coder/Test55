package com.mknotes.app.widget;

import android.content.Context;
import android.content.Intent;
import android.widget.RemoteViews;
import android.widget.RemoteViewsService;

import com.mknotes.app.R;
import com.mknotes.app.db.NotesRepository;
import com.mknotes.app.meditation.MeditationPlayerManager;
import com.mknotes.app.model.Mantra;

import java.util.ArrayList;
import java.util.List;

/**
 * RemoteViewsFactory that builds each mantra row for the widget ListView.
 * Reads DailySession WHERE date = today.
 * Each row shows: numbered name, count (mala format), play icon, speed text.
 * Click intents use fillInIntent to be merged with PendingIntentTemplate.
 * Pure Java, no AndroidX, no lambda - AIDE compatible.
 */
public class MeditationWidgetFactory implements RemoteViewsService.RemoteViewsFactory {

    private Context context;
    private List mantraList;

    public MeditationWidgetFactory(Context context, Intent intent) {
        this.context = context;
        this.mantraList = new ArrayList();
    }

    public void onCreate() {
        // Nothing needed
    }

    public void onDataSetChanged() {
        // Reload today's mantras from DailySession table
        mantraList.clear();
        try {
            String today = MeditationPlayerManager.getTodayDateString();
            NotesRepository repo = NotesRepository.getInstance(context);
            List result = repo.getMantrasWithSessionForDate(today);
            if (result != null) {
                mantraList.addAll(result);
            }
        } catch (Exception e) {
            // Fail silently
        }
    }

    public void onDestroy() {
        mantraList.clear();
    }

    public int getCount() {
        return mantraList.size();
    }

    public RemoteViews getViewAt(int position) {
        if (position < 0 || position >= mantraList.size()) {
            return null;
        }

        Mantra mantra = (Mantra) mantraList.get(position);
        RemoteViews rowView = new RemoteViews(context.getPackageName(), R.layout.widget_mantra_row);

        // Numbered name
        String numberedName = (position + 1) + ". " + mantra.getName();
        rowView.setTextViewText(R.id.widget_row_name, numberedName);

        // Count with mala format
        String today = MeditationPlayerManager.getTodayDateString();
        NotesRepository repo = NotesRepository.getInstance(context);
        int count = repo.getSessionCount(mantra.getId(), today);
        String countStr;
        int malaCount = count / 108;
        int remainder = count % 108;
        if (count == 0) {
            countStr = "0";
        } else if (malaCount == 0) {
            countStr = String.valueOf(count);
        } else if (remainder == 0) {
            countStr = malaCount + "M";
        } else {
            countStr = malaCount + "M+" + remainder;
        }
        rowView.setTextViewText(R.id.widget_row_count, countStr);

        // Play/Pause icon
        MeditationPlayerManager player = MeditationPlayerManager.getInstance(context);
        boolean isThisPlaying = player.isCurrentlyPlaying()
                && player.getCurrentMantraId() == mantra.getId();
        rowView.setImageViewResource(R.id.widget_row_play,
                isThisPlaying ? R.drawable.ic_pause : R.drawable.ic_play);

        // Speed text
        float speed = repo.getSessionSpeed(mantra.getId(), today);
        String speedStr;
        if (speed <= 1.01f) speedStr = "1x";
        else if (speed <= 1.51f) speedStr = "1.5x";
        else if (speed <= 2.01f) speedStr = "2x";
        else if (speed <= 2.51f) speedStr = "2.5x";
        else speedStr = "3x";
        rowView.setTextViewText(R.id.widget_row_speed, speedStr);

        // FillInIntent for Play button - merged with PendingIntentTemplate
        Intent playFillIn = new Intent();
        playFillIn.putExtra(MeditationWidgetProvider.EXTRA_WIDGET_MANTRA_ID, mantra.getId());
        playFillIn.putExtra(MeditationWidgetProvider.EXTRA_WIDGET_ACTION, MeditationWidgetProvider.ACTION_WIDGET_TOGGLE);
        rowView.setOnClickFillInIntent(R.id.widget_row_play, playFillIn);

        // FillInIntent for Speed button
        Intent speedFillIn = new Intent();
        speedFillIn.putExtra(MeditationWidgetProvider.EXTRA_WIDGET_MANTRA_ID, mantra.getId());
        speedFillIn.putExtra(MeditationWidgetProvider.EXTRA_WIDGET_ACTION, MeditationWidgetProvider.ACTION_WIDGET_SPEED);
        rowView.setOnClickFillInIntent(R.id.widget_row_speed, speedFillIn);

        return rowView;
    }

    public RemoteViews getLoadingView() {
        return null;
    }

    public int getViewTypeCount() {
        return 1;
    }

    public long getItemId(int position) {
        if (position >= 0 && position < mantraList.size()) {
            return ((Mantra) mantraList.get(position)).getId();
        }
        return position;
    }

    public boolean hasStableIds() {
        return true;
    }
}
