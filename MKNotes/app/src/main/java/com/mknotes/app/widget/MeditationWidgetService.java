package com.mknotes.app.widget;

import android.content.Context;
import android.content.Intent;
import android.widget.RemoteViewsService;

/**
 * RemoteViewsService for meditation widget scrollable ListView.
 * Provides MeditationWidgetFactory to generate each mantra row.
 * Pure Java, no AndroidX, no lambda - AIDE compatible.
 */
public class MeditationWidgetService extends RemoteViewsService {

    public RemoteViewsFactory onGetViewFactory(Intent intent) {
        return new MeditationWidgetFactory(getApplicationContext(), intent);
    }
}
