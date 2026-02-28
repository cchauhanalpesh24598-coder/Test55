package com.mknotes.app.widget;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;
import android.os.SystemClock;
import android.view.View;
import android.widget.RemoteViews;

import com.mknotes.app.R;
import com.mknotes.app.db.NotesRepository;
import com.mknotes.app.meditation.MeditationPlayerManager;
import com.mknotes.app.model.Mantra;
import com.mknotes.app.service.MeditationService;

import java.util.List;

/**
 * Meditation widget with:
 * - Scrollable ListView of today's active mantras (from DailySession)
 * - Semi-transparent faded state by default (almost invisible)
 * - Tap to wake: full visible on tap, auto-fade after 8 seconds
 * - Play/pause toggle and speed cycle per mantra row
 * - One mantra at a time rule
 *
 * Opacity is handled by swapping background drawable (faded vs active)
 * and changing text colors. No setFloat("setAlpha") used (crashes widgets).
 *
 * Pure Java, no AndroidX, no lambda - AIDE compatible.
 */
public class MeditationWidgetProvider extends AppWidgetProvider {

    public static final String ACTION_WIDGET_TOGGLE = "com.mknotes.app.WIDGET_MED_TOGGLE";
    public static final String ACTION_WIDGET_SPEED = "com.mknotes.app.WIDGET_MED_SPEED";
    public static final String ACTION_WIDGET_WAKE = "com.mknotes.app.WIDGET_MED_WAKE";
    public static final String ACTION_WIDGET_FADE = "com.mknotes.app.WIDGET_MED_FADE";
    public static final String ACTION_WIDGET_LIST_CLICK = "com.mknotes.app.WIDGET_MED_LIST_CLICK";

    public static final String EXTRA_WIDGET_MANTRA_ID = "widget_mantra_id";
    public static final String EXTRA_WIDGET_ACTION = "widget_action_type";

    private static final String PREFS_NAME = "meditation_widget_prefs";
    private static final String KEY_IS_ACTIVE = "widget_is_active";
    private static final long FADE_DELAY_MS = 8000; // 8 seconds auto-fade

    // Color constants for faded state
    private static final int COLOR_HEADER_FADED = 0x2666BB6A;   // ~15% alpha green
    private static final int COLOR_NAME_FADED = 0x2681C784;     // ~15% alpha light green
    private static final int COLOR_COUNT_FADED = 0x26E0E0E0;    // ~15% alpha grey
    private static final int COLOR_SPEED_FADED = 0x26A5D6A7;    // ~15% alpha
    private static final int COLOR_EMPTY_FADED = 0x26888888;    // ~15% alpha

    // Color constants for active (awake) state
    private static final int COLOR_HEADER_ACTIVE = 0xFF66BB6A;  // full green
    private static final int COLOR_NAME_ACTIVE = 0xFF81C784;    // full light green
    private static final int COLOR_COUNT_ACTIVE = 0xFFE0E0E0;   // full grey
    private static final int COLOR_SPEED_ACTIVE = 0xFFA5D6A7;   // full
    private static final int COLOR_EMPTY_ACTIVE = 0xFF888888;   // full

    public void onUpdate(Context context, AppWidgetManager appWidgetManager, int[] appWidgetIds) {
        for (int i = 0; i < appWidgetIds.length; i++) {
            updateSingleWidget(context, appWidgetManager, appWidgetIds[i]);
        }
    }

    public void onReceive(Context context, Intent intent) {
        super.onReceive(context, intent);

        if (intent == null || intent.getAction() == null) {
            return;
        }

        String action = intent.getAction();

        if (ACTION_WIDGET_WAKE.equals(action)) {
            // Tap wake: make widget fully visible
            setActiveState(context, true);
            refreshAllWidgets(context);
            scheduleFade(context);

        } else if (ACTION_WIDGET_FADE.equals(action)) {
            // Auto-fade: return to semi-transparent
            setActiveState(context, false);
            refreshAllWidgets(context);

        } else if (ACTION_WIDGET_LIST_CLICK.equals(action)) {
            // Click from ListView row (play or speed)
            long mantraId = intent.getLongExtra(EXTRA_WIDGET_MANTRA_ID, -1);
            String actionType = intent.getStringExtra(EXTRA_WIDGET_ACTION);

            if (mantraId != -1 && actionType != null) {
                // Keep widget awake on interaction
                setActiveState(context, true);
                scheduleFade(context);

                if (ACTION_WIDGET_TOGGLE.equals(actionType)) {
                    handleToggle(context, mantraId);
                } else if (ACTION_WIDGET_SPEED.equals(actionType)) {
                    handleSpeedCycle(context, mantraId);
                }
            }
            refreshAllWidgets(context);

        } else if (ACTION_WIDGET_TOGGLE.equals(action)) {
            long mantraId = intent.getLongExtra(EXTRA_WIDGET_MANTRA_ID, -1);
            if (mantraId != -1) {
                setActiveState(context, true);
                scheduleFade(context);
                handleToggle(context, mantraId);
            }
            refreshAllWidgets(context);

        } else if (ACTION_WIDGET_SPEED.equals(action)) {
            long mantraId = intent.getLongExtra(EXTRA_WIDGET_MANTRA_ID, -1);
            if (mantraId != -1) {
                setActiveState(context, true);
                scheduleFade(context);
                handleSpeedCycle(context, mantraId);
            }
            refreshAllWidgets(context);

        } else if (Intent.ACTION_DATE_CHANGED.equals(action)) {
            refreshAllWidgets(context);

        } else if (MeditationPlayerManager.ACTION_COUNT_UPDATED.equals(action)
                || MeditationPlayerManager.ACTION_PLAYBACK_STATE_CHANGED.equals(action)) {
            refreshAllWidgets(context);
        }
    }

    /**
     * Build and update a single widget instance.
     * Sets up ListView adapter, tap-wake overlay, and applies faded/active style.
     */
    private void updateSingleWidget(Context context, AppWidgetManager manager, int widgetId) {
        try {
            RemoteViews views = new RemoteViews(context.getPackageName(), R.layout.widget_meditation);
            boolean isActive = isActiveState(context);

            // --- Background swap for opacity ---
            if (isActive) {
                views.setInt(R.id.widget_root, "setBackgroundResource",
                        R.drawable.bg_meditation_widget_active);
            } else {
                views.setInt(R.id.widget_root, "setBackgroundResource",
                        R.drawable.bg_meditation_widget_faded);
            }

            // --- Header text color ---
            views.setTextColor(R.id.widget_header,
                    isActive ? COLOR_HEADER_ACTIVE : COLOR_HEADER_FADED);

            // --- Empty state text color ---
            views.setTextColor(R.id.widget_empty,
                    isActive ? COLOR_EMPTY_ACTIVE : COLOR_EMPTY_FADED);

            // --- Check if mantras exist today ---
            String today = MeditationPlayerManager.getTodayDateString();
            NotesRepository repo = NotesRepository.getInstance(context);
            List mantras = repo.getMantrasWithSessionForDate(today);
            boolean hasMantras = (mantras != null && !mantras.isEmpty());

            if (hasMantras) {
                views.setViewVisibility(R.id.widget_empty, View.GONE);
                views.setViewVisibility(R.id.widget_mantra_list, View.VISIBLE);

                // Setup ListView with RemoteViewsService
                Intent serviceIntent = new Intent(context, MeditationWidgetService.class);
                serviceIntent.putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, widgetId);
                serviceIntent.setData(Uri.parse(serviceIntent.toUri(Intent.URI_INTENT_SCHEME)));
                views.setRemoteAdapter(R.id.widget_mantra_list, serviceIntent);
                views.setEmptyView(R.id.widget_mantra_list, R.id.widget_empty);

                // PendingIntentTemplate for ListView item clicks
                Intent listClickIntent = new Intent(context, MeditationWidgetProvider.class);
                listClickIntent.setAction(ACTION_WIDGET_LIST_CLICK);
                int listFlags = PendingIntent.FLAG_UPDATE_CURRENT;
                if (Build.VERSION.SDK_INT >= 31) {
                    listFlags = listFlags | 0x02000000; // FLAG_MUTABLE = 0x02000000
                }
                PendingIntent listClickPi = PendingIntent.getBroadcast(context, 0,
                        listClickIntent, listFlags);
                views.setPendingIntentTemplate(R.id.widget_mantra_list, listClickPi);

                // Notify adapter to refresh data
                manager.notifyAppWidgetViewDataChanged(widgetId, R.id.widget_mantra_list);

            } else {
                views.setViewVisibility(R.id.widget_empty, View.VISIBLE);
                views.setViewVisibility(R.id.widget_mantra_list, View.GONE);
            }

            // --- Tap-wake overlay ---
            if (isActive) {
                // Widget is active: hide overlay so ListView clicks work
                views.setViewVisibility(R.id.widget_tap_overlay, View.GONE);
            } else {
                // Widget is faded: show overlay to catch tap-wake
                views.setViewVisibility(R.id.widget_tap_overlay, View.VISIBLE);

                Intent wakeIntent = new Intent(context, MeditationWidgetProvider.class);
                wakeIntent.setAction(ACTION_WIDGET_WAKE);
                int wakeFlags = PendingIntent.FLAG_UPDATE_CURRENT;
                if (Build.VERSION.SDK_INT >= 31) {
                    wakeFlags = wakeFlags | 0x04000000; // FLAG_IMMUTABLE = 0x04000000
                }
                PendingIntent wakePi = PendingIntent.getBroadcast(context, 3000,
                        wakeIntent, wakeFlags);
                views.setOnClickPendingIntent(R.id.widget_tap_overlay, wakePi);
            }

            manager.updateAppWidget(widgetId, views);
        } catch (Exception e) {
            // Fail silently - do not crash the widget host
        }
    }

    // ============ PLAY/PAUSE TOGGLE ============

    private void handleToggle(Context context, long mantraId) {
        MeditationPlayerManager player = MeditationPlayerManager.getInstance(context);

        if (player.isCurrentlyPlaying() && player.getCurrentMantraId() == mantraId) {
            // Same mantra playing -> pause
            Intent svcIntent = new Intent(context, MeditationService.class);
            svcIntent.setAction(MeditationService.ACTION_PAUSE);
            startServiceSafe(context, svcIntent);
            player.pausePlayback();

        } else if (!player.isCurrentlyPlaying()
                && player.getCurrentMantraId() == mantraId) {
            // Same mantra paused -> resume
            Intent svcIntent = new Intent(context, MeditationService.class);
            svcIntent.setAction(MeditationService.ACTION_RESUME);
            svcIntent.putExtra(MeditationService.EXTRA_MANTRA_ID, mantraId);
            startServiceSafe(context, svcIntent);
            player.resumePlayback();

        } else {
            // Different mantra or fresh start
            if (player.isCurrentlyPlaying()) {
                player.stopPlayback();
            }
            startMantraFresh(context, player, mantraId);
        }
    }

    private void startMantraFresh(Context context, MeditationPlayerManager player, long mantraId) {
        NotesRepository repo = NotesRepository.getInstance(context);
        Mantra mantra = repo.getMantraById(mantraId);
        if (mantra == null) return;

        String audioPath = mantra.getAudioPath();
        if (audioPath == null || audioPath.length() == 0) return;

        String today = MeditationPlayerManager.getTodayDateString();
        repo.getOrCreateDailySession(mantraId, today);
        float speed = repo.getSessionSpeed(mantraId, today);

        final Context appCtx = context.getApplicationContext();
        player.setListener(new MeditationPlayerManager.PlaybackListener() {
            public void onCountIncremented(long mid, int newCount) {
                refreshAllWidgets(appCtx);
            }
            public void onPlaybackStarted(long mid) {
                refreshAllWidgets(appCtx);
            }
            public void onPlaybackStopped(long mid) {
                refreshAllWidgets(appCtx);
            }
            public void onPlaybackError(long mid, String message) {
                refreshAllWidgets(appCtx);
            }
        });

        Intent svcIntent = new Intent(context, MeditationService.class);
        svcIntent.setAction(MeditationService.ACTION_START);
        svcIntent.putExtra(MeditationService.EXTRA_MANTRA_ID, mantraId);
        startServiceSafe(context, svcIntent);

        player.startPlayback(mantraId, audioPath, speed);
    }

    // ============ SPEED CYCLE ============

    private void handleSpeedCycle(Context context, long mantraId) {
        String today = MeditationPlayerManager.getTodayDateString();
        NotesRepository repo = NotesRepository.getInstance(context);
        float current = repo.getSessionSpeed(mantraId, today);

        float next;
        if (current < 1.4f) next = 1.5f;
        else if (current < 1.9f) next = 2.0f;
        else if (current < 2.4f) next = 2.5f;
        else if (current < 2.9f) next = 3.0f;
        else next = 1.0f;

        repo.updateSessionSpeed(mantraId, today, next);

        MeditationPlayerManager player = MeditationPlayerManager.getInstance(context);
        if (player.isCurrentlyPlaying() && player.getCurrentMantraId() == mantraId) {
            player.setSpeed(next);
        }
    }

    // ============ FADE / WAKE STATE ============

    private boolean isActiveState(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        return prefs.getBoolean(KEY_IS_ACTIVE, false);
    }

    private void setActiveState(Context context, boolean active) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putBoolean(KEY_IS_ACTIVE, active);
        editor.apply();
    }

    /**
     * Schedule auto-fade after FADE_DELAY_MS using AlarmManager.
     * Cancels any previously scheduled fade first.
     */
    private void scheduleFade(Context context) {
        AlarmManager alarmManager = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
        if (alarmManager == null) return;

        Intent fadeIntent = new Intent(context, MeditationWidgetProvider.class);
        fadeIntent.setAction(ACTION_WIDGET_FADE);
        int fadeFlags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= 31) {
            fadeFlags = fadeFlags | 0x04000000; // FLAG_IMMUTABLE = 0x04000000
        }
        PendingIntent fadePi = PendingIntent.getBroadcast(context, 4000,
                fadeIntent, fadeFlags);

        // Cancel previous
        alarmManager.cancel(fadePi);

        // Schedule new fade
        long triggerAt = SystemClock.elapsedRealtime() + FADE_DELAY_MS;
        alarmManager.set(AlarmManager.ELAPSED_REALTIME, triggerAt, fadePi);
    }

    // ============ REFRESH ============

    public static void refreshAllWidgets(Context context) {
        try {
            AppWidgetManager manager = AppWidgetManager.getInstance(context);
            ComponentName component = new ComponentName(context, MeditationWidgetProvider.class);
            int[] ids = manager.getAppWidgetIds(component);
            if (ids != null && ids.length > 0) {
                Intent updateIntent = new Intent(context, MeditationWidgetProvider.class);
                updateIntent.setAction(AppWidgetManager.ACTION_APPWIDGET_UPDATE);
                updateIntent.putExtra(AppWidgetManager.EXTRA_APPWIDGET_IDS, ids);
                context.sendBroadcast(updateIntent);
            }
        } catch (Exception e) {
            // Fail silently
        }
    }

    private static void startServiceSafe(Context context, Intent intent) {
        try {
            if (Build.VERSION.SDK_INT >= 26) {
                context.startForegroundService(intent);
            } else {
                context.startService(intent);
            }
        } catch (Exception e) {
            // Fail silently
        }
    }
}
