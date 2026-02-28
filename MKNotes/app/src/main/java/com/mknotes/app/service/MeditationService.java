package com.mknotes.app.service;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

import com.mknotes.app.R;
import com.mknotes.app.db.NotesRepository;
import com.mknotes.app.meditation.MeditationPlayerManager;
import com.mknotes.app.model.Mantra;

/**
 * Foreground service for meditation playback.
 * Keeps mantra playing when app is in background.
 * Shows notification with mantra name.
 * Supports: START, STOP, PAUSE, RESUME, TOGGLE actions.
 * Pure Java, no AndroidX, no lambda - AIDE compatible.
 */
public class MeditationService extends Service {

    public static final String ACTION_START = "com.mknotes.app.meditation.START";
    public static final String ACTION_STOP = "com.mknotes.app.meditation.STOP";
    public static final String ACTION_PAUSE = "com.mknotes.app.meditation.PAUSE";
    public static final String ACTION_RESUME = "com.mknotes.app.meditation.RESUME";
    public static final String ACTION_TOGGLE = "com.mknotes.app.meditation.TOGGLE";
    public static final String ACTION_SPEED_CYCLE = "com.mknotes.app.meditation.SPEED_CYCLE";
    public static final String EXTRA_MANTRA_ID = "mantra_id";

    private static final String CHANNEL_ID = "meditation_channel";
    private static final int NOTIFICATION_ID = 9001;

    public IBinder onBind(Intent intent) {
        return null;
    }

    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            stopSelf();
            return START_NOT_STICKY;
        }

        String action = intent.getAction();

        if (ACTION_START.equals(action)) {
            long mantraId = intent.getLongExtra(EXTRA_MANTRA_ID, -1);
            if (mantraId != -1) {
                NotesRepository repo = NotesRepository.getInstance(this);
                Mantra mantra = repo.getMantraById(mantraId);
                if (mantra != null) {
                    showForegroundNotification(mantra.getName());
                }
            } else {
                showForegroundNotification("Meditation");
            }

        } else if (ACTION_STOP.equals(action)) {
            MeditationPlayerManager player = MeditationPlayerManager.getInstance(this);
            player.stopPlayback();
            stopForeground(true);
            stopSelf();

        } else if (ACTION_PAUSE.equals(action)) {
            MeditationPlayerManager player = MeditationPlayerManager.getInstance(this);
            player.pausePlayback();
            // Update notification to show paused state
            long mantraId = player.getCurrentMantraId();
            if (mantraId != -1) {
                NotesRepository repo = NotesRepository.getInstance(this);
                Mantra mantra = repo.getMantraById(mantraId);
                if (mantra != null) {
                    showForegroundNotification(mantra.getName() + " (Paused)");
                }
            }

        } else if (ACTION_RESUME.equals(action)) {
            MeditationPlayerManager player = MeditationPlayerManager.getInstance(this);
            long mantraId = intent.getLongExtra(EXTRA_MANTRA_ID, player.getCurrentMantraId());
            if (mantraId != -1) {
                if (player.getCurrentMantraId() == mantraId) {
                    // Resume same mantra
                    player.resumePlayback();
                } else {
                    // Start new mantra
                    NotesRepository repo = NotesRepository.getInstance(this);
                    Mantra mantra = repo.getMantraById(mantraId);
                    if (mantra != null) {
                        String today = MeditationPlayerManager.getTodayDateString();
                        repo.getOrCreateDailySession(mantraId, today);
                        player.startPlayback(mantra.getId(),
                                mantra.getAudioPath(), mantra.getPlaybackSpeed());
                    }
                }
                NotesRepository repo = NotesRepository.getInstance(this);
                Mantra mantra = repo.getMantraById(mantraId);
                if (mantra != null) {
                    showForegroundNotification(mantra.getName());
                }
            }

        } else if (ACTION_TOGGLE.equals(action)) {
            MeditationPlayerManager player = MeditationPlayerManager.getInstance(this);
            if (player.isCurrentlyPlaying()) {
                // Pause
                player.pausePlayback();
                long mantraId = player.getCurrentMantraId();
                if (mantraId != -1) {
                    NotesRepository repo = NotesRepository.getInstance(this);
                    Mantra mantra = repo.getMantraById(mantraId);
                    if (mantra != null) {
                        showForegroundNotification(mantra.getName() + " (Paused)");
                    }
                }
            } else {
                long mantraId = intent.getLongExtra(EXTRA_MANTRA_ID, player.getCurrentMantraId());
                if (mantraId != -1 && player.getCurrentMantraId() == mantraId) {
                    // Resume paused mantra
                    player.resumePlayback();
                    NotesRepository repo = NotesRepository.getInstance(this);
                    Mantra mantra = repo.getMantraById(mantraId);
                    if (mantra != null) {
                        showForegroundNotification(mantra.getName());
                    }
                } else if (mantraId != -1) {
                    // Start fresh
                    NotesRepository repo = NotesRepository.getInstance(this);
                    Mantra mantra = repo.getMantraById(mantraId);
                    if (mantra != null) {
                        String today = MeditationPlayerManager.getTodayDateString();
                        repo.getOrCreateDailySession(mantraId, today);
                        player.startPlayback(mantra.getId(),
                                mantra.getAudioPath(), mantra.getPlaybackSpeed());
                        showForegroundNotification(mantra.getName());
                    }
                }
            }

        } else if (ACTION_SPEED_CYCLE.equals(action)) {
            MeditationPlayerManager player = MeditationPlayerManager.getInstance(this);
            float current = player.getSpeed();
            float next;
            if (current < 1.4f) next = 1.5f;
            else if (current < 1.9f) next = 2.0f;
            else if (current < 2.4f) next = 2.5f;
            else if (current < 2.9f) next = 3.0f;
            else next = 1.0f;
            player.setSpeed(next);

            // Save speed to session
            long mantraId = player.getCurrentMantraId();
            if (mantraId != -1) {
                String today = MeditationPlayerManager.getTodayDateString();
                NotesRepository repo = NotesRepository.getInstance(this);
                repo.updateSessionSpeed(mantraId, today, next);
            }
        }

        return START_STICKY;
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "Meditation Playback",
                    NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("Shows when mantra is playing");
            channel.setSound(null, null);
            NotificationManager nm = (NotificationManager)
                    getSystemService(NOTIFICATION_SERVICE);
            if (nm != null) {
                nm.createNotificationChannel(channel);
            }
        }
    }

    private void showForegroundNotification(String mantraName) {
        Intent stopIntent = new Intent(this, MeditationService.class);
        stopIntent.setAction(ACTION_STOP);
        int piFlags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= 31) {
            piFlags = piFlags | 0x04000000; // FLAG_IMMUTABLE = 0x04000000
        }
        PendingIntent stopPi = PendingIntent.getService(this, 0, stopIntent, piFlags);

        Intent toggleIntent = new Intent(this, MeditationService.class);
        toggleIntent.setAction(ACTION_TOGGLE);
        PendingIntent togglePi = PendingIntent.getService(this, 1, toggleIntent, piFlags);

        MeditationPlayerManager player = MeditationPlayerManager.getInstance(this);
        boolean playing = player.isCurrentlyPlaying();

        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= 26) {
            builder = new Notification.Builder(this, CHANNEL_ID);
        } else {
            builder = new Notification.Builder(this);
        }

        builder.setContentTitle(playing ? "Mantra Playing" : "Mantra Paused")
                .setContentText(mantraName)
                .setSmallIcon(playing ? R.drawable.ic_play : R.drawable.ic_pause)
                .setOngoing(true)
                .addAction(playing ? R.drawable.ic_pause : R.drawable.ic_play,
                        playing ? "Pause" : "Resume", togglePi)
                .addAction(R.drawable.ic_stop, "Stop", stopPi);

        startForeground(NOTIFICATION_ID, builder.build());
    }

    public void onDestroy() {
        // Don't stop playback on service destroy if still playing
        // The player manager lives independently
        super.onDestroy();
    }
}
