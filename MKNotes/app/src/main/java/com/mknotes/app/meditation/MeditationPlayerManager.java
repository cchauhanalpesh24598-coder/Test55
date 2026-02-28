package com.mknotes.app.meditation;

import android.content.Context;
import android.content.Intent;
import android.media.AudioAttributes;
import android.media.AudioFocusRequest;
import android.media.AudioManager;
import android.media.MediaPlayer;
import android.os.Build;
import android.os.Handler;
import android.telephony.PhoneStateListener;
import android.telephony.TelephonyManager;

import android.appwidget.AppWidgetManager;
import android.content.ComponentName;

import com.mknotes.app.db.NotesRepository;
import com.mknotes.app.model.Mantra;
import com.mknotes.app.util.SessionManager;
import com.mknotes.app.widget.MeditationWidgetProvider;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Central meditation playback engine.
 * - Loop playback with count increment on each completion
 * - Count stored centrally in DailySession table (not UI-driven)
 * - Broadcasts MEDITATION_COUNT_UPDATED for UI/widget refresh
 * - Speed control (1x, 1.5x, 2x, 2.5x, 3x)
 * - AudioFocus management (pause on call, resume after)
 * - One mantra at a time (auto-stop previous)
 * - Midnight date change handling
 *
 * Pure Java, no AndroidX, no lambda - AIDE compatible.
 */
public class MeditationPlayerManager {

    public static final String ACTION_COUNT_UPDATED = "com.mknotes.app.MEDITATION_COUNT_UPDATED";
    public static final String ACTION_PLAYBACK_STATE_CHANGED = "com.mknotes.app.MEDITATION_STATE_CHANGED";
    public static final String EXTRA_MANTRA_ID = "mantra_id";
    public static final String EXTRA_NEW_COUNT = "new_count";
    public static final String EXTRA_IS_PLAYING = "is_playing";
    public static final String EXTRA_SESSION_DATE = "session_date";

    private static MeditationPlayerManager sInstance;

    private Context context;
    private MediaPlayer mediaPlayer;
    private AudioManager audioManager;
    private AudioFocusRequest focusRequest;
    private TelephonyManager telephonyManager;
    private PhoneStateListener phoneStateListener;

    private long currentMantraId = -1;
    private String currentAudioPath = "";
    private float currentSpeed = 1.0f;
    private boolean isPlaying = false;
    private boolean wasPlayingBeforeCall = false;
    private boolean hasFocus = false;
    private String currentSessionDate = "";

    private PlaybackListener listener;
    private Handler handler;
    private Runnable midnightChecker;

    public interface PlaybackListener {
        void onCountIncremented(long mantraId, int newCount);
        void onPlaybackStarted(long mantraId);
        void onPlaybackStopped(long mantraId);
        void onPlaybackError(long mantraId, String message);
    }

    public static synchronized MeditationPlayerManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new MeditationPlayerManager(context.getApplicationContext());
        }
        return sInstance;
    }

    private MeditationPlayerManager(Context context) {
        this.context = context;
        this.audioManager = (AudioManager) context.getSystemService(Context.AUDIO_SERVICE);
        this.handler = new Handler();
        this.currentSessionDate = getTodayDateString();
        setupPhoneStateListener();
    }

    public void setListener(PlaybackListener listener) {
        this.listener = listener;
    }

    public boolean isCurrentlyPlaying() {
        return isPlaying;
    }

    public long getCurrentMantraId() {
        return currentMantraId;
    }

    public String getCurrentSessionDate() {
        return currentSessionDate;
    }

    /**
     * Resolve a raw resource ID from a "raw:filename" audio path.
     * Returns 0 if not a raw resource path.
     */
    private int resolveRawResId(String audioPath) {
        if (audioPath != null && audioPath.startsWith("raw:")) {
            String rawName = audioPath.substring(4);
            try {
                int resId = context.getResources().getIdentifier(rawName, "raw", context.getPackageName());
                return resId;
            } catch (Exception e) {
                return 0;
            }
        }
        return 0;
    }

    /**
     * Start playing a mantra audio in loop.
     * If another mantra is playing, it will be stopped first.
     * Supports both file paths and raw resource paths (format: "raw:filename").
     */
    public void startPlayback(long mantraId, String audioPath, float speed) {
        // Stop any current playback
        if (isPlaying) {
            stopPlayback();
        }

        if (audioPath == null || audioPath.length() == 0) {
            if (listener != null) {
                listener.onPlaybackError(mantraId, "No audio file set");
            }
            return;
        }

        // Check if this is a raw resource path
        int rawResId = resolveRawResId(audioPath);
        boolean isRawResource = rawResId > 0;

        if (!isRawResource) {
            File audioFile = new File(audioPath);
            if (!audioFile.exists()) {
                if (listener != null) {
                    listener.onPlaybackError(mantraId, "Audio file not found");
                }
                return;
            }
        }

        currentMantraId = mantraId;
        currentAudioPath = audioPath;
        currentSpeed = speed;
        currentSessionDate = getTodayDateString();

        // Ensure daily session exists
        NotesRepository repo = NotesRepository.getInstance(context);
        repo.getOrCreateDailySession(mantraId, currentSessionDate);

        if (!requestAudioFocus()) {
            if (listener != null) {
                listener.onPlaybackError(mantraId, "Cannot get audio focus");
            }
            return;
        }

        try {
            if (isRawResource) {
                mediaPlayer = MediaPlayer.create(context, rawResId);
                if (mediaPlayer == null) {
                    if (listener != null) {
                        listener.onPlaybackError(mantraId, "Cannot load audio resource");
                    }
                    return;
                }
                mediaPlayer.setLooping(false);
            } else {
                mediaPlayer = new MediaPlayer();
                mediaPlayer.setDataSource(audioPath);
                mediaPlayer.setLooping(false); // We handle loop manually for count
            }

            mediaPlayer.setOnCompletionListener(new MediaPlayer.OnCompletionListener() {
                public void onCompletion(MediaPlayer mp) {
                    // Check for midnight date change
                    String today = getTodayDateString();
                    if (!today.equals(currentSessionDate)) {
                        handleMidnightReset(today);
                    }

                    // Central count increment in DB
                    NotesRepository repo = NotesRepository.getInstance(context);
                    int newCount = repo.incrementSessionCount(currentMantraId, currentSessionDate);

                    // Log timestamp for time-slot based graph analysis
                    repo.insertMantraCountLog(currentMantraId, currentSessionDate,
                            System.currentTimeMillis());

                    // Also save to mantra_history for permanent record
                    repo.saveMantraHistory(currentMantraId, currentSessionDate, newCount);

                    // Broadcast count update for UI and widget
                    broadcastCountUpdate(currentMantraId, newCount, currentSessionDate);

                    // Notify direct listener
                    if (listener != null) {
                        listener.onCountIncremented(currentMantraId, newCount);
                    }

                    // Update widgets
                    updateWidgets();

                    // Restart for loop
                    if (isPlaying && mediaPlayer != null) {
                        try {
                            mediaPlayer.seekTo(0);
                            mediaPlayer.start();
                            if (Build.VERSION.SDK_INT >= 23) {
                                mediaPlayer.setPlaybackParams(
                                        mediaPlayer.getPlaybackParams().setSpeed(currentSpeed));
                            }
                        } catch (Exception e) {
                            isPlaying = false;
                            SessionManager.getInstance(context).setMeditationPlaying(false);
                            releasePlayer();
                            if (listener != null) {
                                listener.onPlaybackStopped(currentMantraId);
                            }
                            broadcastStateChange(currentMantraId, false);
                        }
                    }
                }
            });

            mediaPlayer.setOnErrorListener(new MediaPlayer.OnErrorListener() {
                public boolean onError(MediaPlayer mp, int what, int extra) {
                    stopPlayback();
                    if (listener != null) {
                        listener.onPlaybackError(currentMantraId, "Playback error");
                    }
                    return true;
                }
            });

            if (!isRawResource) {
                mediaPlayer.prepare();
            }

            if (Build.VERSION.SDK_INT >= 23) {
                try {
                    mediaPlayer.setPlaybackParams(
                            mediaPlayer.getPlaybackParams().setSpeed(speed));
                } catch (Exception e) { }
            }

            mediaPlayer.start();
            isPlaying = true;

            // Notify SessionManager that meditation is actively playing.
            // This suspends session timeout until playback stops.
            SessionManager.getInstance(context).setMeditationPlaying(true);

            if (listener != null) {
                listener.onPlaybackStarted(mantraId);
            }

            broadcastStateChange(mantraId, true);
            startMidnightChecker();

        } catch (Exception e) {
            releasePlayer();
            if (listener != null) {
                listener.onPlaybackError(mantraId, "Cannot play audio");
            }
        }
    }

    /**
     * Stop current playback.
     */
    public void stopPlayback() {
        long stoppedId = currentMantraId;
        isPlaying = false;
        wasPlayingBeforeCall = false;

        // Immediately notify SessionManager that meditation is no longer playing.
        // Session timeout logic resumes from this point.
        SessionManager.getInstance(context).setMeditationPlaying(false);

        stopMidnightChecker();
        releasePlayer();
        abandonAudioFocus();

        currentMantraId = -1;

        if (stoppedId != -1) {
            if (listener != null) {
                listener.onPlaybackStopped(stoppedId);
            }
            broadcastStateChange(stoppedId, false);
        }
    }

    /**
     * Toggle play/pause - used by media buttons and widget.
     */
    public void togglePlayback() {
        if (isPlaying) {
            pausePlayback();
        } else {
            resumePlayback();
        }
    }

    /**
     * Pause playback without releasing player.
     */
    public void pausePlayback() {
        if (mediaPlayer != null && isPlaying) {
            try {
                mediaPlayer.pause();
                isPlaying = false;
                // Paused = not actively playing, so session timeout resumes
                SessionManager.getInstance(context).setMeditationPlaying(false);
                broadcastStateChange(currentMantraId, false);
                if (listener != null) {
                    listener.onPlaybackStopped(currentMantraId);
                }
            } catch (Exception e) { }
        }
    }

    /**
     * Resume paused playback.
     */
    public void resumePlayback() {
        if (mediaPlayer != null && !isPlaying && currentMantraId != -1) {
            // Check date change before resuming
            String today = getTodayDateString();
            if (!today.equals(currentSessionDate)) {
                handleMidnightReset(today);
            }

            try {
                mediaPlayer.start();
                if (Build.VERSION.SDK_INT >= 23) {
                    mediaPlayer.setPlaybackParams(
                            mediaPlayer.getPlaybackParams().setSpeed(currentSpeed));
                }
                isPlaying = true;
                // Resumed = actively playing, suspend session timeout
                SessionManager.getInstance(context).setMeditationPlaying(true);
                broadcastStateChange(currentMantraId, true);
                if (listener != null) {
                    listener.onPlaybackStarted(currentMantraId);
                }
                startMidnightChecker();
            } catch (Exception e) { }
        }
    }

    /**
     * Change playback speed while playing.
     */
    public void setSpeed(float speed) {
        currentSpeed = speed;
        if (mediaPlayer != null && isPlaying) {
            try {
                if (Build.VERSION.SDK_INT >= 23) {
                    mediaPlayer.setPlaybackParams(
                            mediaPlayer.getPlaybackParams().setSpeed(speed));
                }
            } catch (Exception e) { }
        }
    }

    public float getSpeed() {
        return currentSpeed;
    }

    /**
     * Handle midnight date change: close old session, start new date session.
     */
    private void handleMidnightReset(String newDate) {
        NotesRepository repo = NotesRepository.getInstance(context);

        // Save final count to history for old date
        int oldCount = repo.getSessionCount(currentMantraId, currentSessionDate);
        if (oldCount > 0) {
            repo.saveMantraHistory(currentMantraId, currentSessionDate, oldCount);
        }

        // Switch to new date
        currentSessionDate = newDate;

        // Create new session for new date
        repo.getOrCreateDailySession(currentMantraId, newDate);

        // Broadcast to refresh UI
        broadcastCountUpdate(currentMantraId, 0, newDate);
        updateWidgets();
    }

    /**
     * Periodically check if date has changed (midnight boundary).
     */
    private void startMidnightChecker() {
        stopMidnightChecker();
        midnightChecker = new Runnable() {
            public void run() {
                if (isPlaying) {
                    String today = getTodayDateString();
                    if (!today.equals(currentSessionDate)) {
                        handleMidnightReset(today);
                    }
                    handler.postDelayed(this, 30000); // Check every 30 seconds
                }
            }
        };
        handler.postDelayed(midnightChecker, 30000);
    }

    private void stopMidnightChecker() {
        if (midnightChecker != null) {
            handler.removeCallbacks(midnightChecker);
            midnightChecker = null;
        }
    }

    private void releasePlayer() {
        if (mediaPlayer != null) {
            try {
                if (mediaPlayer.isPlaying()) {
                    mediaPlayer.stop();
                }
            } catch (Exception e) { }
            try {
                mediaPlayer.release();
            } catch (Exception e) { }
            mediaPlayer = null;
        }
    }

    // ============ BROADCASTS ============

    private void broadcastCountUpdate(long mantraId, int newCount, String date) {
        try {
            Intent intent = new Intent(ACTION_COUNT_UPDATED);
            intent.putExtra(EXTRA_MANTRA_ID, mantraId);
            intent.putExtra(EXTRA_NEW_COUNT, newCount);
            intent.putExtra(EXTRA_SESSION_DATE, date);
            context.sendBroadcast(intent);
        } catch (Exception e) { }
    }

    private void broadcastStateChange(long mantraId, boolean playing) {
        try {
            Intent intent = new Intent(ACTION_PLAYBACK_STATE_CHANGED);
            intent.putExtra(EXTRA_MANTRA_ID, mantraId);
            intent.putExtra(EXTRA_IS_PLAYING, playing);
            context.sendBroadcast(intent);
        } catch (Exception e) { }
    }

    // ============ AUDIO FOCUS ============

    private boolean requestAudioFocus() {
        if (audioManager == null) return false;

        int result;
        if (Build.VERSION.SDK_INT >= 26) {
            AudioAttributes attrs = new AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_MEDIA)
                    .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC)
                    .build();

            focusRequest = new AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN)
                    .setAudioAttributes(attrs)
                    .setOnAudioFocusChangeListener(new AudioManager.OnAudioFocusChangeListener() {
                        public void onAudioFocusChange(int focusChange) {
                            handleAudioFocusChange(focusChange);
                        }
                    })
                    .build();

            result = audioManager.requestAudioFocus(focusRequest);
        } else {
            result = audioManager.requestAudioFocus(
                    new AudioManager.OnAudioFocusChangeListener() {
                        public void onAudioFocusChange(int focusChange) {
                            handleAudioFocusChange(focusChange);
                        }
                    },
                    AudioManager.STREAM_MUSIC,
                    AudioManager.AUDIOFOCUS_GAIN);
        }

        hasFocus = (result == AudioManager.AUDIOFOCUS_REQUEST_GRANTED);
        return hasFocus;
    }

    private void abandonAudioFocus() {
        if (audioManager == null) return;

        if (Build.VERSION.SDK_INT >= 26 && focusRequest != null) {
            audioManager.abandonAudioFocusRequest(focusRequest);
        }
        hasFocus = false;
    }

    private void handleAudioFocusChange(int focusChange) {
        switch (focusChange) {
            case AudioManager.AUDIOFOCUS_LOSS:
                // Permanent loss - stop playback completely
                wasPlayingBeforeCall = false;
                stopPlayback();
                // Stop the foreground service
                try {
                    Intent svcIntent = new Intent(context,
                            com.mknotes.app.service.MeditationService.class);
                    svcIntent.setAction(com.mknotes.app.service.MeditationService.ACTION_STOP);
                    context.startService(svcIntent);
                } catch (Exception e) { }
                break;

            case AudioManager.AUDIOFOCUS_LOSS_TRANSIENT:
                // Temporary loss (incoming call) - pause, will resume on GAIN
                if (isPlaying && mediaPlayer != null) {
                    wasPlayingBeforeCall = true;
                    try {
                        mediaPlayer.pause();
                        isPlaying = false;
                        // Paused due to transient loss, session timeout resumes
                        SessionManager.getInstance(context).setMeditationPlaying(false);
                        broadcastStateChange(currentMantraId, false);
                    } catch (Exception e) { }
                }
                break;

            case AudioManager.AUDIOFOCUS_GAIN:
                // Resume if we were playing before (call ended)
                if (wasPlayingBeforeCall && mediaPlayer != null) {
                    try {
                        mediaPlayer.setVolume(1.0f, 1.0f);
                        mediaPlayer.start();
                        if (Build.VERSION.SDK_INT >= 23) {
                            mediaPlayer.setPlaybackParams(
                                    mediaPlayer.getPlaybackParams().setSpeed(currentSpeed));
                        }
                        isPlaying = true;
                        // Resumed playing, suspend session timeout again
                        SessionManager.getInstance(context).setMeditationPlaying(true);
                        broadcastStateChange(currentMantraId, true);
                        if (listener != null) {
                            listener.onPlaybackStarted(currentMantraId);
                        }
                    } catch (Exception e) { }
                    wasPlayingBeforeCall = false;
                }
                break;

            case AudioManager.AUDIOFOCUS_LOSS_TRANSIENT_CAN_DUCK:
                // Lower volume temporarily
                if (mediaPlayer != null) {
                    try {
                        mediaPlayer.setVolume(0.3f, 0.3f);
                    } catch (Exception e) { }
                }
                break;
        }
    }

    // ============ PHONE CALL HANDLING ============

    private void setupPhoneStateListener() {
        try {
            telephonyManager = (TelephonyManager)
                    context.getSystemService(Context.TELEPHONY_SERVICE);
            if (telephonyManager != null) {
                phoneStateListener = new PhoneStateListener() {
                    public void onCallStateChanged(int state, String phoneNumber) {
                        switch (state) {
                            case TelephonyManager.CALL_STATE_RINGING:
                            case TelephonyManager.CALL_STATE_OFFHOOK:
                                // Incoming or active call - pause
                                if (isPlaying && mediaPlayer != null) {
                                    wasPlayingBeforeCall = true;
                                    try {
                                        mediaPlayer.pause();
                                        isPlaying = false;
                                        SessionManager.getInstance(context).setMeditationPlaying(false);
                                        broadcastStateChange(currentMantraId, false);
                                    } catch (Exception e) { }
                                }
                                break;

                            case TelephonyManager.CALL_STATE_IDLE:
                                // Call ended - resume
                                if (wasPlayingBeforeCall && mediaPlayer != null) {
                                    try {
                                        mediaPlayer.start();
                                        if (Build.VERSION.SDK_INT >= 23) {
                                            mediaPlayer.setPlaybackParams(
                                                    mediaPlayer.getPlaybackParams()
                                                            .setSpeed(currentSpeed));
                                        }
                                        isPlaying = true;
                                        SessionManager.getInstance(context).setMeditationPlaying(true);
                                        broadcastStateChange(currentMantraId, true);
                                        if (listener != null) {
                                            listener.onPlaybackStarted(currentMantraId);
                                        }
                                    } catch (Exception e) { }
                                    wasPlayingBeforeCall = false;
                                }
                                break;
                        }
                    }
                };
                telephonyManager.listen(phoneStateListener, PhoneStateListener.LISTEN_CALL_STATE);
            }
        } catch (Exception e) { }
    }

    // ============ MEDIA BUTTON HANDLING ============

    /**
     * Called from MediaButtonReceiver - toggle play/pause.
     */
    public void handleMediaButton() {
        if (isPlaying) {
            pausePlayback();
            // Update service notification
            try {
                Intent svcIntent = new Intent(context,
                        com.mknotes.app.service.MeditationService.class);
                svcIntent.setAction(com.mknotes.app.service.MeditationService.ACTION_PAUSE);
                context.startService(svcIntent);
            } catch (Exception e) { }
        } else if (currentMantraId != -1 && mediaPlayer != null) {
            resumePlayback();
            try {
                Intent svcIntent = new Intent(context,
                        com.mknotes.app.service.MeditationService.class);
                svcIntent.setAction(com.mknotes.app.service.MeditationService.ACTION_RESUME);
                svcIntent.putExtra(com.mknotes.app.service.MeditationService.EXTRA_MANTRA_ID,
                        currentMantraId);
                if (Build.VERSION.SDK_INT >= 26) {
                    context.startForegroundService(svcIntent);
                } else {
                    context.startService(svcIntent);
                }
            } catch (Exception e) { }
        }
        updateWidgets();
    }

    /**
     * Update all meditation widgets to reflect current state.
     */
    private void updateWidgets() {
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
        } catch (Exception e) { }
    }

    // ============ DAILY RESET HELPER ============

    public static String getTodayDateString() {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
        return sdf.format(new Date());
    }

    public static boolean needsDailyReset(String lastCountDate) {
        if (lastCountDate == null || lastCountDate.length() == 0) {
            return true;
        }
        return !lastCountDate.equals(getTodayDateString());
    }

    public void cleanup() {
        stopPlayback();
        // Ensure meditation flag is cleared on cleanup
        SessionManager.getInstance(context).setMeditationPlaying(false);
        stopMidnightChecker();
        if (telephonyManager != null && phoneStateListener != null) {
            try {
                telephonyManager.listen(phoneStateListener, PhoneStateListener.LISTEN_NONE);
            } catch (Exception e) { }
        }
    }
}
