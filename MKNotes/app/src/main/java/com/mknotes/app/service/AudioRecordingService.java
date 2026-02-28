package com.mknotes.app.service;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.media.MediaRecorder;
import android.os.Binder;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;

import com.mknotes.app.R;

import java.io.File;

/**
 * Service-based audio recording with pause/resume support.
 * Uses MediaRecorder with AAC encoding to .m4a files.
 * Java 7 compatible - no lambdas.
 */
public class AudioRecordingService extends Service {

    public static final String CHANNEL_ID = "mknotes_recording";
    public static final int NOTIFICATION_ID = 1001;

    public static final int STATE_IDLE = 0;
    public static final int STATE_RECORDING = 1;
    public static final int STATE_PAUSED = 2;

    private final IBinder binder = new RecordingBinder();
    private MediaRecorder recorder;
    private int state = STATE_IDLE;
    private String outputPath;
    private long recordingStartTime;
    private long pausedDuration;
    private long pauseStartTime;
    private Handler timerHandler;
    private RecordingCallback callback;

    public interface RecordingCallback {
        void onTimerUpdate(long elapsedMs);
        void onRecordingError(String message);
    }

    public class RecordingBinder extends Binder {
        public AudioRecordingService getService() {
            return AudioRecordingService.this;
        }
    }

    public IBinder onBind(Intent intent) {
        return binder;
    }

    public void onCreate() {
        super.onCreate();
        timerHandler = new Handler();
        createNotificationChannel();
    }

    public void onDestroy() {
        super.onDestroy();
        stopTimerUpdates();
        releaseRecorder();
    }

    public void setCallback(RecordingCallback callback) {
        this.callback = callback;
    }

    public int getState() {
        return state;
    }

    public String getOutputPath() {
        return outputPath;
    }

    public long getElapsedTime() {
        if (state == STATE_RECORDING) {
            return System.currentTimeMillis() - recordingStartTime - pausedDuration;
        } else if (state == STATE_PAUSED) {
            return pauseStartTime - recordingStartTime - pausedDuration;
        }
        return 0;
    }

    /**
     * Start recording to the given file path.
     */
    public boolean startRecording(String filePath) {
        if (state != STATE_IDLE) return false;

        outputPath = filePath;
        try {
            recorder = new MediaRecorder();
            recorder.setAudioSource(MediaRecorder.AudioSource.MIC);
            recorder.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4);
            recorder.setAudioEncoder(MediaRecorder.AudioEncoder.AAC);
            recorder.setAudioEncodingBitRate(128000);
            recorder.setAudioSamplingRate(44100);
            recorder.setOutputFile(outputPath);
            recorder.prepare();
            recorder.start();

            state = STATE_RECORDING;
            recordingStartTime = System.currentTimeMillis();
            pausedDuration = 0;

            startForegroundNotification();
            startTimerUpdates();
            return true;
        } catch (Exception e) {
            releaseRecorder();
            state = STATE_IDLE;
            if (callback != null) {
                callback.onRecordingError("Failed to start recording: " + e.getMessage());
            }
            return false;
        }
    }

    /**
     * Pause recording (API 24+).
     */
    public boolean pauseRecording() {
        if (state != STATE_RECORDING) return false;
        if (Build.VERSION.SDK_INT >= 24) {
            try {
                recorder.pause();
                state = STATE_PAUSED;
                pauseStartTime = System.currentTimeMillis();
                stopTimerUpdates();
                return true;
            } catch (Exception e) {
                if (callback != null) {
                    callback.onRecordingError("Failed to pause: " + e.getMessage());
                }
            }
        }
        return false;
    }

    /**
     * Resume recording from pause (API 24+).
     */
    public boolean resumeRecording() {
        if (state != STATE_PAUSED) return false;
        if (Build.VERSION.SDK_INT >= 24) {
            try {
                recorder.resume();
                pausedDuration += System.currentTimeMillis() - pauseStartTime;
                state = STATE_RECORDING;
                startTimerUpdates();
                return true;
            } catch (Exception e) {
                if (callback != null) {
                    callback.onRecordingError("Failed to resume: " + e.getMessage());
                }
            }
        }
        return false;
    }

    /**
     * Stop recording and finalize the file.
     * Returns the duration in milliseconds.
     */
    public long stopRecording() {
        long duration = getElapsedTime();
        stopTimerUpdates();

        if (recorder != null) {
            try {
                if (state == STATE_PAUSED && Build.VERSION.SDK_INT >= 24) {
                    recorder.resume();
                }
                recorder.stop();
            } catch (Exception e) {
                // Ignore stop errors
            }
            releaseRecorder();
        }

        state = STATE_IDLE;
        stopForeground(true);
        return duration;
    }

    /**
     * Discard recording - stop and delete file.
     */
    public void discardRecording() {
        stopRecording();
        if (outputPath != null) {
            File f = new File(outputPath);
            if (f.exists()) {
                f.delete();
            }
            outputPath = null;
        }
    }

    private void releaseRecorder() {
        if (recorder != null) {
            try {
                recorder.release();
            } catch (Exception e) {
                // Ignore
            }
            recorder = null;
        }
    }

    private void startTimerUpdates() {
        timerHandler.removeCallbacksAndMessages(null);
        timerHandler.post(timerRunnable);
    }

    private void stopTimerUpdates() {
        if (timerHandler != null) {
            timerHandler.removeCallbacksAndMessages(null);
        }
    }

    private Runnable timerRunnable = new Runnable() {
        public void run() {
            if (callback != null && state == STATE_RECORDING) {
                callback.onTimerUpdate(getElapsedTime());
            }
            if (state == STATE_RECORDING) {
                timerHandler.postDelayed(this, 100);
            }
        }
    };

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID, "Audio Recording",
                    NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("Shows while recording audio");
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (nm != null) {
                nm.createNotificationChannel(channel);
            }
        }
    }

    private void startForegroundNotification() {
        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            builder = new Notification.Builder(this, CHANNEL_ID);
        } else {
            builder = new Notification.Builder(this);
        }
        builder.setContentTitle("MK Notes")
                .setContentText("Recording audio...")
                .setSmallIcon(R.drawable.ic_mic)
                .setOngoing(true);

        startForeground(NOTIFICATION_ID, builder.build());
    }
}
