package com.mknotes.app;

import android.app.Activity;
import android.app.Application;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.StrictMode;
import android.util.Log;

import com.google.firebase.FirebaseApp;
import com.google.firebase.appcheck.FirebaseAppCheck;
import com.google.firebase.appcheck.debug.DebugAppCheckProviderFactory;
import com.google.firebase.appcheck.playintegrity.PlayIntegrityAppCheckProviderFactory;

import com.mknotes.app.crypto.KeyManager;
import com.mknotes.app.db.NotesRepository;
import com.mknotes.app.util.SessionManager;

/**
 * Application class with Firebase App Check, auto-lock timer,
 * and ProcessLifecycleOwner-style foreground/background tracking.
 *
 * Firebase App Check:
 * - Debug builds: DebugAppCheckProviderFactory
 * - Release builds: PlayIntegrityAppCheckProviderFactory
 *
 * Auto-lock:
 * - When app goes to background, a 5-minute timer starts
 * - After timeout: KeyManager.lockVault() zeros DEK byte[]
 * - On foreground return after lock: user redirected to MasterPasswordActivity
 */
public class NotesApplication extends Application {

    private static final String TAG = "NotesApplication";

    public static final String CHANNEL_ID_REMINDER = "notes_reminder_channel";
    public static final String CHANNEL_ID_GENERAL = "notes_general_channel";

    /** Auto-lock timer handler */
    private Handler autoLockHandler;
    private Runnable autoLockRunnable;

    public void onCreate() {
        super.onCreate();

        // Allow file:// URIs to be shared with external apps
        StrictMode.VmPolicy.Builder builder = new StrictMode.VmPolicy.Builder();
        StrictMode.setVmPolicy(builder.build());

        createNotificationChannels();

        // Firebase initializes automatically via google-services.json plugin
        // Setup Firebase App Check
        initFirebaseAppCheck();

        // Auto-delete trash notes older than 30 days on app startup
        try {
            NotesRepository.getInstance(this).cleanupOldTrash();
        } catch (Exception e) {
            // Fail silently - don't block app startup
        }

        // Setup auto-lock handler
        autoLockHandler = new Handler(Looper.getMainLooper());
        autoLockRunnable = new Runnable() {
            public void run() {
                // Only lock if meditation is not playing
                SessionManager sm = SessionManager.getInstance(NotesApplication.this);
                if (!sm.isMeditationPlaying()) {
                    KeyManager.getInstance(NotesApplication.this).lockVault();
                    sm.clearSession();
                    Log.d(TAG, "Auto-lock: vault locked after background timeout");
                }
            }
        };

        // Register ActivityLifecycleCallbacks for session timeout tracking
        registerActivityLifecycleCallbacks(new ActivityLifecycleCallbacks() {
            private int activityCount = 0;

            public void onActivityStarted(Activity activity) {
                if (activityCount == 0) {
                    // App came to foreground - cancel pending auto-lock
                    cancelAutoLock();
                    SessionManager.getInstance(activity).onAppForegrounded();
                }
                activityCount++;
            }

            public void onActivityStopped(Activity activity) {
                activityCount--;
                if (activityCount == 0) {
                    // App went to background - schedule auto-lock
                    SessionManager.getInstance(activity).onAppBackgrounded();
                    scheduleAutoLock();
                }
            }

            public void onActivityCreated(Activity a, Bundle b) {}
            public void onActivityResumed(Activity a) {}
            public void onActivityPaused(Activity a) {}
            public void onActivitySaveInstanceState(Activity a, Bundle b) {}
            public void onActivityDestroyed(Activity a) {}
        });
    }

    /**
     * Initialize Firebase App Check.
     * Debug builds: DebugAppCheckProviderFactory (for emulators/test devices)
     * Release builds: PlayIntegrityAppCheckProviderFactory (Google Play Integrity API)
     */
    private void initFirebaseAppCheck() {
        try {
            FirebaseApp.initializeApp(this);
            FirebaseAppCheck firebaseAppCheck = FirebaseAppCheck.getInstance();
            if (BuildConfig.DEBUG) {
                firebaseAppCheck.installAppCheckProviderFactory(
                        DebugAppCheckProviderFactory.getInstance());
                Log.d(TAG, "Firebase App Check: Debug provider installed");
            } else {
                firebaseAppCheck.installAppCheckProviderFactory(
                        PlayIntegrityAppCheckProviderFactory.getInstance());
                Log.d(TAG, "Firebase App Check: Play Integrity provider installed");
            }
        } catch (Exception e) {
            Log.e(TAG, "Firebase App Check init failed: " + e.getMessage());
            // App Check failure should not crash the app
        }
    }

    /**
     * Schedule auto-lock after SESSION_TIMEOUT_MS (5 minutes).
     */
    private void scheduleAutoLock() {
        if (autoLockHandler != null && autoLockRunnable != null) {
            autoLockHandler.postDelayed(autoLockRunnable, SessionManager.SESSION_TIMEOUT_MS);
        }
    }

    /**
     * Cancel pending auto-lock if user returns within timeout.
     */
    private void cancelAutoLock() {
        if (autoLockHandler != null && autoLockRunnable != null) {
            autoLockHandler.removeCallbacks(autoLockRunnable);
        }
    }

    private void createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel reminderChannel = new NotificationChannel(
                    CHANNEL_ID_REMINDER,
                    "Note Reminders",
                    NotificationManager.IMPORTANCE_HIGH
            );
            reminderChannel.setDescription("Notifications for note reminders");
            reminderChannel.enableVibration(true);

            NotificationChannel generalChannel = new NotificationChannel(
                    CHANNEL_ID_GENERAL,
                    "General",
                    NotificationManager.IMPORTANCE_DEFAULT
            );
            generalChannel.setDescription("General notifications");

            NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (manager != null) {
                manager.createNotificationChannel(reminderChannel);
                manager.createNotificationChannel(generalChannel);
            }
        }
    }
}
