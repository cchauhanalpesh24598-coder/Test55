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
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.appcheck.FirebaseAppCheck;
import com.google.firebase.appcheck.debug.DebugAppCheckProviderFactory;
import com.google.firebase.appcheck.playintegrity.PlayIntegrityAppCheckProviderFactory;

import com.mknotes.app.crypto.KeyManager;
import com.mknotes.app.db.NotesRepository;
import com.mknotes.app.util.SessionManager;

public class NotesApplication extends Application {

    private static final String TAG = "NotesApplication";

    public static final String CHANNEL_ID_REMINDER = "notes_reminder_channel";
    public static final String CHANNEL_ID_GENERAL = "notes_general_channel";

    private static boolean sFirebaseAvailable = false;

    private Handler autoLockHandler;
    private Runnable autoLockRunnable;

    public void onCreate() {
        super.onCreate();

        StrictMode.VmPolicy.Builder builder = new StrictMode.VmPolicy.Builder();
        StrictMode.setVmPolicy(builder.build());

        createNotificationChannels();

        initFirebaseAppCheck();

        // ✅ FIX: Firebase auth state listener
        // Jab bhi user login kare, vault Firestore mein upload ensure karo
        try {
            FirebaseAuth.getInstance().addAuthStateListener(firebaseAuth -> {
                if (firebaseAuth.getCurrentUser() != null) {
                    Log.d(TAG, "[AUTH_STATE] User logged in, ensuring vault uploaded...");
                    KeyManager.getInstance(NotesApplication.this).ensureVaultUploaded();
                }
            });
        } catch (Exception e) {
            Log.e(TAG, "Auth state listener setup failed: " + e.getMessage());
        }

        try {
            NotesRepository.getInstance(this).cleanupOldTrash();
        } catch (Exception e) {
            // Fail silently
        }

        autoLockHandler = new Handler(Looper.getMainLooper());
        autoLockRunnable = new Runnable() {
            public void run() {
                SessionManager sm = SessionManager.getInstance(NotesApplication.this);
                if (!sm.isMeditationPlaying()) {
                    KeyManager.getInstance(NotesApplication.this).lockVault();
                    sm.clearSession();
                    Log.d(TAG, "Auto-lock: vault locked after background timeout");
                }
            }
        };

        registerActivityLifecycleCallbacks(new ActivityLifecycleCallbacks() {
            private int activityCount = 0;

            public void onActivityStarted(Activity activity) {
                if (activityCount == 0) {
                    cancelAutoLock();
                    SessionManager.getInstance(activity).onAppForegrounded();
                }
                activityCount++;
            }

            public void onActivityStopped(Activity activity) {
                activityCount--;
                if (activityCount == 0) {
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
     * ✅ FIX: Ye method pehle missing thi - crash ka ek reason yahi tha
     */
    public static boolean isFirebaseAvailable() {
        return sFirebaseAvailable;
    }

    private void initFirebaseAppCheck() {
        try {
            FirebaseApp.initializeApp(this);
            sFirebaseAvailable = true; // ✅ Firebase available mark karo
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
            sFirebaseAvailable = false;
            Log.e(TAG, "Firebase init failed: " + e.getMessage());
        }
    }

    private void scheduleAutoLock() {
        if (autoLockHandler != null && autoLockRunnable != null) {
            autoLockHandler.postDelayed(autoLockRunnable, SessionManager.SESSION_TIMEOUT_MS);
        }
    }

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
