package com.mknotes.app.util;

import android.content.Context;
import android.content.SharedPreferences;

import com.mknotes.app.crypto.KeyManager;

/**
 * Manages session state, auto-lock timer tracking, and delegates to KeyManager
 * for all crypto operations.
 *
 * Security model (2-layer DEK system):
 * - Master password derives KEK, KEK wraps DEK, DEK encrypts notes
 * - KeyManager holds the DEK in memory as byte[]
 * - SessionManager tracks foreground/background for auto-lock
 * - On lockVault(): DEK byte[] is zeroed via KeyManager
 *
 * This class NO LONGER holds any key material directly.
 */
public class SessionManager {

    private static final String PREFS_NAME = "mknotes_security";
    private static final String KEY_IS_SET = "is_master_password_set";
    private static final String KEY_LAST_UNLOCK = "last_unlock_timestamp";
    private static final String KEY_ENCRYPTION_MIGRATED = "encryption_migrated";
    private static final String KEY_BACKGROUND_TIME = "app_background_timestamp";

    // Old system keys -- kept for migration detection
    private static final String KEY_SALT = "master_password_salt";
    private static final String KEY_VERIFY_TOKEN = "master_password_verify_token";
    private static final String KEY_ITERATIONS = "pbkdf2_iterations";

    /** Session timeout in milliseconds. 5 minutes by default. */
    public static final long SESSION_TIMEOUT_MS = 5L * 60L * 1000L;

    /** Old system iteration count -- used ONLY for migration. */
    private static final int OLD_DEFAULT_ITERATIONS = 15000;

    private final SharedPreferences prefs;
    private final Context appContext;
    private static SessionManager sInstance;

    /**
     * Runtime-only flag indicating whether meditation mantra is actively playing.
     * When true, session timeout is temporarily suspended.
     */
    private boolean isMeditationPlaying = false;

    public static synchronized SessionManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new SessionManager(context.getApplicationContext());
        }
        return sInstance;
    }

    private SessionManager(Context context) {
        this.appContext = context.getApplicationContext();
        this.prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    // ======================== PASSWORD STATE ========================

    /**
     * Check if master password has been configured (either old or new system).
     */
    public boolean isPasswordSet() {
        // Check new system first
        KeyManager km = KeyManager.getInstance(appContext);
        if (km.isVaultInitialized()) {
            return true;
        }
        // Check old system
        return prefs.getBoolean(KEY_IS_SET, false);
    }

    /**
     * Check if old-style master password exists (for migration detection).
     */
    public boolean hasOldSystemCredentials() {
        String salt = prefs.getString(KEY_SALT, null);
        String token = prefs.getString(KEY_VERIFY_TOKEN, null);
        return salt != null && token != null && prefs.getBoolean(KEY_IS_SET, false);
    }

    /**
     * Get old system salt hex (for migration).
     */
    public String getOldSaltHex() {
        return prefs.getString(KEY_SALT, null);
    }

    /**
     * Get old system verify token (for migration).
     */
    public String getOldVerifyToken() {
        return prefs.getString(KEY_VERIFY_TOKEN, null);
    }

    /**
     * Get old system iteration count (for migration).
     */
    public int getOldIterations() {
        return prefs.getInt(KEY_ITERATIONS, OLD_DEFAULT_ITERATIONS);
    }

    /**
     * Mark old system password as set.
     */
    public void setPasswordSetFlag(boolean set) {
        prefs.edit().putBoolean(KEY_IS_SET, set).commit();
    }

    // ======================== SESSION MANAGEMENT ========================

    /**
     * Record that the user has successfully unlocked the app right now.
     * CRITICAL FIX: Uses .commit() (synchronous) instead of .apply() (async).
     * This prevents the race condition where MainActivity starts and reads
     * the OLD timestamp (0) before .apply() flushes, causing isSessionValid()
     * to return false and triggering [DECRYPTION_FAILED] on first launch.
     */
    public void updateSessionTimestamp() {
        prefs.edit().putLong(KEY_LAST_UNLOCK, System.currentTimeMillis()).commit();
    }

    /**
     * Check if the current session is still valid (within timeout window).
     */
    public boolean isSessionValid() {
        if (isMeditationPlaying) {
            return true;
        }
        long lastUnlock = prefs.getLong(KEY_LAST_UNLOCK, 0);
        long elapsed = System.currentTimeMillis() - lastUnlock;
        return elapsed < SESSION_TIMEOUT_MS;
    }

    /**
     * Force the session to expire immediately.
     * Delegates to KeyManager.lockVault() to zero DEK.
     */
    public void clearSession() {
        prefs.edit()
                .putLong(KEY_LAST_UNLOCK, 0)
                .remove(KEY_BACKGROUND_TIME)
                .apply();
        KeyManager.getInstance(appContext).lockVault();
    }

    /**
     * Get the cached DEK for encryption/decryption.
     * Delegates to KeyManager.getDEK() which returns a COPY.
     * Returns null if vault is locked.
     *
     * CRITICAL FIX v3: Removed session timeout check from key getter.
     * The DEK availability should NEVER depend on session timeout.
     * Session timeout is only for UI lock (redirect to password screen).
     * If the vault is unlocked (DEK in memory), it should always be available
     * for decryption. The vault is locked explicitly by clearSession() or
     * the lock screen, not by a read-path getter timeout.
     *
     * Previous bug: isSessionValid() used timestamp from SharedPreferences.
     * After reinstall, when MasterPasswordActivity called updateSessionTimestamp()
     * and then launched MainActivity, the timestamp wasn't always flushed,
     * causing getCachedKey() to return null and all notes to show [DECRYPTION_FAILED].
     */
    public byte[] getCachedKey() {
        return KeyManager.getInstance(appContext).getDEK();
    }

    /**
     * Check if the DEK is available in memory.
     */
    public boolean hasKey() {
        return KeyManager.getInstance(appContext).isVaultUnlocked();
    }

    // ======================== ENCRYPTION MIGRATION (OLD SYSTEM) ========================

    /**
     * Check if database has been migrated to encrypted format (old system flag).
     */
    public boolean isEncryptionMigrated() {
        return prefs.getBoolean(KEY_ENCRYPTION_MIGRATED, false);
    }

    /**
     * Mark the database as migrated to encrypted format.
     */
    public void setEncryptionMigrated(boolean migrated) {
        prefs.edit().putBoolean(KEY_ENCRYPTION_MIGRATED, migrated).commit();
    }

    // ======================== FOREGROUND/BACKGROUND ========================

    /**
     * Called when app goes to background.
     */
    public void onAppBackgrounded() {
        prefs.edit().putLong(KEY_BACKGROUND_TIME, System.currentTimeMillis()).commit();
    }

    /**
     * Called when app returns to foreground.
     */
    public void onAppForegrounded() {
        long bgTime = prefs.getLong(KEY_BACKGROUND_TIME, 0);
        prefs.edit().remove(KEY_BACKGROUND_TIME).apply();
        if (bgTime > 0 && !isMeditationPlaying) {
            long elapsed = System.currentTimeMillis() - bgTime;
            if (elapsed > SESSION_TIMEOUT_MS) {
                clearSession();
            }
        }
    }

    // ======================== MEDITATION STATE ========================

    public void setMeditationPlaying(boolean playing) {
        isMeditationPlaying = playing;
    }

    public boolean isMeditationPlaying() {
        return isMeditationPlaying;
    }

    // ======================== BACKUP RESTORE (LEGACY COMPAT) ========================

    /**
     * Restore encryption credentials from a backup (old system format).
     */
    public void restoreFromBackup(String saltHex, String verifyToken) {
        prefs.edit()
                .putString(KEY_SALT, saltHex)
                .putString(KEY_VERIFY_TOKEN, verifyToken)
                .putBoolean(KEY_IS_SET, true)
                .putBoolean(KEY_ENCRYPTION_MIGRATED, true)
                .commit();
    }

    /**
     * Get the stored salt as hex string (for backup export).
     */
    public String getSaltHex() {
        KeyManager km = KeyManager.getInstance(appContext);
        String newSalt = km.getSaltHex();
        if (newSalt != null) return newSalt;
        return prefs.getString(KEY_SALT, null);
    }

    /**
     * Get the stored verify tag/token (for backup export).
     */
    public String getVerifyToken() {
        KeyManager km = KeyManager.getInstance(appContext);
        String tag = km.getVerifyTag();
        if (tag != null) return tag;
        return prefs.getString(KEY_VERIFY_TOKEN, null);
    }

    /**
     * Clear old system credentials after successful migration.
     */
    public void clearOldCredentials() {
        prefs.edit()
                .remove(KEY_SALT)
                .remove(KEY_VERIFY_TOKEN)
                .remove(KEY_ITERATIONS)
                .apply();
    }
}
