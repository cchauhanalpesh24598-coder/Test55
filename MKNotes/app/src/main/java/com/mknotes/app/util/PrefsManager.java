package com.mknotes.app.util;

import android.content.Context;
import android.content.SharedPreferences;

public class PrefsManager {

    private static final String PREFS_NAME = "mknotes_prefs";
    private static final String KEY_SORT_BY = "sort_by";
    private static final String KEY_DEFAULT_COLOR = "default_color";
    private static final String KEY_FONT_SIZE = "font_size";
    private static final String KEY_AUTO_SAVE = "auto_save";
    private static final String KEY_CONFIRM_DELETE = "confirm_delete";
    private static final String KEY_VIEW_MODE = "view_mode";
    private static final String KEY_CURRENT_FILTER = "current_filter";
    private static final String KEY_CURRENT_CATEGORY_ID = "current_category_id";
    private static final String KEY_CLOUD_SYNC_ENABLED = "cloud_sync_enabled";

    public static final String SORT_MODIFIED = "modified";
    public static final String SORT_CREATED = "created";
    public static final String SORT_TITLE = "title";

    public static final int VIEW_LIST = 0;
    public static final int VIEW_GRID = 1;

    public static final String FILTER_ALL = "all";
    public static final String FILTER_FAVORITES = "favorites";
    public static final String FILTER_CATEGORY = "category";

    private SharedPreferences prefs;
    private static PrefsManager sInstance;

    public static synchronized PrefsManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new PrefsManager(context.getApplicationContext());
        }
        return sInstance;
    }

    private PrefsManager(Context context) {
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public String getSortBy() {
        return prefs.getString(KEY_SORT_BY, SORT_MODIFIED);
    }

    public void setSortBy(String sortBy) {
        prefs.edit().putString(KEY_SORT_BY, sortBy).apply();
    }

    public int getDefaultColor() {
        return prefs.getInt(KEY_DEFAULT_COLOR, 0);
    }

    public void setDefaultColor(int color) {
        prefs.edit().putInt(KEY_DEFAULT_COLOR, color).apply();
    }

    public int getFontSize() {
        return prefs.getInt(KEY_FONT_SIZE, 16);
    }

    public void setFontSize(int size) {
        prefs.edit().putInt(KEY_FONT_SIZE, size).apply();
    }

    public boolean isAutoSave() {
        return prefs.getBoolean(KEY_AUTO_SAVE, true);
    }

    public void setAutoSave(boolean autoSave) {
        prefs.edit().putBoolean(KEY_AUTO_SAVE, autoSave).apply();
    }

    public boolean isConfirmDelete() {
        return prefs.getBoolean(KEY_CONFIRM_DELETE, true);
    }

    public void setConfirmDelete(boolean confirm) {
        prefs.edit().putBoolean(KEY_CONFIRM_DELETE, confirm).apply();
    }

    public int getViewMode() {
        return prefs.getInt(KEY_VIEW_MODE, VIEW_LIST);
    }

    public void setViewMode(int viewMode) {
        prefs.edit().putInt(KEY_VIEW_MODE, viewMode).apply();
    }

    public String getCurrentFilter() {
        return prefs.getString(KEY_CURRENT_FILTER, FILTER_ALL);
    }

    public void setCurrentFilter(String filter) {
        prefs.edit().putString(KEY_CURRENT_FILTER, filter).apply();
    }

    public long getCurrentCategoryId() {
        return prefs.getLong(KEY_CURRENT_CATEGORY_ID, -1);
    }

    public void setCurrentCategoryId(long id) {
        prefs.edit().putLong(KEY_CURRENT_CATEGORY_ID, id).apply();
    }

    public boolean isCloudSyncEnabled() {
        return prefs.getBoolean(KEY_CLOUD_SYNC_ENABLED, false);
    }

    public void setCloudSyncEnabled(boolean enabled) {
        prefs.edit().putBoolean(KEY_CLOUD_SYNC_ENABLED, enabled).apply();
    }
}
