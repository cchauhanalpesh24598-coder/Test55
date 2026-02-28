package com.mknotes.app.db;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

public class NotesDatabaseHelper extends SQLiteOpenHelper {

    private static final String DATABASE_NAME = "mknotes.db";
    private static final int DATABASE_VERSION = 16;

    public static final String TABLE_NOTES = "notes";
    public static final String TABLE_CATEGORIES = "categories";
    public static final String TABLE_TRASH = "trash";
    public static final String TABLE_MANTRAS = "mantras";
    public static final String TABLE_MANTRA_HISTORY = "mantra_history";
    public static final String TABLE_DAILY_SESSIONS = "daily_sessions";
    public static final String TABLE_MANTRA_COUNT_LOG = "mantra_count_log";
    public static final String TABLE_NOTE_MOODS = "note_moods";

    // Mantra Count Log columns
    public static final String COL_LOG_ID = "_id";
    public static final String COL_LOG_MANTRA_ID = "mantra_id";
    public static final String COL_LOG_SESSION_DATE = "session_date";
    public static final String COL_LOG_TIMESTAMP = "timestamp";

    // Note Moods columns
    public static final String COL_MOOD_ID = "_id";
    public static final String COL_MOOD_NOTE_ID = "note_id";
    public static final String COL_MOOD_DATE = "date";
    public static final String COL_MOOD_TIMESTAMP = "timestamp";
    public static final String COL_MOOD_EMOJI = "emoji_unicode";
    public static final String COL_MOOD_NAME = "mood_name";
    public static final String COL_MOOD_INTENSITY = "intensity_level";

    // Notes columns
    public static final String COL_ID = "_id";
    public static final String COL_TITLE = "title";
    public static final String COL_CONTENT = "content";
    public static final String COL_CREATED = "created_at";
    public static final String COL_MODIFIED = "modified_at";
    public static final String COL_COLOR = "color";
    public static final String COL_FAVORITE = "is_favorite";
    public static final String COL_LOCKED = "is_locked";
    public static final String COL_PASSWORD = "password";
    public static final String COL_CATEGORY_ID = "category_id";
    public static final String COL_HAS_CHECKLIST = "has_checklist";
    public static final String COL_HAS_IMAGE = "has_image";
    public static final String COL_CHECKLIST_DATA = "checklist_data";
    public static final String COL_IS_CHECKLIST_MODE = "is_checklist_mode";
    public static final String COL_IMAGES_DATA = "images_data";
    public static final String COL_FILES_DATA = "files_data";
    public static final String COL_AUDIOS_DATA = "audios_data";
    public static final String COL_LINKED_NOTE_IDS = "linked_note_ids";
    public static final String COL_IS_ROUTINE_MODE = "is_routine_mode";
    public static final String COL_ROUTINE_DATA = "routine_data";
    public static final String COL_IS_ARCHIVED = "is_archived";
    public static final String COL_SEARCH_INDEX = "search_index";
    public static final String COL_CLOUD_ID = "cloud_id";
    public static final String COL_SYNC_STATUS = "sync_status";

    // Mantras columns
    public static final String COL_MANTRA_ID = "_id";
    public static final String COL_MANTRA_NOTE_ID = "note_id";
    public static final String COL_MANTRA_NAME = "name";
    public static final String COL_MANTRA_AUDIO_PATH = "audio_path";
    public static final String COL_MANTRA_TODAY_COUNT = "today_count";
    public static final String COL_MANTRA_LAST_COUNT_DATE = "last_count_date";
    public static final String COL_MANTRA_CREATED = "created_at";
    public static final String COL_MANTRA_SPEED = "playback_speed";
    public static final String COL_MANTRA_IS_DELETED = "is_deleted";
    public static final String COL_MANTRA_RAW_RES_ID = "raw_res_id";
    public static final String COL_MANTRA_BUILT_IN = "built_in";

    // Mantra History columns
    public static final String COL_HIST_ID = "_id";
    public static final String COL_HIST_MANTRA_ID = "mantra_id";
    public static final String COL_HIST_DATE = "date";
    public static final String COL_HIST_COUNT = "count";

    // Daily Sessions columns
    public static final String COL_SESSION_ID = "_id";
    public static final String COL_SESSION_MANTRA_ID = "mantra_id";
    public static final String COL_SESSION_DATE = "session_date";
    public static final String COL_SESSION_COUNT = "count";
    public static final String COL_SESSION_SPEED = "speed";

    // Categories columns
    public static final String COL_CAT_ID = "_id";
    public static final String COL_CAT_NAME = "name";
    public static final String COL_CAT_COLOR = "color";
    public static final String COL_CAT_ORDER = "sort_order";

    // Trash columns
    public static final String COL_TRASH_ID = "_id";
    public static final String COL_TRASH_NOTE_TITLE = "title";
    public static final String COL_TRASH_NOTE_CONTENT = "content";
    public static final String COL_TRASH_NOTE_COLOR = "color";
    public static final String COL_TRASH_NOTE_CATEGORY = "category_id";
    public static final String COL_TRASH_DATE = "deleted_at";
    public static final String COL_TRASH_ORIGINAL_ID = "original_id";
    public static final String COL_TRASH_CHECKLIST_DATA = "checklist_data";
    public static final String COL_TRASH_IS_CHECKLIST_MODE = "is_checklist_mode";
    public static final String COL_TRASH_IMAGES_DATA = "images_data";
    public static final String COL_TRASH_FILES_DATA = "files_data";
    public static final String COL_TRASH_AUDIOS_DATA = "audios_data";
    public static final String COL_TRASH_LINKED_NOTE_IDS = "linked_note_ids";

    private static final String CREATE_NOTES_TABLE =
            "CREATE TABLE " + TABLE_NOTES + " (" +
                    COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    COL_TITLE + " TEXT, " +
                    COL_CONTENT + " TEXT, " +
                    COL_CREATED + " INTEGER, " +
                    COL_MODIFIED + " INTEGER, " +
                    COL_COLOR + " INTEGER DEFAULT 0, " +
                    COL_FAVORITE + " INTEGER DEFAULT 0, " +
                    COL_LOCKED + " INTEGER DEFAULT 0, " +
                    COL_PASSWORD + " TEXT, " +
                    COL_CATEGORY_ID + " INTEGER DEFAULT -1, " +
                    COL_HAS_CHECKLIST + " INTEGER DEFAULT 0, " +
                    COL_HAS_IMAGE + " INTEGER DEFAULT 0, " +
                    COL_CHECKLIST_DATA + " TEXT DEFAULT '', " +
                    COL_IS_CHECKLIST_MODE + " INTEGER DEFAULT 0, " +
                    COL_IMAGES_DATA + " TEXT DEFAULT '', " +
                    COL_FILES_DATA + " TEXT DEFAULT '', " +
                    COL_AUDIOS_DATA + " TEXT DEFAULT '', " +
                    COL_LINKED_NOTE_IDS + " TEXT DEFAULT '', " +
                    COL_IS_ROUTINE_MODE + " INTEGER DEFAULT 0, " +
                    COL_ROUTINE_DATA + " TEXT DEFAULT '', " +
                    COL_IS_ARCHIVED + " INTEGER DEFAULT 0, " +
                    COL_SEARCH_INDEX + " TEXT DEFAULT '', " +
                    COL_CLOUD_ID + " TEXT, " +
                    COL_SYNC_STATUS + " INTEGER DEFAULT 1" +
                    ");";

    private static final String CREATE_CATEGORIES_TABLE =
            "CREATE TABLE " + TABLE_CATEGORIES + " (" +
                    COL_CAT_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    COL_CAT_NAME + " TEXT NOT NULL, " +
                    COL_CAT_COLOR + " INTEGER DEFAULT 0, " +
                    COL_CAT_ORDER + " INTEGER DEFAULT 0" +
                    ");";

    private static final String CREATE_TRASH_TABLE =
            "CREATE TABLE " + TABLE_TRASH + " (" +
                    COL_TRASH_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    COL_TRASH_NOTE_TITLE + " TEXT, " +
                    COL_TRASH_NOTE_CONTENT + " TEXT, " +
                    COL_TRASH_NOTE_COLOR + " INTEGER DEFAULT 0, " +
                    COL_TRASH_NOTE_CATEGORY + " INTEGER DEFAULT -1, " +
                    COL_TRASH_DATE + " INTEGER, " +
                    COL_TRASH_ORIGINAL_ID + " INTEGER, " +
                    COL_TRASH_CHECKLIST_DATA + " TEXT DEFAULT '', " +
                    COL_TRASH_IS_CHECKLIST_MODE + " INTEGER DEFAULT 0, " +
                    COL_TRASH_IMAGES_DATA + " TEXT DEFAULT '', " +
                    COL_TRASH_FILES_DATA + " TEXT DEFAULT '', " +
                    COL_TRASH_AUDIOS_DATA + " TEXT DEFAULT '', " +
                    COL_TRASH_LINKED_NOTE_IDS + " TEXT DEFAULT ''" +
                    ");";

    private static final String CREATE_MANTRAS_TABLE =
            "CREATE TABLE " + TABLE_MANTRAS + " (" +
                    COL_MANTRA_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    COL_MANTRA_NOTE_ID + " INTEGER DEFAULT -1, " +
                    COL_MANTRA_NAME + " TEXT NOT NULL, " +
                    COL_MANTRA_AUDIO_PATH + " TEXT DEFAULT '', " +
                    COL_MANTRA_TODAY_COUNT + " INTEGER DEFAULT 0, " +
                    COL_MANTRA_LAST_COUNT_DATE + " TEXT DEFAULT '', " +
                    COL_MANTRA_CREATED + " INTEGER, " +
                    COL_MANTRA_SPEED + " REAL DEFAULT 1.0, " +
                    COL_MANTRA_IS_DELETED + " INTEGER DEFAULT 0, " +
                    COL_MANTRA_RAW_RES_ID + " INTEGER DEFAULT 0, " +
                    COL_MANTRA_BUILT_IN + " INTEGER DEFAULT 0" +
                    ");";

    private static final String CREATE_MANTRA_HISTORY_TABLE =
            "CREATE TABLE " + TABLE_MANTRA_HISTORY + " (" +
                    COL_HIST_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    COL_HIST_MANTRA_ID + " INTEGER, " +
                    COL_HIST_DATE + " TEXT NOT NULL, " +
                    COL_HIST_COUNT + " INTEGER DEFAULT 0" +
                    ");";

    private static final String CREATE_DAILY_SESSIONS_TABLE =
            "CREATE TABLE " + TABLE_DAILY_SESSIONS + " (" +
                    COL_SESSION_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    COL_SESSION_MANTRA_ID + " INTEGER, " +
                    COL_SESSION_DATE + " TEXT NOT NULL, " +
                    COL_SESSION_COUNT + " INTEGER DEFAULT 0, " +
                    COL_SESSION_SPEED + " REAL DEFAULT 1.0" +
                    ");";

    private static final String CREATE_MANTRA_COUNT_LOG_TABLE =
            "CREATE TABLE IF NOT EXISTS " + TABLE_MANTRA_COUNT_LOG + " (" +
                    COL_LOG_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    COL_LOG_MANTRA_ID + " INTEGER, " +
                    COL_LOG_SESSION_DATE + " TEXT NOT NULL, " +
                    COL_LOG_TIMESTAMP + " INTEGER NOT NULL" +
                    ");";

    private static final String CREATE_NOTE_MOODS_TABLE =
            "CREATE TABLE IF NOT EXISTS " + TABLE_NOTE_MOODS + " (" +
                    COL_MOOD_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    COL_MOOD_NOTE_ID + " INTEGER, " +
                    COL_MOOD_DATE + " TEXT, " +
                    COL_MOOD_TIMESTAMP + " INTEGER, " +
                    COL_MOOD_EMOJI + " TEXT, " +
                    COL_MOOD_NAME + " TEXT, " +
                    COL_MOOD_INTENSITY + " INTEGER DEFAULT 3" +
                    ");";

    private static final String CREATE_NOTE_MOODS_INDEX_NOTE =
            "CREATE INDEX IF NOT EXISTS idx_mood_note_id ON " + TABLE_NOTE_MOODS + " (" + COL_MOOD_NOTE_ID + ");";

    private static final String CREATE_NOTE_MOODS_INDEX_DATE =
            "CREATE INDEX IF NOT EXISTS idx_mood_date ON " + TABLE_NOTE_MOODS + " (" + COL_MOOD_DATE + ");";

    private static NotesDatabaseHelper sInstance;

    public static synchronized NotesDatabaseHelper getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new NotesDatabaseHelper(context.getApplicationContext());
        }
        return sInstance;
    }

    private NotesDatabaseHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    public void onCreate(SQLiteDatabase db) {
        db.execSQL(CREATE_NOTES_TABLE);
        db.execSQL(CREATE_CATEGORIES_TABLE);
        db.execSQL(CREATE_TRASH_TABLE);
        db.execSQL(CREATE_MANTRAS_TABLE);
        db.execSQL(CREATE_MANTRA_HISTORY_TABLE);
        db.execSQL(CREATE_DAILY_SESSIONS_TABLE);
        db.execSQL(CREATE_MANTRA_COUNT_LOG_TABLE);
        db.execSQL(CREATE_NOTE_MOODS_TABLE);
        db.execSQL(CREATE_NOTE_MOODS_INDEX_NOTE);
        db.execSQL(CREATE_NOTE_MOODS_INDEX_DATE);
        seedBuiltInMantras(db);
    }

    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        if (oldVersion < 2) {
            db.execSQL("ALTER TABLE " + TABLE_NOTES + " ADD COLUMN " + COL_HAS_CHECKLIST + " INTEGER DEFAULT 0");
        }
        if (oldVersion < 3) {
            db.execSQL("ALTER TABLE " + TABLE_NOTES + " ADD COLUMN " + COL_HAS_IMAGE + " INTEGER DEFAULT 0");
            db.execSQL(CREATE_TRASH_TABLE);
        }
        if (oldVersion < 4) {
            db.execSQL("ALTER TABLE " + TABLE_NOTES + " ADD COLUMN " + COL_CHECKLIST_DATA + " TEXT DEFAULT ''");
            db.execSQL("ALTER TABLE " + TABLE_NOTES + " ADD COLUMN " + COL_IS_CHECKLIST_MODE + " INTEGER DEFAULT 0");
        }
        if (oldVersion < 5) {
            db.execSQL("ALTER TABLE " + TABLE_NOTES + " ADD COLUMN " + COL_IMAGES_DATA + " TEXT DEFAULT ''");
            db.execSQL("ALTER TABLE " + TABLE_NOTES + " ADD COLUMN " + COL_FILES_DATA + " TEXT DEFAULT ''");
            db.execSQL("ALTER TABLE " + TABLE_NOTES + " ADD COLUMN " + COL_AUDIOS_DATA + " TEXT DEFAULT ''");
            db.execSQL("ALTER TABLE " + TABLE_NOTES + " ADD COLUMN " + COL_LINKED_NOTE_IDS + " TEXT DEFAULT ''");
            // Add attachment columns to trash table
            try {
                db.execSQL("ALTER TABLE " + TABLE_TRASH + " ADD COLUMN " + COL_TRASH_CHECKLIST_DATA + " TEXT DEFAULT ''");
                db.execSQL("ALTER TABLE " + TABLE_TRASH + " ADD COLUMN " + COL_TRASH_IS_CHECKLIST_MODE + " INTEGER DEFAULT 0");
                db.execSQL("ALTER TABLE " + TABLE_TRASH + " ADD COLUMN " + COL_TRASH_IMAGES_DATA + " TEXT DEFAULT ''");
                db.execSQL("ALTER TABLE " + TABLE_TRASH + " ADD COLUMN " + COL_TRASH_FILES_DATA + " TEXT DEFAULT ''");
                db.execSQL("ALTER TABLE " + TABLE_TRASH + " ADD COLUMN " + COL_TRASH_AUDIOS_DATA + " TEXT DEFAULT ''");
                db.execSQL("ALTER TABLE " + TABLE_TRASH + " ADD COLUMN " + COL_TRASH_LINKED_NOTE_IDS + " TEXT DEFAULT ''");
            } catch (Exception e) {
                // Columns may already exist if trash was recreated
            }
        }
        if (oldVersion < 6) {
            try {
                db.execSQL("ALTER TABLE " + TABLE_NOTES + " ADD COLUMN " + COL_IS_ROUTINE_MODE + " INTEGER DEFAULT 0");
                db.execSQL("ALTER TABLE " + TABLE_NOTES + " ADD COLUMN " + COL_ROUTINE_DATA + " TEXT DEFAULT ''");
            } catch (Exception e) {
                // Columns may already exist
            }
        }
        if (oldVersion < 7) {
            try {
                db.execSQL(CREATE_MANTRAS_TABLE);
                db.execSQL(CREATE_MANTRA_HISTORY_TABLE);
            } catch (Exception e) {
                // Tables may already exist
            }
        }
        if (oldVersion < 8) {
            try {
                db.execSQL(CREATE_DAILY_SESSIONS_TABLE);
            } catch (Exception e) {
                // Table may already exist
            }
        }
        if (oldVersion < 9) {
            try {
                db.execSQL("ALTER TABLE " + TABLE_MANTRAS + " ADD COLUMN " +
                        COL_MANTRA_IS_DELETED + " INTEGER DEFAULT 0");
            } catch (Exception e) {
                // Column may already exist
            }
        }
        if (oldVersion < 10) {
            try {
                db.execSQL("ALTER TABLE " + TABLE_MANTRAS + " ADD COLUMN " +
                        COL_MANTRA_RAW_RES_ID + " INTEGER DEFAULT 0");
            } catch (Exception e) { }
            try {
                db.execSQL("ALTER TABLE " + TABLE_MANTRAS + " ADD COLUMN " +
                        COL_MANTRA_BUILT_IN + " INTEGER DEFAULT 0");
            } catch (Exception e) { }
            seedBuiltInMantras(db);
        }
        if (oldVersion < 11) {
            try {
                db.execSQL(CREATE_MANTRA_COUNT_LOG_TABLE);
            } catch (Exception e) {
                // Table may already exist
            }
        }
        if (oldVersion < 12) {
            try {
                db.execSQL("ALTER TABLE " + TABLE_NOTES + " ADD COLUMN " +
                        COL_IS_ARCHIVED + " INTEGER DEFAULT 0");
            } catch (Exception e) {
                // Column may already exist
            }
        }
        if (oldVersion < 13) {
            try {
                db.execSQL(CREATE_NOTE_MOODS_TABLE);
                db.execSQL(CREATE_NOTE_MOODS_INDEX_NOTE);
                db.execSQL(CREATE_NOTE_MOODS_INDEX_DATE);
            } catch (Exception e) {
                // Table may already exist
            }
        }
        if (oldVersion < 14) {
            try {
                db.execSQL("ALTER TABLE " + TABLE_NOTES + " ADD COLUMN " +
                        COL_SEARCH_INDEX + " TEXT DEFAULT ''");
            } catch (Exception e) {
                // Column may already exist
            }
        }
        if (oldVersion < 15) {
            // Clear deprecated hashed keyword search_index data.
            // Column stays in schema for DB compatibility (SQLite cannot DROP COLUMN).
            // Search now uses in-memory decrypted content matching.
            try {
                db.execSQL("UPDATE " + TABLE_NOTES + " SET " + COL_SEARCH_INDEX + " = ''");
            } catch (Exception e) {
                // Safe to ignore
            }
        }
        if (oldVersion < 16) {
            try {
                db.execSQL("ALTER TABLE " + TABLE_NOTES + " ADD COLUMN " +
                        COL_CLOUD_ID + " TEXT");
            } catch (Exception e) {
                // Column may already exist
            }
            try {
                db.execSQL("ALTER TABLE " + TABLE_NOTES + " ADD COLUMN " +
                        COL_SYNC_STATUS + " INTEGER DEFAULT 1");
            } catch (Exception e) {
                // Column may already exist
            }
        }
    }

    /**
     * Seed 15 predefined built-in mantras into the database.
     * These use R.raw resource IDs for playback - no storage permission needed.
     * Each mantra is inserted only if it does not already exist (by name + built_in=1).
     */
    private void seedBuiltInMantras(SQLiteDatabase db) {
        String[][] builtInMantras = {
            {"Om Namah Shivay", "omnamahshivay"},
            {"Gayatri Mantra", "gayatrimantra"},
            {"Mahamrityunjay", "mahamrityunjayy"},
            {"Krishna Vasudevay", "krishnayvasudevay"},
            {"Navarna Mantra", "navarnamantra"},
            {"Kubera Ast Laxmi", "kuberaastlaxmi"},
            {"Om Yakshay Kuberay", "omyakshaykuberay"},
            {"Shree Suktam", "shreesuktam"},
            {"Om Namo Bhagvate", "omnamohbhagvate"},
            {"Om Ham Hanumate", "omhamhanumate"},
            {"Rudravataray Hanuman", "rudravtarayhanuman"},
            {"Aasutosh Sasank", "aasutoshsasank"},
            {"Nirankaro Mkar", "nirnkaromkar"},
            {"Kaleswar Mahaprabhu", "kaleswarmahaprabhu"},
            {"Om Gananpate Namah", "omganganpatenamah"}
        };
        long now = System.currentTimeMillis();
        for (int i = 0; i < builtInMantras.length; i++) {
            String displayName = builtInMantras[i][0];
            String rawName = builtInMantras[i][1];
            // Check if already exists
            android.database.Cursor cursor = db.rawQuery(
                "SELECT COUNT(*) FROM " + TABLE_MANTRAS +
                " WHERE " + COL_MANTRA_NAME + "=? AND " + COL_MANTRA_BUILT_IN + "=1",
                new String[]{displayName});
            boolean exists = false;
            if (cursor != null) {
                if (cursor.moveToFirst()) {
                    exists = cursor.getInt(0) > 0;
                }
                cursor.close();
            }
            if (!exists) {
                android.content.ContentValues values = new android.content.ContentValues();
                values.put(COL_MANTRA_NOTE_ID, -1);
                values.put(COL_MANTRA_NAME, displayName);
                values.put(COL_MANTRA_AUDIO_PATH, "raw:" + rawName);
                values.put(COL_MANTRA_TODAY_COUNT, 0);
                values.put(COL_MANTRA_LAST_COUNT_DATE, "");
                values.put(COL_MANTRA_CREATED, now + i);
                values.put(COL_MANTRA_SPEED, 1.0f);
                values.put(COL_MANTRA_IS_DELETED, 0);
                values.put(COL_MANTRA_BUILT_IN, 1);
                values.put(COL_MANTRA_RAW_RES_ID, 0);
                db.insert(TABLE_MANTRAS, null, values);
            }
        }
    }
}
