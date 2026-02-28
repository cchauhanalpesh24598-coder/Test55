package com.mknotes.app.util;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import android.webkit.MimeTypeMap;

import java.io.File;
import java.io.FileNotFoundException;

/**
 * Custom ContentProvider that serves internal files via content:// URIs.
 * Replaces android.support.v4.content.FileProvider since this project
 * has no support library or AndroidX dependencies.
 *
 * Authority: com.mknotes.app.fileprovider
 * URI format: content://com.mknotes.app.fileprovider/file/<absolute-path>
 */
public class MKFileProvider extends ContentProvider {

    public static final String AUTHORITY = "com.mknotes.app.fileprovider";

    /**
     * Build a content:// URI for the given file that can be shared
     * with other apps via FLAG_GRANT_READ_URI_PERMISSION.
     */
    public static Uri getUriForFile(File file) {
        String path = file.getAbsolutePath();
        return new Uri.Builder()
                .scheme("content")
                .authority(AUTHORITY)
                .path("file" + path)
                .build();
    }

    public boolean onCreate() {
        return true;
    }

    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        File file = getFileFromUri(uri);
        if (file == null || !file.exists()) {
            throw new FileNotFoundException("File not found: " + uri);
        }
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
    }

    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        File file = getFileFromUri(uri);
        if (file == null || !file.exists()) {
            return null;
        }

        // Default projection if none specified
        if (projection == null) {
            projection = new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE};
        }

        MatrixCursor cursor = new MatrixCursor(projection);
        Object[] row = new Object[projection.length];
        for (int i = 0; i < projection.length; i++) {
            if (OpenableColumns.DISPLAY_NAME.equals(projection[i])) {
                row[i] = file.getName();
            } else if (OpenableColumns.SIZE.equals(projection[i])) {
                row[i] = file.length();
            } else {
                row[i] = null;
            }
        }
        cursor.addRow(row);
        return cursor;
    }

    public String getType(Uri uri) {
        File file = getFileFromUri(uri);
        if (file == null) return "*/*";
        String name = file.getName();
        String ext = MimeTypeMap.getFileExtensionFromUrl(name);
        if (ext != null && ext.length() > 0) {
            String mimeType = MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext.toLowerCase());
            if (mimeType != null) return mimeType;
        }
        // Fallback for common types
        String lower = name.toLowerCase();
        if (lower.endsWith(".pdf")) return "application/pdf";
        if (lower.endsWith(".txt")) return "text/plain";
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
        if (lower.endsWith(".png")) return "image/png";
        if (lower.endsWith(".mp3")) return "audio/mpeg";
        if (lower.endsWith(".m4a")) return "audio/mp4";
        if (lower.endsWith(".3gp")) return "audio/3gpp";
        return "*/*";
    }

    public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException("Insert not supported");
    }

    public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("Delete not supported");
    }

    public int update(Uri uri, ContentValues values, String selection,
                      String[] selectionArgs) {
        throw new UnsupportedOperationException("Update not supported");
    }

    /**
     * Extract the absolute file path from our content URI.
     * URI format: content://authority/file/absolute/path/to/file.ext
     */
    private File getFileFromUri(Uri uri) {
        if (uri == null) return null;
        String path = uri.getPath();
        if (path == null) return null;
        // Remove the leading "/file" prefix to get the absolute path
        if (path.startsWith("/file/")) {
            path = path.substring(5); // removes "/file" leaving "/absolute/path..."
        } else if (path.startsWith("/file")) {
            path = path.substring(5);
        }
        if (path.length() == 0) return null;

        File file = new File(path);

        // Security: only allow access to files within our app's data directories
        String appDataDir = null;
        String appCacheDir = null;
        if (getContext() != null) {
            appDataDir = getContext().getFilesDir().getAbsolutePath();
            appCacheDir = getContext().getCacheDir().getAbsolutePath();
        }

        String filePath = file.getAbsolutePath();
        if (appDataDir != null && filePath.startsWith(appDataDir)) {
            return file;
        }
        if (appCacheDir != null && filePath.startsWith(appCacheDir)) {
            return file;
        }

        // Also allow external cache dir
        if (getContext() != null) {
            File extCache = getContext().getExternalCacheDir();
            if (extCache != null && filePath.startsWith(extCache.getAbsolutePath())) {
                return file;
            }
            // Allow external files dir
            File extFiles = getContext().getExternalFilesDir(null);
            if (extFiles != null && filePath.startsWith(extFiles.getAbsolutePath())) {
                return file;
            }
        }

        // Deny access to files outside our app directories
        return null;
    }
}
