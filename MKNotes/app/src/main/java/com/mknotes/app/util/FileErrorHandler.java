package com.mknotes.app.util;

import android.content.Context;
import android.widget.Toast;

import java.io.File;

/**
 * Handles file-related errors gracefully.
 * Shows user-friendly messages and cleans up orphaned references.
 */
public class FileErrorHandler {

    public static void showFileNotFound(Context context, String fileName) {
        if (context != null) {
            Toast.makeText(context,
                    "File not found: " + (fileName != null ? fileName : "unknown"),
                    Toast.LENGTH_SHORT).show();
        }
    }

    public static void showFileError(Context context, String message) {
        if (context != null) {
            Toast.makeText(context,
                    message != null ? message : "File error occurred",
                    Toast.LENGTH_SHORT).show();
        }
    }

    public static boolean isFileValid(File file) {
        return file != null && file.exists() && file.length() > 0;
    }

    public static void showPermissionDenied(Context context) {
        if (context != null) {
            Toast.makeText(context,
                    "Permission denied. Please grant the required permission.",
                    Toast.LENGTH_LONG).show();
        }
    }

    public static void showRecordingError(Context context) {
        if (context != null) {
            Toast.makeText(context,
                    "Failed to start recording. Please try again.",
                    Toast.LENGTH_SHORT).show();
        }
    }
}
