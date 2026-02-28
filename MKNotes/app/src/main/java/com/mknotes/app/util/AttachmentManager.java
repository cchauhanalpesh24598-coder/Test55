package com.mknotes.app.util;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.OpenableColumns;
import android.webkit.MimeTypeMap;

import com.mknotes.app.model.FileAttachment;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Manages all attachment file operations using app-internal storage.
 * Structure: files/attachments/{noteId}/images|files|audios/
 */
public class AttachmentManager {

    private static final String ATTACHMENTS_DIR = "attachments";
    private static final String IMAGES_DIR = "images";
    private static final String FILES_DIR = "files";
    private static final String AUDIOS_DIR = "audios";
    private static final int BUFFER_SIZE = 4096;

    public static File getAttachmentsDir(Context context, long noteId) {
        File dir = new File(context.getFilesDir(), ATTACHMENTS_DIR + "/" + noteId);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }

    public static File getImagesDir(Context context, long noteId) {
        File dir = new File(getAttachmentsDir(context, noteId), IMAGES_DIR);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }

    public static File getFilesDir(Context context, long noteId) {
        File dir = new File(getAttachmentsDir(context, noteId), FILES_DIR);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }

    public static File getAudiosDir(Context context, long noteId) {
        File dir = new File(getAttachmentsDir(context, noteId), AUDIOS_DIR);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }

    /**
     * Copies a file from a content URI to the note's attachments directory.
     * Returns a FileAttachment with localName, originalName, and mimeType.
     */
    public static FileAttachment copyFileToAttachments(Context context, Uri sourceUri,
                                                        long noteId, String subDir) {
        if (context == null || sourceUri == null) return null;

        try {
            ContentResolver resolver = context.getContentResolver();
            String originalName = getFileName(context, sourceUri);
            String mimeType = resolver.getType(sourceUri);
            if (mimeType == null) {
                mimeType = "application/octet-stream";
            }

            // Generate unique local name
            String extension = getExtensionFromMime(mimeType);
            if (extension.length() == 0) {
                extension = getExtensionFromName(originalName);
            }
            String localName = System.currentTimeMillis() + "_" +
                    ((int)(Math.random() * 99999)) +
                    (extension.length() > 0 ? "." + extension : "");

            File destDir;
            if (IMAGES_DIR.equals(subDir)) {
                destDir = getImagesDir(context, noteId);
            } else if (AUDIOS_DIR.equals(subDir)) {
                destDir = getAudiosDir(context, noteId);
            } else {
                destDir = getFilesDir(context, noteId);
            }

            File destFile = new File(destDir, localName);

            InputStream is = resolver.openInputStream(sourceUri);
            if (is == null) return null;

            OutputStream os = new FileOutputStream(destFile);
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                os.write(buffer, 0, bytesRead);
            }
            os.flush();
            os.close();
            is.close();

            return new FileAttachment(localName, originalName, mimeType);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Get the image file for a note.
     */
    public static File getImageFile(Context context, long noteId, String localName) {
        return new File(getImagesDir(context, noteId), localName);
    }

    /**
     * Get the generic file for a note.
     */
    public static File getFileFile(Context context, long noteId, String localName) {
        return new File(getFilesDir(context, noteId), localName);
    }

    /**
     * Get the audio file for a note.
     */
    public static File getAudioFile(Context context, long noteId, String localName) {
        return new File(getAudiosDir(context, noteId), localName);
    }

    /**
     * Delete a specific attachment file.
     */
    public static boolean deleteAttachmentFile(Context context, long noteId,
                                                String localName, String subDir) {
        File dir;
        if (IMAGES_DIR.equals(subDir)) {
            dir = getImagesDir(context, noteId);
        } else if (AUDIOS_DIR.equals(subDir)) {
            dir = getAudiosDir(context, noteId);
        } else {
            dir = getFilesDir(context, noteId);
        }
        File file = new File(dir, localName);
        if (file.exists()) {
            return file.delete();
        }
        return false;
    }

    /**
     * Delete all attachments for a note.
     */
    public static void deleteAllAttachments(Context context, long noteId) {
        File dir = getAttachmentsDir(context, noteId);
        if (dir.exists()) {
            deleteRecursive(dir);
        }
    }

    private static void deleteRecursive(File fileOrDir) {
        if (fileOrDir.isDirectory()) {
            File[] children = fileOrDir.listFiles();
            if (children != null) {
                for (int i = 0; i < children.length; i++) {
                    deleteRecursive(children[i]);
                }
            }
        }
        fileOrDir.delete();
    }

    /**
     * Get the display name of a file from its URI.
     */
    public static String getFileName(Context context, Uri uri) {
        String name = "unknown";
        if ("content".equals(uri.getScheme())) {
            Cursor cursor = null;
            try {
                cursor = context.getContentResolver().query(uri, null, null, null, null);
                if (cursor != null && cursor.moveToFirst()) {
                    int nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if (nameIndex >= 0) {
                        name = cursor.getString(nameIndex);
                    }
                }
            } catch (Exception e) {
                // Fall through to path extraction
            } finally {
                if (cursor != null) {
                    cursor.close();
                }
            }
        }
        if ("unknown".equals(name)) {
            String path = uri.getPath();
            if (path != null) {
                int lastSlash = path.lastIndexOf('/');
                if (lastSlash >= 0 && lastSlash < path.length() - 1) {
                    name = path.substring(lastSlash + 1);
                }
            }
        }
        return name;
    }

    private static String getExtensionFromMime(String mimeType) {
        if (mimeType == null) return "";
        MimeTypeMap map = MimeTypeMap.getSingleton();
        String ext = map.getExtensionFromMimeType(mimeType);
        return ext != null ? ext : "";
    }

    private static String getExtensionFromName(String name) {
        if (name == null) return "";
        int dotIndex = name.lastIndexOf('.');
        if (dotIndex >= 0 && dotIndex < name.length() - 1) {
            return name.substring(dotIndex + 1);
        }
        return "";
    }

    /**
     * Create an audio output file path for recording.
     */
    public static File createAudioFile(Context context, long noteId) {
        File dir = getAudiosDir(context, noteId);
        String name = "audio_" + System.currentTimeMillis() + ".m4a";
        return new File(dir, name);
    }
}
