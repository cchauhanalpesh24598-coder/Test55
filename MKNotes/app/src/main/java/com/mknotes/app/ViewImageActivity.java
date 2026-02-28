package com.mknotes.app;

import android.app.Activity;
import android.content.ContentValues;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.graphics.Matrix;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.view.MotionEvent;
import android.view.ScaleGestureDetector;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Full-screen image viewer with pinch-to-zoom, rotate and download.
 * Displays image in gallery-style (fitCenter, original aspect ratio).
 */
public class ViewImageActivity extends Activity {

    public static final String EXTRA_IMAGE_PATH = "image_path";
    public static final String EXTRA_NOTE_ID = "note_id";
    public static final String EXTRA_IMAGE_INDEX = "image_index";
    public static final int RESULT_DELETED = 101;

    private static final int PERMISSION_WRITE_STORAGE = 4001;

    private ImageView imageView;
    private ImageButton btnBack;
    private ImageButton btnDelete;
    private ImageButton btnRotate;
    private ImageButton btnDownload;

    private String imagePath;
    private int currentRotation = 0;

    // Zoom/pan support
    private Matrix matrix;
    private Matrix savedMatrix;
    private ScaleGestureDetector scaleDetector;
    private float scaleFactor = 1.0f;
    private float lastTouchX;
    private float lastTouchY;
    private int mode = 0;
    private static final int NONE = 0;
    private static final int DRAG = 1;

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Full screen
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN,
                WindowManager.LayoutParams.FLAG_FULLSCREEN);

        setContentView(R.layout.activity_view_image);

        imageView = (ImageView) findViewById(R.id.iv_full_image);
        btnBack = (ImageButton) findViewById(R.id.btn_view_back);
        btnDelete = (ImageButton) findViewById(R.id.btn_view_delete);
        btnRotate = (ImageButton) findViewById(R.id.btn_view_rotate);
        btnDownload = (ImageButton) findViewById(R.id.btn_view_download);

        matrix = new Matrix();
        savedMatrix = new Matrix();

        imagePath = getIntent().getStringExtra(EXTRA_IMAGE_PATH);
        if (imagePath == null || !new File(imagePath).exists()) {
            Toast.makeText(this, "Image not found", Toast.LENGTH_SHORT).show();
            finish();
            return;
        }

        // Load image at full resolution for display (fitCenter handles scaling)
        loadImage();

        // Pinch zoom setup - start with fitCenter, allow zoom from there
        scaleDetector = new ScaleGestureDetector(this,
                new ScaleGestureDetector.SimpleOnScaleGestureListener() {
                    public boolean onScale(ScaleGestureDetector detector) {
                        scaleFactor = scaleFactor * detector.getScaleFactor();
                        scaleFactor = Math.max(0.5f, Math.min(scaleFactor, 5.0f));
                        applyTransform();
                        return true;
                    }
                });

        imageView.setOnTouchListener(new View.OnTouchListener() {
            public boolean onTouch(View v, MotionEvent event) {
                scaleDetector.onTouchEvent(event);

                switch (event.getActionMasked()) {
                    case MotionEvent.ACTION_DOWN:
                        savedMatrix.set(imageView.getImageMatrix());
                        lastTouchX = event.getX();
                        lastTouchY = event.getY();
                        mode = DRAG;
                        break;
                    case MotionEvent.ACTION_MOVE:
                        if (mode == DRAG && event.getPointerCount() == 1) {
                            float dx = event.getX() - lastTouchX;
                            float dy = event.getY() - lastTouchY;
                            Matrix m = new Matrix(savedMatrix);
                            m.postTranslate(dx, dy);
                            imageView.setImageMatrix(m);
                        }
                        break;
                    case MotionEvent.ACTION_UP:
                    case MotionEvent.ACTION_POINTER_UP:
                        mode = NONE;
                        break;
                }
                return true;
            }
        });

        // Double tap to reset zoom
        btnBack.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                finish();
            }
        });

        btnDelete.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                setResult(RESULT_DELETED, getIntent());
                finish();
            }
        });

        btnRotate.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                rotateImage();
            }
        });

        btnDownload.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                checkStoragePermissionAndDownload();
            }
        });
    }

    /**
     * Load image with fitCenter - gallery-style display.
     * No zoom, no stretch, no crop. Original aspect ratio maintained.
     */
    private void loadImage() {
        if (imagePath == null) return;
        File file = new File(imagePath);
        if (!file.exists()) return;

        // Decode at screen resolution to avoid OOM but maintain quality
        BitmapFactory.Options opts = new BitmapFactory.Options();
        opts.inJustDecodeBounds = true;
        BitmapFactory.decodeFile(imagePath, opts);

        int screenWidth = getResources().getDisplayMetrics().widthPixels;
        int screenHeight = getResources().getDisplayMetrics().heightPixels;
        int maxDim = Math.max(screenWidth, screenHeight);

        // Only downsample if image is significantly larger than screen
        int sampleSize = 1;
        int imgMax = Math.max(opts.outWidth, opts.outHeight);
        while (imgMax / sampleSize > maxDim * 2) {
            sampleSize *= 2;
        }

        opts.inJustDecodeBounds = false;
        opts.inSampleSize = sampleSize;
        Bitmap bitmap = BitmapFactory.decodeFile(imagePath, opts);

        if (bitmap != null) {
            if (currentRotation != 0) {
                Matrix rotMatrix = new Matrix();
                rotMatrix.postRotate(currentRotation);
                Bitmap rotated = Bitmap.createBitmap(bitmap, 0, 0,
                        bitmap.getWidth(), bitmap.getHeight(), rotMatrix, true);
                if (rotated != bitmap) {
                    bitmap.recycle();
                }
                bitmap = rotated;
            }
            // Use fitCenter for gallery-style display
            imageView.setScaleType(ImageView.ScaleType.FIT_CENTER);
            imageView.setImageBitmap(bitmap);
            // Reset zoom state
            scaleFactor = 1.0f;
        } else {
            Toast.makeText(this, "Cannot load image", Toast.LENGTH_SHORT).show();
            finish();
        }
    }

    private void applyTransform() {
        // When user zooms, switch to matrix mode
        imageView.setScaleType(ImageView.ScaleType.MATRIX);
        Matrix m = new Matrix();
        // Get current image matrix from fitCenter
        float[] values = new float[9];
        imageView.getImageMatrix().getValues(values);
        m.set(imageView.getImageMatrix());
        // Scale around center
        float cx = imageView.getWidth() / 2f;
        float cy = imageView.getHeight() / 2f;
        m.setScale(scaleFactor, scaleFactor, cx, cy);
        imageView.setImageMatrix(m);
    }

    /**
     * Rotate image 90 degrees clockwise.
     */
    private void rotateImage() {
        currentRotation = (currentRotation + 90) % 360;
        loadImage();
    }

    /**
     * Check storage permission and download original image.
     */
    private void checkStoragePermissionAndDownload() {
        // On API 29+ (Android 10+), no WRITE_EXTERNAL_STORAGE needed for MediaStore
        if (Build.VERSION.SDK_INT >= 29) {
            downloadOriginalImage();
        } else {
            // API 26-28: need WRITE_EXTERNAL_STORAGE
            if (Build.VERSION.SDK_INT >= 23) {
                if (checkSelfPermission(android.Manifest.permission.WRITE_EXTERNAL_STORAGE)
                        != PackageManager.PERMISSION_GRANTED) {
                    requestPermissions(
                            new String[]{android.Manifest.permission.WRITE_EXTERNAL_STORAGE},
                            PERMISSION_WRITE_STORAGE);
                    return;
                }
            }
            downloadOriginalImage();
        }
    }

    /**
     * Download original image file to device Downloads/MKNotes/ folder.
     * NO compression, NO quality loss - copies the raw file bytes.
     */
    private void downloadOriginalImage() {
        if (imagePath == null) return;
        File sourceFile = new File(imagePath);
        if (!sourceFile.exists()) {
            Toast.makeText(this, "Image file not found", Toast.LENGTH_SHORT).show();
            return;
        }

        try {
            // Determine file extension from source
            String fileName = sourceFile.getName();
            String extension = "";
            int dotIdx = fileName.lastIndexOf('.');
            if (dotIdx >= 0) {
                extension = fileName.substring(dotIdx); // includes the dot
            }

            // Create a nice save name
            String saveName = "MKNotes_" + System.currentTimeMillis() + extension;

            // Determine MIME type
            String mimeType = "image/*";
            String lowerExt = extension.toLowerCase();
            if (lowerExt.equals(".jpg") || lowerExt.equals(".jpeg")) {
                mimeType = "image/jpeg";
            } else if (lowerExt.equals(".png")) {
                mimeType = "image/png";
            } else if (lowerExt.equals(".gif")) {
                mimeType = "image/gif";
            } else if (lowerExt.equals(".webp")) {
                mimeType = "image/webp";
            } else if (lowerExt.equals(".bmp")) {
                mimeType = "image/bmp";
            }

            if (Build.VERSION.SDK_INT >= 29) {
                // Android 10+ : Use MediaStore to save to Pictures
                ContentValues values = new ContentValues();
                values.put(MediaStore.Images.Media.DISPLAY_NAME, saveName);
                values.put(MediaStore.Images.Media.MIME_TYPE, mimeType);
                values.put(MediaStore.Images.Media.RELATIVE_PATH,
                        Environment.DIRECTORY_PICTURES + "/MKNotes");

                Uri imageUri = getContentResolver().insert(
                        MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values);
                if (imageUri == null) {
                    Toast.makeText(this, "Failed to save image", Toast.LENGTH_SHORT).show();
                    return;
                }

                // Copy raw bytes - no compression
                OutputStream os = getContentResolver().openOutputStream(imageUri);
                InputStream is = new FileInputStream(sourceFile);
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    os.write(buffer, 0, bytesRead);
                }
                os.flush();
                os.close();
                is.close();

                Toast.makeText(this, "Image saved to Pictures/MKNotes", Toast.LENGTH_SHORT).show();

            } else {
                // Android 8-9: Save to external storage Downloads/MKNotes/
                File downloadsDir = Environment.getExternalStoragePublicDirectory(
                        Environment.DIRECTORY_DOWNLOADS);
                File mkDir = new File(downloadsDir, "MKNotes");
                if (!mkDir.exists()) {
                    mkDir.mkdirs();
                }

                File destFile = new File(mkDir, saveName);

                // Copy raw bytes - no compression
                InputStream is = new FileInputStream(sourceFile);
                OutputStream os = new FileOutputStream(destFile);
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    os.write(buffer, 0, bytesRead);
                }
                os.flush();
                os.close();
                is.close();

                Toast.makeText(this, "Image saved to Downloads/MKNotes", Toast.LENGTH_SHORT).show();
            }

        } catch (Exception e) {
            Toast.makeText(this, "Failed to save: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_WRITE_STORAGE) {
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                downloadOriginalImage();
            } else {
                Toast.makeText(this, "Storage permission required to save image",
                        Toast.LENGTH_SHORT).show();
            }
        }
    }
}
