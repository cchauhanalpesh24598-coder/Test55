package com.mknotes.app.adapter;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageButton;
import android.widget.ImageView;

import com.mknotes.app.R;
import com.mknotes.app.model.FileAttachment;
import com.mknotes.app.util.AttachmentManager;

import java.io.File;
import java.util.List;

/**
 * Adapter for displaying image thumbnails in horizontal scroll view.
 * Replicates NotallyX PreviewImageAdapter behavior.
 */
public class ImagePreviewAdapter extends BaseAdapter {

    private Context context;
    private List images;
    private long noteId;
    private ImagePreviewListener listener;

    public interface ImagePreviewListener {
        void onImageClicked(int position, FileAttachment image);
        void onImageDeleteClicked(int position, FileAttachment image);
    }

    public ImagePreviewAdapter(Context context, List images, long noteId,
                                ImagePreviewListener listener) {
        this.context = context;
        this.images = images;
        this.noteId = noteId;
        this.listener = listener;
    }

    public int getCount() {
        return images != null ? images.size() : 0;
    }

    public Object getItem(int position) {
        return images.get(position);
    }

    public long getItemId(int position) {
        return position;
    }

    public View getView(int position, View convertView, ViewGroup parent) {
        if (convertView == null) {
            convertView = LayoutInflater.from(context).inflate(
                    R.layout.item_image_preview, parent, false);
        }

        final FileAttachment image = (FileAttachment) images.get(position);
        final int pos = position;

        ImageView ivThumb = (ImageView) convertView.findViewById(R.id.iv_thumbnail);
        ImageButton btnDelete = (ImageButton) convertView.findViewById(R.id.btn_delete_image);

        // Load thumbnail with memory-efficient sampling
        File imageFile = AttachmentManager.getImageFile(context, noteId, image.getLocalName());
        if (imageFile.exists()) {
            Bitmap thumb = decodeSampledBitmap(imageFile.getAbsolutePath(), 120, 120);
            if (thumb != null) {
                ivThumb.setImageBitmap(thumb);
            } else {
                ivThumb.setImageResource(R.drawable.ic_image);
            }
        } else {
            ivThumb.setImageResource(R.drawable.ic_image);
        }

        ivThumb.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (listener != null) {
                    listener.onImageClicked(pos, image);
                }
            }
        });

        btnDelete.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (listener != null) {
                    listener.onImageDeleteClicked(pos, image);
                }
            }
        });

        return convertView;
    }

    public void setNoteId(long noteId) {
        this.noteId = noteId;
    }

    /**
     * Memory-efficient bitmap decoding with inSampleSize.
     */
    private Bitmap decodeSampledBitmap(String path, int reqWidth, int reqHeight) {
        try {
            BitmapFactory.Options options = new BitmapFactory.Options();
            options.inJustDecodeBounds = true;
            BitmapFactory.decodeFile(path, options);

            options.inSampleSize = calculateInSampleSize(options, reqWidth, reqHeight);
            options.inJustDecodeBounds = false;
            return BitmapFactory.decodeFile(path, options);
        } catch (Exception e) {
            return null;
        }
    }

    private int calculateInSampleSize(BitmapFactory.Options options,
                                       int reqWidth, int reqHeight) {
        int height = options.outHeight;
        int width = options.outWidth;
        int inSampleSize = 1;

        if (height > reqHeight || width > reqWidth) {
            int halfHeight = height / 2;
            int halfWidth = width / 2;
            while ((halfHeight / inSampleSize) >= reqHeight
                    && (halfWidth / inSampleSize) >= reqWidth) {
                inSampleSize *= 2;
            }
        }
        return inSampleSize;
    }
}
