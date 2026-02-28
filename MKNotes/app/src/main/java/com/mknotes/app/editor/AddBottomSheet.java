package com.mknotes.app.editor;

import android.app.Dialog;
import android.content.Context;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.widget.LinearLayout;

import com.mknotes.app.R;

/**
 * Custom bottom sheet dialog (no AndroidX) that shows media attachment options.
 * Replicates NotallyX AddBottomSheet behavior with slide-up animation.
 */
public class AddBottomSheet extends Dialog {

    public static final int ACTION_ADD_IMAGE = 1;
    public static final int ACTION_ATTACH_FILE = 2;
    public static final int ACTION_RECORD_AUDIO = 3;
    public static final int ACTION_LINK_NOTE = 4;

    private ActionListener listener;
    private View contentView;

    public interface ActionListener {
        void onActionSelected(int action);
    }

    public AddBottomSheet(Context context, ActionListener listener) {
        super(context, android.R.style.Theme_Translucent_NoTitleBar);
        this.listener = listener;
        init(context);
    }

    private void init(Context context) {
        requestWindowFeature(Window.FEATURE_NO_TITLE);

        contentView = LayoutInflater.from(context).inflate(
                R.layout.dialog_add_bottom_sheet, null);

        setContentView(contentView);

        // Window setup: align to bottom, full width
        Window window = getWindow();
        if (window != null) {
            window.setLayout(WindowManager.LayoutParams.MATCH_PARENT,
                    WindowManager.LayoutParams.WRAP_CONTENT);
            window.setGravity(Gravity.BOTTOM);
            window.setBackgroundDrawableResource(android.R.color.transparent);
            window.setWindowAnimations(0); // We handle animation ourselves
        }

        // Dim background and dismiss on outside touch
        setCanceledOnTouchOutside(true);

        // Setup click listeners for each option
        View optImage = contentView.findViewById(R.id.option_add_image);
        View optFile = contentView.findViewById(R.id.option_attach_file);
        View optAudio = contentView.findViewById(R.id.option_record_audio);
        View optLink = contentView.findViewById(R.id.option_link_note);

        if (optImage != null) {
            optImage.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    if (listener != null) {
                        listener.onActionSelected(ACTION_ADD_IMAGE);
                    }
                    dismiss();
                }
            });
        }

        if (optFile != null) {
            optFile.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    if (listener != null) {
                        listener.onActionSelected(ACTION_ATTACH_FILE);
                    }
                    dismiss();
                }
            });
        }

        if (optAudio != null) {
            optAudio.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    if (listener != null) {
                        listener.onActionSelected(ACTION_RECORD_AUDIO);
                    }
                    dismiss();
                }
            });
        }

        if (optLink != null) {
            optLink.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    if (listener != null) {
                        listener.onActionSelected(ACTION_LINK_NOTE);
                    }
                    dismiss();
                }
            });
        }
    }

    public void show() {
        super.show();
        // Animate slide up
        if (contentView != null) {
            Animation slideUp = AnimationUtils.loadAnimation(
                    getContext(), R.anim.slide_up);
            contentView.startAnimation(slideUp);
        }
    }

    public void dismiss() {
        if (contentView != null) {
            Animation slideDown = AnimationUtils.loadAnimation(
                    getContext(), R.anim.slide_down);
            slideDown.setAnimationListener(new Animation.AnimationListener() {
                public void onAnimationStart(Animation animation) {
                }

                public void onAnimationEnd(Animation animation) {
                    AddBottomSheet.super.dismiss();
                }

                public void onAnimationRepeat(Animation animation) {
                }
            });
            contentView.startAnimation(slideDown);
        } else {
            super.dismiss();
        }
    }
}
