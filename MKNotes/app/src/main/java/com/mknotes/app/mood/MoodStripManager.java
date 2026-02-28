package com.mknotes.app.mood;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Handler;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.mknotes.app.db.MoodRepository;
import com.mknotes.app.model.NoteMood;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Manages the mood strip UI in the NoteEditor.
 * Handles mood selection dialog, intensity selection, strip rendering,
 * and auto-save to database.
 * Supports multiple moods per note with proper persistence.
 * Pure Java, no lambda, no AndroidX.
 */
public class MoodStripManager {

    private Activity activity;
    private MoodRepository moodRepo;
    private long noteId;
    private String noteDate;

    // Views
    private HorizontalScrollView moodStripScroll;
    private LinearLayout moodStripContainer;
    private TextView moodPlaceholder;

    // Current mood list
    private List currentMoods;

    // Prevent rapid tapping
    private long lastTapTime = 0;
    private static final long TAP_DEBOUNCE_MS = 400;

    // Pending mood data for deferred save (when noteId not yet assigned)
    private String pendingEmoji;
    private String pendingMoodName;
    private int pendingIntensityLevel;
    private boolean hasPendingMood = false;

    // Callback for when mood changes (optional)
    private MoodChangeListener changeListener;

    public interface MoodChangeListener {
        void onMoodChanged();
    }

    public MoodStripManager(Activity activity) {
        this.activity = activity;
        this.moodRepo = MoodRepository.getInstance(activity);
        this.currentMoods = new ArrayList();
    }

    /**
     * Initialize with view references. Call after setContentView.
     */
    public void initViews(HorizontalScrollView scroll, LinearLayout container, TextView placeholder) {
        this.moodStripScroll = scroll;
        this.moodStripContainer = container;
        this.moodPlaceholder = placeholder;

        if (moodStripContainer != null) {
            moodStripContainer.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    if (System.currentTimeMillis() - lastTapTime < TAP_DEBOUNCE_MS) return;
                    lastTapTime = System.currentTimeMillis();
                    showMoodSelectionDialog();
                }
            });
        }
    }

    /**
     * Set the note context. Must be called before loadMoods.
     */
    public void setNoteContext(long noteId, long createdAt) {
        this.noteId = noteId;
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
        this.noteDate = sdf.format(new Date(createdAt));
    }

    public void setChangeListener(MoodChangeListener listener) {
        this.changeListener = listener;
    }

    /**
     * Load existing moods from database and refresh the strip.
     */
    public void loadMoods() {
        if (noteId <= 0) {
            currentMoods = new ArrayList();
        } else {
            currentMoods = moodRepo.getMoodsForNote(noteId);
        }
        refreshStrip();
    }

    /**
     * Called after note is saved and noteId is now valid.
     * Saves any pending mood that was deferred.
     */
    public void savePendingMood() {
        if (!hasPendingMood) return;
        if (noteId <= 0) return;

        hasPendingMood = false;
        doSaveMood(pendingEmoji, pendingMoodName, pendingIntensityLevel);
    }

    /**
     * Refresh the visual mood strip based on currentMoods.
     */
    public void refreshStrip() {
        if (moodStripContainer == null) return;

        // Remove all but keep container clickable
        moodStripContainer.removeAllViews();

        if (currentMoods == null || currentMoods.isEmpty()) {
            // Show placeholder - recreate to avoid parent issues
            moodPlaceholder = new TextView(activity);
            moodPlaceholder.setText("+ Mood");
            moodPlaceholder.setTextColor(0xFFBDBDBD);
            moodPlaceholder.setTextSize(12);
            moodPlaceholder.setPadding(dpPx(4), dpPx(4), dpPx(4), dpPx(4));
            moodStripContainer.addView(moodPlaceholder);
            return;
        }

        // Add a "+" button first for adding more moods
        TextView addMore = new TextView(activity);
        addMore.setText("+");
        addMore.setTextSize(18);
        addMore.setTextColor(0xFF9E9E9E);
        addMore.setGravity(Gravity.CENTER);
        addMore.setPadding(dpPx(8), dpPx(2), dpPx(4), dpPx(2));
        LinearLayout.LayoutParams addLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        addMore.setLayoutParams(addLp);
        moodStripContainer.addView(addMore);

        // Build mood chips sorted by intensity (highest first - already sorted from DB)
        for (int i = 0; i < currentMoods.size(); i++) {
            NoteMood mood = (NoteMood) currentMoods.get(i);
            View chip = buildMoodChip(mood);
            // Small spacing between chips
            View spacer = new View(activity);
            LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(dpPx(5), dpPx(1));
            spacer.setLayoutParams(sp);
            moodStripContainer.addView(spacer);
            moodStripContainer.addView(chip);
        }
    }

    /**
     * Build a single mood chip showing emoji + name + intensity.
     * Fixed: proper sizing so emoji is fully visible, name doesn't truncate.
     */
    private View buildMoodChip(final NoteMood mood) {
        LinearLayout chip = new LinearLayout(activity);
        chip.setOrientation(LinearLayout.HORIZONTAL);
        chip.setGravity(Gravity.CENTER_VERTICAL);
        chip.setPadding(dpPx(8), dpPx(5), dpPx(10), dpPx(5));
        LinearLayout.LayoutParams chipLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        chipLp.bottomMargin = dpPx(1);
        chip.setLayoutParams(chipLp);

        // Background pill
        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dpPx(14));
        bg.setColor(0x20FFFFFF);
        chip.setBackground(bg);

        // Emoji - ensure full visibility with explicit min size to prevent crop
        TextView emojiTv = new TextView(activity);
        emojiTv.setText(mood.getEmojiUnicode());
        emojiTv.setTextSize(18);
        emojiTv.setGravity(Gravity.CENTER);
        emojiTv.setIncludeFontPadding(true);
        // Set explicit min size to prevent emoji cropping on all devices
        LinearLayout.LayoutParams emojiLp = new LinearLayout.LayoutParams(
                dpPx(28), dpPx(28));
        emojiLp.rightMargin = dpPx(4);
        emojiTv.setLayoutParams(emojiLp);
        chip.addView(emojiTv);

        // Label column: name + intensity on two lines
        LinearLayout labelCol = new LinearLayout(activity);
        labelCol.setOrientation(LinearLayout.VERTICAL);
        labelCol.setGravity(Gravity.CENTER_VERTICAL);

        // Mood name - full visible, no truncation, explicit wrap_content width
        TextView nameTv = new TextView(activity);
        nameTv.setText(mood.getMoodName());
        nameTv.setTextSize(11);
        nameTv.setTextColor(0xFFDDDDEE);
        nameTv.setSingleLine(true);
        nameTv.setMaxLines(1);
        // Ensure text is never ellipsized - it should always show full name
        LinearLayout.LayoutParams nameLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        nameTv.setLayoutParams(nameLp);
        nameTv.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        labelCol.addView(nameTv);

        // Intensity label with colored dot inline
        LinearLayout intensityRow = new LinearLayout(activity);
        intensityRow.setOrientation(LinearLayout.HORIZONTAL);
        intensityRow.setGravity(Gravity.CENTER_VERTICAL);

        View dot = new View(activity);
        LinearLayout.LayoutParams dotLp = new LinearLayout.LayoutParams(dpPx(5), dpPx(5));
        dotLp.rightMargin = dpPx(3);
        dot.setLayoutParams(dotLp);
        GradientDrawable dotBg = new GradientDrawable();
        dotBg.setShape(GradientDrawable.OVAL);
        dotBg.setColor(mood.getIntensityColor());
        dot.setBackground(dotBg);
        intensityRow.addView(dot);

        TextView intensityTv = new TextView(activity);
        intensityTv.setText(mood.getIntensityLabel());
        intensityTv.setTextSize(8);
        intensityTv.setTextColor(0xFF9E9E9E);
        intensityTv.setSingleLine(true);
        intensityRow.addView(intensityTv);

        labelCol.addView(intensityRow);
        chip.addView(labelCol);

        // Long press to remove
        chip.setOnLongClickListener(new View.OnLongClickListener() {
            public boolean onLongClick(View v) {
                confirmRemoveMood(mood);
                return true;
            }
        });

        return chip;
    }

    // ============ MOOD SELECTION DIALOG ============

    /**
     * Show the mood selection dialog with 10 predefined moods.
     */
    public void showMoodSelectionDialog() {
        if (activity == null || activity.isFinishing()) return;

        final AlertDialog.Builder builder = new AlertDialog.Builder(activity);
        builder.setCancelable(true);

        // Build dialog content
        ScrollView scroll = new ScrollView(activity);
        scroll.setPadding(dpPx(4), dpPx(4), dpPx(4), dpPx(4));

        LinearLayout root = new LinearLayout(activity);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dpPx(16), dpPx(12), dpPx(16), dpPx(12));

        // Dialog background
        GradientDrawable dialogBg = new GradientDrawable();
        dialogBg.setCornerRadius(dpPx(16));
        dialogBg.setColor(0xFF1A1D21);
        root.setBackground(dialogBg);

        // Title
        TextView title = new TextView(activity);
        title.setText("Select Mood");
        title.setTextSize(18);
        title.setTextColor(0xFFFFFFFF);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        title.setPadding(0, 0, 0, dpPx(12));
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        // Grid of moods: 2 columns
        LinearLayout grid = new LinearLayout(activity);
        grid.setOrientation(LinearLayout.VERTICAL);

        final AlertDialog[] dialogHolder = new AlertDialog[1];

        for (int i = 0; i < NoteMood.PREDEFINED_MOODS.length; i += 2) {
            LinearLayout row = new LinearLayout(activity);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER);
            LinearLayout.LayoutParams rowLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            rowLp.bottomMargin = dpPx(6);
            row.setLayoutParams(rowLp);

            // First column
            row.addView(buildMoodButton(i, dialogHolder));

            // Spacer
            View spacer = new View(activity);
            spacer.setLayoutParams(new LinearLayout.LayoutParams(dpPx(8), dpPx(1)));
            row.addView(spacer);

            // Second column (if exists)
            if (i + 1 < NoteMood.PREDEFINED_MOODS.length) {
                row.addView(buildMoodButton(i + 1, dialogHolder));
            } else {
                // Empty filler
                View filler = new View(activity);
                filler.setLayoutParams(new LinearLayout.LayoutParams(0, dpPx(1), 1));
                row.addView(filler);
            }

            grid.addView(row);
        }

        root.addView(grid);

        // Already added moods hint
        if (currentMoods != null && !currentMoods.isEmpty()) {
            TextView hint = new TextView(activity);
            hint.setText("Long press a mood in strip to remove");
            hint.setTextSize(10);
            hint.setTextColor(0xFF666680);
            hint.setGravity(Gravity.CENTER);
            hint.setPadding(0, dpPx(8), 0, 0);
            root.addView(hint);
        }

        scroll.addView(root);
        builder.setView(scroll);

        AlertDialog dialog = builder.create();
        dialogHolder[0] = dialog;

        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }
        dialog.show();
    }

    private View buildMoodButton(final int moodIndex, final AlertDialog[] dialogHolder) {
        final String emoji = NoteMood.PREDEFINED_MOODS[moodIndex][0];
        final String name = NoteMood.PREDEFINED_MOODS[moodIndex][1];

        LinearLayout btn = new LinearLayout(activity);
        btn.setOrientation(LinearLayout.HORIZONTAL);
        btn.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams btnLp = new LinearLayout.LayoutParams(0, dpPx(50), 1);
        btn.setLayoutParams(btnLp);
        btn.setPadding(dpPx(12), dpPx(8), dpPx(12), dpPx(8));

        // Check if already added - use trimmed comparison to handle edge cases
        boolean alreadyAdded = false;
        if (currentMoods != null) {
            for (int i = 0; i < currentMoods.size(); i++) {
                NoteMood existing = (NoteMood) currentMoods.get(i);
                if (existing.getMoodName() != null && existing.getMoodName().trim().equals(name.trim())) {
                    alreadyAdded = true;
                    break;
                }
            }
        }

        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dpPx(10));
        if (alreadyAdded) {
            bg.setColor(0xFF2A3A2A);
            bg.setStroke(dpPx(1), 0xFF4CAF50);
        } else {
            bg.setColor(0xFF2C2F33);
        }
        btn.setBackground(bg);

        // Emoji - ensure proper sizing for surrogate pair emojis (like Happy)
        TextView emojiTv = new TextView(activity);
        emojiTv.setText(emoji);
        emojiTv.setTextSize(22);
        emojiTv.setIncludeFontPadding(true);
        emojiTv.setGravity(Gravity.CENTER);
        // Explicit min size ensures surrogate pair emojis (like Happy) render fully
        LinearLayout.LayoutParams emojiLp = new LinearLayout.LayoutParams(
                dpPx(32), dpPx(32));
        emojiLp.rightMargin = dpPx(8);
        emojiTv.setLayoutParams(emojiLp);
        btn.addView(emojiTv);

        // Name - ensure full text visible, no ellipsize, no truncation
        TextView nameTv = new TextView(activity);
        nameTv.setText(name);
        nameTv.setTextSize(14);
        nameTv.setTextColor(alreadyAdded ? 0xFF4CAF50 : 0xFFEAEAF0);
        nameTv.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL));
        nameTv.setSingleLine(true);
        nameTv.setMaxLines(1);
        LinearLayout.LayoutParams nameLp = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1);
        nameTv.setLayoutParams(nameLp);
        btn.addView(nameTv);

        if (!alreadyAdded) {
            btn.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    if (dialogHolder[0] != null) {
                        dialogHolder[0].dismiss();
                    }
                    showIntensityDialog(emoji, name);
                }
            });
        } else {
            btn.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    Toast.makeText(activity, name + " already added", Toast.LENGTH_SHORT).show();
                }
            });
        }

        return btn;
    }

    // ============ INTENSITY SELECTION DIALOG ============

    private void showIntensityDialog(final String emoji, final String moodName) {
        if (activity == null || activity.isFinishing()) return;

        final AlertDialog.Builder builder = new AlertDialog.Builder(activity);
        builder.setCancelable(true);

        LinearLayout root = new LinearLayout(activity);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dpPx(20), dpPx(16), dpPx(20), dpPx(16));

        GradientDrawable dialogBg = new GradientDrawable();
        dialogBg.setCornerRadius(dpPx(16));
        dialogBg.setColor(0xFF1A1D21);
        root.setBackground(dialogBg);

        // Header: emoji + mood name
        LinearLayout header = new LinearLayout(activity);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER);
        header.setPadding(0, 0, 0, dpPx(14));

        TextView headerEmoji = new TextView(activity);
        headerEmoji.setText(emoji);
        headerEmoji.setTextSize(28);
        headerEmoji.setIncludeFontPadding(true);
        headerEmoji.setPadding(0, 0, dpPx(10), 0);
        header.addView(headerEmoji);

        TextView headerName = new TextView(activity);
        headerName.setText(moodName);
        headerName.setTextSize(18);
        headerName.setTextColor(0xFFFFFFFF);
        headerName.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        header.addView(headerName);

        root.addView(header);

        // Subtitle
        TextView subtitle = new TextView(activity);
        subtitle.setText("Select Intensity");
        subtitle.setTextSize(13);
        subtitle.setTextColor(0xFF8888A0);
        subtitle.setGravity(Gravity.CENTER);
        subtitle.setPadding(0, 0, 0, dpPx(10));
        root.addView(subtitle);

        final AlertDialog[] dialogHolder = new AlertDialog[1];

        // 5 intensity options
        for (int level = 1; level <= 5; level++) {
            final int intensityLevel = level;
            LinearLayout option = new LinearLayout(activity);
            option.setOrientation(LinearLayout.HORIZONTAL);
            option.setGravity(Gravity.CENTER_VERTICAL);
            LinearLayout.LayoutParams optLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, dpPx(44));
            optLp.bottomMargin = dpPx(4);
            option.setLayoutParams(optLp);
            option.setPadding(dpPx(14), dpPx(6), dpPx(14), dpPx(6));

            GradientDrawable optBg = new GradientDrawable();
            optBg.setCornerRadius(dpPx(10));
            optBg.setColor(0xFF2C2F33);
            option.setBackground(optBg);

            // Color dot
            View colorDot = new View(activity);
            LinearLayout.LayoutParams dotLp = new LinearLayout.LayoutParams(dpPx(12), dpPx(12));
            dotLp.rightMargin = dpPx(12);
            colorDot.setLayoutParams(dotLp);
            GradientDrawable dotShape = new GradientDrawable();
            dotShape.setShape(GradientDrawable.OVAL);
            dotShape.setColor(NoteMood.INTENSITY_COLORS[level - 1]);
            colorDot.setBackground(dotShape);
            option.addView(colorDot);

            // Label
            TextView labelTv = new TextView(activity);
            labelTv.setText(NoteMood.INTENSITY_LABELS[level - 1]);
            labelTv.setTextSize(14);
            labelTv.setTextColor(0xFFEAEAF0);
            labelTv.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL));
            LinearLayout.LayoutParams labelLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1);
            labelTv.setLayoutParams(labelLp);
            option.addView(labelTv);

            option.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    if (dialogHolder[0] != null) {
                        dialogHolder[0].dismiss();
                    }
                    saveMood(emoji, moodName, intensityLevel);
                }
            });

            root.addView(option);
        }

        builder.setView(root);
        AlertDialog dialog = builder.create();
        dialogHolder[0] = dialog;

        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }
        dialog.show();
    }

    // ============ SAVE / REMOVE MOOD ============

    private void saveMood(String emoji, String moodName, int intensityLevel) {
        // Defensive: normalize emoji string to avoid comparison issues
        if (emoji == null) emoji = "";

        // If noteId not valid, store as pending and signal caller to save note first
        if (noteId <= 0) {
            pendingEmoji = emoji;
            pendingMoodName = moodName;
            pendingIntensityLevel = intensityLevel;
            hasPendingMood = true;
            if (changeListener != null) {
                changeListener.onMoodChanged();
            }
            return;
        }

        doSaveMood(emoji, moodName, intensityLevel);
    }

    private void doSaveMood(String emoji, String moodName, int intensityLevel) {
        if (noteId <= 0) return;

        // Ensure noteDate is set
        if (noteDate == null || noteDate.length() == 0) {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
            noteDate = sdf.format(new Date());
        }

        // Defensive: normalize emoji to prevent null/empty save issues
        if (emoji == null) emoji = "";

        NoteMood mood = new NoteMood(noteId, noteDate, emoji, moodName, intensityLevel);
        mood.setTimestamp(System.currentTimeMillis());

        long resultId = moodRepo.insertOrUpdateMood(mood);

        // Reload from DB to get sorted list
        currentMoods = moodRepo.getMoodsForNote(noteId);

        // Force UI rebuild on main thread to ensure strip updates immediately
        if (activity != null && !activity.isFinishing()) {
            activity.runOnUiThread(new Runnable() {
                public void run() {
                    refreshStrip();
                }
            });
        } else {
            refreshStrip();
        }
    }

    private void confirmRemoveMood(final NoteMood mood) {
        AlertDialog.Builder builder = new AlertDialog.Builder(activity);

        LinearLayout root = new LinearLayout(activity);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dpPx(20), dpPx(16), dpPx(20), dpPx(16));

        GradientDrawable dialogBg = new GradientDrawable();
        dialogBg.setCornerRadius(dpPx(16));
        dialogBg.setColor(0xFF1A1D21);
        root.setBackground(dialogBg);

        TextView title = new TextView(activity);
        title.setText("Remove " + mood.getEmojiUnicode() + " " + mood.getMoodName() + "?");
        title.setTextSize(16);
        title.setTextColor(0xFFFFFFFF);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        title.setGravity(Gravity.CENTER);
        title.setPadding(0, 0, 0, dpPx(14));
        root.addView(title);

        LinearLayout btnRow = new LinearLayout(activity);
        btnRow.setOrientation(LinearLayout.HORIZONTAL);
        btnRow.setGravity(Gravity.CENTER);

        final AlertDialog[] dialogHolder = new AlertDialog[1];

        // Cancel button
        TextView btnCancel = new TextView(activity);
        btnCancel.setText("Cancel");
        btnCancel.setTextSize(14);
        btnCancel.setTextColor(0xFF8888A0);
        btnCancel.setGravity(Gravity.CENTER);
        btnCancel.setPadding(dpPx(20), dpPx(10), dpPx(20), dpPx(10));
        GradientDrawable cancelBg = new GradientDrawable();
        cancelBg.setCornerRadius(dpPx(8));
        cancelBg.setColor(0xFF2C2F33);
        btnCancel.setBackground(cancelBg);
        btnCancel.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (dialogHolder[0] != null) dialogHolder[0].dismiss();
            }
        });
        btnRow.addView(btnCancel);

        View spacer = new View(activity);
        spacer.setLayoutParams(new LinearLayout.LayoutParams(dpPx(12), dpPx(1)));
        btnRow.addView(spacer);

        // Remove button
        TextView btnRemove = new TextView(activity);
        btnRemove.setText("Remove");
        btnRemove.setTextSize(14);
        btnRemove.setTextColor(0xFFFFFFFF);
        btnRemove.setGravity(Gravity.CENTER);
        btnRemove.setPadding(dpPx(20), dpPx(10), dpPx(20), dpPx(10));
        GradientDrawable removeBg = new GradientDrawable();
        removeBg.setCornerRadius(dpPx(8));
        removeBg.setColor(0xFFE53935);
        btnRemove.setBackground(removeBg);
        btnRemove.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (dialogHolder[0] != null) dialogHolder[0].dismiss();
                removeMood(mood);
            }
        });
        btnRow.addView(btnRemove);

        root.addView(btnRow);
        builder.setView(root);

        AlertDialog dialog = builder.create();
        dialogHolder[0] = dialog;
        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }
        dialog.show();
    }

    private void removeMood(NoteMood mood) {
        if (mood.getId() > 0) {
            moodRepo.deleteMood(mood.getId());
        } else {
            moodRepo.deleteMoodByNoteAndName(noteId, mood.getMoodName());
        }
        currentMoods = moodRepo.getMoodsForNote(noteId);
        refreshStrip();

        if (changeListener != null) {
            changeListener.onMoodChanged();
        }
    }

    // ============ PUBLIC ACCESSORS ============

    public List getCurrentMoods() {
        return currentMoods;
    }

    public void setNoteId(long noteId) {
        this.noteId = noteId;
    }

    public long getNoteId() {
        return noteId;
    }

    /**
     * Apply color theme to the mood strip elements.
     */
    public void applyColors(int hintColor) {
        if (moodPlaceholder != null) {
            moodPlaceholder.setTextColor(hintColor);
        }
    }

    // ============ UNDO/REDO STATE SERIALIZATION ============

    /**
     * Serialize the current mood state into a String for undo/redo snapshots.
     * Format: each mood as "emoji|name|intensity" separated by newlines.
     */
    public String serializeMoodState() {
        if (currentMoods == null || currentMoods.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < currentMoods.size(); i++) {
            NoteMood mood = (NoteMood) currentMoods.get(i);
            if (i > 0) sb.append("\n");
            sb.append(mood.getEmojiUnicode());
            sb.append("|");
            sb.append(mood.getMoodName());
            sb.append("|");
            sb.append(mood.getIntensityLevel());
            sb.append("|");
            sb.append(mood.getId());
        }
        return sb.toString();
    }

    /**
     * Restore mood state from a serialized String (undo/redo).
     * Rebuilds the currentMoods list and refreshes the strip.
     * Also syncs changes to the database.
     */
    public void restoreMoodState(String state) {
        if (state == null || state.length() == 0) {
            // Clear all moods for this note
            if (noteId > 0) {
                moodRepo.deleteMoodsForNote(noteId);
            }
            currentMoods = new ArrayList();
            refreshStrip();
            return;
        }

        // Parse state and rebuild
        String[] lines = state.split("\n");
        List restoredMoods = new ArrayList();
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.length() == 0) continue;
            String[] parts = line.split("\\|");
            if (parts.length >= 3) {
                String emoji = parts[0];
                String name = parts[1];
                int intensity = 3;
                try {
                    intensity = Integer.parseInt(parts[2]);
                } catch (Exception e) { }
                long moodId = 0;
                if (parts.length >= 4) {
                    try {
                        moodId = Long.parseLong(parts[3]);
                    } catch (Exception e) { }
                }
                NoteMood mood = new NoteMood(noteId,
                        noteDate != null ? noteDate : "", emoji, name, intensity);
                mood.setId(moodId);
                mood.setTimestamp(System.currentTimeMillis());
                restoredMoods.add(mood);
            }
        }

        // Sync to database: delete all existing, re-insert restored
        if (noteId > 0) {
            moodRepo.deleteMoodsForNote(noteId);
            for (int i = 0; i < restoredMoods.size(); i++) {
                NoteMood mood = (NoteMood) restoredMoods.get(i);
                moodRepo.insertOrUpdateMood(mood);
            }
            // Reload from DB to get proper IDs
            currentMoods = moodRepo.getMoodsForNote(noteId);
        } else {
            currentMoods = restoredMoods;
        }
        refreshStrip();
    }

    // ============ UTILITY ============

    private int dpPx(float dp) {
        return (int) (dp * activity.getResources().getDisplayMetrics().density + 0.5f);
    }
}
