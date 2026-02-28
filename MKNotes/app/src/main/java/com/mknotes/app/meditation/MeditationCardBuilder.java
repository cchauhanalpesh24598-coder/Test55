package com.mknotes.app.meditation;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.mknotes.app.R;
import com.mknotes.app.db.NotesRepository;
import com.mknotes.app.model.Mantra;
import com.mknotes.app.service.MeditationService;

import java.util.ArrayList;
import java.util.List;

/**
 * Builds a SINGLE compact Meditation box in NoteEditor.
 * Contains multiple mantra rows inside one bordered container.
 * Layout per row:
 *   Line 1: Mantra Name (bold, left) + Delete button (right corner)
 *   Line 2: Count:- Mala:- (108 count = 1 Mala auto calculate)
 *   Line 3: [Play] [Stop] [Reset] [Speed 1x] all in one row
 * Only one mantra can play at a time.
 *
 * Pure Java, no AndroidX, no lambda - AIDE compatible.
 */
public class MeditationCardBuilder {

    private static final int COLOR_BOX_BG = Color.parseColor("#1A2A1A");
    private static final int COLOR_BOX_BORDER = Color.parseColor("#2E7D32");
    private static final int COLOR_HEADER_BG = Color.parseColor("#0D1F0D");
    private static final int COLOR_MANTRA_NAME = Color.parseColor("#81C784");
    private static final int COLOR_COUNT = Color.parseColor("#E0E0E0");
    private static final int COLOR_MALA = Color.parseColor("#A5D6A7");
    private static final int COLOR_BTN_BG = Color.parseColor("#1B5E20");
    private static final int COLOR_BTN_TEXT = Color.parseColor("#A5D6A7");
    private static final int COLOR_SPEED_ACTIVE = Color.parseColor("#4CAF50");
    private static final int COLOR_SPEED_INACTIVE = Color.parseColor("#333333");
    private static final int COLOR_DELETE_TEXT = Color.parseColor("#EF5350");
    private static final int COLOR_DIVIDER = Color.parseColor("#2E3E2E");
    private static final int COLOR_HEADER_TEXT = Color.parseColor("#66BB6A");

    private Activity activity;
    private NotesRepository repository;
    private MeditationPlayerManager playerManager;
    private LinearLayout container;
    private CardActionListener actionListener;
    private BroadcastReceiver countReceiver;
    private BroadcastReceiver stateReceiver;
    private boolean receiversRegistered = false;
    private long currentNoteId = -1;

    // Track row views for efficient updates
    private List mantraRowViews;

    public interface CardActionListener {
        void onMantraDeleted(Mantra mantra);
        void onDataChanged();
    }

    public MeditationCardBuilder(Activity activity, LinearLayout container) {
        this.activity = activity;
        this.container = container;
        this.repository = NotesRepository.getInstance(activity);
        this.playerManager = MeditationPlayerManager.getInstance(activity);
        this.mantraRowViews = new ArrayList();
        registerReceivers();
    }

    public void setActionListener(CardActionListener listener) {
        this.actionListener = listener;
    }

    /**
     * Register broadcast receivers for count updates and state changes.
     */
    private void registerReceivers() {
        if (receiversRegistered) return;

        countReceiver = new BroadcastReceiver() {
            public void onReceive(Context ctx, Intent intent) {
                if (currentNoteId != -1) {
                    refreshCards(currentNoteId);
                }
            }
        };

        stateReceiver = new BroadcastReceiver() {
            public void onReceive(Context ctx, Intent intent) {
                if (currentNoteId != -1) {
                    refreshCards(currentNoteId);
                }
            }
        };

        try {
            activity.registerReceiver(countReceiver,
                    new IntentFilter(MeditationPlayerManager.ACTION_COUNT_UPDATED));
            activity.registerReceiver(stateReceiver,
                    new IntentFilter(MeditationPlayerManager.ACTION_PLAYBACK_STATE_CHANGED));
            receiversRegistered = true;
        } catch (Exception e) { }
    }

    /**
     * Unregister receivers to prevent leaks.
     */
    public void unregisterReceivers() {
        if (!receiversRegistered) return;
        try {
            if (countReceiver != null) activity.unregisterReceiver(countReceiver);
            if (stateReceiver != null) activity.unregisterReceiver(stateReceiver);
        } catch (Exception e) { }
        receiversRegistered = false;
    }

    /**
     * Build the single meditation box with all mantra rows.
     * Data source: DailySession table for today, JOINed with MasterMantra.
     * Only mantras that have a session for today are shown as cards.
     * If a master mantra is soft-deleted (isDeleted=1), play is disabled
     * but the card is still visible with count data.
     */
    public void refreshCards(long noteId) {
        if (container == null) return;
        container.removeAllViews();
        mantraRowViews.clear();
        currentNoteId = noteId;

        String today = MeditationPlayerManager.getTodayDateString();

        // Load mantras that have a DailySession for today (session-driven)
        List mantras = repository.getMantrasWithSessionForNoteAndDate(noteId, today);
        if (mantras.isEmpty()) {
            container.setVisibility(View.GONE);
            return;
        }
        container.setVisibility(View.VISIBLE);

        // Single outer box
        LinearLayout box = new LinearLayout(activity);
        box.setOrientation(LinearLayout.VERTICAL);

        GradientDrawable boxBg = new GradientDrawable();
        boxBg.setCornerRadius(dp(12));
        boxBg.setColor(COLOR_BOX_BG);
        boxBg.setStroke(dp(1), COLOR_BOX_BORDER);
        box.setBackground(boxBg);

        // Header
        LinearLayout header = new LinearLayout(activity);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setPadding(dp(12), dp(8), dp(12), dp(6));

        GradientDrawable headerBg = new GradientDrawable();
        float[] radii = new float[]{dp(12), dp(12), dp(12), dp(12), 0, 0, 0, 0};
        headerBg.setCornerRadii(radii);
        headerBg.setColor(COLOR_HEADER_BG);
        header.setBackground(headerBg);

        TextView tvHeader = new TextView(activity);
        tvHeader.setText("Meditation");
        tvHeader.setTextColor(COLOR_HEADER_TEXT);
        tvHeader.setTextSize(13);
        tvHeader.setTypeface(Typeface.DEFAULT_BOLD);
        LinearLayout.LayoutParams headerTextParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        tvHeader.setLayoutParams(headerTextParams);
        header.addView(tvHeader);

        TextView tvCount = new TextView(activity);
        tvCount.setText(mantras.size() + " mantra" + (mantras.size() > 1 ? "s" : ""));
        tvCount.setTextColor(Color.parseColor("#888888"));
        tvCount.setTextSize(11);
        header.addView(tvCount);

        box.addView(header);

        // Mantra rows
        for (int i = 0; i < mantras.size(); i++) {
            Mantra mantra = (Mantra) mantras.get(i);

            // todayCount is already set from the JOIN query (session_count)
            int sessionCount = mantra.getTodayCount();

            if (i > 0) {
                // Divider between rows
                View divider = new View(activity);
                divider.setBackgroundColor(COLOR_DIVIDER);
                LinearLayout.LayoutParams divParams = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT, dp(1));
                divParams.setMargins(dp(12), 0, dp(12), 0);
                divider.setLayoutParams(divParams);
                box.addView(divider);
            }

            LinearLayout row = buildMantraRow(mantra, sessionCount, today);
            mantraRowViews.add(row);
            box.addView(row);
        }

        LinearLayout.LayoutParams boxParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        boxParams.setMargins(0, dp(4), 0, dp(4));
        box.setLayoutParams(boxParams);

        container.addView(box);
    }

    /**
     * Build a single mantra row within the box.
     * If mantra.isDeleted() == true, play controls are disabled and a "removed" label shown.
     */
    private LinearLayout buildMantraRow(final Mantra mantra, int sessionCount, final String today) {
        final boolean masterDeleted = mantra.isDeleted();

        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.VERTICAL);
        row.setPadding(dp(12), dp(8), dp(12), dp(8));

        // Line 1: Name (left, bold) + optional "removed" label + Delete button (right corner)
        LinearLayout line1 = new LinearLayout(activity);
        line1.setOrientation(LinearLayout.HORIZONTAL);
        line1.setGravity(Gravity.CENTER_VERTICAL);

        TextView tvName = new TextView(activity);
        tvName.setText(mantra.getName());
        tvName.setTextColor(masterDeleted ? Color.parseColor("#666666") : COLOR_MANTRA_NAME);
        tvName.setTextSize(14);
        tvName.setTypeface(Typeface.DEFAULT_BOLD);
        tvName.setSingleLine(true);
        LinearLayout.LayoutParams nameParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        tvName.setLayoutParams(nameParams);
        line1.addView(tvName);

        if (masterDeleted) {
            TextView tvRemoved = new TextView(activity);
            tvRemoved.setText("(removed)");
            tvRemoved.setTextColor(Color.parseColor("#888888"));
            tvRemoved.setTextSize(10);
            tvRemoved.setPadding(dp(4), 0, dp(4), 0);
            line1.addView(tvRemoved);
        }

        // Delete button (top right corner) - for NoteEditor day-specific delete
        TextView btnDelete = new TextView(activity);
        btnDelete.setText("X");
        btnDelete.setTextColor(COLOR_DELETE_TEXT);
        btnDelete.setTextSize(12);
        btnDelete.setTypeface(Typeface.DEFAULT_BOLD);
        btnDelete.setGravity(Gravity.CENTER);
        btnDelete.setPadding(dp(6), dp(2), dp(6), dp(2));

        GradientDrawable delBg = new GradientDrawable();
        delBg.setCornerRadius(dp(4));
        delBg.setStroke(dp(1), Color.parseColor("#EF5350"));
        btnDelete.setBackground(delBg);

        btnDelete.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                AlertDialog.Builder builder = new AlertDialog.Builder(activity);
                builder.setTitle("Remove Today's Session");
                builder.setMessage("Delete today's session data for \"" +
                        mantra.getName() + "\"? Other days and master list are not affected.");
                builder.setPositiveButton("Delete", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        // Stop if this mantra is playing
                        if (playerManager.isCurrentlyPlaying()
                                && playerManager.getCurrentMantraId() == mantra.getId()) {
                            playerManager.stopPlayback();
                            try {
                                Intent svcIntent = new Intent(activity, MeditationService.class);
                                svcIntent.setAction(MeditationService.ACTION_STOP);
                                activity.startService(svcIntent);
                            } catch (Exception ex) { }
                        }
                        // Delete only today's session
                        repository.deleteSessionForDate(mantra.getId(), today);
                        if (actionListener != null) {
                            actionListener.onDataChanged();
                        }
                        refreshCards(currentNoteId);
                    }
                });
                builder.setNegativeButton("Cancel", null);
                builder.show();
            }
        });

        line1.addView(btnDelete);
        row.addView(line1);

        // Line 2: Count:- Mala:-
        LinearLayout line2 = new LinearLayout(activity);
        line2.setOrientation(LinearLayout.HORIZONTAL);
        line2.setGravity(Gravity.CENTER_VERTICAL);
        line2.setPadding(0, dp(2), 0, dp(4));

        final TextView tvCountLabel = new TextView(activity);
        String countStr = "Count: " + sessionCount;
        tvCountLabel.setText(countStr);
        tvCountLabel.setTextColor(COLOR_COUNT);
        tvCountLabel.setTextSize(12);
        tvCountLabel.setPadding(0, 0, dp(12), 0);
        line2.addView(tvCountLabel);

        TextView tvMala = new TextView(activity);
        int malas = sessionCount / 108;
        int remainder = sessionCount % 108;
        String malaStr;
        if (sessionCount == 0) {
            malaStr = "Mala: 0";
        } else if (remainder == 0) {
            malaStr = "Mala: " + malas;
        } else {
            malaStr = "Mala: " + malas + " + " + remainder;
        }
        tvMala.setText(malaStr);
        tvMala.setTextColor(COLOR_MALA);
        tvMala.setTextSize(12);
        line2.addView(tvMala);

        row.addView(line2);

        // Line 3: [Play] [Stop] [Reset] [Speed 1x] all in one row
        LinearLayout line3 = new LinearLayout(activity);
        line3.setOrientation(LinearLayout.HORIZONTAL);
        line3.setGravity(Gravity.CENTER_VERTICAL);

        boolean isThisPlaying = playerManager.isCurrentlyPlaying()
                && playerManager.getCurrentMantraId() == mantra.getId();

        final TextView btnPlay = createActionBtn(isThisPlaying ? "Pause" : "Play");
        final TextView btnStop = createActionBtn("Stop");
        final TextView btnReset = createActionBtn("Reset");

        // Speed button with cycle
        float currentSpd = repository.getSessionSpeed(mantra.getId(), today);
        if (currentSpd < 0.9f) currentSpd = 1.0f;
        final float[] speedVal = {currentSpd};
        final TextView btnSpeed = createActionBtn(formatSpeed(speedVal[0]));

        // If master is deleted, disable play controls visually
        if (masterDeleted) {
            btnPlay.setAlpha(0.3f);
            btnStop.setAlpha(0.3f);
            btnSpeed.setAlpha(0.3f);
        } else {
            btnPlay.setAlpha(1.0f);
            btnStop.setAlpha(isThisPlaying ? 1.0f : 0.4f);
        }

        btnPlay.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (masterDeleted) {
                    Toast.makeText(activity, "Removed from library", Toast.LENGTH_SHORT).show();
                    return;
                }
                if (playerManager.isCurrentlyPlaying()
                        && playerManager.getCurrentMantraId() == mantra.getId()) {
                    // Pause
                    playerManager.pausePlayback();
                    try {
                        Intent svcIntent = new Intent(activity, MeditationService.class);
                        svcIntent.setAction(MeditationService.ACTION_PAUSE);
                        activity.startService(svcIntent);
                    } catch (Exception ex) { }
                } else {
                    // Play (auto-stops any other mantra)
                    String audioPath = mantra.getAudioPath();
                    if (audioPath == null || audioPath.length() == 0) {
                        Toast.makeText(activity, "No audio file assigned", Toast.LENGTH_SHORT).show();
                        return;
                    }

                    // Ensure session exists
                    repository.getOrCreateDailySession(mantra.getId(), today);

                    playerManager.setListener(new MeditationPlayerManager.PlaybackListener() {
                        public void onCountIncremented(long mantraId, int newCount) { }
                        public void onPlaybackStarted(long mantraId) {
                            activity.runOnUiThread(new Runnable() {
                                public void run() { refreshCards(currentNoteId); }
                            });
                        }
                        public void onPlaybackStopped(long mantraId) {
                            activity.runOnUiThread(new Runnable() {
                                public void run() { refreshCards(currentNoteId); }
                            });
                        }
                        public void onPlaybackError(long mantraId, final String message) {
                            activity.runOnUiThread(new Runnable() {
                                public void run() {
                                    Toast.makeText(activity, message, Toast.LENGTH_SHORT).show();
                                    refreshCards(currentNoteId);
                                }
                            });
                        }
                    });

                    Intent svcIntent = new Intent(activity, MeditationService.class);
                    svcIntent.setAction(MeditationService.ACTION_START);
                    svcIntent.putExtra(MeditationService.EXTRA_MANTRA_ID, mantra.getId());
                    try {
                        if (Build.VERSION.SDK_INT >= 26) {
                            activity.startForegroundService(svcIntent);
                        } else {
                            activity.startService(svcIntent);
                        }
                    } catch (Exception ex) { }

                    playerManager.startPlayback(mantra.getId(),
                            mantra.getAudioPath(), speedVal[0]);
                }
            }
        });

        btnStop.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (masterDeleted) return;
                if (playerManager.isCurrentlyPlaying()
                        && playerManager.getCurrentMantraId() == mantra.getId()) {
                    playerManager.stopPlayback();
                    try {
                        Intent svcIntent = new Intent(activity, MeditationService.class);
                        svcIntent.setAction(MeditationService.ACTION_STOP);
                        activity.startService(svcIntent);
                    } catch (Exception ex) { }
                    refreshCards(currentNoteId);
                }
            }
        });

        btnReset.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                AlertDialog.Builder builder = new AlertDialog.Builder(activity);
                builder.setTitle("Reset Count");
                builder.setMessage("Reset today's count for \"" +
                        mantra.getName() + "\" to 0?");
                builder.setPositiveButton("Reset", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        repository.resetSessionCount(mantra.getId(), today);
                        repository.saveMantraHistory(mantra.getId(), today, 0);
                        if (actionListener != null) {
                            actionListener.onDataChanged();
                        }
                        refreshCards(currentNoteId);
                    }
                });
                builder.setNegativeButton("Cancel", null);
                builder.show();
            }
        });

        btnSpeed.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (masterDeleted) return;
                // Cycle: 1x -> 1.5x -> 2x -> 2.5x -> 3x -> 1x
                float next;
                if (speedVal[0] < 1.4f) next = 1.5f;
                else if (speedVal[0] < 1.9f) next = 2.0f;
                else if (speedVal[0] < 2.4f) next = 2.5f;
                else if (speedVal[0] < 2.9f) next = 3.0f;
                else next = 1.0f;

                speedVal[0] = next;
                btnSpeed.setText(formatSpeed(next));

                repository.updateSessionSpeed(mantra.getId(), today, next);
                mantra.setPlaybackSpeed(next);
                repository.updateMantra(mantra);

                if (playerManager.isCurrentlyPlaying()
                        && playerManager.getCurrentMantraId() == mantra.getId()) {
                    playerManager.setSpeed(next);
                }
            }
        });

        line3.addView(btnPlay);
        line3.addView(btnStop);
        line3.addView(btnReset);
        line3.addView(btnSpeed);

        row.addView(line3);

        return row;
    }

    private String formatSpeed(float speed) {
        if (speed == 1.0f) return "1x";
        if (speed == 1.5f) return "1.5x";
        if (speed == 2.0f) return "2x";
        if (speed == 2.5f) return "2.5x";
        if (speed == 3.0f) return "3x";
        return String.valueOf(speed) + "x";
    }

    private TextView createActionBtn(String text) {
        TextView btn = new TextView(activity);
        btn.setText(text);
        btn.setTextColor(COLOR_BTN_TEXT);
        btn.setTextSize(11);
        btn.setGravity(Gravity.CENTER);
        btn.setPadding(dp(10), dp(4), dp(10), dp(4));

        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(4));
        bg.setColor(COLOR_BTN_BG);
        btn.setBackground(bg);

        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        params.setMargins(0, 0, dp(4), 0);
        btn.setLayoutParams(params);

        return btn;
    }

    private int dp(int dp) {
        float density = activity.getResources().getDisplayMetrics().density;
        return (int) (dp * density + 0.5f);
    }
}
