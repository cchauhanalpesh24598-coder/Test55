package com.mknotes.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.TimePickerDialog;
import android.content.ComponentName;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.graphics.PorterDuff;
import android.graphics.drawable.GradientDrawable;
import android.media.MediaPlayer;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.text.Editable;
import android.text.Layout;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.EditText;
import android.widget.HorizontalScrollView;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.PopupMenu;
import android.widget.ScrollView;
import android.widget.SeekBar;
import android.widget.TextView;
import android.widget.FrameLayout;
import android.widget.TimePicker;
import android.widget.Toast;

import com.mknotes.app.cloud.CloudSyncManager;
import com.mknotes.app.cloud.FirebaseAuthManager;
import com.mknotes.app.adapter.ChecklistAdapter;
import com.mknotes.app.checklist.ChangeHistory;
import com.mknotes.app.checklist.ChecklistDragHelper;
import com.mknotes.app.checklist.ChecklistManager;
import com.mknotes.app.db.NotesRepository;
import com.mknotes.app.editor.AddBottomSheet;
import com.mknotes.app.model.AudioAttachment;
import com.mknotes.app.model.Category;
import com.mknotes.app.model.FileAttachment;
import com.mknotes.app.model.ListItem;
import com.mknotes.app.model.Mantra;
import com.mknotes.app.model.Note;
import com.mknotes.app.richtext.RichTextStyleManager;
import com.mknotes.app.meditation.MeditationCardBuilder;
import com.mknotes.app.meditation.MeditationPlayerManager;
import com.mknotes.app.routine.RoutineContentWatcher;
import com.mknotes.app.routine.RoutineManager;
import com.mknotes.app.routine.RoutineTimeWatcher;
import com.mknotes.app.service.AudioRecordingService;
import com.mknotes.app.mood.MoodStripManager;
import com.mknotes.app.undoredo.UndoRedoManager;
import com.mknotes.app.undoredo.GenericUndoRedoManager;
import com.mknotes.app.util.AttachmentConverter;
import com.mknotes.app.util.AttachmentManager;
import com.mknotes.app.util.DateUtils;
import com.mknotes.app.util.FileErrorHandler;
import com.mknotes.app.util.ListItemConverter;
import com.mknotes.app.util.NoteColorUtil;
import com.mknotes.app.util.PrefsManager;
import com.mknotes.app.util.SessionManager;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * NoteEditorActivity - Full editor with:
 * - TopBar: Back, Title (inline), Favorite ONLY
 * - BottomBar: Add, Checklist, Undo, Redo, Pin, (spacer), TextFormat, More
 * - RichTextEditorPanel (horizontal scrollable formatting toolbar)
 * - NoteLinkDialog (add/edit/remove links)
 * - Media Attachments (images, files, audio, linked notes)
 * - NotallyX-style Change Color with dynamic background + contrast
 * - Routine mode with compact header, Wake/Sleep stacked right
 */
public class NoteEditorActivity extends Activity {

    private static final int REQUEST_IMAGE_PICK = 2001;
    private static final int REQUEST_FILE_PICK = 2002;
    private static final int REQUEST_VIEW_IMAGE = 2003;
    private static final int REQUEST_LINK_NOTE = 2004;
    private static final int REQUEST_MANTRA_MP3_PICK = 2005;
    private static final int PERMISSION_RECORD_AUDIO = 3001;
    private static final int PERMISSION_STORAGE = 3002;

    // Pending mantra name for mp3 selection flow
    private String pendingMantraName = null;
    // Reference to open popup dialog and its list container for refresh after mp3 pick
    private AlertDialog activeMantraPopupDialog = null;
    private LinearLayout activeMantraPopupListContainer = null;

    // TopBar views: Back + Title (inline) + Favorite
    private EditText etTitle;
    private EditText etContent;
    private TextView tvDate;
    private ImageButton btnBack;
    private ImageButton btnFavorite;

    // Bottom bar buttons (from XML now)
    private ImageButton btnUndo;
    private ImageButton btnRedo;
    // btnPin removed per ISSUE 10
    private ImageButton btnChecklistToggle;
    private ImageButton btnAddAttachment;
    private ImageButton btnOpenFormatPanel;
    private ImageButton btnBottomMore;

    // Root layout for background color
    private LinearLayout rootLayout;
    private View editorToolbar;

    // BottomBar reference
    private LinearLayout bottomBar;

    // Edited date (programmatic)
    private TextView tvEditedDate;

    // RichTextEditorPanel views
    private HorizontalScrollView richTextPanelScroll;
    private LinearLayout richTextPanel;
    private boolean isPanelVisible = false;

    // Panel buttons
    private ImageButton btnAlignLeft;
    private ImageButton btnAlignCenter;
    private ImageButton btnAlignRight;
    private ImageButton btnBold;
    private ImageButton btnItalic;
    private ImageButton btnUnderline;
    private ImageButton btnStrikethrough;
    private ImageButton btnLink;
    private ImageButton btnFontSize;
    private ImageButton btnTextColor;
    private ImageButton btnHighlight;
    private ImageButton btnBulletList;
    private ImageButton btnNumberedList;
    private ImageButton btnCode;
    private ImageButton btnClosePanel;

    // Checklist views and managers
    private ScrollView scrollTextContent;
    private LinearLayout checklistContainer;
    private ListView lvChecklist;
    private LinearLayout checklistAddItem;
    private ChecklistManager checklistManager;
    private ChecklistAdapter checklistAdapter;
    private ChecklistDragHelper checklistDragHelper;
    private boolean isChecklistMode;

    // Media attachment views
    private LinearLayout imagesContainer;
    private LinearLayout imagesList;
    private LinearLayout audiosContainer;
    private LinearLayout filesContainer;
    private LinearLayout linkedNotesContainer;

    // Media attachment data
    private List imageAttachments;
    private List fileAttachments;
    private List audioAttachments;
    private List linkedNoteIds;

    // Audio playback
    private MediaPlayer mediaPlayer;
    private Handler audioHandler;
    private int playingAudioIndex = -1;

    // Audio recording service
    private AudioRecordingService recordingService;
    private boolean serviceBound = false;

    private NotesRepository repository;
    private PrefsManager prefs;
    private RichTextStyleManager styleManager;
    private Note currentNote;
    private boolean isNewNote;
    private boolean hasChanges;

    // Word-based undo/redo manager for text editor
    private UndoRedoManager textUndoManager;
    // Generic undo/redo for routine mode
    private GenericUndoRedoManager routineUndoManager;
    // Generic undo/redo for mood strip
    private GenericUndoRedoManager moodUndoManager;

    // Pending action after image view returns
    private int pendingDeleteImageIndex = -1;

    // Routine mode fields
    private LinearLayout routineHeaderSection;
    private LinearLayout routineHeader;
    private LinearLayout routineEntriesContainer;
    private EditText etRoutineWake;
    private EditText etRoutineSleep;
    private EditText etRoutineContent;
    private boolean isRoutineMode;
    private RoutineManager routineManager;
    private RoutineContentWatcher routineContentWatcher;

    // Meditation mode fields
    private LinearLayout meditationContainer;
    private MeditationCardBuilder meditationCardBuilder;
    private boolean isMeditationMode;

    // Track which EditText is active for formatting
    private EditText activeEditText;

    // Flag to prevent recursive list continuation
    private boolean isListContinuing = false;

    // Mood strip manager
    private MoodStripManager moodStripManager;

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_note_editor);

        repository = NotesRepository.getInstance(this);
        prefs = PrefsManager.getInstance(this);
        textUndoManager = new UndoRedoManager();
        routineUndoManager = new GenericUndoRedoManager();
        moodUndoManager = new GenericUndoRedoManager();
        imageAttachments = new ArrayList();
        fileAttachments = new ArrayList();
        audioAttachments = new ArrayList();
        linkedNoteIds = new ArrayList();
        audioHandler = new Handler();

        initViews();
        initBottomBar();
        initRichTextPanel();
        initChecklist();
        loadNote();
        setupListeners();
        setupRichTextPanelListeners();
        updateEditedDate();
        applyNoteColor();
    }

    private void initViews() {
        rootLayout = (LinearLayout) findViewById(R.id.root_editor_layout);
        editorToolbar = findViewById(R.id.editor_toolbar);

        // TopBar: Title is now inside the toolbar
        etTitle = (EditText) findViewById(R.id.et_title);
        etContent = (EditText) findViewById(R.id.et_content);
        tvDate = (TextView) findViewById(R.id.tv_date);
        btnBack = (ImageButton) findViewById(R.id.btn_back);
        btnFavorite = (ImageButton) findViewById(R.id.btn_favorite);

        // Bottom bar buttons (all from XML)
        btnUndo = (ImageButton) findViewById(R.id.btn_undo);
        btnRedo = (ImageButton) findViewById(R.id.btn_redo);
        btnAddAttachment = (ImageButton) findViewById(R.id.btn_add_attachment);
        btnChecklistToggle = (ImageButton) findViewById(R.id.btn_checklist);
        btnOpenFormatPanel = (ImageButton) findViewById(R.id.btn_text_format);
        btnBottomMore = (ImageButton) findViewById(R.id.btn_color);

        // Checklist views
        scrollTextContent = (ScrollView) findViewById(R.id.scroll_text_content);
        checklistContainer = (LinearLayout) findViewById(R.id.checklist_container);
        lvChecklist = (ListView) findViewById(R.id.lv_checklist);
        checklistAddItem = (LinearLayout) findViewById(R.id.checklist_add_item);

        // Media attachment views
        imagesContainer = (LinearLayout) findViewById(R.id.images_container);
        imagesList = (LinearLayout) findViewById(R.id.images_list);
        audiosContainer = (LinearLayout) findViewById(R.id.audios_container);
        filesContainer = (LinearLayout) findViewById(R.id.files_container);
        linkedNotesContainer = (LinearLayout) findViewById(R.id.linked_notes_container);

        // Routine views
        routineHeaderSection = (LinearLayout) findViewById(R.id.routine_header_section);
        routineHeader = (LinearLayout) findViewById(R.id.routine_header);
        routineEntriesContainer = (LinearLayout) findViewById(R.id.routine_entries_container);
        etRoutineWake = (EditText) findViewById(R.id.et_routine_wake);
        etRoutineSleep = (EditText) findViewById(R.id.et_routine_sleep);
        etRoutineContent = (EditText) findViewById(R.id.et_routine_content);
        routineManager = new RoutineManager();
        isRoutineMode = false;

        // Meditation views
        meditationContainer = (LinearLayout) findViewById(R.id.meditation_container);
        isMeditationMode = false;

        // Initialize RichTextStyleManager with content EditText
        styleManager = new RichTextStyleManager(etContent);
        activeEditText = etContent;

        isChecklistMode = false;

        // Mood strip
        moodStripManager = new MoodStripManager(this);
        HorizontalScrollView moodScroll = (HorizontalScrollView) findViewById(R.id.mood_strip_scroll);
        LinearLayout moodContainer = (LinearLayout) findViewById(R.id.mood_strip_container);
        TextView moodPlaceholder = (TextView) findViewById(R.id.tv_mood_placeholder);
        moodStripManager.initViews(moodScroll, moodContainer, moodPlaceholder);
        moodStripManager.setChangeListener(new MoodStripManager.MoodChangeListener() {
            public void onMoodChanged() {
                // Ensure note is saved so mood can be attached
                ensureNoteSaved();
                if (moodStripManager.getNoteId() <= 0 && currentNote.getId() > 0) {
                    moodStripManager.setNoteId(currentNote.getId());
                    moodStripManager.setNoteContext(currentNote.getId(), currentNote.getCreatedAt());
                }
                // Save any pending mood that was deferred while noteId was not yet assigned
                moodStripManager.savePendingMood();
                hasChanges = true;

                // Push mood state snapshot for undo/redo
                String moodState = moodStripManager.serializeMoodState();
                moodUndoManager.pushState(moodState);
            }
        });
    }

    /**
     * BottomBar - buttons are defined in XML now. Just set reference and background.
     */
    private void initBottomBar() {
        bottomBar = (LinearLayout) findViewById(R.id.formatting_toolbar);
        if (bottomBar == null) return;
        bottomBar.setBackgroundColor(Color.parseColor("#14131B"));
    }

    /**
     * RichTextEditorPanel - horizontal scrollable formatting toolbar.
     */
    private void initRichTextPanel() {
        richTextPanelScroll = new HorizontalScrollView(this);
        richTextPanelScroll.setHorizontalScrollBarEnabled(false);
        richTextPanelScroll.setBackgroundColor(Color.parseColor("#1E1F2B"));
        richTextPanelScroll.setVisibility(View.GONE);

        richTextPanel = new LinearLayout(this);
        richTextPanel.setOrientation(LinearLayout.HORIZONTAL);
        richTextPanel.setGravity(Gravity.CENTER_VERTICAL);
        int pad = dpToPx(4);
        richTextPanel.setPadding(pad, pad, pad, pad);

        btnAlignLeft = createPanelButton(R.drawable.ic_align_left, getString(R.string.align_left));
        richTextPanel.addView(btnAlignLeft);
        btnAlignCenter = createPanelButton(R.drawable.ic_align_center, getString(R.string.align_center));
        richTextPanel.addView(btnAlignCenter);
        btnAlignRight = createPanelButton(R.drawable.ic_align_right, getString(R.string.align_right));
        richTextPanel.addView(btnAlignRight);
        richTextPanel.addView(createDivider());

        btnBold = createPanelButton(R.drawable.ic_format_bold, getString(R.string.format_bold));
        richTextPanel.addView(btnBold);
        btnItalic = createPanelButton(R.drawable.ic_format_italic, getString(R.string.format_italic));
        richTextPanel.addView(btnItalic);
        btnUnderline = createPanelButton(R.drawable.ic_format_underline, getString(R.string.format_underline));
        richTextPanel.addView(btnUnderline);
        btnStrikethrough = createPanelButton(R.drawable.ic_format_strikethrough, getString(R.string.format_strikethrough));
        richTextPanel.addView(btnStrikethrough);
        richTextPanel.addView(createDivider());

        btnLink = createPanelButton(R.drawable.ic_link, getString(R.string.insert_link));
        richTextPanel.addView(btnLink);
        richTextPanel.addView(createDivider());

        btnFontSize = createPanelButton(R.drawable.ic_font_size, getString(R.string.font_size_toggle));
        richTextPanel.addView(btnFontSize);
        btnTextColor = createPanelButton(R.drawable.ic_color_text, getString(R.string.text_color));
        richTextPanel.addView(btnTextColor);
        btnHighlight = createPanelButton(R.drawable.ic_highlight, getString(R.string.text_highlight));
        richTextPanel.addView(btnHighlight);
        richTextPanel.addView(createDivider());

        btnBulletList = createPanelButton(R.drawable.ic_list_bulleted, getString(R.string.format_bullet_list));
        richTextPanel.addView(btnBulletList);
        btnNumberedList = createPanelButton(R.drawable.ic_list_numbered, getString(R.string.numbered_list));
        richTextPanel.addView(btnNumberedList);
        richTextPanel.addView(createDivider());

        btnCode = createPanelButton(R.drawable.ic_code, getString(R.string.code_format));
        richTextPanel.addView(btnCode);
        btnClosePanel = createPanelButton(R.drawable.ic_close_panel, getString(R.string.close_panel));
        richTextPanel.addView(btnClosePanel);

        richTextPanelScroll.addView(richTextPanel);

        // Insert the panel above the bottom bar
        LinearLayout mainLayout = (LinearLayout) bottomBar.getParent();
        int bottomBarIndex = mainLayout.indexOfChild(bottomBar);
        LinearLayout.LayoutParams scrollParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dpToPx(48));
        mainLayout.addView(richTextPanelScroll, bottomBarIndex, scrollParams);
    }

    /**
     * Initialize the checklist system.
     */
    private void initChecklist() {
        checklistManager = new ChecklistManager();
        checklistAdapter = new ChecklistAdapter(this, checklistManager);

        if (lvChecklist != null) {
            lvChecklist.setAdapter(checklistAdapter);
        }

        if (lvChecklist != null) {
            checklistDragHelper = new ChecklistDragHelper(this, lvChecklist, checklistManager);
            checklistDragHelper.setDragListener(new ChecklistDragHelper.DragListener() {
                public void onDragStarted(int position) { }
                public void onDragMoved(int fromPosition, int toPosition) {
                    checklistAdapter.notifyDataSetChanged();
                }
                public void onDragEnded(int fromPosition, int toPosition) {
                    checklistAdapter.notifyDataSetChanged();
                    hasChanges = true;
                }
            });
            lvChecklist.setOnTouchListener(new View.OnTouchListener() {
                public boolean onTouch(View v, MotionEvent event) {
                    if (checklistDragHelper != null && checklistDragHelper.isDragging()) {
                        return checklistDragHelper.onTouch(v, event);
                    }
                    return false;
                }
            });
        }

        checklistAdapter.setAdapterListener(new ChecklistAdapter.ChecklistAdapterListener() {
            public void onDragStartRequested(int position, View itemView) {
                if (checklistDragHelper != null) {
                    int[] location = new int[2];
                    itemView.getLocationOnScreen(location);
                    checklistDragHelper.startDrag(position, itemView, location[1] + itemView.getHeight() / 2);
                }
            }
            public void onItemFocused(int position) { }
        });

        checklistManager.setListener(new ChecklistManager.ChecklistListener() {
            public void onItemsChanged() { checklistAdapter.notifyDataSetChanged(); hasChanges = true; }
            public void onItemAdded(int position) { checklistAdapter.notifyDataSetChanged(); hasChanges = true; }
            public void onItemRemoved(int position) { checklistAdapter.notifyDataSetChanged(); hasChanges = true; }
            public void onItemMoved(int fromPosition, int toPosition) { checklistAdapter.notifyDataSetChanged(); hasChanges = true; }
            public void onItemUpdated(int position) { checklistAdapter.notifyDataSetChanged(); hasChanges = true; }
            public void onRequestFocus(int position) { checklistAdapter.requestFocusAt(position); }
        });

        checklistManager.setHistoryListener(new ChangeHistory.ChangeHistoryListener() {
            public void onHistoryChanged(boolean canUndo, boolean canRedo) {
                if (isChecklistMode) {
                    btnUndo.setAlpha(canUndo ? 1.0f : 0.3f);
                    btnRedo.setAlpha(canRedo ? 1.0f : 0.3f);
                }
            }
        });

        if (checklistAddItem != null) {
            checklistAddItem.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    checklistManager.addItem("");
                }
            });
        }
    }

    private void toggleChecklistMode() {
        if (isChecklistMode) {
            switchToTextMode();
        } else {
            switchToChecklistMode();
        }
    }

    private void switchToChecklistMode() {
        isChecklistMode = true;
        currentNote.setChecklistMode(true);
        currentNote.setHasChecklist(true);

        String currentText = etContent.getText().toString();
        if (currentNote.getChecklistData() != null && currentNote.getChecklistData().length() > 2) {
            checklistManager.loadFromJson(currentNote.getChecklistData());
        } else if (currentText.length() > 0) {
            checklistManager.loadFromText(currentText);
        } else {
            List empty = new ArrayList();
            empty.add(new ListItem("", false, false, 0));
            checklistManager.loadItems(empty);
        }

        scrollTextContent.setVisibility(View.GONE);
        checklistContainer.setVisibility(View.VISIBLE);

        if (btnChecklistToggle != null) {
            btnChecklistToggle.setColorFilter(Color.parseColor("#1a73e8"));
        }
        if (richTextPanelScroll != null) {
            richTextPanelScroll.setVisibility(View.GONE);
            isPanelVisible = false;
        }
        if (btnOpenFormatPanel != null) {
            btnOpenFormatPanel.setAlpha(0.3f);
            btnOpenFormatPanel.setEnabled(false);
        }

        checklistAdapter.notifyDataSetChanged();
        hasChanges = true;
    }

    private void switchToTextMode() {
        isChecklistMode = false;
        currentNote.setChecklistMode(false);
        currentNote.setChecklistData(checklistManager.saveToJson());

        String textContent = checklistManager.toPlainText();
        etContent.setText(textContent);

        checklistContainer.setVisibility(View.GONE);
        scrollTextContent.setVisibility(View.VISIBLE);

        if (btnChecklistToggle != null) {
            btnChecklistToggle.setColorFilter(Color.parseColor("#CBCCCD"));
        }
        if (btnOpenFormatPanel != null) {
            btnOpenFormatPanel.setAlpha(1.0f);
            btnOpenFormatPanel.setEnabled(true);
        }

        hasChanges = true;
    }

    // ======================== DYNAMIC COLOR APPLICATION ========================

    private void applyNoteColor() {
        if (currentNote == null) return;

        int storedColor = currentNote.getColor();
        int bgColor = NoteColorUtil.resolveColor(storedColor);

        int textColor;
        int hintColor;
        int iconColor;
        int toolbarBg;
        int panelBg;
        int editorBg;

        editorBg = bgColor;
        toolbarBg = NoteColorUtil.getDarkerShade(bgColor);
        panelBg = NoteColorUtil.getLighterShade(bgColor);
        textColor = NoteColorUtil.getContrastTextColor(bgColor);
        hintColor = NoteColorUtil.getContrastHintColor(bgColor);
        iconColor = NoteColorUtil.getContrastIconColor(bgColor);

        if (rootLayout != null) rootLayout.setBackgroundColor(editorBg);
        if (editorToolbar != null) editorToolbar.setBackgroundColor(toolbarBg);

        if (Build.VERSION.SDK_INT >= 21) {
            Window window = getWindow();
            window.setStatusBarColor(toolbarBg);
        }

        if (etTitle != null) {
            etTitle.setTextColor(textColor);
            etTitle.setHintTextColor(hintColor);
        }
        if (etContent != null) {
            etContent.setTextColor(textColor);
            etContent.setHintTextColor(hintColor);
        }
        if (tvDate != null) tvDate.setTextColor(hintColor);

        if (scrollTextContent != null) scrollTextContent.setBackgroundColor(editorBg);
        if (checklistContainer != null) checklistContainer.setBackgroundColor(editorBg);
        if (checklistAddItem != null) checklistAddItem.setBackgroundColor(editorBg);

        if (btnBack != null) btnBack.setColorFilter(iconColor, PorterDuff.Mode.SRC_IN);
        if (btnFavorite != null) {
            if (!currentNote.isFavorite()) {
                btnFavorite.setColorFilter(iconColor, PorterDuff.Mode.SRC_IN);
            }
        }

        if (bottomBar != null) bottomBar.setBackgroundColor(toolbarBg);
        applyBottomBarIconColors(iconColor);

        if (tvEditedDate != null) tvEditedDate.setTextColor(hintColor);
        if (richTextPanelScroll != null) richTextPanelScroll.setBackgroundColor(panelBg);

        if (etRoutineContent != null) {
            etRoutineContent.setTextColor(textColor);
            etRoutineContent.setHintTextColor(hintColor);
        }

        // Apply to mood strip
        if (moodStripManager != null) {
            moodStripManager.applyColors(hintColor);
        }
    }

    private void applyBottomBarIconColors(int iconColor) {
        if (bottomBar == null) return;
        for (int i = 0; i < bottomBar.getChildCount(); i++) {
            View child = bottomBar.getChildAt(i);
            if (child instanceof ImageButton) {
                ImageButton btn = (ImageButton) child;
                if (btn == btnChecklistToggle && isChecklistMode) continue;
                btn.setColorFilter(iconColor, PorterDuff.Mode.SRC_IN);
            }
        }
    }

    // ======================== COLOR PICKER DIALOG ========================

    private void showColorPicker() {
        final AlertDialog.Builder builder = new AlertDialog.Builder(this);
        View dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_color_picker, null);
        builder.setView(dialogView);
        builder.setCancelable(true);

        final AlertDialog dialog = builder.create();
        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }

        final int originalStoredColor = currentNote.getColor();
        int currentBgColor = NoteColorUtil.resolveColor(originalStoredColor);

        final View colorPreview = dialogView.findViewById(R.id.color_preview);
        GradientDrawable previewShape = new GradientDrawable();
        previewShape.setCornerRadius(dpToPx(8));
        previewShape.setColor(currentBgColor);
        colorPreview.setBackground(previewShape);

        android.widget.FrameLayout wheelContainer =
                (android.widget.FrameLayout) dialogView.findViewById(R.id.color_wheel_container);
        final com.mknotes.app.view.ColorWheelView colorWheel =
                new com.mknotes.app.view.ColorWheelView(this);
        android.widget.FrameLayout.LayoutParams wheelParams =
                new android.widget.FrameLayout.LayoutParams(dpToPx(220), dpToPx(220));
        wheelParams.gravity = Gravity.CENTER;
        wheelContainer.addView(colorWheel, wheelParams);
        colorWheel.setColor(currentBgColor);

        android.widget.FrameLayout sliderContainer =
                (android.widget.FrameLayout) dialogView.findViewById(R.id.brightness_slider_container);
        final com.mknotes.app.view.BrightnessSliderView brightnessSlider =
                new com.mknotes.app.view.BrightnessSliderView(this);
        android.widget.FrameLayout.LayoutParams sliderParams =
                new android.widget.FrameLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT, dpToPx(48));
        sliderContainer.addView(brightnessSlider, sliderParams);

        float[] initHsv = new float[3];
        Color.colorToHSV(currentBgColor, initHsv);
        brightnessSlider.setHueAndSaturation(initHsv[0], initHsv[1]);
        brightnessSlider.setValue(initHsv[2]);

        final int[] pendingColor = new int[]{currentBgColor};

        colorWheel.setOnColorSelectedListener(new com.mknotes.app.view.ColorWheelView.OnColorSelectedListener() {
            public void onColorSelected(int color) {
                pendingColor[0] = color;
                updateColorPreview(colorPreview, color);
                brightnessSlider.setHueAndSaturation(
                        colorWheel.getSelectedHue(), colorWheel.getSelectedSaturation());
                applyLiveColorPreview(color);
            }
            public void onColorSelecting(int color) {
                pendingColor[0] = color;
                updateColorPreview(colorPreview, color);
                brightnessSlider.setHueAndSaturation(
                        colorWheel.getSelectedHue(), colorWheel.getSelectedSaturation());
                applyLiveColorPreview(color);
            }
        });

        brightnessSlider.setOnBrightnessChangedListener(new com.mknotes.app.view.BrightnessSliderView.OnBrightnessChangedListener() {
            public void onBrightnessChanged(float brightness) {
                colorWheel.setValue(brightness);
                int color = colorWheel.getSelectedColor();
                pendingColor[0] = color;
                updateColorPreview(colorPreview, color);
                applyLiveColorPreview(color);
            }
            public void onBrightnessChanging(float brightness) {
                colorWheel.setValue(brightness);
                int color = colorWheel.getSelectedColor();
                pendingColor[0] = color;
                updateColorPreview(colorPreview, color);
                applyLiveColorPreview(color);
            }
        });

        LinearLayout row1 = (LinearLayout) dialogView.findViewById(R.id.color_row_1);
        LinearLayout row2 = (LinearLayout) dialogView.findViewById(R.id.color_row_2);
        LinearLayout row3 = (LinearLayout) dialogView.findViewById(R.id.color_row_3);

        int[] presetColors = NoteColorUtil.getAllPresetColors();
        final View[] presetViews = new View[presetColors.length];

        for (int i = 0; i < presetColors.length; i++) {
            final int presetIdx = i;
            final int presetVal = presetColors[i];

            View presetView = new View(this);
            int size = dpToPx(36);
            LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(size, size);
            params.setMargins(dpToPx(5), dpToPx(4), dpToPx(5), dpToPx(4));
            presetView.setLayoutParams(params);

            GradientDrawable shape = new GradientDrawable();
            shape.setShape(GradientDrawable.OVAL);
            shape.setColor(presetVal);

            boolean isSelected = false;
            if (NoteColorUtil.isDefault(originalStoredColor) && presetIdx == 0) {
                isSelected = true;
            } else if (NoteColorUtil.isPreset(originalStoredColor) && originalStoredColor == presetIdx) {
                isSelected = true;
            }
            if (isSelected) {
                shape.setStroke(dpToPx(3), Color.parseColor("#1a73e8"));
            } else if (presetIdx == 0) {
                shape.setStroke(dpToPx(1), Color.parseColor("#767680"));
            }

            presetView.setBackground(shape);
            presetViews[i] = presetView;

            presetView.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    for (int j = 0; j < presetViews.length; j++) {
                        if (presetViews[j] != null) {
                            GradientDrawable s = new GradientDrawable();
                            s.setShape(GradientDrawable.OVAL);
                            s.setColor(NoteColorUtil.getPresetColor(j));
                            if (j == presetIdx) {
                                s.setStroke(dpToPx(3), Color.parseColor("#1a73e8"));
                            } else if (j == 0) {
                                s.setStroke(dpToPx(1), Color.parseColor("#767680"));
                            }
                            presetViews[j].setBackground(s);
                        }
                    }

                    colorWheel.setColor(presetVal);
                    float[] hsv = new float[3];
                    Color.colorToHSV(presetVal, hsv);
                    brightnessSlider.setHueAndSaturation(hsv[0], hsv[1]);
                    brightnessSlider.setValue(hsv[2]);

                    pendingColor[0] = presetVal;
                    updateColorPreview(colorPreview, presetVal);
                    applyLiveColorPreview(presetVal);
                }
            });

            if (i < 4) {
                row1.addView(presetView);
            } else if (i < 8) {
                row2.addView(presetView);
            } else {
                row3.addView(presetView);
            }
        }

        TextView btnColorBack = (TextView) dialogView.findViewById(R.id.btn_color_back);
        btnColorBack.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                currentNote.setColor(originalStoredColor);
                applyNoteColor();
                dialog.dismiss();
            }
        });

        TextView btnSave = (TextView) dialogView.findViewById(R.id.btn_color_save);
        btnSave.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                int finalColor = pendingColor[0];
                int presetMatch = NoteColorUtil.findPresetIndex(finalColor);
                if (presetMatch >= 0) {
                    currentNote.setColor(presetMatch);
                } else {
                    currentNote.setColor(finalColor);
                }
                hasChanges = true;
                applyNoteColor();
                dialog.dismiss();
            }
        });

        dialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
            public void onCancel(DialogInterface d) {
                currentNote.setColor(originalStoredColor);
                applyNoteColor();
            }
        });

        dialog.show();
    }

    private void updateColorPreview(View previewView, int color) {
        GradientDrawable shape = new GradientDrawable();
        shape.setCornerRadius(dpToPx(8));
        shape.setColor(color);
        previewView.setBackground(shape);
    }

    private void applyLiveColorPreview(int bgColor) {
        int textColor = NoteColorUtil.getContrastTextColor(bgColor);
        int hintColor = NoteColorUtil.getContrastHintColor(bgColor);
        int iconColor = NoteColorUtil.getContrastIconColor(bgColor);
        int toolbarBg = NoteColorUtil.getDarkerShade(bgColor);

        if (rootLayout != null) rootLayout.setBackgroundColor(bgColor);
        if (editorToolbar != null) editorToolbar.setBackgroundColor(toolbarBg);
        if (etTitle != null) {
            etTitle.setTextColor(textColor);
            etTitle.setHintTextColor(hintColor);
        }
        if (etContent != null) {
            etContent.setTextColor(textColor);
            etContent.setHintTextColor(hintColor);
        }
        if (tvDate != null) tvDate.setTextColor(hintColor);
        if (scrollTextContent != null) scrollTextContent.setBackgroundColor(bgColor);
        if (bottomBar != null) bottomBar.setBackgroundColor(toolbarBg);
        if (btnBack != null) btnBack.setColorFilter(iconColor, PorterDuff.Mode.SRC_IN);
        applyBottomBarIconColors(iconColor);
        if (tvEditedDate != null) tvEditedDate.setTextColor(hintColor);
        if (Build.VERSION.SDK_INT >= 21) {
            getWindow().setStatusBarColor(toolbarBg);
        }
    }

    // ======================== MEDIA ATTACHMENT SYSTEM ========================

    private void showAddBottomSheet() {
        ensureNoteSaved();

        AddBottomSheet sheet = new AddBottomSheet(this, new AddBottomSheet.ActionListener() {
            public void onActionSelected(int action) {
                switch (action) {
                    case AddBottomSheet.ACTION_ADD_IMAGE:
                        pickImage();
                        break;
                    case AddBottomSheet.ACTION_ATTACH_FILE:
                        pickFile();
                        break;
                    case AddBottomSheet.ACTION_RECORD_AUDIO:
                        checkAudioPermissionAndRecord();
                        break;
                    case AddBottomSheet.ACTION_LINK_NOTE:
                        showLinkNoteDialog();
                        break;
                }
            }
        });
        sheet.show();
    }

    private void ensureNoteSaved() {
        if (isNewNote || currentNote.getId() == -1) {
            String title = etTitle.getText().toString().trim();
            String content = etContent.getText().toString().trim();
            currentNote.setTitle(title);
            currentNote.setContent(content);
            currentNote.setModifiedAt(System.currentTimeMillis());
            long id = repository.insertNote(currentNote);
            currentNote.setId(id);
            isNewNote = false;
            // Update mood strip with new note id
            if (moodStripManager != null) {
                moodStripManager.setNoteId(id);
                moodStripManager.setNoteContext(id, currentNote.getCreatedAt());
            }
        }
    }

    // ---------- IMAGE PICK ----------

    private void pickImage() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("image/*");
        intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
        startActivityForResult(Intent.createChooser(intent, getString(R.string.add_image)), REQUEST_IMAGE_PICK);
    }

    private void handleImageResult(Intent data) {
        if (data == null) return;
        long noteId = currentNote.getId();

        if (data.getClipData() != null) {
            int count = data.getClipData().getItemCount();
            for (int i = 0; i < count; i++) {
                Uri uri = data.getClipData().getItemAt(i).getUri();
                addImageFromUri(uri, noteId);
            }
        } else if (data.getData() != null) {
            addImageFromUri(data.getData(), noteId);
        }

        saveAttachmentData();
        refreshImagePreviews();
        hasChanges = true;
    }

    private void addImageFromUri(Uri uri, long noteId) {
        FileAttachment img = AttachmentManager.copyFileToAttachments(this, uri, noteId, "images");
        if (img != null) {
            imageAttachments.add(img);
            currentNote.setHasImage(true);
        }
    }

    // ---------- FILE PICK ----------

    private void pickFile() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("*/*");
        startActivityForResult(Intent.createChooser(intent, getString(R.string.attach_file)), REQUEST_FILE_PICK);
    }

    private void handleFileResult(Intent data) {
        if (data == null || data.getData() == null) return;
        long noteId = currentNote.getId();

        FileAttachment file = AttachmentManager.copyFileToAttachments(this, data.getData(), noteId, "files");
        if (file != null) {
            fileAttachments.add(file);
            saveAttachmentData();
            refreshFilePreviews();
            hasChanges = true;
            Toast.makeText(this, R.string.file_attached, Toast.LENGTH_SHORT).show();
        }
    }

    // ---------- AUDIO RECORDING ----------

    private void checkAudioPermissionAndRecord() {
        if (Build.VERSION.SDK_INT >= 23) {
            if (checkSelfPermission(android.Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{android.Manifest.permission.RECORD_AUDIO}, PERMISSION_RECORD_AUDIO);
                return;
            }
        }
        showAudioRecordDialog();
    }

    private void showAudioRecordDialog() {
        final AlertDialog.Builder builder = new AlertDialog.Builder(this);
        View dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_audio_recorder, null);
        builder.setView(dialogView);
        builder.setCancelable(false);

        final AlertDialog dialog = builder.create();
        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }

        final TextView tvTimer = (TextView) dialogView.findViewById(R.id.tv_recording_timer);
        final TextView tvStatus = (TextView) dialogView.findViewById(R.id.tv_recording_status);
        final ImageButton btnToggle = (ImageButton) dialogView.findViewById(R.id.btn_record_toggle);
        final ImageButton btnStop = (ImageButton) dialogView.findViewById(R.id.btn_stop_recording);
        final ImageButton btnDiscard = (ImageButton) dialogView.findViewById(R.id.btn_discard_recording);

        final int[] recordState = {0};
        final String[] audioFilePath = {null};

        final ServiceConnection connection = new ServiceConnection() {
            public void onServiceConnected(ComponentName name, IBinder binder) {
                AudioRecordingService.RecordingBinder rb = (AudioRecordingService.RecordingBinder) binder;
                recordingService = rb.getService();
                serviceBound = true;

                recordingService.setCallback(new AudioRecordingService.RecordingCallback() {
                    public void onTimerUpdate(final long elapsedMs) {
                        runOnUiThread(new Runnable() {
                            public void run() {
                                tvTimer.setText(formatDuration(elapsedMs));
                            }
                        });
                    }
                    public void onRecordingError(final String message) {
                        runOnUiThread(new Runnable() {
                            public void run() {
                                Toast.makeText(NoteEditorActivity.this, message, Toast.LENGTH_SHORT).show();
                            }
                        });
                    }
                });
            }
            public void onServiceDisconnected(ComponentName name) {
                recordingService = null;
                serviceBound = false;
            }
        };

        Intent serviceIntent = new Intent(this, AudioRecordingService.class);
        startService(serviceIntent);
        bindService(serviceIntent, connection, Context.BIND_AUTO_CREATE);

        btnToggle.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (recordState[0] == 0) {
                    File audioFile = AttachmentManager.createAudioFile(NoteEditorActivity.this, currentNote.getId());
                    audioFilePath[0] = audioFile.getAbsolutePath();
                    if (recordingService != null && recordingService.startRecording(audioFilePath[0])) {
                        recordState[0] = 1;
                        tvStatus.setText(R.string.recording);
                        btnToggle.setImageResource(R.drawable.ic_pause);
                        btnStop.setVisibility(View.VISIBLE);
                        btnDiscard.setVisibility(View.VISIBLE);
                    } else {
                        FileErrorHandler.showRecordingError(NoteEditorActivity.this);
                    }
                } else if (recordState[0] == 1) {
                    if (recordingService != null && recordingService.pauseRecording()) {
                        recordState[0] = 2;
                        tvStatus.setText(R.string.recording_paused);
                        btnToggle.setImageResource(R.drawable.ic_mic);
                    }
                } else if (recordState[0] == 2) {
                    if (recordingService != null && recordingService.resumeRecording()) {
                        recordState[0] = 1;
                        tvStatus.setText(R.string.recording);
                        btnToggle.setImageResource(R.drawable.ic_pause);
                    }
                }
            }
        });

        btnStop.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (recordingService != null) {
                    long duration = recordingService.stopRecording();
                    if (audioFilePath[0] != null) {
                        File audioFile = new File(audioFilePath[0]);
                        if (audioFile.exists() && audioFile.length() > 0) {
                            AudioAttachment audio = new AudioAttachment(
                                    audioFile.getName(), duration, System.currentTimeMillis());
                            audioAttachments.add(audio);
                            saveAttachmentData();
                            refreshAudioPreviews();
                            hasChanges = true;
                            Toast.makeText(NoteEditorActivity.this, R.string.audio_recorded, Toast.LENGTH_SHORT).show();
                        }
                    }
                }
                cleanupRecordingService(connection);
                dialog.dismiss();
            }
        });

        btnDiscard.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (recordingService != null) {
                    recordingService.discardRecording();
                }
                cleanupRecordingService(connection);
                dialog.dismiss();
            }
        });

        dialog.show();
    }

    private void cleanupRecordingService(ServiceConnection connection) {
        if (serviceBound) {
            try {
                unbindService(connection);
            } catch (Exception e) { }
            serviceBound = false;
        }
        try {
            stopService(new Intent(this, AudioRecordingService.class));
        } catch (Exception e) { }
    }

    private String formatDuration(long ms) {
        long totalSeconds = ms / 1000;
        long minutes = totalSeconds / 60;
        long seconds = totalSeconds % 60;
        return String.format("%02d:%02d", Long.valueOf(minutes), Long.valueOf(seconds));
    }

    // ---------- LINK NOTE ----------

    private void showLinkNoteDialog() {
        final List allNotes = repository.getAllNotes("modified");
        final List available = new ArrayList();
        for (int i = 0; i < allNotes.size(); i++) {
            Note n = (Note) allNotes.get(i);
            if (n.getId() != currentNote.getId()) {
                boolean alreadyLinked = false;
                for (int j = 0; j < linkedNoteIds.size(); j++) {
                    if (((Long) linkedNoteIds.get(j)).longValue() == n.getId()) {
                        alreadyLinked = true;
                        break;
                    }
                }
                if (!alreadyLinked) {
                    available.add(n);
                }
            }
        }

        if (available.isEmpty()) {
            Toast.makeText(this, R.string.no_notes_to_link, Toast.LENGTH_SHORT).show();
            return;
        }

        String[] names = new String[available.size()];
        for (int i = 0; i < available.size(); i++) {
            Note n = (Note) available.get(i);
            String title = n.getTitle();
            if (title == null || title.length() == 0) {
                title = n.getPreview();
            }
            if (title == null || title.length() == 0) {
                title = getString(R.string.untitled);
            }
            if (title.length() > 50) {
                title = title.substring(0, 50) + "...";
            }
            names[i] = title;
        }

        AlertDialog.Builder dlgBuilder = new AlertDialog.Builder(this);
        dlgBuilder.setTitle(R.string.select_note_to_link);
        dlgBuilder.setItems(names, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                Note selected = (Note) available.get(which);
                linkedNoteIds.add(Long.valueOf(selected.getId()));
                saveAttachmentData();
                refreshLinkedNotesPreviews();
                hasChanges = true;
                Toast.makeText(NoteEditorActivity.this, R.string.note_linked, Toast.LENGTH_SHORT).show();
            }
        });
        dlgBuilder.setNegativeButton(R.string.cancel, null);
        dlgBuilder.show();
    }

    // ---------- ATTACHMENT PREVIEW RENDERING ----------

    private void refreshImagePreviews() {
        if (imagesList == null) return;
        imagesList.removeAllViews();

        if (imageAttachments.isEmpty()) {
            if (imagesContainer != null) imagesContainer.setVisibility(View.GONE);
            return;
        }
        if (imagesContainer != null) imagesContainer.setVisibility(View.VISIBLE);

        for (int i = 0; i < imageAttachments.size(); i++) {
            final int index = i;
            final FileAttachment img = (FileAttachment) imageAttachments.get(i);
            File imgFile = AttachmentManager.getImageFile(this, currentNote.getId(), img.getLocalName());

            LinearLayout frame = new LinearLayout(this);
            frame.setOrientation(LinearLayout.VERTICAL);
            LinearLayout.LayoutParams frameParams = new LinearLayout.LayoutParams(dpToPx(100), dpToPx(100));
            frameParams.setMargins(0, 0, dpToPx(8), 0);
            frame.setLayoutParams(frameParams);

            ImageView iv = new ImageView(this);
            iv.setScaleType(ImageView.ScaleType.CENTER_CROP);
            iv.setBackgroundColor(Color.parseColor("#2A2A2A"));
            LinearLayout.LayoutParams ivParams = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT);
            iv.setLayoutParams(ivParams);

            if (imgFile.exists()) {
                Bitmap thumb = decodeSampledBitmap(imgFile.getAbsolutePath(), 120, 120);
                if (thumb != null) {
                    iv.setImageBitmap(thumb);
                } else {
                    iv.setImageResource(R.drawable.ic_image);
                }
            } else {
                iv.setImageResource(R.drawable.ic_image);
            }

            iv.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    File f = AttachmentManager.getImageFile(NoteEditorActivity.this,
                            currentNote.getId(), img.getLocalName());
                    if (f.exists()) {
                        pendingDeleteImageIndex = index;
                        Intent viewIntent = new Intent(NoteEditorActivity.this, ViewImageActivity.class);
                        viewIntent.putExtra(ViewImageActivity.EXTRA_IMAGE_PATH, f.getAbsolutePath());
                        viewIntent.putExtra(ViewImageActivity.EXTRA_NOTE_ID, currentNote.getId());
                        viewIntent.putExtra(ViewImageActivity.EXTRA_IMAGE_INDEX, index);
                        startActivityForResult(viewIntent, REQUEST_VIEW_IMAGE);
                    }
                }
            });

            iv.setOnLongClickListener(new View.OnLongClickListener() {
                public boolean onLongClick(View v) {
                    confirmDeleteImage(index, img);
                    return true;
                }
            });

            frame.addView(iv);
            imagesList.addView(frame);
        }
    }

    private void confirmDeleteImage(final int index, final FileAttachment img) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.delete_image_title);
        builder.setMessage(R.string.delete_image_message);
        builder.setPositiveButton(R.string.delete, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                AttachmentManager.deleteAttachmentFile(NoteEditorActivity.this,
                        currentNote.getId(), img.getLocalName(), "images");
                imageAttachments.remove(index);
                if (imageAttachments.isEmpty()) {
                    currentNote.setHasImage(false);
                }
                saveAttachmentData();
                refreshImagePreviews();
                hasChanges = true;
            }
        });
        builder.setNegativeButton(R.string.cancel, null);
        builder.show();
    }

    private void refreshFilePreviews() {
        if (filesContainer == null) return;
        filesContainer.removeAllViews();

        if (fileAttachments.isEmpty()) {
            filesContainer.setVisibility(View.GONE);
            return;
        }
        filesContainer.setVisibility(View.VISIBLE);

        for (int i = 0; i < fileAttachments.size(); i++) {
            final int index = i;
            final FileAttachment file = (FileAttachment) fileAttachments.get(i);

            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(dpToPx(8), dpToPx(8), dpToPx(8), dpToPx(8));
            row.setBackgroundColor(Color.parseColor("#1E1F2B"));
            LinearLayout.LayoutParams rowParams = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            rowParams.setMargins(0, dpToPx(4), 0, dpToPx(4));
            row.setLayoutParams(rowParams);

            ImageView icon = new ImageView(this);
            icon.setImageResource(R.drawable.ic_attach_file);
            icon.setColorFilter(Color.parseColor("#CBCCCD"));
            LinearLayout.LayoutParams iconParams = new LinearLayout.LayoutParams(dpToPx(24), dpToPx(24));
            icon.setLayoutParams(iconParams);
            row.addView(icon);

            TextView tvName = new TextView(this);
            tvName.setText(file.getOriginalName());
            tvName.setTextColor(Color.parseColor("#E0E0E0"));
            tvName.setTextSize(14);
            tvName.setSingleLine(true);
            LinearLayout.LayoutParams nameParams = new LinearLayout.LayoutParams(
                    0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
            nameParams.setMargins(dpToPx(12), 0, dpToPx(8), 0);
            tvName.setLayoutParams(nameParams);
            row.addView(tvName);

            ImageButton btnDel = new ImageButton(this);
            btnDel.setImageResource(R.drawable.ic_close);
            btnDel.setBackgroundResource(android.R.color.transparent);
            btnDel.setColorFilter(Color.parseColor("#CBCCCD"));
            LinearLayout.LayoutParams delParams = new LinearLayout.LayoutParams(dpToPx(32), dpToPx(32));
            btnDel.setLayoutParams(delParams);
            btnDel.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    confirmDeleteFile(index, file);
                }
            });
            row.addView(btnDel);

            row.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    openAttachedFile(file);
                }
            });

            filesContainer.addView(row);
        }
    }

    private void confirmDeleteFile(final int index, final FileAttachment file) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.delete_file_title);
        builder.setMessage(R.string.delete_file_message);
        builder.setPositiveButton(R.string.delete, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                AttachmentManager.deleteAttachmentFile(NoteEditorActivity.this,
                        currentNote.getId(), file.getLocalName(), "files");
                fileAttachments.remove(index);
                saveAttachmentData();
                refreshFilePreviews();
                hasChanges = true;
            }
        });
        builder.setNegativeButton(R.string.cancel, null);
        builder.show();
    }

    private void openAttachedFile(FileAttachment file) {
        File f = AttachmentManager.getFileFile(this, currentNote.getId(), file.getLocalName());
        if (!f.exists()) {
            FileErrorHandler.showFileNotFound(this, file.getOriginalName());
            return;
        }
        try {
            File cacheDir = getCacheDir();
            File openDir = new File(cacheDir, "open_temp");
            if (!openDir.exists()) {
                openDir.mkdirs();
            }

            String targetName = file.getOriginalName();
            if (targetName == null || targetName.length() == 0) {
                targetName = file.getLocalName();
            }

            File targetFile = new File(openDir, targetName);
            copyFileInternal(f, targetFile);

            Uri contentUri = com.mknotes.app.util.MKFileProvider.getUriForFile(targetFile);
            String mimeType = guessMimeType(targetName);

            Intent openIntent = new Intent(Intent.ACTION_VIEW);
            openIntent.setDataAndType(contentUri, mimeType);
            openIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

            if (openIntent.resolveActivity(getPackageManager()) != null) {
                startActivity(openIntent);
            } else {
                Intent fallback = new Intent(Intent.ACTION_VIEW);
                fallback.setDataAndType(contentUri, "*/*");
                fallback.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                if (fallback.resolveActivity(getPackageManager()) != null) {
                    startActivity(fallback);
                } else {
                    Toast.makeText(this, R.string.no_app_to_open, Toast.LENGTH_SHORT).show();
                }
            }
        } catch (Exception e) {
            Toast.makeText(this, R.string.no_app_to_open, Toast.LENGTH_SHORT).show();
        }
    }

    private void copyFileInternal(File src, File dst) {
        try {
            java.io.FileInputStream in = new java.io.FileInputStream(src);
            java.io.FileOutputStream out = new java.io.FileOutputStream(dst);
            byte[] buf = new byte[4096];
            int len;
            while ((len = in.read(buf)) > 0) {
                out.write(buf, 0, len);
            }
            in.close();
            out.close();
        } catch (Exception e) { }
    }

    private String guessMimeType(String fileName) {
        if (fileName == null) return "*/*";
        String lower = fileName.toLowerCase();
        if (lower.endsWith(".pdf")) return "application/pdf";
        if (lower.endsWith(".txt")) return "text/plain";
        if (lower.endsWith(".doc") || lower.endsWith(".docx")) return "application/msword";
        if (lower.endsWith(".xls") || lower.endsWith(".xlsx")) return "application/vnd.ms-excel";
        if (lower.endsWith(".ppt") || lower.endsWith(".pptx")) return "application/vnd.ms-powerpoint";
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
        if (lower.endsWith(".png")) return "image/png";
        if (lower.endsWith(".gif")) return "image/gif";
        if (lower.endsWith(".mp4")) return "video/mp4";
        if (lower.endsWith(".mp3")) return "audio/mpeg";
        if (lower.endsWith(".m4a")) return "audio/mp4";
        if (lower.endsWith(".wav")) return "audio/wav";
        if (lower.endsWith(".zip")) return "application/zip";
        if (lower.endsWith(".apk")) return "application/vnd.android.package-archive";
        if (lower.endsWith(".html") || lower.endsWith(".htm")) return "text/html";
        if (lower.endsWith(".csv")) return "text/csv";
        if (lower.endsWith(".json")) return "application/json";
        if (lower.endsWith(".xml")) return "text/xml";
        String ext = android.webkit.MimeTypeMap.getFileExtensionFromUrl(fileName);
        if (ext != null && ext.length() > 0) {
            String mapped = android.webkit.MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext);
            if (mapped != null) return mapped;
        }
        return "*/*";
    }

    private void refreshAudioPreviews() {
        if (audiosContainer == null) return;
        audiosContainer.removeAllViews();

        if (audioAttachments.isEmpty()) {
            audiosContainer.setVisibility(View.GONE);
            return;
        }
        audiosContainer.setVisibility(View.VISIBLE);

        for (int i = 0; i < audioAttachments.size(); i++) {
            final int index = i;
            final AudioAttachment audio = (AudioAttachment) audioAttachments.get(i);

            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(dpToPx(8), dpToPx(10), dpToPx(8), dpToPx(10));
            row.setBackgroundColor(Color.parseColor("#1E1F2B"));
            LinearLayout.LayoutParams rowParams = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            rowParams.setMargins(0, dpToPx(4), 0, dpToPx(4));
            row.setLayoutParams(rowParams);

            final ImageButton btnPlay = new ImageButton(this);
            btnPlay.setImageResource(R.drawable.ic_play);
            btnPlay.setBackgroundResource(android.R.color.transparent);
            btnPlay.setColorFilter(Color.parseColor("#CBCCCD"));
            LinearLayout.LayoutParams playParams = new LinearLayout.LayoutParams(dpToPx(32), dpToPx(32));
            btnPlay.setLayoutParams(playParams);
            row.addView(btnPlay);

            final TextView tvDuration = new TextView(this);
            tvDuration.setText(audio.getFormattedDuration());
            tvDuration.setTextColor(Color.parseColor("#E0E0E0"));
            tvDuration.setTextSize(14);
            LinearLayout.LayoutParams durParams = new LinearLayout.LayoutParams(
                    0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
            durParams.setMargins(dpToPx(12), 0, dpToPx(8), 0);
            tvDuration.setLayoutParams(durParams);
            row.addView(tvDuration);

            ImageButton btnDel = new ImageButton(this);
            btnDel.setImageResource(R.drawable.ic_close);
            btnDel.setBackgroundResource(android.R.color.transparent);
            btnDel.setColorFilter(Color.parseColor("#CBCCCD"));
            LinearLayout.LayoutParams delParams = new LinearLayout.LayoutParams(dpToPx(32), dpToPx(32));
            btnDel.setLayoutParams(delParams);
            btnDel.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    confirmDeleteAudio(index, audio);
                }
            });
            row.addView(btnDel);

            btnPlay.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    if (playingAudioIndex == index && mediaPlayer != null && mediaPlayer.isPlaying()) {
                        stopAudioPlayback();
                        btnPlay.setImageResource(R.drawable.ic_play);
                    } else {
                        stopAudioPlayback();
                        playAudio(audio, btnPlay);
                        playingAudioIndex = index;
                    }
                }
            });

            audiosContainer.addView(row);
        }
    }

    private void playAudio(AudioAttachment audio, final ImageButton btnPlay) {
        File audioFile = AttachmentManager.getAudioFile(this, currentNote.getId(), audio.getLocalName());
        if (!audioFile.exists()) {
            FileErrorHandler.showFileNotFound(this, audio.getLocalName());
            return;
        }
        try {
            mediaPlayer = new MediaPlayer();
            mediaPlayer.setDataSource(audioFile.getAbsolutePath());
            mediaPlayer.prepare();
            mediaPlayer.start();
            btnPlay.setImageResource(R.drawable.ic_stop);

            mediaPlayer.setOnCompletionListener(new MediaPlayer.OnCompletionListener() {
                public void onCompletion(MediaPlayer mp) {
                    btnPlay.setImageResource(R.drawable.ic_play);
                    playingAudioIndex = -1;
                    releaseMediaPlayer();
                }
            });
        } catch (Exception e) {
            Toast.makeText(this, "Cannot play audio", Toast.LENGTH_SHORT).show();
            releaseMediaPlayer();
        }
    }

    private void stopAudioPlayback() {
        if (mediaPlayer != null) {
            try {
                if (mediaPlayer.isPlaying()) {
                    mediaPlayer.stop();
                }
            } catch (Exception e) { }
            releaseMediaPlayer();
        }
        playingAudioIndex = -1;
    }

    private void releaseMediaPlayer() {
        if (mediaPlayer != null) {
            try {
                mediaPlayer.release();
            } catch (Exception e) { }
            mediaPlayer = null;
        }
    }

    private void confirmDeleteAudio(final int index, final AudioAttachment audio) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.delete_audio_title);
        builder.setMessage(R.string.delete_audio_message);
        builder.setPositiveButton(R.string.delete, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                stopAudioPlayback();
                AttachmentManager.deleteAttachmentFile(NoteEditorActivity.this,
                        currentNote.getId(), audio.getLocalName(), "audios");
                audioAttachments.remove(index);
                saveAttachmentData();
                refreshAudioPreviews();
                hasChanges = true;
            }
        });
        builder.setNegativeButton(R.string.cancel, null);
        builder.show();
    }

    private void refreshLinkedNotesPreviews() {
        if (linkedNotesContainer == null) return;
        linkedNotesContainer.removeAllViews();

        if (linkedNoteIds.isEmpty()) {
            linkedNotesContainer.setVisibility(View.GONE);
            return;
        }
        linkedNotesContainer.setVisibility(View.VISIBLE);

        for (int i = 0; i < linkedNoteIds.size(); i++) {
            final int index = i;
            long noteId = ((Long) linkedNoteIds.get(i)).longValue();
            final Note linked = repository.getNoteById(noteId);

            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(dpToPx(8), dpToPx(8), dpToPx(8), dpToPx(8));
            row.setBackgroundColor(Color.parseColor("#1E1F2B"));
            LinearLayout.LayoutParams rowParams = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            rowParams.setMargins(0, dpToPx(4), 0, dpToPx(4));
            row.setLayoutParams(rowParams);

            ImageView icon = new ImageView(this);
            icon.setImageResource(R.drawable.ic_link_note);
            icon.setColorFilter(Color.parseColor("#CBCCCD"));
            LinearLayout.LayoutParams iconParams = new LinearLayout.LayoutParams(dpToPx(24), dpToPx(24));
            icon.setLayoutParams(iconParams);
            row.addView(icon);

            TextView tvName = new TextView(this);
            String title = linked != null ? linked.getTitle() : "";
            if (title == null || title.length() == 0) {
                title = linked != null ? linked.getPreview() : getString(R.string.linked_note_deleted);
            }
            if (title == null || title.length() == 0) {
                title = getString(R.string.untitled);
            }
            tvName.setText(title);
            tvName.setTextColor(Color.parseColor("#82B1FF"));
            tvName.setTextSize(14);
            tvName.setSingleLine(true);
            LinearLayout.LayoutParams nameParams = new LinearLayout.LayoutParams(
                    0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
            nameParams.setMargins(dpToPx(12), 0, dpToPx(8), 0);
            tvName.setLayoutParams(nameParams);
            row.addView(tvName);

            ImageButton btnDel = new ImageButton(this);
            btnDel.setImageResource(R.drawable.ic_close);
            btnDel.setBackgroundResource(android.R.color.transparent);
            btnDel.setColorFilter(Color.parseColor("#CBCCCD"));
            LinearLayout.LayoutParams delParams = new LinearLayout.LayoutParams(dpToPx(32), dpToPx(32));
            btnDel.setLayoutParams(delParams);
            btnDel.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    linkedNoteIds.remove(index);
                    saveAttachmentData();
                    refreshLinkedNotesPreviews();
                    hasChanges = true;
                }
            });
            row.addView(btnDel);

            row.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    if (linked != null) {
                        saveNote();
                        Intent intent = new Intent(NoteEditorActivity.this, NoteEditorActivity.class);
                        intent.putExtra("note_id", linked.getId());
                        startActivity(intent);
                    } else {
                        Toast.makeText(NoteEditorActivity.this, R.string.linked_note_deleted, Toast.LENGTH_SHORT).show();
                    }
                }
            });

            linkedNotesContainer.addView(row);
        }
    }

    // ---------- ATTACHMENT DATA PERSISTENCE ----------

    private void loadAttachmentData() {
        if (currentNote == null) return;

        imageAttachments = AttachmentConverter.jsonToFiles(currentNote.getImagesData());
        fileAttachments = AttachmentConverter.jsonToFiles(currentNote.getFilesData());
        audioAttachments = AttachmentConverter.jsonToAudios(currentNote.getAudiosData());
        linkedNoteIds = AttachmentConverter.jsonToIds(currentNote.getLinkedNoteIds());

        refreshImagePreviews();
        refreshFilePreviews();
        refreshAudioPreviews();
        refreshLinkedNotesPreviews();
    }

    private void saveAttachmentData() {
        if (currentNote == null) return;

        currentNote.setImagesData(AttachmentConverter.filesToJson(imageAttachments));
        currentNote.setFilesData(AttachmentConverter.filesToJson(fileAttachments));
        currentNote.setAudiosData(AttachmentConverter.audiosToJson(audioAttachments));
        currentNote.setLinkedNoteIds(AttachmentConverter.idsToJson(linkedNoteIds));
        currentNote.setHasImage(!imageAttachments.isEmpty());
    }

    // ---------- BITMAP HELPER ----------

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

    private int calculateInSampleSize(BitmapFactory.Options options, int reqWidth, int reqHeight) {
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

    // ======================== PANEL / EDITOR HELPERS ========================

    private ImageButton createPanelButton(int drawableRes, String description) {
        ImageButton btn = new ImageButton(this);
        btn.setImageResource(drawableRes);
        btn.setContentDescription(description);
        btn.setScaleType(ImageButton.ScaleType.CENTER_INSIDE);
        btn.setBackgroundResource(R.drawable.bg_editor_panel_btn);
        btn.setColorFilter(Color.parseColor("#CBCCCD"));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                dpToPx(40), dpToPx(40));
        params.setMargins(dpToPx(1), 0, dpToPx(1), 0);
        btn.setLayoutParams(params);
        int padding = dpToPx(6);
        btn.setPadding(padding, padding, padding, padding);
        return btn;
    }

    private View createDivider() {
        View divider = new View(this);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                dpToPx(1), dpToPx(24));
        params.setMargins(dpToPx(4), 0, dpToPx(4), 0);
        divider.setLayoutParams(params);
        divider.setBackgroundColor(Color.parseColor("#393B3D"));
        return divider;
    }

    private void loadNote() {
        long noteId = getIntent().getLongExtra("note_id", -1);
        if (noteId == -1) {
            isNewNote = true;
            currentNote = new Note();
            currentNote.setColor(prefs.getDefaultColor());
            tvDate.setText(DateUtils.formatEditorDate(System.currentTimeMillis()));
        } else {
            isNewNote = false;
            currentNote = repository.getNoteById(noteId);
            if (currentNote != null) {
                etTitle.setText(currentNote.getTitle());
                // ISSUE 5: Load rich text formatting from HTML
                String savedContent = currentNote.getContent();
                if (savedContent != null && savedContent.contains("<") && savedContent.contains(">")) {
                    // Content has HTML tags - parse as HTML
                    android.text.Spanned formatted = android.text.Html.fromHtml(savedContent);
                    etContent.setText(formatted);
                } else {
                    etContent.setText(savedContent);
                }
                tvDate.setText(DateUtils.formatEditorDate(currentNote.getModifiedAt()));
                updateFavoriteIcon();
            } else {
                Toast.makeText(this, R.string.note_not_found, Toast.LENGTH_SHORT).show();
                finish();
                return;
            }
        }

        float fontSize = prefs.getFontSize();
        etContent.setTextSize(fontSize);

        if (!isNewNote) {
            loadAttachmentData();
        }

        if (currentNote.isChecklistMode()) {
            switchToChecklistMode();
        }

        // Restore routine mode for existing routine notes
        if (currentNote.isRoutineMode()) {
            restoreRoutineMode();
        }

        // Restore meditation mode if note has mantras
        if (!isNewNote) {
            restoreMeditationMode();
        }

        // Load mood strip data
        if (currentNote != null) {
            moodStripManager.setNoteContext(currentNote.getId(), currentNote.getCreatedAt());
            moodStripManager.loadMoods();
            // Push initial mood state for undo/redo
            moodUndoManager.pushInitialState(moodStripManager.serializeMoodState());
        }

        // Push initial state for word-based undo system
        textUndoManager.pushInitialState(etContent.getText(), etContent.getSelectionStart());
        textUndoManager.setListener(new UndoRedoManager.UndoRedoListener() {
            public void onUndoRedoStateChanged(boolean canUndo, boolean canRedo) {
                updateUndoRedoButtons();
            }
        });

        // Initialize routine undo manager listener
        routineUndoManager.setListener(routineUndoListener);

        // Initialize mood undo manager listener
        moodUndoManager.setListener(new GenericUndoRedoManager.StateChangeListener() {
            public void onStateChanged(boolean canUndo, boolean canRedo) {
                updateUndoRedoButtons();
            }
        });

        // Initial button state
        updateUndoRedoButtons();
    }

    private void setupListeners() {
        btnBack.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { saveAndFinish(); }
        });

        btnFavorite.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                currentNote.setFavorite(!currentNote.isFavorite());
                updateFavoriteIcon();
                hasChanges = true;
            }
        });

        btnUndo.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { performUndo(); }
        });

        btnRedo.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { performRedo(); }
        });

        // Checklist toggle from XML button
        if (btnChecklistToggle != null) {
            btnChecklistToggle.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    toggleChecklistMode();
                }
            });
        }

        // Add attachment from XML button
        if (btnAddAttachment != null) {
            btnAddAttachment.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    showAddBottomSheet();
                }
            });
        }

        if (btnOpenFormatPanel != null) {
            btnOpenFormatPanel.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) { toggleRichTextPanel(); }
            });
        }

        if (btnBottomMore != null) {
            btnBottomMore.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) { showEditorMenu(v); }
            });
        }

        etContent.addTextChangedListener(new TextWatcher() {
            private int changeStart = 0;
            private int changeCount = 0;
            private int changeBefore = 0;
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                changeStart = start;
                changeBefore = count;
            }
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                changeStart = start;
                changeCount = count;
                changeBefore = before;
            }
            public void afterTextChanged(Editable s) {
                hasChanges = true;

                // Word-based snapshot: push on trigger characters or paste
                if (!textUndoManager.isPerformingUndoRedo()) {
                    boolean shouldSnapshot = false;

                    // Check for paste (multiple chars inserted at once)
                    if (UndoRedoManager.isPaste(changeCount)) {
                        shouldSnapshot = true;
                    }

                    // Check for word boundary trigger (space, newline, punctuation)
                    if (!shouldSnapshot && changeCount == 1 && changeBefore == 0) {
                        int insertedPos = changeStart;
                        if (insertedPos >= 0 && insertedPos < s.length()) {
                            char inserted = s.charAt(insertedPos);
                            if (UndoRedoManager.isSnapshotTrigger(inserted)) {
                                shouldSnapshot = true;
                            }
                        }
                    }

                    // Check for deletion (characters removed)
                    if (!shouldSnapshot && changeBefore > 0 && changeCount == 0) {
                        shouldSnapshot = true;
                    }

                    if (shouldSnapshot) {
                        textUndoManager.pushSnapshot(s, etContent.getSelectionStart());
                    }
                }

                updatePanelButtonStates();
                updateUndoRedoButtons();

                // Auto-continue bullet/number list on Enter
                if (!isListContinuing && changeCount == 1 && changeBefore == 0) {
                    String text = s.toString();
                    if (changeStart < text.length() && text.charAt(changeStart) == '\n') {
                        handleListContinuation(etContent, s, changeStart);
                    }
                }
            }
        });

        etTitle.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) { }
            public void onTextChanged(CharSequence s, int start, int before, int count) { }
            public void afterTextChanged(Editable s) { hasChanges = true; }
        });

        // Track active EditText for formatting and undo/redo button updates
        etContent.setOnFocusChangeListener(new View.OnFocusChangeListener() {
            public void onFocusChange(View v, boolean hasFocus) {
                if (hasFocus) {
                    activeEditText = etContent;
                    styleManager = new RichTextStyleManager(etContent);
                    updateUndoRedoButtons();
                }
            }
        });
    }

    private void setupRichTextPanelListeners() {
        if (btnAlignLeft != null) {
            btnAlignLeft.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    styleManager.setAlignment(Layout.Alignment.ALIGN_NORMAL);
                    pushFormattingSnapshot();
                    updatePanelButtonStates();
                }
            });
        }
        if (btnAlignCenter != null) {
            btnAlignCenter.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    styleManager.setAlignment(Layout.Alignment.ALIGN_CENTER);
                    pushFormattingSnapshot();
                    updatePanelButtonStates();
                }
            });
        }
        if (btnAlignRight != null) {
            btnAlignRight.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    styleManager.setAlignment(Layout.Alignment.ALIGN_OPPOSITE);
                    pushFormattingSnapshot();
                    updatePanelButtonStates();
                }
            });
        }
        if (btnBold != null) {
            btnBold.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    styleManager.toggleBold();
                    pushFormattingSnapshot();
                    updatePanelButtonStates();
                }
            });
        }
        if (btnItalic != null) {
            btnItalic.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    styleManager.toggleItalic();
                    pushFormattingSnapshot();
                    updatePanelButtonStates();
                }
            });
        }
        if (btnUnderline != null) {
            btnUnderline.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    styleManager.toggleUnderline();
                    pushFormattingSnapshot();
                    updatePanelButtonStates();
                }
            });
        }
        if (btnStrikethrough != null) {
            btnStrikethrough.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    styleManager.toggleStrikethrough();
                    pushFormattingSnapshot();
                    updatePanelButtonStates();
                }
            });
        }
        if (btnLink != null) {
            btnLink.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) { showLinkDialog(); }
            });
        }
        if (btnFontSize != null) {
            btnFontSize.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    styleManager.toggleFontSize();
                    pushFormattingSnapshot();
                    updatePanelButtonStates();
                }
            });
        }
        if (btnTextColor != null) {
            btnTextColor.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    styleManager.toggleTextColor();
                    pushFormattingSnapshot();
                    updatePanelButtonStates();
                }
            });
        }
        if (btnHighlight != null) {
            btnHighlight.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    styleManager.toggleHighlight();
                    pushFormattingSnapshot();
                    updatePanelButtonStates();
                }
            });
        }
        if (btnBulletList != null) {
            btnBulletList.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    toggleBulletList();
                    pushFormattingSnapshot();
                    updatePanelButtonStates();
                }
            });
        }
        if (btnNumberedList != null) {
            btnNumberedList.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    toggleNumberedList();
                    pushFormattingSnapshot();
                    updatePanelButtonStates();
                }
            });
        }
        if (btnCode != null) {
            btnCode.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    styleManager.toggleCode();
                    pushFormattingSnapshot();
                    updatePanelButtonStates();
                }
            });
        }
        if (btnClosePanel != null) {
            btnClosePanel.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) { toggleRichTextPanel(); }
            });
        }
    }

    private void toggleRichTextPanel() {
        isPanelVisible = !isPanelVisible;
        if (richTextPanelScroll != null) {
            richTextPanelScroll.setVisibility(isPanelVisible ? View.VISIBLE : View.GONE);
        }
    }

    private void updatePanelButtonStates() {
        if (!isPanelVisible) return;
        styleManager.updateStatesFromCursor();

        int selectedColor = Color.parseColor("#393B3D");
        int normalColor = Color.TRANSPARENT;

        setPanelButtonSelected(btnBold, styleManager.isBoldActive(), selectedColor, normalColor);
        setPanelButtonSelected(btnItalic, styleManager.isItalicActive(), selectedColor, normalColor);
        setPanelButtonSelected(btnUnderline, styleManager.isUnderlineActive(), selectedColor, normalColor);
        setPanelButtonSelected(btnStrikethrough, styleManager.isStrikethroughActive(), selectedColor, normalColor);
        setPanelButtonSelected(btnFontSize, styleManager.isFontSizeActive(), selectedColor, normalColor);
        setPanelButtonSelected(btnTextColor, styleManager.isTextColorActive(), selectedColor, normalColor);
        setPanelButtonSelected(btnHighlight, styleManager.isHighlightActive(), selectedColor, normalColor);
        setPanelButtonSelected(btnBulletList, styleManager.isBulletListActive(), selectedColor, normalColor);
        setPanelButtonSelected(btnCode, styleManager.isCodeActive(), selectedColor, normalColor);

        Layout.Alignment align = styleManager.getCurrentAlignment();
        setPanelButtonSelected(btnAlignLeft, align == Layout.Alignment.ALIGN_NORMAL, selectedColor, normalColor);
        setPanelButtonSelected(btnAlignCenter, align == Layout.Alignment.ALIGN_CENTER, selectedColor, normalColor);
        setPanelButtonSelected(btnAlignRight, align == Layout.Alignment.ALIGN_OPPOSITE, selectedColor, normalColor);

        String linkUrl = styleManager.getLinkAtCursor();
        setPanelButtonSelected(btnLink, linkUrl != null, selectedColor, normalColor);

        if (btnTextColor != null) btnTextColor.setColorFilter(Color.RED);
        if (btnHighlight != null) btnHighlight.setColorFilter(Color.YELLOW);
    }

    private void setPanelButtonSelected(ImageButton btn, boolean selected,
                                        int selectedColor, int normalColor) {
        if (btn == null) return;
        if (selected) {
            btn.setBackgroundColor(selectedColor);
        } else {
            btn.setBackgroundResource(R.drawable.bg_editor_panel_btn);
        }
    }

    private void showLinkDialog() {
        final AlertDialog.Builder builder = new AlertDialog.Builder(this);
        View dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_link, null);
        builder.setView(dialogView);
        final AlertDialog dialog = builder.create();
        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }

        final EditText etLinkText = (EditText) dialogView.findViewById(R.id.et_link_text);
        final EditText etLinkUrl = (EditText) dialogView.findViewById(R.id.et_link_url);
        ImageButton btnClose = (ImageButton) dialogView.findViewById(R.id.btn_link_close);
        final TextView btnRemove = (TextView) dialogView.findViewById(R.id.btn_link_remove);
        final View spacerRemove = dialogView.findViewById(R.id.spacer_remove);
        TextView btnCancel = (TextView) dialogView.findViewById(R.id.btn_link_cancel);
        final TextView btnSave = (TextView) dialogView.findViewById(R.id.btn_link_save);

        String selectedText = styleManager.getSelectedText();
        if (selectedText.length() > 0) {
            etLinkText.setText(selectedText);
        }

        String existingLink = styleManager.getLinkAtCursor();
        if (existingLink != null) {
            etLinkUrl.setText(existingLink);
            etLinkText.setEnabled(false);
            btnRemove.setVisibility(View.VISIBLE);
            if (spacerRemove != null) spacerRemove.setVisibility(View.VISIBLE);
        }

        btnClose.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { dialog.dismiss(); }
        });
        btnCancel.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { dialog.dismiss(); }
        });
        btnRemove.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { styleManager.removeLink(); dialog.dismiss(); }
        });
        btnSave.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                String text = etLinkText.getText().toString().trim();
                String url = etLinkUrl.getText().toString().trim();
                if (url.length() == 0) {
                    Toast.makeText(NoteEditorActivity.this, "URL cannot be empty", Toast.LENGTH_SHORT).show();
                    return;
                }
                if (text.length() == 0) text = url;
                styleManager.addLink(text, url);
                hasChanges = true;
                dialog.dismiss();
            }
        });
        dialog.show();
    }

    private void updateEditedDate() {
        // tvEditedDate is no longer in the bottom bar layout
        // We use tvDate in the header instead
    }

    // Pin button removed per ISSUE 10

    // ======================== LIST AUTO-CONTINUATION ========================

    /**
     * Handle auto-continuation of bullet and numbered lists on Enter key.
     * When user presses Enter on a line starting with a bullet or number,
     * the next line automatically gets the next bullet/number.
     * If the current line only has the prefix (empty content), remove the prefix.
     */
    private void handleListContinuation(EditText target, Editable s, int newlinePos) {
        String text = s.toString();
        String bulletPrefix = "\u25CF ";

        // Find the line before the newline
        int prevLineStart = text.lastIndexOf('\n', newlinePos - 1);
        prevLineStart = (prevLineStart < 0) ? 0 : prevLineStart + 1;
        String prevLine = text.substring(prevLineStart, newlinePos);

        // Check for bullet prefix
        if (prevLine.startsWith(bulletPrefix)) {
            String content = prevLine.substring(bulletPrefix.length()).trim();
            if (content.length() == 0) {
                // Empty bullet line - remove the bullet prefix and don't continue
                isListContinuing = true;
                int removeStart = prevLineStart;
                int removeEnd = newlinePos + 1; // include the newline
                s.delete(removeStart, removeEnd);
                target.setSelection(removeStart);
                isListContinuing = false;
                return;
            }
            // Insert bullet on the new line
            isListContinuing = true;
            int insertPos = newlinePos + 1;
            if (insertPos <= s.length()) {
                s.insert(insertPos, bulletPrefix);
                target.setSelection(insertPos + bulletPrefix.length());
            }
            isListContinuing = false;
            return;
        }

        // Check for numbered list prefix (e.g. "1. ", "2. ", "12. ")
        if (prevLine.matches("^\\d+\\. .*")) {
            int dotIdx = prevLine.indexOf(". ");
            String numStr = prevLine.substring(0, dotIdx);
            String content = prevLine.substring(dotIdx + 2).trim();

            if (content.length() == 0) {
                // Empty numbered line - remove the number prefix and don't continue
                isListContinuing = true;
                int removeStart = prevLineStart;
                int removeEnd = newlinePos + 1;
                s.delete(removeStart, removeEnd);
                target.setSelection(removeStart);
                isListContinuing = false;
                return;
            }

            // Insert next number
            try {
                int num = Integer.parseInt(numStr);
                String nextPrefix = (num + 1) + ". ";
                isListContinuing = true;
                int insertPos = newlinePos + 1;
                if (insertPos <= s.length()) {
                    s.insert(insertPos, nextPrefix);
                    target.setSelection(insertPos + nextPrefix.length());
                }
                isListContinuing = false;
            } catch (Exception e) {
                // Not a valid number, ignore
            }
            return;
        }
    }

    // ======================== BULLET & NUMBERED LIST (Text-based) ========================

    /**
     * Toggle bullet list using text-based bullets for reliable save/load.
     * Uses the Unicode bullet character.
     */
    private void toggleBulletList() {
        EditText target = activeEditText;
        if (target == null) target = etContent;

        int start = target.getSelectionStart();
        int end = target.getSelectionEnd();
        String text = target.getText().toString();

        // Find current line
        int lineStart = text.lastIndexOf('\n', start - 1);
        lineStart = (lineStart < 0) ? 0 : lineStart + 1;
        int lineEnd = text.indexOf('\n', start);
        if (lineEnd < 0) lineEnd = text.length();

        String currentLine = text.substring(lineStart, lineEnd);
        String bulletPrefix = "\u25CF ";

        if (currentLine.startsWith(bulletPrefix)) {
            // Remove bullet
            String newLine = currentLine.substring(bulletPrefix.length());
            String newText = text.substring(0, lineStart) + newLine + text.substring(lineEnd);
            target.setText(newText);
            int newCursor = lineStart + Math.max(0, start - lineStart - bulletPrefix.length());
            if (newCursor > newText.length()) newCursor = newText.length();
            target.setSelection(newCursor);
        } else {
            // Add bullet
            String newLine = bulletPrefix + currentLine;
            String newText = text.substring(0, lineStart) + newLine + text.substring(lineEnd);
            target.setText(newText);
            int newCursor = start + bulletPrefix.length();
            if (newCursor > newText.length()) newCursor = newText.length();
            target.setSelection(newCursor);
        }
    }

    /**
     * Toggle numbered list. Inserts "1. " prefix or removes it.
     */
    private void toggleNumberedList() {
        EditText target = activeEditText;
        if (target == null) target = etContent;

        int start = target.getSelectionStart();
        String text = target.getText().toString();

        int lineStart = text.lastIndexOf('\n', start - 1);
        lineStart = (lineStart < 0) ? 0 : lineStart + 1;
        int lineEnd = text.indexOf('\n', start);
        if (lineEnd < 0) lineEnd = text.length();

        String currentLine = text.substring(lineStart, lineEnd);

        // Check if current line starts with a number like "1. "
        if (currentLine.matches("^\\d+\\. .*")) {
            // Remove the number prefix
            int dotIdx = currentLine.indexOf(". ");
            String newLine = currentLine.substring(dotIdx + 2);
            String newText = text.substring(0, lineStart) + newLine + text.substring(lineEnd);
            target.setText(newText);
            target.setSelection(Math.min(lineStart + newLine.length(), newText.length()));
        } else {
            // Find previous line's number to auto-increment
            int prevNum = 0;
            if (lineStart > 0) {
                int prevLineEnd = lineStart - 1;
                int prevLineStart = text.lastIndexOf('\n', prevLineEnd - 1);
                prevLineStart = (prevLineStart < 0) ? 0 : prevLineStart + 1;
                String prevLine = text.substring(prevLineStart, prevLineEnd);
                if (prevLine.matches("^\\d+\\. .*")) {
                    try {
                        prevNum = Integer.parseInt(prevLine.substring(0, prevLine.indexOf(".")));
                    } catch (Exception e) { }
                }
            }
            int num = prevNum + 1;
            String prefix = num + ". ";
            String newLine = prefix + currentLine;
            String newText = text.substring(0, lineStart) + newLine + text.substring(lineEnd);
            target.setText(newText);
            target.setSelection(Math.min(start + prefix.length(), newText.length()));
        }
    }

    private void performUndo() {
        // Checklist mode has its own undo system
        if (isChecklistMode) {
            if (checklistManager.canUndo()) checklistManager.undo();
            updateUndoRedoButtons();
            return;
        }

        // Routine mode undo
        if (isRoutineMode && activeEditText == etRoutineContent) {
            String previousState = routineUndoManager.undo();
            if (previousState != null) {
                routineUndoManager.setListener(null); // Temporarily disable listener
                etRoutineContent.setText(previousState);
                etRoutineContent.setSelection(previousState.length());
                routineUndoManager.setListener(routineUndoListener);
            }
            updateUndoRedoButtons();
            return;
        }

        // Text editor undo (word-based)
        // First, push current state if it differs from top of stack
        CharSequence currentText = etContent.getText();
        textUndoManager.pushSnapshot(currentText, etContent.getSelectionStart());

        UndoRedoManager.EditorSnapshot snapshot = textUndoManager.undo();
        if (snapshot != null) {
            UndoRedoManager.applySnapshotToEditText(etContent, snapshot);
        }
        updateUndoRedoButtons();
    }

    private void performRedo() {
        // Checklist mode has its own redo system
        if (isChecklistMode) {
            if (checklistManager.canRedo()) checklistManager.redo();
            updateUndoRedoButtons();
            return;
        }

        // Routine mode redo
        if (isRoutineMode && activeEditText == etRoutineContent) {
            String nextState = routineUndoManager.redo();
            if (nextState != null) {
                routineUndoManager.setListener(null);
                etRoutineContent.setText(nextState);
                etRoutineContent.setSelection(nextState.length());
                routineUndoManager.setListener(routineUndoListener);
            }
            updateUndoRedoButtons();
            return;
        }

        // Text editor redo (word-based)
        UndoRedoManager.EditorSnapshot snapshot = textUndoManager.redo();
        if (snapshot != null) {
            UndoRedoManager.applySnapshotToEditText(etContent, snapshot);
        }
        updateUndoRedoButtons();
    }

    /**
     * Update undo/redo button alpha based on current mode's stack state.
     */
    private void updateUndoRedoButtons() {
        if (isChecklistMode) {
            btnUndo.setAlpha(checklistManager.canUndo() ? 1.0f : 0.3f);
            btnRedo.setAlpha(checklistManager.canRedo() ? 1.0f : 0.3f);
        } else if (isRoutineMode && activeEditText == etRoutineContent) {
            btnUndo.setAlpha(routineUndoManager.canUndo() ? 1.0f : 0.3f);
            btnRedo.setAlpha(routineUndoManager.canRedo() ? 1.0f : 0.3f);
        } else {
            btnUndo.setAlpha(textUndoManager.canUndo() ? 1.0f : 0.3f);
            btnRedo.setAlpha(textUndoManager.canRedo() ? 1.0f : 0.3f);
        }
    }

    /**
     * Push a snapshot after a formatting action (bold, italic, etc.).
     * This captures the full spannable state including the formatting change.
     */
    private void pushFormattingSnapshot() {
        if (activeEditText == etContent) {
            textUndoManager.pushSnapshot(etContent.getText(), etContent.getSelectionStart());
        } else if (activeEditText == etRoutineContent && isRoutineMode) {
            routineUndoManager.pushState(etRoutineContent.getText().toString());
        }
    }

    // Listener instance for routine undo manager (avoid recreating)
    private GenericUndoRedoManager.StateChangeListener routineUndoListener =
            new GenericUndoRedoManager.StateChangeListener() {
                public void onStateChanged(boolean canUndo, boolean canRedo) {
                    updateUndoRedoButtons();
                }
            };

    private void updateFavoriteIcon() {
        if (currentNote.isFavorite()) {
            btnFavorite.setImageResource(R.drawable.ic_star_filled);
        } else {
            btnFavorite.setImageResource(R.drawable.ic_star_outline);
        }
    }

    private void shareNote() {
        final String noteText = buildShareText();

        final boolean hasMedia = !imageAttachments.isEmpty() || !fileAttachments.isEmpty()
                || !audioAttachments.isEmpty();

        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.share_options);

        String[] options;
        if (hasMedia) {
            options = new String[]{
                    getString(R.string.share_text_only),
                    getString(R.string.share_text_media)
            };
        } else {
            options = new String[]{
                    getString(R.string.share_text_only)
            };
        }

        builder.setItems(options, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                if (which == 0) {
                    shareTextOnly(noteText);
                } else if (which == 1) {
                    shareTextWithMedia(noteText);
                }
            }
        });
        builder.setNegativeButton(R.string.cancel, null);
        builder.show();
    }

    private String buildShareText() {
        String text = "";
        String title = etTitle.getText().toString().trim();
        if (title.length() > 0) {
            text = title + "\n\n";
        }
        if (isChecklistMode) {
            text = text + checklistManager.toPlainText();
        } else {
            text = text + etContent.getText().toString();
        }
        return text;
    }

    private void shareTextOnly(String text) {
        Intent shareIntent = new Intent(Intent.ACTION_SEND);
        shareIntent.setType("text/plain");
        shareIntent.putExtra(Intent.EXTRA_TEXT, text);
        startActivity(Intent.createChooser(shareIntent, getString(R.string.share)));
    }

    private void shareTextWithMedia(String text) {
        try {
            java.util.ArrayList uris = new java.util.ArrayList();
            long noteId = currentNote.getId();

            for (int i = 0; i < imageAttachments.size(); i++) {
                FileAttachment img = (FileAttachment) imageAttachments.get(i);
                File f = AttachmentManager.getImageFile(this, noteId, img.getLocalName());
                if (f.exists()) {
                    Uri uri = com.mknotes.app.util.MKFileProvider.getUriForFile(f);
                    uris.add(uri);
                }
            }

            for (int i = 0; i < fileAttachments.size(); i++) {
                FileAttachment file = (FileAttachment) fileAttachments.get(i);
                File f = AttachmentManager.getFileFile(this, noteId, file.getLocalName());
                if (f.exists()) {
                    Uri uri = com.mknotes.app.util.MKFileProvider.getUriForFile(f);
                    uris.add(uri);
                }
            }

            for (int i = 0; i < audioAttachments.size(); i++) {
                AudioAttachment audio = (AudioAttachment) audioAttachments.get(i);
                File f = AttachmentManager.getAudioFile(this, noteId, audio.getLocalName());
                if (f.exists()) {
                    Uri uri = com.mknotes.app.util.MKFileProvider.getUriForFile(f);
                    uris.add(uri);
                }
            }

            if (uris.isEmpty()) {
                shareTextOnly(text);
                return;
            }

            Intent shareIntent = new Intent(Intent.ACTION_SEND_MULTIPLE);
            shareIntent.setType("*/*");
            shareIntent.putExtra(Intent.EXTRA_TEXT, text);
            shareIntent.putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris);
            shareIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(shareIntent, getString(R.string.share)));

        } catch (Exception e) {
            Toast.makeText(this, "Could not attach files, sharing text only",
                    Toast.LENGTH_SHORT).show();
            shareTextOnly(text);
        }
    }

    // ======================== ROUTINE MODE ========================

    /**
     * Activate routine mode: show header section, set up watchers, show time picker.
     * Auto-sets wake time from picker selection.
     */
    private void activateRoutineMode() {
        isRoutineMode = true;
        currentNote.setRoutineMode(true);

        if (routineHeaderSection != null) {
            routineHeaderSection.setVisibility(View.VISIBLE);
        }

        if (routineContentWatcher == null) {
            if (etRoutineWake != null) {
                etRoutineWake.addTextChangedListener(new RoutineTimeWatcher(etRoutineWake, false));
            }
            if (etRoutineSleep != null) {
                etRoutineSleep.addTextChangedListener(new RoutineTimeWatcher(etRoutineSleep, true));
            }
            if (etRoutineContent != null) {
                routineContentWatcher = new RoutineContentWatcher(etRoutineContent);
                etRoutineContent.addTextChangedListener(routineContentWatcher);

                // Add word-based undo watcher for routine content
                etRoutineContent.addTextChangedListener(new TextWatcher() {
                    private int rChangeCount = 0;
                    private int rChangeBefore = 0;
                    private int rChangeStart = 0;
                    public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                        rChangeStart = start;
                        rChangeBefore = count;
                    }
                    public void onTextChanged(CharSequence s, int start, int before, int count) {
                        rChangeCount = count;
                        rChangeBefore = before;
                        rChangeStart = start;
                    }
                    public void afterTextChanged(Editable s) {
                        if (!routineUndoManager.isPerformingUndoRedo()) {
                            boolean shouldSnapshot = false;
                            if (UndoRedoManager.isPaste(rChangeCount)) {
                                shouldSnapshot = true;
                            }
                            if (!shouldSnapshot && rChangeCount == 1 && rChangeBefore == 0) {
                                int pos = rChangeStart;
                                if (pos >= 0 && pos < s.length()) {
                                    char c = s.charAt(pos);
                                    if (UndoRedoManager.isSnapshotTrigger(c)) {
                                        shouldSnapshot = true;
                                    }
                                }
                            }
                            if (!shouldSnapshot && rChangeBefore > 0 && rChangeCount == 0) {
                                shouldSnapshot = true;
                            }
                            if (shouldSnapshot) {
                                routineUndoManager.pushState(s.toString());
                            }
                        }
                        updateUndoRedoButtons();
                    }
                });

                etRoutineContent.setOnKeyListener(new View.OnKeyListener() {
                    public boolean onKey(View v, int keyCode, KeyEvent event) {
                        if (keyCode == KeyEvent.KEYCODE_ENTER && event.getAction() == KeyEvent.ACTION_DOWN) {
                            handleRoutineEnterKey();
                            return true;
                        }
                        return false;
                    }
                });

                // Track focus for formatting tools and update undo/redo buttons
                etRoutineContent.setOnFocusChangeListener(new View.OnFocusChangeListener() {
                    public void onFocusChange(View v, boolean hasFocus) {
                        if (hasFocus) {
                            activeEditText = etRoutineContent;
                            styleManager = new RichTextStyleManager(etRoutineContent);
                            updateUndoRedoButtons();
                        }
                    }
                });
            }
        }

        // Initialize routine undo with current state
        routineUndoManager.pushInitialState(
                etRoutineContent != null ? etRoutineContent.getText().toString() : "");

        // Show time picker for first entry only if content is empty
        if (etRoutineContent != null) {
            String currentText = etRoutineContent.getText().toString().trim();
            if (currentText.length() == 0) {
                showRoutineStartTimePicker();
            }
        } else {
            showRoutineStartTimePicker();
        }
        hasChanges = true;
    }

    private void deactivateRoutineMode() {
        if (routineManager != null) {
            if (etRoutineWake != null) {
                routineManager.setWakeTime(etRoutineWake.getText().toString().trim());
            }
            if (etRoutineSleep != null) {
                routineManager.setSleepTime(etRoutineSleep.getText().toString().trim());
            }
            if (etRoutineContent != null) {
                routineManager.setEntriesText(etRoutineContent.getText().toString());
            }
            currentNote.setRoutineData(routineManager.serialize());
        }

        isRoutineMode = false;
        currentNote.setRoutineMode(false);

        if (routineHeaderSection != null) {
            routineHeaderSection.setVisibility(View.GONE);
        }

        if (routineContentWatcher != null && etRoutineContent != null) {
            etRoutineContent.removeTextChangedListener(routineContentWatcher);
        }
        routineContentWatcher = null;

        // Reset active edit text back to content
        activeEditText = etContent;
        styleManager = new RichTextStyleManager(etContent);

        hasChanges = true;
    }

    /**
     * Show TimePickerDialog for routine start time.
     * Also auto-sets Wake field to the selected time.
     */
    private void showRoutineStartTimePicker() {
        int defaultHour = 7;
        int defaultMin = 0;

        TimePickerDialog dialog = new TimePickerDialog(
                this,
                new TimePickerDialog.OnTimeSetListener() {
                    public void onTimeSet(TimePicker view, int hourOfDay, int minute) {
                        String formattedTime = RoutineManager.formatTime12(hourOfDay, minute);

                        if (routineContentWatcher != null) {
                            routineContentWatcher.setCurrentlyPm(hourOfDay >= 12);
                        }

                        // Auto-set Wake field if empty
                        if (etRoutineWake != null) {
                            String wakeText = etRoutineWake.getText().toString().trim();
                            if (wakeText.length() == 0) {
                                etRoutineWake.setText(formattedTime);
                            }
                        }

                        if (etRoutineContent != null) {
                            String current = etRoutineContent.getText().toString();
                            String newEntry = formattedTime + " - ";
                            if (current.length() > 0 && !current.endsWith("\n")) {
                                newEntry = "\n" + newEntry;
                            }
                            etRoutineContent.append(newEntry);
                            etRoutineContent.setSelection(etRoutineContent.getText().length());
                            etRoutineContent.requestFocus();
                        }
                    }
                },
                defaultHour,
                defaultMin,
                false
        );
        dialog.setTitle(getString(R.string.routine_select_start));
        dialog.show();
    }

    private void handleRoutineEnterKey() {
        if (etRoutineContent == null) return;

        String text = etRoutineContent.getText().toString();
        int cursorPos = etRoutineContent.getSelectionStart();
        if (cursorPos < 0) cursorPos = text.length();

        int lineStart = text.lastIndexOf('\n', cursorPos - 1);
        String currentLine;
        if (lineStart < 0) {
            currentLine = text.substring(0, cursorPos);
        } else {
            currentLine = text.substring(lineStart + 1, Math.min(cursorPos, text.length()));
        }

        String endTime = RoutineManager.extractLastEndTime(currentLine);

        if (endTime != null) {
            boolean endIsPm = RoutineManager.isPmTime(endTime);
            if (routineContentWatcher != null) {
                boolean wasPm = routineContentWatcher.isCurrentlyPm();

                if (wasPm && !endIsPm) {
                    showAmPmConfirmDialog(endTime);
                    return;
                }

                routineContentWatcher.setCurrentlyPm(endIsPm);
            }

            String newLine = "\n" + endTime + " - ";
            Editable editable = etRoutineContent.getText();
            editable.insert(cursorPos, newLine);
            etRoutineContent.setSelection(cursorPos + newLine.length());
        } else {
            Editable editable = etRoutineContent.getText();
            editable.insert(cursorPos, "\n");
            etRoutineContent.setSelection(cursorPos + 1);
        }
    }

    private void showAmPmConfirmDialog(final String endTime) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.routine_time_confirm_title);
        builder.setMessage(R.string.routine_time_confirm_msg);
        builder.setPositiveButton("AM", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                if (routineContentWatcher != null) {
                    routineContentWatcher.setCurrentlyPm(false);
                }
                insertRoutineNewLine(endTime);
            }
        });
        builder.setNegativeButton("PM", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                String pmTime = endTime.replace("AM", "PM");
                insertRoutineNewLine(pmTime);
            }
        });
        builder.show();
    }

    private void insertRoutineNewLine(String startTime) {
        if (etRoutineContent == null) return;
        int cursorPos = etRoutineContent.getSelectionStart();
        String newLine = "\n" + startTime + " - ";
        Editable editable = etRoutineContent.getText();
        editable.insert(cursorPos, newLine);
        etRoutineContent.setSelection(cursorPos + newLine.length());
    }

    private void saveRoutineData() {
        if (!isRoutineMode) return;
        if (routineManager == null) return;

        if (etRoutineWake != null) {
            routineManager.setWakeTime(etRoutineWake.getText().toString().trim());
        }
        if (etRoutineSleep != null) {
            routineManager.setSleepTime(etRoutineSleep.getText().toString().trim());
        }
        if (etRoutineContent != null) {
            routineManager.setEntriesText(etRoutineContent.getText().toString());
        }

        currentNote.setRoutineData(routineManager.serialize());
    }

    private void loadRoutineData() {
        if (currentNote == null || routineManager == null) return;

        String data = currentNote.getRoutineData();
        if (data == null || data.length() == 0) return;

        routineManager.deserialize(data);

        if (etRoutineWake != null) {
            etRoutineWake.setText(routineManager.getWakeTime());
        }
        if (etRoutineSleep != null) {
            etRoutineSleep.setText(routineManager.getSleepTime());
        }
        if (etRoutineContent != null) {
            etRoutineContent.setText(routineManager.getEntriesText());
        }
    }

    private void restoreRoutineMode() {
        isRoutineMode = true;

        if (routineHeaderSection != null) {
            routineHeaderSection.setVisibility(View.VISIBLE);
        }

        if (etRoutineWake != null) {
            etRoutineWake.addTextChangedListener(new RoutineTimeWatcher(etRoutineWake, false));
        }
        if (etRoutineSleep != null) {
            etRoutineSleep.addTextChangedListener(new RoutineTimeWatcher(etRoutineSleep, true));
        }
        if (etRoutineContent != null) {
            routineContentWatcher = new RoutineContentWatcher(etRoutineContent);
            etRoutineContent.addTextChangedListener(routineContentWatcher);

            // Add word-based undo watcher for routine content (restore path)
            etRoutineContent.addTextChangedListener(new TextWatcher() {
                private int rChangeCount = 0;
                private int rChangeBefore = 0;
                private int rChangeStart = 0;
                public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                    rChangeStart = start;
                    rChangeBefore = count;
                }
                public void onTextChanged(CharSequence s, int start, int before, int count) {
                    rChangeCount = count;
                    rChangeBefore = before;
                    rChangeStart = start;
                }
                public void afterTextChanged(Editable s) {
                    if (!routineUndoManager.isPerformingUndoRedo()) {
                        boolean shouldSnapshot = false;
                        if (UndoRedoManager.isPaste(rChangeCount)) {
                            shouldSnapshot = true;
                        }
                        if (!shouldSnapshot && rChangeCount == 1 && rChangeBefore == 0) {
                            int pos = rChangeStart;
                            if (pos >= 0 && pos < s.length()) {
                                char c = s.charAt(pos);
                                if (UndoRedoManager.isSnapshotTrigger(c)) {
                                    shouldSnapshot = true;
                                }
                            }
                        }
                        if (!shouldSnapshot && rChangeBefore > 0 && rChangeCount == 0) {
                            shouldSnapshot = true;
                        }
                        if (shouldSnapshot) {
                            routineUndoManager.pushState(s.toString());
                        }
                    }
                    updateUndoRedoButtons();
                }
            });

            etRoutineContent.setOnKeyListener(new View.OnKeyListener() {
                public boolean onKey(View v, int keyCode, KeyEvent event) {
                    if (keyCode == KeyEvent.KEYCODE_ENTER && event.getAction() == KeyEvent.ACTION_DOWN) {
                        handleRoutineEnterKey();
                        return true;
                    }
                    return false;
                }
            });

            etRoutineContent.setOnFocusChangeListener(new View.OnFocusChangeListener() {
                public void onFocusChange(View v, boolean hasFocus) {
                    if (hasFocus) {
                        activeEditText = etRoutineContent;
                        styleManager = new RichTextStyleManager(etRoutineContent);
                        updateUndoRedoButtons();
                    }
                }
            });

            routineContentWatcher.syncAmPmState();
        }

        loadRoutineData();

        // Initialize routine undo with loaded data
        routineUndoManager.pushInitialState(
                etRoutineContent != null ? etRoutineContent.getText().toString() : "");
    }

    /**
     * BottomBar More menu - THE MASTER OPTIONS HOLDER.
     */
    private void showEditorMenu(View anchor) {
        PopupMenu popup = new PopupMenu(this, anchor);
        popup.getMenu().add(0, 7, 0, getString(R.string.share));
        popup.getMenu().add(0, 1, 1, getString(R.string.change_color));
        popup.getMenu().add(0, 2, 2, getString(R.string.set_category));
        popup.getMenu().add(0, 3, 3, currentNote.isLocked() ?
                getString(R.string.unlock_note) : getString(R.string.lock_note));
        if (isChecklistMode) {
            popup.getMenu().add(0, 5, 4, getString(R.string.uncheck_all));
            popup.getMenu().add(0, 6, 5, getString(R.string.delete_checked));
        }
        if (!isNewNote) {
            popup.getMenu().add(0, 4, 6, getString(R.string.delete));
        }
        popup.getMenu().add(0, 8, 7, "Export as TXT");
        popup.getMenu().add(0, 9, 8, "Export as PDF");

        popup.setOnMenuItemClickListener(new PopupMenu.OnMenuItemClickListener() {
            public boolean onMenuItemClick(android.view.MenuItem item) {
                switch (item.getItemId()) {
                    case 1: showColorPicker(); return true;
                    case 2: showCategoryPicker(); return true;
                    case 3: toggleLock(); return true;
                    case 4: deleteCurrentNote(); return true;
                    case 5: checklistManager.uncheckAll(); return true;
                    case 6: checklistManager.deleteCheckedItems(); return true;
                    case 7: shareNote(); return true;
                    case 8: exportAsTxt(); return true;
                    case 9: exportAsPdf(); return true;
                }
                return false;
            }
        });
        popup.show();
    }

    /**
     * Category picker with ADDITIVE system:
     * - Routine and Meditation can coexist with each other and with normal text.
     * - Toggling Routine ON/OFF does NOT affect Meditation and vice versa.
     * - User categories set the note's category_id independently.
     */
    private void showCategoryPicker() {
        final List categories = repository.getAllCategories();

        // Build items: "Toggle Routine", "Meditation Master List", separator, then user categories
        int totalItems = 3 + categories.size();
        String[] names = new String[totalItems];
        names[0] = isRoutineMode ? "Routine (ON - tap to disable)" : "Routine (tap to enable)";
        names[1] = "Meditation";
        names[2] = getString(R.string.no_category);
        for (int i = 0; i < categories.size(); i++) {
            names[i + 3] = ((Category) categories.get(i)).getName();
        }

        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.set_category);
        builder.setItems(names, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                if (which == 0) {
                    // Toggle Routine - additive, does not touch Meditation
                    if (isRoutineMode) {
                        deactivateRoutineMode();
                    } else {
                        activateRoutineMode();
                    }
                } else if (which == 1) {
                    // Open Meditation master list popup - additive, does not touch Routine
                    showMeditationMasterPopup();
                } else if (which == 2) {
                    // No category - only clears user category, does NOT deactivate Routine/Meditation
                    currentNote.setCategoryId(-1);
                } else {
                    // User category - does NOT deactivate Routine/Meditation
                    currentNote.setCategoryId(((Category) categories.get(which - 3)).getId());
                }
                hasChanges = true;
            }
        });
        builder.show();
    }

    private void toggleLock() {
        if (currentNote.isLocked()) {
            currentNote.setLocked(false);
            currentNote.setPassword(null);
            hasChanges = true;
            Toast.makeText(this, R.string.note_unlocked, Toast.LENGTH_SHORT).show();
        } else {
            final EditText input = new EditText(this);
            input.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
            input.setHint(R.string.set_password);

            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle(R.string.lock_note);
            builder.setView(input);
            builder.setPositiveButton(R.string.lock, new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    String pwd = input.getText().toString().trim();
                    if (pwd.length() > 0) {
                        currentNote.setLocked(true);
                        currentNote.setPassword(com.mknotes.app.util.PasswordHashUtil.hashPassword(pwd));
                        hasChanges = true;
                        Toast.makeText(NoteEditorActivity.this, R.string.note_locked, Toast.LENGTH_SHORT).show();
                    }
                }
            });
            builder.setNegativeButton(R.string.cancel, null);
            builder.show();
        }
    }

    private void deleteCurrentNote() {
        if (prefs.isConfirmDelete()) {
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle(R.string.delete_note_title);
            builder.setMessage(R.string.delete_note_message);
            builder.setPositiveButton(R.string.delete, new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    AttachmentManager.deleteAllAttachments(NoteEditorActivity.this, currentNote.getId());
                    repository.moveToTrash(currentNote);
                    Toast.makeText(NoteEditorActivity.this, R.string.note_moved_to_trash, Toast.LENGTH_SHORT).show();
                    setResult(RESULT_OK);
                    finish();
                }
            });
            builder.setNegativeButton(R.string.cancel, null);
            builder.show();
        } else {
            AttachmentManager.deleteAllAttachments(this, currentNote.getId());
            repository.moveToTrash(currentNote);
            Toast.makeText(this, R.string.note_moved_to_trash, Toast.LENGTH_SHORT).show();
            setResult(RESULT_OK);
            finish();
        }
    }

    private void saveNote() {
        String title = etTitle.getText().toString().trim();
        String content;

        if (isRoutineMode) {
            saveRoutineData();
        }

        if (isChecklistMode) {
            String clJson = checklistManager.saveToJson();
            currentNote.setChecklistData(clJson);
            currentNote.setChecklistMode(true);
            currentNote.setHasChecklist(true);
            content = checklistManager.toPlainText();
        } else {
            // ISSUE 5: Save rich text formatting as HTML
            android.text.Spanned spanned = etContent.getText();
            if (spanned != null && spanned.length() > 0) {
                // Check if there are any spans (formatting)
                Object[] spans = spanned.getSpans(0, spanned.length(), Object.class);
                if (spans != null && spans.length > 0) {
                    content = android.text.Html.toHtml(spanned);
                } else {
                    content = spanned.toString().trim();
                }
            } else {
                content = "";
            }
        }

        if (title.length() == 0 && content.length() == 0 && !isChecklistMode
                && !isRoutineMode && !isMeditationMode
                && imageAttachments.isEmpty() && fileAttachments.isEmpty()
                && audioAttachments.isEmpty() && linkedNoteIds.isEmpty()) {
            return;
        }

        currentNote.setTitle(title);
        currentNote.setContent(content);
        currentNote.setModifiedAt(System.currentTimeMillis());

        saveAttachmentData();

        if (isNewNote) {
            long id = repository.insertNote(currentNote);
            currentNote.setId(id);
            isNewNote = false;
            // Flush any pending mood that was deferred while noteId was not yet assigned
            if (moodStripManager != null) {
                moodStripManager.setNoteId(id);
                moodStripManager.setNoteContext(id, currentNote.getCreatedAt());
                moodStripManager.savePendingMood();
            }
        } else {
            repository.updateNote(currentNote);
        }

        // Trigger cloud sync upload after save
        triggerCloudUpload();

        hasChanges = false;
    }

    /**
     * Upload the current note to Firestore if cloud sync is enabled.
     * Uses raw encrypted data from local DB -- plaintext NEVER goes to cloud.
     */
    private void triggerCloudUpload() {
        try {
            if (currentNote == null || currentNote.getId() <= 0) return;
            if (!PrefsManager.getInstance(this).isCloudSyncEnabled()) return;
            if (!FirebaseAuthManager.getInstance(this).isLoggedIn()) return;
            if (!SessionManager.getInstance(this).isSessionValid()) return;

            CloudSyncManager.getInstance(this).uploadNote(currentNote.getId());
        } catch (Exception e) {
            // Cloud sync failure must not crash the app
        }
    }

    private void saveAndFinish() {
        if (hasChanges || isNewNote || isChecklistMode) {
            saveNote();
        }
        setResult(RESULT_OK);
        finish();
    }

    public void onBackPressed() {
        saveAndFinish();
    }

    protected void onPause() {
        super.onPause();
        if (prefs.isAutoSave() && (hasChanges || isChecklistMode)) {
            saveNote();
        }
    }

    protected void onResume() {
        super.onResume();

        // Session-based lock: if session expired and meditation is not playing,
        // redirect to password screen. This prevents bypassing lock when
        // returning to a note that merely has meditation history data.
        SessionManager session = SessionManager.getInstance(this);
        if (session.isPasswordSet() && !session.isSessionValid()) {
            Intent lockIntent = new Intent(this, MasterPasswordActivity.class);
            lockIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(lockIntent);
            finish();
            return;
        }
        // Refresh session timestamp on every resume while session is valid
        if (session.isPasswordSet()) {
            session.updateSessionTimestamp();
        }

        // Refresh meditation cards to show updated count/state from background playback
        if (isMeditationMode && meditationCardBuilder != null && currentNote != null) {
            refreshMeditationCards();
        }
    }

    protected void onDestroy() {
        super.onDestroy();
        stopAudioPlayback();
        // Unregister meditation broadcast receivers to prevent leaks
        if (meditationCardBuilder != null) {
            meditationCardBuilder.unregisterReceivers();
        }
        // Don't cleanup meditation player here - it may be playing via service
    }

    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == REQUEST_IMAGE_PICK && resultCode == RESULT_OK) {
            handleImageResult(data);
        } else if (requestCode == REQUEST_FILE_PICK && resultCode == RESULT_OK) {
            handleFileResult(data);
        } else if (requestCode == REQUEST_MANTRA_MP3_PICK && resultCode == RESULT_OK) {
            handleMantraMp3Result(data);
        } else if (requestCode == REQUEST_VIEW_IMAGE && resultCode == ViewImageActivity.RESULT_DELETED) {
            if (pendingDeleteImageIndex >= 0 && pendingDeleteImageIndex < imageAttachments.size()) {
                FileAttachment img = (FileAttachment) imageAttachments.get(pendingDeleteImageIndex);
                AttachmentManager.deleteAttachmentFile(this, currentNote.getId(), img.getLocalName(), "images");
                imageAttachments.remove(pendingDeleteImageIndex);
                if (imageAttachments.isEmpty()) {
                    currentNote.setHasImage(false);
                }
                saveAttachmentData();
                refreshImagePreviews();
                hasChanges = true;
            }
            pendingDeleteImageIndex = -1;
        }
    }

    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_RECORD_AUDIO) {
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                showAudioRecordDialog();
            } else {
                Toast.makeText(this, R.string.permission_audio_required, Toast.LENGTH_SHORT).show();
            }
        }
    }

    // ======================== MEDITATION MODE ========================

    /**
     * Show Meditation Master Popup with HYBRID mantra library.
     * Section 1: 15 permanent built-in mantras (non-deletable)
     * Section 2: User-added mantras (long-press deletable)
     * Section 3: "Add Mantra" button (name input + mp3 select + save)
     * Tap any mantra to add to this note's meditation session for today.
     */
    private void showMeditationMasterPopup() {
        ensureNoteSaved();

        final AlertDialog.Builder builder = new AlertDialog.Builder(this);

        ScrollView scrollView = new ScrollView(this);
        scrollView.setPadding(dpToPx(4), dpToPx(4), dpToPx(4), dpToPx(4));

        final LinearLayout dialogLayout = new LinearLayout(this);
        dialogLayout.setOrientation(LinearLayout.VERTICAL);
        dialogLayout.setPadding(dpToPx(16), dpToPx(12), dpToPx(16), dpToPx(8));

        // Header
        TextView tvHeader = new TextView(this);
        tvHeader.setText("Mantra Library");
        tvHeader.setTextColor(Color.parseColor("#81C784"));
        tvHeader.setTextSize(16);
        tvHeader.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        tvHeader.setPadding(0, 0, 0, dpToPx(4));
        dialogLayout.addView(tvHeader);

        TextView tvHint = new TextView(this);
        tvHint.setText("Tap to add | Long-press user mantra to delete");
        tvHint.setTextColor(Color.parseColor("#888888"));
        tvHint.setTextSize(11);
        tvHint.setPadding(0, 0, 0, dpToPx(10));
        dialogLayout.addView(tvHint);

        // Container for mantra list items
        final LinearLayout mantraListContainer = new LinearLayout(this);
        mantraListContainer.setOrientation(LinearLayout.VERTICAL);
        dialogLayout.addView(mantraListContainer);

        scrollView.addView(dialogLayout);
        builder.setView(scrollView);
        builder.setNegativeButton("Close", null);

        final AlertDialog dialog = builder.create();

        // Store references for refresh after mp3 pick
        activeMantraPopupDialog = dialog;
        activeMantraPopupListContainer = mantraListContainer;

        // Populate hybrid mantra list
        refreshHybridMantraListInPopup(mantraListContainer, dialog);

        dialog.setOnDismissListener(new DialogInterface.OnDismissListener() {
            public void onDismiss(DialogInterface d) {
                activeMantraPopupDialog = null;
                activeMantraPopupListContainer = null;
            }
        });

        dialog.show();
    }

    /**
     * Populate the mantra list inside the popup with HYBRID list:
     * 1) All 15 built-in mantras (permanent, cannot be long-press deleted)
     * 2) All user-added mantras (long-press to delete from master list)
     * 3) "Add Mantra" button at the bottom
     * Tap adds to today's session for this note.
     */
    private void refreshHybridMantraListInPopup(final LinearLayout listContainer, final AlertDialog dialog) {
        listContainer.removeAllViews();

        final String today = MeditationPlayerManager.getTodayDateString();

        // Get both lists
        List builtInMantras = repository.getAllBuiltInMantras();
        List userMantras = repository.getAllUserAddedMantras();

        // Pre-fetch active sessions for this note today (once for efficiency)
        final List sessionsToday = repository.getMantrasWithSessionForNoteAndDate(
                currentNote.getId(), today);

        // == Section: Built-in Mantras ==
        if (!builtInMantras.isEmpty()) {
            TextView tvBuiltInLabel = new TextView(this);
            tvBuiltInLabel.setText("Built-in Mantras");
            tvBuiltInLabel.setTextColor(Color.parseColor("#66BB6A"));
            tvBuiltInLabel.setTextSize(12);
            tvBuiltInLabel.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
            tvBuiltInLabel.setPadding(0, dpToPx(2), 0, dpToPx(4));
            listContainer.addView(tvBuiltInLabel);

            for (int i = 0; i < builtInMantras.size(); i++) {
                final Mantra mantra = (Mantra) builtInMantras.get(i);
                listContainer.addView(buildMantraPopupRow(mantra, sessionsToday,
                        today, listContainer, dialog, false));
            }
        }

        // == Section: User-Added Mantras ==
        if (!userMantras.isEmpty()) {
            TextView tvUserLabel = new TextView(this);
            tvUserLabel.setText("My Mantras");
            tvUserLabel.setTextColor(Color.parseColor("#64B5F6"));
            tvUserLabel.setTextSize(12);
            tvUserLabel.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
            tvUserLabel.setPadding(0, dpToPx(10), 0, dpToPx(4));
            listContainer.addView(tvUserLabel);

            for (int i = 0; i < userMantras.size(); i++) {
                final Mantra mantra = (Mantra) userMantras.get(i);
                listContainer.addView(buildMantraPopupRow(mantra, sessionsToday,
                        today, listContainer, dialog, true));
            }
        }

        // == "Add Mantra" button at the bottom ==
        LinearLayout addRow = new LinearLayout(this);
        addRow.setOrientation(LinearLayout.HORIZONTAL);
        addRow.setGravity(Gravity.CENTER_VERTICAL);
        addRow.setPadding(dpToPx(10), dpToPx(12), dpToPx(10), dpToPx(12));

        GradientDrawable addBg = new GradientDrawable();
        addBg.setCornerRadius(dpToPx(8));
        addBg.setColor(Color.parseColor("#1A331A"));
        addBg.setStroke(dpToPx(1), Color.parseColor("#4CAF50"));
        addRow.setBackground(addBg);

        LinearLayout.LayoutParams addParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        addParams.setMargins(0, dpToPx(10), 0, dpToPx(4));
        addRow.setLayoutParams(addParams);

        TextView tvAddIcon = new TextView(this);
        tvAddIcon.setText("+");
        tvAddIcon.setTextColor(Color.parseColor("#4CAF50"));
        tvAddIcon.setTextSize(18);
        tvAddIcon.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        tvAddIcon.setPadding(0, 0, dpToPx(8), 0);
        addRow.addView(tvAddIcon);

        TextView tvAddLabel = new TextView(this);
        tvAddLabel.setText("Add New Mantra");
        tvAddLabel.setTextColor(Color.parseColor("#A5D6A7"));
        tvAddLabel.setTextSize(14);
        tvAddLabel.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        addRow.addView(tvAddLabel);

        addRow.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showAddMantraDialog(listContainer, dialog);
            }
        });

        listContainer.addView(addRow);
    }

    /**
     * Build a single mantra row for the popup list.
     * @param allowLongPressDelete true for user-added mantras, false for built-in
     */
    private LinearLayout buildMantraPopupRow(final Mantra mantra, List sessionsToday,
                                              final String today, final LinearLayout listContainer,
                                              final AlertDialog dialog, final boolean allowLongPressDelete) {

        LinearLayout itemRow = new LinearLayout(this);
        itemRow.setOrientation(LinearLayout.HORIZONTAL);
        itemRow.setGravity(Gravity.CENTER_VERTICAL);
        itemRow.setPadding(dpToPx(10), dpToPx(10), dpToPx(10), dpToPx(10));

        GradientDrawable rowBg = new GradientDrawable();
        rowBg.setCornerRadius(dpToPx(8));
        rowBg.setColor(allowLongPressDelete ? Color.parseColor("#1E1E2E") : Color.parseColor("#1E2E1E"));
        itemRow.setBackground(rowBg);

        LinearLayout.LayoutParams itemParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        itemParams.setMargins(0, dpToPx(2), 0, dpToPx(2));
        itemRow.setLayoutParams(itemParams);

        // Left: mantra name
        TextView tvName = new TextView(this);
        tvName.setText(mantra.getName());
        tvName.setTextColor(Color.parseColor("#E0E0E0"));
        tvName.setTextSize(14);
        tvName.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        tvName.setSingleLine(true);
        LinearLayout.LayoutParams nameParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        tvName.setLayoutParams(nameParams);
        itemRow.addView(tvName);

        // Status indicator
        boolean isActiveForNote = false;
        for (int j = 0; j < sessionsToday.size(); j++) {
            Mantra sm = (Mantra) sessionsToday.get(j);
            if (sm.getId() == mantra.getId()) {
                isActiveForNote = true;
                break;
            }
        }

        TextView tvStatus = new TextView(this);
        if (isActiveForNote) {
            tvStatus.setText("Active");
            tvStatus.setTextColor(Color.parseColor("#66BB6A"));
        } else {
            tvStatus.setText("+ Add");
            tvStatus.setTextColor(Color.parseColor("#4CAF50"));
        }
        tvStatus.setTextSize(11);
        tvStatus.setPadding(dpToPx(8), 0, 0, 0);
        itemRow.addView(tvStatus);

        // Tap to add to today's session
        itemRow.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                // Link mantra to this note if not already
                if (mantra.getNoteId() != currentNote.getId()) {
                    mantra.setNoteId(currentNote.getId());
                    repository.updateMantra(mantra);
                }
                // Create/ensure session for today
                repository.getOrCreateDailySession(mantra.getId(), today);
                activateMeditationMode();
                Toast.makeText(NoteEditorActivity.this,
                        mantra.getName() + " added",
                        Toast.LENGTH_SHORT).show();
                refreshHybridMantraListInPopup(listContainer, dialog);
                hasChanges = true;
            }
        });

        // Long-press to delete ONLY user-added mantras from master list
        if (allowLongPressDelete) {
            itemRow.setOnLongClickListener(new View.OnLongClickListener() {
                public boolean onLongClick(View v) {
                    // Safety check: never delete built-in
                    if (mantra.isBuiltIn()) {
                        return true;
                    }
                    AlertDialog.Builder confirmBuilder = new AlertDialog.Builder(NoteEditorActivity.this);
                    confirmBuilder.setTitle("Delete Mantra");
                    confirmBuilder.setMessage("Remove \"" + mantra.getName() +
                            "\" from your library?\n\nExisting daily session history will not be affected.");
                    confirmBuilder.setPositiveButton("Delete", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface d, int which) {
                            // Stop if this mantra is playing
                            MeditationPlayerManager player = MeditationPlayerManager.getInstance(
                                    NoteEditorActivity.this);
                            if (player.isCurrentlyPlaying()
                                    && player.getCurrentMantraId() == mantra.getId()) {
                                player.stopPlayback();
                                try {
                                    Intent svcIntent = new Intent(NoteEditorActivity.this,
                                            com.mknotes.app.service.MeditationService.class);
                                    svcIntent.setAction(com.mknotes.app.service.MeditationService.ACTION_STOP);
                                    startService(svcIntent);
                                } catch (Exception ex) { }
                            }
                            // Hard-delete from master list (not soft-delete)
                            repository.hardDeleteUserMantra(mantra.getId());
                            Toast.makeText(NoteEditorActivity.this,
                                    mantra.getName() + " removed from library",
                                    Toast.LENGTH_SHORT).show();
                            refreshHybridMantraListInPopup(listContainer, dialog);
                        }
                    });
                    confirmBuilder.setNegativeButton("Cancel", null);
                    confirmBuilder.show();
                    return true;
                }
            });
        }

        return itemRow;
    }

    /**
     * Show dialog to add a new user mantra: name input + mp3 file selection.
     * After mp3 is selected, mantra is saved to master library.
     */
    private void showAddMantraDialog(final LinearLayout listContainer, final AlertDialog parentDialog) {
        final AlertDialog.Builder addBuilder = new AlertDialog.Builder(this);
        addBuilder.setTitle("Add New Mantra");

        LinearLayout addLayout = new LinearLayout(this);
        addLayout.setOrientation(LinearLayout.VERTICAL);
        addLayout.setPadding(dpToPx(20), dpToPx(16), dpToPx(20), dpToPx(8));

        // Mantra name input
        TextView tvNameLabel = new TextView(this);
        tvNameLabel.setText("Mantra Name:");
        tvNameLabel.setTextColor(Color.parseColor("#CCCCCC"));
        tvNameLabel.setTextSize(13);
        tvNameLabel.setPadding(0, 0, 0, dpToPx(4));
        addLayout.addView(tvNameLabel);

        final EditText etMantraName = new EditText(this);
        etMantraName.setHint("Enter mantra name");
        etMantraName.setTextColor(Color.parseColor("#FFFFFF"));
        etMantraName.setHintTextColor(Color.parseColor("#666666"));
        etMantraName.setTextSize(14);
        etMantraName.setSingleLine(true);
        etMantraName.setPadding(dpToPx(8), dpToPx(8), dpToPx(8), dpToPx(8));
        GradientDrawable inputBg = new GradientDrawable();
        inputBg.setCornerRadius(dpToPx(6));
        inputBg.setColor(Color.parseColor("#1A1A2A"));
        inputBg.setStroke(dpToPx(1), Color.parseColor("#444444"));
        etMantraName.setBackground(inputBg);
        addLayout.addView(etMantraName);

        // Info text
        TextView tvInfo = new TextView(this);
        tvInfo.setText("After entering the name, tap 'Select MP3' to choose an audio file.");
        tvInfo.setTextColor(Color.parseColor("#888888"));
        tvInfo.setTextSize(11);
        tvInfo.setPadding(0, dpToPx(10), 0, dpToPx(4));
        addLayout.addView(tvInfo);

        addBuilder.setView(addLayout);

        addBuilder.setPositiveButton("Select MP3", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface d, int which) {
                String name = etMantraName.getText().toString().trim();
                if (name.length() == 0) {
                    Toast.makeText(NoteEditorActivity.this,
                            "Please enter a mantra name", Toast.LENGTH_SHORT).show();
                    return;
                }
                // Store the name and launch mp3 picker
                pendingMantraName = name;
                Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                intent.setType("audio/*");
                startActivityForResult(Intent.createChooser(intent, "Select Mantra MP3"),
                        REQUEST_MANTRA_MP3_PICK);
            }
        });

        addBuilder.setNeutralButton("Save without MP3", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface d, int which) {
                String name = etMantraName.getText().toString().trim();
                if (name.length() == 0) {
                    Toast.makeText(NoteEditorActivity.this,
                            "Please enter a mantra name", Toast.LENGTH_SHORT).show();
                    return;
                }
                // Save mantra without audio
                saveNewUserMantra(name, "");
                refreshHybridMantraListInPopup(listContainer, parentDialog);
            }
        });

        addBuilder.setNegativeButton("Cancel", null);
        addBuilder.show();
    }

    /**
     * Save a new user-added mantra to the master library.
     * @param name mantra display name
     * @param audioPath file path or empty string
     */
    private void saveNewUserMantra(String name, String audioPath) {
        Mantra mantra = new Mantra();
        mantra.setName(name);
        mantra.setAudioPath(audioPath != null ? audioPath : "");
        mantra.setBuiltIn(false);
        mantra.setDeleted(false);
        mantra.setNoteId(-1);
        mantra.setCreatedAt(System.currentTimeMillis());
        mantra.setPlaybackSpeed(1.0f);
        mantra.setTodayCount(0);
        mantra.setRawResId(0);
        long id = repository.insertMantra(mantra);
        if (id > 0) {
            Toast.makeText(this, name + " saved to library", Toast.LENGTH_SHORT).show();
        }
    }

    /**
     * Handle mp3 file selection result for new user mantra.
     */
    private void handleMantraMp3Result(Intent data) {
        if (data == null || data.getData() == null || pendingMantraName == null) {
            pendingMantraName = null;
            return;
        }

        Uri uri = data.getData();
        String name = pendingMantraName;
        pendingMantraName = null;

        // Copy the mp3 to app internal storage
        String audioPath = copyMantraMp3ToInternal(uri, name);

        // Save the mantra
        saveNewUserMantra(name, audioPath);

        // Refresh popup if still open
        if (activeMantraPopupDialog != null && activeMantraPopupListContainer != null
                && activeMantraPopupDialog.isShowing()) {
            refreshHybridMantraListInPopup(activeMantraPopupListContainer, activeMantraPopupDialog);
        }
    }

    /**
     * Copy an audio file URI to internal app storage for the mantra.
     * Returns the absolute file path, or empty string on failure.
     */
    private String copyMantraMp3ToInternal(Uri uri, String mantraName) {
        try {
            java.io.InputStream inputStream = getContentResolver().openInputStream(uri);
            if (inputStream == null) return "";

            // Create mantras directory in internal storage
            File mantrasDir = new File(getFilesDir(), "mantras");
            if (!mantrasDir.exists()) {
                mantrasDir.mkdirs();
            }

            // Sanitize filename
            String safeName = mantraName.replaceAll("[^a-zA-Z0-9]", "_").toLowerCase();
            String fileName = safeName + "_" + System.currentTimeMillis() + ".mp3";
            File outFile = new File(mantrasDir, fileName);

            java.io.OutputStream outputStream = new java.io.FileOutputStream(outFile);
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
            outputStream.flush();
            outputStream.close();
            inputStream.close();

            return outFile.getAbsolutePath();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Activate meditation mode - show the meditation container with cards.
     * If already active, just refresh and scroll to it (no duplicate).
     */
    private void activateMeditationMode() {
        if (meditationContainer != null) {
            meditationContainer.setVisibility(View.VISIBLE);
        }

        if (meditationCardBuilder == null) {
            meditationCardBuilder = new MeditationCardBuilder(this, meditationContainer);
            meditationCardBuilder.setActionListener(new MeditationCardBuilder.CardActionListener() {
                public void onMantraDeleted(Mantra mantra) {
                    refreshMeditationCards();
                    hasChanges = true;
                }
                public void onDataChanged() {
                    hasChanges = true;
                }
            });
        }

        isMeditationMode = true;
        refreshMeditationCards();

        // Scroll to meditation container if it exists
        if (meditationContainer != null && scrollTextContent != null) {
            scrollTextContent.post(new Runnable() {
                public void run() {
                    scrollTextContent.scrollTo(0, meditationContainer.getTop());
                }
            });
        }
    }

    /**
     * Deactivate meditation mode - hide container.
     * Does NOT stop playback - mantra can continue in background via service.
     */
    private void deactivateMeditationMode() {
        isMeditationMode = false;

        if (meditationContainer != null) {
            meditationContainer.setVisibility(View.GONE);
        }

        // Unregister receivers
        if (meditationCardBuilder != null) {
            meditationCardBuilder.unregisterReceivers();
        }
    }

    /**
     * Refresh meditation cards in the container.
     * Uses session-driven data: only shows mantras with a DailySession for today.
     */
    private void refreshMeditationCards() {
        if (meditationCardBuilder == null || currentNote == null) return;

        meditationCardBuilder.refreshCards(currentNote.getId());

        // Check if there are any sessions for today - if not, hide container
        String today = MeditationPlayerManager.getTodayDateString();
        List sessionMantras = repository.getMantrasWithSessionForNoteAndDate(
                currentNote.getId(), today);
        if (sessionMantras.isEmpty()) {
            isMeditationMode = false;
            if (meditationContainer != null) {
                meditationContainer.setVisibility(View.GONE);
            }
        }
    }

    /**
     * Restore meditation mode for notes that have active sessions for today.
     * Built-in mantras are always available through the popup.
     */
    private void restoreMeditationMode() {
        if (currentNote == null) return;
        String today = MeditationPlayerManager.getTodayDateString();
        List sessionMantras = repository.getMantrasWithSessionForNoteAndDate(
                currentNote.getId(), today);
        if (!sessionMantras.isEmpty()) {
            activateMeditationMode();
        }
    }

    // ======================== EXPORT METHODS ========================

    /**
     * ISSUE 7: Export note as plain text file and share via Intent.
     * Uses internal cache directory for crash-free file creation.
     */
    private void exportAsTxt() {
        try {
            String title = etTitle.getText().toString().trim();
            String content;
            if (isChecklistMode) {
                content = checklistManager.toPlainText();
            } else {
                content = etContent.getText().toString();
            }

            String fileName = (title.length() > 0 ? title : "note") + ".txt";
            // Sanitize filename
            fileName = fileName.replaceAll("[^a-zA-Z0-9._\\- ]", "_");

            String fileContent = "";
            if (title.length() > 0) {
                fileContent = title + "\n\n";
            }
            fileContent = fileContent + content;

            File cacheDir = getCacheDir();
            File exportDir = new File(cacheDir, "exports");
            if (!exportDir.exists()) {
                exportDir.mkdirs();
            }
            File txtFile = new File(exportDir, fileName);

            java.io.FileOutputStream fos = new java.io.FileOutputStream(txtFile);
            fos.write(fileContent.getBytes("UTF-8"));
            fos.flush();
            fos.close();

            Uri contentUri = com.mknotes.app.util.MKFileProvider.getUriForFile(txtFile);
            Intent shareIntent = new Intent(Intent.ACTION_SEND);
            shareIntent.setType("text/plain");
            shareIntent.putExtra(Intent.EXTRA_STREAM, contentUri);
            shareIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(shareIntent, "Export as TXT"));

        } catch (Exception e) {
            Toast.makeText(this, "Export failed: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    /**
     * ISSUE 7: Export note as PDF using Android PdfDocument API.
     * Creates a single-page PDF with title and content, then shares via Intent.
     * No external libraries used.
     */
    private void exportAsPdf() {
        try {
            String title = etTitle.getText().toString().trim();
            String content;
            if (isChecklistMode) {
                content = checklistManager.toPlainText();
            } else {
                content = etContent.getText().toString();
            }

            String fileName = (title.length() > 0 ? title : "note") + ".pdf";
            fileName = fileName.replaceAll("[^a-zA-Z0-9._\\- ]", "_");

            // Create PDF document
            android.graphics.pdf.PdfDocument document = new android.graphics.pdf.PdfDocument();

            // A4-ish page size in points (595 x 842)
            int pageWidth = 595;
            int pageHeight = 842;
            int margin = 40;
            int usableWidth = pageWidth - (margin * 2);

            // Prepare paint for title
            android.graphics.Paint titlePaint = new android.graphics.Paint();
            titlePaint.setColor(android.graphics.Color.BLACK);
            titlePaint.setTextSize(18);
            titlePaint.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
            titlePaint.setAntiAlias(true);

            // Prepare paint for content
            android.graphics.Paint contentPaint = new android.graphics.Paint();
            contentPaint.setColor(android.graphics.Color.DKGRAY);
            contentPaint.setTextSize(12);
            contentPaint.setAntiAlias(true);

            // Prepare paint for date
            android.graphics.Paint datePaint = new android.graphics.Paint();
            datePaint.setColor(android.graphics.Color.GRAY);
            datePaint.setTextSize(10);
            datePaint.setAntiAlias(true);

            // Break content into lines that fit within page width
            List allLines = new ArrayList();

            // Add title lines
            if (title.length() > 0) {
                List titleLines = breakTextIntoLines(title, titlePaint, usableWidth);
                for (int i = 0; i < titleLines.size(); i++) {
                    allLines.add("TITLE:" + (String) titleLines.get(i));
                }
                allLines.add("SPACE");
            }

            // Add date
            String dateStr = DateUtils.formatEditorDate(
                    currentNote != null ? currentNote.getModifiedAt() : System.currentTimeMillis());
            allLines.add("DATE:" + dateStr);
            allLines.add("SPACE");

            // Add content lines
            if (content.length() > 0) {
                String[] paragraphs = content.split("\n");
                for (int p = 0; p < paragraphs.length; p++) {
                    if (paragraphs[p].trim().length() == 0) {
                        allLines.add("SPACE");
                    } else {
                        List cLines = breakTextIntoLines(paragraphs[p], contentPaint, usableWidth);
                        for (int i = 0; i < cLines.size(); i++) {
                            allLines.add("CONTENT:" + (String) cLines.get(i));
                        }
                    }
                }
            }

            // Now render pages
            int lineIndex = 0;
            int pageNumber = 1;

            while (lineIndex < allLines.size()) {
                android.graphics.pdf.PdfDocument.PageInfo pageInfo =
                        new android.graphics.pdf.PdfDocument.PageInfo.Builder(pageWidth, pageHeight, pageNumber).create();
                android.graphics.pdf.PdfDocument.Page page = document.startPage(pageInfo);
                android.graphics.Canvas canvas = page.getCanvas();

                float yPos = margin;
                float maxY = pageHeight - margin;

                while (lineIndex < allLines.size() && yPos < maxY) {
                    String line = (String) allLines.get(lineIndex);

                    if (line.equals("SPACE")) {
                        yPos = yPos + 12;
                        lineIndex++;
                        continue;
                    }

                    if (line.startsWith("TITLE:")) {
                        String text = line.substring(6);
                        yPos = yPos + 22;
                        if (yPos > maxY) break;
                        canvas.drawText(text, margin, yPos, titlePaint);
                        lineIndex++;
                    } else if (line.startsWith("DATE:")) {
                        String text = line.substring(5);
                        yPos = yPos + 14;
                        if (yPos > maxY) break;
                        canvas.drawText(text, margin, yPos, datePaint);
                        lineIndex++;
                    } else if (line.startsWith("CONTENT:")) {
                        String text = line.substring(8);
                        yPos = yPos + 16;
                        if (yPos > maxY) break;
                        canvas.drawText(text, margin, yPos, contentPaint);
                        lineIndex++;
                    } else {
                        lineIndex++;
                    }
                }

                document.finishPage(page);
                pageNumber++;
            }

            // Write PDF to cache file
            File cacheDir = getCacheDir();
            File exportDir = new File(cacheDir, "exports");
            if (!exportDir.exists()) {
                exportDir.mkdirs();
            }
            File pdfFile = new File(exportDir, fileName);

            java.io.FileOutputStream fos = new java.io.FileOutputStream(pdfFile);
            document.writeTo(fos);
            fos.flush();
            fos.close();
            document.close();

            // Share via Intent
            Uri contentUri = com.mknotes.app.util.MKFileProvider.getUriForFile(pdfFile);
            Intent shareIntent = new Intent(Intent.ACTION_SEND);
            shareIntent.setType("application/pdf");
            shareIntent.putExtra(Intent.EXTRA_STREAM, contentUri);
            shareIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(shareIntent, "Export as PDF"));

        } catch (Exception e) {
            Toast.makeText(this, "PDF export failed: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    /**
     * Break a long text string into lines that fit within the given pixel width.
     * Pure Java, no external libraries.
     */
    private List breakTextIntoLines(String text, android.graphics.Paint paint, int maxWidth) {
        List lines = new ArrayList();
        if (text == null || text.length() == 0) {
            lines.add("");
            return lines;
        }

        String[] words = text.split(" ");
        StringBuilder currentLine = new StringBuilder();

        for (int i = 0; i < words.length; i++) {
            String word = words[i];
            String testLine;
            if (currentLine.length() == 0) {
                testLine = word;
            } else {
                testLine = currentLine.toString() + " " + word;
            }

            float lineWidth = paint.measureText(testLine);
            if (lineWidth <= maxWidth) {
                if (currentLine.length() > 0) {
                    currentLine.append(" ");
                }
                currentLine.append(word);
            } else {
                if (currentLine.length() > 0) {
                    lines.add(currentLine.toString());
                    currentLine = new StringBuilder(word);
                } else {
                    // Single word wider than page - force it on the line
                    lines.add(word);
                    currentLine = new StringBuilder();
                }
            }
        }

        if (currentLine.length() > 0) {
            lines.add(currentLine.toString());
        }

        if (lines.isEmpty()) {
            lines.add("");
        }

        return lines;
    }

    private int dpToPx(int dp) {
        float density = getResources().getDisplayMetrics().density;
        return (int) (dp * density + 0.5f);
    }
}
