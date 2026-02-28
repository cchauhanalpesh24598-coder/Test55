package com.mknotes.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.AdapterView;
import android.widget.GridView;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.PopupMenu;
import android.widget.PopupWindow;
import android.widget.RelativeLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.mknotes.app.cloud.CloudSyncManager;
import com.mknotes.app.cloud.FirebaseAuthManager;
import com.mknotes.app.adapter.NoteAdapter;
import com.mknotes.app.db.NotesRepository;
import com.mknotes.app.model.Category;
import com.mknotes.app.model.Note;
import com.mknotes.app.analysis.CalendarAnalysisActivity;
import com.mknotes.app.util.NoteColorUtil;
import com.mknotes.app.util.PrefsManager;
import com.mknotes.app.util.SessionManager;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class MainActivity extends Activity {

    private ListView listNotes;
    private GridView gridNotes;
    private LinearLayout emptyState;
    private ImageButton fabAdd;
    private LinearLayout categoryContainer;

    // HomeScreenTopBar views
    private RelativeLayout toolbar;
    private ImageButton btnMenu;
    private ImageButton btnSearch;
    private ImageButton btnViewMode;
    private TextView tvSearchHint;

    // SelectedTopBar views (multi-select mode)
    private RelativeLayout selectionToolbar;
    private ImageButton btnSelectionClose;
    private TextView tvSelectionCount;
    private ImageButton btnSelectionArchive;
    private ImageButton btnSelectionStar;
    private ImageButton btnSelectionMore;
    private ImageButton btnSelectAll;

    // State
    private NoteAdapter adapter;
    private NotesRepository repository;
    private PrefsManager prefs;
    private boolean isSelectionMode = false;
    private Set selectedNoteIds;
    private List currentNotes;
    private boolean isGridView = false;

    private static final int REQUEST_EDITOR = 100;
    private static final int REQUEST_SEARCH = 101;
    private static final int REQUEST_SETTINGS = 102;

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        repository = NotesRepository.getInstance(this);
        prefs = PrefsManager.getInstance(this);
        selectedNoteIds = new HashSet();
        currentNotes = new ArrayList();

        initViews();
        initSelectionToolbar();
        setupListeners();
        loadNotes();
        loadCategoryTabs();
    }

    protected void onResume() {
        super.onResume();

        // Session-based lock: if session expired, redirect to password screen
        SessionManager session = SessionManager.getInstance(this);
        if (session.isPasswordSet() && !session.isSessionValid()) {
            Intent lockIntent = new Intent(this, MasterPasswordActivity.class);
            lockIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(lockIntent);
            finish();
            return;
        }
        // Refresh session timestamp on every resume
        if (session.isPasswordSet()) {
            session.updateSessionTimestamp();
        }

        loadNotes();
        loadCategoryTabs();

        // Trigger cloud sync on app resume if authenticated
        triggerCloudSync();
    }

    /**
     * Perform bidirectional cloud sync if enabled and authenticated.
     * On sync complete, refreshes the note list to show any new/updated notes.
     */
    private void triggerCloudSync() {
        try {
            if (!PrefsManager.getInstance(this).isCloudSyncEnabled()) return;
            if (!FirebaseAuthManager.getInstance(this).isLoggedIn()) return;
            if (!SessionManager.getInstance(this).isSessionValid()) return;

            CloudSyncManager.getInstance(this).syncOnAppStart(
                    new CloudSyncManager.SyncCallback() {
                        public void onSyncComplete(final boolean success) {
                            runOnUiThread(new Runnable() {
                                public void run() {
                                    if (success) {
                                        loadNotes();
                                        loadCategoryTabs();
                                    }
                                }
                            });
                        }
                    });
        } catch (Exception e) {
            // Cloud sync failure must not crash the app
        }
    }

    /**
     * Trigger cloud soft-delete when a note is moved to trash.
     * Sets isDeleted=true in Firestore so other devices know this note is deleted.
     */
    private void triggerCloudDeleteForNote(String cloudId) {
        try {
            if (cloudId == null || cloudId.length() == 0) return;
            if (!PrefsManager.getInstance(this).isCloudSyncEnabled()) return;
            if (!FirebaseAuthManager.getInstance(this).isLoggedIn()) return;
            if (!SessionManager.getInstance(this).isSessionValid()) return;

            CloudSyncManager.getInstance(this).deleteNoteFromCloud(cloudId);
        } catch (Exception e) {
            // Cloud sync failure must not crash the app
        }
    }

    /**
     * Trigger cloud upload for a note after local changes (archive/unarchive/favorite toggle).
     */
    private void triggerCloudUploadForNote(long noteId) {
        try {
            if (!PrefsManager.getInstance(this).isCloudSyncEnabled()) return;
            if (!FirebaseAuthManager.getInstance(this).isLoggedIn()) return;
            if (!SessionManager.getInstance(this).isSessionValid()) return;

            CloudSyncManager.getInstance(this).uploadNote(noteId);
        } catch (Exception e) {
            // Cloud sync failure must not crash the app
        }
    }

    private void initViews() {
        listNotes = (ListView) findViewById(R.id.list_notes);
        gridNotes = (GridView) findViewById(R.id.grid_notes);
        emptyState = (LinearLayout) findViewById(R.id.empty_state);
        fabAdd = (ImageButton) findViewById(R.id.fab_add);
        categoryContainer = (LinearLayout) findViewById(R.id.category_container);

        // HomeScreenTopBar
        toolbar = (RelativeLayout) findViewById(R.id.toolbar);
        btnMenu = (ImageButton) findViewById(R.id.btn_menu);
        btnSearch = (ImageButton) findViewById(R.id.btn_search);
        btnViewMode = (ImageButton) findViewById(R.id.btn_view_mode);

        tvSearchHint = (TextView) findViewById(R.id.tv_title);
        if (tvSearchHint != null) {
            tvSearchHint.setText(R.string.search_your_notes);
        }

        styleHomeScreenTopBar();

        adapter = new NoteAdapter(this);
        listNotes.setAdapter(adapter);
        gridNotes.setAdapter(adapter);

        // Restore view mode from preferences
        isGridView = prefs.getViewMode() == PrefsManager.VIEW_GRID;
        applyViewMode();
    }

    private void styleHomeScreenTopBar() {
        if (toolbar == null) return;

        GradientDrawable bg = new GradientDrawable();
        bg.setColor(Color.parseColor("#323335"));
        bg.setCornerRadius(dpToPx(50));
        toolbar.setBackground(bg);

        ViewGroup parent = (ViewGroup) toolbar.getParent();
        if (parent != null) {
            ViewGroup.MarginLayoutParams mlp;
            if (toolbar.getLayoutParams() instanceof ViewGroup.MarginLayoutParams) {
                mlp = (ViewGroup.MarginLayoutParams) toolbar.getLayoutParams();
            } else {
                mlp = new ViewGroup.MarginLayoutParams(toolbar.getLayoutParams());
            }
            mlp.leftMargin = dpToPx(16);
            mlp.rightMargin = dpToPx(16);
            mlp.topMargin = dpToPx(8);
            mlp.bottomMargin = dpToPx(8);
            toolbar.setLayoutParams(mlp);
        }

        toolbar.setElevation(dpToPx(1));

        if (tvSearchHint != null) {
            tvSearchHint.setTextColor(Color.WHITE);
            tvSearchHint.setTextSize(18);
            tvSearchHint.setText(R.string.search_your_notes);
        }

        if (btnMenu != null) btnMenu.setColorFilter(Color.WHITE);
        if (btnSearch != null) btnSearch.setColorFilter(Color.WHITE);
        if (btnViewMode != null) btnViewMode.setColorFilter(Color.WHITE);
    }

    private void initSelectionToolbar() {
        selectionToolbar = new RelativeLayout(this);
        selectionToolbar.setBackgroundColor(Color.parseColor("#323335"));
        selectionToolbar.setVisibility(View.GONE);

        int tbHeight = dpToPx(56);
        int btnSize = dpToPx(40);
        int pad = dpToPx(8);
        selectionToolbar.setPadding(pad, 0, pad, 0);

        // Close button
        btnSelectionClose = new ImageButton(this);
        btnSelectionClose.setImageResource(R.drawable.ic_close);
        btnSelectionClose.setColorFilter(Color.WHITE);
        btnSelectionClose.setBackgroundResource(android.R.color.transparent);
        btnSelectionClose.setScaleType(ImageButton.ScaleType.CENTER_INSIDE);
        btnSelectionClose.setContentDescription(getString(R.string.selection_close));
        btnSelectionClose.setId(android.R.id.button1);
        RelativeLayout.LayoutParams closeLp = new RelativeLayout.LayoutParams(btnSize, btnSize);
        closeLp.addRule(RelativeLayout.ALIGN_PARENT_LEFT);
        closeLp.addRule(RelativeLayout.CENTER_VERTICAL);
        selectionToolbar.addView(btnSelectionClose, closeLp);

        // Selection count
        tvSelectionCount = new TextView(this);
        tvSelectionCount.setTextColor(Color.parseColor("#FFFFFF"));
        tvSelectionCount.setTextSize(18);
        tvSelectionCount.setText("1");
        tvSelectionCount.setId(android.R.id.text1);
        RelativeLayout.LayoutParams countLp = new RelativeLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        countLp.addRule(RelativeLayout.RIGHT_OF, android.R.id.button1);
        countLp.addRule(RelativeLayout.CENTER_VERTICAL);
        countLp.leftMargin = dpToPx(4);
        selectionToolbar.addView(tvSelectionCount, countLp);

        // Right side buttons
        LinearLayout rightButtons = new LinearLayout(this);
        rightButtons.setOrientation(LinearLayout.HORIZONTAL);
        rightButtons.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams rbLp = new LinearLayout.LayoutParams(btnSize, btnSize);

        // Select All button
        btnSelectAll = new ImageButton(this);
        btnSelectAll.setImageResource(R.drawable.ic_checklist);
        btnSelectAll.setColorFilter(Color.WHITE);
        btnSelectAll.setBackgroundResource(android.R.color.transparent);
        btnSelectAll.setScaleType(ImageButton.ScaleType.CENTER_INSIDE);
        btnSelectAll.setContentDescription(getString(R.string.action_select_all));
        rightButtons.addView(btnSelectAll, new LinearLayout.LayoutParams(btnSize, btnSize));

        // Archive button
        btnSelectionArchive = new ImageButton(this);
        btnSelectionArchive.setImageResource(R.drawable.ic_archive);
        btnSelectionArchive.setColorFilter(Color.WHITE);
        btnSelectionArchive.setBackgroundResource(android.R.color.transparent);
        btnSelectionArchive.setScaleType(ImageButton.ScaleType.CENTER_INSIDE);
        btnSelectionArchive.setContentDescription(getString(R.string.archive_note));
        rightButtons.addView(btnSelectionArchive, new LinearLayout.LayoutParams(btnSize, btnSize));

        // Star button
        btnSelectionStar = new ImageButton(this);
        btnSelectionStar.setImageResource(R.drawable.ic_star_filled);
        btnSelectionStar.setColorFilter(Color.WHITE);
        btnSelectionStar.setBackgroundResource(android.R.color.transparent);
        btnSelectionStar.setScaleType(ImageButton.ScaleType.CENTER_INSIDE);
        rightButtons.addView(btnSelectionStar, new LinearLayout.LayoutParams(btnSize, btnSize));

        // More button
        btnSelectionMore = new ImageButton(this);
        btnSelectionMore.setImageResource(R.drawable.ic_more);
        btnSelectionMore.setColorFilter(Color.WHITE);
        btnSelectionMore.setBackgroundResource(android.R.color.transparent);
        btnSelectionMore.setScaleType(ImageButton.ScaleType.CENTER_INSIDE);
        rightButtons.addView(btnSelectionMore, new LinearLayout.LayoutParams(btnSize, btnSize));

        RelativeLayout.LayoutParams rightLp = new RelativeLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rightLp.addRule(RelativeLayout.ALIGN_PARENT_RIGHT);
        rightLp.addRule(RelativeLayout.CENTER_VERTICAL);
        selectionToolbar.addView(rightButtons, rightLp);

        LinearLayout mainLayout = (LinearLayout) toolbar.getParent();
        int toolbarIndex = mainLayout.indexOfChild(toolbar);
        LinearLayout.LayoutParams selLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, tbHeight);
        mainLayout.addView(selectionToolbar, toolbarIndex, selLp);

        // Click listeners
        btnSelectionClose.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { exitSelectionMode(); }
        });
        btnSelectionStar.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { toggleFavoriteSelected(); }
        });
        btnSelectionMore.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { showSelectionMenu(v); }
        });
        btnSelectionArchive.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { archiveSelectedNotes(); }
        });
        btnSelectAll.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { selectAllNotes(); }
        });
    }

    private void enterSelectionMode(Note note) {
        isSelectionMode = true;
        selectedNoteIds.clear();
        selectedNoteIds.add(Long.valueOf(note.getId()));
        syncSelectionToAdapter();
        toolbar.setVisibility(View.GONE);
        selectionToolbar.setVisibility(View.VISIBLE);
        updateSelectionCount();
        adapter.notifyDataSetChanged();
    }

    private void exitSelectionMode() {
        isSelectionMode = false;
        selectedNoteIds.clear();
        syncSelectionToAdapter();
        selectionToolbar.setVisibility(View.GONE);
        toolbar.setVisibility(View.VISIBLE);
        adapter.notifyDataSetChanged();
    }

    private void syncSelectionToAdapter() {
        adapter.setSelectedIds(selectedNoteIds);
    }

    private void updateSelectionCount() {
        if (tvSelectionCount != null) {
            tvSelectionCount.setText(String.valueOf(selectedNoteIds.size()));
        }
    }

    private void toggleNoteSelection(Note note) {
        Long noteId = Long.valueOf(note.getId());
        if (selectedNoteIds.contains(noteId)) {
            selectedNoteIds.remove(noteId);
        } else {
            selectedNoteIds.add(noteId);
        }
        syncSelectionToAdapter();
        if (selectedNoteIds.isEmpty()) {
            exitSelectionMode();
        } else {
            updateSelectionCount();
            adapter.notifyDataSetChanged();
        }
    }

    private void selectAllNotes() {
        selectedNoteIds.clear();
        for (int i = 0; i < currentNotes.size(); i++) {
            Note n = (Note) currentNotes.get(i);
            selectedNoteIds.add(Long.valueOf(n.getId()));
        }
        syncSelectionToAdapter();
        updateSelectionCount();
        adapter.notifyDataSetChanged();
    }

    private void showSelectionMenu(View anchor) {
        PopupMenu popup = new PopupMenu(this, anchor);
        popup.getMenu().add(0, 1, 0, getString(R.string.delete));
        popup.getMenu().add(0, 2, 1, getString(R.string.make_copy));
        popup.getMenu().add(0, 3, 2, getString(R.string.clear));
        popup.setOnMenuItemClickListener(new PopupMenu.OnMenuItemClickListener() {
            public boolean onMenuItemClick(android.view.MenuItem item) {
                switch (item.getItemId()) {
                    case 1: deleteSelectedNotes(); return true;
                    case 2: copySelectedNotes(); return true;
                    case 3: exitSelectionMode(); return true;
                }
                return false;
            }
        });
        popup.show();
    }

    private void deleteSelectedNotes() {
        List toDelete = getSelectedNoteObjects();
        for (int i = 0; i < toDelete.size(); i++) {
            Note note = (Note) toDelete.get(i);
            String cloudId = note.getCloudId();
            repository.moveToTrash(note);
            triggerCloudDeleteForNote(cloudId);
        }
        Toast.makeText(this, R.string.note_moved_to_trash, Toast.LENGTH_SHORT).show();
        exitSelectionMode();
        loadNotes();
    }

    private void copySelectedNotes() {
        List toCopy = getSelectedNoteObjects();
        for (int i = 0; i < toCopy.size(); i++) {
            Note original = (Note) toCopy.get(i);
            Note copy = new Note();
            copy.setTitle(original.getTitle());
            copy.setContent(original.getContent());
            copy.setColor(original.getColor());
            copy.setCategoryId(original.getCategoryId());
            copy.setCreatedAt(System.currentTimeMillis());
            copy.setModifiedAt(System.currentTimeMillis());
            repository.insertNote(copy);
        }
        Toast.makeText(this, getString(R.string.make_copy), Toast.LENGTH_SHORT).show();
        exitSelectionMode();
        loadNotes();
    }

    private void toggleFavoriteSelected() {
        List toFav = getSelectedNoteObjects();
        for (int i = 0; i < toFav.size(); i++) {
            Note note = (Note) toFav.get(i);
            repository.toggleFavorite(note.getId());
        }
        exitSelectionMode();
        loadNotes();
    }

    private void archiveSelectedNotes() {
        List toArchive = getSelectedNoteObjects();
        for (int i = 0; i < toArchive.size(); i++) {
            Note note = (Note) toArchive.get(i);
            repository.archiveNote(note.getId());
            // Trigger cloud update so archived state syncs
            triggerCloudUploadForNote(note.getId());
        }
        Toast.makeText(this, getString(R.string.archive_note), Toast.LENGTH_SHORT).show();
        exitSelectionMode();
        loadNotes();
    }

    private List getSelectedNoteObjects() {
        List result = new ArrayList();
        for (int i = 0; i < currentNotes.size(); i++) {
            Note n = (Note) currentNotes.get(i);
            if (selectedNoteIds.contains(Long.valueOf(n.getId()))) {
                result.add(n);
            }
        }
        return result;
    }

    private void setupListeners() {
        fabAdd.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                Intent intent = new Intent(MainActivity.this, NoteEditorActivity.class);
                intent.putExtra("note_id", -1L);
                startActivityForResult(intent, REQUEST_EDITOR);
            }
        });

        // Shared click listener for both list and grid
        AdapterView.OnItemClickListener itemClickListener = new AdapterView.OnItemClickListener() {
            public void onItemClick(AdapterView parent, View view, int position, long id) {
                Note note = (Note) adapter.getItem(position);
                if (isSelectionMode) {
                    toggleNoteSelection(note);
                    return;
                }
                if (note.isLocked()) {
                    showPasswordDialog(note);
                } else {
                    openEditor(note.getId());
                }
            }
        };

        AdapterView.OnItemLongClickListener itemLongClickListener = new AdapterView.OnItemLongClickListener() {
            public boolean onItemLongClick(AdapterView parent, View view, int position, long id) {
                Note note = (Note) adapter.getItem(position);
                if (!isSelectionMode) {
                    enterSelectionMode(note);
                } else {
                    toggleNoteSelection(note);
                }
                return true;
            }
        };

        listNotes.setOnItemClickListener(itemClickListener);
        listNotes.setOnItemLongClickListener(itemLongClickListener);
        gridNotes.setOnItemClickListener(itemClickListener);
        gridNotes.setOnItemLongClickListener(itemLongClickListener);

        if (tvSearchHint != null) {
            tvSearchHint.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    Intent intent = new Intent(MainActivity.this, SearchActivity.class);
                    startActivityForResult(intent, REQUEST_SEARCH);
                }
            });
        }

        btnSearch.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                Intent intent = new Intent(MainActivity.this, SearchActivity.class);
                startActivityForResult(intent, REQUEST_SEARCH);
            }
        });

        // Menu button opens left-slide drawer with ALL options
        btnMenu.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showDrawerMenu();
            }
        });

        btnViewMode.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                toggleViewMode();
            }
        });
    }

    private void loadNotes() {
        String filter = prefs.getCurrentFilter();
        List notes;

        if (PrefsManager.FILTER_FAVORITES.equals(filter)) {
            notes = repository.getFavoriteNotes(prefs.getSortBy());
        } else if (PrefsManager.FILTER_CATEGORY.equals(filter)) {
            long catId = prefs.getCurrentCategoryId();
            notes = repository.getNotesByCategory(catId, prefs.getSortBy());
        } else {
            notes = repository.getAllNotes(prefs.getSortBy());
        }

        currentNotes = notes;
        adapter.setNotes(notes);

        if (notes.isEmpty()) {
            emptyState.setVisibility(View.VISIBLE);
            listNotes.setVisibility(View.GONE);
            gridNotes.setVisibility(View.GONE);
        } else {
            emptyState.setVisibility(View.GONE);
            applyViewMode();
        }
    }

    /**
     * Apply grid or list mode by switching visibility and adapter mode.
     */
    private void applyViewMode() {
        if (isGridView) {
            adapter.setGridMode(true);
            listNotes.setVisibility(View.GONE);
            gridNotes.setVisibility(View.VISIBLE);
            btnViewMode.setImageResource(R.drawable.ic_view_grid);
        } else {
            adapter.setGridMode(false);
            listNotes.setVisibility(View.VISIBLE);
            gridNotes.setVisibility(View.GONE);
            btnViewMode.setImageResource(R.drawable.ic_view_list);
        }
    }

    private void loadCategoryTabs() {
        categoryContainer.removeAllViews();

        addCategoryTab(getString(R.string.all_notes), -1, PrefsManager.FILTER_ALL.equals(prefs.getCurrentFilter()));
        addCategoryTab(getString(R.string.favorites), -2, PrefsManager.FILTER_FAVORITES.equals(prefs.getCurrentFilter()));

        List categories = repository.getAllCategories();
        for (int i = 0; i < categories.size(); i++) {
            Category cat = (Category) categories.get(i);
            boolean selected = PrefsManager.FILTER_CATEGORY.equals(prefs.getCurrentFilter())
                    && prefs.getCurrentCategoryId() == cat.getId();
            addCategoryTab(cat.getName(), cat.getId(), selected);
        }
    }

    private void addCategoryTab(final String name, final long categoryId, boolean selected) {
        TextView tab = new TextView(this);
        tab.setText(name);
        tab.setTextSize(14);
        tab.setPadding(24, 8, 24, 8);

        if (selected) {
            tab.setTextColor(getResources().getColor(R.color.accent));
            tab.setBackgroundResource(R.drawable.tab_selected_bg);
        } else {
            tab.setTextColor(getResources().getColor(R.color.text_secondary));
            tab.setBackgroundResource(0);
        }

        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.setMargins(4, 4, 4, 4);
        tab.setLayoutParams(params);

        tab.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (categoryId == -1) {
                    prefs.setCurrentFilter(PrefsManager.FILTER_ALL);
                } else if (categoryId == -2) {
                    prefs.setCurrentFilter(PrefsManager.FILTER_FAVORITES);
                } else {
                    prefs.setCurrentFilter(PrefsManager.FILTER_CATEGORY);
                    prefs.setCurrentCategoryId(categoryId);
                }
                loadNotes();
                loadCategoryTabs();
            }
        });

        categoryContainer.addView(tab);
    }

    private void openEditor(long noteId) {
        Intent intent = new Intent(this, NoteEditorActivity.class);
        intent.putExtra("note_id", noteId);
        startActivityForResult(intent, REQUEST_EDITOR);
    }

    private void shareNote(Note note) {
        Intent shareIntent = new Intent(Intent.ACTION_SEND);
        shareIntent.setType("text/plain");
        String shareText = "";
        if (note.getTitle() != null && note.getTitle().length() > 0) {
            shareText = note.getTitle() + "\n\n";
        }
        shareText = shareText + note.getContent();
        shareIntent.putExtra(Intent.EXTRA_TEXT, shareText);
        startActivity(Intent.createChooser(shareIntent, getString(R.string.share)));
    }

    private void showColorPicker(final Note note) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.choose_color);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.HORIZONTAL);
        layout.setGravity(Gravity.CENTER);
        layout.setPadding(16, 16, 16, 16);

        int[] colors = NoteColorUtil.getAllPresetColors();
        for (int i = 0; i < colors.length; i++) {
            final int colorIndex = i;
            View colorView = new View(this);
            int size = 48;
            LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(size, size);
            params.setMargins(8, 8, 8, 8);
            colorView.setLayoutParams(params);

            GradientDrawable shape = new GradientDrawable();
            shape.setShape(GradientDrawable.OVAL);
            if (i == 0) {
                shape.setColor(Color.WHITE);
                shape.setStroke(2, Color.GRAY);
            } else {
                shape.setColor(colors[i]);
            }
            colorView.setBackground(shape);

            colorView.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    note.setColor(colorIndex);
                    repository.updateNote(note);
                    loadNotes();
                }
            });

            layout.addView(colorView);
        }

        builder.setView(layout);
        builder.show();
    }

    private void confirmDeleteNote(final Note note) {
        if (prefs.isConfirmDelete()) {
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle(R.string.delete_note_title);
            builder.setMessage(R.string.delete_note_message);
            builder.setPositiveButton(R.string.delete, new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    String cloudId = note.getCloudId();
                    repository.moveToTrash(note);
                    triggerCloudDeleteForNote(cloudId);
                    loadNotes();
                    Toast.makeText(MainActivity.this, R.string.note_moved_to_trash, Toast.LENGTH_SHORT).show();
                }
            });
            builder.setNegativeButton(R.string.cancel, null);
            builder.show();
        } else {
            String cloudId = note.getCloudId();
            repository.moveToTrash(note);
            triggerCloudDeleteForNote(cloudId);
            loadNotes();
            Toast.makeText(this, R.string.note_moved_to_trash, Toast.LENGTH_SHORT).show();
        }
    }

    private void showPasswordDialog(final Note note) {
        final android.widget.EditText input = new android.widget.EditText(this);
        input.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        input.setHint(R.string.enter_password);

        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.locked_note);
        builder.setView(input);
        builder.setPositiveButton(R.string.unlock, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                String pwd = input.getText().toString();
                if (com.mknotes.app.util.PasswordHashUtil.verifyPassword(pwd, note.getPassword())) {
                    // Auto-migrate plain text password to hash on successful unlock
                    if (!com.mknotes.app.util.PasswordHashUtil.isHashed(note.getPassword())) {
                        note.setPassword(com.mknotes.app.util.PasswordHashUtil.hashPassword(pwd));
                        repository.updateNote(note);
                    }
                    openEditor(note.getId());
                } else {
                    Toast.makeText(MainActivity.this, R.string.wrong_password, Toast.LENGTH_SHORT).show();
                }
            }
        });
        builder.setNegativeButton(R.string.cancel, null);
        builder.show();
    }

    /**
     * ISSUE 9: Drawer menu that slides from left side using AlertDialog
     * positioned at left with all navigation options including Archive and
     * the options previously in btnMore (Settings, Trash, Categories, Calendar Analysis).
     */
    private void showDrawerMenu() {
        // Build drawer content programmatically
        LinearLayout drawerLayout = new LinearLayout(this);
        drawerLayout.setOrientation(LinearLayout.VERTICAL);
        drawerLayout.setBackgroundColor(Color.parseColor("#1E1E1E"));
        drawerLayout.setPadding(0, 0, 0, 0);

        // Header
        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.VERTICAL);
        header.setBackgroundColor(Color.parseColor("#4A90D9"));
        header.setPadding(dpToPx(24), dpToPx(48), dpToPx(24), dpToPx(24));

        ImageView logo = new ImageView(this);
        logo.setImageResource(R.drawable.ic_launcher);
        LinearLayout.LayoutParams logoLp = new LinearLayout.LayoutParams(dpToPx(48), dpToPx(48));
        logoLp.bottomMargin = dpToPx(12);
        header.addView(logo, logoLp);

        TextView appName = new TextView(this);
        appName.setText(R.string.app_name);
        appName.setTextColor(Color.WHITE);
        appName.setTextSize(20);
        header.addView(appName);

        drawerLayout.addView(header);

        // Menu items
        String[] menuLabels = {
            getString(R.string.all_notes),
            getString(R.string.favorites),
            getString(R.string.archive_note),
            getString(R.string.title_categories),
            getString(R.string.title_trash),
            getString(R.string.analysis_title),
            getString(R.string.title_settings)
        };
        int[] menuIcons = {
            R.drawable.ic_note,
            R.drawable.ic_star_outline,
            R.drawable.ic_archive,
            R.drawable.ic_folder,
            R.drawable.ic_trash,
            R.drawable.ic_checklist,
            R.drawable.ic_settings
        };

        final AlertDialog.Builder dialogBuilder = new AlertDialog.Builder(this);

        for (int i = 0; i < menuLabels.length; i++) {
            final int index = i;
            TextView menuItem = new TextView(this);
            menuItem.setText(menuLabels[i]);
            menuItem.setTextColor(Color.WHITE);
            menuItem.setTextSize(15);
            menuItem.setGravity(Gravity.CENTER_VERTICAL);
            menuItem.setPadding(dpToPx(16), 0, dpToPx(16), 0);
            menuItem.setCompoundDrawablePadding(dpToPx(16));
            menuItem.setMinHeight(dpToPx(48));

            try {
                android.graphics.drawable.Drawable icon = getResources().getDrawable(menuIcons[i]);
                if (icon != null) {
                    icon.setBounds(0, 0, dpToPx(24), dpToPx(24));
                    icon.setTint(Color.parseColor("#AAAAAA"));
                    menuItem.setCompoundDrawables(icon, null, null, null);
                }
            } catch (Exception e) {
                // ignore
            }

            drawerLayout.addView(menuItem);

            // Add divider after Favorites and after Archive
            if (i == 1 || i == 2) {
                View divider = new View(this);
                divider.setBackgroundColor(Color.parseColor("#333333"));
                LinearLayout.LayoutParams divLp = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT, dpToPx(1));
                divLp.topMargin = dpToPx(8);
                divLp.bottomMargin = dpToPx(8);
                drawerLayout.addView(divider, divLp);
            }
        }

        // Create dialog
        final AlertDialog dialog = dialogBuilder.create();
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        dialog.setView(drawerLayout);
        dialog.show();

        // Position dialog on the left side
        Window window = dialog.getWindow();
        if (window != null) {
            window.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            WindowManager.LayoutParams wlp = window.getAttributes();
            wlp.gravity = Gravity.LEFT | Gravity.TOP;
            wlp.x = 0;
            wlp.y = 0;
            wlp.width = dpToPx(280);
            wlp.height = WindowManager.LayoutParams.MATCH_PARENT;
            window.setAttributes(wlp);
            window.setWindowAnimations(android.R.style.Animation_Translucent);
        }

        // Set click listeners for each menu item
        for (int i = 0; i < drawerLayout.getChildCount(); i++) {
            View child = drawerLayout.getChildAt(i);
            if (child instanceof TextView && ((TextView) child).getText().length() > 0) {
                final String label = ((TextView) child).getText().toString();
                child.setOnClickListener(new View.OnClickListener() {
                    public void onClick(View v) {
                        dialog.dismiss();
                        handleDrawerItemClick(label);
                    }
                });
            }
        }
    }

    private void handleDrawerItemClick(String label) {
        if (label.equals(getString(R.string.all_notes))) {
            prefs.setCurrentFilter(PrefsManager.FILTER_ALL);
            loadNotes();
            loadCategoryTabs();
        } else if (label.equals(getString(R.string.favorites))) {
            prefs.setCurrentFilter(PrefsManager.FILTER_FAVORITES);
            loadNotes();
            loadCategoryTabs();
        } else if (label.equals(getString(R.string.archive_note))) {
            startActivity(new Intent(MainActivity.this, ArchiveActivity.class));
        } else if (label.equals(getString(R.string.title_categories))) {
            startActivity(new Intent(MainActivity.this, CategoryActivity.class));
        } else if (label.equals(getString(R.string.title_trash))) {
            startActivity(new Intent(MainActivity.this, TrashActivity.class));
        } else if (label.equals(getString(R.string.analysis_title))) {
            startActivity(new Intent(MainActivity.this, CalendarAnalysisActivity.class));
        } else if (label.equals(getString(R.string.title_settings))) {
            startActivityForResult(new Intent(MainActivity.this, SettingsActivity.class), REQUEST_SETTINGS);
        }
    }

    private void toggleViewMode() {
        isGridView = !isGridView;
        if (isGridView) {
            prefs.setViewMode(PrefsManager.VIEW_GRID);
        } else {
            prefs.setViewMode(PrefsManager.VIEW_LIST);
        }
        applyViewMode();
        adapter.notifyDataSetChanged();
    }

    public void onBackPressed() {
        if (isSelectionMode) {
            exitSelectionMode();
        } else {
            super.onBackPressed();
        }
    }

    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_EDITOR || requestCode == REQUEST_SEARCH || requestCode == REQUEST_SETTINGS) {
            loadNotes();
            loadCategoryTabs();
        }
    }

    private int dpToPx(int dp) {
        float density = getResources().getDisplayMetrics().density;
        return (int) (dp * density + 0.5f);
    }
}
