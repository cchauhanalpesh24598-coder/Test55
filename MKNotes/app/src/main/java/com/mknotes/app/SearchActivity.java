package com.mknotes.app;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.AdapterView;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.RelativeLayout;
import android.widget.TextView;

import com.mknotes.app.adapter.NoteAdapter;
import com.mknotes.app.db.NotesRepository;
import com.mknotes.app.model.Note;
import com.mknotes.app.util.SessionManager;

import java.util.ArrayList;
import java.util.List;

/**
 * SearchActivity - Replicates SearchScreenTopBar.kt behavior.
 * Rounded search bar with back arrow, auto-focus, clear button,
 * matching the TopBarBackgroundColor and rounded shape from Kotlin.
 */
public class SearchActivity extends Activity {

    private EditText etSearch;
    private ImageButton btnBack;
    private ImageButton btnClear;
    private ListView listResults;
    private LinearLayout noResults;
    private RelativeLayout searchToolbar;

    private NoteAdapter adapter;
    private NotesRepository repository;

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_search);

        repository = NotesRepository.getInstance(this);

        initViews();
        styleSearchTopBar();
        setupListeners();

        // Auto-focus and show keyboard (like SearchScreenTopBar.kt LaunchedEffect + focusRequester)
        etSearch.requestFocus();
        etSearch.postDelayed(new Runnable() {
            public void run() {
                showKeyboard();
            }
        }, 200);
    }

    private void initViews() {
        etSearch = (EditText) findViewById(R.id.et_search);
        btnBack = (ImageButton) findViewById(R.id.btn_search_back);
        btnClear = (ImageButton) findViewById(R.id.btn_clear_search);
        listResults = (ListView) findViewById(R.id.list_search_results);
        noResults = (LinearLayout) findViewById(R.id.no_results);

        // Get the toolbar container (parent of back button)
        if (btnBack != null && btnBack.getParent() instanceof RelativeLayout) {
            searchToolbar = (RelativeLayout) btnBack.getParent();
        }

        adapter = new NoteAdapter(this);
        listResults.setAdapter(adapter);
    }

    /**
     * Style the search toolbar to match SearchScreenTopBar.kt.
     * Rounded corners, TopBarBackgroundColor, white icons, proper padding.
     */
    private void styleSearchTopBar() {
        if (searchToolbar == null) return;

        // Create rounded background matching Kotlin TopBarBackgroundColor
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(Color.parseColor("#323335"));
        bg.setCornerRadius(dpToPx(50));
        searchToolbar.setBackground(bg);

        // Add margin like SearchScreenTopBar.kt (padding horizontal=16dp, vertical=8dp)
        ViewGroup parent = (ViewGroup) searchToolbar.getParent();
        if (parent != null) {
            ViewGroup.MarginLayoutParams mlp;
            if (searchToolbar.getLayoutParams() instanceof ViewGroup.MarginLayoutParams) {
                mlp = (ViewGroup.MarginLayoutParams) searchToolbar.getLayoutParams();
            } else {
                mlp = new ViewGroup.MarginLayoutParams(searchToolbar.getLayoutParams());
            }
            mlp.leftMargin = dpToPx(16);
            mlp.rightMargin = dpToPx(16);
            mlp.topMargin = dpToPx(8);
            mlp.bottomMargin = dpToPx(8);
            searchToolbar.setLayoutParams(mlp);
        }

        // Remove elevation (like SearchScreenTopBar.kt elevation=0.dp)
        searchToolbar.setElevation(0);

        // Style the search input
        if (etSearch != null) {
            etSearch.setTextColor(Color.WHITE);
            etSearch.setHintTextColor(Color.parseColor("#808080"));
            etSearch.setHint(R.string.search_your_notes);
            etSearch.setTextSize(18);
            // Make background transparent since parent has the rounded bg
            etSearch.setBackgroundColor(Color.TRANSPARENT);
        }

        // White tint for icons
        if (btnBack != null) btnBack.setColorFilter(Color.WHITE);
        if (btnClear != null) btnClear.setColorFilter(Color.WHITE);
    }

    private void setupListeners() {
        btnBack.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                hideKeyboard();
                finish();
            }
        });

        // Clear button - clears text and calls onClearQuery equivalent
        btnClear.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                etSearch.setText("");
                btnClear.setVisibility(View.GONE);
            }
        });

        // Text watcher - matches onQueryChanged callback from Kotlin
        etSearch.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                String query = s.toString().trim();
                if (query.length() > 0) {
                    btnClear.setVisibility(View.VISIBLE);
                    performSearch(query);
                } else {
                    btnClear.setVisibility(View.GONE);
                    adapter.setNotes(new ArrayList());
                    noResults.setVisibility(View.GONE);
                    listResults.setVisibility(View.VISIBLE);
                }
            }
        });

        // IME Done action (matches KeyboardActions onDone from Kotlin)
        etSearch.setOnEditorActionListener(new TextView.OnEditorActionListener() {
            public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
                if (actionId == EditorInfo.IME_ACTION_SEARCH ||
                    actionId == EditorInfo.IME_ACTION_DONE) {
                    String query = etSearch.getText().toString().trim();
                    if (query.length() > 0) {
                        performSearch(query);
                    }
                    hideKeyboard();
                    return true;
                }
                return false;
            }
        });

        listResults.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            public void onItemClick(AdapterView parent, View view, int position, long id) {
                Note note = (Note) adapter.getItem(position);
                Intent intent = new Intent(SearchActivity.this, NoteEditorActivity.class);
                intent.putExtra("note_id", note.getId());
                startActivity(intent);
            }
        });
    }

    private void performSearch(String query) {
        List results = repository.searchNotes(query);
        adapter.setNotes(results);

        if (results.isEmpty()) {
            noResults.setVisibility(View.VISIBLE);
            listResults.setVisibility(View.GONE);
        } else {
            noResults.setVisibility(View.GONE);
            listResults.setVisibility(View.VISIBLE);
        }
    }

    /**
     * Show keyboard programmatically - matches LaunchedEffect focusRequester from Kotlin.
     */
    private void showKeyboard() {
        InputMethodManager imm = (InputMethodManager) getSystemService(INPUT_METHOD_SERVICE);
        if (imm != null && etSearch != null) {
            imm.showSoftInput(etSearch, InputMethodManager.SHOW_IMPLICIT);
        }
    }

    /**
     * Hide keyboard - matches DisposableEffect onDispose cleanup from Kotlin.
     */
    private void hideKeyboard() {
        InputMethodManager imm = (InputMethodManager) getSystemService(INPUT_METHOD_SERVICE);
        if (imm != null && etSearch != null) {
            imm.hideSoftInputFromWindow(etSearch.getWindowToken(), 0);
        }
    }

    protected void onPause() {
        super.onPause();
        hideKeyboard();
    }

    public void onBackPressed() {
        hideKeyboard();
        finish();
    }

    private int dpToPx(int dp) {
        float density = getResources().getDisplayMetrics().density;
        return (int) (dp * density + 0.5f);
    }
}
