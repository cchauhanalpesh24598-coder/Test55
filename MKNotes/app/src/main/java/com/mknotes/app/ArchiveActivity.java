package com.mknotes.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.Toast;

import com.mknotes.app.adapter.NoteAdapter;
import com.mknotes.app.cloud.CloudSyncManager;
import com.mknotes.app.cloud.FirebaseAuthManager;
import com.mknotes.app.db.NotesRepository;
import com.mknotes.app.model.Note;
import com.mknotes.app.util.PrefsManager;
import com.mknotes.app.util.SessionManager;

import java.util.List;

public class ArchiveActivity extends Activity {

    private ListView listArchive;
    private LinearLayout emptyArchiveState;

    private NoteAdapter adapter;
    private NotesRepository repository;

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_archive);

        repository = NotesRepository.getInstance(this);

        initViews();
        setupListeners();
        loadArchive();
    }

    private void initViews() {
        listArchive = (ListView) findViewById(R.id.list_archive);
        emptyArchiveState = (LinearLayout) findViewById(R.id.empty_archive_state);

        ImageButton btnBack = (ImageButton) findViewById(R.id.btn_archive_back);
        btnBack.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                finish();
            }
        });

        adapter = new NoteAdapter(this);
        listArchive.setAdapter(adapter);
    }

    private void setupListeners() {
        listArchive.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            public void onItemClick(AdapterView parent, View view, int position, long id) {
                Note note = (Note) adapter.getItem(position);
                showArchiveOptions(note);
            }
        });
    }

    private void loadArchive() {
        List archivedNotes = repository.getArchivedNotes();
        adapter.setNotes(archivedNotes);

        if (archivedNotes.isEmpty()) {
            emptyArchiveState.setVisibility(View.VISIBLE);
            listArchive.setVisibility(View.GONE);
        } else {
            emptyArchiveState.setVisibility(View.GONE);
            listArchive.setVisibility(View.VISIBLE);
        }
    }

    private void showArchiveOptions(final Note note) {
        String[] options = new String[]{
                getString(R.string.unarchive_note),
                getString(R.string.delete)
        };

        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(note.getTitle() != null && note.getTitle().length() > 0 ?
                note.getTitle() : getString(R.string.untitled));
        builder.setItems(options, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                switch (which) {
                    case 0:
                        repository.unarchiveNote(note.getId());
                        triggerCloudUpdateForNote(note.getId());
                        Toast.makeText(ArchiveActivity.this, R.string.note_unarchived, Toast.LENGTH_SHORT).show();
                        loadArchive();
                        break;
                    case 1:
                        confirmDeleteNote(note);
                        break;
                }
            }
        });
        builder.show();
    }

    private void confirmDeleteNote(final Note note) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.delete_note_title);
        builder.setMessage(R.string.delete_note_message);
        builder.setPositiveButton(R.string.delete, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                // Get cloudId before trashing (moveToTrash deletes from notes table)
                String cloudId = note.getCloudId();
                repository.moveToTrash(note);
                triggerCloudDeleteForNote(cloudId);
                Toast.makeText(ArchiveActivity.this, R.string.note_moved_to_trash, Toast.LENGTH_SHORT).show();
                loadArchive();
            }
        });
        builder.setNegativeButton(R.string.cancel, null);
        builder.show();
    }

    /**
     * Trigger cloud update after unarchive so other devices get updated archived=false.
     */
    private void triggerCloudUpdateForNote(long noteId) {
        try {
            if (!PrefsManager.getInstance(this).isCloudSyncEnabled()) return;
            if (!FirebaseAuthManager.getInstance(this).isLoggedIn()) return;
            if (!SessionManager.getInstance(this).isSessionValid()) return;

            CloudSyncManager.getInstance(this).uploadNote(noteId);
        } catch (Exception e) {
            // Cloud sync failure must not crash the app
        }
    }

    /**
     * Trigger cloud soft-delete when a note is moved to trash.
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
}
