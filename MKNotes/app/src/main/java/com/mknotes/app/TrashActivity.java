package com.mknotes.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
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

public class TrashActivity extends Activity {

    private ListView listTrash;
    private LinearLayout emptyTrashState;
    private ImageButton btnEmptyTrash;

    private NoteAdapter adapter;
    private NotesRepository repository;

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_trash);

        repository = NotesRepository.getInstance(this);

        initViews();
        setupListeners();
        loadTrash();
    }

    private void initViews() {
        listTrash = (ListView) findViewById(R.id.list_trash);
        emptyTrashState = (LinearLayout) findViewById(R.id.empty_trash_state);
        btnEmptyTrash = (ImageButton) findViewById(R.id.btn_empty_trash);

        ImageButton btnBack = (ImageButton) findViewById(R.id.btn_trash_back);
        btnBack.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                finish();
            }
        });

        adapter = new NoteAdapter(this);
        listTrash.setAdapter(adapter);
    }

    private void setupListeners() {
        btnEmptyTrash.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                confirmEmptyTrash();
            }
        });

        listTrash.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            public void onItemClick(AdapterView parent, View view, int position, long id) {
                Note note = (Note) adapter.getItem(position);
                showTrashOptions(note);
            }
        });
    }

    private void loadTrash() {
        List trashNotes = repository.getTrashNotes();
        adapter.setNotes(trashNotes);

        if (trashNotes.isEmpty()) {
            emptyTrashState.setVisibility(View.VISIBLE);
            listTrash.setVisibility(View.GONE);
            btnEmptyTrash.setVisibility(View.GONE);
        } else {
            emptyTrashState.setVisibility(View.GONE);
            listTrash.setVisibility(View.VISIBLE);
            btnEmptyTrash.setVisibility(View.VISIBLE);
        }
    }

    private void showTrashOptions(final Note note) {
        String[] options = new String[]{
                getString(R.string.restore),
                getString(R.string.delete_permanently)
        };

        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(note.getTitle() != null && note.getTitle().length() > 0 ?
                note.getTitle() : getString(R.string.untitled));
        builder.setItems(options, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                switch (which) {
                    case 0:
                        repository.restoreFromTrash(note.getId());
                        // After restore, the note gets a new local ID via insertNote.
                        // syncOnAppStart on next resume will handle uploading it to cloud.
                        Toast.makeText(TrashActivity.this, R.string.note_restored, Toast.LENGTH_SHORT).show();
                        loadTrash();
                        // Trigger sync so restored note appears in cloud
                        triggerCloudSyncAfterRestore();
                        break;
                    case 1:
                        confirmDeletePermanently(note);
                        break;
                }
            }
        });
        builder.show();
    }

    private void confirmDeletePermanently(final Note note) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.delete_permanently_title);
        builder.setMessage(R.string.delete_permanently_message);
        builder.setPositiveButton(R.string.delete, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                repository.deleteFromTrash(note.getId());
                Toast.makeText(TrashActivity.this, R.string.note_deleted, Toast.LENGTH_SHORT).show();
                loadTrash();
            }
        });
        builder.setNegativeButton(R.string.cancel, null);
        builder.show();
    }

    private void confirmEmptyTrash() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.empty_trash_title);
        builder.setMessage(R.string.empty_trash_message);
        builder.setPositiveButton(R.string.btn_empty_trash, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                repository.emptyTrash();
                Toast.makeText(TrashActivity.this, R.string.trash_emptied, Toast.LENGTH_SHORT).show();
                loadTrash();
            }
        });
        builder.setNegativeButton(R.string.cancel, null);
        builder.show();
    }

    /**
     * Trigger cloud sync upload for a restored note.
     * When a note is restored from trash, we need to re-upload it to cloud
     * (or update isDeleted=false) so other devices get it back.
     * Uses syncOnAppStart to handle the upload since the note gets a new local ID.
     */
    private void triggerCloudSyncAfterRestore() {
        try {
            if (!PrefsManager.getInstance(this).isCloudSyncEnabled()) return;
            if (!FirebaseAuthManager.getInstance(this).isLoggedIn()) return;
            if (!SessionManager.getInstance(this).isSessionValid()) return;

            CloudSyncManager.getInstance(this).syncOnAppStart(new CloudSyncManager.SyncCallback() {
                public void onSyncComplete(boolean success) {
                    // Sync done silently
                }
            });
        } catch (Exception e) {
            // Cloud sync failure must not crash the app
        }
    }
}
