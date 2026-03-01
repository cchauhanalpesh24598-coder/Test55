package com.mknotes.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.CompoundButton;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.SeekBar;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import com.mknotes.app.cloud.CloudSyncManager;
import com.mknotes.app.cloud.FirebaseAuthManager;
import com.mknotes.app.crypto.KeyManager;
import com.mknotes.app.db.NotesRepository;
import com.mknotes.app.model.Note;
import com.mknotes.app.util.MKFileProvider;
import com.mknotes.app.util.NoteColorUtil;
import com.mknotes.app.util.PrefsManager;
import com.mknotes.app.util.SessionManager;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;

public class SettingsActivity extends Activity {

    private static final int REQUEST_RESTORE_FILE = 9001;

    private PrefsManager prefs;
    private NotesRepository repository;
    private RadioGroup rgSort;
    private RadioButton rbSortModified;
    private RadioButton rbSortCreated;
    private RadioButton rbSortTitle;
    private LinearLayout colorPickerSettings;
    private SeekBar seekbarFont;
    private TextView tvFontPreview;
    private Switch switchAutoSave;
    private Switch switchConfirmDelete;

    // Cloud Sync views
    private Switch switchCloudSync;
    private LinearLayout cloudAccountSection;
    private TextView tvCloudEmail;
    private TextView btnCloudLoginLogout;
    private LinearLayout btnCloudManualSync;
    private TextView tvSyncStatus;

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        prefs = PrefsManager.getInstance(this);
        repository = NotesRepository.getInstance(this);

        initViews();
        loadSettings();
        setupListeners();
    }

    protected void onResume() {
        super.onResume();
        // Refresh cloud sync UI when returning from Firebase login
        if (switchCloudSync != null) {
            switchCloudSync.setChecked(prefs.isCloudSyncEnabled());
            updateCloudAccountUI();
        }
    }

    private void initViews() {
        ImageButton btnBack = (ImageButton) findViewById(R.id.btn_settings_back);
        btnBack.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                finish();
            }
        });

        rgSort = (RadioGroup) findViewById(R.id.rg_sort);
        rbSortModified = (RadioButton) findViewById(R.id.rb_sort_modified);
        rbSortCreated = (RadioButton) findViewById(R.id.rb_sort_created);
        rbSortTitle = (RadioButton) findViewById(R.id.rb_sort_title);
        colorPickerSettings = (LinearLayout) findViewById(R.id.color_picker_settings);
        seekbarFont = (SeekBar) findViewById(R.id.seekbar_font);
        tvFontPreview = (TextView) findViewById(R.id.tv_font_preview);
        switchAutoSave = (Switch) findViewById(R.id.switch_auto_save);
        switchConfirmDelete = (Switch) findViewById(R.id.switch_confirm_delete);

        // Backup & Restore buttons
        TextView btnBackup = (TextView) findViewById(R.id.btn_backup);
        TextView btnRestore = (TextView) findViewById(R.id.btn_restore);

        btnBackup.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                performBackup();
            }
        });

        btnRestore.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showRestoreConfirmDialog();
            }
        });

        // Change Master Password button
        LinearLayout btnChangePassword = (LinearLayout) findViewById(R.id.btn_change_password);
        btnChangePassword.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showChangePasswordDialog();
            }
        });

        // Cloud Sync views
        switchCloudSync = (Switch) findViewById(R.id.switch_cloud_sync);
        cloudAccountSection = (LinearLayout) findViewById(R.id.cloud_account_section);
        tvCloudEmail = (TextView) findViewById(R.id.tv_cloud_email);
        btnCloudLoginLogout = (TextView) findViewById(R.id.btn_cloud_login_logout);
        btnCloudManualSync = (LinearLayout) findViewById(R.id.btn_cloud_manual_sync);
        tvSyncStatus = (TextView) findViewById(R.id.tv_sync_status);

        initCloudSyncSection();
    }

    private void loadSettings() {
        String sortBy = prefs.getSortBy();
        if (PrefsManager.SORT_CREATED.equals(sortBy)) {
            rbSortCreated.setChecked(true);
        } else if (PrefsManager.SORT_TITLE.equals(sortBy)) {
            rbSortTitle.setChecked(true);
        } else {
            rbSortModified.setChecked(true);
        }

        setupColorPicker();

        int fontSize = prefs.getFontSize();
        int progress = fontSize - 12;
        if (progress < 0) progress = 0;
        if (progress > 10) progress = 10;
        seekbarFont.setProgress(progress);
        tvFontPreview.setTextSize(fontSize);

        switchAutoSave.setChecked(prefs.isAutoSave());
        switchConfirmDelete.setChecked(prefs.isConfirmDelete());
    }

    private void setupColorPicker() {
        colorPickerSettings.removeAllViews();
        int[] colors = NoteColorUtil.getAllPresetColors();
        final int currentColor = prefs.getDefaultColor();

        for (int i = 0; i < colors.length; i++) {
            final int colorIndex = i;
            View colorView = new View(this);
            int size = 40;
            LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(size, size);
            params.setMargins(8, 0, 8, 0);
            colorView.setLayoutParams(params);

            GradientDrawable shape = new GradientDrawable();
            shape.setShape(GradientDrawable.OVAL);
            if (i == 0) {
                shape.setColor(Color.WHITE);
                shape.setStroke(2, Color.GRAY);
            } else {
                shape.setColor(colors[i]);
            }
            if (i == currentColor) {
                shape.setStroke(3, Color.BLACK);
            }
            colorView.setBackground(shape);

            colorView.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    prefs.setDefaultColor(colorIndex);
                    setupColorPicker();
                }
            });

            colorPickerSettings.addView(colorView);
        }
    }

    private void setupListeners() {
        rgSort.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
            public void onCheckedChanged(RadioGroup group, int checkedId) {
                if (checkedId == R.id.rb_sort_modified) {
                    prefs.setSortBy(PrefsManager.SORT_MODIFIED);
                } else if (checkedId == R.id.rb_sort_created) {
                    prefs.setSortBy(PrefsManager.SORT_CREATED);
                } else if (checkedId == R.id.rb_sort_title) {
                    prefs.setSortBy(PrefsManager.SORT_TITLE);
                }
            }
        });

        seekbarFont.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            public void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser) {
                int fontSize = progress + 12;
                prefs.setFontSize(fontSize);
                tvFontPreview.setTextSize(fontSize);
            }

            public void onStartTrackingTouch(SeekBar seekBar) {
            }

            public void onStopTrackingTouch(SeekBar seekBar) {
            }
        });

        switchAutoSave.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                prefs.setAutoSave(isChecked);
            }
        });

        switchConfirmDelete.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                prefs.setConfirmDelete(isChecked);
            }
        });
    }

    // ======================== CLOUD SYNC SETTINGS ========================

    /**
     * Initialize the Cloud Sync section: toggle, account info, login/logout, manual sync.
     * No lambdas, pure anonymous inner classes.
     */
    private void initCloudSyncSection() {
        final FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(this);
        boolean syncEnabled = prefs.isCloudSyncEnabled();

        switchCloudSync.setChecked(syncEnabled);
        updateCloudAccountUI();

        switchCloudSync.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isChecked) {
                    // If not logged in, redirect to Firebase login
                    if (!authManager.isLoggedIn()) {
                        switchCloudSync.setChecked(false);
                        Intent loginIntent = new Intent(SettingsActivity.this, FirebaseLoginActivity.class);
                        startActivity(loginIntent);
                        return;
                    }
                    prefs.setCloudSyncEnabled(true);
                } else {
                    prefs.setCloudSyncEnabled(false);
                }
                updateCloudAccountUI();
            }
        });

        btnCloudLoginLogout.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (authManager.isLoggedIn()) {
                    // Show logout confirmation
                    showCloudLogoutConfirmDialog();
                } else {
                    // Open login screen
                    Intent loginIntent = new Intent(SettingsActivity.this, FirebaseLoginActivity.class);
                    startActivity(loginIntent);
                }
            }
        });

        btnCloudManualSync.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                performManualSync();
            }
        });
    }

    /**
     * Update the Cloud Account section UI based on current auth state.
     */
    private void updateCloudAccountUI() {
        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(this);
        boolean syncEnabled = prefs.isCloudSyncEnabled();

        if (syncEnabled) {
            cloudAccountSection.setVisibility(View.VISIBLE);
        } else {
            cloudAccountSection.setVisibility(View.GONE);
        }

        if (authManager.isLoggedIn()) {
            String email = authManager.getStoredEmail();
            if (email != null && email.length() > 0) {
                tvCloudEmail.setText(email);
            } else {
                tvCloudEmail.setText(getString(R.string.cloud_sync_account));
            }
            btnCloudLoginLogout.setText(R.string.cloud_sync_logout);
        } else {
            tvCloudEmail.setText(R.string.cloud_sync_not_logged_in);
            btnCloudLoginLogout.setText(R.string.cloud_sync_login);
        }
    }

    /**
     * Show logout confirmation dialog.
     */
    private void showCloudLogoutConfirmDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.cloud_sync_logout_confirm_title);
        builder.setMessage(R.string.cloud_sync_logout_confirm_message);
        builder.setPositiveButton(R.string.cloud_sync_logout, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                FirebaseAuthManager.getInstance(SettingsActivity.this).logout();
                prefs.setCloudSyncEnabled(false);
                switchCloudSync.setChecked(false);
                updateCloudAccountUI();
                Toast.makeText(SettingsActivity.this, R.string.cloud_sync_logged_out, Toast.LENGTH_SHORT).show();
            }
        });
        builder.setNegativeButton(R.string.btn_cancel, null);
        builder.show();
    }

    /**
     * Perform manual bidirectional sync with cloud.
     */
    private void performManualSync() {
        if (!prefs.isCloudSyncEnabled()) {
            Toast.makeText(this, R.string.cloud_sync_not_logged_in, Toast.LENGTH_SHORT).show();
            return;
        }
        if (!FirebaseAuthManager.getInstance(this).isLoggedIn()) {
            Toast.makeText(this, R.string.cloud_sync_not_logged_in, Toast.LENGTH_SHORT).show();
            return;
        }
        if (!SessionManager.getInstance(this).isSessionValid()) {
            return;
        }

        tvSyncStatus.setText(R.string.cloud_sync_syncing);

        CloudSyncManager.getInstance(this).syncOnAppStart(new CloudSyncManager.SyncCallback() {
            public void onSyncComplete(final boolean success) {
                runOnUiThread(new Runnable() {
                    public void run() {
                        if (success) {
                            tvSyncStatus.setText(R.string.cloud_sync_success);
                        } else {
                            tvSyncStatus.setText(R.string.cloud_sync_failed);
                        }
                    }
                });
            }
        });
    }

    // ======================== CHANGE PASSWORD ========================

    /**
     * Show a dialog with 3 fields: current password, new password, confirm new password.
     * Uses programmatic LinearLayout to avoid adding another XML layout file.
     */
    private void showChangePasswordDialog() {
        final SessionManager sessionManager = SessionManager.getInstance(this);

        if (!sessionManager.isPasswordSet()) {
            Toast.makeText(this, R.string.master_password_error_generic, Toast.LENGTH_SHORT).show();
            return;
        }

        // Build layout programmatically
        LinearLayout container = new LinearLayout(this);
        container.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (20 * getResources().getDisplayMetrics().density);
        container.setPadding(pad, pad, pad, 0);

        final android.widget.EditText editOld = new android.widget.EditText(this);
        editOld.setHint(R.string.master_password_old_hint);
        editOld.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        editOld.setSingleLine(true);
        container.addView(editOld);

        final android.widget.EditText editNew = new android.widget.EditText(this);
        editNew.setHint(R.string.master_password_new_hint);
        editNew.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        editNew.setSingleLine(true);
        LinearLayout.LayoutParams newParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        int topMargin = (int) (12 * getResources().getDisplayMetrics().density);
        newParams.topMargin = topMargin;
        editNew.setLayoutParams(newParams);
        container.addView(editNew);

        final android.widget.EditText editConfirm = new android.widget.EditText(this);
        editConfirm.setHint(R.string.master_password_new_confirm_hint);
        editConfirm.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        editConfirm.setSingleLine(true);
        LinearLayout.LayoutParams confirmParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        confirmParams.topMargin = topMargin;
        editConfirm.setLayoutParams(confirmParams);
        container.addView(editConfirm);

        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.master_password_change);
        builder.setView(container);
        builder.setPositiveButton(R.string.btn_save, null); // set null, override below
        builder.setNegativeButton(R.string.btn_cancel, null);

        final AlertDialog dialog = builder.create();
        dialog.show();

        // Override positive button to prevent dismiss on validation failure
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                final String oldPwd = editOld.getText().toString();
                final String newPwd = editNew.getText().toString();
                String confirmPwd = editConfirm.getText().toString();

                // Validate new password length
                if (newPwd.length() < 8) {
                    Toast.makeText(SettingsActivity.this,
                            R.string.master_password_error_short, Toast.LENGTH_SHORT).show();
                    return;
                }

                // Validate match
                if (!newPwd.equals(confirmPwd)) {
                    Toast.makeText(SettingsActivity.this,
                            R.string.master_password_error_mismatch, Toast.LENGTH_SHORT).show();
                    return;
                }

                // Use KeyManager.changePassword -- re-wraps DEK, does NOT re-encrypt notes
                final KeyManager km = KeyManager.getInstance(SettingsActivity.this);
                km.changePassword(oldPwd, newPwd, new KeyManager.VaultCallback() {
                    public void onSuccess() {
                        runOnUiThread(new Runnable() {
                            public void run() {
                                // Upload updated vault metadata to Firestore
                                try {
                                    if (PrefsManager.getInstance(SettingsActivity.this).isCloudSyncEnabled()
                                            && FirebaseAuthManager.getInstance(SettingsActivity.this).isLoggedIn()) {
                                        km.uploadVaultToFirestore();
                                    }
                                } catch (Exception e) {
                                    // Cloud sync failure must not crash the app
                                }

                                Toast.makeText(SettingsActivity.this,
                                        R.string.master_password_changed_success, Toast.LENGTH_SHORT).show();
                                dialog.dismiss();
                            }
                        });
                    }

                    public void onError(final String error) {
                        runOnUiThread(new Runnable() {
                            public void run() {
                                if (error != null && error.contains("Old password")) {
                                    Toast.makeText(SettingsActivity.this,
                                            R.string.master_password_old_wrong, Toast.LENGTH_SHORT).show();
                                } else {
                                    Toast.makeText(SettingsActivity.this,
                                            R.string.master_password_error_generic, Toast.LENGTH_SHORT).show();
                                }
                            }
                        });
                    }
                });
            }
        });
    }

    // ======================== BACKUP ========================

    /**
     * ISSUE 6: Backup all notes to a JSON file in cache directory,
     * then share it via Intent so user can save/send the file.
     * Uses org.json (built into Android) - no external libraries.
     *
     * IMPORTANT: Backup exports encrypted data as-is. No decryption
     * is performed before export, ensuring backup files contain no plaintext.
     * Restore requires the same master password to decrypt.
     */
    private void performBackup() {
        try {
            List allNotes = repository.getAllNotesRaw();
            JSONArray jsonArray = new JSONArray();

            for (int i = 0; i < allNotes.size(); i++) {
                Note note = (Note) allNotes.get(i);
                JSONObject obj = new JSONObject();
                obj.put("id", note.getId());
                obj.put("title", note.getTitle() != null ? note.getTitle() : "");
                obj.put("content", note.getContent() != null ? note.getContent() : "");
                obj.put("createdAt", note.getCreatedAt());
                obj.put("modifiedAt", note.getModifiedAt());
                obj.put("color", note.getColor());
                obj.put("favorite", note.isFavorite());
                obj.put("locked", note.isLocked());
                obj.put("password", note.getPassword() != null ? note.getPassword() : "");
                obj.put("categoryId", note.getCategoryId());
                obj.put("hasChecklist", note.hasChecklist());
                obj.put("hasImage", note.hasImage());
                obj.put("checklistData", note.getChecklistData() != null ? note.getChecklistData() : "");
                obj.put("isChecklistMode", note.isChecklistMode());
                obj.put("imagesData", note.getImagesData() != null ? note.getImagesData() : "");
                obj.put("filesData", note.getFilesData() != null ? note.getFilesData() : "");
                obj.put("audiosData", note.getAudiosData() != null ? note.getAudiosData() : "");
                obj.put("linkedNoteIds", note.getLinkedNoteIds() != null ? note.getLinkedNoteIds() : "");
                obj.put("isRoutineMode", note.isRoutineMode());
                obj.put("routineData", note.getRoutineData() != null ? note.getRoutineData() : "");
                obj.put("archived", note.isArchived());
                obj.put("cloudId", note.getCloudId() != null ? note.getCloudId() : "");
                obj.put("encrypted", true);
                jsonArray.put(obj);
            }

            JSONObject root = new JSONObject();
            root.put("appName", "MKNotes");
            root.put("version", 1);
            root.put("encryptionVersion", 2);
            root.put("backupDate", System.currentTimeMillis());
            root.put("notesCount", allNotes.size());
            root.put("notes", jsonArray);

            // Include vault metadata for fresh device restore (v2 system)
            KeyManager km = KeyManager.getInstance(this);
            String salt = km.getLocalSalt();
            String encDEK = km.getLocalEncryptedDEK();
            String verifyTag = km.getLocalVerifyTag();
            String vaultIV = km.getLocalIV();
            int iterations = km.getIterations();
            if (salt != null && salt.length() > 0) {
                root.put("salt", salt);
            }
            if (encDEK != null && encDEK.length() > 0) {
                root.put("encryptedDEK", encDEK);
            }
            if (verifyTag != null && verifyTag.length() > 0) {
                root.put("verifyTag", verifyTag);
            }
            if (vaultIV != null && vaultIV.length() > 0) {
                root.put("vaultIV", vaultIV);
            }
            root.put("iterations", iterations);
            root.put("keyVersion", 1);

            String jsonStr = root.toString(2);

            // Write to cache
            File cacheDir = getCacheDir();
            File backupDir = new File(cacheDir, "backups");
            if (!backupDir.exists()) {
                backupDir.mkdirs();
            }
            File backupFile = new File(backupDir, "mknotes_backup.json");

            FileOutputStream fos = new FileOutputStream(backupFile);
            fos.write(jsonStr.getBytes("UTF-8"));
            fos.flush();
            fos.close();

            // Share via Intent
            Uri contentUri = MKFileProvider.getUriForFile(backupFile);
            Intent shareIntent = new Intent(Intent.ACTION_SEND);
            shareIntent.setType("application/json");
            shareIntent.putExtra(Intent.EXTRA_STREAM, contentUri);
            shareIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(shareIntent, getString(R.string.settings_backup)));

            Toast.makeText(this, R.string.backup_success, Toast.LENGTH_SHORT).show();

        } catch (Exception e) {
            Toast.makeText(this, getString(R.string.backup_failed) + ": " + e.getMessage(),
                    Toast.LENGTH_SHORT).show();
        }
    }

    // ======================== RESTORE ========================

    /**
     * Show confirmation dialog before restoring.
     */
    private void showRestoreConfirmDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.restore_confirm_title);
        builder.setMessage(R.string.restore_confirm_message);
        builder.setPositiveButton(R.string.btn_ok, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                openFilePicker();
            }
        });
        builder.setNegativeButton(R.string.btn_cancel, null);
        builder.show();
    }

    /**
     * Open a file picker to let user select the backup JSON file.
     */
    private void openFilePicker() {
        try {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("*/*");
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            startActivityForResult(Intent.createChooser(intent, getString(R.string.settings_restore_backup)),
                    REQUEST_RESTORE_FILE);
        } catch (Exception e) {
            // If no file picker available, try to restore from default backup location
            restoreFromDefaultBackup();
        }
    }

    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == REQUEST_RESTORE_FILE && resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            if (uri != null) {
                restoreFromUri(uri);
            }
        }
    }

    /**
     * Restore notes from a content URI (file picker result).
     */
    private void restoreFromUri(Uri uri) {
        try {
            InputStream is = getContentResolver().openInputStream(uri);
            if (is == null) {
                Toast.makeText(this, R.string.restore_failed, Toast.LENGTH_SHORT).show();
                return;
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            reader.close();
            is.close();

            performRestore(sb.toString());

        } catch (Exception e) {
            Toast.makeText(this, getString(R.string.restore_failed) + ": " + e.getMessage(),
                    Toast.LENGTH_SHORT).show();
        }
    }

    /**
     * Fallback: restore from the default backup file in cache.
     */
    private void restoreFromDefaultBackup() {
        try {
            File cacheDir = getCacheDir();
            File backupFile = new File(cacheDir, "backups/mknotes_backup.json");
            if (!backupFile.exists()) {
                Toast.makeText(this, R.string.no_backup_found, Toast.LENGTH_SHORT).show();
                return;
            }

            java.io.FileInputStream fis = new java.io.FileInputStream(backupFile);
            BufferedReader reader = new BufferedReader(new InputStreamReader(fis, "UTF-8"));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            reader.close();
            fis.close();

            performRestore(sb.toString());

        } catch (Exception e) {
            Toast.makeText(this, getString(R.string.restore_failed) + ": " + e.getMessage(),
                    Toast.LENGTH_SHORT).show();
        }
    }

    /**
     * Parse JSON string and insert all notes into the database.
     * Existing notes are NOT deleted - backup notes are added alongside them.
     *
     * Backup data is encrypted -- we insert it as raw encrypted values
     * using insertNoteRaw() to avoid double-encryption.
     */
    private void performRestore(String jsonString) {
        try {
            JSONObject root = new JSONObject(jsonString);

            // Validate it is a MKNotes backup
            String appName = root.optString("appName", "");
            if (!"MKNotes".equals(appName)) {
                Toast.makeText(this, R.string.restore_failed, Toast.LENGTH_SHORT).show();
                return;
            }

            JSONArray notesArray = root.getJSONArray("notes");
            int restoredCount = 0;
            boolean isEncryptedBackup = false;

            // Restore v2 vault metadata from backup if on fresh device
            String backupSalt = root.optString("salt", "");
            String backupEncDEK = root.optString("encryptedDEK", "");
            String backupVerifyTag = root.optString("verifyTag", "");
            String backupVaultIV = root.optString("vaultIV", "");
            int backupIterations = root.optInt("iterations", 0);
            if (backupSalt.length() > 0 && backupEncDEK.length() > 0
                    && backupVerifyTag.length() > 0 && backupVaultIV.length() > 0
                    && backupIterations > 0) {
                KeyManager km = KeyManager.getInstance(this);
                if (!km.isVaultInitialized()) {
                    // Fresh device -- restore vault metadata from backup.
                    // User MUST enter the SAME master password from original device.
                    km.restoreVaultFromBackup(backupSalt, backupEncDEK,
                            backupVaultIV, backupVerifyTag, backupIterations);
                }
            }

            for (int i = 0; i < notesArray.length(); i++) {
                JSONObject obj = notesArray.getJSONObject(i);

                // Check if this backup contains encrypted data
                if (i == 0) {
                    isEncryptedBackup = obj.optBoolean("encrypted", false);
                }

                Note note = new Note();
                note.setTitle(obj.optString("title", ""));
                note.setContent(obj.optString("content", ""));
                note.setCreatedAt(obj.optLong("createdAt", System.currentTimeMillis()));
                note.setModifiedAt(obj.optLong("modifiedAt", System.currentTimeMillis()));
                note.setColor(obj.optInt("color", 0));
                note.setFavorite(obj.optBoolean("favorite", false));
                note.setLocked(obj.optBoolean("locked", false));
                note.setPassword(obj.optString("password", ""));
                note.setCategoryId(obj.optLong("categoryId", -1));
                note.setHasChecklist(obj.optBoolean("hasChecklist", false));
                note.setHasImage(obj.optBoolean("hasImage", false));
                note.setChecklistData(obj.optString("checklistData", ""));
                note.setChecklistMode(obj.optBoolean("isChecklistMode", false));
                note.setImagesData(obj.optString("imagesData", ""));
                note.setFilesData(obj.optString("filesData", ""));
                note.setAudiosData(obj.optString("audiosData", ""));
                note.setLinkedNoteIds(obj.optString("linkedNoteIds", ""));
                note.setRoutineMode(obj.optBoolean("isRoutineMode", false));
                note.setRoutineData(obj.optString("routineData", ""));
                note.setArchived(obj.optBoolean("archived", false));

                // Preserve cloudId from backup if present, otherwise a new UUID is generated on insert
                String backupCloudId = obj.optString("cloudId", "");
                if (backupCloudId.length() > 0) {
                    note.setCloudId(backupCloudId);
                }

                long newId;
                if (isEncryptedBackup) {
                    // Data is already encrypted -- insert raw to avoid double-encryption
                    newId = repository.insertNoteRaw(note);
                } else {
                    // Legacy unencrypted backup -- insert normally (will encrypt)
                    newId = repository.insertNote(note);
                }
                if (newId > 0) {
                    restoredCount++;
                }
            }

            Toast.makeText(this, getString(R.string.restore_success) + " (" + restoredCount + " notes)",
                    Toast.LENGTH_SHORT).show();

            // Trigger cloud sync after restore so restored notes get uploaded
            try {
                if (PrefsManager.getInstance(this).isCloudSyncEnabled()
                        && FirebaseAuthManager.getInstance(this).isLoggedIn()
                        && SessionManager.getInstance(this).isSessionValid()) {
                    CloudSyncManager.getInstance(this).syncOnAppStart(new CloudSyncManager.SyncCallback() {
                        public void onSyncComplete(boolean success) {
                            // Sync done silently after restore
                        }
                    });
                }
            } catch (Exception e) {
                // Cloud sync failure must not crash the app
            }

        } catch (Exception e) {
            Toast.makeText(this, getString(R.string.restore_failed) + ": " + e.getMessage(),
                    Toast.LENGTH_SHORT).show();
        }
    }
}
