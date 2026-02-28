package com.mknotes.app.routine;

import android.text.Editable;
import android.text.TextWatcher;
import android.widget.EditText;

/**
 * TextWatcher for Wake/Sleep time fields in Routine mode.
 * Auto-formats raw 4-digit input (e.g. "0645") into "06:45 AM".
 * Wake field defaults to AM, Sleep field defaults to PM.
 * 
 * Pure Java, no lambda, no AndroidX. AIDE compatible.
 */
public class RoutineTimeWatcher implements TextWatcher {

    private EditText editText;
    private boolean defaultPm;
    private boolean isProcessing;

    /**
     * @param editText  the EditText to watch
     * @param defaultPm if true, default AM/PM is PM (for sleep field)
     */
    public RoutineTimeWatcher(EditText editText, boolean defaultPm) {
        this.editText = editText;
        this.defaultPm = defaultPm;
        this.isProcessing = false;
    }

    public void beforeTextChanged(CharSequence s, int start, int count, int after) {
        // no-op
    }

    public void onTextChanged(CharSequence s, int start, int before, int count) {
        // no-op
    }

    public void afterTextChanged(Editable s) {
        if (isProcessing) return;

        String text = s.toString().trim();

        // If already formatted (contains : or AM/PM), don't reformat
        if (text.contains(":") || text.contains("AM") || text.contains("PM")) {
            return;
        }

        // Only accept exactly 4 raw digits
        if (!text.matches("\\d{4}")) {
            return;
        }

        // For Wake field: defaultPm=false, currentlyPm=false -> AM default
        // For Sleep field: defaultPm=true, currentlyPm=true -> PM default
        String formatted = RoutineManager.parseDigitsToTime(text, defaultPm, defaultPm);
        if (formatted == null) return;

        isProcessing = true;
        editText.setText(formatted);
        editText.setSelection(formatted.length());
        isProcessing = false;
    }
}
