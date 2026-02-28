package com.mknotes.app.routine;

import android.text.Editable;
import android.text.TextWatcher;
import android.widget.EditText;

/**
 * TextWatcher for the routine content EditText.
 * Detects exactly 4-digit sequences and converts them to formatted time strings.
 * 
 * Case 1: On a line with " - " (dash), digits after the dash become the end time.
 * Case 2: On a line without dash, digits become the start time and " - " is appended.
 * 
 * Maintains AM/PM state tracking across entries.
 * Pure Java, no lambda, no AndroidX. AIDE compatible.
 */
public class RoutineContentWatcher implements TextWatcher {

    private EditText editText;
    private boolean isProcessing;
    private boolean currentlyPm;

    public RoutineContentWatcher(EditText editText) {
        this.editText = editText;
        this.isProcessing = false;
        this.currentlyPm = false;
    }

    public boolean isCurrentlyPm() {
        return currentlyPm;
    }

    public void setCurrentlyPm(boolean pm) {
        this.currentlyPm = pm;
    }

    public void beforeTextChanged(CharSequence s, int start, int count, int after) {
        // no-op
    }

    public void onTextChanged(CharSequence s, int start, int before, int count) {
        // no-op
    }

    public void afterTextChanged(Editable s) {
        if (isProcessing) return;

        String text = s.toString();
        int cursorPos = editText.getSelectionStart();
        if (cursorPos <= 0) return;

        // Find the current line boundaries
        int lineStart = text.lastIndexOf('\n', cursorPos - 1);
        if (lineStart < 0) {
            lineStart = 0;
        } else {
            lineStart = lineStart + 1;
        }

        int lineEnd = text.indexOf('\n', cursorPos);
        if (lineEnd < 0) {
            lineEnd = text.length();
        }

        if (lineStart >= lineEnd) return;

        String currentLine = text.substring(lineStart, lineEnd);

        // Case 1: Line has a dash - check for end-time digits after the dash
        int dashIdx = currentLine.indexOf(" - ");
        if (dashIdx >= 0) {
            String afterDash = currentLine.substring(dashIdx + 3);

            // Check if afterDash ends with exactly 4 raw digits
            // The user may have typed text after, so check the tail
            String trimmed = afterDash.trim();
            
            // Only process if exactly 4 digits (no other characters)
            if (trimmed.matches("\\d{4}")) {
                String formatted = RoutineManager.parseDigitsToTime(trimmed, false, currentlyPm);
                if (formatted != null) {
                    // Update AM/PM state
                    if (formatted.contains("PM")) {
                        currentlyPm = true;
                    }

                    isProcessing = true;

                    // Find where the digits start in the full text
                    int digitsStartInLine = dashIdx + 3;
                    // Skip any leading spaces
                    while (digitsStartInLine < currentLine.length() 
                            && currentLine.charAt(digitsStartInLine) == ' ') {
                        digitsStartInLine++;
                    }
                    
                    int replaceStart = lineStart + digitsStartInLine;
                    int replaceEnd = replaceStart + trimmed.length();

                    if (replaceEnd <= s.length()) {
                        s.replace(replaceStart, replaceEnd, formatted);

                        int newCursorPos = replaceStart + formatted.length();
                        if (newCursorPos <= s.length()) {
                            editText.setSelection(newCursorPos);
                        }
                    }

                    isProcessing = false;
                    return;
                }
            }
            return;
        }

        // Case 2: Line has no dash - check for start-time digits
        String trimmedLine = currentLine.trim();
        if (trimmedLine.matches("\\d{4}")) {
            String formatted = RoutineManager.parseDigitsToTime(trimmedLine, false, currentlyPm);
            if (formatted != null) {
                if (formatted.contains("PM")) {
                    currentlyPm = true;
                }

                isProcessing = true;

                // Find the digit start position (may have leading spaces)
                int digitStart = lineStart;
                while (digitStart < lineEnd && text.charAt(digitStart) == ' ') {
                    digitStart++;
                }
                int digitEnd = digitStart + trimmedLine.length();

                String replacement = formatted + " - ";
                if (digitEnd <= s.length()) {
                    s.replace(digitStart, digitEnd, replacement);

                    int newCursorPos = digitStart + replacement.length();
                    if (newCursorPos <= s.length()) {
                        editText.setSelection(newCursorPos);
                    }
                }

                isProcessing = false;
            }
        }
    }

    /**
     * Detect the last end time from the full text content.
     * Scans from bottom up to find the most recent "HH:MM AM/PM" after a dash.
     */
    public String findLastEndTime() {
        String text = editText.getText().toString();
        String[] lines = text.split("\n");
        for (int i = lines.length - 1; i >= 0; i--) {
            String endTime = RoutineManager.extractLastEndTime(lines[i]);
            if (endTime != null) {
                return endTime;
            }
        }
        return null;
    }

    /**
     * Update the AM/PM state by scanning all existing entries.
     */
    public void syncAmPmState() {
        String text = editText.getText().toString();
        String[] lines = text.split("\n");
        currentlyPm = false;
        for (int i = 0; i < lines.length; i++) {
            String endTime = RoutineManager.extractLastEndTime(lines[i]);
            if (endTime != null && RoutineManager.isPmTime(endTime)) {
                currentlyPm = true;
            }
            // Also check start time on each line
            String line = lines[i].trim();
            if (line.length() >= 8) {
                String startTime = line.substring(0, 8);
                if (startTime.matches("\\d{2}:\\d{2} [AP]M")) {
                    if (RoutineManager.isPmTime(startTime)) {
                        currentlyPm = true;
                    }
                }
            }
        }
    }
}
