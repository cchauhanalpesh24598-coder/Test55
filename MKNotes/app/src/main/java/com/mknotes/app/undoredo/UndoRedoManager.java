package com.mknotes.app.undoredo;

import android.os.Bundle;
import android.text.Editable;
import android.text.SpannableStringBuilder;
import android.text.Spannable;
import android.text.style.AlignmentSpan;
import android.text.style.BackgroundColorSpan;
import android.text.style.BulletSpan;
import android.text.style.ForegroundColorSpan;
import android.text.style.RelativeSizeSpan;
import android.text.style.StrikethroughSpan;
import android.text.style.StyleSpan;
import android.text.style.TypefaceSpan;
import android.text.style.URLSpan;
import android.text.style.UnderlineSpan;
import android.widget.EditText;

import java.util.ArrayList;
import java.util.List;

/**
 * UndoRedoManager - Centralized word-based undo/redo system.
 * 
 * Snapshots are pushed when:
 * - User types a space (word boundary)
 * - User types a newline
 * - User types punctuation (. , ! ? ; :)
 * - User pastes text
 * - User applies formatting (bold, italic, underline, etc.)
 * - User adds/removes sticky notes, mood, routine entries, meditation entries
 * 
 * Each snapshot stores the full SpannableStringBuilder (text + spans)
 * and cursor position. Duplicate consecutive states are skipped.
 * Max stack size is enforced to prevent memory leaks.
 * 
 * Pure Java, no AndroidX, no lambda expressions.
 */
public class UndoRedoManager {

    private static final int MAX_STACK_SIZE = 50;

    private List undoStack;
    private List redoStack;
    private boolean isPerformingUndoRedo;
    private UndoRedoListener listener;

    /**
     * Listener for undo/redo state changes.
     */
    public interface UndoRedoListener {
        void onUndoRedoStateChanged(boolean canUndo, boolean canRedo);
    }

    /**
     * Represents a single snapshot of editor state.
     */
    public static class EditorSnapshot {
        private SpannableStringBuilder content;
        private int cursorPosition;

        public EditorSnapshot(CharSequence text, int cursor) {
            this.content = cloneSpannable(text);
            this.cursorPosition = cursor;
        }

        public SpannableStringBuilder getContent() {
            return content;
        }

        public int getCursorPosition() {
            return cursorPosition;
        }

        /**
         * Deep clone a CharSequence preserving all spans.
         */
        private static SpannableStringBuilder cloneSpannable(CharSequence source) {
            if (source == null) {
                return new SpannableStringBuilder("");
            }
            SpannableStringBuilder clone = new SpannableStringBuilder(source.toString());

            if (source instanceof Spannable) {
                Spannable spannable = (Spannable) source;
                Object[] spans = spannable.getSpans(0, source.length(), Object.class);
                for (int i = 0; i < spans.length; i++) {
                    Object span = spans[i];
                    int start = spannable.getSpanStart(span);
                    int end = spannable.getSpanEnd(span);
                    int flags = spannable.getSpanFlags(span);

                    // Clone each span type to avoid shared references
                    Object clonedSpan = cloneSpan(span);
                    if (clonedSpan != null && start >= 0 && end >= start && end <= clone.length()) {
                        clone.setSpan(clonedSpan, start, end, flags);
                    }
                }
            }
            return clone;
        }

        /**
         * Clone individual span objects to prevent shared references.
         */
        private static Object cloneSpan(Object span) {
            if (span instanceof StyleSpan) {
                return new StyleSpan(((StyleSpan) span).getStyle());
            }
            if (span instanceof UnderlineSpan) {
                return new UnderlineSpan();
            }
            if (span instanceof StrikethroughSpan) {
                return new StrikethroughSpan();
            }
            if (span instanceof ForegroundColorSpan) {
                return new ForegroundColorSpan(((ForegroundColorSpan) span).getForegroundColor());
            }
            if (span instanceof BackgroundColorSpan) {
                return new BackgroundColorSpan(((BackgroundColorSpan) span).getBackgroundColor());
            }
            if (span instanceof RelativeSizeSpan) {
                return new RelativeSizeSpan(((RelativeSizeSpan) span).getSizeChange());
            }
            if (span instanceof URLSpan) {
                return new URLSpan(((URLSpan) span).getURL());
            }
            if (span instanceof TypefaceSpan) {
                return new TypefaceSpan(((TypefaceSpan) span).getFamily());
            }
            if (span instanceof BulletSpan) {
                return new BulletSpan(20);
            }
            if (span instanceof AlignmentSpan.Standard) {
                return new AlignmentSpan.Standard(((AlignmentSpan.Standard) span).getAlignment());
            }
            // For unknown span types, return null (skip them)
            return null;
        }

        /**
         * Check if this snapshot's text content equals another's.
         */
        public boolean contentEquals(EditorSnapshot other) {
            if (other == null) return false;
            String thisText = content.toString();
            String otherText = other.content.toString();
            return thisText.equals(otherText);
        }
    }

    public UndoRedoManager() {
        undoStack = new ArrayList();
        redoStack = new ArrayList();
        isPerformingUndoRedo = false;
    }

    public void setListener(UndoRedoListener listener) {
        this.listener = listener;
    }

    /**
     * Check if currently performing an undo/redo operation.
     * TextWatchers should check this to avoid pushing snapshots during restore.
     */
    public boolean isPerformingUndoRedo() {
        return isPerformingUndoRedo;
    }

    /**
     * Push a snapshot onto the undo stack.
     * Skips if the new state is identical to the top of the stack.
     * Clears the redo stack (new action invalidates redo history).
     */
    public void pushSnapshot(CharSequence text, int cursorPosition) {
        if (isPerformingUndoRedo) return;

        EditorSnapshot snapshot = new EditorSnapshot(text, cursorPosition);

        // Skip duplicate consecutive states
        if (!undoStack.isEmpty()) {
            EditorSnapshot top = (EditorSnapshot) undoStack.get(undoStack.size() - 1);
            if (top.contentEquals(snapshot)) {
                return;
            }
        }

        // Enforce max stack size
        if (undoStack.size() >= MAX_STACK_SIZE) {
            undoStack.remove(0);
        }

        undoStack.add(snapshot);
        redoStack.clear();
        notifyListener();
    }

    /**
     * Push the initial state (first snapshot before any edits).
     * Should be called once when the editor loads its content.
     */
    public void pushInitialState(CharSequence text, int cursorPosition) {
        undoStack.clear();
        redoStack.clear();
        undoStack.add(new EditorSnapshot(text, cursorPosition));
        notifyListener();
    }

    /**
     * Perform undo: restore the previous state.
     * Moves current state to redo stack.
     * Returns the snapshot to restore, or null if nothing to undo.
     */
    public EditorSnapshot undo() {
        if (undoStack.size() <= 1) {
            return null;
        }
        isPerformingUndoRedo = true;
        EditorSnapshot current = (EditorSnapshot) undoStack.remove(undoStack.size() - 1);
        redoStack.add(current);
        EditorSnapshot previous = (EditorSnapshot) undoStack.get(undoStack.size() - 1);
        isPerformingUndoRedo = false;
        notifyListener();
        return previous;
    }

    /**
     * Perform redo: restore the next state.
     * Moves state from redo back to undo stack.
     * Returns the snapshot to restore, or null if nothing to redo.
     */
    public EditorSnapshot redo() {
        if (redoStack.isEmpty()) {
            return null;
        }
        isPerformingUndoRedo = true;
        EditorSnapshot next = (EditorSnapshot) redoStack.remove(redoStack.size() - 1);
        undoStack.add(next);
        isPerformingUndoRedo = false;
        notifyListener();
        return next;
    }

    /**
     * Check if undo is available.
     */
    public boolean canUndo() {
        return undoStack.size() > 1;
    }

    /**
     * Check if redo is available.
     */
    public boolean canRedo() {
        return !redoStack.isEmpty();
    }

    /**
     * Clear all history.
     */
    public void clear() {
        undoStack.clear();
        redoStack.clear();
        notifyListener();
    }

    /**
     * Get the current undo stack size.
     */
    public int getUndoSize() {
        return undoStack.size();
    }

    /**
     * Get the current redo stack size.
     */
    public int getRedoSize() {
        return redoStack.size();
    }

    private void notifyListener() {
        if (listener != null) {
            listener.onUndoRedoStateChanged(canUndo(), canRedo());
        }
    }

    // ============ STATIC HELPER: Apply snapshot to EditText ============

    /**
     * Apply a snapshot to an EditText, restoring text, spans, and cursor.
     * The caller should set isPerformingUndoRedo before calling this
     * to prevent TextWatcher from pushing new snapshots.
     */
    public static void applySnapshotToEditText(EditText editText, EditorSnapshot snapshot) {
        if (editText == null || snapshot == null) return;

        SpannableStringBuilder restored = EditorSnapshot.cloneSpannable(snapshot.getContent());
        editText.setText(restored);

        int cursor = snapshot.getCursorPosition();
        if (cursor > editText.getText().length()) {
            cursor = editText.getText().length();
        }
        if (cursor < 0) {
            cursor = 0;
        }
        editText.setSelection(cursor);
    }

    // ============ WORD BOUNDARY DETECTION ============

    /**
     * Check if a character is a word boundary trigger for snapshot.
     * Returns true for space, newline, and common punctuation.
     */
    public static boolean isSnapshotTrigger(char c) {
        return c == ' '
                || c == '\n'
                || c == '.'
                || c == ','
                || c == '!'
                || c == '?'
                || c == ';'
                || c == ':';
    }

    /**
     * Check if text was pasted (more than 1 character inserted at once).
     */
    public static boolean isPaste(int countInserted) {
        return countInserted > 1;
    }
}
