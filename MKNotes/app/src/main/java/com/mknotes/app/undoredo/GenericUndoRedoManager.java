package com.mknotes.app.undoredo;

import java.util.ArrayList;
import java.util.List;

/**
 * GenericUndoRedoManager - State-based undo/redo for non-text modules.
 * 
 * Used by Routine, Meditation, and Mood categories where the "state"
 * is represented as a serialized String (JSON, serialized data, etc.).
 * 
 * Each snapshot is a full state string. Duplicate consecutive states
 * are skipped. Max stack size is enforced.
 * 
 * Pure Java, no AndroidX, no lambda expressions.
 */
public class GenericUndoRedoManager {

    private static final int MAX_STACK_SIZE = 50;

    private List undoStack;
    private List redoStack;
    private boolean isPerformingUndoRedo;
    private StateChangeListener listener;

    /**
     * Listener for state changes.
     */
    public interface StateChangeListener {
        void onStateChanged(boolean canUndo, boolean canRedo);
    }

    public GenericUndoRedoManager() {
        undoStack = new ArrayList();
        redoStack = new ArrayList();
        isPerformingUndoRedo = false;
    }

    public void setListener(StateChangeListener listener) {
        this.listener = listener;
    }

    public boolean isPerformingUndoRedo() {
        return isPerformingUndoRedo;
    }

    /**
     * Push a state snapshot. Skips if identical to top.
     */
    public void pushState(String state) {
        if (isPerformingUndoRedo) return;
        if (state == null) state = "";

        // Skip duplicates
        if (!undoStack.isEmpty()) {
            String top = (String) undoStack.get(undoStack.size() - 1);
            if (top.equals(state)) {
                return;
            }
        }

        if (undoStack.size() >= MAX_STACK_SIZE) {
            undoStack.remove(0);
        }

        undoStack.add(state);
        redoStack.clear();
        notifyListener();
    }

    /**
     * Push initial state (first snapshot before edits).
     */
    public void pushInitialState(String state) {
        undoStack.clear();
        redoStack.clear();
        if (state == null) state = "";
        undoStack.add(state);
        notifyListener();
    }

    /**
     * Undo: returns previous state, or null if nothing to undo.
     */
    public String undo() {
        if (undoStack.size() <= 1) return null;
        isPerformingUndoRedo = true;
        String current = (String) undoStack.remove(undoStack.size() - 1);
        redoStack.add(current);
        String previous = (String) undoStack.get(undoStack.size() - 1);
        isPerformingUndoRedo = false;
        notifyListener();
        return previous;
    }

    /**
     * Redo: returns next state, or null if nothing to redo.
     */
    public String redo() {
        if (redoStack.isEmpty()) return null;
        isPerformingUndoRedo = true;
        String next = (String) redoStack.remove(redoStack.size() - 1);
        undoStack.add(next);
        isPerformingUndoRedo = false;
        notifyListener();
        return next;
    }

    public boolean canUndo() {
        return undoStack.size() > 1;
    }

    public boolean canRedo() {
        return !redoStack.isEmpty();
    }

    public void clear() {
        undoStack.clear();
        redoStack.clear();
        notifyListener();
    }

    public int getUndoSize() {
        return undoStack.size();
    }

    public int getRedoSize() {
        return redoStack.size();
    }

    private void notifyListener() {
        if (listener != null) {
            listener.onStateChanged(canUndo(), canRedo());
        }
    }
}
