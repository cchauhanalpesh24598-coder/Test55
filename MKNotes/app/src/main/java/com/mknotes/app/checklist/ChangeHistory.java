package com.mknotes.app.checklist;

import java.util.ArrayList;
import java.util.List;

public class ChangeHistory {

    private static final int MAX_HISTORY = 50;

    private List undoStack;
    private List redoStack;
    private ChangeHistoryListener listener;

    public interface ChangeHistoryListener {
        void onHistoryChanged(boolean canUndo, boolean canRedo);
    }

    public ChangeHistory() {
        undoStack = new ArrayList();
        redoStack = new ArrayList();
    }

    public void setListener(ChangeHistoryListener listener) {
        this.listener = listener;
    }

    public void pushChange(ListChange change) {
        undoStack.add(change);
        if (undoStack.size() > MAX_HISTORY) {
            undoStack.remove(0);
        }
        redoStack.clear();
        notifyListener();
    }

    public boolean canUndo() {
        return !undoStack.isEmpty();
    }

    public boolean canRedo() {
        return !redoStack.isEmpty();
    }

    public void undo(ChecklistManager manager) {
        if (undoStack.isEmpty()) {
            return;
        }
        ListChange change = (ListChange) undoStack.remove(undoStack.size() - 1);
        change.undo(manager);
        redoStack.add(change);
        notifyListener();
    }

    public void redo(ChecklistManager manager) {
        if (redoStack.isEmpty()) {
            return;
        }
        ListChange change = (ListChange) redoStack.remove(redoStack.size() - 1);
        change.redo(manager);
        undoStack.add(change);
        notifyListener();
    }

    public void clear() {
        undoStack.clear();
        redoStack.clear();
        notifyListener();
    }

    private void notifyListener() {
        if (listener != null) {
            listener.onHistoryChanged(canUndo(), canRedo());
        }
    }

    public int getUndoSize() {
        return undoStack.size();
    }

    public int getRedoSize() {
        return redoStack.size();
    }
}
