package com.mknotes.app.checklist;

import java.util.ArrayList;
import java.util.List;

public class ListBatchChange extends ListChange {

    private List changes;

    public ListBatchChange(List changes) {
        super(TYPE_BATCH);
        this.changes = new ArrayList();
        for (int i = 0; i < changes.size(); i++) {
            this.changes.add(changes.get(i));
        }
    }

    public void undo(ChecklistManager manager) {
        for (int i = changes.size() - 1; i >= 0; i--) {
            ((ListChange) changes.get(i)).undo(manager);
        }
    }

    public void redo(ChecklistManager manager) {
        for (int i = 0; i < changes.size(); i++) {
            ((ListChange) changes.get(i)).redo(manager);
        }
    }

    public List getChanges() {
        return changes;
    }
}
