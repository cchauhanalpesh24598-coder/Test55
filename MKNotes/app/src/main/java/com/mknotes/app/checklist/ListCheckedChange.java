package com.mknotes.app.checklist;

public class ListCheckedChange extends ListChange {

    private int position;
    private boolean wasChecked;

    public ListCheckedChange(int position, boolean wasChecked) {
        super(TYPE_CHECKED);
        this.position = position;
        this.wasChecked = wasChecked;
    }

    public void undo(ChecklistManager manager) {
        manager.setItemCheckedInternal(position, wasChecked);
    }

    public void redo(ChecklistManager manager) {
        manager.setItemCheckedInternal(position, !wasChecked);
    }

    public int getPosition() {
        return position;
    }

    public boolean wasChecked() {
        return wasChecked;
    }
}
