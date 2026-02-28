package com.mknotes.app.checklist;

public class ListIndentChange extends ListChange {

    private int position;
    private boolean wasChild;

    public ListIndentChange(int position, boolean wasChild) {
        super(TYPE_INDENT);
        this.position = position;
        this.wasChild = wasChild;
    }

    public void undo(ChecklistManager manager) {
        manager.setItemChildInternal(position, wasChild);
    }

    public void redo(ChecklistManager manager) {
        manager.setItemChildInternal(position, !wasChild);
    }

    public int getPosition() {
        return position;
    }

    public boolean wasChild() {
        return wasChild;
    }
}
