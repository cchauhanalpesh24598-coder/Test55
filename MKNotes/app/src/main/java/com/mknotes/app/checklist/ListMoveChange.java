package com.mknotes.app.checklist;

public class ListMoveChange extends ListChange {

    private int fromPosition;
    private int toPosition;

    public ListMoveChange(int fromPosition, int toPosition) {
        super(TYPE_MOVE);
        this.fromPosition = fromPosition;
        this.toPosition = toPosition;
    }

    public void undo(ChecklistManager manager) {
        manager.moveItemInternal(toPosition, fromPosition);
    }

    public void redo(ChecklistManager manager) {
        manager.moveItemInternal(fromPosition, toPosition);
    }

    public int getFromPosition() {
        return fromPosition;
    }

    public int getToPosition() {
        return toPosition;
    }
}
