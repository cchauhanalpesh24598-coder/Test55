package com.mknotes.app.checklist;

public abstract class ListChange {

    public static final int TYPE_ADD = 1;
    public static final int TYPE_DELETE = 2;
    public static final int TYPE_MOVE = 3;
    public static final int TYPE_CHECKED = 4;
    public static final int TYPE_EDIT_TEXT = 5;
    public static final int TYPE_INDENT = 6;
    public static final int TYPE_BATCH = 7;

    private int type;

    public ListChange(int type) {
        this.type = type;
    }

    public int getType() {
        return type;
    }

    public abstract void undo(ChecklistManager manager);

    public abstract void redo(ChecklistManager manager);
}
