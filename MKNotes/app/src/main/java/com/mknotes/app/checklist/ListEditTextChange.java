package com.mknotes.app.checklist;

public class ListEditTextChange extends ListChange {

    private int position;
    private String oldText;
    private String newText;

    public ListEditTextChange(int position, String oldText, String newText) {
        super(TYPE_EDIT_TEXT);
        this.position = position;
        this.oldText = oldText != null ? oldText : "";
        this.newText = newText != null ? newText : "";
    }

    public void undo(ChecklistManager manager) {
        manager.setItemTextInternal(position, oldText);
    }

    public void redo(ChecklistManager manager) {
        manager.setItemTextInternal(position, newText);
    }

    public int getPosition() {
        return position;
    }

    public String getOldText() {
        return oldText;
    }

    public String getNewText() {
        return newText;
    }
}
