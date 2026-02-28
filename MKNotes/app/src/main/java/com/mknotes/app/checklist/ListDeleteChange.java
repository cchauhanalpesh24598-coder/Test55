package com.mknotes.app.checklist;

import com.mknotes.app.model.ListItem;

public class ListDeleteChange extends ListChange {

    private int position;
    private ListItem item;

    public ListDeleteChange(int position, ListItem item) {
        super(TYPE_DELETE);
        this.position = position;
        this.item = item.clone();
    }

    public void undo(ChecklistManager manager) {
        manager.addItemAtInternal(position, item.clone());
    }

    public void redo(ChecklistManager manager) {
        manager.removeItemAtInternal(position);
    }

    public int getPosition() {
        return position;
    }

    public ListItem getItem() {
        return item;
    }
}
