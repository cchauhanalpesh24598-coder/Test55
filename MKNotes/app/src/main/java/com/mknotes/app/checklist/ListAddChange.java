package com.mknotes.app.checklist;

import com.mknotes.app.model.ListItem;

public class ListAddChange extends ListChange {

    private int position;
    private ListItem item;

    public ListAddChange(int position, ListItem item) {
        super(TYPE_ADD);
        this.position = position;
        this.item = item.clone();
    }

    public void undo(ChecklistManager manager) {
        manager.removeItemAtInternal(position);
    }

    public void redo(ChecklistManager manager) {
        manager.addItemAtInternal(position, item.clone());
    }

    public int getPosition() {
        return position;
    }

    public ListItem getItem() {
        return item;
    }
}
