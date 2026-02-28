package com.mknotes.app.checklist;

import com.mknotes.app.model.ListItem;
import com.mknotes.app.util.ListItemConverter;

import java.util.ArrayList;
import java.util.List;

public class ChecklistManager {

    private List items;
    private ChangeHistory history;
    private ChecklistListener listener;
    private boolean autoSortChecked;
    private boolean isPerformingUndoRedo;

    public interface ChecklistListener {
        void onItemsChanged();
        void onItemAdded(int position);
        void onItemRemoved(int position);
        void onItemMoved(int fromPosition, int toPosition);
        void onItemUpdated(int position);
        void onRequestFocus(int position);
    }

    public ChecklistManager() {
        items = new ArrayList();
        history = new ChangeHistory();
        autoSortChecked = true;
        isPerformingUndoRedo = false;
    }

    public void setListener(ChecklistListener listener) {
        this.listener = listener;
    }

    public void setHistoryListener(ChangeHistory.ChangeHistoryListener historyListener) {
        history.setListener(historyListener);
    }

    public void setAutoSortChecked(boolean autoSort) {
        this.autoSortChecked = autoSort;
    }

    public boolean isAutoSortChecked() {
        return autoSortChecked;
    }

    public ChangeHistory getHistory() {
        return history;
    }

    // ============ Data Access ============

    public List getItems() {
        return items;
    }

    public int getItemCount() {
        return items.size();
    }

    public ListItem getItem(int position) {
        if (position >= 0 && position < items.size()) {
            return (ListItem) items.get(position);
        }
        return null;
    }

    public int getPositionById(int itemId) {
        for (int i = 0; i < items.size(); i++) {
            if (((ListItem) items.get(i)).getId() == itemId) {
                return i;
            }
        }
        return -1;
    }

    // ============ Load / Save ============

    public void loadItems(List loadedItems) {
        items.clear();
        if (loadedItems != null) {
            for (int i = 0; i < loadedItems.size(); i++) {
                items.add(loadedItems.get(i));
            }
        }
        history.clear();
        if (listener != null) {
            listener.onItemsChanged();
        }
    }

    public void loadFromJson(String json) {
        List loaded = ListItemConverter.fromJson(json);
        List flat = ListItemConverter.flattenItems(loaded);
        loadItems(flat);
    }

    public String saveToJson() {
        List structured = ListItemConverter.unflattenItems(items);
        return ListItemConverter.toJson(structured);
    }

    public void loadFromText(String text) {
        List parsed = ListItemConverter.fromPlainText(text);
        List flat = ListItemConverter.flattenItems(parsed);
        loadItems(flat);
    }

    public String toPlainText() {
        List structured = ListItemConverter.unflattenItems(items);
        return ListItemConverter.toPlainText(structured);
    }

    // ============ Add Item ============

    public void addItem(String body) {
        int position = findInsertPosition();
        ListItem item = new ListItem(body, false, false, position);
        items.add(position, item);
        if (!isPerformingUndoRedo) {
            history.pushChange(new ListAddChange(position, item));
        }
        if (listener != null) {
            listener.onItemAdded(position);
            listener.onRequestFocus(position);
        }
    }

    public void addItemAfter(int currentPosition) {
        int insertPos = currentPosition + 1;
        ListItem currentItem = getItem(currentPosition);
        boolean makeChild = (currentItem != null && currentItem.isChild());
        ListItem item = new ListItem("", false, makeChild, insertPos);
        items.add(insertPos, item);
        updateOrders();
        if (!isPerformingUndoRedo) {
            history.pushChange(new ListAddChange(insertPos, item));
        }
        if (listener != null) {
            listener.onItemAdded(insertPos);
            listener.onRequestFocus(insertPos);
        }
    }

    public void addItemAt(int position, String body) {
        ListItem item = new ListItem(body, false, false, position);
        items.add(position, item);
        updateOrders();
        if (!isPerformingUndoRedo) {
            history.pushChange(new ListAddChange(position, item));
        }
        if (listener != null) {
            listener.onItemAdded(position);
        }
    }

    private int findInsertPosition() {
        for (int i = 0; i < items.size(); i++) {
            if (((ListItem) items.get(i)).isChecked()) {
                return i;
            }
        }
        return items.size();
    }

    // ============ Delete Item ============

    public void deleteItem(int position) {
        if (position < 0 || position >= items.size()) return;
        ListItem removed = (ListItem) items.remove(position);
        updateOrders();
        if (!isPerformingUndoRedo) {
            history.pushChange(new ListDeleteChange(position, removed));
        }
        if (listener != null) {
            listener.onItemRemoved(position);
            if (position > 0) {
                listener.onRequestFocus(position - 1);
            }
        }
    }

    public void deleteItemIfEmpty(int position) {
        if (position < 0 || position >= items.size()) return;
        ListItem item = (ListItem) items.get(position);
        if (item.getBody().length() == 0 && items.size() > 1) {
            deleteItem(position);
        }
    }

    // ============ Check / Uncheck ============

    public void toggleChecked(int position) {
        if (position < 0 || position >= items.size()) return;
        ListItem item = (ListItem) items.get(position);
        boolean wasChecked = item.isChecked();
        item.setChecked(!wasChecked);

        if (!isPerformingUndoRedo) {
            history.pushChange(new ListCheckedChange(position, wasChecked));
        }

        if (listener != null) {
            listener.onItemUpdated(position);
        }

        if (autoSortChecked) {
            sortCheckedToBottom(position);
        }
    }

    private void sortCheckedToBottom(int changedPosition) {
        ListItem item = getItem(changedPosition);
        if (item == null) return;

        if (item.isChecked()) {
            int targetPos = findLastUncheckedPosition() + 1;
            if (targetPos > changedPosition && targetPos <= items.size()) {
                // Already in the right spot or needs to move down
            } else if (changedPosition < targetPos - 1) {
                moveItemInternal(changedPosition, targetPos - 1);
                if (listener != null) {
                    listener.onItemsChanged();
                }
            }
        } else {
            int targetPos = findLastUncheckedPosition();
            if (changedPosition > targetPos && targetPos >= 0) {
                // Already in the right spot
            }
        }
        // Full re-sort for safety
        sortAllCheckedToBottom();
    }

    private void sortAllCheckedToBottom() {
        List unchecked = new ArrayList();
        List checked = new ArrayList();
        for (int i = 0; i < items.size(); i++) {
            ListItem item = (ListItem) items.get(i);
            if (item.isChecked()) {
                checked.add(item);
            } else {
                unchecked.add(item);
            }
        }
        boolean changed = false;
        int expectedUncheckedEnd = unchecked.size();
        for (int i = 0; i < unchecked.size(); i++) {
            if (items.indexOf(unchecked.get(i)) != i) {
                changed = true;
                break;
            }
        }
        if (!changed) {
            for (int i = 0; i < checked.size(); i++) {
                if (items.indexOf(checked.get(i)) != expectedUncheckedEnd + i) {
                    changed = true;
                    break;
                }
            }
        }
        if (changed) {
            items.clear();
            items.addAll(unchecked);
            items.addAll(checked);
            updateOrders();
            if (listener != null) {
                listener.onItemsChanged();
            }
        }
    }

    private int findLastUncheckedPosition() {
        for (int i = items.size() - 1; i >= 0; i--) {
            if (!((ListItem) items.get(i)).isChecked()) {
                return i;
            }
        }
        return -1;
    }

    // ============ Edit Text ============

    public void setItemText(int position, String text) {
        if (position < 0 || position >= items.size()) return;
        ListItem item = (ListItem) items.get(position);
        String oldText = item.getBody();
        if (oldText.equals(text)) return;
        item.setBody(text);
        if (!isPerformingUndoRedo) {
            history.pushChange(new ListEditTextChange(position, oldText, text));
        }
    }

    // ============ Indent / Outdent ============

    public void toggleIndent(int position) {
        if (position < 0 || position >= items.size()) return;
        if (position == 0) return;

        ListItem item = (ListItem) items.get(position);
        boolean wasChild = item.isChild();

        if (wasChild) {
            item.setIsChild(false);
        } else {
            ListItem prevItem = null;
            for (int i = position - 1; i >= 0; i--) {
                ListItem candidate = (ListItem) items.get(i);
                if (!candidate.isChild()) {
                    prevItem = candidate;
                    break;
                }
            }
            if (prevItem != null) {
                item.setIsChild(true);
            }
        }

        if (!isPerformingUndoRedo) {
            history.pushChange(new ListIndentChange(position, wasChild));
        }
        if (listener != null) {
            listener.onItemUpdated(position);
        }
    }

    public boolean canIndent(int position) {
        if (position <= 0 || position >= items.size()) return false;
        ListItem item = (ListItem) items.get(position);
        if (item.isChild()) return true;
        for (int i = position - 1; i >= 0; i--) {
            ListItem candidate = (ListItem) items.get(i);
            if (!candidate.isChild()) {
                return true;
            }
        }
        return false;
    }

    // ============ Move Item (Drag & Drop) ============

    public void moveItem(int fromPosition, int toPosition) {
        if (fromPosition == toPosition) return;
        if (fromPosition < 0 || fromPosition >= items.size()) return;
        if (toPosition < 0 || toPosition >= items.size()) return;

        moveItemInternal(fromPosition, toPosition);

        if (!isPerformingUndoRedo) {
            history.pushChange(new ListMoveChange(fromPosition, toPosition));
        }
        if (listener != null) {
            listener.onItemMoved(fromPosition, toPosition);
        }
    }

    // ============ Internal methods (used by undo/redo) ============

    public void moveItemInternal(int fromPosition, int toPosition) {
        if (fromPosition < 0 || fromPosition >= items.size()) return;
        if (toPosition < 0 || toPosition >= items.size()) return;

        Object item = items.remove(fromPosition);
        items.add(toPosition, item);
        updateOrders();
    }

    public void addItemAtInternal(int position, ListItem item) {
        if (position < 0) position = 0;
        if (position > items.size()) position = items.size();
        items.add(position, item);
        updateOrders();
        if (listener != null) {
            listener.onItemAdded(position);
        }
    }

    public void removeItemAtInternal(int position) {
        if (position >= 0 && position < items.size()) {
            items.remove(position);
            updateOrders();
            if (listener != null) {
                listener.onItemRemoved(position);
            }
        }
    }

    public void setItemCheckedInternal(int position, boolean checked) {
        if (position >= 0 && position < items.size()) {
            ((ListItem) items.get(position)).setChecked(checked);
            if (listener != null) {
                listener.onItemUpdated(position);
            }
        }
    }

    public void setItemTextInternal(int position, String text) {
        if (position >= 0 && position < items.size()) {
            ((ListItem) items.get(position)).setBody(text);
            if (listener != null) {
                listener.onItemUpdated(position);
            }
        }
    }

    public void setItemChildInternal(int position, boolean isChild) {
        if (position >= 0 && position < items.size()) {
            ((ListItem) items.get(position)).setIsChild(isChild);
            if (listener != null) {
                listener.onItemUpdated(position);
            }
        }
    }

    // ============ Undo / Redo ============

    public void undo() {
        isPerformingUndoRedo = true;
        history.undo(this);
        isPerformingUndoRedo = false;
        if (listener != null) {
            listener.onItemsChanged();
        }
    }

    public void redo() {
        isPerformingUndoRedo = true;
        history.redo(this);
        isPerformingUndoRedo = false;
        if (listener != null) {
            listener.onItemsChanged();
        }
    }

    public boolean canUndo() {
        return history.canUndo();
    }

    public boolean canRedo() {
        return history.canRedo();
    }

    // ============ Utilities ============

    private void updateOrders() {
        for (int i = 0; i < items.size(); i++) {
            ((ListItem) items.get(i)).setOrder(i);
        }
    }

    public int getCheckedCount() {
        int count = 0;
        for (int i = 0; i < items.size(); i++) {
            if (((ListItem) items.get(i)).isChecked()) {
                count++;
            }
        }
        return count;
    }

    public int getUncheckedCount() {
        return items.size() - getCheckedCount();
    }

    public void uncheckAll() {
        List changes = new ArrayList();
        for (int i = 0; i < items.size(); i++) {
            ListItem item = (ListItem) items.get(i);
            if (item.isChecked()) {
                changes.add(new ListCheckedChange(i, true));
                item.setChecked(false);
            }
        }
        if (!changes.isEmpty() && !isPerformingUndoRedo) {
            history.pushChange(new ListBatchChange(changes));
        }
        if (listener != null) {
            listener.onItemsChanged();
        }
    }

    public void deleteCheckedItems() {
        List changes = new ArrayList();
        for (int i = items.size() - 1; i >= 0; i--) {
            ListItem item = (ListItem) items.get(i);
            if (item.isChecked()) {
                changes.add(new ListDeleteChange(i, item));
                items.remove(i);
            }
        }
        if (!changes.isEmpty()) {
            updateOrders();
            if (!isPerformingUndoRedo) {
                history.pushChange(new ListBatchChange(changes));
            }
            if (listener != null) {
                listener.onItemsChanged();
            }
        }
    }

    public int findParentPosition(int childPosition) {
        if (childPosition <= 0) return -1;
        ListItem child = getItem(childPosition);
        if (child == null || !child.isChild()) return -1;

        for (int i = childPosition - 1; i >= 0; i--) {
            ListItem candidate = (ListItem) items.get(i);
            if (!candidate.isChild()) {
                return i;
            }
        }
        return -1;
    }

    public List getChildPositions(int parentPosition) {
        List childPositions = new ArrayList();
        if (parentPosition < 0 || parentPosition >= items.size()) return childPositions;
        ListItem parent = (ListItem) items.get(parentPosition);
        if (parent.isChild()) return childPositions;

        for (int i = parentPosition + 1; i < items.size(); i++) {
            ListItem item = (ListItem) items.get(i);
            if (item.isChild()) {
                childPositions.add(Integer.valueOf(i));
            } else {
                break;
            }
        }
        return childPositions;
    }
}
