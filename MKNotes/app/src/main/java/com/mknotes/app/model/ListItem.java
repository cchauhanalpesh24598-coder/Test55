package com.mknotes.app.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class ListItem implements Serializable {

    private static int sNextId = 1;

    private int id;
    private String body;
    private boolean checked;
    private boolean isChild;
    private int order;
    private List children;

    public ListItem() {
        this.id = sNextId++;
        this.body = "";
        this.checked = false;
        this.isChild = false;
        this.order = 0;
        this.children = new ArrayList();
    }

    public ListItem(String body, boolean checked, boolean isChild, int order) {
        this.id = sNextId++;
        this.body = body != null ? body : "";
        this.checked = checked;
        this.isChild = isChild;
        this.order = order;
        this.children = new ArrayList();
    }

    public static void resetIdCounter(int startId) {
        sNextId = startId;
    }

    public static int getNextId() {
        return sNextId;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body != null ? body : "";
    }

    public boolean isChecked() {
        return checked;
    }

    public void setChecked(boolean checked) {
        this.checked = checked;
    }

    public boolean isChild() {
        return isChild;
    }

    public void setIsChild(boolean isChild) {
        this.isChild = isChild;
    }

    public int getOrder() {
        return order;
    }

    public void setOrder(int order) {
        this.order = order;
    }

    public List getChildren() {
        return children;
    }

    public void setChildren(List children) {
        this.children = children != null ? children : new ArrayList();
    }

    public void addChild(ListItem child) {
        child.setIsChild(true);
        children.add(child);
    }

    public void removeChild(ListItem child) {
        children.remove(child);
    }

    public int getTotalItemCount() {
        int count = 1;
        for (int i = 0; i < children.size(); i++) {
            count += ((ListItem) children.get(i)).getTotalItemCount();
        }
        return count;
    }

    public ListItem clone() {
        ListItem copy = new ListItem();
        copy.id = this.id;
        copy.body = this.body;
        copy.checked = this.checked;
        copy.isChild = this.isChild;
        copy.order = this.order;
        copy.children = new ArrayList();
        for (int i = 0; i < this.children.size(); i++) {
            copy.children.add(((ListItem) this.children.get(i)).clone());
        }
        return copy;
    }

    public ListItem deepCopyWithNewId() {
        ListItem copy = new ListItem();
        copy.body = this.body;
        copy.checked = this.checked;
        copy.isChild = this.isChild;
        copy.order = this.order;
        copy.children = new ArrayList();
        for (int i = 0; i < this.children.size(); i++) {
            copy.children.add(((ListItem) this.children.get(i)).deepCopyWithNewId());
        }
        return copy;
    }

    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ListItem other = (ListItem) o;
        return id == other.id;
    }

    public int hashCode() {
        return id;
    }

    public String toString() {
        String prefix = isChild ? "  " : "";
        String check = checked ? "[x] " : "[ ] ";
        return prefix + check + body;
    }
}
