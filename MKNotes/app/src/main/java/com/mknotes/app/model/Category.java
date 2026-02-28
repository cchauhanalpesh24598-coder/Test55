package com.mknotes.app.model;

import java.io.Serializable;

public class Category implements Serializable {

    private long id;
    private String name;
    private int color;
    private int sortOrder;

    public Category() {
        this.id = -1;
        this.name = "";
        this.color = 0;
        this.sortOrder = 0;
    }

    public Category(String name, int color) {
        this.id = -1;
        this.name = name;
        this.color = color;
        this.sortOrder = 0;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getColor() {
        return color;
    }

    public void setColor(int color) {
        this.color = color;
    }

    public int getSortOrder() {
        return sortOrder;
    }

    public void setSortOrder(int sortOrder) {
        this.sortOrder = sortOrder;
    }
}
