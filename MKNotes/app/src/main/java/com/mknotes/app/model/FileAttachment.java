package com.mknotes.app.model;

import java.io.Serializable;

public class FileAttachment implements Serializable {

    private String localName;
    private String originalName;
    private String mimeType;

    public FileAttachment() {
        this.localName = "";
        this.originalName = "";
        this.mimeType = "";
    }

    public FileAttachment(String localName, String originalName, String mimeType) {
        this.localName = localName != null ? localName : "";
        this.originalName = originalName != null ? originalName : "";
        this.mimeType = mimeType != null ? mimeType : "";
    }

    public String getLocalName() {
        return localName;
    }

    public void setLocalName(String localName) {
        this.localName = localName != null ? localName : "";
    }

    public String getOriginalName() {
        return originalName;
    }

    public void setOriginalName(String originalName) {
        this.originalName = originalName != null ? originalName : "";
    }

    public String getMimeType() {
        return mimeType;
    }

    public void setMimeType(String mimeType) {
        this.mimeType = mimeType != null ? mimeType : "";
    }

    public boolean isImage() {
        return mimeType != null && mimeType.startsWith("image/");
    }

    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FileAttachment that = (FileAttachment) o;
        return localName != null && localName.equals(that.localName);
    }

    public int hashCode() {
        return localName != null ? localName.hashCode() : 0;
    }

    public String toString() {
        return "FileAttachment{" + originalName + ", " + mimeType + "}";
    }
}
