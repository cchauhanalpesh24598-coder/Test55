package com.mknotes.app.model;

import java.io.Serializable;

public class AudioAttachment implements Serializable {

    private String localName;
    private long duration;
    private long timestamp;

    public AudioAttachment() {
        this.localName = "";
        this.duration = 0;
        this.timestamp = System.currentTimeMillis();
    }

    public AudioAttachment(String localName, long duration, long timestamp) {
        this.localName = localName != null ? localName : "";
        this.duration = duration;
        this.timestamp = timestamp;
    }

    public String getLocalName() {
        return localName;
    }

    public void setLocalName(String localName) {
        this.localName = localName != null ? localName : "";
    }

    public long getDuration() {
        return duration;
    }

    public void setDuration(long duration) {
        this.duration = duration;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public String getFormattedDuration() {
        long totalSeconds = duration / 1000;
        long minutes = totalSeconds / 60;
        long seconds = totalSeconds % 60;
        return String.format("%02d:%02d", minutes, seconds);
    }

    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AudioAttachment that = (AudioAttachment) o;
        return localName != null && localName.equals(that.localName);
    }

    public int hashCode() {
        return localName != null ? localName.hashCode() : 0;
    }

    public String toString() {
        return "AudioAttachment{" + localName + ", " + getFormattedDuration() + "}";
    }
}
