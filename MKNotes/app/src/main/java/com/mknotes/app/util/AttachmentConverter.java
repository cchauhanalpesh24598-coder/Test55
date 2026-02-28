package com.mknotes.app.util;

import com.mknotes.app.model.AudioAttachment;
import com.mknotes.app.model.FileAttachment;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Converts attachment lists to/from JSON strings for database storage.
 * Uses org.json (Android built-in) - no external dependencies.
 */
public class AttachmentConverter {

    // ========== FileAttachment (Images & Files) ==========

    public static String filesToJson(List files) {
        if (files == null || files.isEmpty()) return "[]";
        JSONArray array = new JSONArray();
        for (int i = 0; i < files.size(); i++) {
            FileAttachment f = (FileAttachment) files.get(i);
            try {
                JSONObject obj = new JSONObject();
                obj.put("localName", f.getLocalName());
                obj.put("originalName", f.getOriginalName());
                obj.put("mimeType", f.getMimeType());
                array.put(obj);
            } catch (JSONException e) {
                // Skip this item on error
            }
        }
        return array.toString();
    }

    public static List jsonToFiles(String json) {
        List list = new ArrayList();
        if (json == null || json.length() < 2) return list;
        try {
            JSONArray array = new JSONArray(json);
            for (int i = 0; i < array.length(); i++) {
                JSONObject obj = array.getJSONObject(i);
                FileAttachment f = new FileAttachment();
                f.setLocalName(obj.optString("localName", ""));
                f.setOriginalName(obj.optString("originalName", ""));
                f.setMimeType(obj.optString("mimeType", ""));
                list.add(f);
            }
        } catch (JSONException e) {
            // Return empty list on parse error
        }
        return list;
    }

    // ========== AudioAttachment ==========

    public static String audiosToJson(List audios) {
        if (audios == null || audios.isEmpty()) return "[]";
        JSONArray array = new JSONArray();
        for (int i = 0; i < audios.size(); i++) {
            AudioAttachment a = (AudioAttachment) audios.get(i);
            try {
                JSONObject obj = new JSONObject();
                obj.put("localName", a.getLocalName());
                obj.put("duration", a.getDuration());
                obj.put("timestamp", a.getTimestamp());
                array.put(obj);
            } catch (JSONException e) {
                // Skip this item on error
            }
        }
        return array.toString();
    }

    public static List jsonToAudios(String json) {
        List list = new ArrayList();
        if (json == null || json.length() < 2) return list;
        try {
            JSONArray array = new JSONArray(json);
            for (int i = 0; i < array.length(); i++) {
                JSONObject obj = array.getJSONObject(i);
                AudioAttachment a = new AudioAttachment();
                a.setLocalName(obj.optString("localName", ""));
                a.setDuration(obj.optLong("duration", 0));
                a.setTimestamp(obj.optLong("timestamp", 0));
                list.add(a);
            }
        } catch (JSONException e) {
            // Return empty list on parse error
        }
        return list;
    }

    // ========== Linked Note IDs ==========

    public static String idsToJson(List ids) {
        if (ids == null || ids.isEmpty()) return "[]";
        JSONArray array = new JSONArray();
        for (int i = 0; i < ids.size(); i++) {
            array.put(((Long) ids.get(i)).longValue());
        }
        return array.toString();
    }

    public static List jsonToIds(String json) {
        List list = new ArrayList();
        if (json == null || json.length() < 2) return list;
        try {
            JSONArray array = new JSONArray(json);
            for (int i = 0; i < array.length(); i++) {
                list.add(Long.valueOf(array.getLong(i)));
            }
        } catch (JSONException e) {
            // Return empty list on parse error
        }
        return list;
    }
}
