package com.mknotes.app.util;

import com.mknotes.app.model.ListItem;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

public class ListItemConverter {

    private ListItemConverter() {
    }

    public static String toJson(List items) {
        if (items == null || items.isEmpty()) {
            return "[]";
        }
        try {
            JSONArray jsonArray = new JSONArray();
            for (int i = 0; i < items.size(); i++) {
                ListItem item = (ListItem) items.get(i);
                jsonArray.put(itemToJson(item));
            }
            return jsonArray.toString();
        } catch (JSONException e) {
            return "[]";
        }
    }

    private static JSONObject itemToJson(ListItem item) throws JSONException {
        JSONObject obj = new JSONObject();
        obj.put("id", item.getId());
        obj.put("body", item.getBody());
        obj.put("checked", item.isChecked());
        obj.put("isChild", item.isChild());
        obj.put("order", item.getOrder());
        JSONArray childrenArr = new JSONArray();
        List children = item.getChildren();
        for (int i = 0; i < children.size(); i++) {
            childrenArr.put(itemToJson((ListItem) children.get(i)));
        }
        obj.put("children", childrenArr);
        return obj;
    }

    public static List fromJson(String json) {
        List items = new ArrayList();
        if (json == null || json.length() == 0 || json.equals("[]")) {
            return items;
        }
        try {
            JSONArray jsonArray = new JSONArray(json);
            int maxId = 0;
            for (int i = 0; i < jsonArray.length(); i++) {
                JSONObject obj = jsonArray.getJSONObject(i);
                ListItem item = jsonToItem(obj);
                items.add(item);
                int localMax = findMaxId(item);
                if (localMax > maxId) {
                    maxId = localMax;
                }
            }
            ListItem.resetIdCounter(maxId + 1);
        } catch (JSONException e) {
            // Return empty list on error
        }
        return items;
    }

    private static int findMaxId(ListItem item) {
        int max = item.getId();
        List children = item.getChildren();
        for (int i = 0; i < children.size(); i++) {
            int childMax = findMaxId((ListItem) children.get(i));
            if (childMax > max) {
                max = childMax;
            }
        }
        return max;
    }

    private static ListItem jsonToItem(JSONObject obj) throws JSONException {
        ListItem item = new ListItem();
        item.setId(obj.optInt("id", item.getId()));
        item.setBody(obj.optString("body", ""));
        item.setChecked(obj.optBoolean("checked", false));
        item.setIsChild(obj.optBoolean("isChild", false));
        item.setOrder(obj.optInt("order", 0));
        JSONArray childrenArr = obj.optJSONArray("children");
        if (childrenArr != null) {
            List children = new ArrayList();
            for (int i = 0; i < childrenArr.length(); i++) {
                children.add(jsonToItem(childrenArr.getJSONObject(i)));
            }
            item.setChildren(children);
        }
        return item;
    }

    public static String toPlainText(List items) {
        if (items == null || items.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < items.size(); i++) {
            ListItem item = (ListItem) items.get(i);
            appendItemText(sb, item, 0);
        }
        if (sb.length() > 0 && sb.charAt(sb.length() - 1) == '\n') {
            sb.deleteCharAt(sb.length() - 1);
        }
        return sb.toString();
    }

    private static void appendItemText(StringBuilder sb, ListItem item, int depth) {
        for (int d = 0; d < depth; d++) {
            sb.append("  ");
        }
        if (item.isChecked()) {
            sb.append("[x] ");
        } else {
            sb.append("[ ] ");
        }
        sb.append(item.getBody());
        sb.append('\n');
        List children = item.getChildren();
        for (int i = 0; i < children.size(); i++) {
            appendItemText(sb, (ListItem) children.get(i), depth + 1);
        }
    }

    public static List fromPlainText(String text) {
        List items = new ArrayList();
        if (text == null || text.length() == 0) {
            return items;
        }
        String[] lines = text.split("\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (line.trim().length() == 0) {
                continue;
            }
            boolean isChild = line.startsWith("  ") || line.startsWith("\t");
            String cleanLine = line.trim();
            boolean checked = false;

            if (cleanLine.startsWith("[x] ") || cleanLine.startsWith("[X] ")) {
                checked = true;
                cleanLine = cleanLine.substring(4);
            } else if (cleanLine.startsWith("[ ] ")) {
                checked = false;
                cleanLine = cleanLine.substring(4);
            } else if (cleanLine.startsWith("- [x] ") || cleanLine.startsWith("- [X] ")) {
                checked = true;
                cleanLine = cleanLine.substring(6);
            } else if (cleanLine.startsWith("- [ ] ")) {
                checked = false;
                cleanLine = cleanLine.substring(6);
            } else if (cleanLine.startsWith("- ")) {
                cleanLine = cleanLine.substring(2);
            }

            ListItem item = new ListItem(cleanLine, checked, false, i);

            if (isChild && items.size() > 0) {
                ListItem parent = (ListItem) items.get(items.size() - 1);
                item.setIsChild(true);
                parent.addChild(item);
            } else {
                items.add(item);
            }
        }
        return items;
    }

    public static List flattenItems(List items) {
        List flat = new ArrayList();
        for (int i = 0; i < items.size(); i++) {
            ListItem item = (ListItem) items.get(i);
            flat.add(item);
            List children = item.getChildren();
            for (int c = 0; c < children.size(); c++) {
                flat.add((ListItem) children.get(c));
            }
        }
        return flat;
    }

    public static List unflattenItems(List flatItems) {
        List result = new ArrayList();
        ListItem currentParent = null;
        for (int i = 0; i < flatItems.size(); i++) {
            ListItem item = (ListItem) flatItems.get(i);
            if (item.isChild() && currentParent != null) {
                currentParent.addChild(item);
            } else {
                item.setIsChild(false);
                item.setChildren(new ArrayList());
                currentParent = item;
                result.add(item);
            }
        }
        return result;
    }
}
