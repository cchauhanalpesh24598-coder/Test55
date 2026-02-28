package com.mknotes.app.util;

import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.BackgroundColorSpan;
import android.text.style.ForegroundColorSpan;

public class HighlightText {

    private HighlightText() {
    }

    public static CharSequence highlight(String text, String query, int highlightColor, int textColor) {
        if (text == null || text.length() == 0) {
            return text != null ? text : "";
        }
        if (query == null || query.length() == 0) {
            return text;
        }

        SpannableString spannable = new SpannableString(text);
        String lowerText = text.toLowerCase();
        String lowerQuery = query.toLowerCase();

        int start = 0;
        while (start < lowerText.length()) {
            int index = lowerText.indexOf(lowerQuery, start);
            if (index < 0) {
                break;
            }
            int end = index + lowerQuery.length();
            spannable.setSpan(
                    new BackgroundColorSpan(highlightColor),
                    index,
                    end,
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            );
            spannable.setSpan(
                    new ForegroundColorSpan(textColor),
                    index,
                    end,
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            );
            start = end;
        }
        return spannable;
    }

    public static CharSequence highlight(String text, String query, int highlightColor) {
        return highlight(text, query, highlightColor, 0xFF000000);
    }

    public static boolean containsQuery(String text, String query) {
        if (text == null || query == null || query.length() == 0) {
            return false;
        }
        return text.toLowerCase().contains(query.toLowerCase());
    }
}
