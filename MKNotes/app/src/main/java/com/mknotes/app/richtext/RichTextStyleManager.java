package com.mknotes.app.richtext;

import android.graphics.Typeface;
import android.text.Editable;
import android.text.Layout;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.style.AlignmentSpan;
import android.text.style.BackgroundColorSpan;
import android.text.style.BulletSpan;
import android.text.style.ForegroundColorSpan;
import android.text.style.RelativeSizeSpan;
import android.text.style.StrikethroughSpan;
import android.text.style.StyleSpan;
import android.text.style.TypefaceSpan;
import android.text.style.URLSpan;
import android.text.style.UnderlineSpan;
import android.widget.EditText;

/**
 * RichTextStyleManager - Core rich text formatting engine.
 * Replicates the behavior of RichTextEditorPanel.kt from Keep-notes-dev
 * using pure Java Spannable API. No AndroidX required.
 */
public class RichTextStyleManager {

    private EditText editText;

    // State tracking for toggles
    private boolean boldActive = false;
    private boolean italicActive = false;
    private boolean underlineActive = false;
    private boolean strikethroughActive = false;
    private boolean bulletListActive = false;
    private boolean numberedListActive = false;
    private boolean codeActive = false;
    private boolean largeFontActive = false;
    private boolean textColorActive = false;
    private boolean highlightActive = false;

    // Default colors matching Keep-notes-dev
    private int textColor = 0xFFFF0000;       // Red
    private int highlightColor = 0xFFFFFF00;  // Yellow

    public RichTextStyleManager(EditText editText) {
        this.editText = editText;
    }

    /**
     * Get current selection start, ensuring valid range.
     */
    private int getSelStart() {
        int start = editText.getSelectionStart();
        return Math.max(0, start);
    }

    /**
     * Get current selection end, ensuring valid range.
     */
    private int getSelEnd() {
        int end = editText.getSelectionEnd();
        return Math.max(0, end);
    }

    /**
     * Check if there is an active text selection.
     */
    private boolean hasSelection() {
        return getSelStart() != getSelEnd();
    }

    // ========== BOLD ==========

    public void toggleBold() {
        boldActive = !boldActive;
        if (hasSelection()) {
            applyBoldToSelection();
        }
    }

    private void applyBoldToSelection() {
        int start = getSelStart();
        int end = getSelEnd();
        Editable text = editText.getText();

        // Check if bold already exists in selection
        StyleSpan[] existing = text.getSpans(start, end, StyleSpan.class);
        boolean hasBold = false;
        for (StyleSpan span : existing) {
            if (span.getStyle() == Typeface.BOLD) {
                text.removeSpan(span);
                hasBold = true;
            }
        }

        if (!hasBold) {
            text.setSpan(new StyleSpan(Typeface.BOLD), start, end,
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        boldActive = !hasBold;
    }

    public boolean isBoldActive() {
        if (hasSelection()) {
            return hasStyleSpan(Typeface.BOLD);
        }
        return boldActive;
    }

    // ========== ITALIC ==========

    public void toggleItalic() {
        italicActive = !italicActive;
        if (hasSelection()) {
            applyItalicToSelection();
        }
    }

    private void applyItalicToSelection() {
        int start = getSelStart();
        int end = getSelEnd();
        Editable text = editText.getText();

        StyleSpan[] existing = text.getSpans(start, end, StyleSpan.class);
        boolean hasItalic = false;
        for (StyleSpan span : existing) {
            if (span.getStyle() == Typeface.ITALIC) {
                text.removeSpan(span);
                hasItalic = true;
            }
        }

        if (!hasItalic) {
            text.setSpan(new StyleSpan(Typeface.ITALIC), start, end,
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        italicActive = !hasItalic;
    }

    public boolean isItalicActive() {
        if (hasSelection()) {
            return hasStyleSpan(Typeface.ITALIC);
        }
        return italicActive;
    }

    // ========== UNDERLINE ==========

    public void toggleUnderline() {
        underlineActive = !underlineActive;
        if (hasSelection()) {
            applyUnderlineToSelection();
        }
    }

    private void applyUnderlineToSelection() {
        int start = getSelStart();
        int end = getSelEnd();
        Editable text = editText.getText();

        UnderlineSpan[] existing = text.getSpans(start, end, UnderlineSpan.class);
        if (existing.length > 0) {
            for (UnderlineSpan span : existing) {
                text.removeSpan(span);
            }
            underlineActive = false;
        } else {
            text.setSpan(new UnderlineSpan(), start, end,
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            underlineActive = true;
        }
    }

    public boolean isUnderlineActive() {
        if (hasSelection()) {
            int start = getSelStart();
            int end = getSelEnd();
            UnderlineSpan[] spans = editText.getText().getSpans(start, end, UnderlineSpan.class);
            return spans.length > 0;
        }
        return underlineActive;
    }

    // ========== STRIKETHROUGH ==========

    public void toggleStrikethrough() {
        strikethroughActive = !strikethroughActive;
        if (hasSelection()) {
            applyStrikethroughToSelection();
        }
    }

    private void applyStrikethroughToSelection() {
        int start = getSelStart();
        int end = getSelEnd();
        Editable text = editText.getText();

        StrikethroughSpan[] existing = text.getSpans(start, end, StrikethroughSpan.class);
        if (existing.length > 0) {
            for (StrikethroughSpan span : existing) {
                text.removeSpan(span);
            }
            strikethroughActive = false;
        } else {
            text.setSpan(new StrikethroughSpan(), start, end,
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            strikethroughActive = true;
        }
    }

    public boolean isStrikethroughActive() {
        if (hasSelection()) {
            int start = getSelStart();
            int end = getSelEnd();
            StrikethroughSpan[] spans = editText.getText().getSpans(start, end, StrikethroughSpan.class);
            return spans.length > 0;
        }
        return strikethroughActive;
    }

    // ========== TEXT COLOR ==========

    public void toggleTextColor() {
        textColorActive = !textColorActive;
        if (hasSelection()) {
            applyTextColorToSelection();
        }
    }

    private void applyTextColorToSelection() {
        int start = getSelStart();
        int end = getSelEnd();
        Editable text = editText.getText();

        ForegroundColorSpan[] existing = text.getSpans(start, end, ForegroundColorSpan.class);
        if (existing.length > 0) {
            for (ForegroundColorSpan span : existing) {
                text.removeSpan(span);
            }
            textColorActive = false;
        } else {
            text.setSpan(new ForegroundColorSpan(textColor), start, end,
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            textColorActive = true;
        }
    }

    public boolean isTextColorActive() {
        if (hasSelection()) {
            int start = getSelStart();
            int end = getSelEnd();
            ForegroundColorSpan[] spans = editText.getText().getSpans(start, end, ForegroundColorSpan.class);
            return spans.length > 0;
        }
        return textColorActive;
    }

    // ========== HIGHLIGHT / BACKGROUND COLOR ==========

    public void toggleHighlight() {
        highlightActive = !highlightActive;
        if (hasSelection()) {
            applyHighlightToSelection();
        }
    }

    private void applyHighlightToSelection() {
        int start = getSelStart();
        int end = getSelEnd();
        Editable text = editText.getText();

        BackgroundColorSpan[] existing = text.getSpans(start, end, BackgroundColorSpan.class);
        if (existing.length > 0) {
            for (BackgroundColorSpan span : existing) {
                text.removeSpan(span);
            }
            highlightActive = false;
        } else {
            text.setSpan(new BackgroundColorSpan(highlightColor), start, end,
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            highlightActive = true;
        }
    }

    public boolean isHighlightActive() {
        if (hasSelection()) {
            int start = getSelStart();
            int end = getSelEnd();
            BackgroundColorSpan[] spans = editText.getText().getSpans(start, end, BackgroundColorSpan.class);
            return spans.length > 0;
        }
        return highlightActive;
    }

    // ========== FONT SIZE TOGGLE ==========

    public void toggleFontSize() {
        largeFontActive = !largeFontActive;
        if (hasSelection()) {
            applyFontSizeToSelection();
        }
    }

    private void applyFontSizeToSelection() {
        int start = getSelStart();
        int end = getSelEnd();
        Editable text = editText.getText();

        RelativeSizeSpan[] existing = text.getSpans(start, end, RelativeSizeSpan.class);
        if (existing.length > 0) {
            for (RelativeSizeSpan span : existing) {
                text.removeSpan(span);
            }
            largeFontActive = false;
        } else {
            // 1.75x size ~ 28sp when base is 16sp
            text.setSpan(new RelativeSizeSpan(1.75f), start, end,
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            largeFontActive = true;
        }
    }

    public boolean isFontSizeActive() {
        if (hasSelection()) {
            int start = getSelStart();
            int end = getSelEnd();
            RelativeSizeSpan[] spans = editText.getText().getSpans(start, end, RelativeSizeSpan.class);
            return spans.length > 0;
        }
        return largeFontActive;
    }

    // ========== ALIGNMENT ==========

    public void setAlignment(Layout.Alignment alignment) {
        int start = getSelStart();
        int end = getSelEnd();
        Editable text = editText.getText();

        // Find line boundaries
        int lineStart = findLineStart(text, start);
        int lineEnd = findLineEnd(text, end);

        // Remove existing alignment spans in range
        AlignmentSpan[] existing = text.getSpans(lineStart, lineEnd, AlignmentSpan.class);
        for (AlignmentSpan span : existing) {
            text.removeSpan(span);
        }

        // Apply new alignment
        text.setSpan(new AlignmentSpan.Standard(alignment), lineStart, lineEnd,
                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
    }

    public Layout.Alignment getCurrentAlignment() {
        int pos = getSelStart();
        Editable text = editText.getText();
        AlignmentSpan[] spans = text.getSpans(pos, pos + 1, AlignmentSpan.class);
        if (spans.length > 0) {
            return spans[spans.length - 1].getAlignment();
        }
        return Layout.Alignment.ALIGN_NORMAL;
    }

    // ========== BULLET LIST ==========

    public void toggleBulletList() {
        bulletListActive = !bulletListActive;
        int start = getSelStart();
        int end = getSelEnd();
        Editable text = editText.getText();

        int lineStart = findLineStart(text, start);
        int lineEnd = findLineEnd(text, end);

        BulletSpan[] existing = text.getSpans(lineStart, lineEnd, BulletSpan.class);
        if (existing.length > 0) {
            for (BulletSpan span : existing) {
                text.removeSpan(span);
            }
            bulletListActive = false;
        } else {
            // Apply bullet to each line in selection
            int pos = lineStart;
            while (pos < lineEnd) {
                int nextNewline = text.toString().indexOf('\n', pos);
                int currentLineEnd;
                if (nextNewline == -1 || nextNewline >= lineEnd) {
                    currentLineEnd = lineEnd;
                } else {
                    currentLineEnd = nextNewline + 1;
                }
                text.setSpan(new BulletSpan(20), pos, currentLineEnd,
                        Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
                pos = currentLineEnd;
            }
            bulletListActive = true;
        }
    }

    public boolean isBulletListActive() {
        int pos = getSelStart();
        Editable text = editText.getText();
        int lineStart = findLineStart(text, pos);
        int lineEnd = findLineEnd(text, pos);
        BulletSpan[] spans = text.getSpans(lineStart, lineEnd, BulletSpan.class);
        return spans.length > 0;
    }

    // ========== CODE / MONOSPACE ==========

    public void toggleCode() {
        codeActive = !codeActive;
        if (hasSelection()) {
            applyCodeToSelection();
        }
    }

    private void applyCodeToSelection() {
        int start = getSelStart();
        int end = getSelEnd();
        Editable text = editText.getText();

        TypefaceSpan[] existing = text.getSpans(start, end, TypefaceSpan.class);
        boolean hasMonospace = false;
        for (TypefaceSpan span : existing) {
            if ("monospace".equals(span.getFamily())) {
                text.removeSpan(span);
                hasMonospace = true;
            }
        }

        if (!hasMonospace) {
            text.setSpan(new TypefaceSpan("monospace"), start, end,
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            // Also add a subtle background
            text.setSpan(new BackgroundColorSpan(0x33FFFFFF), start, end,
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        codeActive = !hasMonospace;
    }

    public boolean isCodeActive() {
        if (hasSelection()) {
            int start = getSelStart();
            int end = getSelEnd();
            TypefaceSpan[] spans = editText.getText().getSpans(start, end, TypefaceSpan.class);
            for (TypefaceSpan span : spans) {
                if ("monospace".equals(span.getFamily())) {
                    return true;
                }
            }
            return false;
        }
        return codeActive;
    }

    // ========== LINK ==========

    public void addLink(String displayText, String url) {
        int start = getSelStart();
        int end = getSelEnd();
        Editable text = editText.getText();

        if (hasSelection()) {
            // Replace selection with link
            text.replace(start, end, displayText);
            end = start + displayText.length();
        } else {
            // Insert at cursor
            text.insert(start, displayText);
            end = start + displayText.length();
        }

        text.setSpan(new URLSpan(url), start, end,
                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
        // Make links blue and underlined
        text.setSpan(new ForegroundColorSpan(0xFF4A90D9), start, end,
                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
        text.setSpan(new UnderlineSpan(), start, end,
                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
    }

    public void removeLink() {
        int start = getSelStart();
        int end = getSelEnd();
        Editable text = editText.getText();

        URLSpan[] spans = text.getSpans(start, end, URLSpan.class);
        for (URLSpan span : spans) {
            text.removeSpan(span);
        }
    }

    /**
     * Get selected text, or empty string if no selection.
     */
    public String getSelectedText() {
        if (hasSelection()) {
            int start = getSelStart();
            int end = getSelEnd();
            return editText.getText().subSequence(start, end).toString();
        }
        return "";
    }

    /**
     * Get URL of link at current cursor position.
     */
    public String getLinkAtCursor() {
        int pos = getSelStart();
        Editable text = editText.getText();
        URLSpan[] spans = text.getSpans(pos, pos + 1, URLSpan.class);
        if (spans.length > 0) {
            return spans[0].getURL();
        }
        return null;
    }

    /**
     * Update all panel button states based on current cursor position.
     * Call this from onSelectionChanged or TextWatcher.
     */
    public void updateStatesFromCursor() {
        int pos = getSelStart();
        if (pos < 0) return;

        Editable text = editText.getText();
        int checkEnd = Math.min(pos + 1, text.length());

        // Bold
        StyleSpan[] styleSpans = text.getSpans(pos, checkEnd, StyleSpan.class);
        boldActive = false;
        italicActive = false;
        for (StyleSpan s : styleSpans) {
            if (s.getStyle() == Typeface.BOLD) boldActive = true;
            if (s.getStyle() == Typeface.ITALIC) italicActive = true;
        }

        // Underline
        UnderlineSpan[] uSpans = text.getSpans(pos, checkEnd, UnderlineSpan.class);
        underlineActive = uSpans.length > 0;

        // Strikethrough
        StrikethroughSpan[] sSpans = text.getSpans(pos, checkEnd, StrikethroughSpan.class);
        strikethroughActive = sSpans.length > 0;

        // Text color
        ForegroundColorSpan[] fSpans = text.getSpans(pos, checkEnd, ForegroundColorSpan.class);
        textColorActive = fSpans.length > 0;

        // Highlight
        BackgroundColorSpan[] bSpans = text.getSpans(pos, checkEnd, BackgroundColorSpan.class);
        highlightActive = bSpans.length > 0;

        // Font size
        RelativeSizeSpan[] rSpans = text.getSpans(pos, checkEnd, RelativeSizeSpan.class);
        largeFontActive = rSpans.length > 0;

        // Code
        TypefaceSpan[] tSpans = text.getSpans(pos, checkEnd, TypefaceSpan.class);
        codeActive = false;
        for (TypefaceSpan t : tSpans) {
            if ("monospace".equals(t.getFamily())) {
                codeActive = true;
                break;
            }
        }
    }

    // ========== HELPER METHODS ==========

    private boolean hasStyleSpan(int style) {
        int start = getSelStart();
        int end = getSelEnd();
        StyleSpan[] spans = editText.getText().getSpans(start, end, StyleSpan.class);
        for (StyleSpan span : spans) {
            if (span.getStyle() == style) {
                return true;
            }
        }
        return false;
    }

    private int findLineStart(CharSequence text, int pos) {
        if (pos <= 0) return 0;
        String str = text.toString();
        int lineStart = str.lastIndexOf('\n', pos - 1);
        return lineStart == -1 ? 0 : lineStart + 1;
    }

    private int findLineEnd(CharSequence text, int pos) {
        String str = text.toString();
        int lineEnd = str.indexOf('\n', pos);
        return lineEnd == -1 ? str.length() : lineEnd;
    }

    // ========== GETTERS FOR UI STATE ==========

    public boolean getBoldActive() { return boldActive; }
    public boolean getItalicActive() { return italicActive; }
    public boolean getUnderlineActive() { return underlineActive; }
    public boolean getStrikethroughActive() { return strikethroughActive; }
    public boolean getBulletListActive() { return bulletListActive; }
    public boolean getCodeActive() { return codeActive; }
    public boolean getLargeFontActive() { return largeFontActive; }
    public boolean getTextColorActive() { return textColorActive; }
    public boolean getHighlightActive() { return highlightActive; }
}
