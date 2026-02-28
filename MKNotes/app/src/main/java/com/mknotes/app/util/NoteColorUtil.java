package com.mknotes.app.util;

import android.graphics.Color;

/**
 * NotallyX-style color palette for note backgrounds.
 * Supports both preset palette (12 indexed colors) AND custom colors from the color wheel.
 * 
 * Color storage strategy:
 * - Values 0..11 = preset palette index (legacy + preset support)
 * - Value -1 = DEFAULT (white background)
 * - Values >= 100 = raw ARGB color stored directly (custom wheel colors)
 *   The raw color is stored as: colorInt itself (always has alpha=0xFF, so it's > 100)
 * 
 * When reading from DB: if color == 0 or color == -1, treat as DEFAULT WHITE.
 * If color is 1..11, look up preset palette.
 * If color is anything else (large positive or negative), treat as raw ARGB color int.
 */
public class NoteColorUtil {

    // Special sentinel for default (white)
    public static final int COLOR_DEFAULT = 0;

    // Preset palette indices
    public static final int COLOR_CORAL = 1;
    public static final int COLOR_ORANGE = 2;
    public static final int COLOR_SAND = 3;
    public static final int COLOR_STORM = 4;
    public static final int COLOR_FOG = 5;
    public static final int COLOR_SAGE = 6;
    public static final int COLOR_MINT = 7;
    public static final int COLOR_DUSK = 8;
    public static final int COLOR_FLOWER = 9;
    public static final int COLOR_BLOSSOM = 10;
    public static final int COLOR_CLAY = 11;

    // Default background color = WHITE
    public static final int DEFAULT_BG_COLOR = Color.WHITE;

    // NotallyX color hex values
    private static final String[] COLOR_HEX = {
            "#FFFFFF",    // 0  - DEFAULT (White)
            "#FAAFA9",    // 1  - Coral
            "#FFCC80",    // 2  - Orange
            "#FFF8B9",    // 3  - Sand
            "#AFCCDC",    // 4  - Storm
            "#D3E4EC",    // 5  - Fog
            "#B4DED4",    // 6  - Sage
            "#E2F6D3",    // 7  - Mint
            "#D3BFDB",    // 8  - Dusk
            "#F8BBD0",    // 9  - Flower
            "#F5E2DC",    // 10 - Blossom
            "#E9E3D3",    // 11 - Clay
    };

    // Color display names
    private static final String[] COLOR_NAMES = {
            "Default",
            "Coral",
            "Orange",
            "Sand",
            "Storm",
            "Fog",
            "Sage",
            "Mint",
            "Dusk",
            "Flower",
            "Blossom",
            "Clay",
    };

    // Parsed color int values (lazy init)
    private static int[] sColorValues;

    private static void ensureColors() {
        if (sColorValues != null) return;
        sColorValues = new int[COLOR_HEX.length];
        for (int i = 0; i < COLOR_HEX.length; i++) {
            sColorValues[i] = Color.parseColor(COLOR_HEX[i]);
        }
    }

    /**
     * Get the background color int for a given color index.
     * Index 0 (default) returns WHITE.
     * Index 1-11 returns preset colors.
     */
    public static int getPresetColor(int index) {
        ensureColors();
        if (index >= 0 && index < sColorValues.length) {
            return sColorValues[index];
        }
        return DEFAULT_BG_COLOR;
    }

    /**
     * Resolve a stored color value to an actual ARGB color int.
     * - 0 = default (WHITE)
     * - 1..11 = preset palette
     * - anything else = raw ARGB color int (custom from wheel)
     */
    public static int resolveColor(int storedColor) {
        if (storedColor == 0) {
            return DEFAULT_BG_COLOR;
        }
        if (storedColor >= 1 && storedColor <= 11) {
            return getPresetColor(storedColor);
        }
        // Raw ARGB color int from the color wheel
        // Ensure it has full alpha
        return storedColor | 0xFF000000;
    }

    /**
     * Check if a stored color value represents the default white.
     */
    public static boolean isDefault(int storedColor) {
        return storedColor == 0;
    }

    /**
     * Check if a stored color value is a preset palette color (1-11).
     */
    public static boolean isPreset(int storedColor) {
        return storedColor >= 1 && storedColor <= 11;
    }

    /**
     * Check if a stored color value is a custom wheel color.
     */
    public static boolean isCustom(int storedColor) {
        return storedColor != 0 && (storedColor < 1 || storedColor > 11);
    }

    /**
     * Find matching preset index for a given ARGB color, or -1 if no match.
     */
    public static int findPresetIndex(int argbColor) {
        ensureColors();
        for (int i = 0; i < sColorValues.length; i++) {
            if (sColorValues[i] == argbColor) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Get the hex string for a given preset color index.
     */
    public static String getColorHex(int index) {
        if (index >= 0 && index < COLOR_HEX.length) {
            return COLOR_HEX[index];
        }
        return "#FFFFFF";
    }

    /**
     * Get the display name for a given preset color index.
     */
    public static String getColorName(int index) {
        if (index >= 0 && index < COLOR_NAMES.length) {
            return COLOR_NAMES[index];
        }
        return "Custom";
    }

    public static int getPresetCount() {
        return COLOR_HEX.length;
    }

    public static int[] getAllPresetColors() {
        ensureColors();
        return sColorValues;
    }

    /**
     * Determines if a color is "light" using relative luminance.
     * Used to decide whether to show dark or light text/icons on top.
     */
    public static boolean isLightColor(int color) {
        int r = Color.red(color);
        int g = Color.green(color);
        int b = Color.blue(color);
        // Relative luminance formula (ITU-R BT.709)
        double luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255.0;
        return luminance > 0.5;
    }

    /**
     * Returns the appropriate text color (dark or light) for contrast
     * against the given background color.
     */
    public static int getContrastTextColor(int bgColor) {
        if (isLightColor(bgColor)) {
            return Color.parseColor("#1A1B21"); // Dark text
        } else {
            return Color.parseColor("#FFFFFF"); // Light text
        }
    }

    /**
     * Returns the appropriate secondary/hint text color for contrast.
     */
    public static int getContrastHintColor(int bgColor) {
        if (isLightColor(bgColor)) {
            return Color.parseColor("#45464F"); // Dark hint
        } else {
            return Color.parseColor("#B0B0B0"); // Light hint
        }
    }

    /**
     * Returns the appropriate icon tint color for contrast.
     */
    public static int getContrastIconColor(int bgColor) {
        if (isLightColor(bgColor)) {
            return Color.parseColor("#2F3036"); // Dark icon
        } else {
            return Color.parseColor("#E0E0E0"); // Light icon
        }
    }

    /**
     * Returns a slightly darkened version of the color for toolbar/bottom bar.
     */
    public static int getDarkerShade(int color) {
        float[] hsv = new float[3];
        Color.colorToHSV(color, hsv);
        hsv[2] = hsv[2] * 0.88f; // 12% darker
        return Color.HSVToColor(hsv);
    }

    /**
     * Returns a slightly lighter version of the color for panels.
     */
    public static int getLighterShade(int color) {
        float[] hsv = new float[3];
        Color.colorToHSV(color, hsv);
        hsv[1] = hsv[1] * 0.7f; // Less saturation
        hsv[2] = Math.min(hsv[2] * 1.1f, 1.0f); // Slightly brighter
        return Color.HSVToColor(hsv);
    }
}
