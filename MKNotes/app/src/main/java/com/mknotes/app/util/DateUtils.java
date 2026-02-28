package com.mknotes.app.util;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;

public class DateUtils {

    public static String formatNoteDate(long timestamp) {
        Calendar now = Calendar.getInstance();
        Calendar noteDate = Calendar.getInstance();
        noteDate.setTimeInMillis(timestamp);

        if (now.get(Calendar.YEAR) == noteDate.get(Calendar.YEAR)) {
            if (now.get(Calendar.DAY_OF_YEAR) == noteDate.get(Calendar.DAY_OF_YEAR)) {
                SimpleDateFormat sdf = new SimpleDateFormat("h:mm a", Locale.getDefault());
                return sdf.format(new Date(timestamp));
            } else if (now.get(Calendar.DAY_OF_YEAR) - noteDate.get(Calendar.DAY_OF_YEAR) == 1) {
                SimpleDateFormat sdf = new SimpleDateFormat("h:mm a", Locale.getDefault());
                return "Yesterday " + sdf.format(new Date(timestamp));
            } else {
                SimpleDateFormat sdf = new SimpleDateFormat("MMM d", Locale.getDefault());
                return sdf.format(new Date(timestamp));
            }
        } else {
            SimpleDateFormat sdf = new SimpleDateFormat("MMM d, yyyy", Locale.getDefault());
            return sdf.format(new Date(timestamp));
        }
    }

    public static String formatEditorDate(long timestamp) {
        SimpleDateFormat sdf = new SimpleDateFormat("EEEE, MMMM d, yyyy h:mm a", Locale.getDefault());
        return sdf.format(new Date(timestamp));
    }
}
