package com.mknotes.app.receiver;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

import com.mknotes.app.NoteEditorActivity;
import com.mknotes.app.NotesApplication;
import com.mknotes.app.R;

public class ReminderReceiver extends BroadcastReceiver {

    public void onReceive(Context context, Intent intent) {
        long noteId = intent.getLongExtra("note_id", -1);
        String noteTitle = intent.getStringExtra("note_title");

        if (noteId == -1) return;

        if (noteTitle == null || noteTitle.length() == 0) {
            noteTitle = context.getString(R.string.reminder);
        }

        Intent openIntent = new Intent(context, NoteEditorActivity.class);
        openIntent.putExtra("note_id", noteId);
        int piFlags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= 31) {
            piFlags = piFlags | 0x04000000; // FLAG_IMMUTABLE = 0x04000000
        }
        PendingIntent pendingIntent = PendingIntent.getActivity(
                context, (int) noteId, openIntent, piFlags);

        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= 26) {
            builder = new Notification.Builder(context, NotesApplication.CHANNEL_ID_REMINDER);
        } else {
            builder = new Notification.Builder(context);
        }

        builder.setSmallIcon(R.drawable.ic_notification)
                .setContentTitle(context.getString(R.string.app_name))
                .setContentText(noteTitle)
                .setContentIntent(pendingIntent)
                .setAutoCancel(true);

        NotificationManager nm = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm != null) {
            nm.notify((int) noteId, builder.build());
        }
    }
}
