package com.mknotes.app.receiver;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.view.KeyEvent;

import com.mknotes.app.meditation.MeditationPlayerManager;

/**
 * Handles media button events (earphone/bluetooth pause/play).
 * Toggle behavior: if playing -> pause, if paused -> resume.
 * Pure Java, no AndroidX, no lambda - AIDE compatible.
 */
public class MediaButtonReceiver extends BroadcastReceiver {

    public void onReceive(Context context, Intent intent) {
        if (intent == null) return;

        String action = intent.getAction();
        if (Intent.ACTION_MEDIA_BUTTON.equals(action)) {
            KeyEvent event = (KeyEvent) intent.getParcelableExtra(Intent.EXTRA_KEY_EVENT);
            if (event == null) return;

            if (event.getAction() == KeyEvent.ACTION_DOWN) {
                int keyCode = event.getKeyCode();
                switch (keyCode) {
                    case KeyEvent.KEYCODE_MEDIA_PAUSE:
                    case KeyEvent.KEYCODE_MEDIA_PLAY:
                    case KeyEvent.KEYCODE_MEDIA_PLAY_PAUSE:
                    case KeyEvent.KEYCODE_HEADSETHOOK:
                        // Toggle play/pause
                        MeditationPlayerManager player =
                                MeditationPlayerManager.getInstance(context);
                        player.handleMediaButton();
                        break;

                    case KeyEvent.KEYCODE_MEDIA_STOP:
                        // Full stop
                        MeditationPlayerManager stopPlayer =
                                MeditationPlayerManager.getInstance(context);
                        if (stopPlayer.isCurrentlyPlaying()) {
                            stopPlayer.stopPlayback();
                            try {
                                Intent svcIntent = new Intent(context,
                                        com.mknotes.app.service.MeditationService.class);
                                svcIntent.setAction(
                                        com.mknotes.app.service.MeditationService.ACTION_STOP);
                                context.startService(svcIntent);
                            } catch (Exception e) { }
                        }
                        break;
                }
            }
        }
    }
}
