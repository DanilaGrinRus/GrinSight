package org.grinsight.fly;

import android.app.NativeActivity;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;

/**
 * The window: Slint draws it from libfly_ui.so. Before it, the core service
 * is started; the window connects to the wallet process the service keeps.
 */
public class FlyActivity extends NativeActivity {
    @Override
    protected void onCreate(Bundle state) {
        Intent core = new Intent(this, CoreService.class);
        if (Build.VERSION.SDK_INT >= 26) {
            startForegroundService(core);
        } else {
            startService(core);
        }
        if (Build.VERSION.SDK_INT >= 33) {
            // the notice that the wallet is open; the service runs without it too
            requestPermissions(new String[] {"android.permission.POST_NOTIFICATIONS"}, 1);
        }
        super.onCreate(state);
    }
}
