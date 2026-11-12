package fixture.contextbridge;

import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.TextView;
import co.ostorlab.rasp.RuntimeBridge;

/** Real SDK Activity; normal touches use actual OS MotionEvents, never fabricated obscuration flags. */
public final class MainActivity extends android.app.Activity {
    private boolean resumed;
    @Override public void onCreate(android.os.Bundle state) {
        super.onCreate(state);
        TextView view = new TextView(this);
        view.setText("Observation fixture: tap, rotate, pause/resume. Screenshot observation shows an Android notice. Use only neutral screen content for screenshot/recording tests. No input or captured content is collected.");
        setContentView(view);
    }
    @Override public void onResume() {
        super.onResume();
        resumed = true;
        new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
            @Override public void run() {
                if (!resumed) return;
                int attached = RuntimeBridge.attachWindow(getWindow());
                if (attached != RuntimeBridge.INITIALIZED && attached != RuntimeBridge.ALREADY_INITIALIZED) {
                    throw new AssertionError("window attach result " + attached);
                }
                Log.i("WindowBridgeFixture", "active window attached");
                int capture = RuntimeBridge.attachCaptureActivity(MainActivity.this);
                if (capture != RuntimeBridge.INITIALIZED && capture != RuntimeBridge.ALREADY_INITIALIZED
                        && capture != RuntimeBridge.PARTIAL && capture != RuntimeBridge.UNSUPPORTED
                        && capture != RuntimeBridge.PERMISSION_REQUIRED) {
                    throw new AssertionError("capture attach result " + capture);
                }
            }
        }, 11000);
    }
    @Override public void onPause() { resumed = false; super.onPause(); }
}
