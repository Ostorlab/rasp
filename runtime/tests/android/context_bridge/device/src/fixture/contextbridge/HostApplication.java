package fixture.contextbridge;

import android.app.Application;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import co.ostorlab.rasp.RuntimeBridge;

/** Source-integrated host; delay beyond the first bounded identity lookup to exercise the next monitor pass. */
public final class HostApplication extends Application {
    @Override public void onCreate() {
        super.onCreate();
        new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
            @Override public void run() {
                int first = RuntimeBridge.initialize(HostApplication.this);
                int repeated = RuntimeBridge.initialize(HostApplication.this);
                if (first != RuntimeBridge.INITIALIZED || repeated != RuntimeBridge.ALREADY_INITIALIZED) {
                    throw new AssertionError("bridge results " + first + "/" + repeated);
                }
                int started = RuntimeBridge.startWindowObservation(HostApplication.this);
                if (started != RuntimeBridge.INITIALIZED || RuntimeBridge.startWindowObservation(HostApplication.this) != RuntimeBridge.ALREADY_INITIALIZED) {
                    throw new AssertionError("window start result " + started);
                }
                Log.i("WindowBridgeFixture", "window adapter started");
                int capture = RuntimeBridge.startCaptureObservation(HostApplication.this, true, true);
                if (capture != RuntimeBridge.INITIALIZED && capture != RuntimeBridge.PARTIAL
                        && capture != RuntimeBridge.UNSUPPORTED && capture != RuntimeBridge.PERMISSION_REQUIRED) {
                    throw new AssertionError("capture start result " + capture);
                }
                Log.i("CaptureBridgeFixture", "capture lifecycle adapter started: " + capture);
                Log.i("ContextBridgeFixture", "initialized after attachment");
            }
        }, 10000);
    }
}
