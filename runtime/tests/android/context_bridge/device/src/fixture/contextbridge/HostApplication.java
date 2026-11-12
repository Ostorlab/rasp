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
                Log.i("ContextBridgeFixture", "initialized after attachment");
            }
        }, 10000);
    }
}
