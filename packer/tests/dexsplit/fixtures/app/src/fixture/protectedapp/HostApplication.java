package fixture.protectedapp;

import android.app.Application;
import android.util.Log;
import co.ostorlab.rasp.RuntimeBridge;

/** The bridge is compile-only; the unprotected baseline remains runnable without it. */
public final class HostApplication extends Application {
    @Override public void onCreate() {
        super.onCreate();
        try {
            Log.i("PK02", "BRIDGE=" + RuntimeBridge.initialize(this));
        } catch (NoClassDefFoundError baseline) {
            Log.i("PK02", "BRIDGE=unprotected-baseline");
        }
    }
}
