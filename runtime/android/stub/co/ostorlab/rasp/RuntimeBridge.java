package co.ostorlab.rasp;

import android.content.Context;

/** Optional source integration, called after Application attachment, normally from Application.onCreate(). */
public final class RuntimeBridge {
    public static final int INITIALIZED = 0;
    public static final int ALREADY_INITIALIZED = 1;
    public static final int INVALID_CONTEXT = 2;
    public static final int UNAVAILABLE = 3;
    public static final int DIFFERENT_APPLICATION = 4;
    public static final int JNI_ERROR = 5;

    private RuntimeBridge() {}

    /**
     * Supplies the process Application Context without waiting for the monitor or running a check.
     * Only the normalized Application is retained, for process lifetime. Repeated calls are safe.
     *
     * @param context an attached Context; Activity and wrapper inputs are normalized, never retained.
     * @return a result constant; UNAVAILABLE includes absent native registration or incompatible runtime.
     */
    public static int initialize(Context context) {
        try {
            return initializeNative(context);
        } catch (LinkageError error) {
            return UNAVAILABLE;
        }
    }

    private static native int initializeNative(Context context);
}
