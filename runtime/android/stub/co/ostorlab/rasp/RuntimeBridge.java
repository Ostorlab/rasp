package co.ostorlab.rasp;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.*;
import android.view.accessibility.AccessibilityEvent;
import java.lang.ref.WeakReference;
import java.util.List;

/** Optional source integration, called after Application attachment, normally from Application.onCreate(). */
public final class RuntimeBridge {
    public static final int INITIALIZED = 0;
    public static final int ALREADY_INITIALIZED = 1;
    public static final int INVALID_CONTEXT = 2;
    public static final int UNAVAILABLE = 3;
    public static final int DIFFERENT_APPLICATION = 4;
    public static final int JNI_ERROR = 5;

    public static final int WRONG_THREAD = 6;
    public static final int UNSUPPORTED = 7;
    public static final int NOT_INITIALIZED = 8;
    public static final int WINDOW_LIMIT = 9;
    public static final int OWNERSHIP_LOST = 10;

    private static Session windows;

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

    /**
     * Opts in to received-touch observations after initialize(application). Call on the main thread.
     * New Activity windows attach after resume and detach before pause. For an already resumed Activity,
     * or a Dialog, call attachWindow(window) explicitly. No Activity enumeration or private API is used.
     * Returns INITIALIZED, ALREADY_INITIALIZED or a failure constant. Does not change check selection.
     */
    public static int startWindowObservation(Application application) {
        if (Looper.myLooper() != Looper.getMainLooper()) return WRONG_THREAD;
        if (application == null) return INVALID_CONTEXT;
        if (windows != null) return windows.application == application ? ALREADY_INITIALIZED : DIFFERENT_APPLICATION;
        long epoch = 0;
        Session session = null;
        try {
            if (Build.VERSION.SDK_INT < 31) {
                stopWindowsNative(0, 2);
                return UNSUPPORTED;
            }
            epoch = startWindowsNative(application);
            if (epoch <= 0) return (int) -epoch;
            session = new Session(application, epoch);
            windows = session;
            application.registerActivityLifecycleCallbacks(session);
            if (!session.handler.postDelayed(session, 1000)) throw new IllegalStateException("main looper stopped");
            return INITIALIZED;
        } catch (LinkageError error) {
            cleanupFailedStart(session, epoch);
            return epoch > 0 ? JNI_ERROR : UNAVAILABLE;
        } catch (RuntimeException error) {
            cleanupFailedStart(session, epoch);
            return JNI_ERROR;
        }
    }

    private static void cleanupFailedStart(Session session, long epoch) {
        if (session != null) {
            session.stop(1);
        } else if (epoch > 0) {
            try {
                stopWindowsNative(epoch, 1);
            } catch (RuntimeException | LinkageError error) {
                // Native registration/availability metadata remains unknown if the boundary itself is unavailable.
            }
        }
    }

    /** Stops observation, disables old wrappers, unregisters callbacks and restores only callbacks still owned.
     * Main thread only; repeated stops are safe. Wrappers retained in a newer host chain remain inert delegates.
     */
    public static int stopWindowObservation() {
        if (Looper.myLooper() != Looper.getMainLooper()) return WRONG_THREAD;
        if (windows == null) return ALREADY_INITIALIZED;
        Session session = windows;
        windows = null;
        return session.stop(0);
    }

    /** Explicitly attaches an app-owned, currently active window (including Dialogs); max 32 simultaneous windows.
     * Main thread only. Caller must detach manual windows on dismissal/pause. Never pass another app's window.
     */
    public static int attachWindow(Window window) {
        if (Looper.myLooper() != Looper.getMainLooper()) return WRONG_THREAD;
        if (windows == null) return NOT_INITIALIZED;
        return windows.attach(window);
    }

    /** Detaches one window without overwriting a callback installed by the host after attachment. Main thread only. */
    public static int detachWindow(Window window) {
        if (Looper.myLooper() != Looper.getMainLooper()) return WRONG_THREAD;
        if (windows == null) return NOT_INITIALIZED;
        return windows.detach(window);
    }

    private static native long startWindowsNative(Application application);
    private static native void stopWindowsNative(long epoch, int reason);
    private static native boolean windowEventNative(long epoch, int token, int kind, int flags);

    private static boolean event(long epoch, int token, int kind, int flags) {
        try {
            return windowEventNative(epoch, token, kind, flags);
        } catch (RuntimeException | LinkageError error) {
            return false;
        }
    }

    private static final class Entry {
        final WeakReference<Window> window;
        final WeakReference<TouchCallback> callback;
        final int token;
        Entry(Window window, TouchCallback callback, int token) {
            this.window = new WeakReference<>(window);
            this.callback = new WeakReference<>(callback);
            this.token = token;
        }
    }

    private static final class Session implements Application.ActivityLifecycleCallbacks, Runnable {
        final Application application;
        final long epoch;
        final Handler handler = new Handler(Looper.getMainLooper());
        final Entry[] entries = new Entry[32];
        int nextToken = 1;
        boolean active = true;

        Session(Application application, long epoch) {
            this.application = application;
            this.epoch = epoch;
        }

        void fault() { event(epoch, 0, 5, 0); }

        int attach(Window window) {
            if (!active || window == null) return INVALID_CONTEXT;
            int empty = -1;
            for (int index = 0; index < entries.length; index++) {
                Entry entry = entries[index];
                if (entry == null) {
                    if (empty < 0) empty = index;
                } else if (entry.window.get() == window) {
                    TouchCallback callback = entry.callback.get();
                    try {
                        if (callback != null && callback.enabled && window.getCallback() == callback) return ALREADY_INITIALIZED;
                        release(index, true);
                        return OWNERSHIP_LOST;
                    } catch (RuntimeException | LinkageError error) {
                        release(index, true);
                        fault();
                        return JNI_ERROR;
                    }
                }
            }
            if (empty < 0 || nextToken == Integer.MAX_VALUE) {
                fault();
                return WINDOW_LIMIT;
            }
            try {
                Window.Callback delegate = window.getCallback();
                if (delegate == null) { fault(); return INVALID_CONTEXT; }
                int token = nextToken++;
                TouchCallback callback = new TouchCallback(window, delegate, epoch, token);
                entries[empty] = new Entry(window, callback, token);
                if (!event(epoch, token, 1, 0)) {
                    entries[empty] = null;
                    return JNI_ERROR;
                }
                callback.registered = true;
                window.setCallback(callback);
                callback.enabled = true;
                return INITIALIZED;
            } catch (RuntimeException | LinkageError error) {
                release(empty, true);
                fault();
                return JNI_ERROR;
            }
        }

        int detach(Window window) {
            if (window == null) return INVALID_CONTEXT;
            for (int index = 0; index < entries.length; index++) {
                Entry entry = entries[index];
                if (entry != null && entry.window.get() == window) return release(index, false);
            }
            return ALREADY_INITIALIZED;
        }

        int release(int index, boolean lost) {
            Entry entry = entries[index];
            entries[index] = null;
            if (entry == null) return ALREADY_INITIALIZED;
            TouchCallback callback = entry.callback.get();
            Window window = entry.window.get();
            boolean wasRegistered = callback == null || callback.registered;
            if (callback != null) callback.enabled = false;
            try {
                boolean owned = callback != null && window != null && window.getCallback() == callback;
                if (wasRegistered) event(epoch, entry.token, lost || !owned ? 4 : 2, 0);
                if (callback != null) callback.registered = false;
                if (owned) window.setCallback(callback.delegate);
                return lost || !owned ? OWNERSHIP_LOST : INITIALIZED;
            } catch (RuntimeException | LinkageError error) {
                if (callback == null || callback.registered) event(epoch, entry.token, 4, 0);
                if (callback != null) callback.registered = false;
                fault();
                return JNI_ERROR;
            }
        }

        int stop(int reason) {
            active = false;
            if (windows == this) windows = null;
            // Disable all wrappers before touching the host's callback chain or releasing entries.
            for (Entry entry : entries) {
                if (entry != null) {
                    TouchCallback callback = entry.callback.get();
                    if (callback != null) callback.enabled = false;
                }
            }
            int result = INITIALIZED;
            for (int index = 0; index < entries.length; index++) {
                if (release(index, false) == JNI_ERROR) result = JNI_ERROR;
            }
            try {
                handler.removeCallbacks(this);
            } catch (RuntimeException | LinkageError error) {
                result = JNI_ERROR;
            }
            try {
                application.unregisterActivityLifecycleCallbacks(this);
            } catch (RuntimeException | LinkageError error) {
                result = JNI_ERROR;
            }
            try {
                stopWindowsNative(epoch, reason == 0 && result == INITIALIZED ? 0 : 1);
            } catch (RuntimeException | LinkageError error) {
                result = JNI_ERROR;
            }
            return result;
        }

        @Override public void run() {
            if (!active) return;
            for (int index = 0; index < entries.length; index++) {
                Entry entry = entries[index];
                if (entry == null) continue;
                TouchCallback callback = entry.callback.get();
                Window window = entry.window.get();
                try {
                    if (callback == null || window == null || !callback.enabled || window.getCallback() != callback) {
                        release(index, true);
                    }
                } catch (RuntimeException | LinkageError error) {
                    release(index, true);
                    fault();
                }
            }
            try {
                if (!handler.postDelayed(this, 1000)) throw new IllegalStateException("main looper stopped");
            } catch (RuntimeException | LinkageError error) {
                stop(1);
            }
        }

        void activityWindow(Activity activity, boolean attachWindow) {
            if (!active) return;
            try {
                if (attachWindow) {
                    handler.removeCallbacks(this);
                    run();
                }
                if (!active) return;
                Window window = activity.getWindow();
                if (window == null) { stop(1); return; }
                if (attachWindow) attach(window);
                else detach(window);
            } catch (RuntimeException | LinkageError error) {
                stop(1);
            }
        }
        @Override public void onActivityPostResumed(Activity activity) { activityWindow(activity, true); }
        @Override public void onActivityPrePaused(Activity activity) { activityWindow(activity, false); }
        @Override public void onActivityStopped(Activity activity) { activityWindow(activity, false); }
        @Override public void onActivityDestroyed(Activity activity) { activityWindow(activity, false); }
        @Override public void onActivityCreated(Activity activity, Bundle state) {}
        @Override public void onActivityStarted(Activity activity) {}
        @Override public void onActivityResumed(Activity activity) {}
        @Override public void onActivityPaused(Activity activity) {}
        @Override public void onActivitySaveInstanceState(Activity activity, Bundle state) {}
    }

    private static final class TouchCallback implements Window.Callback {
        final Window.Callback delegate;
        final WeakReference<Window> window;
        final long epoch;
        final int token;
        boolean enabled;
        boolean registered;

        TouchCallback(Window window, Window.Callback delegate, long epoch, int token) {
            this.window = new WeakReference<>(window);
            this.delegate = delegate;
            this.epoch = epoch;
            this.token = token;
        }

        @Override public boolean dispatchTouchEvent(MotionEvent motion) {
            if (enabled) {
                try {
                    Window current = window.get();
                    if (Looper.myLooper() != Looper.getMainLooper() || current == null || current.getCallback() != this) {
                        enabled = false;
                        event(epoch, token, 4, 0);
                        registered = false;
                    } else if (motion != null) {
                        if (!event(epoch, token, 3, motion.getFlags() &
                                (MotionEvent.FLAG_WINDOW_IS_OBSCURED | MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED))) {
                            enabled = false;
                        }
                    }
                } catch (RuntimeException | LinkageError error) {
                    enabled = false;
                    event(epoch, token, 4, 0);
                    registered = false;
                }
            }
            return delegate.dispatchTouchEvent(motion);
        }

        @Override public void onDetachedFromWindow() {
            if (registered) { enabled = false; registered = false; event(epoch, token, 2, 0); }
            delegate.onDetachedFromWindow();
        }
        @Override public boolean dispatchKeyEvent(KeyEvent event) { return delegate.dispatchKeyEvent(event); }
        @Override public boolean dispatchKeyShortcutEvent(KeyEvent event) { return delegate.dispatchKeyShortcutEvent(event); }
        @Override public boolean dispatchTrackballEvent(MotionEvent event) { return delegate.dispatchTrackballEvent(event); }
        @Override public boolean dispatchGenericMotionEvent(MotionEvent event) { return delegate.dispatchGenericMotionEvent(event); }
        @Override public boolean dispatchPopulateAccessibilityEvent(AccessibilityEvent event) { return delegate.dispatchPopulateAccessibilityEvent(event); }
        @Override public View onCreatePanelView(int feature) { return delegate.onCreatePanelView(feature); }
        @Override public boolean onCreatePanelMenu(int feature, Menu menu) { return delegate.onCreatePanelMenu(feature, menu); }
        @Override public boolean onPreparePanel(int feature, View view, Menu menu) { return delegate.onPreparePanel(feature, view, menu); }
        @Override public boolean onMenuOpened(int feature, Menu menu) { return delegate.onMenuOpened(feature, menu); }
        @Override public boolean onMenuItemSelected(int feature, MenuItem item) { return delegate.onMenuItemSelected(feature, item); }
        @Override public void onWindowAttributesChanged(WindowManager.LayoutParams attrs) { delegate.onWindowAttributesChanged(attrs); }
        @Override public void onContentChanged() { delegate.onContentChanged(); }
        @Override public void onWindowFocusChanged(boolean focused) { delegate.onWindowFocusChanged(focused); }
        @Override public void onAttachedToWindow() { delegate.onAttachedToWindow(); }
        @Override public void onPanelClosed(int feature, Menu menu) { delegate.onPanelClosed(feature, menu); }
        @Override public boolean onSearchRequested() { return delegate.onSearchRequested(); }
        @Override public boolean onSearchRequested(SearchEvent event) { return delegate.onSearchRequested(event); }
        @Override public ActionMode onWindowStartingActionMode(ActionMode.Callback callback) { return delegate.onWindowStartingActionMode(callback); }
        @Override public ActionMode onWindowStartingActionMode(ActionMode.Callback callback, int type) { return delegate.onWindowStartingActionMode(callback, type); }
        @Override public void onActionModeStarted(ActionMode mode) { delegate.onActionModeStarted(mode); }
        @Override public void onActionModeFinished(ActionMode mode) { delegate.onActionModeFinished(mode); }
        @Override public void onProvideKeyboardShortcuts(List<KeyboardShortcutGroup> data, Menu menu, int device) { delegate.onProvideKeyboardShortcuts(data, menu, device); }
        @Override public void onPointerCaptureChanged(boolean captured) { delegate.onPointerCaptureChanged(captured); }
    }
}
