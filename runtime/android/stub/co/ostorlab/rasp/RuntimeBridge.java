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

    public static final int ACTIVITY_LIMIT = 11;
    public static final int PERMISSION_REQUIRED = 12;
    public static final int PARTIAL = 13;
    public static final int INVALID_OPTIONS = 14;
    private static CaptureSession captures;

    /** Opts in independently to resumed-Activity screenshots and UID-scoped recording visibility.
     * Call after initialize(application), on the main thread. Selection and manifest permissions are separate.
     */
    public static int startCaptureObservation(Application application, boolean screenshots, boolean recording) {
        if (Looper.myLooper() != Looper.getMainLooper()) return WRONG_THREAD;
        if (application == null) return INVALID_CONTEXT;
        if (!screenshots && !recording) return INVALID_OPTIONS;
        if (captures != null) {
            if (captures.application != application) return DIFFERENT_APPLICATION;
            if (captures.active) return captures.screenshots == screenshots && captures.recording == recording
                    ? ALREADY_INITIALIZED : INVALID_OPTIONS;
            if (!captures.cleanup()) return JNI_ERROR;
            captures = null;
        }
        CaptureSession session = null;
        try {
            long epoch = startCaptureNative(application, screenshots, recording);
            if (epoch <= 0) return (int) -epoch;
            session = new CaptureSession(application, epoch, screenshots, recording);
            captures = session;
            int result = session.permissions();
            session.lifecycle = true;
            application.registerActivityLifecycleCallbacks(session);
            return result;
        } catch (RuntimeException | LinkageError error) {
            if (session != null) { session.stop(); session.failSource(0); session.failSource(1); return JNI_ERROR; }
            return error instanceof LinkageError ? UNAVAILABLE : JNI_ERROR;
        }
    }

    /** Attaches an already resumed host Activity; no Activity inventory is queried. Main thread only. */
    public static int attachCaptureActivity(Activity activity) {
        if (Looper.myLooper() != Looper.getMainLooper()) return WRONG_THREAD;
        if (captures == null || !captures.active) return NOT_INITIALIZED;
        return captures.attach(activity);
    }

    /** Invalidates Activity callback generations before public removal. Main thread only. */
    public static int detachCaptureActivity(Activity activity) {
        if (Looper.myLooper() != Looper.getMainLooper()) return WRONG_THREAD;
        if (captures == null || !captures.active) return NOT_INITIALIZED;
        return captures.detach(activity);
    }

    /** Stops capture only; unresolved inert registrations remain bounded across restarts. Main thread only. */
    public static int stopCaptureObservation() {
        if (Looper.myLooper() != Looper.getMainLooper()) return WRONG_THREAD;
        if (captures == null) return ALREADY_INITIALIZED;
        return captures.stop();
    }

    private static native long startCaptureNative(Application application, boolean screenshots, boolean recording);
    private static native void stopCaptureNative(long epoch);
    private static native boolean captureEventNative(long epoch, int source, int token, int kind, int value);

    private static final class CaptureEntry {
        final WeakReference<Activity> activity;
        final int token;
        Object shot;
        boolean eligible = true;
        boolean shotOpen;
        boolean recordingOpen;
        boolean shotFailed;
        CaptureEntry(Activity activity, int token) { this.activity = new WeakReference<>(activity); this.token = token; }
    }

    private static final class CaptureSession implements Application.ActivityLifecycleCallbacks {
        final Application application;
        final long epoch;
        final boolean screenshots;
        final boolean recording;
        final CaptureEntry[] entries = new CaptureEntry[32];
        final int[] permissionStates = new int[2];
        int nextToken = 1;
        volatile boolean active = true;
        boolean lifecycle;
        boolean nativeStopped;
        volatile boolean screenshotFault;
        volatile boolean recordingFault;
        RecordCallback recorder;
        CaptureEntry recordingOwner;
        WeakReference<WindowManager> recordingManager;

        CaptureSession(Application application, long epoch, boolean screenshots, boolean recording) {
            this.application = application; this.epoch = epoch; this.screenshots = screenshots; this.recording = recording;
        }
        boolean supported(int source) { return Build.VERSION.SDK_INT >= (source == 0 ? 34 : 35); }
        boolean requested(int source) { return source == 0 ? screenshots : recording; }
        boolean emit(int source, int token, int kind, int value) {
            if (nativeStopped && kind == 2) return true;
            try { return captureEventNative(epoch, source, token, kind, value); }
            catch (RuntimeException | LinkageError error) { return false; }
        }
        void state(int source, int value) { if (supported(source) && requested(source)) emit(source, 0, 5, value); }
        void loss(int source) { if (supported(source) && requested(source)) emit(source, 0, 7, 0); }
        void failSource(int source) {
            if (source == 0) screenshotFault = true; else recordingFault = true;
            state(source, 11); loss(source);
        }
        int permission(int source) {
            if (!supported(source) || !requested(source)) return permissionStates[source] = 1;
            int result = 0;
            try {
                String permission = source == 0 ? "android.permission.DETECT_SCREEN_CAPTURE" : "android.permission.DETECT_SCREEN_RECORDING";
                android.content.pm.PackageInfo info = application.getPackageManager().getPackageInfo(
                        application.getPackageName(), android.content.pm.PackageManager.GET_PERMISSIONS);
                if (info == null) throw new IllegalStateException("own manifest unavailable");
                String[] declared = info.requestedPermissions;
                if (declared != null && declared.length > 1024) throw new IllegalStateException("permission bound");
                result = 2;
                if (declared != null) for (String name : declared) if (permission.equals(name)) {
                    result = application.checkSelfPermission(permission) == android.content.pm.PackageManager.PERMISSION_GRANTED ? 4 : 3;
                    break;
                }
                boolean removed = true;
                if (result != 4) {
                    if (source == 0) {
                        for (CaptureEntry entry : entries) if (entry != null && !removeShot(entry)) removed = false;
                    } else removed = removeRecording();
                }
                emit(source, 0, 6, result);
                if (!removed) state(source, 10);
            } catch (android.content.pm.PackageManager.NameNotFoundException | RuntimeException | LinkageError error) {
                result = 0;
                if (source == 0) { for (CaptureEntry entry : entries) if (entry != null) removeShot(entry); }
                else removeRecording();
                emit(source, 0, 6, 0); state(source, 11); loss(source);
            }
            permissionStates[source] = result;
            return result;
        }
        int permissions() {
            int usable = 0, asked = 0, supported = 0;
            boolean failed = false;
            for (int source = 0; source < 2; source++) if (requested(source)) {
                asked++;
                if (supported(source)) {
                    supported++; int checked = permission(source);
                    if (checked == 4) usable++;
                    else if (checked == 0) failed = true;
                }
            }
            return usable == asked ? INITIALIZED : usable > 0 ? PARTIAL : supported == 0 ? UNSUPPORTED
                    : failed ? JNI_ERROR : PERMISSION_REQUIRED;
        }
        boolean granted(int source) {
            try {
                String permission = source == 0 ? "android.permission.DETECT_SCREEN_CAPTURE" : "android.permission.DETECT_SCREEN_RECORDING";
                if (application.checkSelfPermission(permission) == android.content.pm.PackageManager.PERMISSION_GRANTED) return true;
            } catch (RuntimeException | LinkageError error) { state(source, 11); }
            loss(source); return false;
        }
        void summarizeShots() {
            if (!screenshots || !supported(0)) return;
            if (screenshotFault) { state(0, 11); return; }
            if (permissionStates[0] != 4) return;
            int good = 0, failed = 0, quarantined = 0;
            for (CaptureEntry entry : entries) if (entry != null) {
                if (entry.shotOpen) good++;
                else if (entry.shot != null || (entry.eligible && entry.shotFailed)) {
                    failed++; if (entry.shot != null) quarantined++;
                }
            }
            if (good > 0) state(0, failed > 0 ? 8 : 7);
            else if (failed > 0) state(0, quarantined > 0 ? 10 : 9);
            else state(0, 6);
        }
        int attach(Activity activity) {
            if (!active || activity == null) return INVALID_CONTEXT;
            try {
                if (activity.getApplication() != application) return DIFFERENT_APPLICATION;
                CaptureEntry entry = null;
                int empty = -1;
                for (int index = 0; index < entries.length; index++) {
                    CaptureEntry candidate = entries[index];
                    if (candidate != null && candidate.activity.get() == null) { release(index); candidate = entries[index]; }
                    if (candidate == null && empty < 0) empty = index;
                    else if (candidate != null && candidate.activity.get() == activity) entry = candidate;
                }
                if (entry == null) {
                    if (empty < 0 || nextToken == Integer.MAX_VALUE) { loss(0); loss(1); return ACTIVITY_LIMIT; }
                    entry = new CaptureEntry(activity, nextToken++); entries[empty] = entry;
                }
                entry.eligible = true;
                if (screenshotFault) {
                    boolean removed = true;
                    for (CaptureEntry other : entries) if (other != null) {
                        other.shotOpen = false;
                        if (!removeShot(other)) removed = false;
                    }
                    if (!removed) return JNI_ERROR;
                    screenshotFault = false;
                }
                if (recordingFault) {
                    for (CaptureEntry other : entries) if (other != null) other.recordingOpen = false;
                    if (!removeRecording()) return JNI_ERROR;
                    recordingFault = false;
                }
                int result = permissions();
                if (screenshots && supported(0) && permissionStates[0] == 4 && !entry.shotOpen) {
                    if (entry.shot == null || removeShot(entry)) {
                        Object callback = Api34.callback(this, entry.token);
                        entry.shot = callback;
                        try {
                            Api34.add(activity, callback, this);
                            if (screenshotFault) throw new IllegalStateException("capture executor rejected");
                            if (!emit(0, entry.token, 1, 0)) throw new IllegalStateException("native capture unavailable");
                            entry.shotOpen = true; entry.shotFailed = false; Api34.enable(callback);
                        } catch (RuntimeException | LinkageError error) {
                            entry.shotFailed = true; loss(0); removeShot(entry); result = JNI_ERROR;
                        }
                    } else result = JNI_ERROR;
                    summarizeShots();
                }
                if (recording && supported(1) && permissionStates[1] == 4) {
                    if (recorder == null) startRecording();
                    else if (recorder.enabled && !entry.recordingOpen) entry.recordingOpen = emit(1, entry.token, 1, 0);
                    if (recorder == null || !recorder.enabled || !entry.recordingOpen) {
                        return entry.shotOpen ? PARTIAL : JNI_ERROR;
                    }
                }
                if (result == JNI_ERROR && entry.recordingOpen) return PARTIAL;
                return result;
            } catch (RuntimeException | LinkageError error) { state(0, 11); state(1, 11); loss(0); loss(1); return JNI_ERROR; }
        }
        boolean removeShot(CaptureEntry entry) {
            Object callback = entry.shot;
            if (callback == null) return true;
            Api34.disable(callback);
            if (entry.shotOpen) { emit(0, entry.token, 2, 0); entry.shotOpen = false; }
            Activity activity = entry.activity.get();
            if (activity == null) { loss(0); return false; }
            try { Api34.remove(activity, callback); entry.shot = null; return true; }
            catch (RuntimeException | LinkageError error) { loss(0); state(0, 10); return false; }
        }
        void startRecording() {
            if (!active || recorder != null) return;
            CaptureEntry owner = null;
            for (CaptureEntry entry : entries) if (entry != null && entry.eligible && entry.activity.get() != null) { owner = entry; break; }
            if (owner == null) return;
            try {
                Activity activity = owner.activity.get();
                if (activity == null) throw new IllegalStateException("recording owner collected");
                WindowManager manager = activity.getWindowManager();
                if (manager == null) throw new IllegalStateException("window manager unavailable");
                recordingManager = new WeakReference<>(manager); recordingOwner = owner;
                recorder = new RecordCallback(this, owner.token);
                int initial = Api35.add(manager, this, recorder);
                if (recordingFault) throw new IllegalStateException("capture executor rejected");
                if (initial != 0 && initial != 1) throw new IllegalStateException("unknown recording state");
                for (CaptureEntry entry : entries) if (entry != null && entry.eligible) {
                    if (!emit(1, entry.token, 1, 0)) throw new IllegalStateException("native capture unavailable");
                    entry.recordingOpen = true;
                }
                if (!emit(1, owner.token, 4, initial)) throw new IllegalStateException("initial state rejected");
                RecordCallback callback = recorder;
                callback.preparing = false; callback.enabled = true;
                if (callback.pendingCount > 1) loss(1);
                if (callback.pendingCount > 0) callback.accept(callback.pending);
            } catch (RuntimeException | LinkageError error) { loss(1); state(1, removeRecording() ? 9 : 10); }
        }
        boolean removeRecording() {
            if (recorder == null) return true;
            recorder.enabled = false; recorder.preparing = false; recorder.live = false;
            for (CaptureEntry entry : entries) if (entry != null && entry.recordingOpen) {
                emit(1, entry.token, 2, 0); entry.recordingOpen = false;
            }
            WindowManager manager = recordingManager == null ? null : recordingManager.get();
            if (manager == null) { loss(1); state(1, 10); return false; }
            try {
                Api35.remove(manager, recorder); recorder = null; recordingOwner = null; recordingManager = null; return true;
            } catch (RuntimeException | LinkageError error) { loss(1); state(1, 10); return false; }
        }
        boolean release(int index) {
            CaptureEntry entry = entries[index];
            if (entry == null) return true;
            entry.eligible = false;
            boolean owner = recordingOwner == entry;
            boolean removed = removeShot(entry);
            if (owner) { if (!removeRecording()) removed = false; }
            else if (entry.recordingOpen) { emit(1, entry.token, 2, 0); entry.recordingOpen = false; }
            if (removed) entries[index] = null;
            return removed;
        }
        int detach(Activity activity) {
            if (activity == null) return INVALID_CONTEXT;
            for (int index = 0; index < entries.length; index++) {
                CaptureEntry entry = entries[index];
                if (entry != null && entry.activity.get() == activity) {
                    boolean owner = recordingOwner == entry;
                    boolean result = release(index);
                    summarizeShots();
                    if (owner && active && recorder == null) {
                        boolean remaining = false;
                        for (CaptureEntry other : entries) if (other != null && other.eligible) remaining = true;
                        if (remaining) { loss(1); startRecording(); }
                    }
                    return result ? INITIALIZED : JNI_ERROR;
                }
            }
            return ALREADY_INITIALIZED;
        }
        boolean cleanup() {
            boolean success = removeRecording();
            for (int index = 0; index < entries.length; index++) if (!release(index)) success = false;
            if (lifecycle) try { application.unregisterActivityLifecycleCallbacks(this); lifecycle = false; }
            catch (RuntimeException | LinkageError error) { state(0, 10); state(1, 10); loss(0); loss(1); success = false; }
            return success;
        }
        int stop() {
            active = false;
            for (CaptureEntry entry : entries) if (entry != null && entry.shot != null) Api34.disable(entry.shot);
            if (recorder != null) { recorder.enabled = false; recorder.preparing = false; recorder.live = false; }
            try { stopCaptureNative(epoch); nativeStopped = true; }
            catch (RuntimeException | LinkageError error) { cleanup(); return JNI_ERROR; }
            boolean success = cleanup();
            if (!success) {
                // Native generation is already inert; stopped failures are kept in the interval loss counters.
                return JNI_ERROR;
            }
            if (captures == this) captures = null;
            return INITIALIZED;
        }
        @Override public void onActivityPostResumed(Activity activity) { if (active) attach(activity); }
        @Override public void onActivityPrePaused(Activity activity) { if (active) detach(activity); }
        @Override public void onActivityStopped(Activity activity) { if (active) detach(activity); }
        @Override public void onActivityDestroyed(Activity activity) { if (active) detach(activity); }
        @Override public void onActivityCreated(Activity activity, Bundle state) {}
        @Override public void onActivityStarted(Activity activity) {}
        @Override public void onActivityResumed(Activity activity) {}
        @Override public void onActivityPaused(Activity activity) {}
        @Override public void onActivitySaveInstanceState(Activity activity, Bundle state) {}
    }

    private static final class Api34 {
        static Object callback(CaptureSession session, int token) { return new ShotCallback(session, token); }
        static void add(Activity activity, Object callback, CaptureSession session) {
            activity.registerScreenCaptureCallback(new CaptureExecutor(session, 0, (ShotCallback) callback), (Activity.ScreenCaptureCallback) callback);
        }
        static void remove(Activity activity, Object callback) { activity.unregisterScreenCaptureCallback((Activity.ScreenCaptureCallback) callback); }
        static void enable(Object callback) { ((ShotCallback) callback).enabled = true; }
        static void disable(Object callback) { ((ShotCallback) callback).enabled = false; ((ShotCallback) callback).live = false; }
        private static final class ShotCallback extends CaptureGate implements Activity.ScreenCaptureCallback {
            final CaptureSession session;
            final int token;
            boolean enabled;
            ShotCallback(CaptureSession session, int token) { this.session = session; this.token = token; }
            @Override public void onScreenCaptured() {
                if (!enabled || !session.active || session.screenshotFault) return;
                if (session.granted(0)) {
                    if (!session.emit(0, token, 3, 0)) { enabled = false; session.failSource(0); }
                } else {
                    for (CaptureEntry entry : session.entries) if (entry != null) session.removeShot(entry);
                    session.permission(0);
                }
            }
        }
    }
    private static final class RecordCallback extends CaptureGate implements java.util.function.Consumer<Integer> {
        final CaptureSession session;
        final int token;
        boolean preparing = true;
        boolean enabled;
        int pending;
        int pendingCount;
        RecordCallback(CaptureSession session, int token) { this.session = session; this.token = token; }
        @Override public void accept(Integer value) {
            if (preparing) { pending = value == null ? -1 : value; if (pendingCount < 2) pendingCount++; return; }
            if (!enabled || !session.active || session.recordingFault) return;
            if (!session.granted(1)) { session.removeRecording(); session.permission(1); return; }
            if (!session.emit(1, token, 3, value == null ? -1 : value)) {
                enabled = false;
                for (CaptureEntry entry : session.entries) if (entry != null) entry.recordingOpen = false;
                session.removeRecording(); session.failSource(1);
            }
        }
    }
    private static final class Api35 {
        static int add(WindowManager manager, CaptureSession session, RecordCallback callback) {
            return manager.addScreenRecordingCallback(new CaptureExecutor(session, 1, callback), callback);
        }
        static void remove(WindowManager manager, RecordCallback callback) { manager.removeScreenRecordingCallback(callback); }
    }

    private static class CaptureGate { volatile boolean live = true; }
    private static final class CaptureExecutor implements java.util.concurrent.Executor {
        final CaptureSession session;
        final int source;
        final java.util.concurrent.Executor main;
        final CaptureGate gate;
        CaptureExecutor(CaptureSession session, int source, CaptureGate gate) {
            this.session = session; this.source = source; this.gate = gate; this.main = session.application.getMainExecutor();
        }
        @Override public void execute(Runnable command) {
            if (!gate.live || !session.active) return;
            try { main.execute(command); }
            catch (RuntimeException | LinkageError error) { if (gate.live && session.active) session.failSource(source); }
        }
    }

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
