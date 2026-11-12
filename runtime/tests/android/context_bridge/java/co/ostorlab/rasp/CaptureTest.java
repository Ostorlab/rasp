package co.ostorlab.rasp;

/** Actual production bridge API contract; public platform boundaries are simulated on a real JVM. */
public final class CaptureTest {
    private static native String[] read(int mask);
    private static native boolean paired(boolean worker);
    private static native boolean rebind(boolean reject);
    private static native boolean coldSupportCorrect();
    private static void check(boolean value) { if (!value) throw new AssertionError(); }
    private static void row(String[] rows, String source, String signal, String value) {
        String expected = "capture." + source + "." + signal + "/" +
                (source.equals("screenshot") ? "activity_screen_capture" : "window_manager_recording") + " " + value;
        for (String row : rows) if (row.equals(expected)) return;
        throw new AssertionError(expected + " missing from " + java.util.Arrays.toString(rows));
    }
    private static android.app.Activity activity(android.app.Application app) {
        android.app.Activity activity = new android.app.Activity(); activity.application = app; return activity;
    }
    private static void stop(android.app.Application app) {
        check(RuntimeBridge.stopCaptureObservation() == 0);
        check(app.callbacks.isEmpty());
        check(android.view.WindowManager.callbacks.isEmpty());
        read(3);
    }
    public static void main(String[] args) throws Exception {
        try {
            RuntimeBridge.class.getDeclaredMethod("startCaptureObservation", android.app.Application.class,
                    boolean.class, boolean.class);
        } catch (NoSuchMethodException missing) {
            throw new AssertionError("production capture opt-in API is absent", missing);
        }
        int api = Integer.parseInt(args[1]);
        android.os.Build.VERSION.SDK_INT = api;
        System.load(args[0]);
        check(coldSupportCorrect());
        android.app.Application app = new android.app.Application();
        String[] initial = read(3);
        row(initial, "screenshot", "observer_state", "ok " + (api < 34 ? "unsupported" : "never_started"));
        row(initial, "recording", "observer_state", "ok " + (api < 35 ? "unsupported" : "never_started"));
        check(RuntimeBridge.startCaptureObservation(app, true, true) == RuntimeBridge.NOT_INITIALIZED);
        row(read(1), "screenshot", "observer_state", "ok " + (api < 34 ? "unsupported" : "no_application"));
        check(RuntimeBridge.initialize(app) == 0);
        check(RuntimeBridge.startCaptureObservation(new android.app.Application(), true, true) == RuntimeBridge.DIFFERENT_APPLICATION);
        java.util.concurrent.atomic.AtomicInteger workerResult = new java.util.concurrent.atomic.AtomicInteger(-1);
        Thread worker = new Thread(() -> workerResult.set(RuntimeBridge.startCaptureObservation(app, true, true)));
        worker.start(); worker.join(); check(workerResult.get() == RuntimeBridge.WRONG_THREAD);
        check(rebind(true));
        check(RuntimeBridge.startCaptureObservation(app, true, true) == RuntimeBridge.UNAVAILABLE);
        check(rebind(false));
        int start = RuntimeBridge.startCaptureObservation(app, true, true);
        check(start == (api < 34 ? RuntimeBridge.UNSUPPORTED : api < 35 ? RuntimeBridge.PARTIAL : 0));
        check(RuntimeBridge.startCaptureObservation(app, false, false) == RuntimeBridge.INVALID_OPTIONS);
        android.app.Activity first = activity(app);
        android.view.WindowManager.initial = 1;
        android.view.WindowManager.duringRegistration = api >= 35 ? 0 : null;
        app.resume(first);
        first.screenshot(); first.screenshot();
        android.view.WindowManager.duringRegistration = null;
        String[] shot = read(1);
        if (api < 34) {
            row(shot, "screenshot", "callback_events", "unsupported");
            check(first.screenshots.isEmpty());
        } else row(shot, "screenshot", "callback_events", "ok 2");
        String[] record = read(2);
        if (api < 35) {
            row(record, "recording", "visibility", "unsupported");
            check(android.view.WindowManager.callbacks.isEmpty());
        } else {
            row(record, "recording", "initial_samples", "ok 1");
            row(record, "recording", "visibility", "ok not_visible");
            row(record, "recording", "callback_events", "ok 1");
            row(record, "recording", "visibility_changes", "ok 1");
            android.app.Activity second = activity(app);
            app.resume(second); app.resume(second);
            check(android.view.WindowManager.callbacks.size() == 1);
            android.view.WindowManager.recording(1); android.view.WindowManager.recording(1);
            row(read(2), "recording", "visibility_changes", "ok 1");
            app.pause(first);
            check(android.view.WindowManager.callbacks.size() == 1);
            row(read(2), "recording", "active_activities", "ok 1");
            app.destroy(second);
            row(read(2), "recording", "visibility", "ok unknown");
            check(android.view.WindowManager.callbacks.isEmpty());
        }
        check(paired(false) && paired(true));
        stop(app);
        if (api < 34) return;

        app.failRegistration = true;
        check(RuntimeBridge.startCaptureObservation(app, true, false) == RuntimeBridge.JNI_ERROR);
        check(app.callbacks.isEmpty());
        row(read(1), "screenshot", "observer_state", "ok error");
        app.failRegistration = false;
        app.failPermission = true;
        check(RuntimeBridge.startCaptureObservation(app, true, false) == RuntimeBridge.JNI_ERROR);
        row(read(1), "screenshot", "observer_state", "ok error");
        stop(app); app.failPermission = false;

        android.content.pm.PackageInfo.permissions = new String[0];
        check(RuntimeBridge.startCaptureObservation(app, true, false) == RuntimeBridge.PERMISSION_REQUIRED);
        app.resume(first);
        row(read(1), "screenshot", "observer_state", "ok permission_absent");
        stop(app);
        android.content.pm.PackageInfo.permissions = new String[]{"android.permission.DETECT_SCREEN_CAPTURE", "android.permission.DETECT_SCREEN_RECORDING"};
        app.deniedPermissions.add("android.permission.DETECT_SCREEN_CAPTURE");
        check(RuntimeBridge.startCaptureObservation(app, true, false) == RuntimeBridge.PERMISSION_REQUIRED);
        row(read(1), "screenshot", "observer_state", "ok permission_denied");
        stop(app); app.deniedPermissions.clear();

        check(RuntimeBridge.startCaptureObservation(app, true, false) == 0);
        android.app.Activity teardownA = activity(app), healthyB = activity(app);
        app.resume(teardownA); app.resume(healthyB); read(1);
        android.app.Activity.ScreenCaptureCallback lateA = teardownA.screenshots.get(0);
        teardownA.failCaptureRemoval = true;
        check(RuntimeBridge.detachCaptureActivity(teardownA) == RuntimeBridge.JNI_ERROR);
        String[] partial = read(1);
        row(partial, "screenshot", "observer_state", "ok partial");
        row(partial, "screenshot", "active_activities", "ok 1");
        row(partial, "screenshot", "invalid_events", "ok 0");
        healthyB.screenshot(); lateA.onScreenCaptured();
        String[] retainedB = read(1);
        row(retainedB, "screenshot", "callback_events", "ok 1");
        row(retainedB, "screenshot", "invalid_events", "ok 0");
        row(retainedB, "screenshot", "observer_state", "ok partial");
        teardownA.failCaptureRemoval = false;
        check(RuntimeBridge.detachCaptureActivity(teardownA) == 0);
        android.app.Activity failedA = activity(app);
        failedA.failCaptureRegistration = true; failedA.failCaptureRemoval = true;
        check(RuntimeBridge.attachCaptureActivity(failedA) == RuntimeBridge.JNI_ERROR);
        row(read(1), "screenshot", "active_activities", "ok 1");
        healthyB.screenshot(); failedA.screenshot();
        String[] afterFailedA = read(1);
        row(afterFailedA, "screenshot", "callback_events", "ok 1");
        row(afterFailedA, "screenshot", "invalid_events", "ok 0");
        row(afterFailedA, "screenshot", "observer_state", "ok partial");
        failedA.failCaptureRemoval = false;
        stop(app);

        check(RuntimeBridge.startCaptureObservation(app, true, false) == 0);
        app.resume(first);
        app.rejectCaptureExecutor = true;
        first.screenshot();
        row(read(1), "screenshot", "observer_state", "ok error");
        app.rejectCaptureExecutor = false;
        RuntimeBridge.detachCaptureActivity(first);
        row(read(1), "screenshot", "observer_state", "ok error");
        stop(app);

        if (api >= 35) {
            check(RuntimeBridge.startCaptureObservation(app, true, true) == 0);
            android.app.Activity recordBroken = activity(app); recordBroken.manager.failRegistration = true;
            check(RuntimeBridge.attachCaptureActivity(recordBroken) == RuntimeBridge.PARTIAL);
            row(read(2), "recording", "observer_state", "ok registration_error");
            check(android.view.WindowManager.callbacks.isEmpty());
            recordBroken.screenshot(); row(read(1), "screenshot", "callback_events", "ok 1");
            stop(app);
            android.view.WindowManager.initial = 9;
            check(RuntimeBridge.startCaptureObservation(app, false, true) == 0);
            check(RuntimeBridge.attachCaptureActivity(first) == RuntimeBridge.JNI_ERROR);
            row(read(2), "recording", "observer_state", "ok registration_error");
            row(read(2), "recording", "visibility", "ok unknown");
            stop(app); android.view.WindowManager.initial = 0;
            check(RuntimeBridge.startCaptureObservation(app, false, true) == 0);
            app.resume(first);
            first.manager.failRemoval = true;
            check(RuntimeBridge.stopCaptureObservation() == RuntimeBridge.JNI_ERROR);
            row(read(2), "recording", "observer_state", "ok teardown_error");
            check(android.view.WindowManager.callbacks.size() == 1);
            check(RuntimeBridge.startCaptureObservation(app, false, true) == RuntimeBridge.JNI_ERROR);
            first.manager.failRemoval = false;
            check(RuntimeBridge.startCaptureObservation(app, false, true) == 0);
            app.resume(first); android.view.WindowManager.recording(null);
            row(read(2), "recording", "visibility", "ok unknown");
            row(read(2), "recording", "observer_state", "ok error");
            stop(app);
        }

        check(RuntimeBridge.startCaptureObservation(app, true, false) == 0);
        android.app.Activity broken = activity(app); broken.failCaptureRegistration = true;
        app.resume(first); app.resume(broken);
        row(read(1), "screenshot", "observer_state", "ok partial");
        check(broken.screenshots.isEmpty()); first.screenshot();
        row(read(1), "screenshot", "callback_events", "ok 1");
        android.app.Activity.ScreenCaptureCallback stale = first.screenshots.get(0);
        first.failCaptureRemoval = true;
        check(RuntimeBridge.stopCaptureObservation() == RuntimeBridge.JNI_ERROR);
        stale.onScreenCaptured();
        row(read(1), "screenshot", "active_activities", "ok 0");
        row(read(1), "screenshot", "observer_state", "ok teardown_error");
        check(RuntimeBridge.startCaptureObservation(app, true, false) == RuntimeBridge.JNI_ERROR);
        first.failCaptureRemoval = false;
        check(RuntimeBridge.startCaptureObservation(app, true, false) == 0);
        app.resume(first);
        stale.onScreenCaptured();
        row(read(1), "screenshot", "callback_events", "ok 0");
        stop(app);

        check(RuntimeBridge.startCaptureObservation(app, true, false) == 0);
        app.resume(first);
        app.deniedPermissions.add("android.permission.DETECT_SCREEN_CAPTURE");
        app.resume(first);
        String[] revoked = read(1);
        row(revoked, "screenshot", "observer_state", "ok permission_denied");
        row(revoked, "screenshot", "active_activities", "ok 0");
        row(revoked, "screenshot", "invalid_events", "ok 0");
        check(first.screenshots.isEmpty());
        stop(app); app.deniedPermissions.clear();

        check(RuntimeBridge.startCaptureObservation(app, true, false) == 0);
        java.util.List<android.app.Activity> activities = new java.util.ArrayList<>();
        for (int index = 0; index < 32; index++) { android.app.Activity current = activity(app); activities.add(current); app.resume(current); }
        check(RuntimeBridge.attachCaptureActivity(activity(app)) == RuntimeBridge.ACTIVITY_LIMIT);
        row(read(1), "screenshot", "active_activities", "ok 32");
        stop(app);
        System.out.println("PASS capture API" + api + ": production Java/JNI/CycleMonitor with simulated public platform boundaries");
    }
}
