package co.ostorlab.rasp;

import android.app.*;
import android.os.*;
import android.view.*;
import java.lang.ref.WeakReference;
import java.lang.reflect.*;
import java.util.concurrent.atomic.AtomicReference;

/** Real JVM, actual shipped adapter/JNI/dispatcher; simulated public Android boundary, never a device claim. */
public final class WindowTest {
    private static native String[] read(boolean enabled);
    private static native boolean registrationFailure();
    private static native boolean cycleProbe(boolean worker);
    private static void check(boolean value) { if (!value) throw new AssertionError(); }
    private static void contains(String[] values, String signal, String value) {
        String expected = "overlay." + signal + "/window_callback ok " + value;
        for (String line : values) if (line.equals(expected)) return;
        throw new AssertionError(expected + " missing from " + java.util.Arrays.toString(values));
    }
    private static Activity activity(Window.Callback callback) {
        Activity activity = new Activity(); activity.getWindow().setCallback(callback); return activity;
    }
    private static Window.Callback delegate(java.util.List<String> calls, RuntimeException failure) {
        return (Window.Callback) Proxy.newProxyInstance(WindowTest.class.getClassLoader(), new Class<?>[]{Window.Callback.class},
            (proxy, method, args) -> {
                calls.add(method.toString());
                if (failure != null) throw failure;
                if (method.getReturnType() == boolean.class) return true;
                return null;
            });
    }
    private static void forwardAll(Window.Callback wrapper, java.util.List<String> calls) throws Exception {
        for (Method method : Window.Callback.class.getDeclaredMethods()) {
            Object[] values = new Object[method.getParameterCount()];
            Class<?>[] types = method.getParameterTypes();
            for (int index = 0; index < types.length; index++) {
                if (types[index] == int.class) values[index] = 17;
                if (types[index] == boolean.class) values[index] = true;
            }
            int before = calls.size();
            Object result = method.invoke(wrapper, values);
            check(calls.size() == before + 1 && calls.get(before).equals(method.toString()));
            if (method.getReturnType() == boolean.class) check(Boolean.TRUE.equals(result));
        }
    }
    private static void exactForwarding() throws Exception {
        View view = new View(); ActionMode action = new ActionMode();
        Object[][] received = new Object[1][];
        Window window = new Window();
        window.setCallback((Window.Callback) Proxy.newProxyInstance(WindowTest.class.getClassLoader(), new Class<?>[]{Window.Callback.class},
            (proxy, method, args) -> {
                received[0] = args;
                if (method.getReturnType() == boolean.class) return false;
                if (method.getReturnType() == View.class) return view;
                if (method.getReturnType() == ActionMode.class) return action;
                return null;
            }));
        check(RuntimeBridge.attachWindow(window) == 0);
        Window.Callback wrapper = window.getCallback();
        for (Method method : Window.Callback.class.getDeclaredMethods()) {
            Object[] values = new Object[method.getParameterCount()];
            for (int index = 0; index < values.length; index++) {
                Class<?> type = method.getParameterTypes()[index];
                if (type == int.class) values[index] = 47;
                else if (type == boolean.class) values[index] = true;
                else if (type == java.util.List.class) values[index] = new java.util.ArrayList<KeyboardShortcutGroup>();
                else if (type == MotionEvent.class) values[index] = new MotionEvent(0);
                else if (type == ActionMode.Callback.class) values[index] = new ActionMode.Callback() {};
                else values[index] = type.getDeclaredConstructor().newInstance();
            }
            Object result = method.invoke(wrapper, values);
            if (values.length > 0) {
                check(received[0].length == values.length);
                for (int index = 0; index < values.length; index++) check(received[0][index] == values[index]);
            }
            if (method.getReturnType() == boolean.class) check(Boolean.FALSE.equals(result));
            if (method.getReturnType() == View.class) check(result == view);
            if (method.getReturnType() == ActionMode.class) check(result == action);
        }
        RuntimeBridge.detachWindow(window);
    }
    private static WeakReference<Activity> abandoned(Application app, Window.Callback callback) {
        Activity activity = activity(callback); app.resume(activity); return new WeakReference<>(activity);
    }
    private static void adapterFailures(Application app, Window.Callback original) {
        Handler.throwConstruct = true;
        try { check(RuntimeBridge.startWindowObservation(app) == RuntimeBridge.JNI_ERROR); }
        finally { Handler.throwConstruct = false; }
        String[] construction = read(true); contains(construction, "observer_state", "error"); contains(construction, "active_windows", "0");
        check(RuntimeBridge.attachWindow(new Window()) == RuntimeBridge.NOT_INITIALIZED);
        check(app.callbacks.isEmpty() && Handler.count() == 0);
        Handler.throwPost = true;
        try { check(RuntimeBridge.startWindowObservation(app) == RuntimeBridge.JNI_ERROR); }
        finally { Handler.throwPost = false; }
        contains(read(true), "observer_state", "error");
        check(app.callbacks.isEmpty() && Handler.count() == 0);
        check(RuntimeBridge.startWindowObservation(app) == 0);
        Activity activity = activity(original); app.resume(activity);
        Window.Callback wrapper = activity.getWindow().getCallback();
        Handler.throwRemove = true;
        try { check(RuntimeBridge.stopWindowObservation() == RuntimeBridge.JNI_ERROR); }
        finally { Handler.throwRemove = false; }
        wrapper.dispatchTouchEvent(new MotionEvent(3));
        String[] removal = read(true); contains(removal, "observer_state", "error"); contains(removal, "active_windows", "0");
        contains(removal, "touch_events", "0"); check(app.callbacks.isEmpty());
        // A Handler that refuses removal can retain one task; it must be inert and never reschedule.
        Handler.pulse(); check(Handler.count() == 0);
        check(RuntimeBridge.startWindowObservation(app) == 0); app.resume(activity);
        wrapper = activity.getWindow().getCallback();
        Handler.throwPost = true;
        try { Handler.pulse(); } finally { Handler.throwPost = false; }
        wrapper.dispatchTouchEvent(new MotionEvent(3));
        String[] reschedule = read(true); contains(reschedule, "observer_state", "error"); contains(reschedule, "active_windows", "0");
        contains(reschedule, "touch_events", "0"); check(app.callbacks.isEmpty() && Handler.count() == 0);
        check(RuntimeBridge.startWindowObservation(app) == 0);
        Handler.throwPost = true;
        try { app.resume(activity); } finally { Handler.throwPost = false; }
        contains(read(true), "observer_state", "error"); check(app.callbacks.isEmpty());
        check(RuntimeBridge.startWindowObservation(app) == 0); app.resume(activity);
        wrapper = activity.getWindow().getCallback();
        Handler.throwRemove = true;
        try { app.resume(activity); } finally { Handler.throwRemove = false; }
        wrapper.dispatchTouchEvent(new MotionEvent(3));
        String[] probeRemoval = read(true); contains(probeRemoval, "observer_state", "error");
        contains(probeRemoval, "active_windows", "0"); contains(probeRemoval, "touch_events", "0");
        Handler.pulse(); check(Handler.count() == 0 && app.callbacks.isEmpty());
        // Every lifecycle window lookup is adapter-owned, with the same teardown boundary.
        for (int phase = 0; phase < 4; phase++) {
            check(RuntimeBridge.startWindowObservation(app) == 0); app.resume(activity);
            wrapper = activity.getWindow().getCallback(); activity.failWindow = true;
            try {
                if (phase == 0) app.resume(activity);
                else if (phase == 1) app.pause(activity);
                else if (phase == 2) app.stop(activity);
                else app.destroy(activity);
            } finally { activity.failWindow = false; }
            wrapper.dispatchTouchEvent(new MotionEvent(3));
            String[] lookup = read(true); contains(lookup, "observer_state", "error"); contains(lookup, "active_windows", "0");
            contains(lookup, "touch_events", "0"); check(app.callbacks.isEmpty() && Handler.count() == 0);
        }
    }
    private static final class RejectingWindow extends Window {
        boolean reject;
        @Override public void setCallback(Window.Callback callback) {
            if (reject) throw new IllegalStateException("host window setter failure");
            super.setCallback(callback);
        }
    }
    public static void main(String[] args) throws Exception {
        // Force main-looper initialization before spawning a worker.
        Looper.getMainLooper();
        Application app = new Application();
        check(RuntimeBridge.startWindowObservation(app) == RuntimeBridge.UNAVAILABLE);
        System.load(args[0]);
        check(read(false).length == 0);
        contains(read(true), "observer_state", "never_started");
        check(RuntimeBridge.startWindowObservation(app) == RuntimeBridge.NOT_INITIALIZED);
        contains(read(true), "observer_state", "error");
        check(RuntimeBridge.initialize(app) == 0);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread wrong = new Thread(() -> {
            try {
                check(RuntimeBridge.startWindowObservation(app) == RuntimeBridge.WRONG_THREAD);
                check(RuntimeBridge.stopWindowObservation() == RuntimeBridge.WRONG_THREAD);
                check(RuntimeBridge.attachWindow(new Window()) == RuntimeBridge.WRONG_THREAD);
            } catch (Throwable error) { failure.set(error); }
        }); wrong.start(); wrong.join(); if (failure.get() != null) throw new AssertionError(failure.get());
        Build.VERSION.SDK_INT = 30;
        check(RuntimeBridge.startWindowObservation(app) == RuntimeBridge.UNSUPPORTED);
        contains(read(true), "observer_state", "unsupported");
        Build.VERSION.SDK_INT = 35;
        app.failRegistration = true;
        check(RuntimeBridge.startWindowObservation(app) == RuntimeBridge.JNI_ERROR);
        check(app.callbacks.isEmpty() && Handler.count() == 0);
        contains(read(true), "observer_state", "error");
        app.failRegistration = false;
        check(RuntimeBridge.startWindowObservation(new Application()) == RuntimeBridge.DIFFERENT_APPLICATION);
        check(RuntimeBridge.startWindowObservation(app) == 0);
        check(RuntimeBridge.startWindowObservation(app) == 1);
        check(app.callbacks.size() == 1 && Handler.count() == 1);
        contains(read(true), "coverage", "unknown");
        java.util.ArrayList<String> calls = new java.util.ArrayList<>();
        Window.Callback original = delegate(calls, null);
        Activity first = activity(original), second = activity(original);
        app.resume(first); app.resume(second);
        Window.Callback wrapper = first.getWindow().getCallback();
        check(wrapper != original && RuntimeBridge.attachWindow(first.getWindow()) == 1);
        contains(read(true), "active_windows", "2");
        for (int flags : new int[]{0, 1, 2, 3, 128}) check(wrapper.dispatchTouchEvent(new MotionEvent(flags)));
        check(read(false).length == 0);
        String[] touches = read(true);
        contains(touches, "touch_events", "5"); contains(touches, "obscured_touch_events", "2");
        contains(touches, "partially_obscured_touch_events", "2");
        contains(read(true), "touch_events", "0");
        // A successful callback must see telemetry before host code, and the same event object.
        for (boolean worker : new boolean[]{false, true}) {
            wrapper.dispatchTouchEvent(new MotionEvent(3));
            check(cycleProbe(worker));
        }
        MotionEvent exact = new MotionEvent(1);
        Window order = new Window();
        order.setCallback((Window.Callback) Proxy.newProxyInstance(WindowTest.class.getClassLoader(), new Class<?>[]{Window.Callback.class},
            (proxy, method, values) -> { check(values[0] == exact); contains(read(true), "touch_events", "1"); return false; }));
        check(RuntimeBridge.attachWindow(order) == 0);
        check(!order.getCallback().dispatchTouchEvent(exact));
        check(RuntimeBridge.detachWindow(order) == 0);
        exactForwarding();
        // Every public Callback method forwards once, including defaults and overloads.
        forwardAll(wrapper, calls);
        RuntimeException sentinel = new IllegalStateException("host sentinel");
        Activity throwing = activity(delegate(calls, sentinel)); app.resume(throwing);
        try { throwing.getWindow().getCallback().dispatchTouchEvent(new MotionEvent(2)); throw new AssertionError(); }
        catch (RuntimeException error) { check(error == sentinel); }
        for (Method method : Window.Callback.class.getDeclaredMethods()) {
            Object[] values = new Object[method.getParameterCount()];
            for (int index = 0; index < values.length; index++) {
                if (method.getParameterTypes()[index] == int.class) values[index] = 1;
                if (method.getParameterTypes()[index] == boolean.class) values[index] = false;
            }
            try { method.invoke(throwing.getWindow().getCallback(), values); throw new AssertionError(); }
            catch (InvocationTargetException error) { check(error.getCause() == sentinel); }
        }
        app.destroy(throwing); app.pause(first); app.stop(second);
        check(first.getWindow().getCallback() == original && second.getWindow().getCallback() == original);
        app.resume(first); wrapper = first.getWindow().getCallback();
        Window.Callback replacement = delegate(calls, null);
        first.getWindow().setCallback(replacement);
        Handler.pulse();
        contains(read(true), "lost_windows", "1");
        check(first.getWindow().getCallback() == replacement);
        // Old wrapper can survive in host chains but must become inert, including after stop/restart.
        wrapper.dispatchTouchEvent(new MotionEvent(3));
        contains(read(true), "touch_events", "0");
        check(RuntimeBridge.stopWindowObservation() == 0);
        check(first.getWindow().getCallback() == replacement && app.callbacks.isEmpty() && Handler.count() == 0);
        contains(read(true), "observer_state", "deactivated");
        check(RuntimeBridge.stopWindowObservation() == 1);
        check(RuntimeBridge.startWindowObservation(app) == 0);
        Activity rotated = activity(original); app.resume(rotated); app.destroy(rotated);
        check(rotated.getWindow().getCallback() == original);
        WeakReference<Activity> collected = new WeakReference<>(rotated); rotated = null;
        for (int attempt = 0; attempt < 30 && collected.get() != null; attempt++) { System.gc(); Thread.sleep(5); }
        check(collected.get() == null);
        Window overflow = new Window(); overflow.setCallback(original); check(RuntimeBridge.attachWindow(overflow) == 0);
        read(true);
        for (int index = 0; index < 200; index++) overflow.getCallback().dispatchTouchEvent(new MotionEvent(3));
        String[] full = read(true); contains(full, "touch_events", "128"); contains(full, "dropped_events", "72");
        contains(full, "coverage", "loss_detected");
        Method raw = RuntimeBridge.class.getDeclaredMethod("windowEventNative", long.class, int.class, int.class, int.class);
        raw.setAccessible(true);
        check(Boolean.FALSE.equals(raw.invoke(null, -1L, -1, 3, 7)));
        contains(read(true), "invalid_events", "1");
        Thread reader = new Thread(() -> { try { for (int pass = 0; pass < 400; pass++) check(read(true).length == 10); }
            catch (Throwable error) { failure.set(error); } });
        reader.start();
        for (int index = 0; index < 400; index++) overflow.getCallback().dispatchTouchEvent(new MotionEvent(index & 3));
        reader.join(); if (failure.get() != null) throw new AssertionError(failure.get());
        Window[] retained = new Window[31];
        for (int index = 0; index < retained.length; index++) {
            retained[index] = new Window(); retained[index].setCallback(original); check(RuntimeBridge.attachWindow(retained[index]) == 0);
        }
        Window excess = new Window(); excess.setCallback(original); check(RuntimeBridge.attachWindow(excess) == RuntimeBridge.WINDOW_LIMIT);
        check(excess.getCallback() == original);
        check(RuntimeBridge.stopWindowObservation() == 0);
        check(RuntimeBridge.startWindowObservation(app) == 0);
        WeakReference<Activity> abandoned = abandoned(app, original);
        for (int attempt = 0; attempt < 50 && abandoned.get() != null; attempt++) { System.gc(); Thread.sleep(5); }
        check(abandoned.get() == null); Handler.pulse();
        String[] reclaimed = read(true); contains(reclaimed, "active_windows", "0");
        // Slot-limit failure remains pending across stop/start, alongside the newly collected window.
        contains(reclaimed, "lost_windows", "2");
        Window chained = new Window(); chained.setCallback(original); check(RuntimeBridge.attachWindow(chained) == 0);
        Window.Callback old = chained.getCallback();
        Window.Callback chain = (Window.Callback) Proxy.newProxyInstance(WindowTest.class.getClassLoader(), new Class<?>[]{Window.Callback.class},
            (proxy, method, values) -> method.invoke(old, values));
        chained.setCallback(chain);
        check(RuntimeBridge.stopWindowObservation() == 0); check(chained.getCallback() == chain);
        contains(read(true), "lost_windows", "1");
        chain.dispatchTouchEvent(new MotionEvent(3)); contains(read(true), "touch_events", "0");
        check(RuntimeBridge.startWindowObservation(app) == 0);
        Handler.fail = true; Handler.pulse(); Handler.fail = false;
        check(Handler.count() == 0 && app.callbacks.isEmpty());
        contains(read(true), "observer_state", "error");
        check(RuntimeBridge.startWindowObservation(app) == 0);
        RejectingWindow broken = new RejectingWindow(); broken.setCallback(original); broken.reject = true;
        check(RuntimeBridge.attachWindow(broken) == RuntimeBridge.JNI_ERROR);
        check(broken.getCallback() == original); contains(read(true), "active_windows", "0");
        broken.reject = false; check(RuntimeBridge.attachWindow(broken) == 0); broken.reject = true;
        Window.Callback inert = broken.getCallback();
        check(RuntimeBridge.stopWindowObservation() == RuntimeBridge.JNI_ERROR);
        inert.dispatchTouchEvent(new MotionEvent(3));
        String[] failedRestore = read(true); contains(failedRestore, "observer_state", "error");
        contains(failedRestore, "active_windows", "0"); contains(failedRestore, "touch_events", "0");
        check(RuntimeBridge.startWindowObservation(app) == 0);
        Activity unregister = activity(original); app.resume(unregister); app.failUnregister = true;
        check(RuntimeBridge.stopWindowObservation() == RuntimeBridge.JNI_ERROR);
        check(unregister.getWindow().getCallback() == original && Handler.count() == 0);
        app.resume(unregister); check(unregister.getWindow().getCallback() == original);
        contains(read(true), "observer_state", "error");
        app.failUnregister = false; app.callbacks.clear();
        adapterFailures(app, original);
        check(registrationFailure()); contains(read(true), "observer_state", "error");
        System.out.println("actual Java/JNI/window dispatcher lifecycle, forwarding, loss, overflow, concurrency PASS");
    }
}
