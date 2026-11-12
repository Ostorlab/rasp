package co.ostorlab.rasp;

import android.app.Application;
import android.app.ActivityThread;
import android.content.Context;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicReference;

/** Runs the shipped Java bridge and production JNI consumer against JVM Android boundary fixtures. */
public final class BridgeTest {
    private static native boolean readCertificate();
    private static native boolean hasContext();
    private static native void testFailures();
    private static native boolean readerFailures();
    private static native boolean nativeThreadRead();

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError();
    }

    private static java.lang.ref.WeakReference<Application> initializeTemporary() {
        Application temporary = new Application();
        check(RuntimeBridge.initialize(temporary) == RuntimeBridge.INITIALIZED);
        return new java.lang.ref.WeakReference<>(temporary);
    }

    public static void main(String[] args) throws Exception {
        check(RuntimeBridge.initialize(null) == RuntimeBridge.UNAVAILABLE);
        String mode = args.length > 1 ? args[1] : "late";
        System.load(args[0]);
        testFailures();
        check(RuntimeBridge.initialize(null) == RuntimeBridge.INVALID_CONTEXT);
        check(!hasContext());
        if (mode.equals("unavailable")) {
            check(!readCertificate());
            check(!hasContext());
            System.out.println("unintegrated consumer unavailable without pending exception");
            return;
        }
        if (mode.equals("lifetime")) {
            java.lang.ref.WeakReference<Application> retained = initializeTemporary();
            for (int pass = 0; pass < 5; ++pass) System.gc();
            check(retained.get() != null);
            check(nativeThreadRead());
            return;
        }
        Application app = new Application();
        if (mode.equals("early")) {
            check(RuntimeBridge.initialize(app) == RuntimeBridge.INITIALIZED);
            check(readCertificate());
            check(ActivityThread.calls == 0);
            return;
        }
        if (mode.equals("concurrent")) {
            java.util.concurrent.atomic.AtomicInteger initialized = new java.util.concurrent.atomic.AtomicInteger();
            ArrayList<Thread> starters = new ArrayList<>();
            AtomicReference<Throwable> errors = new AtomicReference<>();
            for (int index = 0; index < 16; ++index) {
                Thread starter = new Thread(() -> {
                    try {
                        int result = RuntimeBridge.initialize(app);
                        if (result == RuntimeBridge.INITIALIZED) initialized.incrementAndGet();
                        else check(result == RuntimeBridge.ALREADY_INITIALIZED);
                        check(nativeThreadRead());
                    } catch (Throwable error) { errors.set(error); }
                });
                starters.add(starter);
                starter.start();
            }
            for (Thread starter : starters) starter.join();
            check(initialized.get() == 1);
            if (errors.get() != null) throw new AssertionError(errors.get());
            return;
        }
        ActivityThread.application = app;
        check(readCertificate());
        check(ActivityThread.calls > 0);
        ActivityThread.application = null;
        Context unattached = new Context() {
            public Context getApplicationContext() { return null; }
            public String getPackageName() { throw new AssertionError(); }
            public android.content.pm.PackageManager getPackageManager() { throw new AssertionError(); }
        };
        check(RuntimeBridge.initialize(unattached) == RuntimeBridge.INVALID_CONTEXT);
        check(RuntimeBridge.initialize(new Application() {
            public Context getApplicationContext() { throw new IllegalStateException("unattached"); }
        }) == RuntimeBridge.JNI_ERROR);
        check(!hasContext());
        Context wrapper = new Context() {
            public Context getApplicationContext() { return app; }
            public String getPackageName() { throw new AssertionError(); }
            public android.content.pm.PackageManager getPackageManager() { throw new AssertionError(); }
        };
        check(RuntimeBridge.initialize(new Context() {
            public Context getApplicationContext() { return this; }
            public String getPackageName() { throw new AssertionError(); }
            public android.content.pm.PackageManager getPackageManager() { throw new AssertionError(); }
        }) == RuntimeBridge.INVALID_CONTEXT);
        check(RuntimeBridge.initialize(wrapper) == RuntimeBridge.INITIALIZED);
        check(RuntimeBridge.initialize(app) == RuntimeBridge.ALREADY_INITIALIZED);
        check(RuntimeBridge.initialize(new Application()) == RuntimeBridge.DIFFERENT_APPLICATION);
        check(readerFailures());
        check(nativeThreadRead());
        int fallbackCalls = ActivityThread.calls;
        check(readCertificate());
        check(ActivityThread.calls == fallbackCalls);
        app.fail = true;
        check(!readCertificate());
        app.fail = false;
        check(readCertificate());
        AtomicReference<Throwable> failure = new AtomicReference<>();
        ArrayList<Thread> threads = new ArrayList<>();
        for (int index = 0; index < 8; ++index) {
            Thread thread = new Thread(() -> {
                try {
                    for (int pass = 0; pass < 1000; ++pass) {
                        check(RuntimeBridge.initialize(wrapper) == RuntimeBridge.ALREADY_INITIALIZED);
                        check(hasContext());
                        check(readCertificate());
                    }
                } catch (Throwable error) { failure.set(error); }
            });
            threads.add(thread);
            thread.start();
        }
        for (Thread thread : threads) thread.join();
        if (failure.get() != null) throw new AssertionError(failure.get());
        System.gc();
        check(hasContext());
        check(readCertificate());
        System.out.println("production bridge/JNI/PackageManager checks passed");
    }
}
