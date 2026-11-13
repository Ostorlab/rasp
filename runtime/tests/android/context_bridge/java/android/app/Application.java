package android.app;

public class Application extends android.content.Context {
    public volatile boolean fail;
    public final java.util.Set<String> deniedPermissions = new java.util.HashSet<>();
    public boolean rejectCaptureExecutor;
    public boolean failPermission;
    @Override public java.util.concurrent.Executor getMainExecutor() {
        return command -> {
            if (rejectCaptureExecutor) throw new java.util.concurrent.RejectedExecutionException("main looper unavailable");
            command.run();
        };
    }
    @Override public int checkSelfPermission(String permission) {
        if (failPermission) throw new IllegalStateException("permission boundary failure");
        return deniedPermissions.contains(permission) ? -1 : 0;
    }
    public boolean forbidPackageName;
    public android.net.ConnectivityManager connectivity = new android.net.ConnectivityManager();
    public android.content.pm.PackageManager packages = new android.content.pm.PackageManager();
    public java.io.File getNoBackupFilesDir() { return null; }
    public boolean failRegistration;
    public boolean failUnregister;
    public final java.util.ArrayList<ActivityLifecycleCallbacks> callbacks = new java.util.ArrayList<>();
    public void registerActivityLifecycleCallbacks(ActivityLifecycleCallbacks callback) {
        callbacks.add(callback);
        if (failRegistration) throw new IllegalStateException("registration failure after registration");
    }
    public void unregisterActivityLifecycleCallbacks(ActivityLifecycleCallbacks callback) {
        if (failUnregister) throw new IllegalStateException("unregister failure");
        callbacks.remove(callback);
    }
    public void resume(Activity activity) {
        for (ActivityLifecycleCallbacks callback : callbacks.toArray(new ActivityLifecycleCallbacks[0])) callback.onActivityResumed(activity);
        for (ActivityLifecycleCallbacks callback : callbacks.toArray(new ActivityLifecycleCallbacks[0])) callback.onActivityPostResumed(activity);
    }
    public void pause(Activity activity) {
        for (ActivityLifecycleCallbacks callback : callbacks.toArray(new ActivityLifecycleCallbacks[0])) callback.onActivityPrePaused(activity);
        for (ActivityLifecycleCallbacks callback : callbacks.toArray(new ActivityLifecycleCallbacks[0])) callback.onActivityPaused(activity);
    }
    public void destroy(Activity activity) { for (ActivityLifecycleCallbacks callback : callbacks.toArray(new ActivityLifecycleCallbacks[0])) callback.onActivityDestroyed(activity); }
    public void stop(Activity activity) { for (ActivityLifecycleCallbacks callback : callbacks.toArray(new ActivityLifecycleCallbacks[0])) callback.onActivityStopped(activity); }
    public interface ActivityLifecycleCallbacks {
        void onActivityCreated(Activity activity, android.os.Bundle state);
        void onActivityStarted(Activity activity);
        void onActivityResumed(Activity activity);
        void onActivityPaused(Activity activity);
        void onActivityStopped(Activity activity);
        void onActivitySaveInstanceState(Activity activity, android.os.Bundle state);
        void onActivityDestroyed(Activity activity);
        default void onActivityPostResumed(Activity activity) {}
        default void onActivityPrePaused(Activity activity) {}
    }

    public boolean nullManager;
    public boolean failName;
    public String name = "fixture.app";
    public android.view.accessibility.AccessibilityManager accessibility = new android.view.accessibility.AccessibilityManager();
    public android.view.inputmethod.InputMethodManager ime = new android.view.inputmethod.InputMethodManager();
    public Object getSystemService(String name) {
        if (name.equals("connectivity")) return connectivity;
        if (name.equals("accessibility")) return accessibility;
        if (name.equals("input_method")) return ime;
        throw new AssertionError(name);
    }
    public android.content.Context getApplicationContext() { return this; }
    public String getPackageName() {
        if (forbidPackageName) throw new AssertionError("global process alias must not become package query input");
        if (failName) throw new IllegalStateException("name unavailable");
        return name;
    }
    public android.content.pm.PackageManager getPackageManager() {
        if (fail) throw new IllegalStateException("package manager failure");
        return nullManager ? null : packages;
    }
}
