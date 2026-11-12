package android.app;

public class Application extends android.content.Context {
    public volatile boolean fail;
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
    public android.content.Context getApplicationContext() { return this; }
    public String getPackageName() { return "fixture.app"; }
    public android.content.pm.PackageManager getPackageManager() {
        if (fail) throw new IllegalStateException("package manager failure");
        return new android.content.pm.PackageManager();
    }
}
