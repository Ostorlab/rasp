package android.app;
public class Activity {
    public Application application;
    public Application getApplication() { return application; }
    public final android.view.WindowManager manager = new android.view.WindowManager();
    public android.view.WindowManager getWindowManager() { return manager; }
    public interface ScreenCaptureCallback { void onScreenCaptured(); }
    public final java.util.List<ScreenCaptureCallback> screenshots = new java.util.ArrayList<>();
    private final java.util.Map<ScreenCaptureCallback, java.util.concurrent.Executor> executors = new java.util.IdentityHashMap<>();
    public boolean failCaptureRegistration;
    public boolean failCaptureRemoval;
    public void registerScreenCaptureCallback(java.util.concurrent.Executor executor, ScreenCaptureCallback callback) {
        screenshots.add(callback);
        executors.put(callback, executor);
        if (failCaptureRegistration) throw new IllegalStateException("capture registration after side effects");
    }
    public void unregisterScreenCaptureCallback(ScreenCaptureCallback callback) {
        if (failCaptureRemoval) throw new IllegalStateException("capture unregister");
        screenshots.remove(callback);
        executors.remove(callback);
    }
    public void screenshot() { for (ScreenCaptureCallback callback : screenshots.toArray(new ScreenCaptureCallback[0])) executors.get(callback).execute(callback::onScreenCaptured); }
    public boolean failWindow;
    private final android.view.Window window = new android.view.Window();
    public android.view.Window getWindow() {
        if (failWindow) throw new IllegalStateException("activity window lookup");
        return window;
    }
}
