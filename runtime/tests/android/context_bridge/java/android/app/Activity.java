package android.app;
public class Activity extends android.content.Context {
    public android.content.Intent intent;
    public ComponentCaller initialCaller=new ComponentCaller(),currentCaller=new ComponentCaller();
    public int initialCallerReads,currentCallerReads;
    public android.content.Intent getIntent(){return intent;}
    public void onNewIntent(android.content.Intent input){}
    public void onDestroy(){}
    public ComponentCaller getCaller(){initialCallerReads++;return initialCaller;}
    public ComponentCaller getCurrentCaller(){currentCallerReads++;return currentCaller;}
    public android.content.ComponentName getComponentName(){return new android.content.ComponentName(getPackageName(),getClass().getName());}
    public android.content.Context getApplicationContext(){return application;}
    public android.content.pm.PackageManager getPackageManager(){return application.getPackageManager();}
    public String getPackageName(){return application.getPackageName();}
    public int checkPermission(String permission,int pid,int uid){return application.checkPermission(permission,pid,uid);}
    public void onCreate(android.os.Bundle saved) {}
    public void onResume() {}
    public void onPause() {}
    public void setContentView(android.view.View view) {}
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
