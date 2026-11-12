package android.app;

public class Application extends android.content.Context {
    public volatile boolean fail;
    public android.content.Context getApplicationContext() { return this; }
    public String getPackageName() { return "fixture.app"; }
    public android.content.pm.PackageManager getPackageManager() {
        if (fail) throw new IllegalStateException("package manager failure");
        return new android.content.pm.PackageManager();
    }
}
