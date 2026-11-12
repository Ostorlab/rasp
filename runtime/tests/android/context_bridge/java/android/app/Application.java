package android.app;

public class Application extends android.content.Context {
    public volatile boolean fail;
    public boolean nullManager;
    public boolean failName;
    public String name = "fixture.app";
    public android.content.Context getApplicationContext() { return this; }
    public String getPackageName() {
        if (failName) throw new IllegalStateException("name unavailable");
        return name;
    }
    public android.content.pm.PackageManager getPackageManager() {
        if (fail) throw new IllegalStateException("package manager failure");
        return nullManager ? null : new android.content.pm.PackageManager();
    }
}
