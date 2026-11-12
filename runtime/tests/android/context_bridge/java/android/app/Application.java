package android.app;

public class Application extends android.content.Context {
    public volatile boolean fail;
    public boolean forbidPackageName;
    public android.view.accessibility.AccessibilityManager accessibility = new android.view.accessibility.AccessibilityManager();
    public android.view.inputmethod.InputMethodManager ime = new android.view.inputmethod.InputMethodManager();
    public android.net.ConnectivityManager connectivity = new android.net.ConnectivityManager();
    public android.content.pm.PackageManager packages = new android.content.pm.PackageManager();
    public Object getSystemService(String name) {
        if (name.equals("connectivity")) return connectivity;
        if (name.equals("accessibility")) return accessibility;
        if (name.equals("input_method")) return ime;
        throw new AssertionError(name);
    }
    public android.content.Context getApplicationContext() { return this; }
    public String getPackageName() { if(forbidPackageName) throw new AssertionError("global process alias must not become package query input"); return "fixture.app"; }
    public android.content.pm.PackageManager getPackageManager() {
        if (fail) throw new IllegalStateException("package manager failure");
        return packages;
    }
}
