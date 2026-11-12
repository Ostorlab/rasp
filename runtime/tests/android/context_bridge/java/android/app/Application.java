package android.app;

public class Application extends android.content.Context {
    public volatile boolean fail;
    public android.view.accessibility.AccessibilityManager accessibility = new android.view.accessibility.AccessibilityManager();
    public android.view.inputmethod.InputMethodManager ime = new android.view.inputmethod.InputMethodManager();
    public Object getSystemService(String name) {
        if (name.equals("accessibility")) return accessibility;
        if (name.equals("input_method")) return ime;
        throw new AssertionError(name);
    }
    public android.content.Context getApplicationContext() { return this; }
    public String getPackageName() { return "fixture.app"; }
    public android.content.pm.PackageManager getPackageManager() {
        if (fail) throw new IllegalStateException("package manager failure");
        return new android.content.pm.PackageManager();
    }
}
