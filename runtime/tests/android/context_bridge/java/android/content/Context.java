package android.content;

public abstract class Context {
    public abstract Context getApplicationContext();
    public abstract android.content.pm.PackageManager getPackageManager();
    public abstract String getPackageName();
}
