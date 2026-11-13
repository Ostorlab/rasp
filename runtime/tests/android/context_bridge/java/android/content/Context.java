package android.content;

public abstract class Context {
    public abstract Context getApplicationContext();
    public abstract android.content.pm.PackageManager getPackageManager();
    public abstract String getPackageName();
    public Object getSystemService(String name) { return null; }
    public ContentResolver getContentResolver() { return new ContentResolver(); }
    public java.util.concurrent.Executor getMainExecutor() { return Runnable::run; }
    public int checkSelfPermission(String permission) { return 0; }
    public android.content.pm.ApplicationInfo getApplicationInfo(){return new android.content.pm.ApplicationInfo();}
    public int checkCallingPermission(String permission){return 0;}
    public int checkPermission(String permission,int pid,int uid){return checkCallingPermission(permission);}
}
