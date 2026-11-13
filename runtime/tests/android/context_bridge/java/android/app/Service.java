package android.app;
public abstract class Service extends android.content.Context {
 public static final int START_NOT_STICKY=2;public Application application=new Application();
 public abstract android.os.IBinder onBind(android.content.Intent intent);
 public int onStartCommand(android.content.Intent intent,int flags,int startId){return 0;}
 public android.content.Context getApplicationContext(){return application;}
 public android.content.pm.PackageManager getPackageManager(){return application.getPackageManager();}
 public String getPackageName(){return application.getPackageName();}
 public int checkCallingPermission(String permission){return application.checkCallingPermission(permission);}
}
