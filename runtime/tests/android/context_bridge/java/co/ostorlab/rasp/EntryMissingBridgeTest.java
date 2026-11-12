package co.ostorlab.rasp;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.lang.reflect.InvocationTargetException;

/** Actual handlers with their compile-only bridge class absent, not a supplied native decision. */
public final class EntryMissingBridgeTest {
    private static final class WithoutBridge extends URLClassLoader {
        WithoutBridge(URL location){super(new URL[]{location},ClassLoader.getPlatformClassLoader());}
        @Override protected Class<?> loadClass(String name,boolean resolve) throws ClassNotFoundException {
            if(name.equals("co.ostorlab.rasp.RuntimeBridge") || name.startsWith("co.ostorlab.rasp.RuntimeBridge$"))throw new ClassNotFoundException(name);
            return super.loadClass(name,resolve);
        }
    }
    private static Object app(ClassLoader loader) throws Exception {
        Class<?> type=loader.loadClass("android.app.Application");Object value=type.getConstructor().newInstance();
        type.getField("name").set(value,"fixture.entrypoints");return value;
    }
    public static void main(String[] args) throws Exception {
        int failures=0;
        try(WithoutBridge loader=new WithoutBridge(Path.of(args[0]).toUri().toURL())) {
            Object calling=loader.loadClass("android.os.Binder").getField("callingUid").get(null);
            calling.getClass().getMethod("set",Object.class).invoke(calling,10002);
            Class<?> intent=loader.loadClass("android.content.Intent"),parcel=loader.loadClass("android.os.Parcel");
            Object service=loader.loadClass("fixture.entrypoints.DemoService").getConstructor().newInstance();
            service.getClass().getField("application").set(service,app(loader));
            Object endpoint=service.getClass().getMethod("onBind",intent).invoke(service,intent.getConstructor().newInstance());
            Object data=parcel.getMethod("obtain").invoke(null),reply=parcel.getMethod("obtain").invoke(null);
            parcel.getMethod("writeInterfaceToken",String.class).invoke(data,"fixture.entrypoints.Demo");
            try {
                Object result=loader.loadClass("android.os.IBinder").getMethod("transact",int.class,parcel,parcel,int.class).invoke(endpoint,1,data,reply,0);
                if(!Boolean.FALSE.equals(result))throw new AssertionError("missing bridge admitted Binder effect");
            } catch(InvocationTargetException failure) {
                System.out.println("FAIL actual Binder boundary escaped missing bridge: "+failure.getCause().getClass().getSimpleName());failures++;
            }
            Object provider=loader.loadClass("fixture.entrypoints.StatusProvider").getConstructor().newInstance();
            provider.getClass().getField("context").set(provider,app(loader));
            Class<?> uri=loader.loadClass("android.net.Uri");
            Object input=uri.getMethod("parse",String.class).invoke(null,"content://fixture.entrypoints.status/status");
            try {
                Object result=provider.getClass().getMethod("query",uri,String[].class,String.class,String[].class,String.class).invoke(provider,input,null,null,null,null);
                if(result!=null)throw new AssertionError("missing bridge published provider data");
            } catch(InvocationTargetException failure) {
                System.out.println("FAIL actual provider boundary escaped missing bridge: "+failure.getCause().getClass().getSimpleName());failures++;
            }
        }
        if(failures!=0)throw new AssertionError("missing bridge escaped "+failures+" actual boundaries");
        System.out.println("PASS actual Binder/provider handlers safely refuse absent compile-only bridge class");
    }
}
