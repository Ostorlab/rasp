package co.ostorlab.rasp;

import android.app.AppComponentFactory;
import android.content.pm.ApplicationInfo;
import android.util.Log;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * The component factory the packer points the app's manifest at.
 *
 * <p>The packer sets {@code android:appComponentFactory} to this class. Android asks it for the class
 * loader before it creates the app's Application or any component. It installs a {@link
 * GeneratingClassLoader} as the parent of the app's base loader, so the chain is:
 *
 * <pre>boot &lt;- GeneratingClassLoader (business, on demand) &lt;- base (framework)</pre>
 *
 * <p>Framework classes stay in the base dex and resolve normally; the app's own ("business") classes
 * were split out, encrypted, and are served on demand by the generating loader. Inserting it as the
 * base's parent (rather than returning it) is what lets a framework class reference a business class.
 *
 * <p>Fails open: on any error the original loader is returned unchanged.
 */
public final class RaspStub extends AppComponentFactory {

    @Override
    public ClassLoader instantiateClassLoader(ClassLoader base, ApplicationInfo info) {
        try {
            liftHiddenApi();
            ClassLoader boot = base.getParent();
            GeneratingClassLoader generating =
                    new GeneratingClassLoader(boot, base, info.nativeLibraryDir);
            setParent(base, generating);
            return base;
        } catch (Throwable error) {
            Log.e("RASP", "could not install the loader, falling back", error);
            return base;
        }
    }

    /** Overwrites ClassLoader.parent, which is otherwise final. */
    private static void setParent(ClassLoader child, ClassLoader newParent) throws Exception {
        Field parent = ClassLoader.class.getDeclaredField("parent");
        parent.setAccessible(true);
        parent.set(child, newParent);
    }

    /** Exempts the app from the non-SDK API blocklist, so the reflection above is allowed. */
    private static void liftHiddenApi() {
        try {
            Method forName = Class.class.getDeclaredMethod("forName", String.class);
            Method getDeclaredMethod =
                    Class.class.getDeclaredMethod("getDeclaredMethod", String.class, Class[].class);
            Class<?> vmRuntime = (Class<?>) forName.invoke(null, "dalvik.system.VMRuntime");
            Method getRuntime = (Method) getDeclaredMethod.invoke(vmRuntime, "getRuntime", (Object) null);
            Method setExemptions =
                    (Method)
                            getDeclaredMethod.invoke(
                                    vmRuntime, "setHiddenApiExemptions", new Class[] {String[].class});
            Object runtime = getRuntime.invoke(null);
            setExemptions.invoke(runtime, new Object[] {new String[] {"L"}});
        } catch (Throwable ignored) {
            // Older or newer platforms may not need or allow this; the field access may still work.
        }
    }
}
