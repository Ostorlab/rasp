package co.ostorlab.rasp;

import android.app.AppComponentFactory;
import android.content.pm.ApplicationInfo;
import android.util.Log;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * The component factory the packer points the app's manifest at.
 *
 * <p>The packer sets {@code android:appComponentFactory} to this class, so Android asks it for the class loader before
 * it creates the app's Application or any component. This class is the only Java the packer ships: it loads the native
 * runtime and asks it for the on-demand loader. The runtime loads the loader's dex, which is embedded in the library,
 * and returns a loader, which this class installs as the parent of the app's base loader, so the chain is:
 *
 * <pre>boot &lt;- GeneratingClassLoader (business, on demand) &lt;- base (framework)</pre>
 *
 * <p>Framework classes stay in the base dex and resolve normally; the app's own ("business") classes were split out,
 * encrypted, and are served on demand by that loader. Inserting it as the base's parent (rather than
 * returning it) is what lets a framework class reference a business class.
 *
 * <p>Fails open: on any error the original loader is returned unchanged.
 */
public final class RaspStub extends AppComponentFactory {

    static {
        System.loadLibrary("rasp");
    }

    /**
     * Installs the on-demand loader as the parent of the app's base loader.
     *
     * @param base the app's base class loader, which Android created for the app's own dex files.
     * @param info the app's application info, whose {@code nativeLibraryDir} is where the app's native libraries are.
     * @return the base loader, with the on-demand loader as its parent when the runtime could create it, and unchanged
     *     otherwise.
     */
    @Override
    public ClassLoader instantiateClassLoader(ClassLoader base, ApplicationInfo info) {
        try {
            liftHiddenApi();
            ClassLoader generating = install(base, info.nativeLibraryDir);
            if (generating == null) {
                return base;
            }
            setParent(base, generating);
            return base;
        } catch (Throwable error) {
            Log.e("RASP", "could not install the loader, falling back", error);
            return base;
        }
    }

    /**
     * Asks the native runtime for the on-demand loader. The runtime loads the loader's dex, which is embedded in the
     * library, binds the loader's native findClass, and creates the loader.
     *
     * @param base the app's base loader, which holds the framework classes the loader falls back to.
     * @param librarySearchPath where a generated class's System.loadLibrary looks for the app's .so.
     * @return the loader to install, or null when the runtime could not create it.
     */
    private static native ClassLoader install(ClassLoader base, String librarySearchPath);

    /**
     * Overwrites ClassLoader.parent, which is otherwise final.
     *
     * @param child the loader whose parent changes.
     * @param newParent its new parent.
     * @throws Exception when the field can't be found or written by reflection.
     */
    private static void setParent(ClassLoader child, ClassLoader newParent) throws Exception {
        Field parent = ClassLoader.class.getDeclaredField("parent");
        parent.setAccessible(true);
        parent.set(child, newParent);
    }

    /**
     * Exempts the app from the non-SDK API blocklist, so the reflection in setParent is allowed. It ignores any failure:
     * older or newer platforms may not need or allow this, and the field access may still work.
     */
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
            setExemptions.invoke(
                    runtime,
                    new Object[] {new String[] {"Ljava/lang/ClassLoader;->parent:Ljava/lang/ClassLoader;"}});
        } catch (Throwable ignored) {
        }
    }
}
