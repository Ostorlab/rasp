package co.ostorlab.rasp;

import android.app.AppComponentFactory;
import android.content.pm.ApplicationInfo;

/**
 * The component factory the packer points the app's manifest at.
 *
 * <p>The packer sets {@code android:appComponentFactory} to this class and leaves the app's own
 * {@code android:name} alone. Android loads this factory from the stub dex and asks it for the class
 * loader before it creates the app's Application and any component.
 *
 * <p>The static initializer loads the native runtime. As it loads, the runtime runs the checks,
 * decrypts the app's original dex files, and builds a class loader that serves them from memory,
 * storing it in {@link #classLoader}. {@link #instantiateClassLoader} returns it,
 * so Android creates the app's own Application and every component from it and the app runs as
 * itself: {@code getApplication()} is the app's real Application, and its components load normally.
 * The stub calls no native method; it only reads the field the runtime fills.
 *
 * <p>The decrypted dex files are kept in memory ({@link dalvik.system.InMemoryDexClassLoader}) and
 * never written to disk, which is why the minimum supported API is 31, Android 12. API 31 is also
 * the first with a public {@link dalvik.system.InMemoryDexClassLoader} constructor that takes a
 * native-library search path, so the app's own native libraries load from its APK, and the first
 * where app native code can obtain the Java VM from a load-time constructor.
 */
public final class RaspStub extends AppComponentFactory {

    private static ClassLoader classLoader;

    static {
        System.loadLibrary("rasp");
    }

    @Override
    public ClassLoader instantiateClassLoader(ClassLoader parent, ApplicationInfo info) {
        ClassLoader loader = classLoader;
        if (loader == null) {
            throw new IllegalStateException("rasp: the runtime did not start the app");
        }
        return loader;
    }
}
