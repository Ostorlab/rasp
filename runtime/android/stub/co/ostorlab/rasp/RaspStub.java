package co.ostorlab.rasp;

import android.app.AppComponentFactory;
import android.content.pm.ApplicationInfo;

/**
 * The component factory the packer points the app's manifest at.
 *
 * <p>The packer sets {@code android:appComponentFactory} to this class, so Android asks it for the class loader before
 * it creates the app's Application or any component. This class is the only Java the packer ships: it loads the native
 * runtime, which installs the on-demand loader as the parent of the app's base loader.
 */
public final class RaspStub extends AppComponentFactory {

    static {
        System.loadLibrary("rasp");
    }

    /**
     * Has the runtime install the on-demand loader, then returns the app's base loader.
     *
     * @param base the app's base class loader, which Android created for the app's own dex files.
     * @param info the app's application info, whose {@code nativeLibraryDir} is where the app's native libraries are.
     * @return the base loader, with the on-demand loader as its parent when the runtime could install it.
     */
    @Override
    public ClassLoader instantiateClassLoader(ClassLoader base, ApplicationInfo info) {
        install(base, info.nativeLibraryDir);
        return base;
    }

    /**
     * Creates the on-demand loader and installs it as the parent of the base loader. It leaves the base loader
     * unchanged, and throws nothing, when it can't.
     *
     * @param base the app's base class loader.
     * @param librarySearchPath where a class the on-demand loader defines looks for the app's native libraries.
     */
    private static native void install(ClassLoader base, String librarySearchPath);
}
