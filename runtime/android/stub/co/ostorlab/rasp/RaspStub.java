package co.ostorlab.rasp;

import android.app.AppComponentFactory;
import android.content.pm.ApplicationInfo;

/**
 * The component factory the packer points the app's manifest at.
 *
 * <p>The packer sets {@code android:appComponentFactory} to this class, so Android asks it for the class loader before
 * it creates the app's Application or any component. The stub's classes are the only Java the packer ships: this
 * factory loads the native runtime, which installs the on-demand loader as the parent of the app's base loader, and
 * {@link JArm} runs the key schedule's Java program through the runtime before any class loads.
 */
public final class RaspStub extends AppComponentFactory {

    static {
        System.loadLibrary("rasp");
    }

    /**
     * Has the runtime install the on-demand loader, arms it with the Java share, and returns the app's base
     * loader.
     *
     * <p>The install recovers the schedule's root natively and opens the dex store, but the store stays unarmed:
     * the business dexes are sealed under the armed master, which needs the share the app's Java program yields on
     * a real runtime. This method runs that program — resolving its classes through ART — before Android loads any
     * class, and arms the store with what it yields. A runtime that resolves the steps the way the packer predicted
     * arms correctly and the classes decrypt; anything else arms with a wrong share, every frame's tag fails, and
     * nothing reports why. When the program cannot run, the store is left unarmed and no business class decrypts.
     *
     * @param base the app's base class loader, which Android created for the app's own dex files.
     * @param info the app's application info, whose {@code nativeLibraryDir} is where the app's native libraries are.
     * @return the base loader, with the on-demand loader as its parent when the runtime could install it.
     */
    @Override
    public ClassLoader instantiateClassLoader(ClassLoader base, ApplicationInfo info) {
        install(base, info.nativeLibraryDir);
        byte[] steps = program();
        if (steps != null) {
            try {
                arm(JArm.run(base, steps));
            } catch (RuntimeException | ReflectiveOperationException ignored) {
                // An unrunnable program leaves the store unarmed: no business class decrypts, and nothing says why.
            }
        }
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

    /**
     * Returns the app's decrypted Java program, or null when the store never opened or the app shipped none.
     *
     * @return the program's bytes, or null.
     */
    private static native byte[] program();

    /**
     * Arms the store with the share the Java program produced, and lets the business dexes decrypt. A wrong share
     * arms just as quietly, and every frame's tag fails.
     *
     * @param share the 32-byte share, or null to leave the store unarmed.
     */
    private static native void arm(byte[] share);
}
