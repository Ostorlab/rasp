package co.ostorlab.rasp;

/**
 * The on-demand class loader. Its only logic is {@link #findClass(String)}, a native method the runtime binds when it
 * loads this class.
 *
 * <p>The packer doesn't ship this class as a dex of the app. When CMake configures the runtime's build, {@code
 * cmake/loader_dex.cmake} compiles this file with javac and d8, and the dex is embedded in librasp.so as a byte array.
 * At run time the runtime loads that dex from memory.
 */
public final class GeneratingClassLoader extends ClassLoader {

    /** The app's base class loader, which holds the classes left in the app's own dex files. */
    private ClassLoader base;

    /**
     * Creates the loader.
     *
     * @param parent the loader to ask first, as {@link ClassLoader#ClassLoader(ClassLoader)} does.
     * @param base the app's base class loader.
     */
    public GeneratingClassLoader(ClassLoader parent, ClassLoader base) {
        super(parent);
        this.base = base;
    }

    /**
     * Finds a class that the parent loader did not find. Its body is native code, which the runtime binds when it loads
     * this class.
     *
     * @param name the binary name of the class, such as {@code com.example.Main}.
     * @return the class.
     * @throws ClassNotFoundException when the class can't be found.
     */
    @Override
    protected native Class<?> findClass(String name) throws ClassNotFoundException;
}
