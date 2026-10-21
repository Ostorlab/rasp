package co.ostorlab.rasp;

import dalvik.system.InMemoryDexClassLoader;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A class loader that serves the app's classes on demand: when a class is first needed, the native
 * runtime produces the dex that holds it (mapping it, reading the encrypted dex from the APK, and
 * decrypting it), and this loader defines the class from that dex. A dex whose classes are never used
 * is never produced. Framework classes resolve through the parent, so {@link #findClass} runs only for
 * the app's own names.
 *
 * <p>{@link #generate} is a native method bound by the runtime's {@code JNI_OnLoad} with
 * RegisterNatives, so it is not an exported symbol and the native library's symbols can be stripped or
 * renamed.
 */
public final class GeneratingClassLoader extends ClassLoader {

    static {
        System.loadLibrary("rasp");
    }

    /** One dex and the binary names of every class it defines. Built by the native runtime. */
    public static final class GeneratedDex {
        final byte[] bytes;
        final Set<String> classNames;

        public GeneratedDex(byte[] bytes, Set<String> classNames) {
            this.bytes = bytes;
            this.classNames = Collections.unmodifiableSet(new HashSet<String>(classNames));
        }
    }

    private static final Method FIND_CLASS;

    static {
        try {
            FIND_CLASS = ClassLoader.class.getDeclaredMethod("findClass", String.class);
            FIND_CLASS.setAccessible(true);
        } catch (NoSuchMethodException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private final ClassLoader base;
    private final String librarySearchPath;
    private final Map<String, InMemoryDexClassLoader> owners =
            new ConcurrentHashMap<String, InMemoryDexClassLoader>();
    private final Map<String, Class<?>> defined = new ConcurrentHashMap<String, Class<?>>();
    private final Map<String, Object> defineLocks = new ConcurrentHashMap<String, Object>();
    private final Object generationLock = new Object();
    private final ThreadLocal<Set<String>> inProgress = new ThreadLocal<Set<String>>();

    /**
     * @param parent the loader to delegate to first (the boot loader): framework/platform classes
     *     resolve through it.
     * @param base the app's base loader, which defines the framework classes that stayed in the base
     *     dexes. A name that is not a business class is defined from here, so a business class can
     *     reference a framework class even though base is this loader's child in the chain.
     * @param librarySearchPath where a generated class's System.loadLibrary looks for the app's .so.
     */
    public GeneratingClassLoader(ClassLoader parent, ClassLoader base, String librarySearchPath) {
        super(parent);
        this.base = base;
        this.librarySearchPath = librarySearchPath;
    }

    /** Produces the dex that defines {@code className}, or null when it is not a split-out class. Native. */
    private native GeneratedDex generate(String className);

    private Set<String> inProgress() {
        Set<String> set = inProgress.get();
        if (set == null) {
            set = new HashSet<String>();
            inProgress.set(set);
        }
        return set;
    }

    private Object lockFor(String name) {
        Object created = new Object();
        Object previous = defineLocks.putIfAbsent(name, created);
        return previous != null ? previous : created;
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        Class<?> loaded = defined.get(name);
        if (loaded != null) {
            return loaded;
        }
        Set<String> active = inProgress();
        if (!active.add(name)) {
            throw new ClassNotFoundException(name);
        }
        try {
            synchronized (lockFor(name)) {
                loaded = defined.get(name);
                if (loaded != null) {
                    return loaded;
                }
                InMemoryDexClassLoader owner = ownerOf(name);
                loaded = defineIn(owner != null ? owner : base, name);
                defined.put(name, loaded);
                return loaded;
            }
        } finally {
            active.remove(name);
        }
    }

    private static Class<?> defineIn(ClassLoader owner, String name) throws ClassNotFoundException {
        try {
            return (Class<?>) FIND_CLASS.invoke(owner, name);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof ClassNotFoundException) throw (ClassNotFoundException) cause;
            if (cause instanceof RuntimeException) throw (RuntimeException) cause;
            if (cause instanceof Error) throw (Error) cause;
            throw new ClassNotFoundException(name, cause);
        } catch (IllegalAccessException e) {
            throw new ClassNotFoundException(name, e);
        }
    }

    private InMemoryDexClassLoader ownerOf(String name) {
        InMemoryDexClassLoader owner = owners.get(name);
        if (owner != null) {
            return owner;
        }
        synchronized (generationLock) {
            owner = owners.get(name);
            if (owner != null) {
                return owner;
            }
            GeneratedDex dex = generate(name);
            if (dex == null) {
                return null;
            }
            InMemoryDexClassLoader child =
                    new InMemoryDexClassLoader(
                            new ByteBuffer[] {ByteBuffer.wrap(dex.bytes)}, librarySearchPath, this);
            for (String companion : dex.classNames) {
                owners.put(companion, child);
            }
            return child;
        }
    }
}
