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
 * A class loader that serves the app's classes on demand: when a class is first needed, it asks the
 * generator for the dex that holds it, decrypts/opens that dex once, and defines the class from it.
 * A dex whose classes are never used is never opened. Framework classes (android.*, java.*) resolve
 * through the parent, so findClass runs only for the app's own names.
 */
public final class GeneratingClassLoader extends ClassLoader {

    /** Produces the dex that holds a class, on demand. */
    public interface DexGenerator {
        GeneratedDex generate(String className) throws Exception;
    }

    /** One dex and the binary names of every class it defines. */
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

    private final DexGenerator generator;
    private final String librarySearchPath;
    private final Map<String, InMemoryDexClassLoader> owners =
            new ConcurrentHashMap<String, InMemoryDexClassLoader>();
    private final Map<String, Class<?>> defined = new ConcurrentHashMap<String, Class<?>>();
    private final Map<String, Object> defineLocks = new ConcurrentHashMap<String, Object>();
    private final Object generationLock = new Object();
    private final ThreadLocal<Set<String>> inProgress = new ThreadLocal<Set<String>>();

    public GeneratingClassLoader(ClassLoader parent, DexGenerator generator, String librarySearchPath) {
        super(parent);
        this.generator = generator;
        this.librarySearchPath = librarySearchPath;
    }

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
                if (owner == null) {
                    throw new ClassNotFoundException(name);
                }
                loaded = defineIn(owner, name);
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

    private InMemoryDexClassLoader ownerOf(String name) throws ClassNotFoundException {
        InMemoryDexClassLoader owner = owners.get(name);
        if (owner != null) {
            return owner;
        }
        synchronized (generationLock) {
            owner = owners.get(name);
            if (owner != null) {
                return owner;
            }
            GeneratedDex dex;
            try {
                dex = generator.generate(name);
            } catch (Exception e) {
                throw new ClassNotFoundException("generating dex for " + name + " failed", e);
            }
            if (dex == null) {
                return null;
            }
            if (!dex.classNames.contains(name)) {
                throw new ClassNotFoundException("dex for " + name + " does not list it");
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
