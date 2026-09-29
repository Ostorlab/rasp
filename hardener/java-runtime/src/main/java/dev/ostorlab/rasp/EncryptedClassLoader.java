package dev.ostorlab.rasp;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureClassLoader;
import java.util.Arrays;

/** Parent-first loader for explicitly provisioned authenticated JVM class packages.
 * Encryption does not sandbox bytecode; package keys and sources must be trusted. */
public final class EncryptedClassLoader extends SecureClassLoader {
    public interface Source { byte[] read(String binaryName) throws IOException; }
    private final Source source;
    private final AuthenticatedPackage.KeyProvider keys;

    public EncryptedClassLoader(ClassLoader parent, Source source, AuthenticatedPackage.KeyProvider keys) {
        super(parent);
        if (source == null || keys == null) throw new IllegalArgumentException("Source and keys required");
        this.source = source;
        this.keys = keys;
    }

    @Override protected Class<?> findClass(String name) throws ClassNotFoundException {
        byte[] plaintext = null;
        try {
            plaintext = AuthenticatedPackage.open(source.read(name), name, keys);
            return defineClass(name, plaintext, 0, plaintext.length);
        } catch (IOException | GeneralSecurityException error) {
            throw new ClassNotFoundException("Authenticated class loading failed: " + name, error);
        } finally { if (plaintext != null) Arrays.fill(plaintext, (byte)0); }
    }
}
