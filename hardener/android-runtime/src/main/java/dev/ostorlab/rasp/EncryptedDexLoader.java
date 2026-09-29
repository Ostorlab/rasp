package dev.ostorlab.rasp;

import android.os.Build;
import dalvik.system.InMemoryDexClassLoader;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/** Authenticated in-memory DEX loading on Android API 26+. No lower-API fallback. */
public final class EncryptedDexLoader {
    private EncryptedDexLoader() {}
    public static ClassLoader load(byte[] envelope, String identity,
                                   AuthenticatedPackage.KeyProvider keys, ClassLoader parent)
            throws GeneralSecurityException {
        if (Build.VERSION.SDK_INT < 26) throw new UnsupportedOperationException("Authenticated DEX loading requires API 26+");
        byte[] dex = AuthenticatedPackage.open(envelope, identity, keys);
        // ART needs the plaintext buffer. Do not claim plaintext is inaccessible to an in-process analyst.
        return new InMemoryDexClassLoader(ByteBuffer.wrap(dex).asReadOnlyBuffer(), parent);
    }
}
