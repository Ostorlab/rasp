package dev.ostorlab.rasp;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** JVM/Android envelope: RAJ1 || nonce[12] || AES-GCM ciphertext and 128-bit tag.
 * Identity is authenticated as AAD. Compatible with Android API 26+. */
public final class AuthenticatedPackage {
    private static final byte[] MAGIC = {82, 65, 74, 49};
    private static final int MAX_BYTES = 16 * 1024 * 1024;
    private AuthenticatedPackage() {}

    public interface KeyProvider { byte[] keyFor(String identity) throws GeneralSecurityException; }

    private static byte[] key(KeyProvider provider, String identity) throws GeneralSecurityException {
        byte[] provided = provider.keyFor(identity);
        if (provided == null || (provided.length != 16 && provided.length != 32))
            throw new GeneralSecurityException("AES key must contain 16 or 32 bytes");
        return provided.clone();
    }

    private static byte[] aad(String identity) throws GeneralSecurityException {
        if (identity == null || identity.isEmpty() || identity.length() > 4096)
            throw new GeneralSecurityException("Invalid resource identity");
        return ("rasp/jvm-package/v1\u0000" + identity).getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] seal(byte[] plaintext, String identity, KeyProvider provider) throws GeneralSecurityException {
        byte[] associated = aad(identity);
        if (plaintext == null || plaintext.length > MAX_BYTES) throw new GeneralSecurityException("Invalid resource size");
        byte[] secret = key(provider, identity);
        try {
            byte[] nonce = new byte[12];
            new SecureRandom().nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secret, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(associated);
            byte[] encrypted = cipher.doFinal(plaintext);
            byte[] result = new byte[16 + encrypted.length];
            System.arraycopy(MAGIC, 0, result, 0, 4);
            System.arraycopy(nonce, 0, result, 4, 12);
            System.arraycopy(encrypted, 0, result, 16, encrypted.length);
            return result;
        } finally { Arrays.fill(secret, (byte)0); }
    }

    public static byte[] open(byte[] envelope, String identity, KeyProvider provider) throws GeneralSecurityException {
        byte[] associated = aad(identity);
        if (envelope == null || envelope.length < 32 || envelope.length > MAX_BYTES + 32)
            throw new GeneralSecurityException("Invalid package size");
        for (int i = 0; i < 4; i++) if (envelope[i] != MAGIC[i]) throw new GeneralSecurityException("Invalid package version");
        byte[] secret = key(provider, identity);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(secret, "AES"), new GCMParameterSpec(128, envelope, 4, 12));
            cipher.updateAAD(associated);
            // No plaintext is returned until doFinal authenticates the complete tag.
            return cipher.doFinal(envelope, 16, envelope.length - 16);
        } finally { Arrays.fill(secret, (byte)0); }
    }
}
