package co.ostorlab.rasp;

/** The native runtime surface: decrypts one business dex frame. Implemented in librasp.so. */
public final class Native {

    static {
        System.loadLibrary("rasp");
    }

    /** Decrypts one encrypted business dex frame, or returns null when it cannot be decrypted. */
    public static native byte[] decrypt(byte[] frame);

    private Native() {}
}
