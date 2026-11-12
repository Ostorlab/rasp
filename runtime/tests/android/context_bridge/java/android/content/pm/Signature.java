package android.content.pm;

public class Signature {
    private final byte[] bytes;
    public static boolean fail;
    public Signature() { this(new byte[] { 1, 2, 3 }); }
    public Signature(byte[] bytes) { this.bytes = bytes; }
    public byte[] toByteArray() {
        if (fail) throw new IllegalStateException("signature unavailable");
        return bytes;
    }
}
