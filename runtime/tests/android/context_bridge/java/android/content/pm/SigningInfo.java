package android.content.pm;

/** Framework-shaped boundary fixture; it does not implement Android signature verification. */
public class SigningInfo {
    public static Signature[] current = new Signature[] { new Signature() };
    public static Signature[] history = current;
    public static boolean multiple;
    public static boolean failCurrent;
    public static boolean failHistory;
    public static boolean failMultiple;
    public static int historyCalls;
    public Signature[] getApkContentsSigners() {
        if (failCurrent) throw new SecurityException("current denied");
        return current;
    }
    public Signature[] getSigningCertificateHistory() {
        ++historyCalls;
        if (failHistory) throw new SecurityException("history denied");
        return history;
    }
    public boolean hasMultipleSigners() {
        if (failMultiple) throw new SecurityException("multiple denied");
        return multiple;
    }
}
