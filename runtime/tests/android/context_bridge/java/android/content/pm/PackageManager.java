package android.content.pm;

public class PackageManager {
    public static boolean fail;
    public static boolean nullInfo;
    public static boolean nullSigningInfo;
    public PackageInfo getPackageInfo(String name, int flags) {
        if (!name.equals("fixture.app") || flags != 0x08000000) throw new AssertionError();
        if (fail) throw new SecurityException("own package denied");
        if (nullInfo) return null;
        PackageInfo info = new PackageInfo();
        if (nullSigningInfo) info.signingInfo = null;
        return info;
    }
}
