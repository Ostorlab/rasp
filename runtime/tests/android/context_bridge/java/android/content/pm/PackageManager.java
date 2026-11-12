package android.content.pm;

public class PackageManager {
    public static class NameNotFoundException extends Exception {}
    public static final int GET_PERMISSIONS = 4096;
    public static final int PERMISSION_GRANTED = 0;
    public static boolean fail;
    public static boolean nullInfo;
    public static boolean nullSigningInfo;
    public PackageInfo getPackageInfo(String name, int flags) throws NameNotFoundException {
        if (!name.equals("fixture.app") || (flags != 0x08000000 && flags != GET_PERMISSIONS)) throw new AssertionError();
        if (fail) throw new SecurityException("own package denied");
        if (nullInfo) return null;
        PackageInfo info = new PackageInfo();
        if (nullSigningInfo) info.signingInfo = null;
        return info;
    }
}
