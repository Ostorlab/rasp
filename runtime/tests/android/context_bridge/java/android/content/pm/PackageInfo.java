package android.content.pm;

public class PackageInfo {
    public static String[] permissions = {"android.permission.DETECT_SCREEN_CAPTURE", "android.permission.DETECT_SCREEN_RECORDING"};
    public String[] requestedPermissions = permissions;
    public SigningInfo signingInfo = new SigningInfo();
}
