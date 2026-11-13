package android.content.pm;

public class PackageManager {
    public static final int CERT_INPUT_SHA256=1;
    public int callerUid=10002;public String[] callerPackages={"fixture.entrycaller"};public boolean pinMatches=true,callerFailure;
    public PermissionInfo permission=new PermissionInfo();
    public String[] getPackagesForUid(int uid){if(callerFailure)throw new SecurityException();return callerPackages;}
    public ApplicationInfo getApplicationInfo(String name,int flags) throws NameNotFoundException {if(callerFailure)throw new NameNotFoundException();ApplicationInfo result=new ApplicationInfo();result.uid=callerUid;return result;}
    public PermissionInfo getPermissionInfo(String name,int flags) throws NameNotFoundException {return permission;}
    public boolean hasSigningCertificate(String name,byte[] pin,int kind){if(!name.equals("fixture.entrycaller") || pin==null || pin.length!=32 || kind!=CERT_INPUT_SHA256)throw new AssertionError("caller pin boundary");return pinMatches && java.util.Arrays.equals(pin,new byte[32]);}
    public static final int GET_PERMISSIONS = 4096;
    public static final int PERMISSION_GRANTED = 0;
    public static boolean fail;
    public static boolean nullInfo;
    public static boolean nullSigningInfo;
    public static class NameNotFoundException extends Exception {}
    public java.util.Set<String> visible = new java.util.HashSet<>();
    public int calls;
    public int failure;
    public PackageInfo getPackageInfo(String name, int flags) throws NameNotFoundException {
        if (flags == 0) {
            ++calls;
            if (!java.util.Set.of("com.topjohnwu.magisk", "me.weishu.kernelsu", "me.bmax.apatch").contains(name)) throw new AssertionError("inventory");
            if (failure == 1) throw new SecurityException("denied");
            if (failure == 2) return null;
            if (failure == 3 && calls % 3 == 2) throw new IllegalStateException("disappeared during pass");
            if (!visible.contains(name)) throw new NameNotFoundException();
            return new PackageInfo();
        }
        if (!name.equals("fixture.app") || (flags != 0x08000000 && flags != GET_PERMISSIONS)) throw new AssertionError();
        if (fail) throw new SecurityException("own package denied");
        if (nullInfo) return null;
        PackageInfo info = new PackageInfo();
        if (nullSigningInfo) info.signingInfo = null;
        return info;
    }
}
