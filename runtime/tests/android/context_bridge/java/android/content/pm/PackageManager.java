package android.content.pm;

public class PackageManager {
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
        if (!name.equals("fixture.app") || flags != 0x08000000) throw new AssertionError();
        return new PackageInfo();
    }
}
