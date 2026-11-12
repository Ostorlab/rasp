package android.content.pm;

public class PackageManager {
    public PackageInfo getPackageInfo(String name, int flags) {
        if (!name.equals("fixture.app") || flags != 0x08000000) throw new AssertionError();
        return new PackageInfo();
    }
}
