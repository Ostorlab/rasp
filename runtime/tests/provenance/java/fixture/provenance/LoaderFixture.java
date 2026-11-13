package fixture.provenance;

/** Public Android-service boundary replacements; java.lang parent/name operations run on a real VM. */
public final class LoaderFixture {
    /** A legitimate custom plugin chain with no class-resolution override. */
    public static final class PluginLoader extends ClassLoader {
        public PluginLoader(ClassLoader parent) { super(parent); }
    }
    /** Context getClassLoader/getApplicationInfo boundary with explicit failure/race cases. */
    public static final class Application {
        private final ClassLoader loader;
        private final int mode;
        private int calls;
        public Application(int depth, int selectedMode) {
            ClassLoader parent = null;
            for (int index = 0; index < depth; ++index) parent = new PluginLoader(parent);
            loader = parent;
            mode = selectedMode;
        }
        public ClassLoader getClassLoader() {
            if (mode == 1) throw new SecurityException("probe boundary refusal");
            if (mode == 2 && ++calls > 1) return new PluginLoader(null);
            return loader;
        }
        public android.content.pm.ApplicationInfo getApplicationInfo() {
            android.content.pm.ApplicationInfo info = new android.content.pm.ApplicationInfo();
            if (mode == 3) info.splitSourceDirs = new String[65];
            if (mode == 4) info.sourceDir = "/data/app/../other/base.apk";
            return info;
        }
    }
    public static Application make(int depth, int mode) { return new Application(depth, mode); }
}
