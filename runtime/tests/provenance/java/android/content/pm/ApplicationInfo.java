package android.content.pm;

/** Public SDK field boundary; no ART internals or class loading is simulated. */
public final class ApplicationInfo {
    public String sourceDir = "/data/app/secret/base.apk";
    public String[] splitSourceDirs = {"/data/app/secret/feature.apk"};
    public String nativeLibraryDir = "/data/app/secret/lib";
}
