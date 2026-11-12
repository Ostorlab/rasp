package android.app;

public final class ActivityThread {
    public static volatile Application application;
    public static int calls;
    public static Application currentApplication() {
        ++calls;
        return application;
    }
}
