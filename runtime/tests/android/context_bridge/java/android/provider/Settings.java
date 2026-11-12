package android.provider;
public final class Settings {
    public static final class Secure {
        public static String listeners = "";
        public static boolean denied;
        public static String getString(android.content.ContentResolver resolver, String key) {
            if (denied) throw new SecurityException("denied");
            if (!key.equals("enabled_notification_listeners")) throw new AssertionError(key);
            return listeners;
        }
    }
}
