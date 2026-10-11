package co.ostorlab.rasp;

import android.app.Application;
import android.content.Context;
import android.content.res.Configuration;
import dalvik.system.InMemoryDexClassLoader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;

/**
 * The generic loader the packer points the manifest at.
 *
 * <p>It loads the native runtime, which runs the checks and decrypts the app's original code, then
 * loads that code and hands control to the app's own Application class. The decrypted dex files are
 * kept in memory ({@link InMemoryDexClassLoader}) and never written to disk, which is why the
 * minimum supported API is 26.
 */
public final class RaspStub extends Application {

    static {
        System.loadLibrary("rasp");
    }

    private Application delegate;

    private static native byte[][] raspStart(byte[] key, byte[] payload);

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        try {
            byte[] configBytes = readAsset(base, "rasp/config.json");
            byte[] payload = readAsset(base, "rasp/payload.bin");
            JSONObject config = new JSONObject(new String(configBytes, StandardCharsets.UTF_8));
            byte[] key = hexToBytes(config.getString("key_hex"));
            String applicationClass = config.getString("application_class");

            byte[][] dexes = raspStart(key, payload);
            if (dexes == null) {
                throw new IllegalStateException("the runtime refused to start the app");
            }

            ByteBuffer[] buffers = new ByteBuffer[dexes.length];
            for (int i = 0; i < dexes.length; i++) {
                buffers[i] = ByteBuffer.wrap(dexes[i]);
            }
            ClassLoader loader = new InMemoryDexClassLoader(buffers, getClassLoader());
            delegate = (Application) loader.loadClass(applicationClass).getDeclaredConstructor().newInstance();

            Method attach = Application.class.getDeclaredMethod("attachBaseContext", Context.class);
            attach.setAccessible(true);
            attach.invoke(delegate, base);
        } catch (Exception error) {
            throw new RuntimeException("rasp: could not start the protected app", error);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        if (delegate != null) {
            delegate.onCreate();
        }
    }

    @Override
    public void onTerminate() {
        if (delegate != null) {
            delegate.onTerminate();
        }
        super.onTerminate();
    }

    @Override
    public void onLowMemory() {
        if (delegate != null) {
            delegate.onLowMemory();
        }
        super.onLowMemory();
    }

    @Override
    public void onTrimMemory(int level) {
        if (delegate != null) {
            delegate.onTrimMemory(level);
        }
        super.onTrimMemory(level);
    }

    @Override
    public void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        if (delegate != null) {
            delegate.onConfigurationChanged(configuration);
        }
    }

    private static byte[] readAsset(Context context, String name) throws Exception {
        try (InputStream input = context.getAssets().open(name)) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int read;
            while ((read = input.read(chunk)) != -1) {
                output.write(chunk, 0, read);
            }
            return output.toByteArray();
        }
    }

    private static byte[] hexToBytes(String hex) {
        int length = hex.length();
        byte[] bytes = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            int high = Character.digit(hex.charAt(i), 16);
            int low = Character.digit(hex.charAt(i + 1), 16);
            bytes[i / 2] = (byte) ((high << 4) + low);
        }
        return bytes;
    }
}
