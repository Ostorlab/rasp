package co.ostorlab.rasp;

import android.util.Log;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Serves the app's business dex files from the APK on demand, decrypting each through {@link Native}.
 *
 * <p>At build time the packer writes {@code assets/pack_map.txt}, one line per business class: its
 * binary name, a comma, and the asset dex that holds it (for example {@code
 * com.app.Foo,business/3.dex}). A dex is read and decrypted only the first time one of its classes is
 * needed.
 */
public final class AssetDexGenerator implements GeneratingClassLoader.DexGenerator {

    private static final String MAP = "assets/pack_map.txt";

    private final ZipFile apk;
    private final Map<String, String> classToFile = new HashMap<String, String>();
    private final Map<String, Set<String>> fileToClasses = new HashMap<String, Set<String>>();

    public AssetDexGenerator(String sourceDir) throws Exception {
        this.apk = new ZipFile(sourceDir);
        ZipEntry mapEntry = apk.getEntry(MAP);
        if (mapEntry == null) {
            throw new IllegalStateException("missing " + MAP);
        }
        BufferedReader reader =
                new BufferedReader(
                        new InputStreamReader(apk.getInputStream(mapEntry), StandardCharsets.UTF_8));
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                int comma = line.indexOf(',');
                if (comma <= 0) {
                    continue;
                }
                String name = line.substring(0, comma);
                String file = line.substring(comma + 1).trim();
                classToFile.put(name, file);
                Set<String> classes = fileToClasses.get(file);
                if (classes == null) {
                    classes = new HashSet<String>();
                    fileToClasses.put(file, classes);
                }
                classes.add(name);
            }
        } finally {
            reader.close();
        }
        Log.i("RASP", "map: " + classToFile.size() + " classes in " + fileToClasses.size() + " dex");
    }

    @Override
    public GeneratingClassLoader.GeneratedDex generate(String className) throws Exception {
        String file = classToFile.get(className);
        if (file == null) {
            return null;
        }
        byte[] frame = read("assets/" + file);
        byte[] bytes = Native.decrypt(frame);
        if (bytes == null) {
            throw new IllegalStateException("could not decrypt " + file);
        }
        Log.i("RASP", "decrypted " + file + " for " + className);
        return new GeneratingClassLoader.GeneratedDex(bytes, fileToClasses.get(file));
    }

    private byte[] read(String entryName) throws Exception {
        ZipEntry entry = apk.getEntry(entryName);
        if (entry == null) {
            throw new IllegalStateException("missing asset " + entryName);
        }
        InputStream in = apk.getInputStream(entry);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int read;
            while ((read = in.read(chunk)) != -1) {
                out.write(chunk, 0, read);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }
}
