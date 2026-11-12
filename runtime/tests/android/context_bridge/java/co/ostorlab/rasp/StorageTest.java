package co.ostorlab.rasp;

import android.app.Application;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.concurrent.CountDownLatch;

/** Real JVM uses the shipped bridge/provider; only public Android services are fixture replacements. */
public final class StorageTest {
    private static native String snapshotNative(int mode);
    private static native String workerSnapshot();
    private static native String faultySnapshot(int fault);
    private static native String cycleSnapshot();
    private static native String lateCycleTransition(Runnable initialize);

    private static void require(boolean value, String detail) {
        if (!value) throw new AssertionError(detail);
    }
    private static String ready(String result) {
        require(result.startsWith("ready:"), result);
        String identity = result.substring(6);
        require(identity.matches("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"), identity);
        return identity;
    }
    private static final class Owner extends Application {
        volatile File directory;
        volatile boolean storageFail;
        volatile boolean nullDirectory;
        Owner(Path path) { directory = path.toFile(); }
        public File getNoBackupFilesDir() {
            if (storageFail) throw new IllegalStateException("locked/unavailable storage fixture");
            return nullDirectory ? null : directory;
        }
        public String getPackageName() { throw new AssertionError("provider must not infer package path"); }
    }
    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        if (args.length > 1) {
            require(Files.readString(Path.of("/proc/self/cmdline")).startsWith("unrelated.global.process\0"),
                "test did not run under the actual global process alias");
        }
        Path root = Files.createTempDirectory("rasp-public-owner-");
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"));
        try {
            require(snapshotNative(0).equals("unavailable"), "early provider fabricated a capability");
            require(workerSnapshot().equals("unavailable"), "early worker fabricated a capability");
            require(cycleSnapshot().equals("unavailable"), "early cycle provider fabricated a capability");
            Owner app = new Owner(root);
            String identity = ready(lateCycleTransition(() -> {
                require(RuntimeBridge.initialize(app) == RuntimeBridge.INITIALIZED, "bridge initialization");
            }));
            require(ready(snapshotNative(0)).equals(identity), "late cycle identity mismatch");
            require(ready(workerSnapshot()).equals(identity), "worker identity changed or attachment leaked");
            require(ready(cycleSnapshot()).equals(identity), "cycle consumer identity changed");
            require(Files.readString(root.resolve("rasp_install_id")).equals(identity), "wrong owner identity");
            require(Files.readString(root.resolve("rasp_private/consumer_probe")).equals(identity), "wrong queue owner");
            require(Files.getPosixFilePermissions(root.resolve("rasp_private")).equals(
                PosixFilePermissions.fromString("rwx------")), "queue mode");
            require(RuntimeBridge.initialize(app) == RuntimeBridge.ALREADY_INITIALIZED, "bridge duplicate init");
            for (int fault = 0; fault < 14; ++fault) {
                require(!faultySnapshot(fault).startsWith("ready:"), "JNI failure became success: " + fault);
                require(ready(snapshotNative(0)).equals(identity), "failure poisoned retry: " + fault);
            }
            app.storageFail = true;
            require(snapshotNative(0).equals("unavailable"), "exception was not cleared");
            app.storageFail = false;
            app.nullDirectory = true;
            require(snapshotNative(0).equals("unavailable"), "null directory fallback");
            app.nullDirectory = false;
            File saved = app.directory;
            app.directory = new File(root.toFile(), "x".repeat(4100));
            require(!snapshotNative(0).startsWith("ready:"), "unbounded path accepted");
            app.directory = new File(root.toFile(), "not-present");
            require(!snapshotNative(0).startsWith("ready:"), "missing directory fallback");
            Path alias = root.resolve("alias");
            Files.createSymbolicLink(alias, root);
            app.directory = alias.toFile();
            require(!snapshotNative(0).startsWith("ready:"), "final directory symlink accepted");
            app.directory = saved;
            Path intermediate = root.resolve("mutable");
            Files.createSymbolicLink(intermediate, root);
            app.directory = intermediate.resolve("rasp_private").toFile();
            require(!snapshotNative(0).startsWith("ready:"), "mutable intermediate symlink accepted");
            app.directory = saved;
            CountDownLatch start = new CountDownLatch(1);
            String[] values = new String[2];
            Thread[] threads = new Thread[2];
            for (int i = 0; i < threads.length; ++i) {
                final int slot = i;
                threads[i] = new Thread(() -> {
                    try { start.await(); } catch (InterruptedException error) { throw new AssertionError(error); }
                    for (int attempt = 0; attempt < 100; ++attempt) {
                        String value = snapshotNative(0);
                        if (value.startsWith("ready:")) { values[slot] = ready(value); return; }
                        Thread.yield();
                    }
                });
                threads[i].start();
            }
            start.countDown();
            for (Thread thread : threads) thread.join();
            for (String value : values) require(identity.equals(value), "concurrent retry failed");
            for (int i = 0; i < 100; ++i) require(ready(snapshotNative(0)).equals(identity), "reference/stability loop");
            System.out.println("public Application/private storage, late cycle consumer, worker detach and JNI failures PASS");
        } finally {
            try (var paths = Files.walk(root)) {
                paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                    try { Files.delete(path); } catch (Exception error) { throw new RuntimeException(error); }
                });
            }
        }
    }
}
