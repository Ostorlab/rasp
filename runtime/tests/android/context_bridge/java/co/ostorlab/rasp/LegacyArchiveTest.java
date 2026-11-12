package co.ostorlab.rasp;

import android.app.Application;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

/** Calls the production identity dispatcher with a real FIFO/directory/device as its discovered base APK. */
public final class LegacyArchiveTest {
    private static void check(boolean condition, String detail) {
        if (!condition) throw new AssertionError(detail);
    }

    private static void checkIdentity(Path library) {
        long started = System.nanoTime();
        String[] observations = IdentityTest.rows();
        long elapsed = System.nanoTime() - started;
        check(Arrays.asList(observations).contains("id.code_path/dladdr ok " + library.toAbsolutePath()),
              "identity did not use the copied library beside the fixture base.apk");
        check(Arrays.asList(observations).contains("sig.cert_sha256/apk_signing_block error"),
              "legacy file reader did not report unavailable");
        check(Arrays.asList(observations).contains("sig.current_sha256.v1/apk_signing_block error"),
              "complete-set file reader did not report unavailable");
        check(elapsed < TimeUnit.MILLISECONDS.toNanos(500), "identity did not return promptly");
    }

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("rasp-identity-file-types-");
        Path libraries = Files.createDirectory(root.resolve("lib"));
        Path abi = Files.createDirectory(libraries.resolve("fixture-abi"));
        Path library = Files.copy(Path.of(args[0]), abi.resolve("librasp-fixture.so"));
        Path apk = root.resolve("base.apk");
        try {
            System.load(library.toAbsolutePath().toString());
            check(RuntimeBridge.initialize(new Application()) == RuntimeBridge.INITIALIZED, "Context initialization");
            Process fifo = new ProcessBuilder("mkfifo", apk.toString()).inheritIO().start();
            if (!fifo.waitFor(5, TimeUnit.SECONDS)) {
                fifo.destroyForcibly();
                throw new AssertionError("mkfifo did not finish");
            }
            check(fifo.exitValue() == 0, "mkfifo failed");
            // No writer and no reader worker: the native dispatcher returns synchronously on this calling thread.
            checkIdentity(library);
            Files.delete(apk);
            Files.createDirectory(apk);
            checkIdentity(library);
            Files.delete(apk);
            Files.createSymbolicLink(apk, Path.of("/dev/null"));
            checkIdentity(library);
            System.out.println("production identity: legacy + complete readers promptly reject FIFO/directory/device");
        } finally {
            Files.deleteIfExists(apk);
            Files.deleteIfExists(library);
            Files.deleteIfExists(abi);
            Files.deleteIfExists(libraries);
            Files.deleteIfExists(root);
        }
    }
}
