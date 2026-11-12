package co.ostorlab.rasp;

import android.app.ActivityThread;
import android.app.Application;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;

/** Real JVM + compiled production dispatcher; simulated Android services are not ART/device verification. */
public final class IdentityTest {
    private static native String[] rows();
    private static native boolean faults();
    private static native boolean threadReads();
    private static final String CURRENT = "sig.current_sha256.v1/package_manager";
    private static final String HISTORY = "sig.history_sha256.v1/package_manager";
    private static final String PACKAGE = "id.package.v1/application_context";

    private static void check(boolean value) {
        if (!value) throw new AssertionError();
    }
    private static String digest(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
    private static String row(String[] rows, String key) {
        return Arrays.stream(rows).filter(value -> value.startsWith(key + " ")).findFirst().orElseThrow();
    }
    private static void expect(String[] rows, String key, String value) {
        String actual = row(rows, key);
        if (!actual.equals(key + " " + value)) throw new AssertionError(actual + " expected " + value);
    }
    private static void reset(Signature current) {
        SigningInfo.current = new Signature[] { current };
        SigningInfo.history = SigningInfo.current;
        SigningInfo.multiple = false;
        SigningInfo.failCurrent = SigningInfo.failHistory = SigningInfo.failMultiple = false;
        PackageManager.fail = PackageManager.nullInfo = PackageManager.nullSigningInfo = false;
        Signature.fail = false;
    }
    private static void currentError() {
        expect(rows(), CURRENT, "error");
    }
    private static byte[] largeEnvelope() {
        // Structurally valid envelope only: this fixture deliberately does not claim X.509 or signature validity.
        byte[] encoded = new byte[60018];
        encoded[0] = 0x30; encoded[1] = (byte) 0x82;
        encoded[2] = (byte) (60014 >> 8); encoded[3] = (byte) 60014;
        byte[] prefix = {0x30, 3, 2, 1, 1, 0x30, 3, 6, 1, 42, 3, (byte) 0x82, (byte) (60000 >> 8), (byte) 60000};
        System.arraycopy(prefix, 0, encoded, 4, prefix.length);
        return encoded;
    }

    public static void main(String[] args) throws Exception {
        byte[] oldDer = Files.readAllBytes(Path.of(args[1], "signer_a.der"));
        byte[] newDer = Files.readAllBytes(Path.of(args[1], "signer_b.der"));
        String oldDigest = digest(oldDer), newDigest = digest(newDer);
        Signature oldKey = new Signature(oldDer), newKey = new Signature(newDer);
        reset(oldKey);
        System.load(args[0]);
        Application app = new Application();
        ActivityThread.application = app;
        int before = ActivityThread.calls;
        String[] missingContext = rows();
        check(missingContext.length == 9);
        expect(missingContext, PACKAGE, "error");
        expect(missingContext, CURRENT, "error");
        expect(missingContext, HISTORY, "error");
        // Only the preserved legacy scalar may consult ActivityThread.
        check(ActivityThread.calls == before + 1);
        check(RuntimeBridge.initialize(app) == RuntimeBridge.INITIALIZED);
        String[] single = rows();
        expect(single, PACKAGE, "ok fixture.app");
        if (args.length > 2) expect(single, "id.package/proc_cmdline", "ok " + args[2]);
        check(!row(single, "id.package/proc_cmdline").equals("id.package/proc_cmdline ok fixture.app"));
        expect(single, CURRENT, "ok [" + oldDigest + "]");
        expect(single, HISTORY, "ok [" + oldDigest + "]");
        expect(single, "sig.cert_sha256/package_manager", "ok " + oldDigest);
        check(faults());

        reset(newKey);
        SigningInfo.history = new Signature[] {oldKey, newKey};
        String[] rotated = rows();
        expect(rotated, CURRENT, "ok [" + newDigest + "]");
        expect(rotated, HISTORY, "ok [" + oldDigest + ", " + newDigest + "]");
        expect(rotated, "sig.cert_sha256/package_manager", "ok " + newDigest);
        SigningInfo.history = new Signature[] {newKey, oldKey};
        expect(rows(), HISTORY, "error");
        SigningInfo.history = null;
        expect(rows(), CURRENT, "ok [" + newDigest + "]");
        expect(rows(), HISTORY, "error");
        SigningInfo.history = new Signature[0];
        expect(rows(), HISTORY, "error");
        SigningInfo.history = new Signature[] {null};
        expect(rows(), HISTORY, "error");
        SigningInfo.failHistory = true;
        expect(rows(), HISTORY, "error");
        reset(newKey);
        SigningInfo.history = new Signature[33];
        Arrays.fill(SigningInfo.history, newKey);
        expect(rows(), HISTORY, "error");

        reset(oldKey);
        SigningInfo.current = new Signature[] {newKey, oldKey, newKey};
        SigningInfo.multiple = true;
        int historyCalls = SigningInfo.historyCalls;
        String[] multiple = rows();
        String[] sorted = new String[] {oldDigest, newDigest};
        Arrays.sort(sorted);
        expect(multiple, CURRENT, "ok [" + sorted[0] + ", " + sorted[1] + "]");
        expect(multiple, HISTORY, "unsupported");
        expect(multiple, "sig.cert_sha256/package_manager", "ok " + newDigest);
        check(SigningInfo.historyCalls == historyCalls);
        SigningInfo.current = new Signature[32]; Arrays.fill(SigningInfo.current, oldKey);
        expect(rows(), CURRENT, "ok [" + oldDigest + "]");
        SigningInfo.current = new Signature[33]; Arrays.fill(SigningInfo.current, oldKey);
        currentError();
        SigningInfo.current = new Signature[0]; currentError();
        SigningInfo.current = null; currentError();
        SigningInfo.current = new Signature[] {oldKey, null}; currentError();
        SigningInfo.current = new Signature[] {oldKey, new Signature(newDer) {
            public byte[] toByteArray() { throw new SecurityException("late signer failure"); }
        }};
        currentError();
        SigningInfo.current = new Signature[] {oldKey}; currentError();
        reset(oldKey);
        for (byte[] invalid : new byte[][] {null, new byte[0], {1, 2, 3}, new byte[65537], Arrays.copyOf(oldDer, oldDer.length - 1)}) {
            SigningInfo.current = new Signature[] {new Signature(invalid)};
            currentError();
        }
        reset(oldKey);
        Signature huge = new Signature(largeEnvelope());
        SigningInfo.multiple = true;
        SigningInfo.current = new Signature[] {huge, huge, huge, huge};
        check(row(rows(), CURRENT).startsWith(CURRENT + " ok "));
        SigningInfo.current = new Signature[] {huge, huge, huge, huge, huge};
        currentError();
        reset(oldKey);
        SigningInfo.failCurrent = true; currentError();
        reset(oldKey);
        SigningInfo.failMultiple = true; currentError();
        reset(oldKey);
        Signature.fail = true; currentError();
        reset(oldKey);
        PackageManager.fail = true; currentError();
        expect(rows(), PACKAGE, "ok fixture.app");
        reset(oldKey);
        PackageManager.nullInfo = true; currentError();
        reset(oldKey);
        PackageManager.nullSigningInfo = true; currentError();
        reset(oldKey);
        app.nullManager = true; currentError(); app.nullManager = false;
        app.fail = true; currentError(); app.fail = false;
        app.failName = true; expect(rows(), PACKAGE, "error"); app.failName = false;
        for (String invalid : new String[] {null, "", "x".repeat(256), "fixture.app:remote", "global:alias", "f\u0000x", "\uD83D\uDE00"}) {
            app.name = invalid; expect(rows(), PACKAGE, "error"); currentError();
        }
        app.name = "fixture.app";
        for (int api : new int[] {31, 32, 33, 34}) {
            Build.VERSION.SDK_INT = api;
            expect(rows(), CURRENT, "ok [" + oldDigest + "]");
        }
        Build.VERSION.SDK_INT = 30;
        expect(rows(), CURRENT, "unsupported");
        expect(rows(), "sig.current_sha256.v1/apk_signing_block", "unsupported");
        expect(rows(), PACKAGE, "unsupported");
        Build.VERSION.SDK_INT = -1;
        expect(rows(), CURRENT, "error");
        Build.VERSION.SDK_INT = 34;
        int fallbackCalls = ActivityThread.calls;
        for (int pass = 0; pass < 1000; ++pass) {
            expect(rows(), CURRENT, "ok [" + oldDigest + "]");
        }
        check(ActivityThread.calls == fallbackCalls);
        check(threadReads());
        System.out.println("production identity dispatcher: current sets, history, bounds, failures and supported Context passed");
    }
}
