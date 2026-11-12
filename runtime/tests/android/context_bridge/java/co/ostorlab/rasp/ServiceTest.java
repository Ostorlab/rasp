package co.ostorlab.rasp;

import android.app.Application;
import android.os.Build;
import android.provider.Settings;
import android.accessibilityservice.AccessibilityServiceInfo;
import android.view.inputmethod.InputMethodInfo;
import java.util.*;

/** Real JVM / simulated public Android APIs; no device execution. */
public final class ServiceTest {
    private static native String snapshotNative(int group);
    private static native String workerSnapshot(int group);
    private static native String faultySnapshot(int faultKind);
    private static String snapshot(int group, boolean worker) {
        return worker ? workerSnapshot(group) : snapshotNative(group);
    }
    private static void expect(int group, String expected) {
        String actual = snapshot(group, false);
        if (!actual.equals(expected)) throw new AssertionError("expected=" + expected + " actual=" + actual);
    }
    private static void expectCycleRetention(Application app) {
        for (int count : new int[]{64, 128}) {
            List<AccessibilityServiceInfo> services = new ArrayList<>();
            for (int index = 0; index < count; ++index) {
                services.add(new AccessibilityServiceInfo("pkg/.Service" + index, 1, 0));
            }
            app.accessibility.enabled = services;
            String expected = "cycle complete=" + (count == 64 ? "true" : "false")
                + " execution_finished=true dropped=" + (count == 64 ? "0" : "1")
                + " expected=1 seen=1 missing=0 retained=" + (count == 64 ? "1" : "0");
            for (boolean worker : new boolean[]{false, true}) {
                String actual = snapshot(10, worker);
                if (!actual.equals(expected)) throw new AssertionError("cycle retention expected=" + expected + " actual=" + actual);
            }
            String raw = snapshotNative(0);
            if (!raw.startsWith(A11Y + "ok [") || !raw.contains("pkg/pkg.Service" + (count - 1))) {
                throw new AssertionError("raw collector limit changed: " + raw);
            }
        }
        app.accessibility.enabled = new ArrayList<>();
    }
    private static final String A11Y = "a11y.enabled_services/accessibility_manager ";
    private static final String ENABLED = "ime.enabled_components/input_method_manager ";
    private static final String CURRENT = "ime.current_component/input_method_manager ";
    private static final String NOTIFY = "notification.enabled_listeners/settings_secure ";
    private static final String PACKAGES = "root.manager_packages_v1/package_manager ";
    private static final String PROXY = "net.default_proxy_v1/connectivity_manager ";
    private static void rootContextTests(Application app) {
        app.forbidPackageName = true;
        for (int fault = 3; fault < 9; ++fault) {
            if (!faultySnapshot(fault).equals((fault < 6 ? PACKAGES : PROXY) + "error")) throw new AssertionError("context fault state");
        }
        for (boolean worker : new boolean[]{false, true}) {
            String local = snapshot(6, worker);
            if (!local.startsWith("root.mountinfo_context_v1/proc_self_mountinfo ok [mounts=") ||
                !local.contains("root.mount_namespace_v1/proc_self_ns_mnt ok mnt:[")) throw new AssertionError("own proc context: " + local);
        }
        String hidden = PACKAGES + "ok [com.topjohnwu.magisk not_visible, me.weishu.kernelsu not_visible, me.bmax.apatch not_visible]";
        expect(3, hidden);
        app.packages.visible.add("com.topjohnwu.magisk");
        expect(3, hidden.replace("magisk not_visible", "magisk visible"));
        for (int failure : new int[]{1, 2, 3}) {
            app.packages.failure = failure;
            expect(3, PACKAGES + "error");
        }
        app.packages.failure = 0;
        android.content.pm.PackageManager savedPackages = app.packages;
        app.packages = null;
        expect(3, PACKAGES + "error");
        app.packages = savedPackages;
        app.fail = true;
        expect(3, PACKAGES + "error");
        app.fail = false;
        android.net.ConnectivityManager savedConnectivity = app.connectivity;
        app.connectivity = null;
        expect(4, PROXY + "error");
        app.connectivity = savedConnectivity;
        for (int api : new int[]{31, 32, 33, 34, 35, 36}) {
            Build.VERSION.SDK_INT = api;
            expect(3, hidden.replace("magisk not_visible", "magisk visible"));
            expect(4, PROXY + "ok [mode=none]");
            expect(5, "debug.adb_enabled_v1/settings_global unsupported\ndebug.developer_options_enabled_v1/settings_global unsupported");
        }
        Build.VERSION.SDK_INT = 35;
        expect(4, PROXY + "ok [mode=none]");
        app.connectivity.proxy = new android.net.ProxyInfo();
        expect(4, PROXY + "ok [mode=manual, host=proxy.example, port=8080]");
        for (String bad : new String[]{null, "", "user:secret@proxy", "user:secret", "[", ":::", "proxy/path", "proxy\n", "x".repeat(254), "é"}) {
            app.connectivity.proxy.host = bad;
            expect(4, PROXY + "error");
        }
        for (String host : new String[]{"localhost", "127.0.0.1", "[::1]", "2001:db8::1"}) {
            app.connectivity.proxy.host = host;
            expect(4, PROXY + "ok [mode=manual, host=" + host + ", port=8080]");
        }
        app.connectivity.proxy.host = "127.0.0.1";
        app.connectivity.proxy.port = 0;
        expect(4, PROXY + "error");
        app.connectivity.proxy.port = 65536;
        expect(4, PROXY + "error");
        app.connectivity.proxy.pac = new android.net.Uri(false);
        expect(4, PROXY + "ok [mode=pac]");
        app.connectivity.proxy.pac = null;
        app.connectivity.proxy.host = "proxy.example";
        app.connectivity.proxy.port = 8080;
        expect(4, PROXY + "ok [mode=manual, host=proxy.example, port=8080]");
        app.connectivity.proxy.fail = true;
        expect(4, PROXY + "error");
        app.connectivity.proxy.fail = false;
        app.connectivity.proxy = null;
        app.connectivity.fail = true;
        expect(4, PROXY + "error");
        app.connectivity.fail = false;
        Build.VERSION.SDK_INT = 30;
        expect(3, PACKAGES + "unsupported");
        expect(4, PROXY + "unsupported");
        Build.VERSION.SDK_INT = -1;
        expect(3, PACKAGES + "error");
        expect(4, PROXY + "error");
        Build.VERSION.SDK_INT = 35;
        for (int pass = 0; pass < 1000; ++pass) {
            if (!workerSnapshot(3).equals(hidden.replace("magisk not_visible", "magisk visible"))) throw new AssertionError("package worker refs");
            if (!workerSnapshot(4).equals(PROXY + "ok [mode=none]")) throw new AssertionError("proxy worker refs");
        }
        expect(5, "debug.adb_enabled_v1/settings_global unsupported\ndebug.developer_options_enabled_v1/settings_global unsupported");
        app.forbidPackageName = false;
    }
    public static void main(String[] args) {
        System.load(args[0]);
        expect(3, PACKAGES + "error");
        expect(4, PROXY + "error");
        expect(0, A11Y + "error");
        expect(1, ENABLED + "error\n" + CURRENT + "error");
        expect(2, NOTIFY + "error");
        Application app = new Application();
        if (RuntimeBridge.initialize(app) != RuntimeBridge.INITIALIZED) throw new AssertionError();
        rootContextTests(app);
        expectCycleRetention(app);
        for (int faultKind = 0; faultKind < 3; ++faultKind) {
            if (!faultySnapshot(faultKind).equals(A11Y + "error")) throw new AssertionError("JNI fault not explicit");
        }
        expect(0, A11Y + "ok []");
        expect(1, ENABLED + "ok []\n" + CURRENT + "error");
        expect(2, NOTIFY + "ok []");
        app.accessibility.enabled = Arrays.asList(
            new AccessibilityServiceInfo("org.example/.Assist", 33, 2),
            new AccessibilityServiceInfo("com.google.android.marvin.talkback/.TalkBackService", 1, 0),
            new AccessibilityServiceInfo("org.example/.Assist", 33, 2),
            new AccessibilityServiceInfo("org.example/.Assist", 1, 0),
            new AccessibilityServiceInfo("org.password/.FillService", 1, 128));
        String a11y = A11Y + "ok [com.google.android.marvin.talkback/com.google.android.marvin.talkback.TalkBackService capabilities=1 flags=0, org.example/org.example.Assist capabilities=1 flags=0, org.example/org.example.Assist capabilities=33 flags=2, org.password/org.password.FillService capabilities=1 flags=128]";
        expect(0, a11y);
        app.ime.enabled = Arrays.asList(new InputMethodInfo("org.assist/.Keyboard"), new InputMethodInfo("com.android.inputmethod.latin/.LatinIME"));
        app.ime.current = new InputMethodInfo("org.assist/.Keyboard");
        String enabled = ENABLED + "ok [com.android.inputmethod.latin/com.android.inputmethod.latin.LatinIME, org.assist/org.assist.Keyboard]";
        for (int api : new int[]{31, 33, 34, 35}) {
            Build.VERSION.SDK_INT = api;
            expect(1, enabled + "\n" + CURRENT + (api < 34 ? "unsupported" : "ok org.assist/org.assist.Keyboard"));
            expect(0, a11y);
            Settings.Secure.listeners = "org.support/.Listener:org.password/.Otp:org.support/org.support.Listener";
            expect(2, NOTIFY + "ok [org.password/org.password.Otp, org.support/org.support.Listener]");
        }
        Build.VERSION.SDK_INT = 30;
        expect(0, A11Y + "unsupported");
        expect(1, ENABLED + "unsupported\n" + CURRENT + "unsupported");
        expect(2, NOTIFY + "unsupported");
        Build.VERSION.SDK_INT = 35;
        for (String bad : new String[]{null, "bad", "pkg/", "pkg/.A:", ":pkg/.A", "pkg/.A::pkg/.B", "pkg/.A\n", "pkg/." + "x".repeat(1024), "pkg/.É"}) {
            Settings.Secure.listeners = bad;
            expect(2, NOTIFY + "error");
        }
        Settings.Secure.listeners = "pkg/.A";
        Settings.Secure.denied = true;
        expect(2, NOTIFY + "error");
        Settings.Secure.denied = false;
        Settings.Secure.listeners = String.join(":", Collections.nCopies(129, "pkg/.A"));
        expect(2, NOTIFY + "error");
        Settings.Secure.listeners = "x".repeat(131073);
        expect(2, NOTIFY + "error");
        Settings.Secure.listeners = "";
        app.accessibility.fail = true;
        expect(0, A11Y + "error");
        app.accessibility.fail = false;
        app.accessibility.enabled = null;
        expect(0, A11Y + "error");
        app.accessibility.enabled = Arrays.asList((AccessibilityServiceInfo)null);
        expect(0, A11Y + "error");
        app.accessibility.enabled = Collections.nCopies(129, new AccessibilityServiceInfo("pkg/.A", 1, 0));
        expect(0, A11Y + "error");
        app.accessibility.enabled = Arrays.asList(new AccessibilityServiceInfo(null, 1, 0));
        expect(0, A11Y + "error");
        app.accessibility.enabled = Arrays.asList(new AccessibilityServiceInfo("pkg/.A", -1, Integer.MIN_VALUE));
        expect(0, A11Y + "ok [pkg/pkg.A capabilities=4294967295 flags=2147483648]");
        app.accessibility.enabled = Collections.nCopies(128, new AccessibilityServiceInfo("p/" + "A".repeat(1022), 1, 0));
        expect(0, A11Y + "error");
        app.accessibility.enabled = new AbstractList<AccessibilityServiceInfo>() {
            public int size() { return 2; }
            public AccessibilityServiceInfo get(int index) {
                if (index == 1) throw new IllegalStateException("list changed");
                return new AccessibilityServiceInfo("pkg/.A", 1, 0);
            }
        };
        expect(0, A11Y + "error");
        app.accessibility.enabled = new ArrayList<>();
        app.ime.fail = true;
        expect(1, ENABLED + "error\n" + CURRENT + "error");
        app.ime.fail = false;
        app.ime.enabled = null;
        app.ime.current = new InputMethodInfo("invalid");
        expect(1, ENABLED + "error\n" + CURRENT + "error");
        app.ime.enabled = Collections.nCopies(129, new InputMethodInfo("pkg/.A"));
        app.ime.current = new InputMethodInfo("org.assist/.Keyboard");
        expect(1, ENABLED + "error\n" + CURRENT + "ok org.assist/org.assist.Keyboard");
        app.ime.enabled = Arrays.asList((InputMethodInfo)null);
        expect(1, ENABLED + "error\n" + CURRENT + "ok org.assist/org.assist.Keyboard");
        app.ime.enabled = new ArrayList<>();
        Build.VERSION.SDK_INT = -1;
        expect(0, A11Y + "error");
        expect(1, ENABLED + "error\n" + CURRENT + "error");
        expect(2, NOTIFY + "error");
        Build.VERSION.SDK_INT = 35;
        for (int pass = 0; pass < 1000; ++pass) {
            expect(0, A11Y + "ok []");
            if (!snapshot(0, true).equals(A11Y + "ok []")) throw new AssertionError("accessibility worker refs");
            if (!snapshot(1, true).equals(ENABLED + "ok []\n" + CURRENT + "ok org.assist/org.assist.Keyboard")) throw new AssertionError("worker refs");
            expect(2, NOTIFY + "ok []");
            if (!snapshot(2, true).equals(NOTIFY + "ok []")) throw new AssertionError("settings worker refs");
        }
        app.accessibility = null;
        app.ime = null;
        expect(0, A11Y + "error");
        expect(1, ENABLED + "error\n" + CURRENT + "error");
        System.out.println("ServiceTest PASS: real JVM, simulated API31/33/34/35; benign metadata and unknown failures");
    }
}
