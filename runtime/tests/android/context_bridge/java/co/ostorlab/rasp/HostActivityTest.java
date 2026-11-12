package co.ostorlab.rasp;

import android.os.Looper;
import android.os.SystemClock;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import fixture.hostcontext.MainActivity;
import java.lang.reflect.Field;

/** Actual reference Activity callbacks, real reducer and JNI gate; only UI/clock boundaries are replaced. */
public final class HostActivityTest {
    private static final long BASE = 1000000000000L;
    private static void check(boolean value, String why) { if (!value) throw new AssertionError(why); }
    private static Object field(MainActivity host, String name) throws ReflectiveOperationException {
        Field field = MainActivity.class.getDeclaredField(name); field.setAccessible(true); return field.get(host);
    }
    private static void click(MainActivity host, String name) throws ReflectiveOperationException {
        check(((Button)field(host, name)).performClick(), "missing callback: " + name);
    }
    private static void tuple(MainActivity host, long sequence, int attempt) throws ReflectiveOperationException {
        check((Long)field(host, "sequence") == sequence && (Integer)field(host, "attempt") == attempt,
            "local tuple advanced without acceptance: " + field(host, "sequence") + "/" + field(host, "attempt"));
    }
    private static void stopped(MainActivity host, int receipts) throws ReflectiveOperationException {
        check(!(Boolean)field(host, "pending"), "rejected event left flow pending");
        check((Integer)field(host, "receipts") == receipts, "unexpected receipt mutation");
        String output = ((TextView)field(host, "status")).output;
        check(output.contains("unavailable") && output.contains(Integer.toString(receipts)), "rejection not visible: " + output);
    }
    private static void denied(MainActivity host) throws ReflectiveOperationException {
        PolicyTest.publishValuesNative(new long[] {42, 0, 1000000000L});
        click(host, "append");
        tuple(host, 3, 1);
        check((Boolean)field(host, "pending") && (Boolean)field(host, "consumed"), "native DENY must consume for explicit retry");
        check((Integer)field(host, "receipts") == 0, "native DENY appended receipt");
    }
    public static void main(String[] args) throws Exception {
        Looper.getMainLooper(); System.load(args[0]);
        check(PolicyTest.initializeNative(new long[] {1, 0}), "native initialization");
        PolicyTest.publishValuesNative(new long[] {0, 0, 1000000000L});
        String scenario = args[1];
        SystemClock.tick = BASE; SystemClock.samples = 0;
        SystemClock.readings = scenario.equals("start_clock") ? new long[] {-1, BASE} :
            (scenario.equals("begin_clock") || scenario.equals("recovery")) ? new long[] {BASE, -1} : new long[0];
        MainActivity host = new MainActivity(); host.onCreate(null); host.onResume();
        if (scenario.equals("start_clock")) { stopped(host, 0); tuple(host, 0, 0); check(SystemClock.samples == 1, "BEGIN ran after rejected START"); }
        else if (scenario.equals("begin_clock")) { stopped(host, 0); tuple(host, 1, 0); }
        else if (scenario.equals("recovery")) {
            stopped(host, 0); SystemClock.readings = new long[0]; SystemClock.tick = BASE;
            click(host, "begin"); tuple(host, 2, 1); click(host, "append");
            check((Integer)field(host, "receipts") == 1, "explicit fresh flow did not recover");
        } else if (scenario.startsWith("input_")) {
            SystemClock.tick = scenario.equals("input_clock") ? -1 : BASE + 30000000001L;
            click(host, "append"); stopped(host, 0); tuple(host, 2, 1);
        } else if (scenario.startsWith("retry_")) {
            denied(host);
            SystemClock.tick = scenario.equals("retry_clock") ? -1 : BASE + (scenario.equals("retry_action_age") ? 120000000001L : 30000000001L);
            click(host, "retry"); stopped(host, 0); tuple(host, 3, 1);
        } else if (scenario.equals("gate_clock")) {
            SystemClock.samples = 0; SystemClock.readings = new long[] {BASE, -1};
            click(host, "append"); stopped(host, 0); tuple(host, 3, 1);
        } else if (scenario.equals("end_clock")) {
            SystemClock.samples = 0; SystemClock.readings = new long[] {BASE, BASE, -1};
            click(host, "append"); stopped(host, 1); tuple(host, 3, 1);
            click(host, "append"); check((Integer)field(host, "receipts") == 1, "rejected END replayed effect");
        } else if (scenario.equals("cancel_expiry")) {
            SystemClock.tick = BASE + 30000000001L; click(host, "cancel"); stopped(host, 0); tuple(host, 2, 1);
        } else if (scenario.equals("cancel_ok")) {
            click(host, "cancel"); tuple(host, 3, 0);
            check(!(Boolean)field(host, "pending") && (Integer)field(host, "receipts") == 0, "accepted cancel did not stop");
        } else if (scenario.equals("deny_retry")) {
            denied(host); PolicyTest.publishValuesNative(new long[] {0, 0, 2000000000L});
            click(host, "retry"); tuple(host, 4, 2); check(!(Boolean)field(host, "consumed"), "accepted retry stayed consumed");
            click(host, "append"); tuple(host, 6, 0);
            check((Integer)field(host, "receipts") == 1 && !(Boolean)field(host, "pending"), "fresh real gate did not append once");
        } else if (scenario.equals("deny_limit")) {
            denied(host); click(host, "retry"); click(host, "append"); click(host, "retry"); click(host, "append");
            stopped(host, 0); tuple(host, 7, 3);
        } else if (scenario.equals("pause")) {
            Button append = (Button)field(host, "append"); View.OnClickListener old = append.listener;
            host.onPause(); host.onResume(); old.onClick(append);
            check((Integer)field(host, "receipts") == 0, "stale callback affected new owner");
            tuple(host, 2, 1); click(host, "append"); check((Integer)field(host, "receipts") == 1, "new lifecycle flow unavailable");
        } else if (scenario.equals("benign")) {
            tuple(host, 2, 1); click(host, "append"); tuple(host, 4, 0);
            click(host, "append"); check((Integer)field(host, "receipts") == 1 && !(Boolean)field(host, "pending"), "ALLOW did not append exactly once");
        } else throw new AssertionError("unknown scenario");
        System.out.println("Actual Activity/JNI " + scenario + " passed; receipts=" + field(host, "receipts"));
    }
}
