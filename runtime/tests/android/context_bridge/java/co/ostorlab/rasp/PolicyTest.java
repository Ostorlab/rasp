package co.ostorlab.rasp;

import java.util.ArrayList;
import java.util.List;

/** Actual production Java/JNI/C gate before a harmless host-owned in-memory operation. */
public final class PolicyTest {
    private static native boolean initializeVersionNative(long version);
    private static native void publishValuesNative(long[] values);
    private static void publishNative(int tracer, int status, long tick) {
        publishValuesNative(new long[] {tracer, status, tick});
    }
    private static native void advanceNative(long tick);
    private static final List<Integer> RECEIPTS = new ArrayList<>();
    private static String expectedHash;
    private static void check(boolean value) { if (!value) throw new AssertionError("policy fixture"); }
    private static void appendReceipt() {
        RuntimeBridge.PolicyDecision decision = RuntimeBridge.gateLocalOperation("append_demo_receipt", expectedHash);
        if (decision == null || decision.status() != RuntimeBridge.POLICY_OK || decision.action() != RuntimeBridge.POLICY_ALLOW) return;
        RECEIPTS.add(1);
    }
    public static void main(String[] args) {
        System.load(args[0]);
        expectedHash = args[1];
        RuntimeBridge.PolicyInfo before = RuntimeBridge.localPolicyInfo();
        check(before != null && before.status() != RuntimeBridge.POLICY_OK);
        appendReceipt(); check(RECEIPTS.size() == 0);
        final long expectedVersion = args.length > 2 ? Long.parseLong(args[2]) : 1L;
        check(initializeVersionNative(expectedVersion));
        publishNative(0, 0, 1000000000L);
        RuntimeBridge.PolicyInfo info = RuntimeBridge.localPolicyInfo();
        check(info != null && info.status() == 0 && info.checksKnown());
        check(info.policySha256().equals(expectedHash));
        check(info.policyVersion() == expectedVersion);
        check(info.effectiveChecks().size() == 1 && info.effectiveChecks().get(0).equals("debugger"));
        appendReceipt(); check(RECEIPTS.size() == 1);
        RuntimeBridge.PolicyDecision retained = RuntimeBridge.gateLocalOperation("append_demo_receipt", expectedHash);
        check(retained != null && retained.action() == 2 && retained.details().size() == 1);
        check(retained.policyVersion() == expectedVersion);
        check(retained.details().get(0).ruleId.equals("native.android.dbg.tracer_pid.proc_status"));
        int[] indices = retained.details().get(0).evidenceIndices(); indices[0] = 999;
        check(retained.details().get(0).evidenceIndices()[0] != 999);
        publishNative(42, 0, 2000000000L);
        appendReceipt(); check(RECEIPTS.size() == 1);
        check(retained.action() == 2 && retained.runId().length() == 36);
        for (int status : new int[]{1, 2, 3}) {
            publishNative(0, status, 3000000000L); appendReceipt(); check(RECEIPTS.size() == 1);
        }
        publishNative(0, 0, 4000000000L);
        advanceNative(79000000001L); appendReceipt(); check(RECEIPTS.size() == 1);
        publishNative(0, 0, 80000000000L);
        advanceNative(-1); appendReceipt(); advanceNative(81000000000L); appendReceipt(); check(RECEIPTS.size() == 1);
        publishNative(0, 0, 82000000000L); appendReceipt(); check(RECEIPTS.size() == 2);
        check(RuntimeBridge.gateLocalOperation("append_demo_receipt", "0".repeat(64)).action() == 0);
        check(RuntimeBridge.gateLocalOperation("bad\u0000op", expectedHash) == null);
        System.out.println("Actual host operation count=2; denied/error/stale/clock paths appended nothing");
    }
}
