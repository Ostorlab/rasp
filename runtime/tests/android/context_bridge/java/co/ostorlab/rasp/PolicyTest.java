package co.ostorlab.rasp;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/** Actual production Java/JNI/C gate before a harmless host-owned in-memory operation. */
public final class PolicyTest {
    private static native boolean initializeNative(long[] configuration);
    private static native void publishValuesNative(long[] values);
    private static void publishNative(int tracer, int status, long tick) {
        publishValuesNative(new long[] {tracer, status, tick});
    }
    private static native void advanceNative(long tick);
    private static final List<Integer> RECEIPTS = new ArrayList<>();
    private static String expectedHash;
    private static void check(boolean value) { if (!value) throw new AssertionError("policy fixture"); }
    private static RuntimeBridge.PolicyDecision decision() {
        return RuntimeBridge.gateLocalOperation("append_demo_receipt", expectedHash);
    }
    private static void appendReceipt() {
        RuntimeBridge.PolicyDecision decision = decision();
        if (decision == null || !decision.allows()) return;
        RECEIPTS.add(1);
    }
    private static void checkDeniedReason(int reason) {
        RuntimeBridge.PolicyDecision value = decision();
        check(value != null && value.status() == RuntimeBridge.POLICY_OK);
        check(value.action() == RuntimeBridge.POLICY_DENY && value.candidateAction() == RuntimeBridge.POLICY_DENY);
        check(value.reason() == reason && !value.allows());
    }
    /** Boundary-only future/invalid copied fields; the gate and receipt operation remain real. */
    private static void rejectUnknownCopiedFields(RuntimeBridge.PolicyDecision actual) throws ReflectiveOperationException {
        Field storage = RuntimeBridge.PolicyDecision.class.getDeclaredField("bytes");
        storage.setAccessible(true);
        byte[] copy = ((byte[]) storage.get(actual)).clone();
        Constructor<RuntimeBridge.PolicyDecision> constructor = RuntimeBridge.PolicyDecision.class.getDeclaredConstructor(byte[].class);
        constructor.setAccessible(true);
        ByteBuffer fields = ByteBuffer.wrap(copy).order(ByteOrder.LITTLE_ENDIAN);
        fields.putInt(8, Integer.MAX_VALUE); fields.putInt(12, RuntimeBridge.POLICY_ALLOW);
        check(!constructor.newInstance((Object) copy).allows());
        fields.putInt(8, RuntimeBridge.POLICY_OK); fields.putInt(12, Integer.MAX_VALUE);
        check(!constructor.newInstance((Object) copy).allows());
        check(actual.allows());
    }
    public static void main(String[] args) throws ReflectiveOperationException {
        expectedHash = args[1];
        check(decision() == null); // Real unsupported linkage before loading the native facade.
        appendReceipt(); check(RECEIPTS.size() == 0);
        System.load(args[0]);
        RuntimeBridge.PolicyInfo before = RuntimeBridge.localPolicyInfo();
        check(before != null && before.status() != RuntimeBridge.POLICY_OK);
        RuntimeBridge.PolicyDecision uninitialized = decision();
        check(uninitialized != null && uninitialized.status() != RuntimeBridge.POLICY_OK && !uninitialized.allows());
        appendReceipt(); check(RECEIPTS.size() == 0);
        final long expectedVersion = args.length > 2 ? Long.parseLong(args[2]) : 1L;
        final boolean reportOnly = args.length > 3 && args[3].equals("report_only");
        check(initializeNative(new long[] {expectedVersion, reportOnly ? 1 : 0}));
        RuntimeBridge.PolicyDecision noPublication = decision();
        check(noPublication != null && !noPublication.allows());
        if (reportOnly) check(noPublication.status() == RuntimeBridge.POLICY_OK && noPublication.action() == RuntimeBridge.POLICY_REPORT);
        else check(noPublication.status() != RuntimeBridge.POLICY_OK && noPublication.action() == RuntimeBridge.POLICY_DENY);
        publishNative(0, 0, 1000000000L);
        RuntimeBridge.PolicyInfo info = RuntimeBridge.localPolicyInfo();
        check(info != null && info.status() == 0 && info.checksKnown());
        check(info.policySha256().equals(expectedHash));
        check(info.policyVersion() == expectedVersion);
        check(info.effectiveChecks().size() == 1 && info.effectiveChecks().get(0).equals("debugger"));
        RuntimeBridge.PolicyDecision wrongHash = RuntimeBridge.gateLocalOperation("append_demo_receipt", "0".repeat(64));
        check(wrongHash != null && wrongHash.status() == RuntimeBridge.POLICY_OK && wrongHash.action() == RuntimeBridge.POLICY_DENY);
        check(wrongHash.candidateAction() == RuntimeBridge.POLICY_DENY && wrongHash.reason() == 3 && !wrongHash.allows());
        RuntimeBridge.PolicyDecision unknownOperation = RuntimeBridge.gateLocalOperation("unknown", expectedHash);
        check(unknownOperation != null && unknownOperation.status() == RuntimeBridge.POLICY_OK && !unknownOperation.allows());
        check(unknownOperation.action() == (reportOnly ? RuntimeBridge.POLICY_REPORT : RuntimeBridge.POLICY_DENY));
        check(unknownOperation.candidateAction() == RuntimeBridge.POLICY_DENY && unknownOperation.reason() == 4);
        if (reportOnly) {
            RuntimeBridge.PolicyDecision report = decision();
            check(report != null && report.status() == RuntimeBridge.POLICY_OK && report.action() == RuntimeBridge.POLICY_REPORT);
            check(report.candidateAction() == RuntimeBridge.POLICY_ALLOW && !report.allows());
            appendReceipt(); check(RECEIPTS.size() == 0);
            System.out.println("Actual report-only candidate ALLOW appended no receipt; expected hash mismatch stayed DENY");
            return;
        }
        appendReceipt(); check(RECEIPTS.size() == 1);
        RuntimeBridge.PolicyDecision retained = decision();
        check(retained != null && retained.allows() && retained.details().size() == 1);
        check(retained.policyVersion() == expectedVersion);
        check(retained.details().get(0).ruleId.equals("native.android.dbg.tracer_pid.proc_status"));
        rejectUnknownCopiedFields(retained);
        int[] indices = retained.details().get(0).evidenceIndices(); indices[0] = 999;
        check(retained.details().get(0).evidenceIndices()[0] != 999);
        publishNative(42, 0, 2000000000L);
        appendReceipt(); check(RECEIPTS.size() == 1);
        check(retained.allows() && retained.runId().length() == 36); // Historical copy is not reauthorization.
        for (int status : new int[]{1, 2, 3}) {
            publishNative(0, status, 3000000000L); appendReceipt(); check(RECEIPTS.size() == 1);
        }
        publishNative(0, 4, 3500000000L); checkDeniedReason(6); // Unknown collector status makes coverage incomplete.
        appendReceipt(); check(RECEIPTS.size() == 1);
        publishNative(0, 0, 4000000000L);
        advanceNative(79000000001L); checkDeniedReason(8); appendReceipt(); check(RECEIPTS.size() == 1);
        publishNative(0, 0, 80000000000L);
        advanceNative(-1); checkDeniedReason(7); appendReceipt();
        advanceNative(81000000000L); appendReceipt(); check(RECEIPTS.size() == 1);
        publishNative(0, 0, 82000000000L); appendReceipt(); check(RECEIPTS.size() == 2);
        check(RuntimeBridge.gateLocalOperation("bad\u0000op", expectedHash) == null);
        System.out.println("Actual host operation count=2; denied/error/stale/clock/coverage/unknown paths appended nothing");
    }
}
