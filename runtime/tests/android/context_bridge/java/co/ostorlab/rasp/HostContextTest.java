package co.ostorlab.rasp;

import android.os.Looper;
import android.os.SystemClock;
import co.ostorlab.rasp.host.HostOperationContext;
import java.nio.file.Files;
import java.nio.file.Paths;
import android.widget.EditText;
import android.text.method.PasswordTransformationMethod;

/** Shared independently specified vectors through the actual Java/JNI/native gate. */
public final class HostContextTest {
    private static final String HASH = "5685df69e0340b2a8472c2929cd9be01db0444191abb8c5fdf366a51b0262c81";
    private static void check(boolean value, String message) { if (!value) throw new AssertionError(message); }
    private static byte[] ref(int value) { byte[] bytes = new byte[16]; bytes[0] = (byte)value; return bytes; }
    private static HostOperationContext.Event event(String command, long generation, long sequence, int attempt, int secure) {
        int kind = command.equals("start") ? 1 : command.equals("begin") ? 2 : command.equals("input") ? 3 :
            (command.equals("background") || command.equals("foreground")) ? 4 : (command.equals("finish") || command.equals("fail")) ? 5 :
            command.equals("cancel") ? 6 : command.equals("retry") ? 7 : command.equals("stop") ? 8 : 99;
        return new HostOperationContext.Event(kind, (kind == 2 || kind == 3 || kind == 7) ? 1 : 0,
            (kind == 2 || kind == 3 || kind == 7) ? secure : 0, kind == 1 ? 1 : kind == 4 ? (command.equals("foreground") ? 1 : 3) : 0,
            attempt, kind == 5 ? (command.equals("finish") ? 1 : 2) : 0, generation, sequence,
            ref(kind == 8 ? 0 : generation == 1 ? 1 : 3), ref(kind == 1 || kind == 8 || (kind == 4 && attempt == 0) ? 0 : 2));
    }
    private static HostOperationContext flow() {
        SystemClock.tick = 1000000000L;
        HostOperationContext result = new HostOperationContext(new HostOperationContext.Binding("append_demo_receipt", HASH, true));
        check(result.apply(event("start",1,1,0,0)).status == 0, "flow start");
        check(result.apply(event("begin",1,2,1,1)).status == 0, "flow begin");
        return result;
    }
    public static void main(String[] args) throws Exception {
        Looper.getMainLooper();
        System.load(args[0]);
        HostOperationContext startup = flow();
        check(startup.gate(1,2,1).context.status == 12, "unavailable real native service");
        check(startup.gate(1,2,1).context.reason == 13, "native failure consumed");
        check(PolicyTest.initializeVersionNative(1), "native installation");
        PolicyTest.publishValuesNative(new long[] {0, 0, 1000000000L});
        String previous = "";
        HostOperationContext owner = null;
        int receipts = 0;
        int rows = 0;
        for (String line : Files.readAllLines(Paths.get(args[1]))) {
            if (line.startsWith("#") || line.isEmpty()) continue;
            String[] f = line.split(" +");
            if (!f[0].equals(previous)) {
                owner = new HostOperationContext(new HostOperationContext.Binding("append_demo_receipt", HASH, true));
                previous = f[0];
            }
            long generation = Long.parseLong(f[2]), sequence = Long.parseLong(f[3]);
            int attempt = Integer.parseInt(f[4]), secure = Integer.parseInt(f[5]);
            SystemClock.tick = Long.parseLong(f[6]);
            HostOperationContext.View view;
            RuntimeBridge.PolicyDecision nativeDecision = null;
            if (f[1].equals("gate")) {
                HostOperationContext.GateResult result = owner.gate(generation, sequence, attempt);
                view = result.context; nativeDecision = result.nativeDecision;
                if (view.status == 0 && nativeDecision != null && nativeDecision.status() == 0 && nativeDecision.action() == 2) receipts++;
            } else view = owner.apply(event(f[1], generation, sequence, attempt, secure));
            check(view.status == Integer.parseInt(f[7]), "status: " + line + " got=" + view.status);
            check(view.state == Integer.parseInt(f[8]), "state: " + line + " got=" + view.state);
            check((nativeDecision != null) == f[9].equals("1"), "native invocation: " + line);
            check((nativeDecision == null ? 0 : nativeDecision.action()) == Integer.parseInt(f[10]), "native action: " + line);
            byte[] copy = view.sessionRef(); copy[0] = 99;
            check(view.sessionRef()[0] != 99, "owned view");
            rows++;
        }
        check(receipts > 0 && rows > 50, "real receipt mutations and shared vectors");
        HostOperationContext denied = flow();
        PolicyTest.publishValuesNative(new long[] {42,0,2000000000L});
        HostOperationContext.GateResult blocked = denied.gate(1,2,1);
        check(blocked.context.status == 0 && blocked.nativeDecision.action() == 0, "native indicator denies");
        check(denied.gate(1,2,1).context.reason == 13, "native denial consumed");
        check(denied.apply(event("retry",1,3,2,1)).status == 0, "explicit retry");
        PolicyTest.publishValuesNative(new long[] {0,0,3000000000L});
        check(denied.gate(1,3,2).nativeDecision.action() == 2, "fresh real native gate");
        HostOperationContext threadOwner = flow();
        int[] threadStatus = new int[1];
        Thread wrong = new Thread(() -> threadStatus[0] = threadOwner.gate(1,2,1).context.status);
        wrong.start(); wrong.join();
        check(threadStatus[0] == 4 && threadOwner.gate(1,2,1).context.status == 0, "wrong thread cannot consume");
        EditText field = new EditText();
        field.inputType = 129; field.transformation = new PasswordTransformationMethod();
        check(HostOperationContext.secureEntry(field) == 1, "password configuration");
        field.inputType = 145;
        check(HostOperationContext.secureEntry(field) == 2, "visible password");
        field.inputType = 18;
        check(HostOperationContext.secureEntry(field) == 1, "numeric password");
        check(HostOperationContext.secureEntry(new Object()) == 3, "unsupported control");
        check(HostOperationContext.secureEntry(null) == 0, "unknown control");
        check(threadOwner.close() == 0 && threadOwner.gate(1,2,1).context.status == 10, "logical disposal");
        System.out.println("HostContext shared vectors=" + rows + "; actual gated receipts=" + receipts);
    }
}
