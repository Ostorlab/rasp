package fixture.hostcontext;

import android.app.Activity;
import android.os.Bundle;
import android.text.InputType;
import android.text.method.PasswordTransformationMethod;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import co.ostorlab.rasp.RuntimeBridge;
import co.ostorlab.rasp.host.HostOperationContext;
import java.nio.ByteBuffer;
import java.util.UUID;

/** Harmless source-host integration. Empty/demo input is never read; only receipts mutate. */
public final class MainActivity extends Activity {
    private static final String HASH = "5685df69e0340b2a8472c2929cd9be01db0444191abb8c5fdf366a51b0262c81";
    private HostOperationContext owner;
    private byte[] session, action;
    private long sequence;
    private int attempt, receipts;
    private boolean pending, consumed;
    private EditText selected;
    private TextView status;
    private Button append, retry, cancel, begin;
    private static byte[] fresh() {
        UUID value = UUID.randomUUID();
        return ByteBuffer.allocate(16).putLong(value.getMostSignificantBits()).putLong(value.getLeastSignificantBits()).array();
    }
    private Button button(LinearLayout layout, String title) {
        Button value = new Button(this); value.setText(title); layout.addView(value); return value;
    }
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        LinearLayout layout = new LinearLayout(this); layout.setOrientation(LinearLayout.VERTICAL);
        status = new TextView(this); status.setText("Local demo receipts: 0"); layout.addView(status);
        selected = new EditText(this); selected.setHint("Demo input; leave empty");
        selected.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        selected.setTransformationMethod(PasswordTransformationMethod.getInstance()); layout.addView(selected);
        begin = button(layout, "Begin a demo flow"); append = button(layout, "Append one demo receipt");
        retry = button(layout, "Retry a denied attempt"); cancel = button(layout, "Cancel demo flow");
        setContentView(layout);
    }
    @Override public void onResume() {
        super.onResume();
        beginFlow();
    }
    private void unavailable() {
        pending = false; consumed = false;
        if (owner != null) owner.close();
        session = null; action = null;
        status.setText("Demo flow unavailable; receipts: " + receipts);
    }
    private void beginFlow() {
        pending = false; consumed = false;
        if (owner != null) owner.close();
        try {
            owner = new HostOperationContext(new HostOperationContext.Binding("append_demo_receipt", HASH, true));
            final HostOperationContext captured = owner;
            begin.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View view) { if (owner == captured) beginFlow(); }
            });
            byte[] nextSession = fresh();
            HostOperationContext.View started = owner.apply(new HostOperationContext.Event(1,0,0,1,0,0,1,1,nextSession,new byte[16]));
            if (started.status != 0) { unavailable(); return; }
            session = nextSession; sequence = started.sequence; attempt = started.attempt;
            byte[] nextAction = fresh();
            HostOperationContext.View begun = owner.apply(new HostOperationContext.Event(2,2,
                HostOperationContext.secureEntry(selected),0,1,0,1,sequence+1,session,nextAction));
            if (begun.status != 0) { unavailable(); return; }
            action = nextAction; sequence = begun.sequence; attempt = begun.attempt; pending = true;
            append.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View view) { append(captured); }
            });
            retry.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View view) { retry(captured); }
            });
            cancel.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View view) { cancel(captured); }
            });
            status.setText("Demo ready; receipts: " + receipts);
        } catch (RuntimeException | LinkageError error) { unavailable(); }
    }
    private void retry(HostOperationContext captured) {
        if (owner != captured || !pending || !consumed) return;
        if (attempt >= 3 || sequence == Long.MAX_VALUE) { unavailable(); return; }
        HostOperationContext.View result = owner.apply(new HostOperationContext.Event(7,2,
            HostOperationContext.secureEntry(selected),0,attempt+1,0,1,sequence+1,session,action));
        if (result.status != 0) { unavailable(); return; }
        attempt = result.attempt; sequence = result.sequence; consumed = false;
        status.setText("Demo retry ready; receipts: " + receipts);
    }
    private void cancel(HostOperationContext captured) {
        if (owner != captured || !pending) return;
        if (sequence == Long.MAX_VALUE) { unavailable(); return; }
        HostOperationContext.View result = owner.apply(new HostOperationContext.Event(6,0,0,0,attempt,0,1,sequence+1,session,action));
        if (result.status != 0) { unavailable(); return; }
        sequence = result.sequence; attempt = result.attempt; pending = false; consumed = false;
        owner.close(); session = null; action = null;
        status.setText("Demo canceled; receipts: " + receipts);
    }
    private void append(HostOperationContext captured) {
        if (owner != captured || !pending || consumed) return;
        if (sequence == Long.MAX_VALUE) { unavailable(); return; }
        HostOperationContext.View input = owner.apply(new HostOperationContext.Event(3,2,
            HostOperationContext.secureEntry(selected),0,attempt,0,1,sequence+1,session,action));
        if (input.status != 0) { unavailable(); return; }
        sequence = input.sequence; attempt = input.attempt;
        HostOperationContext.GateResult result = owner.gate(1,sequence,attempt);
        consumed = result.context.state == 9;
        RuntimeBridge.PolicyDecision nativeDecision = result.nativeDecision;
        if (!consumed) { unavailable(); return; }
        if (result.context.status != 0 || nativeDecision == null || !nativeDecision.allows()) {
            if (attempt >= 3) { unavailable(); return; }
            status.setText("Demo denied/unavailable; receipts: " + receipts); return;
        }
        receipts++;
        if (sequence == Long.MAX_VALUE) { unavailable(); return; }
        HostOperationContext.View ended = owner.apply(new HostOperationContext.Event(5,0,0,0,attempt,1,1,sequence+1,session,action));
        if (ended.status != 0) { unavailable(); return; }
        sequence = ended.sequence; attempt = ended.attempt; pending = false; consumed = false;
        owner.close(); session = null; action = null;
        status.setText("Local demo receipts: " + receipts);
    }
    @Override public void onPause() {
        append.setOnClickListener(null); retry.setOnClickListener(null); cancel.setOnClickListener(null); begin.setOnClickListener(null);
        if (owner != null) owner.close(); owner = null; session = null; action = null; pending = false; consumed = false;
        super.onPause();
    }
}
