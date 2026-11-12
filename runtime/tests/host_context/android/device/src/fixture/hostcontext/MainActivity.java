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
    private void beginFlow() {
        if (owner != null) owner.close();
        try {
            session = fresh(); action = fresh(); sequence = 1; attempt = 1; pending = true; consumed = false;
            owner = new HostOperationContext(new HostOperationContext.Binding("append_demo_receipt", HASH, true));
            owner.apply(new HostOperationContext.Event(1,0,0,1,0,0,1,sequence,session,new byte[16]));
            owner.apply(new HostOperationContext.Event(2,2,HostOperationContext.secureEntry(selected),0,attempt,0,1,++sequence,session,action));
            final HostOperationContext captured = owner;
            begin.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View view) { if (owner == captured) beginFlow(); }
            });
            append.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View view) { append(captured); }
            });
            retry.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View view) {
                if (owner != captured || !pending || !consumed || attempt >= 3) return;
                HostOperationContext.View result = owner.apply(new HostOperationContext.Event(7,2,
                    HostOperationContext.secureEntry(selected),0,attempt+1,0,1,sequence+1,session,action));
                if (result.status == 0) { attempt++; sequence++; consumed = false; }
                }
            });
            cancel.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View view) {
                if (owner != captured || !pending) return;
                owner.apply(new HostOperationContext.Event(6,0,0,0,attempt,0,1,++sequence,session,action));
                pending = false; owner.close();
                }
            });
        } catch (RuntimeException | LinkageError error) {
            pending = false; if (owner != null) owner.close(); status.setText("Demo flow unavailable");
        }
    }
    private void append(HostOperationContext captured) {
        if (owner != captured || !pending || consumed || sequence == Long.MAX_VALUE) return;
        HostOperationContext.View input = owner.apply(new HostOperationContext.Event(3,2,
            HostOperationContext.secureEntry(selected),0,attempt,0,1,++sequence,session,action));
        if (input.status != 0) return;
        HostOperationContext.GateResult result = owner.gate(1,sequence,attempt);
        consumed = result.context.state == 9;
        RuntimeBridge.PolicyDecision nativeDecision = result.nativeDecision;
        if (result.context.status != 0 || nativeDecision == null || !nativeDecision.allows()) {
            status.setText("Demo denied/unavailable; receipts: " + receipts); return;
        }
        receipts++;
        owner.apply(new HostOperationContext.Event(5,0,0,0,attempt,1,1,++sequence,session,action));
        pending = false;
        status.setText("Local demo receipts: " + receipts);
    }
    @Override public void onPause() {
        append.setOnClickListener(null); retry.setOnClickListener(null); cancel.setOnClickListener(null); begin.setOnClickListener(null);
        if (owner != null) owner.close(); owner = null; session = null; action = null; pending = false;
        super.onPause();
    }
}
