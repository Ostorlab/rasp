package fixture.policy;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.util.ArrayList;
import java.util.List;
import co.ostorlab.rasp.RuntimeBridge;

/** A harmless source host, compiled against the actual compile-only API, never device-efficacy proof. */
public final class MainActivity extends Activity {
    private static final String EXPECTED_POLICY_SHA256 = "5685df69e0340b2a8472c2929cd9be01db0444191abb8c5fdf366a51b0262c81";
    private final List<Integer> receipts = new ArrayList<>();
    private TextView status;
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        status = new TextView(this);
        status.setText("Demo receipts: 0. No device health or attestation claim.");
        Button append = new Button(this);
        append.setText("Append a demo receipt");
        append.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View view) { appendReceipt(); }
        });
        layout.addView(status); layout.addView(append); setContentView(layout);
        try { RuntimeBridge.initialize(getApplication()); }
        catch (RuntimeException | LinkageError error) { status.setText("Runtime unavailable before operation"); }
    }
    private void appendReceipt() {
        final RuntimeBridge.PolicyDecision decision;
        try {
            decision = RuntimeBridge.gateLocalOperation("append_demo_receipt", EXPECTED_POLICY_SHA256);
            if (decision == null || !decision.allows()) {
                status.setText("Not admitted before append; receipts: " + receipts.size()); return;
            }
        } catch (RuntimeException | LinkageError error) {
            status.setText("Runtime unavailable; no receipt appended"); return;
        }
        receipts.add(1);
        status.setText("Receipts: " + receipts.size() + "; adapted local gate allowed");
    }
}
