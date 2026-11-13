package fixture.validation;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.TextView;
import co.ostorlab.rasp.RuntimeBridge;
import java.util.List;
import org.json.JSONException;
import org.json.JSONObject;

/** Harmless owned host using only production APIs; never device attestation. */
public final class MainActivity extends Activity {
    private final Handler handler = new Handler(Looper.getMainLooper());
    private TextView status;
    private String nonce;
    private String scenario;
    private boolean baselineComplete;
    private boolean executionStarted;
    private int baselineReceipts;
    private int receipts;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        status = new TextView(this);
        status.setId(R.id.status);
        status.setText("Waiting for actual production publication");
        setContentView(status);
        Intent intent = getIntent();
        nonce = intent.getStringExtra("validation_nonce");
        scenario = intent.getStringExtra("validation_scenario");
        if (nonce == null || !nonce.matches("[a-f0-9]{32}")
                || !("android_clean_receipt".equals(scenario) || "android_policy_hash_mismatch".equals(scenario))
                || !"baseline".equals(intent.getStringExtra("validation_phase"))) {
            status.setText("Rejected fixture invocation");
            return;
        }
        try {
            int initialized = RuntimeBridge.initialize(getApplication());
            if (initialized != RuntimeBridge.INITIALIZED && initialized != RuntimeBridge.ALREADY_INITIALIZED) {
                status.setText("Production context unavailable"); return;
            }
            pollBaseline(0);
        } catch (RuntimeException | LinkageError error) {
            status.setText("Production runtime unavailable");
        }
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if (baselineComplete && !executionStarted && nonce.equals(intent.getStringExtra("validation_nonce"))
                && scenario.equals(intent.getStringExtra("validation_scenario"))
                && "execution".equals(intent.getStringExtra("validation_phase"))) {
            executionStarted = true;
            append("execution");
        } else {
            status.setText("Rejected stale or duplicate fixture phase");
        }
    }

    private void pollBaseline(final int attempt) {
        if (isFinishing()) return;
        if (append("baseline")) {
            baselineComplete = true;
        } else if (attempt < 44) {
            handler.postDelayed(new Runnable() {
                @Override public void run() { pollBaseline(attempt + 1); }
            }, 1000);
        }
    }

    /** Gate on the execution thread immediately before the actual in-memory mutation. */
    private boolean append(String phase) {
        try {
            RuntimeBridge.PolicyInfo info = RuntimeBridge.localPolicyInfo();
            if (info == null || info.status() != RuntimeBridge.POLICY_OK) return false;
            boolean mismatch = "execution".equals(phase) && "android_policy_hash_mismatch".equals(scenario);
            String expected = ExpectedPolicy.SHA256;
            if (mismatch) expected = (expected.charAt(0) == '0' ? "1" : "0") + expected.substring(1);
            int before = "baseline".equals(phase) ? baselineReceipts : receipts;
            RuntimeBridge.PolicyDecision decision = RuntimeBridge.gateLocalOperation("append_demo_receipt", expected);
            if (decision == null) return false;
            if (decision.allows()) {
                if ("baseline".equals(phase)) ++baselineReceipts;
                else ++receipts;
            }
            if ("baseline".equals(phase) && !decision.allows()) return false;
            JSONObject event = new JSONObject();
            event.put("nonce", nonce); event.put("scenario", scenario); event.put("phase", phase);
            event.put("policy_sha256", info.policySha256());
            event.put("config_sha256", info.effectiveConfigSha256());
            event.put("status", decision.status()); event.put("action", decision.action());
            event.put("reason", decision.reason()); event.put("before", before);
            event.put("after", "baseline".equals(phase) ? baselineReceipts : receipts);
            List<RuntimeBridge.PolicyDetail> details = decision.details();
            RuntimeBridge.PolicyDetail detail = details.size() == 1 ? details.get(0) : null;
            event.put("rule_id", detail == null ? JSONObject.NULL : detail.ruleId);
            event.put("rule_version", detail == null ? JSONObject.NULL : detail.ruleVersion);
            event.put("rule_status", detail == null || detail.statusPresent != 1 ? JSONObject.NULL : detail.status);
            event.put("rule_evaluated", detail != null && detail.predicateEvaluated == 1);
            event.put("rule_verdict", detail == null ? JSONObject.NULL : detail.verdict);
            status.setText(event.toString());
            return true;
        } catch (JSONException | RuntimeException | LinkageError error) {
            status.setText("Production API/fixture output unavailable");
            return false;
        }
    }

    @Override protected void onDestroy() {
        handler.removeCallbacksAndMessages(null);
        super.onDestroy();
    }
}
