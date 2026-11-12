package fixture.entrypoints;
import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Looper;
import android.os.SystemClock;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import co.ostorlab.rasp.RuntimeBridge;
import co.ostorlab.rasp.entry.EntryPointValidation;
import co.ostorlab.rasp.host.HostOperationContext;
import java.nio.ByteBuffer;
import java.util.UUID;

/** Actual source Activity: strict route -> fresh real gate -> one harmless effect, never raw dispatch. */
public final class MainActivity extends Activity {
    private int pendingRoute, receipts, confirmations, reason;
    private long generation, pendingTick, lastTick;
    private boolean active, busy, exhausted;
    private TextView status;
    private Button confirm;
    private HostOperationContext context;
    private static long clock() {
        try { return SystemClock.elapsedRealtimeNanos(); }
        catch(RuntimeException | LinkageError unavailable) { return -1; }
    }
    private static boolean main() { return Looper.myLooper()==Looper.getMainLooper(); }
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        LinearLayout layout=new LinearLayout(this); layout.setOrientation(LinearLayout.VERTICAL);
        status=new TextView(this); status.setText("Entry demo receipts: 0"); layout.addView(status);
        confirm=new Button(this); confirm.setText("Confirm a new local demo action"); layout.addView(confirm);
        confirm.setOnClickListener(new android.view.View.OnClickListener() {
            @Override public void onClick(android.view.View view) { confirmDemo(); }
        }); setContentView(layout);
        receive(getIntent(),false);
    }
    @Override public void onNewIntent(Intent intent) { super.onNewIntent(intent); receive(intent,true); }
    private void receive(Intent intent,boolean newIntent) {
        if(!main() || busy) return;
        pendingRoute=0;
        if(exhausted || generation==Long.MAX_VALUE) { exhausted=true; reason=18; return; }
        generation++;
        EntryPointValidation.Check check=newIntent ? EntryPointValidation.checkNewActivity(this,intent,Routes.LINKS) :
            EntryPointValidation.checkInitialActivity(this,intent,Routes.LINKS);
        reason=check.reason;
        if(check.status!=EntryPointValidation.MATCH) return;
        EntryPointValidation.Rule rule=Routes.LINKS.rule(check.routeId);
        if(rule==null) return;
        if(active) { dispatch(rule); return; }
        if(rule.dispatchClass!=1 && rule.dispatchClass!=3) { reason=16; return; }
        long now=clock();
        if(now<0 || now<lastTick) { reason=18; return; }
        pendingTick=now; lastTick=now; pendingRoute=rule.routeId;
    }
    @Override public void onResume() {
        super.onResume(); if(!main()) return;
        active=true;
        long expectedGeneration=generation;
        int route=pendingRoute; pendingRoute=0;
        if(route==0 || exhausted) return;
        long now=clock();
        if(now<0 || now<lastTick || now<pendingTick || now-pendingTick>30000000000L || expectedGeneration!=generation) { reason=18; return; }
        lastTick=now;
        EntryPointValidation.Rule rule=Routes.LINKS.rule(route);
        if(rule!=null && (rule.dispatchClass==1 || rule.dispatchClass==3)) dispatch(rule);
    }
    private void dispatch(EntryPointValidation.Rule rule) {
        if(!main() || !active || busy || exhausted || !Routes.LINKS.valid || rule.dispatchClass==4) return;
        busy=true;
        try {
            RuntimeBridge.PolicyDecision gate=RuntimeBridge.gateLocalOperation(rule.operation,rule.expectedPolicySha256);
            if(gate==null || !gate.allows()) { reason=14; return; }
            switch(rule.routeId) {
                case 1: case 4: case 5: if(receipts<Integer.MAX_VALUE) receipts++; break;
                case 2: confirmations=1; break;
                default: return;
            }
            status.setText("Entry demo receipts: "+receipts+"; confirmation entry: "+confirmations);
        } catch(RuntimeException | LinkageError error) { reason=14; }
        finally { busy=false; }
    }
    private static byte[] fresh() {
        UUID value=UUID.randomUUID();
        return ByteBuffer.allocate(16).putLong(value.getMostSignificantBits()).putLong(value.getLeastSignificantBits()).array();
    }
    /** A deliberate new button action, never an automatic continuation or URL-supplied transaction. */
    private void confirmDemo() {
        if(!main() || !active || busy || confirmations!=1) return;
        busy=true;
        confirmations=0;
        try {
            if(context!=null) context.close();
            context=new HostOperationContext(new HostOperationContext.Binding(Routes.OPERATION,Routes.HASH,false));
            byte[] session=fresh(), action=fresh();
            if(context.apply(new HostOperationContext.Event(1,0,0,1,0,0,1,1,session,new byte[16])).status!=0) return;
            if(context.apply(new HostOperationContext.Event(2,3,4,0,1,0,1,2,session,action)).status!=0) return;
            HostOperationContext.GateResult result=context.gate(1,2,1);
            if(result.context.status!=0 || result.nativeDecision==null || !result.nativeDecision.allows()) return;
            if(receipts<Integer.MAX_VALUE) receipts++;
            confirmations=0;
            if(context.apply(new HostOperationContext.Event(5,0,0,0,1,1,1,3,session,action)).status!=0) reason=14;
        } catch(RuntimeException | LinkageError error) { reason=14; }
        finally {
            if(context!=null) context.close(); context=null; busy=false;
            status.setText("Entry demo receipts: "+receipts+"; confirmation entry: "+confirmations);
        }
    }
    @Override public void onPause() {
        active=false; pendingRoute=0; confirmations=0;
        if(generation==Long.MAX_VALUE) exhausted=true; else generation++;
        if(context!=null) context.close(); context=null;
        super.onPause();
    }
    @Override public void onDestroy() { pendingRoute=0; exhausted=true; confirm.setOnClickListener(null); super.onDestroy(); }
}
