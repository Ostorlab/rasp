package fixture.entrycaller;
import android.app.Activity;
import android.app.ActivityOptions;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.widget.Button;
import android.widget.LinearLayout;

/** Unsigned real platform caller fixture. A build is not evidence of a permitted signed invocation. */
public final class MainActivity extends Activity {
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        LinearLayout layout=new LinearLayout(this);layout.setOrientation(LinearLayout.VERTICAL);
        add(layout,"Benign public link",0);add(layout,"Forged sender and query",1);add(layout,"Shared-identity partner link",2);
        add(layout,"Synchronous bound method",3);setContentView(layout);
    }
    private void add(LinearLayout layout,String label,final int kind) {
        Button button=new Button(this);button.setText(label);layout.addView(button);
        button.setOnClickListener(new android.view.View.OnClickListener(){@Override public void onClick(android.view.View view){send(kind);}});
    }
    private void send(int kind) {
        if(kind==3) {
            Intent service=new Intent();service.setComponent(new ComponentName("fixture.entrypoints","fixture.entrypoints.DemoService"));
            try { bindService(service,new ServiceConnection(){
                @Override public void onServiceConnected(ComponentName name,IBinder endpoint) {
                    Parcel data=Parcel.obtain(),reply=Parcel.obtain();
                    try {data.writeInterfaceToken("fixture.entrypoints.Demo");if(endpoint.transact(1,data,reply,0)){reply.readException();reply.readInt();}}
                    catch(android.os.RemoteException | RuntimeException error) {}
                    finally {data.recycle();reply.recycle();unbindService(this);}
                }
                @Override public void onServiceDisconnected(ComponentName name) {}
            },Context.BIND_AUTO_CREATE); } catch(RuntimeException error) {}
            return;
        }
        String path=kind==1 ? "/open/help?sender=trusted" : kind==2 ? "/partner/help" : "/open/help";
        Intent intent=new Intent(Intent.ACTION_VIEW,Uri.parse("https://links.example.invalid"+path));
        intent.setComponent(new ComponentName("fixture.entrypoints","fixture.entrypoints.MainActivity"));
        intent.putExtra("sender","trusted");
        if(kind==2 && Build.VERSION.SDK_INT>=35) Api35.launch(this,intent);else startActivity(intent);
    }
    private static final class Api35 {
        static void launch(Activity host,Intent intent){ActivityOptions options=ActivityOptions.makeBasic();options.setShareIdentityEnabled(true);host.startActivity(intent,options.toBundle());}
    }
}
