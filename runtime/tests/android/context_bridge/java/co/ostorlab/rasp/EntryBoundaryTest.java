package co.ostorlab.rasp;

import android.app.Application;
import android.app.ComponentCaller;
import android.content.Intent;
import android.net.Uri;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.Looper;
import android.os.Parcel;
import android.os.SystemClock;
import co.ostorlab.rasp.entry.EntryPointValidation;
import fixture.entrypoints.MainActivity;
import fixture.entrypoints.DemoService;
import fixture.entrypoints.Routes;
import fixture.entrypoints.StatusProvider;
import java.lang.reflect.Field;

/** Actual reference handlers and JNI/native gate. Only Android OS delivery/identity/UI/clock are controlled. */
public final class EntryBoundaryTest {
    private static int assertions;
    private static final String URL="https://links.example.invalid/open/help";
    private static void check(boolean good,String message) { assertions++;if(!good)throw new AssertionError(message); }
    private static Intent link(String url) { return new Intent(Intent.ACTION_VIEW,Uri.parse(url)); }
    private static Application app() { Application app=new Application();app.name="fixture.entrypoints";return app; }
    private static Object field(Object host,String name) throws Exception {Field field=host.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(host);}
    private static int receipts(MainActivity host) throws Exception {return (Integer)field(host,"receipts");}
    private static MainActivity host(String url) {
        MainActivity host=new MainActivity();host.application=app();host.intent=link(url);host.onCreate(null);return host;
    }
    private static void publish(int tracer,int status) {PolicyTest.publishValuesNative(new long[]{tracer,status,1000000000L});}
    private static void activity() throws Exception {
        SystemClock.tick=1000000000000L;
        MainActivity host=host(URL);
        check(receipts(host)==0,"cold start acted before foreground");host.onResume();check(receipts(host)==1,"cold public navigation did not gate/dispatch");
        host.onNewIntent(link(URL));check(receipts(host)==2,"repeat public navigation falsely presented as replay protection");
        RuntimeBridge.PolicyDecision historical=RuntimeBridge.gateLocalOperation(Routes.OPERATION,Routes.HASH);
        publish(42,0);host.onNewIntent(link(URL));check(receipts(host)==2 && historical.allows(),"cached ALLOW admitted newer indicator");
        for(int status:new int[]{1,2,3,4}) {publish(0,status);host.onNewIntent(link(URL));check(receipts(host)==2,"unavailable/incomplete native evidence dispatched");}
        publish(0,0);
        for(String bad:new String[]{URL+"?",URL+"#",URL+"%00",URL+"/", "https://links.example.invalid/commit"}) {
            host.onNewIntent(link(bad));check(receipts(host)==2,"malicious/sensitive link acted");
        }
        for(int kind=0;kind<7;kind++) {
            Intent intent=link(URL);
            if(kind==0)intent.type="text/plain";if(kind==1)intent.flags=1;if(kind==2)intent.clip=new android.content.ClipData();
            if(kind==3)intent.selector=new Intent();if(kind==4)intent.pkg="evil.app";
            if(kind==5)intent.component=new android.content.ComponentName("evil.app","Fake");
            if(kind==6)intent.categories=java.util.Set.of("evil.category");
            host.onNewIntent(intent);check(receipts(host)==2,"unsafe Intent envelope dispatched");
        }
        Intent benign=link(URL).putExtra("sender","trusted");benign.categories=java.util.Set.of(Intent.CATEGORY_BROWSABLE,Intent.CATEGORY_DEFAULT);
        host.onNewIntent(benign);check(receipts(host)==3,"benign browser extras/categories failed or extras read");
        String restricted="https://links.example.invalid/partner/help";
        Build.VERSION.SDK_INT=34;host.onNewIntent(link(restricted));check(receipts(host)==3,"API34 restricted route admitted");
        Build.VERSION.SDK_INT=35;host.initialCaller.uid=-1;host.currentCaller=new ComponentCaller();
        host.onNewIntent(link(restricted));check(receipts(host)==4 && host.currentCallerReads==1 && host.initialCallerReads==0,"new Intent used old caller");
        for(int kind=0;kind<9;kind++) {
            host.currentCaller=new ComponentCaller();host.application.packages.callerPackages=new String[]{"fixture.entrycaller"};
            host.application.packages.callerUid=10002;host.application.packages.pinMatches=true;host.application.denyCallerPermission=false;
            host.application.packages.permission.protection=2;host.application.packages.permission.flags=0;
            if(kind==0)host.currentCaller.uid=-1;if(kind==1)host.currentCaller.uid=android.os.Process.myUid();
            if(kind==2)host.currentCaller.uid=99001;if(kind==3)host.currentCaller.uid=110002;
            if(kind==4)host.application.packages.callerPackages=new String[]{"fixture.entrycaller","shared.other"};
            if(kind==5)host.application.packages.pinMatches=false;if(kind==6)host.application.denyCallerPermission=true;
            if(kind==7)host.application.packages.permission.protection=0;if(kind==8)host.application.packages.callerUid=10003;
            host.onNewIntent(link(restricted));check(receipts(host)==4,"forged/missing caller, UID, signature or permission admitted");
        }
        host.onNewIntent(link("https://links.example.invalid/open/confirm"));
        check((Integer)field(host,"confirmations")==1 && receipts(host)==4,"confirmation entry committed mutation");
        ((android.widget.Button)field(host,"confirm")).performClick();check(receipts(host)==5,"new deliberate RT20 action did not use real gate");
        host.onPause();host.onResume();check(receipts(host)==5,"resume replayed an old action");
        int before=receipts(host);
        Thread worker=new Thread(()->host.onNewIntent(link(URL)));worker.start();worker.join();
        check(receipts(host)==before,"wrong-thread handler dispatched");host.onDestroy();
        Build.VERSION.SDK_INT=35;
        MainActivity failedConfirmation=host("https://links.example.invalid/open/confirm");failedConfirmation.onResume();
        SystemClock.tick=-1;
        ((android.widget.Button)field(failedConfirmation,"confirm")).performClick();
        check((Integer)field(failedConfirmation,"confirmations")==0,"failed START left confirmation armed for a new owner/reset retry");
        SystemClock.tick=1000000000000L;
        ((android.widget.Button)field(failedConfirmation,"confirm")).performClick();
        check(receipts(failedConfirmation)==0,"failed confirmation recovered by recreating a context owner");
        failedConfirmation.onPause();failedConfirmation.onDestroy();
        MainActivity exhausted=host(URL);
        Field generation=MainActivity.class.getDeclaredField("generation");generation.setAccessible(true);generation.setLong(exhausted,Long.MAX_VALUE);
        exhausted.onNewIntent(link(URL));exhausted.onResume();check(receipts(exhausted)==0,"generation counter wrapped or repaired");
        exhausted.onPause();exhausted.onDestroy();
    }
    private static void lifecycle() throws Exception {
        for(int kind=0;kind<7;kind++) {
            SystemClock.tick=1000000000000L;
            MainActivity host=host(URL);
            if(kind==0)SystemClock.tick+=30000000000L;
            if(kind==1)SystemClock.tick+=30000000001L;
            if(kind==2)SystemClock.tick=-1;
            if(kind==3)host.onPause();
            if(kind==4)host.onNewIntent(link(URL+"#"));
            if(kind==5)SystemClock.tick--;
            if(kind==6)SystemClock.fail=true;
            host.onResume();SystemClock.fail=false;check(receipts(host)==(kind==0 ? 1 : 0),"pending route time/lifecycle/invalid replacement");host.onPause();host.onDestroy();
        }
    }
    private static boolean transact(IBinder binder,int flags,boolean extra) throws Exception {
        Parcel data=Parcel.obtain(),reply=Parcel.obtain();data.writeInterfaceToken(DemoService.DESCRIPTOR);if(extra)data.writeInt(7);
        try{return binder.transact(1,data,reply,flags);}finally{data.recycle();reply.recycle();}
    }
    private static void ipc() throws Exception {
        DemoService service=new DemoService();service.application=app();IBinder endpoint=service.onBind(new Intent());
        check(service.onStartCommand(null,0,1)==2,"started service work/restart");
        Binder.callingUid.remove();check(!transact(endpoint,0,false),"direct invocation without Binder identity");
        Binder.callingUid.set(10002);
        byte[] originalPin=new byte[32];
        EntryPointValidation.CallerProfile profile=new EntryPointValidation.CallerProfile("fixture.entrycaller",Routes.PERMISSION,new byte[][]{originalPin});
        EntryPointValidation.Rule compiled=Routes.BINDER.rule(6);
        EntryPointValidation.Rule[] originalRules={compiled};
        EntryPointValidation.Binding copied=new EntryPointValidation.Binding(originalRules,new EntryPointValidation.CallerProfile[]{profile});
        originalPin[0]=1;originalRules[0]=null;
        check(EntryPointValidation.checkBinder(service,copied).status==0,"caller pin or rule input was not defensively copied");
        check(transact(endpoint,0,false),"actual Binder method with valid profile did not dispatch");
        check(transact(endpoint,0,false),"repeated nonsensitive IPC mistaken for replay protection");
        check(!transact(endpoint,1,false) && !transact(endpoint,0,true),"oneway or extra command accepted");
        service.application.denyCallerPermission=true;check(!transact(endpoint,0,false),"onBind authorization reused after permission loss");
        service.application.denyCallerPermission=false;publish(42,0);check(!transact(endpoint,0,false),"native DENY did not block actual Binder effect");publish(0,0);
        StatusProvider provider=new StatusProvider();provider.context=app();check(provider.onCreate(),"provider create");
        Uri uri=Uri.parse("content://fixture.entrypoints.status/status");
        android.database.Cursor cursor=provider.query(uri,null,(android.os.Bundle)null,null);check(cursor!=null && cursor.getCount()==1,"actual fixed query effect");cursor.close();
        provider.callingPackage=null;check(provider.query(uri,null,null,null,null)==null,"provider missing verified package admitted");provider.callingPackage="fixture.entrycaller";
        android.os.CancellationSignal signal=new android.os.CancellationSignal();signal.cancel();check(provider.query(uri,null,(android.os.Bundle)null,signal)==null,"canceled provider published cursor");
        android.os.CancellationSignal late=new android.os.CancellationSignal();late.readings=new boolean[]{false,true};
        check(provider.query(uri,null,(android.os.Bundle)null,late)==null,"cancellation at publication returned provider data");
        check(provider.query(Uri.parse("content://fixture.entrypoints.status/status?x=1"),null,null,null,null)==null,"query URL parameters accepted");
        check(provider.call("commit",null,null)==null,"provider call inherited query authority");
        publish(42,0);check(provider.query(uri,null,null,null,null)==null,"native DENY provider data");publish(0,0);
        Binder.callingUid.remove();check(provider.query(uri,null,null,null,null)==null,"provider asynchronous identity loss");
    }
    public static void main(String[] args) throws Exception {
        Looper.getMainLooper();System.load(args[0]);check(PolicyTest.initializeNative(new long[]{1,0}),"real native init");
        MainActivity before=host(URL);before.onResume();check(receipts(before)==0,"startup without publication acted");before.onPause();before.onDestroy();
        publish(0,0);activity();lifecycle();ipc();
        System.out.println("PASS actual Android reference handlers with real JNI/native gate: "+assertions+" assertions; controlled OS seams, no device proof");
    }
}
