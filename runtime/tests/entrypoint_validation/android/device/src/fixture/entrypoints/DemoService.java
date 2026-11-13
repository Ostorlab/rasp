package fixture.entrypoints;
import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import co.ostorlab.rasp.RuntimeBridge;
import co.ostorlab.rasp.entry.EntryPointValidation;
import java.util.concurrent.atomic.AtomicInteger;

/** Bound synchronous Binder example. onBind/onStartCommand never authorize the business method. */
public final class DemoService extends Service {
    public static final String DESCRIPTOR="fixture.entrypoints.Demo";
    private final AtomicInteger receipts=new AtomicInteger();
    private final Binder endpoint=new Binder() {
        @Override protected boolean onTransact(int code,Parcel data,Parcel reply,int flags) throws RemoteException {
            if(code!=1 || flags!=0 || reply==null) return false;
            data.enforceInterface(DESCRIPTOR);
            if(data.dataAvail()!=0) return false;
            EntryPointValidation.Check check=EntryPointValidation.checkBinder(DemoService.this,Routes.BINDER);
            if(check.status!=0 || check.routeId!=6 || check.callerState!=2) return false;
            try {
                RuntimeBridge.PolicyDecision gate=RuntimeBridge.gateLocalOperation(Routes.OPERATION,Routes.HASH);
                if(gate==null || !gate.allows()) return false;
            } catch(RuntimeException | LinkageError unavailable) { return false; }
            int current=receipts.get();
            if(current==Integer.MAX_VALUE || !receipts.compareAndSet(current,current+1)) return false;
            reply.writeNoException(); reply.writeInt(current+1); return true;
        }
    };
    @Override public IBinder onBind(Intent intent) { return endpoint; }
    @Override public int onStartCommand(Intent intent,int flags,int startId) { return START_NOT_STICKY; }
}
