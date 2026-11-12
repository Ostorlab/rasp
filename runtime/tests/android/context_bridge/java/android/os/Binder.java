package android.os;
/** Live transaction identity is simulated; native gate/effect code is never replaced. */
public class Binder implements IBinder {
 public static final ThreadLocal<Integer> callingUid=new ThreadLocal<>();
 public static int getCallingUidOrThrow(){Integer uid=callingUid.get();if(uid==null)throw new IllegalStateException();return uid;}
 public boolean transact(int code,Parcel data,Parcel reply,int flags) throws RemoteException{return onTransact(code,data,reply,flags);}
 protected boolean onTransact(int code,Parcel data,Parcel reply,int flags) throws RemoteException{return false;}
}
