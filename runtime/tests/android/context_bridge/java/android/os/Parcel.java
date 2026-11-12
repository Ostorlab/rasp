package android.os;
public final class Parcel {
 private String token; private final java.util.ArrayDeque<Integer> values=new java.util.ArrayDeque<>();
 public static Parcel obtain(){return new Parcel();}
 public void writeInterfaceToken(String value){token=value;}
 public void enforceInterface(String value){if(!value.equals(token))throw new SecurityException();}
 public int dataAvail(){return values.size()*4;}
 public void writeNoException(){}
 public void readException(){}
 public void writeInt(int value){values.add(value);}
 public int readInt(){return values.remove();}
 public void recycle(){}
}
