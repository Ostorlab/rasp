package android.os;
/** Controlled OS identity boundary only. */
public final class Process {
 public static int ownUid=10001;
 public static int myUid(){return ownUid;}
 public static UserHandle myUserHandle(){return UserHandle.getUserHandleForUid(ownUid);}
 public static boolean isApplicationUid(int uid){int app=uid%100000;return uid>=0 && app>=10000 && app<=19999;}
}
