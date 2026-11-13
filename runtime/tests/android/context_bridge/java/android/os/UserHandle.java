package android.os;
public final class UserHandle {
 private final int user; private UserHandle(int user){this.user=user;}
 public static UserHandle getUserHandleForUid(int uid){return new UserHandle(uid/100000);}
 @Override public boolean equals(Object other){return other instanceof UserHandle && ((UserHandle)other).user==user;}
 @Override public int hashCode(){return user;}
}
