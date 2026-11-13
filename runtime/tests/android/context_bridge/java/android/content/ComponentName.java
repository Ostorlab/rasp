package android.content;
public final class ComponentName {
 private final String name; public ComponentName(String pkg,String cls){name=pkg+"/"+cls;}
 @Override public boolean equals(Object other){return other instanceof ComponentName && name.equals(((ComponentName)other).name);}
 @Override public int hashCode(){return name.hashCode();}
}
