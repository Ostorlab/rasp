package android.content;
public class Intent {
 public static final String ACTION_VIEW="android.intent.action.VIEW",CATEGORY_DEFAULT="android.intent.category.DEFAULT",CATEGORY_BROWSABLE="android.intent.category.BROWSABLE";
 public static final int FLAG_GRANT_READ_URI_PERMISSION=1,FLAG_GRANT_WRITE_URI_PERMISSION=2,FLAG_GRANT_PERSISTABLE_URI_PERMISSION=64,FLAG_GRANT_PREFIX_URI_PERMISSION=128;
 public String action,pkg,type; public android.net.Uri data; public Intent selector;public ClipData clip;public ComponentName component;public int flags;
 public java.util.Set<String> categories;
 public Intent(){} public Intent(String action,android.net.Uri data){this.action=action;this.data=data;}
 public String getAction(){return action;}public android.net.Uri getData(){return data;}public String getType(){return type;}
 public Intent getSelector(){return selector;}public ClipData getClipData(){return clip;}public int getFlags(){return flags;}
 public String getPackage(){return pkg;}public ComponentName getComponent(){return component;}public java.util.Set<String> getCategories(){return categories;}
 public android.os.Bundle getExtras(){throw new AssertionError("Intent extras must never be touched");}
 public Intent putExtra(String key,String value){return this;}
}
