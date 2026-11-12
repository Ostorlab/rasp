package android.content;
import android.net.Uri;
import android.database.Cursor;
import android.os.*;
public abstract class ContentProvider {
 public Context context;public String callingPackage="fixture.entrycaller";
 public Context getContext(){return context;}public String getCallingPackage(){return callingPackage;}
 public abstract boolean onCreate();
 public abstract Cursor query(Uri uri,String[] projection,String selection,String[] args,String order);
 public Cursor query(Uri uri,String[] projection,String selection,String[] args,String order,CancellationSignal cancellation){return query(uri,projection,selection,args,order);}
 public Cursor query(Uri uri,String[] projection,Bundle args,CancellationSignal cancellation){return null;}
 public abstract Uri insert(Uri uri,ContentValues values);public abstract int update(Uri uri,ContentValues values,String selection,String[] args);
 public abstract int delete(Uri uri,String selection,String[] args);public abstract String getType(Uri uri);
 public Bundle call(String method,String arg,Bundle extras){return null;}
 public ContentProviderResult[] applyBatch(java.util.ArrayList<ContentProviderOperation> operations) throws OperationApplicationException{return null;}
 public int bulkInsert(Uri uri,ContentValues[] values){return 0;}
 public ParcelFileDescriptor openFile(Uri uri,String mode) throws java.io.FileNotFoundException{return null;}
}
