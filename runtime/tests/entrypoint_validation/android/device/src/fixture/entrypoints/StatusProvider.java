package fixture.entrypoints;
import android.content.ContentProvider;
import android.content.ContentProviderOperation;
import android.content.ContentProviderResult;
import android.content.ContentValues;
import android.content.OperationApplicationException;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;
import co.ostorlab.rasp.RuntimeBridge;
import co.ostorlab.rasp.entry.EntryPointValidation;
import java.io.FileNotFoundException;
import java.util.ArrayList;

/** Fixed non-sensitive query only. No SQL, records, grants, arbitrary projection or lazy worker. */
public final class StatusProvider extends ContentProvider {
    @Override public boolean onCreate() { return true; }
    private Cursor status(Uri uri,CancellationSignal cancellation) {
        if(cancellation!=null && cancellation.isCanceled()) return null;
        EntryPointValidation.Check check=EntryPointValidation.checkProviderQuery(this,uri,Routes.PROVIDER);
        if(check.status!=0 || check.routeId!=7 || check.callerState!=2) return null;
        try {
            RuntimeBridge.PolicyDecision gate=RuntimeBridge.gateLocalOperation(Routes.OPERATION,Routes.HASH);
            if(gate==null || !gate.allows() || cancellation!=null && cancellation.isCanceled()) return null;
        } catch(RuntimeException | LinkageError unavailable) { return null; }
        MatrixCursor result=new MatrixCursor(new String[]{"demo_status"},1);
        result.addRow(new Object[]{1}); return result;
    }
    @Override public Cursor query(Uri uri,String[] projection,String selection,String[] args,String order) { return status(uri,null); }
    @Override public Cursor query(Uri uri,String[] projection,String selection,String[] args,String order,CancellationSignal cancellation) { return status(uri,cancellation); }
    @Override public Cursor query(Uri uri,String[] projection,Bundle args,CancellationSignal cancellation) { return status(uri,cancellation); }
    @Override public Uri insert(Uri uri,ContentValues values) { throw new UnsupportedOperationException(); }
    @Override public int update(Uri uri,ContentValues values,String selection,String[] args) { throw new UnsupportedOperationException(); }
    @Override public int delete(Uri uri,String selection,String[] args) { throw new UnsupportedOperationException(); }
    @Override public String getType(Uri uri) { return null; }
    @Override public Bundle call(String method,String arg,Bundle extras) { return null; }
    @Override public ContentProviderResult[] applyBatch(ArrayList<ContentProviderOperation> operations) throws OperationApplicationException { throw new OperationApplicationException(); }
    @Override public int bulkInsert(Uri uri,ContentValues[] values) { throw new UnsupportedOperationException(); }
    @Override public ParcelFileDescriptor openFile(Uri uri,String mode) throws FileNotFoundException { throw new FileNotFoundException(); }
}
