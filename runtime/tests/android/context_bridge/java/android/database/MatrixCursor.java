package android.database;
public final class MatrixCursor implements Cursor {
 private int count; public MatrixCursor(String[] columns,int capacity){}
 public void addRow(Object[] row){count++;}public int getCount(){return count;}public void close(){}
}
