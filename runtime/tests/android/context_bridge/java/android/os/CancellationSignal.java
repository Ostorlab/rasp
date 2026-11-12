package android.os;
/** Controlled OS cancellation observation, including a cancellation arriving after the real gate. */
public final class CancellationSignal {
 private boolean canceled;public boolean[] readings=new boolean[0];private int index;
 public void cancel(){canceled=true;}
 public boolean isCanceled(){return index<readings.length ? readings[index++] : canceled;}
}
