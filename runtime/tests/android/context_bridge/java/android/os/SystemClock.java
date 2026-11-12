package android.os;
/** Test-only OS clock boundary; the reducer cannot receive a caller timestamp. */
public final class SystemClock {
    public static long tick = 1000000000L;
    public static long[] readings = new long[0];
    public static int samples;
    public static long elapsedRealtimeNanos() {
        int index = samples++;
        return index < readings.length ? readings[index] : tick;
    }
}
