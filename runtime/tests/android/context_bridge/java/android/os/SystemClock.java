package android.os;
/** Test-only OS clock boundary; the reducer cannot receive a caller timestamp. */
public final class SystemClock {
    public static long tick = 1000000000L;
    public static long elapsedRealtimeNanos() { return tick; }
}
