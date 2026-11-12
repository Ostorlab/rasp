package android.view;
public class MotionEvent {
    public static final int FLAG_WINDOW_IS_OBSCURED = 1, FLAG_WINDOW_IS_PARTIALLY_OBSCURED = 2;
    private final int flags;
    public MotionEvent(int flags) { this.flags = flags; }
    public int getFlags() { return flags; }
}
