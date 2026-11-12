package android.net;
public class Uri {
    private final boolean empty;
    public Uri(boolean empty) { this.empty = empty; }
    public boolean equals(Object other) { return other instanceof Uri && empty == ((Uri)other).empty; }
    public String toString() { throw new AssertionError("PAC secrets must never be copied"); }
    public static final Uri EMPTY = new Uri(true);
}
