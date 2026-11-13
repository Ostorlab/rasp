package android.net;
public class Uri {
    private String raw;
    private final boolean empty;
    public Uri(boolean empty) { this.empty = empty; }
    public boolean equals(Object other) { return other instanceof Uri && empty == ((Uri)other).empty; }
    public static Uri parse(String raw){Uri uri=new Uri(false);uri.raw=raw;return uri;}
    public String toString() { if(raw!=null)return raw; throw new AssertionError("PAC secrets must never be copied"); }
    public static final Uri EMPTY = new Uri(true);
}
