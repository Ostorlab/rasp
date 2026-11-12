package android.app;
public class Activity {
    public boolean failWindow;
    private final android.view.Window window = new android.view.Window();
    public android.view.Window getWindow() {
        if (failWindow) throw new IllegalStateException("activity window lookup");
        return window;
    }
}
