package android.os;
import java.util.ArrayList;
public class Handler {
    private static final ArrayList<Runnable> pending = new ArrayList<>();
    public static boolean fail;
    public static boolean throwConstruct;
    public static boolean throwRemove;
    public static boolean throwPost;
    public Handler(Looper looper) { if (throwConstruct) throw new IllegalStateException("handler construction"); }
    public boolean postDelayed(Runnable task, long delay) {
        if (throwPost) throw new IllegalStateException("handler post");
        if (fail) return false;
        pending.add(task); return true;
    }
    public void removeCallbacks(Runnable task) {
        if (throwRemove) throw new IllegalStateException("handler remove");
        pending.removeIf(value -> value == task);
    }
    public static int count() { return pending.size(); }
    public static void pulse() {
        ArrayList<Runnable> copy = new ArrayList<>(pending); pending.clear();
        for (Runnable task : copy) task.run();
    }
}
