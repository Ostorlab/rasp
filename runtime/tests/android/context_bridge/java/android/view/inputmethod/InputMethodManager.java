package android.view.inputmethod;
import java.util.*;
public class InputMethodManager {
    public List<InputMethodInfo> enabled = new ArrayList<>();
    public InputMethodInfo current;
    public boolean fail;
    public List<InputMethodInfo> getEnabledInputMethodList() {
        if (fail) throw new SecurityException("denied");
        return enabled;
    }
    public InputMethodInfo getCurrentInputMethodInfo() {
        if (android.os.Build.VERSION.SDK_INT < 34) throw new AssertionError("unguarded API34");
        if (fail) throw new SecurityException("denied");
        return current;
    }
}
