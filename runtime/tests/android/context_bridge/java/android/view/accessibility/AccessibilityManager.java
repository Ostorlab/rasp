package android.view.accessibility;
import android.accessibilityservice.AccessibilityServiceInfo;
import java.util.*;
public class AccessibilityManager {
    public List<AccessibilityServiceInfo> enabled = new ArrayList<>();
    public boolean fail;
    public List<AccessibilityServiceInfo> getEnabledAccessibilityServiceList(int mask) {
        if (mask != -1) throw new AssertionError("FEEDBACK_ALL_MASK");
        if (fail) throw new SecurityException("denied");
        return enabled;
    }
}
