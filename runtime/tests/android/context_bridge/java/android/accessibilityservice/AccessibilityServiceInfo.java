package android.accessibilityservice;
public class AccessibilityServiceInfo {
    public String component;
    public int capabilities;
    public int flags;
    public AccessibilityServiceInfo(String component, int capabilities, int flags) {
        this.component = component; this.capabilities = capabilities; this.flags = flags;
    }
    public String getId() { return component; }
    public int getCapabilities() { return capabilities; }
}
