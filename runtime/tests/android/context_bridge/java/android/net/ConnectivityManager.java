package android.net;
public class ConnectivityManager {
    public ProxyInfo proxy;
    public boolean fail;
    public ProxyInfo getDefaultProxy() {
        if (fail) throw new SecurityException("denied");
        return proxy;
    }
}
