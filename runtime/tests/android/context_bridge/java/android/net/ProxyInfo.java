package android.net;
public class ProxyInfo {
    public String host = "proxy.example";
    public int port = 8080;
    public android.net.Uri pac = new android.net.Uri(true);
    public boolean fail;
    public String getHost() { if(fail) throw new IllegalStateException(); return host; }
    public int getPort() { if(fail) throw new IllegalStateException(); return port; }
    public android.net.Uri getPacFileUrl() { if(fail) throw new IllegalStateException(); return pac; }
}
