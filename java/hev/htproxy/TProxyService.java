package hev.htproxy;

/**
 * JNI shim for hev-socks5-tunnel (tun2socks). The native library registers its methods to exactly this
 * class name when it is built with the default PKGNAME/CLSNAME, so do not rename or move this file.
 */
public class TProxyService {
    static {
        System.loadLibrary("hev-socks5-tunnel");
    }

    public static native boolean TProxyStartService(String configPath, int fd);

    public static native boolean TProxyStopService();

    public static native boolean TProxyIsRunning();

    public static native long[] TProxyGetStats();
}
