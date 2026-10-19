package org.proxyscout.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.TrafficStats;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import hev.htproxy.TProxyService;

/**
 * VPN glue:  apps -> tun -> hev-socks5-tunnel -> Xray (local SOCKS5) -> the chosen proxy.
 * Xray runs as a child process of this app (libxray.so from the APK's native lib dir). The app itself is
 * excluded from the VPN, so Xray's own connections to the proxy server do not loop back into the tunnel.
 * Python (pyjnius) drives it with intents and reads state through the static getters below.
 */
public class ProxyVpnService extends VpnService {
    public static final String ACTION_START = "org.proxyscout.vpn.START";
    public static final String ACTION_STOP = "org.proxyscout.vpn.STOP";
    private static final String TAG = "ProxyScoutVpn";
    private static final String CHANNEL = "proxyscout_vpn";

    private static volatile String state = "stopped";      // stopped | starting | running | error
    private static volatile String lastError = "";
    private static volatile ProxyVpnService instance;
    private static volatile int generation = 0;          // bumped by every START/STOP intent; older work backs off
    private static final StringBuilder xrayLog = new StringBuilder();

    private final Object lock = new Object();
    private ParcelFileDescriptor tun;
    private java.lang.Process xray;
    private Thread tunThread;

    // ------------------------------------------------------------------ API used from Python
    public static String getState() { return state; }

    public static String getLastError() { return lastError; }

    /** Called by Python right before it sends ACTION_START, so a stale 'running'/'error' is never read. */
    public static void markStarting() { setState("starting", ""); }

    public static String getXrayLog() {
        synchronized (xrayLog) { return xrayLog.toString(); }
    }

    public static boolean isXrayAlive() {
        ProxyVpnService s = instance;
        return s != null && alive(s.xray);
    }

    /** Bytes this app (= the Xray process) really sent / received on the network since boot: {tx, rx}. */
    public static long[] getWanBytes() {
        int uid = android.os.Process.myUid();
        return new long[]{TrafficStats.getUidTxBytes(uid), TrafficStats.getUidRxBytes(uid)};
    }

    // ------------------------------------------------------------------ service life cycle
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        instance = this;
        if (ACTION_STOP.equals(action)) {
            startForegroundSafe();                          // satisfies startForegroundService()
            final int g = ++generation;
            new Thread(new Runnable() {
                public void run() {
                    synchronized (lock) {
                        if (g != generation) return;        // a newer START arrived: keep the service alive
                        stopAll();
                        setState("stopped", "");
                    }
                    stopForegroundSafe();
                    stopSelf();
                }
            }, "proxyscout-stop").start();
            return START_NOT_STICKY;
        }
        if (ACTION_START.equals(action)) {
            // Python writes <filesDir>/xray.json before starting us; extras are only an optional override.
            String extra = intent.getStringExtra("xray_config");
            final String cfg = extra != null ? extra : new File(getFilesDir(), "xray.json").getAbsolutePath();
            final int port = 10808;
            startForegroundSafe();
            setState("starting", "");
            final int g = ++generation;
            new Thread(new Runnable() {
                public void run() { startAll(cfg, port, g); }
            }, "proxyscout-start").start();
            return START_NOT_STICKY;
        }
        startForegroundSafe();
        stopSelf();
        return START_NOT_STICKY;
    }

    @Override
    public void onRevoke() {                                // user turned the VPN off from system UI
        stopAll();
        setState("stopped", "");
        stopForegroundSafe();
        stopSelf();
    }

    @Override
    public void onDestroy() {
        stopAll();
        if (!"error".equals(state)) setState("stopped", "");
        instance = null;
        super.onDestroy();
    }

    // ------------------------------------------------------------------ start / stop
    private void startAll(String cfgPath, int port, int g) {
        synchronized (lock) {
            if (g != generation) return;                    // cancelled by a newer STOP/START before it began
            stopAll();
            setState("starting", "");
            try {
                if (cfgPath == null || !new File(cfgPath).exists()) {
                    throw new IOException("Xray config file is missing: " + cfgPath);
                }
                File bin = new File(getApplicationInfo().nativeLibraryDir, "libxray.so");
                if (!bin.exists()) {
                    throw new IOException("libxray.so is not in the APK (" + bin.getParent() + "). The Xray core was not bundled.");
                }
                synchronized (xrayLog) { xrayLog.setLength(0); }
                ProcessBuilder pb = new ProcessBuilder(bin.getAbsolutePath(), "run", "-c", cfgPath);
                pb.environment().put("XRAY_LOCATION_ASSET", getFilesDir().getAbsolutePath());
                pb.redirectErrorStream(true);
                xray = pb.start();
                pump(xray);

                if (!waitForPort(port, 6000)) {
                    throw new IOException("Xray did not start: " + tailLog(600));
                }

                Builder b = new Builder();
                b.setSession("ProxyScout");
                b.setMtu(1500);
                b.addAddress("198.18.0.1", 32);
                b.addRoute("0.0.0.0", 0);
                b.addDnsServer("198.18.0.2");               // answered by hev's mapped DNS, never leaves the phone
                try { b.addDisallowedApplication(getPackageName()); } catch (Exception e) { Log.w(TAG, e); }
                tun = b.establish();
                if (tun == null) throw new IOException("VPN permission was not granted");

                File yml = new File(getFilesDir(), "hev.yml");
                String conf = "tunnel:\n  mtu: 1500\n  ipv4: 198.18.0.1\n"
                        + "socks5:\n  port: " + port + "\n  address: 127.0.0.1\n  udp: 'udp'\n"
                        + "mapdns:\n  address: 198.18.0.2\n  port: 53\n  network: 100.64.0.0\n"
                        + "  netmask: 255.192.0.0\n  cache-size: 10000\n"
                        + "misc:\n  connect-timeout: 10000\n  tcp-read-write-timeout: 300000\n  log-level: warn\n";
                FileOutputStream out = new FileOutputStream(yml);
                out.write(conf.getBytes(StandardCharsets.UTF_8));
                out.close();

                final String ymlPath = yml.getAbsolutePath();
                final int fd = tun.getFd();
                tunThread = new Thread(new Runnable() {
                    public void run() {
                        try {
                            TProxyService.TProxyStartService(ymlPath, fd);
                        } catch (Throwable t) {
                            setState("error", "tunnel library failed: " + t);
                        }
                    }
                }, "hev-tunnel");
                tunThread.start();

                long end = System.currentTimeMillis() + 4000;
                boolean up = false;
                while (System.currentTimeMillis() < end && !"error".equals(state)) {
                    try { up = TProxyService.TProxyIsRunning(); } catch (Throwable t) { up = true; break; }
                    if (up) break;
                    Thread.sleep(100);
                }
                if ("error".equals(state)) throw new IOException(lastError);
                if (!up) throw new IOException("tunnel (hev-socks5-tunnel) did not start");
                if (!alive(xray)) throw new IOException("Xray stopped right after start: " + tailLog(600));
                setState("running", "");
            } catch (Throwable t) {
                String msg = String.valueOf(t.getMessage() == null ? t : t.getMessage());
                stopAll();
                setState("error", msg);
            }
        }
    }

    private void stopAll() {
        try { if (TProxyService.TProxyIsRunning()) TProxyService.TProxyStopService(); } catch (Throwable ignored) { }
        try { if (tunThread != null) tunThread.join(1500); } catch (Throwable ignored) { }
        tunThread = null;
        try { if (tun != null) tun.close(); } catch (Throwable ignored) { }
        tun = null;
        java.lang.Process p = xray;
        xray = null;
        if (p != null) {
            p.destroy();
            try {
                Thread.sleep(300);
                if (alive(p) && Build.VERSION.SDK_INT >= 26) p.destroyForcibly();
            } catch (Throwable ignored) { }
        }
    }

    // ------------------------------------------------------------------ helpers
    private static boolean alive(java.lang.Process p) {
        if (p == null) return false;
        try { p.exitValue(); return false; } catch (IllegalThreadStateException e) { return true; }
    }

    private boolean waitForPort(int port, int timeoutMs) throws InterruptedException {
        long end = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < end) {
            if (!alive(xray)) return false;
            Socket s = new Socket();
            try {
                s.connect(new InetSocketAddress("127.0.0.1", port), 250);
                return true;
            } catch (IOException e) {
                Thread.sleep(150);
            } finally {
                try { s.close(); } catch (IOException ignored) { }
            }
        }
        return false;
    }

    private void pump(final java.lang.Process p) {
        Thread t = new Thread(new Runnable() {
            public void run() {
                try {
                    BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8));
                    String line;
                    while ((line = r.readLine()) != null) {
                        Log.i("ProxyScoutXray", line);
                        synchronized (xrayLog) {
                            xrayLog.append(line).append('\n');
                            if (xrayLog.length() > 8000) xrayLog.delete(0, xrayLog.length() - 6000);
                        }
                    }
                } catch (IOException ignored) { }
            }
        }, "xray-log");
        t.setDaemon(true);
        t.start();
    }

    private static String tailLog(int n) {
        try { Thread.sleep(150); } catch (InterruptedException ignored) { }
        synchronized (xrayLog) {
            String s = xrayLog.toString().trim();
            return s.length() > n ? s.substring(s.length() - n) : (s.isEmpty() ? "(no output)" : s);
        }
    }

    private static void setState(String s, String err) {
        lastError = err == null ? "" : err;
        state = s;
        Log.i(TAG, "state=" + s + (lastError.isEmpty() ? "" : " error=" + lastError));
    }

    private void startForegroundSafe() {
        try {
            if (Build.VERSION.SDK_INT >= 26) {
                NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
                nm.createNotificationChannel(new NotificationChannel(CHANNEL, "VPN status", NotificationManager.IMPORTANCE_LOW));
            }
            Notification.Builder nb = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(this, CHANNEL) : new Notification.Builder(this);
            nb.setContentTitle("ProxyScout VPN").setContentText("Tap to open").setOngoing(true)
                    .setSmallIcon(getApplicationInfo().icon);
            try {
                Intent open = getPackageManager().getLaunchIntentForPackage(getPackageName());
                if (open != null) {
                    nb.setContentIntent(PendingIntent.getActivity(this, 0, open,
                            Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0));
                }
            } catch (Throwable ignored) { }
            startForeground(1, nb.build());
        } catch (Throwable t) {
            Log.w(TAG, "startForeground failed", t);
        }
    }

    private void stopForegroundSafe() {
        try { stopForeground(true); } catch (Throwable ignored) { }
    }
}
