"""engine - connects the phone to a chosen proxy.

Android : Java VpnService (org.proxyscout.vpn.ProxyVpnService) = tun -> hev-socks5-tunnel -> Xray -> proxy.
Desktop : a simulation, so the connection screen can be tried on a PC.
The UI only talks to the small API of BaseEngine.
"""
import os
import random
import threading
import time

import proxycore as pc
import xrayconf as xc

ACTION_START = "org.proxyscout.vpn.START"
ACTION_STOP = "org.proxyscout.vpn.STOP"
SERVICE_CLASS = "org.proxyscout.vpn.ProxyVpnService"
REQ_VPN = 7421


def on_android():
    return "ANDROID_ARGUMENT" in os.environ or "ANDROID_PRIVATE" in os.environ


class BaseEngine:
    simulated = False

    def __init__(self):
        self.state = "stopped"          # stopped | starting | running | error
        self.error = ""
        self.proxy = None
        self.t0 = None

    def connect(self, proxy):
        raise NotImplementedError

    def disconnect(self):
        raise NotImplementedError

    def poll(self):
        """-> dict(state, error, tx, rx, uptime); tx/rx = real bytes sent/received since the connection came up."""
        raise NotImplementedError

    def tunnel_ping(self):
        """ms for a full request THROUGH the running tunnel (Xray's local SOCKS), or None."""
        return pc.check_socks5("127.0.0.1", xc.LOCAL_PORT, 6.0)

    def direct_ping(self):
        """ms to open a TCP connection to the proxy server from this phone's own internet."""
        return pc.tcp_ping(self.proxy.host, self.proxy.port) if self.proxy else None


def looks_like_xray_config_error(err):
    e = (err or "").lower()
    return "xray" in e and any(k in e for k in ("config", "json", "unmarshal", "unknown", "invalid", "parse", "failed to start"))


class AndroidEngine(BaseEngine):
    def __init__(self):
        super().__init__()
        from jnius import autoclass
        self._ac = autoclass
        self.act = autoclass("org.kivy.android.PythonActivity").mActivity
        self.Intent = autoclass("android.content.Intent")
        self.VpnService = autoclass("android.net.VpnService")
        self.Svc = autoclass(SERVICE_CLASS)
        self.sdk = autoclass("android.os.Build$VERSION").SDK_INT
        self._base = (0, 0)
        self._cancel = False
        self._gen = 0

    # -------------------------------------------------------------- service plumbing
    def _intent(self, action):
        i = self.Intent()
        i.setClassName(self.act.getPackageName(), SERVICE_CLASS)
        i.setAction(action)
        return i

    def _start_service(self):
        """The service reads <filesDir>/xray.json (written just before); nothing is passed through extras."""
        self.Svc.markStarting()
        i = self._intent(ACTION_START)
        if self.sdk >= 26:
            self.act.startForegroundService(i)
        else:
            self.act.startService(i)

    def _stop_service(self):
        try:
            self.act.startService(self._intent(ACTION_STOP))
        except Exception:
            pass

    def _wait(self, wanted, timeout):
        end = time.time() + timeout
        while time.time() < end and not self._cancel:
            st = str(self.Svc.getState())
            if st in wanted:
                return st
            time.sleep(0.25)
        return None

    # -------------------------------------------------------------- API
    def connect(self, proxy):
        self.proxy, self.error, self.state, self.t0 = proxy, "", "starting", None
        self._cancel = False
        self._gen += 1
        try:
            need = self.VpnService.prepare(self.act)             # Intent when Android still has to ask the user
        except Exception as e:
            return self._fail("VPN check failed: %s" % e)
        if need is None:
            self._begin(self._gen)
            return
        from android import activity
        try:
            activity.unbind(on_activity_result=self._on_result)
        except Exception:
            pass
        activity.bind(on_activity_result=self._on_result)
        self.act.startActivityForResult(need, REQ_VPN)

    def _on_result(self, request, result, data):
        if request != REQ_VPN:
            return
        from android import activity
        try:
            activity.unbind(on_activity_result=self._on_result)
        except Exception:
            pass
        if result == -1:                                           # RESULT_OK
            self._begin(self._gen)
        else:
            self._fail("VPN permission was denied")

    def _begin(self, gen):
        threading.Thread(target=self._run, args=(gen,), daemon=True).start()

    def _fail(self, msg):
        self.error, self.state = msg, "error"

    def _run(self, gen):
        cfg_path = os.path.join(str(self.act.getFilesDir().getAbsolutePath()), "xray.json")
        last = ""
        for legacy in (False, True):                                # Xray >= 25.10 layout first, then the older one
            if self._cancel or gen != self._gen:
                return
            try:
                text = xc.dumps(self.proxy, legacy=legacy)
            except xc.ConfigError as e:
                return self._fail(str(e))
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(text)
            self._start_service()
            st = self._wait(("running", "error"), 30)
            if self._cancel or gen != self._gen:
                return
            if st == "running":
                w = self.Svc.getWanBytes()
                self._base = (max(0, int(w[0])), max(0, int(w[1])))
                self.t0, self.state, self.error = time.time(), "running", ""
                return
            last = str(self.Svc.getLastError()) or "connection timed out"
            if not (not legacy and looks_like_xray_config_error(last)):
                break
            self._stop_service()
            time.sleep(1.0)
        self._stop_service()
        self._fail(last)

    def disconnect(self):
        self._cancel = True
        self._gen += 1
        self._stop_service()
        self.state, self.error, self.t0 = "stopped", "", None

    def poll(self):
        st, err, tx, rx = self.state, self.error, 0, 0
        if st == "running":
            try:
                java = str(self.Svc.getState())
                if java != "running":                              # revoked from system UI, Xray died, ...
                    st, err = ("error", str(self.Svc.getLastError()) or "VPN stopped") if java == "error" else ("stopped", "")
                    self.state, self.error, self.t0 = st, err, None
                else:
                    w = self.Svc.getWanBytes()
                    tx, rx = max(0, int(w[0]) - self._base[0]), max(0, int(w[1]) - self._base[1])
            except Exception as e:
                err = str(e)
        return {"state": st, "error": err, "tx": tx, "rx": rx, "uptime": (time.time() - self.t0) if self.t0 else 0,
                "log": str(self.Svc.getXrayLog()) if st == "error" else ""}


class BrokenEngine(BaseEngine):
    """Android build whose native VPN pieces are missing: connecting reports why, it never fakes a connection."""

    def __init__(self, reason):
        super().__init__()
        self.reason = reason

    def connect(self, proxy):
        self.proxy, self.state, self.error = proxy, "error", self.reason

    def disconnect(self):
        self.state, self.error = "stopped", ""

    def poll(self):
        return {"state": self.state, "error": self.error, "tx": 0, "rx": 0, "uptime": 0, "log": ""}

    def tunnel_ping(self):
        return None


class DummyEngine(BaseEngine):
    """Desktop preview: pretends to connect and produces random traffic."""
    simulated = True

    def __init__(self):
        super().__init__()
        self._tx = self._rx = 0.0
        self._last = time.time()

    def connect(self, proxy):
        self.proxy, self.error, self.state = proxy, "", "starting"
        self._tx = self._rx = 0.0
        threading.Timer(1.2, self._up).start()

    def _up(self):
        if self.state == "starting":
            self.state, self.t0, self._last = "running", time.time(), time.time()

    def disconnect(self):
        self.state, self.t0 = "stopped", None

    def poll(self):
        now = time.time()
        if self.state == "running":
            dt, self._last = now - self._last, now
            self._rx += random.uniform(0.2e6, 3e6) * dt
            self._tx += random.uniform(0.02e6, 0.4e6) * dt
        return {"state": self.state, "error": "", "tx": int(self._tx), "rx": int(self._rx),
                "uptime": (now - self.t0) if self.t0 else 0, "log": ""}

    def tunnel_ping(self):
        return random.randint(90, 400)

    def direct_ping(self):
        return random.randint(30, 200)


def get_engine():
    if on_android():
        try:
            return AndroidEngine()
        except Exception as e:                                      # e.g. the Java classes are missing from this build
            return BrokenEngine("The VPN service is not in this APK (%s: %s). Check the CI log of prebuild.py / the Java sources."
                                % (type(e).__name__, e))
    return DummyEngine()
