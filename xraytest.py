"""xraytest - REAL verification of V2Ray configs with the Xray core (like 'real delay' in v2rayNG / NPV Tunnel).

A TCP/TLS connect only proves that a server is alive. This starts Xray with the config and sends a real HTTP
request through it, so a config with a wrong UUID, wrong path or a blocked transport fails here too.
Also provides LocalProxy: Xray as a plain local SOCKS5/HTTP proxy (no VPN), e.g. as Psiphon's upstream proxy.
"""
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import proxycore as pc
import xrayconf as xc

TEST_BASE_PORT = 21000
LOCAL_SOCKS, LOCAL_HTTP = 10818, 10819


def find_xray():
    env = os.environ.get("XRAY_BIN")
    if env and os.path.exists(env):
        return env
    if "ANDROID_ARGUMENT" in os.environ or "ANDROID_PRIVATE" in os.environ:
        try:
            from jnius import autoclass
            act = autoclass("org.kivy.android.PythonActivity").mActivity
            path = os.path.join(str(act.getApplicationInfo().nativeLibraryDir), "libxray.so")
            return path if os.path.exists(path) else None
        except Exception:
            return None
    return shutil.which("xray")


def _env():
    e = dict(os.environ)
    e["XRAY_LOCATION_ASSET"] = tempfile.gettempdir()
    return e


def _wait_port(port, proc, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        s = socket.socket()
        s.settimeout(0.25)
        try:
            s.connect(("127.0.0.1", port))
            return True
        except OSError:
            time.sleep(0.15)
        finally:
            s.close()
    return False


def _launch(xray, cfg, first_port):
    """Start Xray with cfg; (proc, None) when it listens, (None, output) when it died / never listened."""
    fd, path = tempfile.mkstemp(suffix=".json", prefix="xr")
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f)
    proc = subprocess.Popen([xray, "run", "-c", path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=_env())
    ok = _wait_port(first_port, proc, 5.0)
    if ok:
        return proc, None
    out = ""
    try:
        proc.kill()
        out = proc.communicate(timeout=2)[0].decode("utf-8", "ignore")[-400:]
    except Exception:
        pass
    return None, out or "no output"


def _stop(proc):
    try:
        proc.terminate()
        proc.wait(timeout=2)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _batch(xray, group, legacy, stop, timeout, base_port):
    """-> list of ms|None per proxy, or None when Xray itself would not start with this config."""
    cfg, ports = xc.build_test_config(group, base_port, legacy)
    live = [(i, p) for i, p in enumerate(ports) if p]
    res = [None] * len(group)
    if not live:
        return res
    proc, err = _launch(xray, cfg, live[0][1])
    if proc is None:
        return None
    try:
        def one(item):
            i, port = item
            if stop.is_set():
                return i, None
            a = pc.check_socks5("127.0.0.1", port, timeout)
            if a is None:
                return i, None
            b = pc.check_socks5("127.0.0.1", port, timeout)          # 2nd request: connection already warm
            return i, min(a, b) if b is not None else a
        with ThreadPoolExecutor(max_workers=16) as ex:
            for i, ms in ex.map(one, live):
                res[i] = ms
    finally:
        _stop(proc)
    return res


def real_delay_many(proxies, stop, on_result, timeout=8.0, batch=40):
    """Verify v2ray proxies through Xray. on_result(proxy, ms|None) per proxy. Returns False if Xray is unavailable."""
    xray = find_xray()
    if not xray:
        return False

    def do(group, depth=0):
        if stop.is_set() or not group:
            return
        for legacy in (False, True):                                    # Xray >= 25.10 layout, then the older one
            res = _batch(xray, group, legacy, stop, timeout, TEST_BASE_PORT)
            if res is not None:
                for p, ms in zip(group, res):
                    on_result(p, ms)
                return
        if len(group) == 1:                                             # this one config breaks Xray itself
            on_result(group[0], None)
            return
        mid = len(group) // 2                                           # bisect to isolate the bad config(s)
        do(group[:mid], depth + 1)
        do(group[mid:], depth + 1)

    for i in range(0, len(proxies), batch):
        do(list(proxies[i:i + batch]))
    return True


class LocalProxy:
    """Xray as a local proxy: SOCKS5 127.0.0.1:10818 and HTTP 127.0.0.1:10819 (no VPN)."""

    def __init__(self):
        self.proc = None
        self.state = "stopped"          # stopped | starting | running | error
        self.error = ""

    @property
    def running(self):
        return self.state == "running" and self.proc is not None and self.proc.poll() is None

    def start(self, proxy):
        """Blocking (a few seconds) - call from a thread."""
        self.stop()
        self.state, self.error = "starting", ""
        xray = find_xray()
        if not xray:
            self.state, self.error = "error", "The Xray core is not available in this build."
            return
        last = ""
        for legacy in (False, True):
            try:
                cfg = xc.build_config(proxy, legacy, local_port=LOCAL_SOCKS, http_port=LOCAL_HTTP)
            except xc.ConfigError as e:
                self.state, self.error = "error", str(e)
                return
            proc, err = _launch(xray, cfg, LOCAL_SOCKS)
            if proc is not None:
                self.proc, self.state = proc, "running"
                return
            last = err
        self.state, self.error = "error", "Xray did not start: " + last

    def stop(self):
        if self.proc is not None:
            _stop(self.proc)
        self.proc, self.state, self.error = None, "stopped", ""
