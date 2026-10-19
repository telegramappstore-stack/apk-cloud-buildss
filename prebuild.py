#!/usr/bin/env python3
"""CI-only step (runs on the GitHub Actions runner BEFORE `buildozer android debug`; never part of the APK).

 1. downloads the Xray core for Android (arm64) and stores it as libs/arm64-v8a/libxray.so
 2. builds hev-socks5-tunnel (tun2socks, JNI) with the runner's Android NDK -> libs/arm64-v8a/libhev-socks5-tunnel.so
 3. clones python-for-android, adds the <service> entry that Android requires for a VpnService to its manifest
    template, and points buildozer.spec at that copy (p4a.source_dir).
Buildozer then packs the two .so files (android.add_libs_arm64_v8a) and the Java sources (android.add_src).
"""
import glob
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
LIBS = os.path.join(ROOT, "libs", "arm64-v8a")
SPEC = os.path.join(ROOT, "buildozer.spec")

XRAY_TAGS = os.environ.get("XRAY_TAGS", "v25.10.15,latest").split(",")   # tried in this order
HEV_TAGS = os.environ.get("HEV_TAGS", "2.17.1,").split(",")               # '' = default branch

SERVICE_XML = """
        <service android:name="org.proxyscout.vpn.ProxyVpnService"
                 android:permission="android.permission.BIND_VPN_SERVICE"
                 android:exported="true">
            <intent-filter>
                <action android:name="android.net.VpnService" />
            </intent-filter>
        </service>
"""


def log(*a):
    print("[prebuild]", *a, flush=True)


def run(cmd, cwd=None, env=None):
    log("$", " ".join(cmd))
    subprocess.run(cmd, cwd=cwd, env=env, check=True)


def download(url, tries=3):
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "proxyscout-ci"})
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.read()
        except Exception as e:
            last = e
            log("download failed (%s), try %d/%d: %s" % (type(e).__name__, i + 1, tries, url))
    raise last


# ------------------------------------------------------------------ 1. Xray core
def fetch_xray():
    out = os.path.join(LIBS, "libxray.so")
    if os.path.exists(out):
        return
    os.makedirs(LIBS, exist_ok=True)
    errors = []
    for tag in XRAY_TAGS:
        tag = tag.strip()
        base = ("https://github.com/XTLS/Xray-core/releases/latest/download/" if tag in ("", "latest")
                else "https://github.com/XTLS/Xray-core/releases/download/%s/" % tag)
        url = base + "Xray-android-arm64-v8a.zip"
        try:
            z = zipfile.ZipFile(io.BytesIO(download(url)))
            member = next(n for n in z.namelist() if os.path.basename(n) == "xray")
            data = z.read(member)
            if data[:4] != b"\x7fELF" or data[18:20] != b"\xb7\x00":
                raise ValueError("not an ARM64 ELF executable")
            with open(out, "wb") as f:
                f.write(data)
            os.chmod(out, 0o755)
            log("Xray core ready (%s, %.1f MB)" % (tag or "latest", len(data) / 1e6))
            return
        except Exception as e:
            errors.append("%s: %s: %s" % (url, type(e).__name__, e))
            log("Xray %s failed: %s" % (tag, e))
    raise SystemExit("could not get the Xray core:\n" + "\n".join(errors))


# ------------------------------------------------------------------ 2. hev-socks5-tunnel
def find_ndk():
    cands = [os.environ.get(v) for v in ("ANDROID_NDK_HOME", "ANDROID_NDK_LATEST_HOME", "ANDROID_NDK_ROOT", "ANDROID_NDK")]
    cands += sorted(glob.glob("/usr/local/lib/android/sdk/ndk/*"), reverse=True)
    cands += sorted(glob.glob(os.path.expanduser("~/.buildozer/android/platform/android-ndk-*")), reverse=True)
    for c in cands:
        if c and os.path.exists(os.path.join(c, "ndk-build")):
            return c
    return None


def build_hev():
    out = os.path.join(LIBS, "libhev-socks5-tunnel.so")
    if os.path.exists(out):
        return
    os.makedirs(LIBS, exist_ok=True)
    ndk = find_ndk()
    if not ndk:
        raise SystemExit("no Android NDK found on this runner (looked at ANDROID_NDK_HOME and /usr/local/lib/android/sdk/ndk)")
    log("NDK:", ndk)
    work = tempfile.mkdtemp(prefix="hev-")
    last = None
    for tag in HEV_TAGS:
        tag = tag.strip()
        proj = os.path.join(work, "t" + (tag or "default"))
        os.makedirs(proj)
        try:
            cmd = ["git", "clone", "--recursive", "--depth", "1"] + (["--branch", tag] if tag else [])
            run(cmd + ["https://github.com/heiher/hev-socks5-tunnel", os.path.join(proj, "jni")])
            run([os.path.join(ndk, "ndk-build"), "APP_ABI=arm64-v8a", "APP_PLATFORM=android-24", "-j4"], cwd=proj)
            so = os.path.join(proj, "libs", "arm64-v8a", "libhev-socks5-tunnel.so")
            if not os.path.exists(so):
                raise FileNotFoundError(so)
            shutil.copy(so, out)
            log("hev-socks5-tunnel ready (%s)" % (tag or "default branch"))
            return
        except Exception as e:
            last = e
            log("hev %s failed: %s" % (tag or "default", e))
    raise SystemExit("could not build hev-socks5-tunnel: %s" % last)


# ------------------------------------------------------------------ 3. python-for-android with the VPN service entry
def spec_text():
    with open(SPEC, encoding="utf-8") as f:
        return f.read()


def spec_get(spec, key):
    m = re.search(r"^[ \t]*%s[ \t]*=[ \t]*(.*?)[ \t]*$" % re.escape(key), spec, re.M)
    return m.group(1) if m else ""


def spec_set(spec, key, value):
    line = "%s = %s" % (key, value)
    pat = re.compile(r"^[ \t]*#?[ \t]*%s[ \t]*=.*$" % re.escape(key), re.M)
    if pat.search(spec):
        return pat.sub(lambda m: line, spec, count=1)
    return re.sub(r"^\[app\][ \t]*$", lambda m: "[app]\n" + line, spec, count=1, flags=re.M)


def patch_manifest_template(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if "ProxyVpnService" in text:
        return False
    i = text.rfind("</application>")
    if i < 0:
        raise ValueError("no </application> in " + path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text[:i] + SERVICE_XML + "    " + text[i:])
    return True


def patch_p4a(p4a_dir):
    hits = glob.glob(os.path.join(p4a_dir, "**", "AndroidManifest.tmpl.xml"), recursive=True)
    if not hits:
        raise SystemExit("no AndroidManifest.tmpl.xml found in " + p4a_dir)
    for h in hits:
        log("manifest template %s: %s" % (os.path.relpath(h, p4a_dir), "service added" if patch_manifest_template(h) else "already patched"))


def prepare_p4a():
    spec = spec_text()
    ref = spec_get(spec, "p4a.branch") or "master"
    d = os.path.join(os.path.dirname(ROOT), "_p4a_patched")
    shutil.rmtree(d, ignore_errors=True)
    run(["git", "clone", "--depth", "1", "--branch", ref, "https://github.com/kivy/python-for-android", d])
    patch_p4a(d)
    # p4a's own pure-python requirements (buildozer would normally pull them in when it installs p4a itself)
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "sh", "jinja2", "colorama", "appdirs",
                    "packaging", "toml", "build", "setuptools"], check=False)
    spec = spec_set(spec, "p4a.source_dir", d)
    if "libs/arm64-v8a" not in spec_get(spec, "android.add_libs_arm64_v8a"):
        spec = spec_set(spec, "android.add_libs_arm64_v8a", "libs/arm64-v8a/*.so")
    if not spec_get(spec, "android.add_src"):
        spec = spec_set(spec, "android.add_src", "java")
    with open(SPEC, "w", encoding="utf-8") as f:
        f.write(spec)
    log("buildozer.spec: p4a.source_dir = " + d)


def main():
    fetch_xray()
    build_hev()
    prepare_p4a()
    for f in sorted(glob.glob(os.path.join(LIBS, "*.so"))):
        log("packed lib: %s (%.1f MB)" % (os.path.basename(f), os.path.getsize(f) / 1e6))


if __name__ == "__main__":
    main()
