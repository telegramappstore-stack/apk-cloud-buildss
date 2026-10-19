"""xrayconf - turns a Proxy (v2ray share link, SOCKS5 or HTTP proxy) into an Xray-core config.

The generated config has ONE local SOCKS5 inbound (127.0.0.1:LOCAL_PORT, UDP enabled) and the proxy as the
first (= default) outbound. hev-socks5-tunnel feeds the phone's traffic into that inbound.

Xray changed the outbound `settings` layout in v25.10 (one endpoint, flat fields). build_config(legacy=False)
writes the flat layout, build_config(legacy=True) the older vnext/servers layout; the engine tries both.
"""
import base64
import json
import socket
import urllib.parse

LOCAL_PORT = 10808


class ConfigError(Exception):
    pass


def _b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "ignore")


def _resolve(host):
    """Resolve here (the app is outside the VPN) so the Xray binary never needs DNS for the server address."""
    try:
        socket.inet_pton(socket.AF_INET, host)
        return host
    except OSError:
        pass
    if ":" in host:
        return host
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except OSError:
        return host


def _truthy(v):
    return str(v).lower() in ("1", "true", "yes", "tls")


def parse_link(link):
    """Share link -> flat dict of everything the config needs."""
    link = link.strip()
    low = link.lower()
    L = {"proto": low.split("://", 1)[0], "enc": "none"}
    try:
        if low.startswith("vmess://"):
            d = json.loads(_b64d(link[8:]))
            L.update(address=str(d["add"]).strip(), port=int(d["port"]), id=str(d["id"]), aid=int(d.get("aid") or 0),
                     scy=d.get("scy") or "auto", net=(d.get("net") or "tcp").lower(),
                     security="tls" if str(d.get("tls", "")).lower() in ("tls", "reality", "1", "true") else "none",
                     sni=d.get("sni") or "", host=d.get("host") or "", path=d.get("path") or "",
                     headerType=d.get("type") or "none", alpn=d.get("alpn") or "", fp=d.get("fp") or "",
                     serviceName=d.get("path") or "", mode="")
        elif low.startswith("ss://"):
            body = link[5:].split("#", 1)[0].split("?", 1)[0]
            if "@" not in body:
                body = _b64d(body)
            userinfo, hostport = body.rsplit("@", 1)
            if ":" not in userinfo:
                userinfo = _b64d(urllib.parse.unquote(userinfo))
            method, password = userinfo.split(":", 1)
            host, port = hostport.rsplit(":", 1)
            L.update(address=host.strip("[]"), port=int(port), method=method, password=urllib.parse.unquote(password),
                     net="tcp", security="none")
        elif low.startswith(("vless://", "trojan://")):
            u = urllib.parse.urlsplit(link)
            q = {k: v for k, v in urllib.parse.parse_qsl(u.query)}
            L.update(address=u.hostname, port=u.port, net=(q.get("type") or "tcp").lower(),
                     security=(q.get("security") or ("tls" if L["proto"] == "trojan" else "none")).lower(),
                     sni=q.get("sni") or q.get("peer") or "", host=q.get("host") or "", path=urllib.parse.unquote(q.get("path") or ""),
                     headerType=q.get("headerType") or "none", alpn=q.get("alpn") or "", fp=q.get("fp") or "",
                     serviceName=q.get("serviceName") or "", mode=q.get("mode") or "", flow=q.get("flow") or "",
                     pbk=q.get("pbk") or "", sid=q.get("sid") or "", spx=q.get("spx") or "",
                     insecure=_truthy(q.get("allowInsecure") or q.get("insecure") or "0"),
                     enc=q.get("encryption") or "none", id=urllib.parse.unquote(u.username or ""),
                     password=urllib.parse.unquote(u.username or ""))
        else:
            raise ConfigError("unsupported link type")
    except ConfigError:
        raise
    except (KeyError, ValueError, TypeError, IndexError, AttributeError) as e:
        raise ConfigError("cannot read this link (%s)" % type(e).__name__)
    if not L.get("address") or not L.get("port"):
        raise ConfigError("link has no server address")
    return L


def _stream(L, orig_host):
    net = {"h2": "http", "websocket": "ws", "raw": "tcp", "splithttp": "xhttp"}.get(L["net"], L["net"])
    sec = L.get("security") or "none"
    s = {"network": net, "security": sec}
    name = L.get("sni") or L.get("host") or orig_host
    if sec == "tls":
        t = {"serverName": name, "allowInsecure": bool(L.get("insecure", True))}
        if L.get("alpn"):
            t["alpn"] = [a for a in L["alpn"].split(",") if a]
        if L.get("fp"):
            t["fingerprint"] = L["fp"]
        s["tlsSettings"] = t
    elif sec == "reality":
        s["realitySettings"] = {"serverName": L.get("sni") or orig_host, "fingerprint": L.get("fp") or "chrome",
                                "publicKey": L.get("pbk", ""), "shortId": L.get("sid", ""), "spiderX": L.get("spx", "")}
    elif sec != "none":
        raise ConfigError("unsupported security '%s'" % sec)
    host = L.get("host") or L.get("sni") or orig_host
    path = L.get("path") or "/"
    if net == "ws":
        s["wsSettings"] = {"path": path, "headers": {"Host": host}}
    elif net == "grpc":
        s["grpcSettings"] = {"serviceName": L.get("serviceName") or L.get("path") or "", "multiMode": L.get("mode") == "multi"}
        if L.get("host") or L.get("sni"):
            s["grpcSettings"]["authority"] = host
    elif net == "tcp":
        if L.get("headerType") == "http":
            s["tcpSettings"] = {"header": {"type": "http", "request": {"path": [p for p in path.split(",") if p] or ["/"],
                                                                      "headers": {"Host": [h for h in host.split(",") if h]}}}}
    elif net == "http":
        s["httpSettings"] = {"host": [h for h in host.split(",") if h], "path": path}
    elif net == "httpupgrade":
        s["httpupgradeSettings"] = {"path": path, "host": host}
    elif net == "xhttp":
        s["xhttpSettings"] = {"path": path, "host": host, "mode": L.get("mode") or "auto"}
    elif net == "kcp":
        s["kcpSettings"] = {"header": {"type": L.get("headerType") or "none"}, "seed": L.get("path") or ""}
    else:
        raise ConfigError("unsupported transport '%s'" % net)
    return s


def _endpoint(proto, addr, port, body, legacy):
    """Flat (Xray >= 25.10) or legacy (vnext / servers) outbound settings."""
    if not legacy:
        return dict(address=addr, port=port, **body)
    if proto in ("vmess", "vless"):
        return {"vnext": [{"address": addr, "port": port, "users": [body]}]}
    return {"servers": [dict(address=addr, port=port, **body)]}


def outbound(p, legacy=False):
    if p.kind == "socks5":
        return {"tag": "proxy", "protocol": "socks", "settings": _endpoint("socks", p.host, p.port, {}, legacy)}
    if p.kind == "http":
        return {"tag": "proxy", "protocol": "http", "settings": _endpoint("http", p.host, p.port, {}, legacy)}
    if p.kind != "v2ray" or not p.link:
        raise ConfigError("nothing to connect to")
    L = parse_link(p.link)
    orig = L["address"]
    addr = _resolve(orig)
    proto = L["proto"]
    if proto == "vless":
        body = {"id": L["id"], "encryption": L.get("enc") or "none", "level": 0}
        if L.get("flow"):
            body["flow"] = L["flow"]
    elif proto == "vmess":
        body = {"id": L["id"], "security": L.get("scy") or "auto", "level": 0}
        if legacy:
            body["alterId"] = L.get("aid", 0)
    elif proto == "trojan":
        body = {"password": L["password"], "level": 0}
    elif proto == "ss":
        body = {"method": L["method"], "password": L["password"], "level": 0}
    else:
        raise ConfigError("unsupported protocol '%s'" % proto)
    ob = {"tag": "proxy", "protocol": {"ss": "shadowsocks"}.get(proto, proto),
          "settings": _endpoint(proto, addr, L["port"], body, legacy)}
    if proto != "ss":
        ob["streamSettings"] = _stream(L, orig)
    return ob


def build_config(p, legacy=False, local_port=LOCAL_PORT, log_level="warning", http_port=None):
    cfg = {
        "log": {"loglevel": log_level},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": local_port, "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}}],
        "outbounds": [outbound(p, legacy), {"tag": "direct", "protocol": "freedom"},
                      {"tag": "block", "protocol": "blackhole"}],
        "routing": {"domainStrategy": "AsIs", "rules": []},
    }
    if http_port:                                   # local HTTP proxy too (Psiphon's upstream proxy wants HTTP)
        cfg["inbounds"].append({"tag": "http-in", "listen": "127.0.0.1", "port": http_port, "protocol": "http",
                                "settings": {}})
    return cfg


def build_test_config(proxies, base_port, legacy=False):
    """ONE Xray process that tests many servers: proxy j gets its own local SOCKS port base_port+j.
    Returns (config, ports) where ports[j] is the port for proxies[j], or None if it cannot be expressed."""
    inbounds, outbounds, rules, ports = [], [], [], []
    for p in proxies:
        try:
            ob = outbound(p, legacy)
        except ConfigError:
            ports.append(None)
            continue
        i = len(inbounds)
        ob["tag"] = "o%d" % i
        inbounds.append({"tag": "i%d" % i, "listen": "127.0.0.1", "port": base_port + i, "protocol": "socks",
                         "settings": {"auth": "noauth", "udp": False}})
        outbounds.append(ob)
        rules.append({"type": "field", "inboundTag": ["i%d" % i], "outboundTag": "o%d" % i})
        ports.append(base_port + i)
    outbounds += [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}]
    return {"log": {"loglevel": "warning"}, "inbounds": inbounds, "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules}}, ports


def dumps(p, legacy=False, **kw):
    return json.dumps(build_config(p, legacy, **kw), indent=1)
