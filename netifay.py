#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rathole + GRE web panel
- Pure Python 3 standard library (no pip packages).
- 100% compatible with the files created by rathole_v2_gre.sh:
    /root/rathole-core/iran<PORT>.toml | kharej<PORT>.toml
    /root/rathole-core/gre-<NAME>.sh
    /etc/systemd/system/rathole-<NAME>.service
    crontab: "# gre-rathole-<NAME>"  (GRE domain watcher)
             "#rathole-<NAME>.service" (scheduled restart)
"""
import os
import sys
import re
import json
import time
import hmac
import hashlib
import secrets
import subprocess
import ipaddress
import threading
import zipfile
import io
import socket
import ssl
import shutil
import tempfile
import tarfile
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http import cookies
from urllib.parse import urlparse

VERSION = "2.5.6"
CORE_DIR = os.environ.get("RATHOLE_DIR", "/root/rathole-core")
SERVICE_DIR = os.environ.get("RATHOLE_SERVICE_DIR", "/etc/systemd/system")
PANEL_CONF = os.environ.get("RATHOLE_PANEL_CONF", "/etc/netifay/config.json")
PANEL_UNIT = "netifay.service"
DEFAULT_REPO = "NETplusiran/NETIFAY"   # overwritten by the installer (config "repo")
CORE_BIN = os.path.join(CORE_DIR, "rathole")
BACKUP_DIR = os.environ.get("RATHOLE_BACKUP_DIR", "/root/netifay-backups")
BH_DIR = os.environ.get("RATHOLE_BH_DIR", "/root/backhaul-core")
BH_BIN = os.path.join(BH_DIR, "backhaul")
BH_TRANSPORTS = ("tcp", "tcpmux", "ws", "wss", "wsmux", "wssmux")
NAME_RE = re.compile(r"^(iran|kharej)([0-9]{2,5})$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_.@:+=\-]{1,128}$")
CRON_CHOICES = {
    "": "",
    "30m": "*/30 * * * *",
    "1h": "0 * * * *",
    "2h": "0 */2 * * *",
    "4h": "0 */4 * * *",
    "6h": "0 */6 * * *",
    "12h": "0 */12 * * *",
    "24h": "0 0 * * *",
}
CF_TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443]
CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095]
CF_NETS = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22")]
LOCK = threading.RLock()          # serialises every change to files / system


class ApiError(Exception):
    pass


# ---------------------------------------------------------------- helpers
def run(cmd, input_text=None, timeout=25, env=None):
    """Run a command (list form, never through a shell). Returns (rc, output)."""
    try:
        full_env = None
        if env:
            full_env = dict(os.environ)
            full_env.update(env)
        p = subprocess.run(cmd, input=input_text, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, universal_newlines=True,
                           timeout=timeout, env=full_env)
        return p.returncode, p.stdout or ""
    except FileNotFoundError:
        return 127, "command not found: %s" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "timeout: %s" % " ".join(cmd)
    except OSError as e:
        return 126, "%s: %s" % (cmd[0], e)


def read_file(path, default=""):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return default


def write_file(path, text, mode=0o644):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def is_ipv4(s):
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def v_port(x, label="پورت"):
    try:
        n = int(str(x).strip())
    except (TypeError, ValueError):
        raise ApiError("%s نامعتبر است" % label)
    if not 23 <= n <= 65535:
        raise ApiError("%s باید بین 23 تا 65535 باشد" % label)
    return n


def v_host(x, label):
    s = str(x or "").strip().lower().rstrip(".")
    if not s:
        raise ApiError("%s خالی است" % label)
    if is_ipv4(s) or DOMAIN_RE.match(s):
        return s
    raise ApiError("%s نامعتبر است: %s" % (label, s))


def v_ipv4(x, label):
    s = str(x or "").strip()
    if not is_ipv4(s):
        raise ApiError("%s یک IPv4 معتبر نیست" % label)
    return s


def v_int(x, label, lo, hi, default=None):
    if (x is None or str(x).strip() == "") and default is not None:
        return default
    try:
        n = int(str(x).strip())
    except (TypeError, ValueError):
        raise ApiError("%s نامعتبر است" % label)
    if not lo <= n <= hi:
        raise ApiError("%s باید بین %d و %d باشد" % (label, lo, hi))
    return n


def net30(ip):
    return ipaddress.ip_interface("%s/30" % ip).network


def peer30(ip):
    """The other usable host inside the /30 of `ip`."""
    n = net30(ip)
    hosts = [str(h) for h in n.hosts()]
    if ip not in hosts:
        raise ApiError("IP داخلی %s آدرس شبکه/برادکست /30 است؛ آخرین عدد باید مثل 1 یا 2 باشد (نه مضرب 4 و نه مضرب 4 منهای 1)" % ip)
    return hosts[1] if hosts[0] == ip else hosts[0]


def resolve_ipv4(host):
    if is_ipv4(host):
        return host
    for ns in ("1.1.1.1", "8.8.8.8"):
        rc, out = run(["dig", "+short", "+time=2", "+tries=1", "A", host, "@" + ns], timeout=6)
        if rc == 0:
            for line in out.split():
                if is_ipv4(line):
                    return line
    try:
        return socket.gethostbyname(host)
    except OSError:
        return ""


# ---------------------------------------------------------------- toml
def parse_toml(text):
    """Minimal parser – enough for the configs generated by the script."""
    data, sect = {}, None
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        i += 1
        if not s or s.startswith("#"):
            continue
        am = re.match(r"^([A-Za-z0-9_]+)\s*=\s*\[(.*)$", s)
        if am and sect is not None:
            def _clean(x):
                return re.sub(r'#[^"]*$', "", x)
            buf = _clean(am.group(2))
            while "]" not in re.sub(r'"[^"]*"', "", buf) and i < len(lines):
                buf += " " + _clean(lines[i])
                i += 1
            data[sect][am.group(1)] = re.findall(r'"([^"]*)"', buf)
            continue
        m = re.match(r"^\[([^\]]+)\]\s*(#.*)?$", s)
        if m:
            sect = m.group(1).strip().strip('"')
            data.setdefault(sect, {})
            continue
        m = re.match(r"^([A-Za-z0-9_]+)\s*=\s*(.+)$", s)
        if m and sect is not None:
            k, v = m.group(1), m.group(2).strip()
            if v.startswith('"'):
                e = v.find('"', 1)
                v = v[1:e] if e > 0 else v[1:]
            else:
                v = v.split("#")[0].strip()
                if v in ("true", "false"):
                    v = (v == "true")
                else:
                    try:
                        v = int(v)
                    except ValueError:
                        pass
            data[sect][k] = v
    return data


def split_hostport(addr):
    addr = str(addr or "")
    if ":" not in addr:
        return addr, 0
    h, p = addr.rsplit(":", 1)
    try:
        return h, int(p)
    except ValueError:
        return h, 0


# ---------------------------------------------------------------- paths
def engine_of(name):
    """Which tunnel engine owns this name."""
    if os.path.isfile(os.path.join(BH_DIR, name + ".toml")):
        return "backhaul"
    return gen_engine_of(name) or "rathole"


def _dir(engine):
    if engine in GEN:
        return GEN[engine]["dir"]
    return BH_DIR if engine == "backhaul" else CORE_DIR


def p_toml(name, engine=None):
    engine = engine or engine_of(name)
    if engine in GEN:
        return p_cfg(name, engine)
    return os.path.join(_dir(engine), name + ".toml")


def p_gre(name, engine=None):
    return os.path.join(_dir(engine or engine_of(name)), "gre-%s.sh" % name)


def p_service(name, engine=None):
    return os.path.join(SERVICE_DIR, svc(name, engine))


def p_reset(name, engine=None):
    e = engine or engine_of(name)
    return os.path.join(_dir(e), "%s-%s.sh" % (e, name))


def svc(name, engine=None):
    return "%s-%s.service" % (engine or engine_of(name), name)


def p_bh_cert(name):
    return os.path.join(BH_DIR, "tls-%s.crt" % name), os.path.join(BH_DIR, "tls-%s.key" % name)


def p_p12(name):
    return os.path.join(CORE_DIR, "cdn-%s.p12" % name)


def is_cf_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in CF_NETS)


LINK_TYPES = ("gre", "ipip", "sit")
LINK_MTU = {"gre": 1476, "ipip": 1480, "sit": 1480}
LINK_LABEL = {"gre": "GRE", "ipip": "IPIP", "sit": "6to4 (SIT)"}


def inner6(ip):
    """Deterministic IPv6 ULA for the SIT (6to4) link, derived from the /30 IPv4."""
    a, b, c, d = [int(x) for x in ip.split(".")]
    return "fd00:%x:%x:%x::%x" % (a, b, c, d)


def inner_addr(ip, link):
    """Address string an app binds/dials on inside the link."""
    return "[%s]" % inner6(ip) if link == "sit" else ip


def link_dev(name, link="gre"):
    m = NAME_RE.match(name)
    side = "IR" if m.group(1) == "iran" else "KH"
    return {"gre": "gre", "ipip": "ipip", "sit": "sit"}.get(link, "gre") + side + m.group(2)


def v_link(p):
    lk = str(p.get("link") or "gre")
    if lk not in LINK_TYPES:
        raise ApiError("نوع لینک باید GRE، IPIP یا 6to4 باشد")
    return lk


def gre_down_all(name):
    for lk in LINK_TYPES:
        gre_down(link_dev(name, lk))


def gre_dev(name):
    m = NAME_RE.match(name)
    return ("greIR" if m.group(1) == "iran" else "greKH") + m.group(2)


def check_name(name):
    name = str(name or "")
    if not NAME_RE.match(name):
        raise ApiError("نام تانل نامعتبر است")
    return name


# ---------------------------------------------------------------- generators (same format as the bash script)
def gen_gre_script(dev, local_domain, remote_domain, gre_ip, mtu, link="gre"):
    inner = ("%s/64" % inner6(gre_ip)) if link == "sit" else ("%s/30" % gre_ip)
    head = (
        "#!/bin/bash\n"
        "# Auto-generated by rathole script - GRE-over-domain manager\n"
        'DEV="%s"\n'
        'MODE="%s"\n'
        'LOCAL_DOMAIN="%s"\n'
        'REMOTE_DOMAIN="%s"\n'
        'GRE_LOCAL_IP="%s"\n'
        'INNER="%s"\n'
        'GRE_CIDR="30"\n'
        'MTU="%s"\n'
        'TTL="255"\n'
    ) % (dev, link, local_domain, remote_domain, gre_ip, inner, mtu)
    body = r'''
resolve() {
    local d="$1" ip=""
    ip=$(dig +short A "$d" @1.1.1.1 2>/dev/null | grep -Eo '^[0-9]+(\.[0-9]+){3}$' | head -n1)
    [ -z "$ip" ] && ip=$(dig +short A "$d" @8.8.8.8 2>/dev/null | grep -Eo '^[0-9]+(\.[0-9]+){3}$' | head -n1)
    [ -z "$ip" ] && ip=$(getent ahostsv4 "$d" 2>/dev/null | awk '{print $1; exit}')
    echo "$ip"
}

new_local=$(resolve "$LOCAL_DOMAIN")
new_remote=$(resolve "$REMOTE_DOMAIN")

# On a transient DNS failure, do NOT tear anything down.
if [ -z "$new_local" ] || [ -z "$new_remote" ]; then
    logger -t rathole-gre "[$DEV] DNS resolve failed (local=$new_local remote=$new_remote); leaving tunnel untouched"
    exit 0
fi

# Safety: GRE 'local' must be an address on this host. If the local domain's
# public IP is not on any interface (e.g. server is behind NAT), fall back to
# the real outbound source IP so the tunnel still comes up.
if ! ip -o -4 addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -qx "$new_local"; then
    detected=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -n1)
    if [ -n "$detected" ]; then
        logger -t rathole-gre "[$DEV] local-domain IP $new_local not on host, using detected $detected"
        new_local="$detected"
    fi
fi

# Create the device if it does not exist yet
if ! ip link show "$DEV" &>/dev/null; then
    ip tunnel add "$DEV" mode "$MODE" remote "$new_remote" local "$new_local" ttl "$TTL"
    ip addr add "$INNER" dev "$DEV"
    ip link set "$DEV" mtu "$MTU"
    ip link set "$DEV" up
    logger -t rathole-gre "[$DEV] created mode=$MODE local=$new_local remote=$new_remote inner=$INNER"
    exit 0
fi

# Device exists: read its current endpoints
cur=$(ip tunnel show "$DEV" 2>/dev/null)
cur_remote=$(echo "$cur" | grep -oP 'remote \K[0-9.]+')
cur_local=$(echo "$cur" | grep -oP 'local \K[0-9.]+')

# Only reconfigure when a public endpoint actually changed.
# 'ip tunnel change' keeps the device and its internal GRE IP intact, so the
# rathole tunnel riding on $GRE_LOCAL_IP is not disturbed.
if [ "$cur_remote" != "$new_remote" ] || [ "$cur_local" != "$new_local" ]; then
    ip tunnel change "$DEV" mode "$MODE" remote "$new_remote" local "$new_local" ttl "$TTL"
    ip addr show dev "$DEV" 2>/dev/null | grep -q "${INNER%/*}" || ip addr add "$INNER" dev "$DEV"
    ip link set "$DEV" up
    logger -t rathole-gre "[$DEV] endpoints updated local:${cur_local}->${new_local} remote:${cur_remote}->${new_remote}"
fi
exit 0
'''
    return head + body


def gen_toml_cdn(t):
    bind_host = "[::]" if t["ipv6"] else "0.0.0.0"
    nd = "true" if t["nodelay"] else "false"
    tls = "true" if t["cdn_tls"] else "false"
    if t["role"] == "iran":
        out = (
            "# panel-mode: cdn\n"
            "# panel-cdn-domain: %s\n"
            "[server]\n"
            'bind_addr = "%s:%d"\n'
            'default_token = "%s"\n'
            "heartbeat_interval = %d\n\n"
            "[server.transport]\n"
            'type = "websocket"\n\n'
            "[server.transport.tcp]\n"
            "nodelay = %s\n\n"
            "[server.transport.websocket]\n"
            "tls = %s\n\n"
        ) % (t["cdn_domain"], bind_host, t["port"], t["token"], t["heartbeat"], nd, tls)
        if t["cdn_tls"]:
            out += '[server.transport.tls]\npkcs12 = "%s"\npkcs12_password = "%s"\n\n' % (
                p_p12(t["name"]), t["p12_pass"])
        for s in t["services"]:
            out += '[server.services.%d]\ntype = "%s"\nbind_addr = "%s:%d"\n\n' % (
                s["port"], s["type"], bind_host, s["port"])
    else:
        out = (
            "# panel-mode: cdn\n"
            "[client]\n"
            'remote_addr = "%s:%d"\n'
            'default_token = "%s"\n'
            "heartbeat_timeout = %d\n"
            "retry_interval = %d\n\n"
            "[client.transport]\n"
            'type = "websocket"\n\n'
            "[client.transport.tcp]\n"
            "nodelay = %s\n\n"
            "[client.transport.websocket]\n"
            "tls = %s\n\n"
        ) % (t["cdn_domain"], t["port"], t["token"], t["heartbeat"], t["retry"], nd, tls)
        if t["cdn_tls"]:
            out += '[client.transport.tls]\nhostname = "%s"\n\n' % t["cdn_domain"]
        for s in t["services"]:
            out += '[client.services.%d]\ntype = "%s"\nlocal_addr = "0.0.0.0:%d"\n\n' % (
                s["port"], s["type"], s["port"])
    return out


def gen_toml(t):
    if t.get("mode") == "cdn":
        return gen_toml_cdn(t)
    bind_host = "[::]" if t["ipv6"] else "0.0.0.0"
    if t["role"] == "iran":
        out = (
            "[server]\n"
            'bind_addr = "%s:%d"\n'
            'default_token = "%s"\n'
            "heartbeat_interval = %d\n\n"
            "[server.transport]\n"
            'type = "tcp"\n\n'
            "[server.transport.tcp]\n"
            "nodelay = %s\n\n"
        ) % (inner_addr(t["gre_ip"], t.get("link", "gre")), t["port"], t["token"], t["heartbeat"], "true" if t["nodelay"] else "false")
        for s in t["services"]:
            out += '[server.services.%d]\ntype = "%s"\nbind_addr = "%s:%d"\n\n' % (
                s["port"], s["type"], bind_host, s["port"])
    else:
        out = (
            "[client]\n"
            'remote_addr = "%s:%d"\n'
            'default_token = "%s"\n'
            "heartbeat_timeout = %d\n"
            "retry_interval = %d\n\n"
            "[client.transport]\n"
            'type = "tcp"\n\n'
            "[client.transport.tcp]\n"
            "nodelay = %s\n\n"
        ) % (inner_addr(t["peer_ip"], t.get("link", "gre")), t["port"], t["token"], t["heartbeat"], t["retry"],
             "true" if t["nodelay"] else "false")
        for s in t["services"]:
            # Kharej side always dials the local service over IPv4 (same as the
            # original script); "[::]" here would dial ::1 and fail when the
            # service (e.g. Xray) only listens on IPv4.
            out += '[client.services.%d]\ntype = "%s"\nlocal_addr = "0.0.0.0:%d"\n\n' % (
                s["port"], s["type"], s["port"])
    return out


def gen_bh_service(name, use_gre):
    m = NAME_RE.match(name)
    role, port = m.group(1), m.group(2)
    return (
        "[Unit]\n"
        "Description=Backhaul %s Port %s%s\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        "%s"
        "ExecStart=%s -c %s\n"
        "Restart=always\n"
        "RestartSec=3\n"
        "LimitNOFILE=1048576\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    ) % ("Iran" if role == "iran" else "Kharej", port, " over GRE" if use_gre else "",
         ("ExecStartPre=/bin/bash %s\n" % p_gre(name, "backhaul")) if use_gre else "",
         BH_BIN, p_toml(name, "backhaul"))


def gen_service(name, use_gre=True):
    m = NAME_RE.match(name)
    role, port = m.group(1), m.group(2)
    desc = ("Rathole Iran Port %s (Iran) over GRE" % port) if role == "iran" \
        else ("Rathole Kharej Port %s over GRE" % port)
    if not use_gre:
        desc = desc.replace("over GRE", "over Cloudflare CDN")
        return (
            "[Unit]\n"
            "Description=%s\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            "ExecStart=%s %s\n"
            "Restart=always\n"
            "RestartSec=3\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        ) % (desc, CORE_BIN, p_toml(name, "rathole"))
    return (
        "[Unit]\n"
        "Description=%s\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStartPre=/bin/bash %s\n"
        "ExecStart=%s %s\n"
        "Restart=always\n"
        "RestartSec=3\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    ) % (desc, p_gre(name, "rathole"), CORE_BIN, p_toml(name, "rathole"))


# ---------------------------------------------------------------- crontab
def cron_get():
    rc, out = run(["crontab", "-l"])
    return out if rc == 0 else ""


def cron_set(lines):
    text = "\n".join(l for l in lines if l.strip()) + "\n"
    rc, out = run(["crontab", "-"], input_text=text)
    if rc != 0:
        raise ApiError("ثبت crontab ناموفق بود: " + out.strip())


def cron_lines():
    return [l for l in cron_get().splitlines()]


def cron_remove_tag(lines, tag_suffix):
    return [l for l in lines if not l.rstrip().endswith(tag_suffix)]


def watcher_add(name):
    tag = "# gre-rathole-%s" % name
    lines = cron_remove_tag(cron_lines(), tag)
    lines.append("*/2 * * * * /bin/bash %s >/dev/null 2>&1 %s" % (p_gre(name), tag))
    cron_set(lines)


def watcher_remove(name):
    cron_set(cron_remove_tag(cron_lines(), "# gre-rathole-%s" % name))


def restart_cron_get(name):
    tag = "#" + svc(name)
    for l in cron_lines():
        if l.rstrip().endswith(tag) and not l.lstrip().startswith("#"):
            sched = " ".join(l.split()[:5])
            for k, v in CRON_CHOICES.items():
                if v == sched:
                    return k
            return sched
    return ""


def restart_cron_set(name, choice):
    if choice not in CRON_CHOICES:
        raise ApiError("بازه زمانی نامعتبر است")
    tag = "#" + svc(name)
    lines = cron_remove_tag(cron_lines(), tag)
    if choice:
        # NOTE: the original script kills *every* rathole process here, which
        # drops all other tunnels too. We only restart this one service.
        write_file(p_reset(name),
                   "#! /bin/bash\nsystemctl daemon-reload\nsystemctl restart %s\n" % svc(name), 0o755)
        lines.append("%s %s %s" % (CRON_CHOICES[choice], p_reset(name), tag))
    else:
        try:
            os.remove(p_reset(name))
        except OSError:
            pass
    cron_set(lines)


# ---------------------------------------------------------------- system state
def list_names():
    out = []
    dirs = [(CORE_DIR, ".toml"), (BH_DIR, ".toml")] + [(g["dir"], ".meta.json") for g in GEN.values()]
    for d, suf in dirs:
        try:
            for f in os.listdir(d):
                if f.endswith(suf):
                    n = f[:-len(suf)]
                    if NAME_RE.match(n) and n not in out:
                        out.append(n)
        except OSError:
            pass
    out.sort(key=lambda n: (0 if n.startswith("iran") else 1, int(NAME_RE.match(n).group(2))))
    return out


def load_tunnel(name):
    eng = engine_of(name)
    if eng in GEN:
        return load_gen(name, eng)
    if eng == "backhaul":
        return load_bh(name)
    t = _load_rathole(name)
    t["engine"] = "rathole"
    return t


def _load_rathole(name):
    path = p_toml(name, "rathole")
    if not os.path.isfile(path):
        raise ApiError("تانل %s پیدا نشد" % name)
    m = NAME_RE.match(name)
    role, port = m.group(1), int(m.group(2))
    d = parse_toml(read_file(path))
    t = {"name": name, "role": role, "port": port, "services": [], "ipv6": False,
         "gre_ip": "", "peer_ip": "", "local_domain": "", "remote_domain": "",
         "mtu": 1476, "retry": 1}
    if role == "iran":
        base = d.get("server", {})
        t["gre_ip"] = split_hostport(base.get("bind_addr"))[0]
        t["heartbeat"] = base.get("heartbeat_interval", 30)
        tcp = d.get("server.transport.tcp", {})
        prefix = "server.services."
        key = "bind_addr"
    else:
        base = d.get("client", {})
        t["peer_ip"] = split_hostport(base.get("remote_addr"))[0]
        t["heartbeat"] = base.get("heartbeat_timeout", 40)
        t["retry"] = base.get("retry_interval", 1)
        tcp = d.get("client.transport.tcp", {})
        prefix = "client.services."
        key = "local_addr"
    t["token"] = base.get("default_token", "")
    t["nodelay"] = bool(tcp.get("nodelay", False))
    for sect, vals in d.items():
        if sect.startswith(prefix):
            addr = vals.get(key, "")
            h, p = split_hostport(addr)
            if h.startswith("["):
                t["ipv6"] = True
            try:
                sp = p or int(sect[len(prefix):])
            except ValueError:
                sp = 0
            t["services"].append({"port": sp, "type": vals.get("type", "tcp"), "name": sect[len(prefix):]})
    t["services"].sort(key=lambda s: s["port"])
    # GRE script
    g = read_file(p_gre(name))
    t["link"] = "gre"
    for k, v in re.findall(r'^(DEV|MODE|LOCAL_DOMAIN|REMOTE_DOMAIN|GRE_LOCAL_IP|MTU)="([^"]*)"', g, re.M):
        if k == "MODE" and v in LINK_TYPES:
            t["link"] = v
        elif k == "LOCAL_DOMAIN":
            t["local_domain"] = v
        elif k == "REMOTE_DOMAIN":
            t["remote_domain"] = v
        elif k == "GRE_LOCAL_IP":
            t["gre_ip"] = v
            t["gre_script_ip"] = v
        elif k == "MTU":
            try:
                t["mtu"] = int(v)
            except ValueError:
                pass
    t["has_gre_script"] = bool(g)
    t["dev"] = link_dev(name, t["link"])
    if role == "kharej":
        t["gre_ip"] = t.get("gre_script_ip", "")
        if t["link"] == "sit" and t["gre_ip"]:
            try:
                t["peer_ip"] = peer30(t["gre_ip"])
            except ApiError:
                pass
    ttype = d.get(("server" if role == "iran" else "client") + ".transport", {}).get("type", "tcp")
    t["mode"] = "cdn" if ttype == "websocket" else "gre"
    t["cdn_domain"], t["cdn_tls"], t["p12_pass"] = "", True, ""
    if t["mode"] == "cdn":
        pre = "server" if role == "iran" else "client"
        t["cdn_tls"] = bool(d.get(pre + ".transport.websocket", {}).get("tls", False))
        if role == "iran":
            mm = re.search(r"^# panel-cdn-domain: (\S+)", read_file(path), re.M)
            t["cdn_domain"] = mm.group(1) if mm else ""
            t["p12_pass"] = str(d.get("server.transport.tls", {}).get("pkcs12_password", ""))
        else:
            t["cdn_domain"] = split_hostport(base.get("remote_addr"))[0]
            t["peer_ip"] = ""
        t["gre_ip"], t["local_domain"], t["remote_domain"] = "", "", ""
        t["has_gre_script"] = True
        t["peer_calc"] = ""
        return t
    try:
        t["peer_calc"] = peer30(t["gre_ip"]) if t["gre_ip"] else ""
    except (ApiError, ValueError):
        t["peer_calc"] = ""
    return t


def sys_read(path):
    return read_file(path, "").strip()


def runtime_state(t):
    name, dev = t["name"], t["dev"]
    st = {}
    rc, out = run(["systemctl", "show", svc(name), "-p", "ActiveState,SubState,NRestarts,ActiveEnterTimestamp,UnitFileState"])
    kv = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
    st["active"] = kv.get("ActiveState", "unknown")
    st["sub"] = kv.get("SubState", "")
    st["enabled"] = kv.get("UnitFileState", "")
    st["restarts"] = kv.get("NRestarts", "")
    st["since"] = kv.get("ActiveEnterTimestamp", "")
    base = "/sys/class/net/%s" % dev
    st["gre_exists"] = os.path.isdir(base)
    st["gre_state"] = sys_read(base + "/operstate") if st["gre_exists"] else ""
    st["rx"] = int(sys_read(base + "/statistics/rx_bytes") or 0) if st["gre_exists"] else 0
    st["tx"] = int(sys_read(base + "/statistics/tx_bytes") or 0) if st["gre_exists"] else 0
    st["ep_local"] = st["ep_remote"] = ""
    if st["gre_exists"]:
        rc, out = run(["ip", "tunnel", "show", dev])
        mm = re.search(r"remote (\S+)", out)
        st["ep_remote"] = mm.group(1) if mm else ""
        mm = re.search(r"local (\S+)", out)
        st["ep_local"] = mm.group(1) if mm else ""
    st["restart_cron"] = restart_cron_get(name)
    st["watcher"] = any(l.rstrip().endswith("# gre-rathole-%s" % name) for l in cron_lines())
    return st


CPU = {"pct": 0.0, "per": []}


def _cpu_times():
    res = []
    for l in read_file("/proc/stat").splitlines():
        if l.startswith("cpu"):
            p = l.split()
            vals = [int(x) for x in p[1:]]
            idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
            res.append((p[0], sum(vals), idle))
    return res


def cpu_sampler():
    prev = _cpu_times()
    while True:
        time.sleep(2)
        cur = _cpu_times()
        out = []
        for (n1, t1, i1), (n2, t2, i2) in zip(prev, cur):
            dt = t2 - t1
            out.append(round(100.0 * (dt - (i2 - i1)) / dt, 1) if dt > 0 else 0.0)
        if out:
            CPU["pct"] = out[0]
            CPU["per"] = out[1:]
        prev = cur


def system_info():
    info = {"hostname": socket.gethostname(), "version": VERSION}
    try:
        up = float(read_file("/proc/uptime", "0").split()[0])
        info["uptime"] = int(up)
    except (ValueError, IndexError):
        info["uptime"] = 0
    info["load"] = " ".join(read_file("/proc/loadavg", "").split()[:3])
    mem = {}
    for l in read_file("/proc/meminfo").splitlines():
        p = l.split()
        if len(p) >= 2:
            mem[p[0].rstrip(":")] = int(p[1])
    total = mem.get("MemTotal", 0)
    avail = mem.get("MemAvailable", 0)
    info["mem_total"] = total * 1024
    info["mem_used"] = (total - avail) * 1024
    info["core"] = os.path.isfile(CORE_BIN)
    info["bh_core"] = os.path.isfile(BH_BIN)
    info["cores"] = {e: (bool(shutil.which("iptables")) if e == "iptables" else
                         all(os.path.isfile(gen_bin(e, b)) for b in g["bins"])) for e, g in GEN.items()}
    info["cpus"] = os.cpu_count() or 1
    info["cpu"] = CPU["pct"]
    info["cpu_per"] = CPU["per"]
    try:
        du = shutil.disk_usage("/")
        info["disk_total"], info["disk_used"] = du.total, du.used
    except OSError:
        info["disk_total"] = info["disk_used"] = 0
    return info


def listening(proto):
    rc, out = run(["ss", "-H", "-ln", "-t" if proto == "tcp" else "-u"])
    ports = set()
    if rc != 0:
        return ports
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 4:
            _, port = split_hostport(p[3])
            if port:
                ports.add(port)
    return ports


def host_networks():
    """[(dev, network)] for all IPv4 addresses on the host."""
    rc, out = run(["ip", "-o", "-4", "addr", "show"])
    res = []
    for line in out.splitlines():
        m = re.search(r"^\d+:\s+(\S+)\s+inet\s+(\S+)", line)
        if m:
            try:
                res.append((m.group(1).split("@")[0], ipaddress.ip_interface(m.group(2)).network))
            except ValueError:
                pass
    return res


# ---------------------------------------------------------------- validation of a tunnel form
def build_tunnel(p, existing=None):
    if existing:
        role, port = existing["role"], existing["port"]
    else:
        role = p.get("role")
        if role not in ("iran", "kharej"):
            raise ApiError("نوع سرور را انتخاب کنید (ایران / خارج)")
        port = v_port(p.get("port"), "پورت تانل")
    name = "%s%d" % (role, port)
    t = {"name": name, "role": role, "port": port}
    mode = p.get("mode") or "gre"
    if mode not in ("gre", "cdn"):
        raise ApiError("نوع تانل نامعتبر است")
    t["mode"] = mode
    if mode == "cdn" and not (existing and existing.get("mode") == "cdn"):
        raise ApiError("حالت CDN کلادفلر فقط با موتور Backhaul ساخته می‌شود؛ موتور را Backhaul انتخاب کنید")
    if mode == "cdn":
        dom = v_host(p.get("cdn_domain"), "دامنه CDN")
        if is_ipv4(dom):
            raise ApiError("در حالت CDN باید دامنه (نه IP) وارد کنید؛ دامنه‌ای که در کلادفلر تیک پروکسی آن روشن است")
        t["cdn_domain"] = dom
        t["cdn_tls"] = bool(p.get("cdn_tls"))
        allowed = CF_TLS_PORTS if t["cdn_tls"] else CF_HTTP_PORTS
        if port not in allowed:
            raise ApiError("کلادفلر فقط این پورت‌ها را %s پروکسی می‌کند: %s. پورت تانل باید یکی از این‌ها باشد%s"
                           % ("با TLS" if t["cdn_tls"] else "بدون TLS", "، ".join(map(str, allowed)),
                              "؛ برای تغییر پورت، تانل جدید بسازید" if existing else ""))
        t["p12_pass"] = (existing or {}).get("p12_pass") or secrets.token_hex(12)
        t["local_domain"] = t["remote_domain"] = t["gre_ip"] = t["peer_ip"] = ""
        t["mtu"] = 1476
    else:
        t["local_domain"] = v_host(p.get("local_domain"), "دامنه همین سرور")
        t["remote_domain"] = v_host(p.get("remote_domain"), "دامنه سرور مقابل")
        t["gre_ip"] = v_ipv4(p.get("gre_ip"), "IP داخلی این سرور")
        t["link"] = v_link(p)
        calc_peer = peer30(t["gre_ip"])
        if role == "kharej":
            pi = str(p.get("peer_ip") or "").strip() or calc_peer
            t["peer_ip"] = v_ipv4(pi, "IP داخلی سرور ایران")
            if t["peer_ip"] != calc_peer:
                raise ApiError("IP داخلی ایران (%s) با IP داخلی این سرور (%s) در یک شبکه /30 نیست. مقدار درست: %s"
                               % (t["peer_ip"], t["gre_ip"], calc_peer))
        else:
            t["peer_ip"] = calc_peer
        t["mtu"] = v_int(p.get("mtu"), "MTU", 576, 9000, LINK_MTU[t["link"]])
    tok = str(p.get("token") or "").strip()
    if not TOKEN_RE.match(tok):
        raise ApiError("توکن فقط می‌تواند شامل حروف انگلیسی، عدد و _ . - @ : + = باشد (حداکثر 128 کاراکتر)")
    t["token"] = tok
    t["nodelay"] = bool(p.get("nodelay"))
    t["heartbeat"] = v_int(p.get("heartbeat"), "Heartbeat", 0, 3600,
                           (30 if role == "iran" else 40) if mode == "cdn" else 0)   # default: off
    t["retry"] = v_int(p.get("retry"), "Retry interval", 1, 120, 1)
    t["ipv6"] = bool(p.get("ipv6"))
    if mode == "cdn":
        if t["heartbeat"] == 0:
            raise ApiError("در حالت CDN باید Heartbeat روشن باشد؛ کلادفلر اتصال بیکار را بعد از حدود 100 ثانیه می‌بندد (ایران 30، خارج 40)")
        if role == "iran" and t["heartbeat"] > 80:
            raise ApiError("در حالت CDN مقدار Heartbeat ایران باید کمتر از 80 ثانیه باشد")
    svcs, seen = [], set()
    for s in (p.get("services") or []):
        sp = v_port(s.get("port"), "پورت سرویس")
        ty = s.get("type", "tcp")
        if ty not in ("tcp", "udp"):
            raise ApiError("نوع پورت %d باید tcp یا udp باشد" % sp)
        if sp in seen:
            raise ApiError("پورت %d تکراری است" % sp)
        if sp == port and role == "iran":
            raise ApiError("پورت سرویس %d با پورت تانل یکی است" % sp)
        seen.add(sp)
        svcs.append({"port": sp, "type": ty})
    if not svcs:
        raise ApiError("حداقل یک پورت سرویس وارد کنید")
    t["services"] = sorted(svcs, key=lambda s: s["port"])

    # --- port in use checks (Iran side listens on them)
    if role == "iran":
        old_ports = set()
        if existing:
            old_ports = set((s["port"], s["type"]) for s in existing["services"])
        else:
            if port in listening("tcp"):
                raise ApiError("پورت تانل %d در حال استفاده است" % port)
        busy = {"tcp": listening("tcp"), "udp": listening("udp")}
        for s in t["services"]:
            if (s["port"], s["type"]) in old_ports:
                continue
            if s["port"] in busy[s["type"]]:
                raise ApiError("پورت %d/%s روی این سرور در حال استفاده است" % (s["port"], s["type"]))

    if mode == "cdn":
        return t
    # --- GRE subnet conflicts (the classic multi-tunnel bug)
    my_net = net30(t["gre_ip"])
    my_dev = link_dev(name, t.get("link", "gre"))
    for other in list_names():
        if other == name:
            continue
        try:
            o = load_tunnel(other)
        except ApiError:
            continue
        if o.get("gre_ip") and is_ipv4(o["gre_ip"]) and net30(o["gre_ip"]).overlaps(my_net):
            raise ApiError("شبکه داخلی %s با تانل %s (IP %s) تداخل دارد. برای هر تانل یک شبکه /30 جدا بدهید، مثلاً عدد سوم را عوض کنید."
                           % (my_net, other, o["gre_ip"]))
    for dev, net in host_networks():
        if dev != my_dev and net.overlaps(my_net) and net.prefixlen > 8:
            raise ApiError("شبکه داخلی %s با اینترفیس %s (%s) روی این سرور تداخل دارد" % (my_net, dev, net))
    return t


def resolve_check(t):
    a = resolve_ipv4(t["local_domain"])
    b = resolve_ipv4(t["remote_domain"])
    if not a or not b:
        raise ApiError("ریزالو دامنه ناموفق بود: %s → %s ، %s → %s" % (
            t["local_domain"], a or "FAILED", t["remote_domain"], b or "FAILED"))
    return a, b


def gre_down(dev):
    if os.path.isdir("/sys/class/net/%s" % dev) or run(["ip", "link", "show", dev])[0] == 0:
        run(["ip", "link", "set", dev, "down"])
        run(["ip", "tunnel", "del", dev])


def ensure_cert(name, domain, password, force=False):
    """Self-signed cert for the Iran side (Cloudflare SSL mode 'Full' accepts it)."""
    p12 = p_p12(name)
    meta = p12 + ".domain"
    if not force and os.path.isfile(p12) and read_file(meta).strip() == domain:
        return
    if not shutil.which("openssl"):
        raise ApiError("برای حالت CDN با TLS، برنامه openssl لازم است: apt install openssl")
    tmpd = tempfile.mkdtemp()
    try:
        key, crt = os.path.join(tmpd, "k.pem"), os.path.join(tmpd, "c.pem")
        rc, out = run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                       "-out", crt, "-days", "3650", "-subj", "/CN=%s" % domain,
                       "-addext", "subjectAltName=DNS:%s" % domain], timeout=60)
        if rc != 0:
            rc, out = run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                           "-out", crt, "-days", "3650", "-subj", "/CN=%s" % domain], timeout=60)
        if rc != 0:
            raise ApiError("ساخت گواهی ناموفق بود: " + out.strip()[-300:])
        # 3DES/SHA1 pkcs12 is readable by both OpenSSL 1.1 and 3.x
        rc, out = run(["openssl", "pkcs12", "-export", "-out", p12, "-inkey", key, "-in", crt,
                       "-passout", "env:RP12PASS", "-keypbe", "PBE-SHA1-3DES",
                       "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1"], timeout=60,
                      env={"RP12PASS": password})
        if rc != 0:
            raise ApiError("ساخت فایل pkcs12 ناموفق بود: " + out.strip()[-300:])
        os.chmod(p12, 0o600)
        write_file(meta, domain, 0o600)
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)


def core_supports_websocket():
    rc, out = run([CORE_BIN, "--version"], timeout=5)
    if "Features" not in out:
        return None  # unknown (old build without feature list)
    return "websocket" in out


def write_all(t):
    if t.get("mode") == "cdn":
        try:
            os.remove(p_gre(t["name"], "rathole"))
        except OSError:
            pass
        if t["role"] == "iran" and t["cdn_tls"]:
            ensure_cert(t["name"], t["cdn_domain"], t["p12_pass"])
        write_file(p_toml(t["name"], "rathole"), gen_toml(t), 0o600)
        write_file(p_service(t["name"], "rathole"), gen_service(t["name"], use_gre=False))
        return
    write_file(p_gre(t["name"], "rathole"), gen_gre_script(link_dev(t["name"], t["link"]), t["local_domain"],
                                                           t["remote_domain"], t["gre_ip"], t["mtu"], t["link"]), 0o755)
    write_file(p_toml(t["name"], "rathole"), gen_toml(t), 0o600)
    write_file(p_service(t["name"], "rathole"), gen_service(t["name"]))


def cdn_check_log(t):
    log = []
    ip = resolve_ipv4(t["cdn_domain"])
    if not ip:
        log.append("هشدار: دامنه %s ریزالو نشد" % t["cdn_domain"])
    elif is_cf_ip(ip):
        log.append("%s → %s (کلادفلر، تیک پروکسی روشن است ✓)" % (t["cdn_domain"], ip))
    else:
        log.append("هشدار: %s → %s که IP کلادفلر نیست؛ تیک پروکسی (ابر نارنجی) را روشن کنید" % (t["cdn_domain"], ip))
    return log


# ---------------------------------------------------------------- cross-tunnel port reservations
def _listener_ports(t):
    """Ports a tunnel occupies on THIS server (by config, even while disconnected)."""
    eng = t.get("engine", "rathole")
    out = []
    if t["role"] == "iran":
        for s_ in t.get("services", []):
            out.append((int(s_["port"]), s_.get("type", "tcp"), "سرویس"))
    listener = GEN[eng]["listener"] if eng in GEN else "iran"
    if listener == t["role"] and eng != "iptables":
        P = int(t["port"])
        if eng == "hysteria":
            out.append((P, "udp", "تانل"))
        else:
            out.append((P, "tcp", "تانل"))
            if (eng == "frp" and t.get("protocol") in ("kcp", "quic")) or \
                    (eng == "gost" and t.get("transport") in ("kcp", "quic")):
                out.append((P, "udp", "تانل"))
    return out


ENGINE_PROCS = ("rathole", "backhaul", "frps", "frpc", "gost", "hysteria", "xray")


def _resolve_cached(host, cache):
    if host not in cache:
        cache[host] = resolve_ipv4(host) if host else ""
    return cache[host]


def same_pair_link(t, o, cache):
    """True if t and o build the same kind of kernel tunnel to the same peer.
    Linux allows only one GRE / IPIP / SIT tunnel (without key) per local+remote pair."""
    if t.get("mode") != "gre" or o.get("mode") != "gre":
        return False
    if (t.get("link") or "gre") != (o.get("link") or "gre"):
        return False
    a, b = t.get("remote_domain", ""), o.get("remote_domain", "")
    if not a or not b:
        return False
    if a == b:
        return True
    ia, ib = _resolve_cached(a, cache), _resolve_cached(b, cache)
    return bool(ia) and ia == ib


def check_conflicts(t):
    """All config-level conflicts of a new/edited tunnel with everything else on this server."""
    mine = _listener_ports(t)
    panel_port = int(CONF.get("port", 0) or 0)
    for port, proto, kind in mine:
        if proto == "tcp" and port == panel_port:
            raise ApiError("پورت %d (%s) پورت خود پنل NETIFAY است؛ پورت دیگری انتخاب کنید" % (port, kind))
    taken, cache = {}, {}
    for other in list_names():
        if other == t["name"]:
            continue
        try:
            o = load_tunnel(other)
        except ApiError:
            continue
        for port, proto, kind in _listener_ports(o):
            taken[(port, proto)] = (other, kind)
        if same_pair_link(t, o, cache):
            lk = LINK_LABEL.get(t.get("link") or "gre", "GRE")
            raise ApiError("بین این سرور و %s قبلا یک لینک %s ساخته شده (تانل %s). لینوکس فقط یک لینک %s بین دو سرور مشخص اجازه می‌دهد. "
                           "یا پورت‌ها را به همان تانل اضافه کنید، یا برای این تانل نوع لینک دیگری (GRE / IPIP / 6to4) انتخاب کنید، یا حالت «مستقیم»."
                           % (t["remote_domain"], lk, other, lk))
    for port, proto, kind in mine:
        if (port, proto) in taken:
            o_name, o_kind = taken[(port, proto)]
            raise ApiError("پورت %d/%s (%s) قبلا توسط تانل %s (%s) روی این سرور رزرو شده است"
                           % (port, proto, kind, o_name, o_kind))


def _listen_procs(proto):
    """{port: set(process names)} for listening sockets."""
    rc, out = run(["ss", "-H", "-lnp", "-t" if proto == "tcp" else "-u"])
    res = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) < 4:
            continue
        _, port = split_hostport(p[3])
        if not port:
            continue
        names = set(re.findall(r'\(\("([^"]+)"', line)) or {"?"}
        res.setdefault(port, set()).update(names)
    return res


def a_audit(p):
    """Scan every tunnel on this server for anything that can collide."""
    items = []

    def add(level, msg):
        items.append({"level": level, "msg": msg})
    tunnels = []
    for n in list_names():
        try:
            tunnels.append(load_tunnel(n))
        except ApiError as e:
            add("err", "%s: کانفیگ خوانده نشد (%s)" % (n, e))
    # duplicate port reservations between tunnels
    seen = {}
    panel_port = int(CONF.get("port", 0) or 0)
    for t in tunnels:
        for port, proto, kind in _listener_ports(t):
            key = (port, proto)
            if key in seen and seen[key][0] != t["name"]:
                add("err", "پورت %d/%s هم در تانل %s (%s) و هم در تانل %s (%s) استفاده شده است"
                    % (port, proto, seen[key][0], seen[key][1], t["name"], kind))
            else:
                seen[key] = (t["name"], kind)
            if proto == "tcp" and port == panel_port:
                add("err", "پورت %d در تانل %s با پورت پنل یکی است" % (port, t["name"]))
    # foreign processes on reserved ports
    procs = {"tcp": _listen_procs("tcp"), "udp": _listen_procs("udp")}
    for (port, proto), (owner, kind) in seen.items():
        users = procs[proto].get(port, set())
        foreign = [u for u in users if u not in ENGINE_PROCS and u not in ("python3", "?")]
        if foreign:
            eng = engine_of(owner)
            if eng == "iptables":
                add("warn", "پورت %d/%s توسط iptables (تانل %s) فوروارد می‌شود ولی برنامه %s هم روی آن گوش می‌دهد؛ ترافیک ورودی به آن برنامه نمی‌رسد"
                    % (port, proto, owner, ", ".join(sorted(foreign))))
            else:
                add("err", "پورت %d/%s (%s تانل %s) توسط برنامه دیگری گرفته شده: %s"
                    % (port, proto, kind, owner, ", ".join(sorted(foreign))))
    # internal network overlaps
    nets = []
    for t in tunnels:
        if t.get("mode") == "gre" and t.get("gre_ip") and is_ipv4(t["gre_ip"]):
            nets.append((t["name"], net30(t["gre_ip"]), t.get("dev")))
    for i in range(len(nets)):
        for j in range(i + 1, len(nets)):
            if nets[i][1].overlaps(nets[j][1]):
                add("err", "شبکه داخلی %s در دو تانل %s و %s تکراری است" % (nets[i][1], nets[i][0], nets[j][0]))
    our_devs = set(link_dev(t["name"], lk) for t in tunnels for lk in LINK_TYPES)
    hnets = host_networks()
    for name, net, dev in nets:
        for hdev, hnet in hnets:
            if hdev not in our_devs and hnet.prefixlen > 8 and hnet.overlaps(net):
                add("err", "شبکه داخلی %s (تانل %s) با اینترفیس %s (%s) روی سرور تداخل دارد" % (net, name, hdev, hnet))
    # same-pair kernel links
    cache = {}
    for i in range(len(tunnels)):
        for j in range(i + 1, len(tunnels)):
            if same_pair_link(tunnels[i], tunnels[j], cache):
                add("err", "تانل‌های %s و %s هر دو لینک %s به یک سرور (%s) دارند؛ فقط یکی از آن‌ها کار می‌کند"
                    % (tunnels[i]["name"], tunnels[j]["name"], LINK_LABEL.get(tunnels[i].get("link") or "gre"),
                       tunnels[i]["remote_domain"]))
    # per-tunnel health
    for t in tunnels:
        eng = t.get("engine", "rathole")
        if eng == "rathole" and not os.path.isfile(CORE_BIN):
            add("err", "تانل %s به هسته rathole نیاز دارد که نصب نیست" % t["name"])
        elif eng == "backhaul" and not os.path.isfile(BH_BIN):
            add("err", "تانل %s به هسته Backhaul نیاز دارد که نصب نیست" % t["name"])
        elif eng in GEN and eng != "iptables" and not all(os.path.isfile(gen_bin(eng, b)) for b in GEN[eng]["bins"]):
            add("err", "تانل %s به هسته %s نیاز دارد که نصب نیست" % (t["name"], GEN[eng]["label"]))
        if t.get("mode") == "gre" and not t.get("has_gre_script", True):
            add("warn", "اسکریپت لینک تانل %s پیدا نشد؛ یک بار «ویرایش» و ذخیره کنید" % t["name"])
        if eng == "rathole" and t["role"] == "kharej" and 0 < int(t.get("heartbeat") or 0) <= 30:
            add("warn", "Heartbeat تانل %s روی %s است؛ اگر سمت ایران 30 باشد اتصال مدام قطع و وصل می‌شود (پیشنهاد: 40)"
                % (t["name"], t.get("heartbeat")))
        st = run(["systemctl", "is-active", svc(t["name"])])[1].strip()
        if st not in ("active", "activating"):
            add("warn", "سرویس تانل %s فعال نیست (%s)" % (t["name"], st or "?"))
    if not items:
        add("ok", "هیچ تداخل یا مشکلی پیدا نشد ✓ (%d تانل بررسی شد)" % len(tunnels))
    return {"items": items, "count": len(tunnels)}


# ---------------------------------------------------------------- API actions
def a_list(p):
    tunnels = []
    for n in list_names():
        try:
            t = load_tunnel(n)
            t["state"] = runtime_state(t)
        except ApiError as e:
            t = {"name": n, "error": str(e)}
        tunnels.append(t)
    return {"tunnels": tunnels, "system": system_info()}


def a_get(p):
    return load_tunnel(check_name(p.get("name")))


def check_clone(p, t):
    """A clone must point to a different peer: new domain(s) and new GRE network."""
    src_name = str(p.get("clone_of") or "")
    if not src_name:
        return
    src = load_tunnel(check_name(src_name))
    if t["mode"] == "cdn":
        if src.get("mode") == "cdn" and src.get("cdn_domain") == t["cdn_domain"]:
            raise ApiError("برای کلون باید دامنه CDN را تغییر دهید (الان همان %s است)" % t["cdn_domain"])
        return
    if t["mode"] == "direct":
        if src.get("mode") == "direct" and t.get("remote_host") and src.get("remote_host") == t["remote_host"]:
            raise ApiError("برای کلون باید آدرس سرور مقابل را تغییر دهید (الان همان %s است)" % t["remote_host"])
        return
    if src.get("mode") == "gre":
        if src.get("remote_domain") == t["remote_domain"]:
            raise ApiError("برای کلون باید دامنه سرور مقابل را تغییر دهید (الان همان %s است)" % t["remote_domain"])
        if src.get("gre_ip") and net30(src["gre_ip"]) == net30(t["gre_ip"]):
            raise ApiError("برای کلون باید IP داخلی GRE را به یک شبکه جدید تغییر دهید")


def a_create(p):
    if p.get("engine") == "backhaul":
        return a_create_bh(p)
    if p.get("engine") in GEN:
        return a_create_gen(p)
    if not os.path.isfile(CORE_BIN):
        raise ApiError("هسته rathole نصب نیست. از بخش «هسته» نصبش کنید.")
    with LOCK:
        t = build_tunnel(p)
        t["engine"] = "rathole"
        check_clone(p, t)
        check_conflicts(t)
        if os.path.exists(p_toml(t["name"], "rathole")) or os.path.exists(p_toml(t["name"], "backhaul")) \
                or os.path.exists(p_service(t["name"], "rathole")):
            raise ApiError("تانل %s از قبل وجود دارد" % t["name"])
        t["engine"] = "rathole"
        if t["mode"] == "cdn":
            if core_supports_websocket() is False:
                raise ApiError("هسته rathole فعلی از websocket پشتیبانی نمی‌کند؛ نسخه 0.5.0 یا بالاتر لازم است")
            log = cdn_check_log(t)
            write_all(t)
            run(["systemctl", "daemon-reload"])
            rc, out = run(["systemctl", "enable", "--now", svc(t["name"])])
            if rc != 0:
                log.append("خطای systemd: " + out.strip())
            return {"name": t["name"], "log": log}
        a, b = resolve_check(t)
        write_all(t)
        log = ["%s → %s" % (t["local_domain"], a), "%s → %s" % (t["remote_domain"], b)]
        rc, out = run(["/bin/bash", p_gre(t["name"])])
        log.append(LINK_LABEL[t["link"]] + ": " + ("ساخته شد" if os.path.isdir("/sys/class/net/" + link_dev(t["name"], t["link"])) else "بالا نیامد " + out.strip()))
        run(["systemctl", "daemon-reload"])
        rc, out = run(["systemctl", "enable", "--now", svc(t["name"])])
        if rc != 0:
            log.append("خطای systemd: " + out.strip())
        watcher_add(t["name"])
        return {"name": t["name"], "log": log}


def a_update(p):
    name = check_name(p.get("name"))
    with LOCK:
        old = load_tunnel(name)
        if old.get("engine") == "backhaul":
            return a_update_bh(p, old)
        if old.get("engine") in GEN:
            return a_update_gen(p, old)
        t = build_tunnel(p, existing=old)
        t["engine"] = "rathole"
        check_conflicts(t)
        if t["mode"] == "cdn":
            if old.get("mode") != "cdn" and core_supports_websocket() is False:
                raise ApiError("هسته rathole فعلی از websocket پشتیبانی نمی‌کند؛ نسخه 0.5.0 یا بالاتر لازم است")
            if old.get("cdn_domain") != t["cdn_domain"] and t["role"] == "iran" and t["cdn_tls"]:
                ensure_cert(name, t["cdn_domain"], t["p12_pass"], force=True)
            write_all(t)
            run(["systemctl", "daemon-reload"])
            watcher_remove(name)
            if old.get("mode") != "cdn":
                run(["systemctl", "stop", svc(name)])
                gre_down_all(name)
                rc, out = run(["systemctl", "start", svc(name)])
            else:
                rc, out = run(["systemctl", "restart", svc(name)])
            return {"name": name, "gre_rebuilt": False, "log": cdn_check_log(t),
                    "warning": out.strip() if rc != 0 else ""}
        gre_changed = (old.get("mode") == "cdn" or old.get("local_domain") != t["local_domain"] or
                       old.get("remote_domain") != t["remote_domain"] or
                       old.get("gre_ip") != t["gre_ip"] or old.get("link", "gre") != t["link"] or
                       int(old.get("mtu") or 1476) != t["mtu"])
        if gre_changed:
            resolve_check(t)
        write_all(t)
        run(["systemctl", "daemon-reload"])
        if gre_changed:
            run(["systemctl", "stop", svc(name)])
            gre_down_all(name)
            rc, out = run(["systemctl", "start", svc(name)])
        else:
            rc, out = run(["systemctl", "restart", svc(name)])
        watcher_add(name)
        return {"name": name, "gre_rebuilt": gre_changed,
                "warning": out.strip() if rc != 0 else ""}


def a_action(p):
    name = check_name(p.get("name"))
    op = p.get("op")
    if op not in ("start", "stop", "restart"):
        raise ApiError("عملیات نامعتبر")
    load_tunnel(name)
    with LOCK:
        rc, out = run(["systemctl", op, svc(name)], timeout=40)
    if rc != 0:
        raise ApiError(out.strip() or "خطا در systemctl")
    return {}


def a_delete(p):
    name = check_name(p.get("name"))
    with LOCK:
        if name not in list_names():
            raise ApiError("تانل %s پیدا نشد" % name)
        _remove_tunnel(name)
        run(["systemctl", "daemon-reload"])
    return {}


def a_logs(p):
    name = check_name(p.get("name"))
    n = v_int(p.get("lines"), "lines", 10, 2000, 200)
    if p.get("kind") == "gre":
        rc, out = run(["journalctl", "-t", "rathole-gre", "-n", "2000", "--no-pager", "-o", "short-iso"])
        devs = ["[%s]" % link_dev(name, lk) for lk in LINK_TYPES]
        out = "\n".join([l for l in out.splitlines() if any(d in l for d in devs)][-n:])
    else:
        rc, out = run(["journalctl", "-u", svc(name), "-n", str(n), "--no-pager", "-o", "short-iso"])
    return {"text": out or "(خالی)"}


def a_ping(p):
    t = load_tunnel(check_name(p.get("name")))
    if t.get("mode") in ("cdn", "direct"):
        raise ApiError("این تانل لینک شبکه (GRE/IPIP/6to4) ندارد؛ از «تست پورت‌ها» استفاده کنید")
    peer = t.get("peer_ip") if t["role"] == "kharej" else t.get("peer_calc")
    if not peer:
        raise ApiError("IP داخلی طرف مقابل مشخص نیست")
    if t.get("link") == "sit":
        peer = inner6(peer)
    rc, out = run(["ping", "-c", "4", "-W", "1", "-i", "0.3", peer], timeout=15)
    return {"peer": peer, "ok": rc == 0, "text": out}


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def tcp_probe(port, host="127.0.0.1", timeout=2.0):
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.settimeout(timeout)
    try:
        sk.connect((host, port))
        return "ok"
    except ConnectionRefusedError:
        return "refused"
    except socket.timeout:
        return "timeout"
    except OSError as e:
        return "error: %s" % e
    finally:
        sk.close()


def e2e_probe(port, timeout=2.5):
    """End-to-end check through the tunnel, right now: connect to the service port on this
    (Iran) server and see whether the far side keeps the connection open. If the tunnel or
    the real service abroad refuses it, the tunnel closes our connection almost at once."""
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.settimeout(2.0)
    try:
        sk.connect(("127.0.0.1", port))
    except OSError:
        sk.close()
        return "noconn"
    try:
        sk.settimeout(timeout)
        data = sk.recv(1)
        return "ok" if data else "closed"
    except socket.timeout:
        return "ok"          # still open: the far side accepted and is waiting for the client
    except OSError:
        return "closed"
    finally:
        sk.close()


def _run_parallel(fn, items):
    res, th = {}, []
    def w(x):
        res[x] = fn(x)
    for x in items:
        tt = threading.Thread(target=w, args=(x,), daemon=True)
        tt.start()
        th.append(tt)
    for tt in th:
        tt.join(10)
    return res


def a_port_test(p):
    t = load_tunnel(check_name(p.get("name")))
    ir = t["role"] == "iran"
    rc, active = run(["systemctl", "is-active", svc(t["name"])])
    active = active.strip()
    # tunnel-level: GRE ping to the peer internal IP
    peer = t.get("peer_calc") if ir else t.get("peer_ip")
    gre_ok = None
    if peer and t.get("link") == "sit":
        peer = inner6(peer)
    if peer and t.get("mode") == "gre":
        gre_ok = run(["ping", "-c", "2", "-W", "1", "-i", "0.3", peer], timeout=6)[0] == 0
    # established tunnel connections (server: inbound on tunnel port, client: outbound to it)
    eng = t.get("engine", "rathole")
    listener = GEN[eng]["listener"] if eng in GEN else "iran"
    udp_tunnel = eng == "hysteria" or (eng == "frp" and t.get("protocol") in ("kcp", "quic")) \
        or (eng == "gost" and t.get("transport") in ("kcp", "quic"))
    tunnel_conns = None
    if listener and not udp_tunnel:
        flt = ("sport = :%d" if listener == t["role"] else "dport = :%d") % t["port"]
        rc, est = run(["ss", "-H", "-tn", "state", "established", flt])
        tunnel_conns = len([l for l in est.splitlines() if l.strip()]) if rc == 0 else None
    ipt_rules = ipt_rules_text(t["name"]) if eng == "iptables" and ir else ""
    # per-service channel state: only from the log of the CURRENT run of the service (since its
    # last start), so an old error never shows after a fix + restart. Counters: last 2 minutes.
    rc, pid = run(["systemctl", "show", "-p", "MainPID", "--value", svc(t["name"])])
    pid = pid.strip() if pid.strip().isdigit() else "0"
    logs = ""
    if pid != "0":
        rc, logs = run(["journalctl", "-u", svc(t["name"]), "_PID=" + pid, "-n", "4000",
                        "--no-pager", "-o", "cat"], timeout=20)
    rc, recent = run(["journalctl", "-u", svc(t["name"]), "--since", "-2min", "-n", "4000",
                      "--no-pager", "-o", "cat"], timeout=20)
    cnt = {}
    for line in recent.splitlines():
        line = ANSI_RE.sub("", line)
        m = re.search(r"service=(\d+)", line)
        if not m:
            continue
        c = cnt.setdefault(int(m.group(1)), {"refused": 0, "eof": 0})
        if "Failed to connect to" in line and "refused" in line.lower():
            c["refused"] += 1
        if "early eof" in line:
            c["eof"] += 1
    st = {}
    for line in logs.splitlines():
        line = ANSI_RE.sub("", line)
        m = re.search(r"service=(\d+)", line)
        if not m:
            continue
        sp = int(m.group(1))
        d = st.setdefault(sp, {"ctrl": "", "refused": 0, "eof": 0})
        if "Control channel established" in line:
            d["ctrl"] = "ok"
        elif "Incorrect token" in line:
            d["ctrl"] = "token"
        elif "not exist" in line.lower() or "Service not found" in line:
            d["ctrl"] = "missing"
        elif "Failed to run the control channel" in line:
            d["ctrl"] = "error"
    for sp, c in cnt.items():
        st.setdefault(sp, {"ctrl": "", "refused": 0, "eof": 0}).update(c)
    busy = {"tcp": listening("tcp"), "udp": listening("udp")}
    e2e = {}
    if ir and eng != "iptables" and active == "active":
        e2e = _run_parallel(e2e_probe, [s_["port"] for s_ in t["services"]
                                        if s_["type"] == "tcp" and s_["port"] in busy["tcp"]])
    rows = []
    for s_ in t["services"]:
        port, typ = s_["port"], s_["type"]
        d = st.get(port, {"ctrl": "", "refused": 0, "eof": 0})
        d.setdefault("refused", 0)
        d.setdefault("eof", 0)
        row = {"port": port, "type": typ, "ctrl": d["ctrl"], "refused": d["refused"], "eof": d["eof"]}
        row["listen"] = port in busy[typ]
        if eng == "iptables" and ir:
            row["listen"] = ("--dport %d " % port) in ipt_rules + " " and ("-p %s" % typ) in ipt_rules
        row["probe"] = tcp_probe(port) if typ == "tcp" else ("ok" if row["listen"] else "closed")
        row["e2e"] = e2e.get(port, "")
        if ir and eng == "rathole" and row["listen"] and d["ctrl"] in ("", "error"):
            d["ctrl"] = "ok"          # rathole opens a service port only while its channel is up
        # verdict
        problems = []
        if active != "active":
            problems.append("سرویس تانل اجرا نیست")
        if d["ctrl"] == "token":
            problems.append("توکن با سرور مقابل یکی نیست")
        elif d["ctrl"] == "missing":
            problems.append("این پورت در کانفیگ سرور مقابل نیست")
        elif d["ctrl"] == "error":
            problems.append("اتصال تانل این پورت برقرار نمی‌شود")
        if ir:
            if not row["listen"]:
                problems.append("قانون فوروارد iptables برای این پورت وجود ندارد" if eng == "iptables"
                                else "این پورت روی سرور ایران باز نشده (تانل این پورت وصل نیست)")
            elif row["e2e"] == "closed":
                problems.append("اتصال تا سرور خارج کامل نشد: طرف مقابل اتصال را بست (سرویس اصلی روی این پورت در خارج جواب نمی‌دهد یا تانل این پورت وصل نیست)")
        else:
            if typ == "tcp" and row["probe"] != "ok":
                problems.append("روی این سرور سرویسی (مثلا Xray) روی این پورت جواب نمی‌دهد")
            elif typ == "udp" and d["refused"] >= 3:
                problems.append("اتصال به سرویس محلی %d بار رد شد" % d["refused"])
        if not problems and d["eof"] > 20:
            problems.append("قطع و وصل زیاد (%d بار early eof)" % d["eof"])
        row["ok"] = not problems
        row["problems"] = problems
        rows.append(row)
    if eng != "rathole" and tunnel_conns == 0:
        for r in rows:
            r["ok"] = False
            r["problems"].insert(0, "سرور خارج به این تانل وصل نیست" if ir else "به سرور ایران وصل نیست")
    return {"role": t["role"], "active": active, "peer": peer, "gre_ok": gre_ok, "rows": rows,
            "engine": t.get("engine", "rathole"), "tunnel_conns": tunnel_conns,
            "ok_count": sum(1 for r in rows if r["ok"]), "total": len(rows)}


def a_gre_info(p):
    t = load_tunnel(check_name(p.get("name")))
    if t.get("mode") == "direct":
        return {"text": "این تانل Backhaul در حالت اتصال مستقیم است و GRE ندارد."}
    if t.get("mode") == "cdn":
        return {"text": "این تانل در حالت CDN کلادفلر است و GRE ندارد.\nدامنه: %s\nTLS: %s"
                        % (t["cdn_domain"], "بله" if t["cdn_tls"] else "خیر")}
    dev = t["dev"]
    parts = []
    for cmd in (["ip", "tunnel", "show", dev], ["ip", "-4", "addr", "show", "dev", dev],
                ["ip", "-s", "link", "show", dev]):
        rc, out = run(cmd)
        parts.append("$ " + " ".join(cmd) + "\n" + out.strip())
    return {"text": "\n\n".join(parts)}


def a_cron(p):
    name = check_name(p.get("name"))
    load_tunnel(name)
    with LOCK:
        restart_cron_set(name, str(p.get("schedule") or ""))
    return {}


def a_raw_get(p):
    name = check_name(p.get("name"))
    eng = engine_of(name)
    return {"text": read_file(p_toml(name)), "engine": eng, "generated": eng in GEN,
            "readonly": eng == "iptables"}


def a_raw_save(p):
    name = check_name(p.get("name"))
    text = str(p.get("text") or "")
    if not os.path.isfile(p_toml(name)):
        raise ApiError("تانل پیدا نشد")
    eng = engine_of(name)
    if eng == "iptables":
        raise ApiError("ویرایش مستقیم اسکریپت iptables مجاز نیست؛ از «ویرایش» استفاده کنید")
    if eng in GEN:
        if eng == "xray":
            try:
                json.loads(text)
            except ValueError as e:
                raise ApiError("JSON نامعتبر است: %s" % e)
    else:
        need = "[server]" if name.startswith("iran") else "[client]"
        if need not in text:
            raise ApiError("فایل باید بخش %s داشته باشد" % need)
    if len(text) > 200000:
        raise ApiError("فایل خیلی بزرگ است")
    with LOCK:
        path = p_toml(name)
        old = read_file(path)
        try:
            mode = os.stat(path).st_mode & 0o700 or 0o600
        except OSError:
            mode = 0o600
        write_file(path + ".bak", old, 0o600)
        write_file(path, text, mode)
        rc, out = run(["systemctl", "restart", svc(name)], timeout=40)
    return {"warning": out.strip() if rc != 0 else ""}


def a_restart_all(p):
    res = []
    with LOCK:
        for n in list_names():
            rc, out = run(["systemctl", "restart", svc(n)], timeout=40)
            res.append("%s: %s" % (n, "OK" if rc == 0 else out.strip()))
    return {"log": res}


def a_core_info(p):
    info = {"installed": os.path.isfile(CORE_BIN), "path": CORE_BIN, "arch": os.uname().machine}
    if info["installed"]:
        info["size"] = os.path.getsize(CORE_BIN)
        info["mtime"] = int(os.path.getmtime(CORE_BIN))
        rc, out = run([CORE_BIN, "--version"], timeout=5)
        info["version"] = rathole_version(out)
    return info


def rathole_version(out):
    """`rathole --version` prints the number on a later line ("Build Version: 0.5.0")."""
    m = re.search(r"Build Version:\s*(\S+)", out or "")
    if not m:
        return (out or "").strip().splitlines()[0].strip() if (out or "").strip() else ""
    t = re.search(r"Target Triple:\s*\S+-(musl|gnu)", out)
    return "rathole %s%s" % (m.group(1), " (%s)" % t.group(1) if t else "")


def install_core_bytes(data):
    if data[:2] == b"PK":
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            raise ApiError("فایل zip خراب است")
        member = None
        for n in z.namelist():
            base = os.path.basename(n)
            if base.startswith("rathole") and not n.endswith("/") and not base.endswith(".zip"):
                member = n
                break
        if not member:
            raise ApiError("داخل zip فایلی به اسم rathole نبود")
        data = z.read(member)
    if data[:4] != b"\x7fELF":
        raise ApiError("فایل باینری لینوکس (ELF) نیست")
    os.makedirs(CORE_DIR, exist_ok=True)
    tmp = CORE_BIN + ".new"
    with open(tmp, "wb") as f:
        f.write(data)
    os.chmod(tmp, 0o755)
    rc, out = run([tmp, "--version"], timeout=5)
    if "shared libraries" in out:
        os.remove(tmp)
        raise ApiError("کتابخانه‌ای که این نسخه لازم دارد روی سرور نیست (%s). نسخه musl یا هسته اسکریپت قبلی را آپلود کنید، یا «دانلود از GitHub» را بزنید که خودش نسخه سازگار را انتخاب می‌کند."
                       % (re.findall(r"lib[\w.+-]+\.so[\d.]*", out) or ["?"])[0])
    if rc == 126 or rc == 127 or "Exec format" in out:
        os.remove(tmp)
        raise ApiError("این باینری روی این معماری اجرا نمی‌شود: " + out.strip())
    os.replace(tmp, CORE_BIN)
    return rathole_version(out)


def a_core_upload(body):
    if not body:
        raise ApiError("فایلی ارسال نشد")
    with LOCK:
        v = install_core_bytes(body)
    return {"version": v}



# ---------------------------------------------------------------- Backhaul engine
def bh_is_mux(tr):
    return tr in ("tcpmux", "wsmux", "wssmux")


def bh_is_tls(tr):
    return tr in ("wss", "wssmux")


def bh_is_ws(tr):
    return tr in ("ws", "wss", "wsmux", "wssmux")


def gen_bh_toml(t):
    ports_meta = ",".join("%d/%s" % (x["port"], x["type"]) for x in t["services"])
    head = ("# panel-engine: backhaul\n"
            "# panel-link: %s\n"
            "# panel-ports: %s\n") % (t["mode"], ports_meta)
    tr = t["transport"]
    nd = "true" if t["nodelay"] else "false"
    if t["mode"] == "cdn" and t["role"] == "iran":
        head += "# panel-cdn-domain: %s\n" % t["cdn_domain"]
    if t["role"] == "iran":
        if t["mode"] == "gre":
            bind = "%s:%d" % (inner_addr(t["gre_ip"], t["link"]), t["port"])
        else:
            bind = "%s:%d" % ("[::]" if t["ipv6"] else "0.0.0.0", t["port"])
        udp = any(x["type"] == "udp" for x in t["services"])
        out = head + (
            "[server]\n"
            'bind_addr = "%s"\n'
            'transport = "%s"\n'
            "accept_udp = %s\n"
            'token = "%s"\n'
            "keepalive_period = %d\n"
            "nodelay = %s\n"
            "heartbeat = %d\n"
            "channel_size = %d\n"
        ) % (bind, tr, "true" if udp else "false", t["token"], t["keepalive"], nd,
             t["heartbeat"], t["channel_size"])
        if bh_is_mux(tr):
            out += ("mux_con = %d\nmux_version = %d\nmux_framesize = 32768\n"
                    "mux_recievebuffer = 4194304\nmux_streambuffer = 65536\n") % (t["mux_con"], t["mux_version"])
        if bh_is_tls(tr):
            crt, key = p_bh_cert(t["name"])
            out += 'tls_cert = "%s"\ntls_key = "%s"\n' % (crt, key)
        seen, plist = set(), []
        for x in t["services"]:
            if x["port"] not in seen:
                seen.add(x["port"])
                plist.append('"%d"' % x["port"])
        out += ('sniffer = false\nweb_port = 0\nlog_level = "info"\n'
                "ports = [%s]\n") % ", ".join(plist)
        return out
    target = {"gre": inner_addr(t["peer_ip"], t.get("link", "gre")) if t["peer_ip"] else "",
              "direct": t["remote_host"], "cdn": t["cdn_domain"]}[t["mode"]]
    remote = "%s:%d" % (target, t["port"])
    out = head + (
        "[client]\n"
        'remote_addr = "%s"\n'
        'transport = "%s"\n'
        'token = "%s"\n'
        "connection_pool = %d\n"
        "aggressive_pool = %s\n"
        "keepalive_period = %d\n"
        "dial_timeout = %d\n"
        "retry_interval = %d\n"
        "nodelay = %s\n"
    ) % (remote, tr, t["token"], t["conn_pool"], "true" if t["aggressive"] else "false",
         t["keepalive"], t["dial_timeout"], t["retry"], nd)
    if bh_is_ws(tr) and t.get("edge_ip"):
        out += 'edge_ip = "%s"\n' % t["edge_ip"]
    if bh_is_mux(tr):
        out += ("mux_version = %d\nmux_framesize = 32768\n"
                "mux_recievebuffer = 4194304\nmux_streambuffer = 65536\n") % t["mux_version"]
    out += 'sniffer = false\nweb_port = 0\nlog_level = "info"\n'
    return out


def load_bh(name):
    path = p_toml(name, "backhaul")
    if not os.path.isfile(path):
        raise ApiError("تانل %s پیدا نشد" % name)
    text = read_file(path)
    m = NAME_RE.match(name)
    role, port = m.group(1), int(m.group(2))
    d = parse_toml(text)
    base = d.get("server" if role == "iran" else "client", {})
    meta = dict(re.findall(r"^# panel-([\w-]+): *(.*)$", text, re.M))
    t = {"name": name, "role": role, "port": port, "engine": "backhaul", "services": [], "ipv6": False,
         "gre_ip": "", "peer_ip": "", "local_domain": "", "remote_domain": "", "mtu": 1476,
         "remote_host": "", "edge_ip": "", "cdn_domain": "", "cdn_tls": False, "peer_calc": ""}
    t["transport"] = str(base.get("transport", "tcp"))
    t["token"] = str(base.get("token", ""))
    t["nodelay"] = bool(base.get("nodelay", False))
    t["keepalive"] = int(base.get("keepalive_period", 75) or 75)
    t["heartbeat"] = int(base.get("heartbeat", 40) or 40)
    t["channel_size"] = int(base.get("channel_size", 2048) or 2048)
    t["mux_con"] = int(base.get("mux_con", 8) or 8)
    t["mux_version"] = int(base.get("mux_version", 1) or 1)
    t["conn_pool"] = int(base.get("connection_pool", 8) or 8)
    t["aggressive"] = bool(base.get("aggressive_pool", False))
    t["dial_timeout"] = int(base.get("dial_timeout", 10) or 10)
    t["retry"] = int(base.get("retry_interval", 3) or 3)
    t["edge_ip"] = str(base.get("edge_ip", ""))
    # services: panel metadata first, otherwise derive from server ports array
    for item in [x for x in meta.get("ports", "").split(",") if x.strip()]:
        try:
            pp, ty = item.strip().split("/")
            t["services"].append({"port": int(pp), "type": ty if ty in ("tcp", "udp") else "tcp"})
        except ValueError:
            pass
    if not t["services"] and role == "iran":
        for entry in base.get("ports", []) or []:
            mm = re.match(r"^(?:[\d.]+:)?(\d+)", str(entry))
            if mm:
                t["services"].append({"port": int(mm.group(1)), "type": "tcp"})
    t["services"].sort(key=lambda x: x["port"])
    if role == "iran":
        h, _ = split_hostport(base.get("bind_addr", ""))
        t["ipv6"] = h.startswith("[")
        bind_ip = h.strip("[]")
    else:
        h, _ = split_hostport(base.get("remote_addr", ""))
    g = read_file(p_gre(name, "backhaul"))
    link = meta.get("link", "").strip()
    if link not in ("gre", "direct", "cdn"):
        link = "gre" if g else "direct"
    t["mode"] = link
    t["has_gre_script"] = True
    t["dev"] = gre_dev(name)
    t["link"] = "gre"
    if link == "gre":
        t["has_gre_script"] = bool(g)
        t["link"] = "gre"
        for k, v in re.findall(r'^(MODE|LOCAL_DOMAIN|REMOTE_DOMAIN|GRE_LOCAL_IP|MTU)="([^"]*)"', g, re.M):
            if k == "MODE" and v in LINK_TYPES:
                t["link"] = v
            elif k == "LOCAL_DOMAIN":
                t["local_domain"] = v
            elif k == "REMOTE_DOMAIN":
                t["remote_domain"] = v
            elif k == "GRE_LOCAL_IP":
                t["gre_ip"] = v
            elif k == "MTU":
                try:
                    t["mtu"] = int(v)
                except ValueError:
                    pass
        t["dev"] = link_dev(name, t["link"])
        if role == "kharej":
            t["peer_ip"] = h
            if t["link"] == "sit" and t["gre_ip"]:
                t["peer_ip"] = peer30(t["gre_ip"])
        try:
            t["peer_calc"] = peer30(t["gre_ip"]) if t["gre_ip"] else ""
        except (ApiError, ValueError):
            t["peer_calc"] = ""
    elif link == "cdn":
        t["cdn_tls"] = bh_is_tls(t["transport"])
        t["cdn_domain"] = meta.get("cdn-domain", "").strip() if role == "iran" else h
    elif role == "kharej":
        t["remote_host"] = h
    return t


def build_bh(p, existing=None):
    if existing:
        role, port = existing["role"], existing["port"]
    else:
        role = p.get("role")
        if role not in ("iran", "kharej"):
            raise ApiError("نوع سرور را انتخاب کنید (ایران / خارج)")
        port = v_port(p.get("port"), "پورت تانل")
    name = "%s%d" % (role, port)
    t = {"name": name, "role": role, "port": port, "engine": "backhaul"}
    mode = p.get("mode") or "gre"
    if mode not in ("gre", "direct", "cdn"):
        raise ApiError("در Backhaul نوع اتصال باید GRE، مستقیم یا CDN باشد")
    t["mode"] = mode
    tr = str(p.get("transport") or ("wssmux" if mode == "cdn" else "tcpmux"))
    if tr not in BH_TRANSPORTS:
        raise ApiError("ترنسپورت نامعتبر است")
    t["transport"] = tr
    t["cdn_domain"], t["cdn_tls"] = "", False
    if mode == "cdn":
        if not bh_is_ws(tr):
            raise ApiError("در حالت CDN ترنسپورت باید ws، wss، wsmux یا wssmux باشد (پیشنهادی: wssmux)")
        dom = v_host(p.get("cdn_domain"), "دامنه CDN")
        if is_ipv4(dom):
            raise ApiError("در حالت CDN باید دامنه (نه IP) وارد کنید؛ دامنه‌ای که در کلادفلر تیک پروکسی آن روشن است")
        t["cdn_domain"], t["cdn_tls"] = dom, bh_is_tls(tr)
        allowed = CF_TLS_PORTS if t["cdn_tls"] else CF_HTTP_PORTS
        if port not in allowed:
            raise ApiError("کلادفلر فقط این پورت‌ها را %s پروکسی می‌کند: %s. پورت تانل باید یکی از این‌ها باشد%s"
                           % ("با TLS (wss/wssmux)" if t["cdn_tls"] else "بدون TLS (ws/wsmux)",
                              "، ".join(map(str, allowed)),
                              "؛ برای تغییر پورت، تانل جدید بسازید (یا کلون)" if existing else ""))
    tok = str(p.get("token") or "").strip()
    if not TOKEN_RE.match(tok):
        raise ApiError("توکن فقط می‌تواند شامل حروف انگلیسی، عدد و _ . - @ : + = باشد (حداکثر 128 کاراکتر)")
    t["token"] = tok
    t["nodelay"] = bool(p.get("nodelay"))
    t["ipv6"] = bool(p.get("ipv6")) and role == "iran" and mode in ("direct", "cdn")
    t["keepalive"] = v_int(p.get("keepalive"), "Keepalive", 5, 600, 75)
    t["heartbeat"] = v_int(p.get("heartbeat"), "Heartbeat", 1, 600, 40)
    if mode == "cdn" and role == "iran" and t["heartbeat"] > 80:
        raise ApiError("در حالت CDN مقدار Heartbeat باید کمتر از 80 ثانیه باشد (کلادفلر اتصال بیکار را بعد از 100 ثانیه می‌بندد)")
    t["channel_size"] = v_int(p.get("channel_size"), "Channel size", 64, 65536, 2048)
    t["mux_con"] = v_int(p.get("mux_con"), "Mux connections", 1, 64, 8)
    t["mux_version"] = v_int(p.get("mux_version"), "Mux version", 1, 2, 1)
    t["conn_pool"] = v_int(p.get("conn_pool"), "Connection pool", 1, 128, 8)
    t["aggressive"] = bool(p.get("aggressive"))
    t["dial_timeout"] = v_int(p.get("dial_timeout"), "Dial timeout", 1, 60, 10)
    t["retry"] = v_int(p.get("retry"), "Retry interval", 1, 120, 3)
    t["edge_ip"] = ""
    t["remote_host"] = ""
    t["local_domain"] = t["remote_domain"] = t["gre_ip"] = t["peer_ip"] = ""
    t["mtu"] = 1476
    if role == "kharej" and bh_is_ws(tr) and str(p.get("edge_ip") or "").strip():
        t["edge_ip"] = v_ipv4(p.get("edge_ip"), "Edge IP")
    if mode == "gre":
        t["local_domain"] = v_host(p.get("local_domain"), "دامنه همین سرور")
        t["remote_domain"] = v_host(p.get("remote_domain"), "دامنه سرور مقابل")
        t["gre_ip"] = v_ipv4(p.get("gre_ip"), "IP داخلی این سرور")
        t["link"] = v_link(p)
        calc_peer = peer30(t["gre_ip"])
        if role == "kharej":
            pi = str(p.get("peer_ip") or "").strip() or calc_peer
            t["peer_ip"] = v_ipv4(pi, "IP داخلی سرور ایران")
            if t["peer_ip"] != calc_peer:
                raise ApiError("IP داخلی ایران (%s) با IP داخلی این سرور (%s) در یک شبکه /30 نیست. مقدار درست: %s"
                               % (t["peer_ip"], t["gre_ip"], calc_peer))
        else:
            t["peer_ip"] = calc_peer
        t["mtu"] = v_int(p.get("mtu"), "MTU", 576, 9000, LINK_MTU[t["link"]])
    elif role == "kharej" and mode == "direct":
        t["remote_host"] = v_host(p.get("remote_host"), "آدرس سرور ایران (دامنه یا IP)")
    svcs, seen = [], set()
    for x in (p.get("services") or []):
        sp = v_port(x.get("port"), "پورت سرویس")
        ty = x.get("type", "tcp")
        if ty not in ("tcp", "udp"):
            raise ApiError("نوع پورت %d باید tcp یا udp باشد" % sp)
        if (sp, ty) in seen:
            raise ApiError("پورت %d تکراری است" % sp)
        if sp == port and role == "iran":
            raise ApiError("پورت سرویس %d با پورت تانل یکی است" % sp)
        if ty == "udp" and tr != "tcp":
            raise ApiError("UDP در Backhaul فقط با ترنسپورت tcp کار می‌کند (پورت %d)" % sp)
        seen.add((sp, ty))
        svcs.append({"port": sp, "type": ty})
    if not svcs:
        raise ApiError("حداقل یک پورت سرویس وارد کنید")
    t["services"] = sorted(svcs, key=lambda x: (x["port"], x["type"]))
    if role == "iran":
        old_ports = set((x["port"], x["type"]) for x in (existing or {}).get("services", []))
        if not existing and port in listening("tcp"):
            raise ApiError("پورت تانل %d در حال استفاده است" % port)
        busy = {"tcp": listening("tcp"), "udp": listening("udp")}
        for x in t["services"]:
            if (x["port"], x["type"]) not in old_ports and x["port"] in busy[x["type"]]:
                raise ApiError("پورت %d/%s روی این سرور در حال استفاده است" % (x["port"], x["type"]))
    if mode == "gre":
        my_net = net30(t["gre_ip"])
        my_dev = link_dev(name, t.get("link", "gre"))
        for other in list_names():
            if other == name:
                continue
            try:
                o = load_tunnel(other)
            except ApiError:
                continue
            if o.get("gre_ip") and is_ipv4(o["gre_ip"]) and net30(o["gre_ip"]).overlaps(my_net):
                raise ApiError("شبکه داخلی %s با تانل %s (IP %s) تداخل دارد. برای هر تانل یک شبکه /30 جدا بدهید."
                               % (my_net, other, o["gre_ip"]))
        for dev, net in host_networks():
            if dev != my_dev and net.overlaps(my_net) and net.prefixlen > 8:
                raise ApiError("شبکه داخلی %s با اینترفیس %s (%s) روی این سرور تداخل دارد" % (my_net, dev, net))
    return t


def ensure_bh_cert(name, force=False):
    crt, key = p_bh_cert(name)
    if not force and os.path.isfile(crt) and os.path.isfile(key):
        return
    if not shutil.which("openssl"):
        raise ApiError("برای wss/wssmux برنامه openssl لازم است: apt install openssl")
    os.makedirs(BH_DIR, exist_ok=True)
    rc, out = run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                   "-days", "3650", "-subj", "/CN=%s" % name], timeout=60)
    if rc != 0:
        raise ApiError("ساخت گواهی TLS ناموفق بود: " + out.strip()[-300:])
    os.chmod(key, 0o600)


def write_bh(t):
    os.makedirs(BH_DIR, exist_ok=True)
    name = t["name"]
    if t["mode"] == "gre":
        write_file(p_gre(name, "backhaul"), gen_gre_script(link_dev(name, t["link"]), t["local_domain"],
                                                          t["remote_domain"], t["gre_ip"], t["mtu"], t["link"]), 0o755)
    else:
        try:
            os.remove(p_gre(name, "backhaul"))
        except OSError:
            pass
    if t["role"] == "iran" and bh_is_tls(t["transport"]):
        ensure_bh_cert(name)
    write_file(p_toml(name, "backhaul"), gen_bh_toml(t), 0o600)
    write_file(p_service(name, "backhaul"), gen_bh_service(name, t["mode"] == "gre"))


def a_create_bh(p):
    if not os.path.isfile(BH_BIN):
        raise ApiError("هسته Backhaul نصب نیست. از تب «هسته» آن را نصب کنید.")
    with LOCK:
        t = build_bh(p)
        check_clone(p, t)
        check_conflicts(t)
        name = t["name"]
        if os.path.exists(p_toml(name, "rathole")) or os.path.exists(p_toml(name, "backhaul")) \
                or os.path.exists(p_service(name, "backhaul")):
            raise ApiError("تانل %s از قبل وجود دارد" % name)
        log = []
        if t["mode"] == "gre":
            a, b = resolve_check(t)
            log += ["%s → %s" % (t["local_domain"], a), "%s → %s" % (t["remote_domain"], b)]
        elif t["mode"] == "cdn":
            log += cdn_check_log(t)
        elif t["role"] == "kharej":
            ip = resolve_ipv4(t["remote_host"])
            log.append("%s → %s%s" % (t["remote_host"], ip or "FAILED",
                                      " (کلادفلر)" if ip and is_cf_ip(ip) else ""))
        write_bh(t)
        if t["mode"] == "gre":
            rc, out = run(["/bin/bash", p_gre(name, "backhaul")])
            log.append(LINK_LABEL[t["link"]] + ": " + ("ساخته شد" if os.path.isdir("/sys/class/net/" + link_dev(name, t["link"])) else "بالا نیامد " + out.strip()))
        run(["systemctl", "daemon-reload"])
        rc, out = run(["systemctl", "enable", "--now", svc(name, "backhaul")])
        if rc != 0:
            log.append("خطای systemd: " + out.strip())
        if t["mode"] == "gre":
            watcher_add(name)
        return {"name": name, "log": log}


def a_update_bh(p, old):
    name = old["name"]
    t = build_bh(p, existing=old)
    check_conflicts(t)
    gre_changed = (old.get("mode") != t["mode"]) or (t["mode"] == "gre" and (
        old.get("local_domain") != t["local_domain"] or old.get("remote_domain") != t["remote_domain"] or
        old.get("gre_ip") != t["gre_ip"] or old.get("link", "gre") != t.get("link", "gre") or
        int(old.get("mtu") or 1476) != t["mtu"]))
    if t["mode"] == "gre" and gre_changed:
        resolve_check(t)
    write_bh(t)
    run(["systemctl", "daemon-reload"])
    if gre_changed:
        run(["systemctl", "stop", svc(name, "backhaul")])
        gre_down_all(name)
        rc, out = run(["systemctl", "start", svc(name, "backhaul")])
    else:
        rc, out = run(["systemctl", "restart", svc(name, "backhaul")])
    if t["mode"] == "gre":
        watcher_add(name)
    else:
        watcher_remove(name)
    return {"name": name, "gre_rebuilt": gre_changed and t["mode"] == "gre",
            "log": cdn_check_log(t) if t["mode"] == "cdn" else [],
            "warning": out.strip() if rc != 0 else ""}


# ---- Backhaul core
def bh_version():
    if not os.path.isfile(BH_BIN):
        return ""
    for flag in ("-v", "--version", "version"):
        rc, out = run([BH_BIN, flag], timeout=5)
        mm = re.search(r"v?\d+\.\d+\.\d+", out)
        if mm:
            return mm.group(0)
    return "نصب شده"


def install_bh_bytes(data):
    blob = None
    if data[:2] == b"\x1f\x8b":
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                for m in tar.getmembers():
                    if m.isfile() and os.path.basename(m.name).startswith("backhaul") \
                            and not m.name.endswith((".gz", ".zip", ".md", ".txt")):
                        blob = tar.extractfile(m).read()
                        break
        except (tarfile.TarError, OSError, EOFError):
            raise ApiError("فایل tar.gz خراب است")
        if blob is None:
            raise ApiError("داخل فایل، باینری backhaul پیدا نشد")
    elif data[:2] == b"PK":
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            raise ApiError("فایل zip خراب است")
        for n in z.namelist():
            if os.path.basename(n).startswith("backhaul") and not n.endswith("/"):
                blob = z.read(n)
                break
        if blob is None:
            raise ApiError("داخل zip باینری backhaul پیدا نشد")
    else:
        blob = data
    if blob[:4] != b"\x7fELF":
        raise ApiError("فایل باینری لینوکس (ELF) نیست")
    os.makedirs(BH_DIR, exist_ok=True)
    tmp = BH_BIN + ".new"
    with open(tmp, "wb") as f:
        f.write(blob)
    os.chmod(tmp, 0o755)
    rc, out = run([tmp, "-v"], timeout=5)
    if "Exec format" in out or "shared libraries" in out or rc == 126:
        os.remove(tmp)
        raise ApiError("این باینری روی این سرور اجرا نمی‌شود: " + out.strip()[:200])
    os.replace(tmp, BH_BIN)
    return bh_version()


def a_bh_core_info(p):
    info = {"installed": os.path.isfile(BH_BIN), "path": BH_BIN, "arch": os.uname().machine}
    if info["installed"]:
        info["size"] = os.path.getsize(BH_BIN)
        info["version"] = bh_version()
    return info


def a_bh_core_upload(body):
    if not body:
        raise ApiError("فایلی ارسال نشد")
    with LOCK:
        v = install_bh_bytes(body)
    return {"version": v}




# ---------------------------------------------------------------- generic engines (iptables, FRP, Gost, Hysteria2, Xray reverse)
# For these engines the panel's own <name>.meta.json is the source of truth; the
# engine config file is always generated from it.
import uuid as _uuid
import base64 as _b64

GEN = {
    "iptables": {"dir": os.environ.get("RP_IPT_DIR", "/root/iptables-core"), "ext": "sh", "bins": [],
                 "listener": None, "dialer": "iran", "udp": True, "label": "iptables"},
    "frp": {"dir": os.environ.get("RP_FRP_DIR", "/root/frp-core"), "ext": "toml", "bins": ["frps", "frpc"],
            "listener": "iran", "dialer": "kharej", "udp": True, "label": "FRP",
            "repo": "fatedier/frp"},
    "gost": {"dir": os.environ.get("RP_GOST_DIR", "/root/gost-core"), "ext": "yaml", "bins": ["gost"],
             "listener": "kharej", "dialer": "iran", "udp": True, "label": "Gost",
             "repo": "go-gost/gost"},
    "hysteria": {"dir": os.environ.get("RP_HY_DIR", "/root/hysteria-core"), "ext": "yaml", "bins": ["hysteria"],
                 "listener": "kharej", "dialer": "iran", "udp": True, "label": "Hysteria2",
                 "repo": "apernet/hysteria"},
    "xray": {"dir": os.environ.get("RP_XRAY_DIR", "/root/xray-core"), "ext": "json", "bins": ["xray"],
             "listener": "iran", "dialer": "kharej", "udp": False, "label": "Xray Reverse",
             "repo": "XTLS/Xray-core"},
}
FRP_PROTOCOLS = ("tcp", "kcp", "quic", "websocket")
GOST_TRANSPORTS = ("tcp", "tls", "mtls", "ws", "wss", "mwss", "grpc", "h2", "kcp", "quic")
XRAY_DOMAIN = "reverse.panel.internal"


def p_meta(name, eng):
    return os.path.join(GEN[eng]["dir"], name + ".meta.json")


def p_cfg(name, eng):
    return os.path.join(GEN[eng]["dir"], "%s.%s" % (name, GEN[eng]["ext"]))


def gen_bin(eng, which=None):
    return os.path.join(GEN[eng]["dir"], which or GEN[eng]["bins"][0])


def gen_engine_of(name):
    for eng in GEN:
        if os.path.isfile(p_meta(name, eng)):
            return eng
    return None


# ---- pure-python X25519 (RFC 7748) for Xray REALITY keys
_P = 2 ** 255 - 19
_A24 = 121665


def _x25519(k, u):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    kn = int.from_bytes(bytes(k), "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        kt = (kn >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a, b = (x2 + z2) % _P, (x2 - z2) % _P
        aa, bb = a * a % _P, b * b % _P
        e = (aa - bb) % _P
        c, d = (x3 + z3) % _P, (x3 - z3) % _P
        da, cb = d * a % _P, c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def _b64u(b):
    return _b64.urlsafe_b64encode(b).decode().rstrip("=")


def xray_keys(token):
    """Deterministic REALITY keypair / UUID / shortId from the shared token,
    so both servers derive matching values without copying keys around."""
    seed = bytearray(hashlib.sha256(("xray-reality:" + token).encode()).digest())
    seed[0] &= 248
    seed[31] &= 127
    seed[31] |= 64
    priv = bytes(seed)
    pub = _x25519(priv, (9).to_bytes(32, "little"))
    uid = str(_uuid.uuid5(_uuid.NAMESPACE_URL, "rathole-panel:" + token))
    sid = hashlib.sha256(("xray-sid:" + token).encode()).hexdigest()[:16]
    return {"private": _b64u(priv), "public": _b64u(pub), "uuid": uid, "short_id": sid}


def _yq(v):
    return json.dumps(str(v))  # JSON strings are valid YAML scalars


def gen_link_target(t):
    """Address the dialing side uses to reach the listening side."""
    if t["mode"] == "gre":
        other = t["peer_ip"] if t["role"] == "kharej" else t.get("peer_calc") or peer30(t["gre_ip"])
        return inner_addr(other, t.get("link", "gre"))
    return t["remote_host"]


def gen_bind_host(t):
    if t["mode"] == "gre":
        return inner_addr(t["gre_ip"], t.get("link", "gre"))
    return "[::]" if t.get("ipv6") else "0.0.0.0"


def _hp(host, port):
    return "%s:%d" % (host, port)


def _plain(host):
    return host[1:-1] if host.startswith("[") else host


def gen_engine_config(t):
    eng, role, P = t["engine"], t["role"], t["port"]
    tcp = [s_["port"] for s_ in t["services"] if s_["type"] == "tcp"]
    udp = [s_["port"] for s_ in t["services"] if s_["type"] == "udp"]
    if eng == "frp":
        if role == "iran":
            out = ["# generated by NETIFAY", 'bindAddr = "%s"' % _plain(gen_bind_host(t)), "bindPort = %d" % P]
            if t["protocol"] == "kcp":
                out.append("kcpBindPort = %d" % P)
            if t["protocol"] == "quic":
                out.append("quicBindPort = %d" % P)
            out += ['auth.method = "token"', 'auth.token = "%s"' % t["token"],
                    "transport.tcpMux = %s" % ("true" if t["tcp_mux"] else "false"),
                    "transport.maxPoolCount = 200", 'log.level = "info"']
            return "\n".join(out) + "\n"
        out = ["# generated by NETIFAY", 'serverAddr = "%s"' % _plain(gen_link_target(t)), "serverPort = %d" % P,
               "loginFailExit = false", 'auth.method = "token"', 'auth.token = "%s"' % t["token"],
               'transport.protocol = "%s"' % t["protocol"],
               "transport.tcpMux = %s" % ("true" if t["tcp_mux"] else "false"),
               "transport.poolCount = %d" % t["pool"], 'log.level = "info"', ""]
        for typ, ports in (("tcp", tcp), ("udp", udp)):
            for sp in ports:
                out += ["[[proxies]]", 'name = "%s-%d"' % (typ, sp), 'type = "%s"' % typ, 'localIP = "127.0.0.1"',
                        "localPort = %d" % sp, "remotePort = %d" % sp, ""]
        return "\n".join(out)
    if eng == "gost":
        if role == "kharej":
            return ("# generated by NETIFAY\nservices:\n- name: relay\n  addr: %s\n  handler:\n    type: relay\n"
                    "    auth:\n      username: panel\n      password: %s\n  listener:\n    type: %s\n") % (
                _yq(_hp(gen_bind_host(t) if t["mode"] == "gre" else "", P)), _yq(t["token"]), t["transport"])
        host = gen_link_target(t)
        out = ["# generated by NETIFAY", "services:"]
        for typ, ports in (("tcp", tcp), ("udp", udp)):
            for sp in ports:
                out += ["- name: %s-%d" % (typ, sp), "  addr: %s" % _yq(":%d" % sp), "  handler:",
                        "    type: %s" % typ, "    chain: chain-0", "  listener:", "    type: %s" % typ,
                        "  forwarder:", "    nodes:", "    - name: target-0", "      addr: %s" % _yq("127.0.0.1:%d" % sp)]
        out += ["chains:", "- name: chain-0", "  hops:", "  - name: hop-0", "    nodes:", "    - name: node-0",
                "      addr: %s" % _yq(_hp(host, P)), "      connector:", "        type: relay", "        auth:",
                "          username: panel", "          password: %s" % _yq(t["token"]), "      dialer:",
                "        type: %s" % t["transport"]]
        if t["transport"] in ("tls", "mtls", "wss", "mwss", "grpc", "h2", "quic") and not is_ipv4(_plain(host)) \
                and not _plain(host).startswith("fd00:"):
            out += ["        tls:", "          serverName: %s" % _yq(_plain(host))]
        return "\n".join(out) + "\n"
    if eng == "hysteria":
        obfs = ""
        if t.get("obfs"):
            obfs = "obfs:\n  type: salamander\n  salamander:\n    password: %s\n" % _yq(t["obfs"])
        if role == "kharej":
            crt, key = gen_cert_paths(t["name"], eng)
            return ("# generated by NETIFAY\nlisten: %s\ntls:\n  cert: %s\n  key: %s\nauth:\n  type: password\n"
                    "  password: %s\n%s") % (_yq(_hp(gen_bind_host(t) if t["mode"] == "gre" else "", P)),
                                             _yq(crt), _yq(key), _yq(t["token"]), obfs)
        host = gen_link_target(t)
        out = ["# generated by NETIFAY", "server: %s" % _yq(_hp(host, P)), "auth: %s" % _yq(t["token"]),
               "tls:", "  insecure: true"]
        if not is_ipv4(_plain(host)) and ":" not in _plain(host):
            out.append("  sni: %s" % _yq(host))
        if obfs:
            out.append(obfs.rstrip("\n"))
        if tcp:
            out.append("tcpForwarding:")
            for sp in tcp:
                out += ["  - listen: %s" % _yq("0.0.0.0:%d" % sp), "    remote: %s" % _yq("127.0.0.1:%d" % sp)]
        if udp:
            out.append("udpForwarding:")
            for sp in udp:
                out += ["  - listen: %s" % _yq("0.0.0.0:%d" % sp), "    remote: %s" % _yq("127.0.0.1:%d" % sp),
                        "    timeout: 60s"]
        return "\n".join(out) + "\n"
    if eng == "xray":
        k = xray_keys(t["token"])
        stream = {"network": "tcp", "security": "none"}
        if role == "iran":
            if t["xsec"] == "reality":
                stream = {"network": "tcp", "security": "reality", "realitySettings": {
                    "show": False, "dest": "%s:443" % t["sni"], "xver": 0, "serverNames": [t["sni"]],
                    "privateKey": k["private"], "shortIds": [k["short_id"]]}}
            inbounds = [{"tag": "ext-%d" % sp, "listen": "0.0.0.0", "port": sp, "protocol": "dokodemo-door",
                         "settings": {"address": "127.0.0.1", "port": sp, "network": "tcp"}} for sp in tcp]
            inbounds.append({"tag": "interconn", "listen": _plain(gen_bind_host(t)), "port": P, "protocol": "vless",
                             "settings": {"clients": [{"id": k["uuid"]}], "decryption": "none"},
                             "streamSettings": stream})
            cfg = {"log": {"loglevel": "warning"},
                   "reverse": {"portals": [{"tag": "portal", "domain": XRAY_DOMAIN}]},
                   "inbounds": inbounds,
                   "outbounds": [{"tag": "direct", "protocol": "freedom"}],
                   "routing": {"rules": [
                       {"type": "field", "inboundTag": ["ext-%d" % sp for sp in tcp], "outboundTag": "portal"},
                       {"type": "field", "inboundTag": ["interconn"], "outboundTag": "portal"}]}}
        else:
            if t["xsec"] == "reality":
                stream = {"network": "tcp", "security": "reality", "realitySettings": {
                    "serverName": t["sni"], "fingerprint": "chrome", "publicKey": k["public"],
                    "shortId": k["short_id"]}}
            cfg = {"log": {"loglevel": "warning"},
                   "reverse": {"bridges": [{"tag": "bridge", "domain": XRAY_DOMAIN}]},
                   "outbounds": [
                       {"tag": "direct", "protocol": "freedom", "settings": {}},
                       {"tag": "interconn", "protocol": "vless", "settings": {"vnext": [{
                           "address": _plain(gen_link_target(t)), "port": P,
                           "users": [{"id": k["uuid"], "encryption": "none"}]}]},
                        "streamSettings": stream}],
                   "routing": {"rules": [
                       {"type": "field", "inboundTag": ["bridge"], "domain": ["full:" + XRAY_DOMAIN],
                        "outboundTag": "interconn"},
                       {"type": "field", "inboundTag": ["bridge"], "outboundTag": "direct"}]}}
        return json.dumps(cfg, indent=2) + "\n"
    if eng == "iptables":
        return gen_iptables_script(t)
    raise ApiError("engine?")


def gen_iptables_script(t):
    ch = "RP_" + t["name"]
    rules = []
    for s_ in t["services"]:
        rules.append('    iptables -t nat -A "$CH" -p %s --dport %d -j DNAT --to-destination "$TARGET:%d"'
                     % (s_["type"], s_["port"], s_["port"]))
    target = gen_link_target(t) if t["role"] == "iran" else ""
    return r'''#!/bin/bash
# generated by NETIFAY - iptables port forwarding for %(name)s
CH="%(ch)s"
TARGET_HOST="%(target)s"
STATE="/run/rp-%(name)s.target"

resolve() {
    local d="$1" ip=""
    if [[ "$d" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then echo "$d"; return; fi
    ip=$(dig +short A "$d" @1.1.1.1 2>/dev/null | grep -Eo '^[0-9]+(\.[0-9]+){3}$' | head -n1)
    [ -z "$ip" ] && ip=$(dig +short A "$d" @8.8.8.8 2>/dev/null | grep -Eo '^[0-9]+(\.[0-9]+){3}$' | head -n1)
    [ -z "$ip" ] && ip=$(getent ahostsv4 "$d" 2>/dev/null | awk '{print $1; exit}')
    echo "$ip"
}

stop_rules() {
    iptables -t nat -D PREROUTING -j "$CH" 2>/dev/null
    iptables -t nat -D OUTPUT -j "$CH" 2>/dev/null
    iptables -t nat -D POSTROUTING -j "${CH}_P" 2>/dev/null
    iptables -D FORWARD -j "${CH}_F" 2>/dev/null
    for c in "$CH" "${CH}_P"; do iptables -t nat -F "$c" 2>/dev/null; iptables -t nat -X "$c" 2>/dev/null; done
    iptables -F "${CH}_F" 2>/dev/null; iptables -X "${CH}_F" 2>/dev/null
    rm -f "$STATE"
}

case "$1" in
  stop) stop_rules; exit 0 ;;
esac
[ -z "$TARGET_HOST" ] && exit 0   # kharej side: only the link is needed

TARGET=$(resolve "$TARGET_HOST")
if [ -z "$TARGET" ]; then
    logger -t netifay "[$CH] cannot resolve $TARGET_HOST; rules unchanged"
    [ "$1" = "watch" ] && exit 0
    exit 1
fi
if [ "$1" = "watch" ] && [ "$(cat "$STATE" 2>/dev/null)" = "$TARGET" ] && iptables -t nat -S "$CH" >/dev/null 2>&1; then
    exit 0
fi
sysctl -qw net.ipv4.ip_forward=1
iptables -t nat -N "$CH" 2>/dev/null; iptables -t nat -F "$CH"
iptables -t nat -N "${CH}_P" 2>/dev/null; iptables -t nat -F "${CH}_P"
iptables -N "${CH}_F" 2>/dev/null; iptables -F "${CH}_F"
iptables -t nat -C PREROUTING -j "$CH" 2>/dev/null || iptables -t nat -A PREROUTING -j "$CH"
iptables -t nat -C POSTROUTING -j "${CH}_P" 2>/dev/null || iptables -t nat -A POSTROUTING -j "${CH}_P"
iptables -C FORWARD -j "${CH}_F" 2>/dev/null || iptables -I FORWARD -j "${CH}_F"
%(rules)s
iptables -t nat -A "${CH}_P" -d "$TARGET" -j MASQUERADE
iptables -A "${CH}_F" -d "$TARGET" -j ACCEPT
iptables -A "${CH}_F" -s "$TARGET" -j ACCEPT
echo "$TARGET" > "$STATE"
logger -t netifay "[$CH] forwarding to $TARGET"
exit 0
''' % {"name": t["name"], "ch": ch, "target": target, "rules": "\n".join(rules) or "    :"}


def gen_cert_paths(name, eng):
    d = GEN[eng]["dir"]
    return os.path.join(d, "tls-%s.crt" % name), os.path.join(d, "tls-%s.key" % name)


def ensure_gen_cert(name, eng):
    crt, key = gen_cert_paths(name, eng)
    if os.path.isfile(crt) and os.path.isfile(key):
        return
    if not shutil.which("openssl"):
        raise ApiError("برای ساخت گواهی TLS برنامه openssl لازم است: apt install openssl")
    rc, out = run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                   "-keyout", key, "-out", crt, "-days", "3650", "-subj", "/CN=%s" % name], timeout=60)
    if rc != 0:
        raise ApiError("ساخت گواهی ناموفق بود: " + out.strip()[-200:])
    os.chmod(key, 0o600)


def gen_exec(t):
    eng, role = t["engine"], t["role"]
    cfg = p_cfg(t["name"], eng)
    if eng == "frp":
        return "%s -c %s" % (gen_bin(eng, "frps" if role == "iran" else "frpc"), cfg)
    if eng == "gost":
        return "%s -C %s" % (gen_bin(eng), cfg)
    if eng == "hysteria":
        return "%s %s -c %s" % (gen_bin(eng), "client" if role == "iran" else "server", cfg)
    if eng == "xray":
        return "%s run -c %s" % (gen_bin(eng), cfg)
    return None


def gen_service_unit(t):
    name, eng = t["name"], t["engine"]
    link = t["mode"] == "gre"
    pre = ("ExecStartPre=/bin/bash %s\n" % p_gre(name, eng)) if link else ""
    desc = "%s %s %s%s" % (GEN[eng]["label"], "Iran" if t["role"] == "iran" else "Kharej", name,
                           (" over " + LINK_LABEL[t.get("link", "gre")]) if link else "")
    if eng == "iptables":
        body = ("Type=oneshot\nRemainAfterExit=yes\n%sExecStart=/bin/bash %s start\nExecStop=/bin/bash %s stop\n"
                % (pre, p_cfg(name, eng), p_cfg(name, eng)))
    else:
        body = "Type=simple\n%sExecStart=%s\nRestart=always\nRestartSec=3\nLimitNOFILE=1048576\n" % (pre, gen_exec(t))
    return ("[Unit]\nDescription=%s\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\n%s\n"
            "[Install]\nWantedBy=multi-user.target\n") % (desc, body)


def build_gen(p, existing=None):
    eng = (existing or {}).get("engine") or p.get("engine")
    if eng not in GEN:
        raise ApiError("موتور نامعتبر است")
    info = GEN[eng]
    if existing:
        role, port = existing["role"], existing["port"]
    else:
        role = p.get("role")
        if role not in ("iran", "kharej"):
            raise ApiError("نوع سرور را انتخاب کنید (ایران / خارج)")
        port = v_port(p.get("port"), "پورت تانل") if eng != "iptables" else \
            v_int(p.get("port"), "شماره تانل", 10, 65535)
    name = "%s%d" % (role, port)
    t = {"name": name, "role": role, "port": port, "engine": eng, "ipv6": False}
    mode = p.get("mode") or "gre"
    if mode not in ("gre", "direct"):
        raise ApiError("برای %s نوع اتصال باید لینک (GRE/IPIP/6to4) یا مستقیم باشد" % info["label"])
    t["mode"] = mode
    if eng == "iptables":
        t["token"] = ""
        if role == "kharej" and mode == "direct":
            raise ApiError("در iptables حالت مستقیم، سمت خارج هیچ تنظیمی لازم ندارد؛ فقط سرور ایران را بسازید")
    else:
        tok = str(p.get("token") or "").strip()
        if not TOKEN_RE.match(tok):
            raise ApiError("توکن فقط می‌تواند شامل حروف انگلیسی، عدد و _ . - @ : + = باشد (حداکثر 128 کاراکتر)")
        t["token"] = tok
    t["local_domain"] = t["remote_domain"] = t["gre_ip"] = t["peer_ip"] = t["remote_host"] = ""
    t["link"], t["mtu"], t["peer_calc"] = "gre", 1476, ""
    if mode == "gre":
        t["local_domain"] = v_host(p.get("local_domain"), "دامنه همین سرور")
        t["remote_domain"] = v_host(p.get("remote_domain"), "دامنه سرور مقابل")
        t["gre_ip"] = v_ipv4(p.get("gre_ip"), "IP داخلی این سرور")
        t["link"] = v_link(p)
        if eng == "iptables" and t["link"] == "sit":
            raise ApiError("iptables روی 6to4 (IPv6) کار نمی‌کند؛ لینک GRE یا IPIP را انتخاب کنید")
        calc_peer = peer30(t["gre_ip"])
        t["peer_calc"] = calc_peer
        if role == "kharej":
            pi = str(p.get("peer_ip") or "").strip() or calc_peer
            t["peer_ip"] = v_ipv4(pi, "IP داخلی سرور ایران")
            if t["peer_ip"] != calc_peer:
                raise ApiError("IP داخلی ایران (%s) با IP داخلی این سرور (%s) در یک شبکه /30 نیست. مقدار درست: %s"
                               % (t["peer_ip"], t["gre_ip"], calc_peer))
        else:
            t["peer_ip"] = calc_peer
        t["mtu"] = v_int(p.get("mtu"), "MTU", 576, 9000, LINK_MTU[t["link"]])
    elif role == info["dialer"]:
        other = "خارج" if role == "iran" else "ایران"
        t["remote_host"] = v_host(p.get("remote_host"), "آدرس سرور %s (دامنه یا IP)" % other)
    # engine options
    t["protocol"] = str(p.get("protocol") or "tcp")
    if eng == "frp" and t["protocol"] not in FRP_PROTOCOLS:
        raise ApiError("پروتکل FRP نامعتبر است")
    t["tcp_mux"] = bool(p.get("tcp_mux", True))
    t["pool"] = v_int(p.get("pool"), "Pool count", 0, 200, 8)
    t["transport"] = str(p.get("transport") or "tls")
    if eng == "gost" and t["transport"] not in GOST_TRANSPORTS:
        raise ApiError("ترنسپورت Gost نامعتبر است")
    t["obfs"] = str(p.get("obfs") or "").strip()
    if t["obfs"] and not TOKEN_RE.match(t["obfs"]):
        raise ApiError("رمز Obfs فقط حروف انگلیسی، عدد و _ . - @ : + =")
    t["xsec"] = "reality"   # newer Xray refuses unencrypted VLESS to remote hosts
    t["sni"] = str(p.get("sni") or "www.speedtest.net").strip().lower()
    if eng == "xray" and t["xsec"] == "reality" and not DOMAIN_RE.match(t["sni"]):
        raise ApiError("SNI برای REALITY باید یک دامنه معتبر باشد (مثلا www.speedtest.net)")
    # services
    svcs, seen = [], set()
    for x in (p.get("services") or []):
        sp = v_port(x.get("port"), "پورت سرویس")
        ty = x.get("type", "tcp")
        if ty not in ("tcp", "udp"):
            raise ApiError("نوع پورت %d باید tcp یا udp باشد" % sp)
        if ty == "udp" and not info["udp"]:
            raise ApiError("%s فقط پورت‌های tcp را پشتیبانی می‌کند (پورت %d)" % (info["label"], sp))
        if (sp, ty) in seen:
            raise ApiError("پورت %d تکراری است" % sp)
        if sp == port and eng != "iptables" and role == "iran":
            raise ApiError("پورت سرویس %d با پورت تانل یکی است" % sp)
        seen.add((sp, ty))
        svcs.append({"port": sp, "type": ty})
    if not svcs:
        raise ApiError("حداقل یک پورت سرویس وارد کنید")
    t["services"] = sorted(svcs, key=lambda x: (x["port"], x["type"]))
    # busy ports
    busy = {"tcp": listening("tcp"), "udp": listening("udp")}
    old_ports = set((x["port"], x["type"]) for x in (existing or {}).get("services", []))
    if role == "iran":
        for x in t["services"]:
            if (x["port"], x["type"]) not in old_ports and x["port"] in busy[x["type"]]:
                raise ApiError("پورت %d/%s روی این سرور در حال استفاده است" % (x["port"], x["type"]))
    if not existing and info["listener"] == role and eng != "iptables":
        proto = "udp" if eng == "hysteria" or (eng == "frp" and t["protocol"] in ("kcp", "quic")) \
            or (eng == "gost" and t["transport"] in ("kcp", "quic")) else "tcp"
        if port in busy[proto]:
            raise ApiError("پورت تانل %d/%s روی این سرور در حال استفاده است" % (port, proto))
    # link conflicts
    if mode == "gre":
        my_net = net30(t["gre_ip"])
        my_dev = link_dev(name, t["link"])
        for other in list_names():
            if other == name:
                continue
            try:
                o = load_tunnel(other)
            except ApiError:
                continue
            if o.get("gre_ip") and is_ipv4(o["gre_ip"]) and net30(o["gre_ip"]).overlaps(my_net):
                raise ApiError("شبکه داخلی %s با تانل %s (IP %s) تداخل دارد. برای هر تانل یک شبکه /30 جدا بدهید."
                               % (my_net, other, o["gre_ip"]))
        for dev, net in host_networks():
            if dev != my_dev and net.overlaps(my_net) and net.prefixlen > 8:
                raise ApiError("شبکه داخلی %s با اینترفیس %s (%s) روی این سرور تداخل دارد" % (my_net, dev, net))
    return t


META_KEYS = ("engine", "role", "port", "mode", "link", "mtu", "local_domain", "remote_domain", "gre_ip", "peer_ip",
             "remote_host", "token", "services", "protocol", "tcp_mux", "pool", "transport", "obfs", "xsec", "sni")


def load_gen(name, eng=None):
    eng = eng or gen_engine_of(name)
    try:
        meta = json.loads(read_file(p_meta(name, eng)) or "{}")
    except ValueError:
        raise ApiError("فایل تنظیمات تانل %s خراب است" % name)
    m = NAME_RE.match(name)
    t = {k: meta.get(k) for k in META_KEYS}
    t.update({"name": name, "engine": eng, "role": m.group(1), "port": int(m.group(2))})
    t["services"] = t.get("services") or []
    t["link"] = t.get("link") or "gre"
    t["mode"] = t.get("mode") or "gre"
    for k in ("local_domain", "remote_domain", "gre_ip", "peer_ip", "remote_host", "token", "obfs"):
        t[k] = t.get(k) or ""
    t["cdn_domain"], t["cdn_tls"], t["ipv6"], t["nodelay"] = "", False, False, False
    t["heartbeat"] = 0
    t["dev"] = link_dev(name, t["link"])
    t["has_gre_script"] = (t["mode"] != "gre") or os.path.isfile(p_gre(name, eng))
    try:
        t["peer_calc"] = peer30(t["gre_ip"]) if t["gre_ip"] else ""
    except ApiError:
        t["peer_calc"] = ""
    if eng == "xray":
        t["xray_public"] = xray_keys(t["token"])["public"] if t["token"] else ""
    return t


def write_gen(t):
    eng, name = t["engine"], t["name"]
    os.makedirs(GEN[eng]["dir"], exist_ok=True)
    os.chmod(GEN[eng]["dir"], 0o700)
    if t["mode"] == "gre":
        write_file(p_gre(name, eng), gen_gre_script(link_dev(name, t["link"]), t["local_domain"],
                                                    t["remote_domain"], t["gre_ip"], t["mtu"], t["link"]), 0o755)
    else:
        try:
            os.remove(p_gre(name, eng))
        except OSError:
            pass
    if eng == "hysteria" and t["role"] == "kharej":
        ensure_gen_cert(name, eng)
    write_file(p_meta(name, eng), json.dumps({k: t.get(k) for k in META_KEYS}, indent=2, ensure_ascii=False), 0o600)
    write_file(p_cfg(name, eng), gen_engine_config(t), 0o700 if eng == "iptables" else 0o600)
    write_file(p_service(name, eng), gen_service_unit(t))


def ipt_watch_set(name, on):
    tag = "# rp-ipt-%s" % name
    lines = cron_remove_tag(cron_lines(), tag)
    if on:
        lines.append("*/5 * * * * /bin/bash %s watch >/dev/null 2>&1 %s" % (p_cfg(name, "iptables"), tag))
    cron_set(lines)


def a_create_gen(p):
    eng = p.get("engine")
    info = GEN.get(eng)
    if not info:
        raise ApiError("موتور نامعتبر است")
    if eng == "iptables":
        if not shutil.which("iptables"):
            raise ApiError("iptables روی این سرور نصب نیست: apt install iptables")
    elif not all(os.path.isfile(gen_bin(eng, b)) for b in info["bins"]):
        raise ApiError("هسته %s نصب نیست. از تب «هسته» آن را نصب کنید." % info["label"])
    with LOCK:
        t = build_gen(p)
        check_clone(p, t)
        check_conflicts(t)
        name = t["name"]
        if name in list_names() or os.path.exists(p_service(name, eng)):
            raise ApiError("تانل %s از قبل وجود دارد" % name)
        log = []
        if t["mode"] == "gre":
            a, b = resolve_check(t)
            log += ["%s → %s" % (t["local_domain"], a), "%s → %s" % (t["remote_domain"], b)]
        elif t["remote_host"]:
            ip = resolve_ipv4(t["remote_host"])
            log.append("%s → %s" % (t["remote_host"], ip or "FAILED"))
        write_gen(t)
        if t["mode"] == "gre":
            rc, out = run(["/bin/bash", p_gre(name, eng)])
            log.append(LINK_LABEL[t["link"]] + ": " + ("ساخته شد" if os.path.isdir("/sys/class/net/" + link_dev(name, t["link"])) else "بالا نیامد " + out.strip()))
            watcher_add(name)
        run(["systemctl", "daemon-reload"])
        rc, out = run(["systemctl", "enable", "--now", svc(name, eng)], timeout=60)
        if rc != 0:
            log.append("خطای systemd: " + out.strip())
        if eng == "iptables":
            ipt_watch_set(name, t["role"] == "iran" and t["mode"] == "direct")
        if eng == "xray" and t["role"] == "iran":
            log.append("کلید عمومی REALITY (خودکار از توکن ساخته می‌شود؛ لازم نیست کپی کنید): " + xray_keys(t["token"])["public"])
        return {"name": name, "log": log}


def a_update_gen(p, old):
    name, eng = old["name"], old["engine"]
    t = build_gen(p, existing=old)
    check_conflicts(t)
    link_changed = (old.get("mode") != t["mode"]) or (t["mode"] == "gre" and (
        old.get("local_domain") != t["local_domain"] or old.get("remote_domain") != t["remote_domain"] or
        old.get("gre_ip") != t["gre_ip"] or old.get("link") != t["link"] or int(old.get("mtu") or 0) != t["mtu"]))
    if t["mode"] == "gre" and link_changed:
        resolve_check(t)
    if eng == "iptables":
        run(["systemctl", "stop", svc(name, eng)], timeout=40)
    write_gen(t)
    run(["systemctl", "daemon-reload"])
    if link_changed:
        run(["systemctl", "stop", svc(name, eng)], timeout=40)
        gre_down_all(name)
        rc, out = run(["systemctl", "start", svc(name, eng)], timeout=60)
    else:
        rc, out = run(["systemctl", "restart", svc(name, eng)], timeout=60)
    if t["mode"] == "gre":
        watcher_add(name)
    else:
        watcher_remove(name)
    if eng == "iptables":
        ipt_watch_set(name, t["role"] == "iran" and t["mode"] == "direct")
    return {"name": name, "gre_rebuilt": link_changed and t["mode"] == "gre",
            "warning": out.strip() if rc != 0 else ""}


# ---- cores for generic engines
def gen_version(eng):
    b = gen_bin(eng)
    if not os.path.isfile(b):
        return ""
    for args in (["version"], ["-v"], ["--version"], ["-V"]):
        rc, out = run([b] + args, timeout=5)
        mm = re.search(r"v?\d+\.\d+\.\d+", out)
        if mm:
            return mm.group(0)
    return "نصب شده"


def _pick_members(names, wanted):
    found = {}
    for n in names:
        base = os.path.basename(n)
        for w in wanted:
            if base == w or (len(wanted) == 1 and base.startswith(w) and not base.endswith((".md", ".txt", ".dat", ".json", ".toml", ".yaml", ".zip", ".gz", ".ini", ".service"))):
                found.setdefault(w, n)
    return found


def install_gen_bytes(eng, data, filename=""):
    wanted = GEN[eng]["bins"]
    blobs = {}
    if data[:2] == b"\x1f\x8b":
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                mem = {m.name: m for m in tar.getmembers() if m.isfile()}
                for w, n in _pick_members(list(mem), wanted).items():
                    blobs[w] = tar.extractfile(mem[n]).read()
        except (tarfile.TarError, OSError, EOFError):
            raise ApiError("فایل tar.gz خراب است")
    elif data[:2] == b"PK":
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            raise ApiError("فایل zip خراب است")
        for w, n in _pick_members([n for n in z.namelist() if not n.endswith("/")], wanted).items():
            blobs[w] = z.read(n)
    else:
        target = None
        base = os.path.basename(filename or "")
        for w in wanted:
            if base.startswith(w):
                target = w
        if target is None and len(wanted) == 1:
            target = wanted[0]
        if target is None:
            raise ApiError("برای %s فایل tar.gz کامل (شامل %s) را آپلود کنید" % (GEN[eng]["label"], " و ".join(wanted)))
        blobs[target] = data
    if not blobs:
        raise ApiError("داخل فایل، باینری %s پیدا نشد" % " / ".join(wanted))
    os.makedirs(GEN[eng]["dir"], exist_ok=True)
    for w, blob in blobs.items():
        if blob[:4] != b"\x7fELF":
            raise ApiError("%s یک باینری لینوکس (ELF) نیست" % w)
        dst = gen_bin(eng, w)
        tmp = dst + ".new"
        with open(tmp, "wb") as f:
            f.write(blob)
        os.chmod(tmp, 0o755)
        rc, out = run([tmp, "-h"], timeout=5)
        if "Exec format" in out or "shared libraries" in out or rc == 126:
            os.remove(tmp)
            raise ApiError("%s روی این سرور اجرا نمی‌شود: %s" % (w, out.strip()[:200]))
        os.replace(tmp, dst)
    missing = [w for w in wanted if not os.path.isfile(gen_bin(eng, w))]
    return {"version": gen_version(eng), "installed": sorted(blobs), "missing": missing}


def a_cores(p):
    out = {}
    for eng, info in GEN.items():
        if eng == "iptables":
            out[eng] = {"label": info["label"], "installed": bool(shutil.which("iptables")), "system": True,
                        "version": (run(["iptables", "--version"])[1].strip().splitlines() or [""])[0]
                        if shutil.which("iptables") else ""}
            continue
        inst = [b for b in info["bins"] if os.path.isfile(gen_bin(eng, b))]
        out[eng] = {"label": info["label"], "installed": len(inst) == len(info["bins"]), "bins": info["bins"],
                    "have": inst, "version": gen_version(eng) if inst else "", "dir": info["dir"]}
    return out


def a_gen_core_upload(body, headers):
    eng = headers.get("X-Engine", "")
    if eng not in GEN or eng == "iptables":
        raise ApiError("موتور نامعتبر است")
    if not body:
        raise ApiError("فایلی ارسال نشد")
    fname = headers.get("X-Filename", "")
    try:
        from urllib.parse import unquote
        fname = unquote(fname)
    except Exception:  # noqa
        pass
    with LOCK:
        return install_gen_bytes(eng, body, fname)


def ipt_rules_text(name):
    rc, out = run(["iptables", "-t", "nat", "-S", "RP_" + name])
    return out if rc == 0 else ""

# ---------------------------------------------------------------- cores from the NETIFAY GitHub release
CORES_TAG = "cores"


def core_repo():
    r = str(CONF.get("repo") or DEFAULT_REPO).strip().strip("/")
    if not re.match(r"^[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+$", r) or r.startswith("YOUR_"):
        raise ApiError("مخزن گیت‌هاب NETIFAY تنظیم نشده است. پنل را با لینک نصب رسمی دوباره نصب کنید یا هسته را دستی آپلود کنید.")
    return r


def core_arch():
    return {"x86_64": "amd64", "aarch64": "arm64"}.get(os.uname().machine, os.uname().machine)


def core_asset(eng):
    a = core_arch()
    if eng == "rathole":
        if a == "amd64" and "libssl.so.3" not in run(["ldconfig", "-p"])[1]:
            return "rathole-musl-linux-amd64.zip"   # static build for Ubuntu 20.04 / Debian 11
        return "rathole-linux-%s.zip" % a
    return {"backhaul": "backhaul-linux-%s.tar.gz", "frp": "frp-linux-%s.tar.gz", "gost": "gost-linux-%s.tar.gz",
            "hysteria": "hysteria-linux-%s", "xray": "xray-linux-%s.zip"}[eng] % a


def fetch_core(eng):
    """Download a core from github.com/<repo>/releases/download/cores/<asset>."""
    url = "https://github.com/%s/releases/download/%s/%s" % (core_repo(), CORES_TAG, core_asset(eng))
    fd, tmp = tempfile.mkstemp()
    os.close(fd)
    try:
        rc, out = run(["curl", "-fsSL", "--retry", "2", "--connect-timeout", "15", "--max-time", "240",
                       "-o", tmp, url], timeout=260)
        if rc != 0 or os.path.getsize(tmp) < 1024:
            raise ApiError("دانلود از مخزن NETIFAY ناموفق بود (%s). اتصال سرور به github.com را چک کنید یا فایل را دستی آپلود کنید. %s"
                           % (url, out.strip()[:160]))
        with open(tmp, "rb") as f:
            return f.read(), url
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def a_core_remove(p):
    """Delete an installed core binary. Refused while any tunnel still uses that engine."""
    eng = str(p.get("engine") or "")
    if eng == "rathole":
        files = [CORE_BIN, CORE_BIN + ".new"]
    elif eng == "backhaul":
        files = [BH_BIN, BH_BIN + ".new"]
    elif eng in GEN and eng != "iptables":
        files = [gen_bin(eng, b) for b in GEN[eng]["bins"]] + [gen_bin(eng, b) + ".new" for b in GEN[eng]["bins"]]
    else:
        raise ApiError("موتور نامعتبر است")
    with LOCK:
        users = [n for n in list_names() if engine_of(n) == eng]
        if users:
            raise ApiError("این هسته را تانل‌های %s استفاده می‌کنند؛ اول آن تانل‌ها را حذف کنید" % "، ".join(users))
        removed = 0
        for f in files:
            try:
                os.remove(f)
                removed += 1
            except OSError:
                pass
    if not removed:
        raise ApiError("هسته‌ای برای حذف پیدا نشد")
    return {"removed": removed}


def a_core_download(p):
    data, url = fetch_core("rathole")
    with LOCK:
        v = install_core_bytes(data)
    return {"version": v, "url": url}


def a_bh_core_download(p):
    data, url = fetch_core("backhaul")
    with LOCK:
        v = install_bh_bytes(data)
    return {"version": v, "url": url}


def a_gen_core_download(p):
    eng = p.get("engine")
    if eng not in GEN or eng == "iptables":
        raise ApiError("موتور نامعتبر است")
    data, url = fetch_core(eng)
    with LOCK:
        r = install_gen_bytes(eng, data, url.rsplit("/", 1)[-1])
    r["url"] = url
    return r


# ---------------------------------------------------------------- backup / restore
# Backups contain ONLY tunnel configs (no core binaries): cores differ per server/arch and are
# installed from the «هسته» tab. Before restoring, every selected tunnel is checked for its core.
BK_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,100}\.tar\.gz$")
BK_MEMBER_RE = re.compile(r"^(manifest\.json|tunnels/(iran|kharej)\d{2,5}\.meta\.json|tunnels/(iran|kharej)\d{2,5}\.toml|tunnels/gre-(iran|kharej)\d{2,5}\.sh)$")
BK_MAX_MEMBERS = 5000
ENGINE_LABELS = {"rathole": "Rathole", "backhaul": "Backhaul"}


def engine_label(eng):
    return GEN[eng]["label"] if eng in GEN else ENGINE_LABELS.get(eng, str(eng))


def core_ok(eng):
    """Is everything this engine needs installed on this server?"""
    if eng == "rathole":
        return os.path.isfile(CORE_BIN)
    if eng == "backhaul":
        return os.path.isfile(BH_BIN)
    if eng == "iptables":
        return bool(shutil.which("iptables"))
    if eng in GEN:
        return all(os.path.isfile(gen_bin(eng, b)) for b in GEN[eng]["bins"])
    return False


def existing_engine(name):
    return engine_of(name) if name in list_names() else None


def make_backup():
    """Build a .tar.gz in memory with the configs of all tunnels (never core binaries)."""
    manifest = {"type": "netifay-backup", "version": VERSION, "format": 2, "created": int(time.time()),
                "hostname": socket.gethostname(), "tunnels": []}
    buf = io.BytesIO()
    now = int(time.time())
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        def add(arcname, data):
            ti = tarfile.TarInfo(arcname)
            ti.size = len(data)
            ti.mtime = now
            ti.mode = 0o600
            tar.addfile(ti, io.BytesIO(data))
        for n in list_names():
            eng = engine_of(n)
            if eng in GEN:
                meta = read_file(p_meta(n, eng))
                if not meta:
                    continue
                add("tunnels/%s.meta.json" % n, meta.encode())
            else:
                toml = read_file(p_toml(n, eng))
                if not toml:
                    continue
                add("tunnels/%s.toml" % n, toml.encode())
                g = read_file(p_gre(n, eng))
                if g:
                    add("tunnels/gre-%s.sh" % n, g.encode())
            manifest["tunnels"].append({"name": n, "engine": eng, "restart_cron": restart_cron_get(n)})
        add("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False).encode())
    return buf.getvalue(), manifest


def _bk_store(prefix, data):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    os.chmod(BACKUP_DIR, 0o700)
    base = "%s-%s-%s" % (prefix, re.sub(r"[^A-Za-z0-9_-]", "", socket.gethostname())[:30] or "server",
                         time.strftime("%Y%m%d-%H%M%S"))
    fn, i = base + ".tar.gz", 1
    while os.path.exists(os.path.join(BACKUP_DIR, fn)):
        i += 1
        fn = "%s_%d.tar.gz" % (base, i)
    path = os.path.join(BACKUP_DIR, fn)
    tmp = path + ".part"
    with open(tmp, "wb") as f:
        f.write(data)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return fn


def save_backup(prefix):
    data, man = make_backup()
    return _bk_store(prefix, data), man


def bk_path(name):
    name = str(name or "")
    if not BK_NAME_RE.match(name) or name.startswith("."):
        raise ApiError("نام فایل بکاپ نامعتبر است")
    path = os.path.join(BACKUP_DIR, name)
    if not os.path.isfile(path):
        raise ApiError("بکاپ پیدا نشد")
    return path


def read_backup(data):
    try:
        tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except (tarfile.TarError, OSError, EOFError, ValueError):
        raise ApiError("فایل بکاپ خراب است یا tar.gz نیست")
    files, has_core = {}, False
    try:
        with tar:
            count = 0
            for m in tar:
                count += 1
                if count > BK_MAX_MEMBERS:
                    raise ApiError("فایل بکاپ بیش از حد بزرگ/عجیب است")
                if m.name.startswith("core/"):
                    has_core = True
                if not m.isfile() or not BK_MEMBER_RE.match(m.name) or m.size > 2 * 1024 * 1024:
                    continue  # cores, links, paths outside the layout... are ignored
                files[m.name] = tar.extractfile(m).read()
    except (tarfile.TarError, OSError, EOFError, zlib.error):
        raise ApiError("فایل بکاپ ناقص یا خراب است")
    if "manifest.json" not in files:
        raise ApiError("این فایل، بکاپ پنل NETIFAY نیست (manifest پیدا نشد)")
    try:
        man = json.loads(files["manifest.json"].decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ApiError("manifest بکاپ خراب است")
    if not isinstance(man, dict) or man.get("type") not in ("netifay-backup", "rathole-panel-backup"):
        raise ApiError("این فایل، بکاپ پنل NETIFAY نیست")
    items, seen = [], set()
    for it in man.get("tunnels") or []:
        if not isinstance(it, dict):
            continue
        name = str(it.get("name", ""))
        if not NAME_RE.match(name) or name in seen:
            continue
        seen.add(name)
        eng = it.get("engine") or "rathole"            # very old backups had only rathole
        if eng not in ("rathole", "backhaul") and eng not in GEN:
            eng = "?"
        items.append({"name": name, "engine": eng, "restart_cron": str(it.get("restart_cron") or "")})
    man["tunnels"] = items
    man["_has_core"] = has_core
    return man, files


def bk_has_files(item, files):
    if item["engine"] in GEN:
        return "tunnels/%s.meta.json" % item["name"] in files
    return "tunnels/%s.toml" % item["name"] in files


def plan_restore(man, files):
    """Per-tunnel preview: what will happen if it is restored on THIS server."""
    out = []
    for it in man["tunnels"]:
        name, eng = it["name"], it["engine"]
        r = {"name": name, "engine": eng, "label": engine_label(eng), "core": False,
             "exists": None, "status": "ok", "msg": ""}
        ex = existing_engine(name)
        if ex:
            r["exists"] = ex
        if eng == "?":
            r.update(status="bad", msg="موتور این تانل برای این نسخه پنل ناشناخته است")
        elif not bk_has_files(it, files):
            r.update(status="bad", msg="فایل تنظیمات این تانل داخل بکاپ نیست")
        elif ex and ex != eng:
            r.update(status="taken", msg="تانل %s با موتور %s روی این سرور هست؛ برای بازیابی، اول آن را حذف کنید"
                     % (name, engine_label(ex)))
        else:
            r["core"] = core_ok(eng)
            if not r["core"]:
                r.update(status="nocore", msg="هسته %s روی این سرور نصب نیست" % engine_label(eng))
            elif ex:
                r.update(status="replace", msg="تانل فعلی با همین نام جایگزین می‌شود")
        out.append(r)
    return out


def _remove_tunnel(name):
    """Remove every trace of a tunnel (caller holds LOCK)."""
    eng = engine_of(name)
    unit = svc(name, eng)
    files = [p_toml(name, eng), p_toml(name, eng) + ".bak", p_service(name, eng), p_gre(name, eng),
             p_reset(name, eng), p_p12(name), p_p12(name) + ".domain"]
    if eng == "backhaul":
        files += list(p_bh_cert(name))
    if eng in GEN:
        files += [p_meta(name, eng)] + list(gen_cert_paths(name, eng))
    run(["systemctl", "disable", "--now", unit], timeout=40)
    if eng == "iptables":
        run(["/bin/bash", p_cfg(name, eng), "stop"])
        ipt_watch_set(name, False)
    for f in files:
        try:
            os.remove(f)
        except OSError:
            pass
    lines = cron_remove_tag(cron_lines(), "#" + unit)
    lines = cron_remove_tag(lines, "# gre-rathole-%s" % name)
    cron_set(lines)
    gre_down_all(name)


def restore_one(name, eng, item, files):
    """Write one tunnel from backup files. Raises ApiError on any problem."""
    if eng in GEN:
        meta = files.get("tunnels/%s.meta.json" % name)
        if not meta:
            raise ApiError("فایل تنظیمات در بکاپ نبود")
        try:
            meta = json.loads(meta.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ApiError("فایل تنظیمات خراب است")
        if not isinstance(meta, dict):
            raise ApiError("فایل تنظیمات خراب است")
        return restore_gen(name, item, meta)
    toml = files.get("tunnels/%s.toml" % name)
    gre = files.get("tunnels/gre-%s.sh" % name)
    if not toml:
        raise ApiError("فایل کانفیگ در بکاپ نبود")
    toml = toml.decode("utf-8", "replace")
    if eng == "backhaul":
        return restore_bh(name, toml, gre, item)
    return restore_rathole(name, toml, gre, item)


def restore_rathole(name, toml, gre, item):
    need = "[server]" if name.startswith("iran") else "[client]"
    if need not in toml:
        raise ApiError("کانفیگ rathole نامعتبر است")
    if 'type = "websocket"' in toml:
        raise ApiError("تانل CDN قدیمی روی rathole است؛ CDN حالا فقط روی Backhaul است. آن را با Backhaul (حالت CDN) دوباره بسازید")
    g = dict(re.findall(r'^(MODE|LOCAL_DOMAIN|REMOTE_DOMAIN|GRE_LOCAL_IP|MTU)="([^"]*)"',
                        (gre or b"").decode("utf-8", "replace"), re.M))
    lk = g.get("MODE") if g.get("MODE") in LINK_TYPES else "gre"
    ld = v_host(g.get("LOCAL_DOMAIN"), "دامنه این سرور")
    rd = v_host(g.get("REMOTE_DOMAIN"), "دامنه سرور مقابل")
    gip = v_ipv4(g.get("GRE_LOCAL_IP"), "IP داخلی")
    mtu = v_int(g.get("MTU"), "MTU", 576, 9000, 1476)
    if os.path.exists(p_service(name, "rathole")):
        run(["systemctl", "stop", svc(name, "rathole")], timeout=40)
    gre_down_all(name)
    os.makedirs(CORE_DIR, exist_ok=True)
    write_file(p_toml(name, "rathole"), toml, 0o600)
    # the link script is re-generated from its values (never executed as-is from a backup)
    write_file(p_gre(name, "rathole"), gen_gre_script(link_dev(name, lk), ld, rd, gip, mtu, lk), 0o755)
    write_file(p_service(name, "rathole"), gen_service(name))
    watcher_add(name)
    rc_choice = item.get("restart_cron") or ""
    restart_cron_set(name, rc_choice if rc_choice in CRON_CHOICES else "")
    return name


def restore_backup(data, opts):
    man, files = read_backup(data)
    only = opts.get("only")
    only = set(str(x) for x in only) if isinstance(only, list) else None
    plan = {r["name"]: r for r in plan_restore(man, files)}
    chosen = [it for it in man["tunnels"] if only is None or it["name"] in only]
    if not chosen:
        raise ApiError("هیچ تانلی برای بازیابی انتخاب نشده است")
    # 1) refuse up-front if any selected tunnel cannot be restored — nothing is changed on the server
    nocore = {}
    problems = []
    for it in chosen:
        r = plan[it["name"]]
        if r["status"] == "nocore":
            nocore.setdefault(r["label"], []).append(it["name"])
        elif r["status"] in ("bad", "taken"):
            problems.append("%s: %s" % (it["name"], r["msg"]))
    if nocore:
        raise ApiError("هسته لازم روی این سرور نصب نیست — " +
                       "؛ ".join("%s (برای %s)" % (k, "، ".join(v)) for k, v in nocore.items()) +
                       ". اول از تب «هسته» نصبش کنید، یا این تانل‌ها را از انتخاب بردارید. هیچ تغییری اعمال نشد.")
    if problems:
        raise ApiError("این تانل‌ها قابل بازیابی نیستند (هیچ تغییری اعمال نشد): " + " | ".join(problems) +
                       ". آن‌ها را از انتخاب بردارید.")
    log, restored, failed = [], [], []
    with LOCK:
        snap_data, _ = make_backup()
        snap = _bk_store("auto-before-restore", snap_data)
        log.append("بکاپ خودکار از وضعیت فعلی: " + snap)
        snap_man, snap_files = read_backup(snap_data)
        snap_items = {it["name"]: it for it in snap_man["tunnels"]}
        for it in chosen:
            name, eng = it["name"], it["engine"]
            existed = name in snap_items
            try:
                restore_one(name, eng, it, files)
                check_conflicts(load_tunnel(name))
                restored.append(name)
            except Exception as e:  # noqa — any failure: undo this tunnel, keep going
                msg = str(e) if isinstance(e, ApiError) else "خطای داخلی: %s" % e
                try:
                    if name in list_names():
                        _remove_tunnel(name)
                    if existed:
                        old = snap_items[name]
                        restore_one(name, old["engine"], old, snap_files)
                        restored.append(name)
                        msg += " — نسخه قبلی همین تانل برگردانده شد"
                except Exception as e2:  # noqa
                    msg += " — برگرداندن نسخه قبلی هم ناموفق بود (%s)؛ از بکاپ خودکار استفاده کنید" % e2
                failed.append(name)
                log.append("%s: بازیابی نشد، %s" % (name, msg))
        run(["systemctl", "daemon-reload"])
        for name in restored:
            rc, out = run(["systemctl", "enable", "--now", svc(name)], timeout=60)
            if name not in failed:
                log.append("%s (%s): %s" % (name, engine_label(engine_of(name)),
                                           "بازیابی و اجرا شد" if rc == 0 else "بازیابی شد ولی اجرا نشد: " + out.strip()[:300]))
    if not [n for n in restored if n not in failed]:
        log.append("هیچ تانلی بازیابی نشد")
    return {"log": log, "restored": [n for n in restored if n not in failed], "failed": failed, "snapshot": snap}


def restore_bh(name, toml, gre, item):
    need = "[server]" if name.startswith("iran") else "[client]"
    if need not in toml:
        raise ApiError("کانفیگ Backhaul نامعتبر")
    link = "gre" if gre else "direct"
    g = {}
    mm = re.search(r"^# panel-link: *(\w+)", toml, re.M)
    if mm and mm.group(1) in ("direct", "cdn") and not gre:
        link = mm.group(1)
    if gre:
        g = dict(re.findall(r'^(MODE|LOCAL_DOMAIN|REMOTE_DOMAIN|GRE_LOCAL_IP|MTU)="([^"]*)"',
                            gre.decode("utf-8", "replace"), re.M))
        lk = g.get("MODE") if g.get("MODE") in LINK_TYPES else "gre"
        ld = v_host(g.get("LOCAL_DOMAIN"), "دامنه این سرور")
        rd = v_host(g.get("REMOTE_DOMAIN"), "دامنه سرور مقابل")
        gip = v_ipv4(g.get("GRE_LOCAL_IP"), "IP داخلی")
        mtu = v_int(g.get("MTU"), "MTU", 576, 9000, 1476)
    # never trust paths from a backup: rewrite cert paths to this server's location
    crt, key = p_bh_cert(name)
    toml = re.sub(r'^tls_cert = "[^"]*"', 'tls_cert = "%s"' % crt, toml, flags=re.M)
    toml = re.sub(r'^tls_key = "[^"]*"', 'tls_key = "%s"' % key, toml, flags=re.M)
    if os.path.exists(p_service(name, "backhaul")):
        run(["systemctl", "stop", svc(name, "backhaul")], timeout=40)
    gre_down_all(name)
    os.makedirs(BH_DIR, exist_ok=True)
    write_file(p_toml(name, "backhaul"), toml, 0o600)
    if "tls_cert" in toml:
        ensure_bh_cert(name)
    if link == "gre":
        write_file(p_gre(name, "backhaul"), gen_gre_script(link_dev(name, lk), ld, rd, gip, mtu, lk), 0o755)
        watcher_add(name)
    else:
        try:
            os.remove(p_gre(name, "backhaul"))
        except OSError:
            pass
        watcher_remove(name)
    write_file(p_service(name, "backhaul"), gen_bh_service(name, link == "gre"))
    rc_choice = str(item.get("restart_cron") or "")
    restart_cron_set(name, rc_choice if rc_choice in CRON_CHOICES else "")
    return name


def restore_gen(name, item, meta):
    eng = item.get("engine")
    m = NAME_RE.match(name)
    p = dict(meta)
    p.update({"engine": eng, "role": m.group(1), "port": int(m.group(2))})
    existing = None
    if engine_of(name) == eng:
        existing = load_gen(name, eng)
    elif name in list_names():
        raise ApiError("تانل دیگری با همین نام روی این سرور هست")
    t = build_gen(p, existing=existing)
    if os.path.exists(p_service(name, eng)):
        run(["systemctl", "stop", svc(name, eng)], timeout=40)
    gre_down_all(name)
    write_gen(t)
    if t["mode"] == "gre":
        watcher_add(name)
    else:
        watcher_remove(name)
    if eng == "iptables":
        ipt_watch_set(name, t["role"] == "iran" and t["mode"] == "direct")
    rc_choice = str(item.get("restart_cron") or "")
    restart_cron_set(name, rc_choice if rc_choice in CRON_CHOICES else "")
    return name


def a_backup_list(p):
    items = []
    try:
        for f in sorted(os.listdir(BACKUP_DIR), key=lambda f: os.path.getmtime(os.path.join(BACKUP_DIR, f)), reverse=True):
            if BK_NAME_RE.match(f) and not f.startswith("."):
                path = os.path.join(BACKUP_DIR, f)
                items.append({"name": f, "size": os.path.getsize(path), "mtime": int(os.path.getmtime(path))})
    except OSError:
        pass
    return {"items": items, "dir": BACKUP_DIR}


def a_backup_create(p):
    with LOCK:
        if not list_names():
            raise ApiError("هنوز تانلی روی این سرور نیست که بکاپ گرفته شود")
        fn, man = save_backup("backup")
    return {"name": fn, "tunnels": len(man["tunnels"])}


def _bk_info(data):
    man, files = read_backup(data)
    return {"manifest": {k: man.get(k) for k in ("version", "created", "hostname")},
            "tunnels": plan_restore(man, files),
            "has_core": bool(man.get("_has_core"))}


def a_backup_info(p):
    with open(bk_path(p.get("name")), "rb") as f:
        return _bk_info(f.read())


def a_backup_restore_saved(p):
    with open(bk_path(p.get("name")), "rb") as f:
        data = f.read()
    return restore_backup(data, p)


def a_backup_delete(p):
    os.remove(bk_path(p.get("name")))
    return {}


def a_backup_upload(body, headers):
    if not body:
        raise ApiError("فایلی ارسال نشد")
    info = _bk_info(body)             # validate before storing
    if not info["tunnels"]:
        raise ApiError("این بکاپ هیچ تانلی ندارد")
    with LOCK:
        fn = _bk_store("uploaded", body)
    info["name"] = fn
    return info


SYSCTL_FILE = "/etc/sysctl.d/99-netifay.conf"
SYSCTL_SETTINGS = [
    ("net.core.default_qdisc", "fq"),
    ("net.ipv4.tcp_congestion_control", "bbr"),
    ("net.ipv4.ip_forward", "1"),
    ("net.core.somaxconn", "65535"),
    ("net.core.netdev_max_backlog", "16384"),
    ("net.core.rmem_max", "33554432"),
    ("net.core.wmem_max", "33554432"),
    ("net.ipv4.tcp_rmem", "4096 87380 33554432"),
    ("net.ipv4.tcp_wmem", "4096 65536 33554432"),
    ("net.ipv4.udp_rmem_min", "16384"),
    ("net.ipv4.udp_wmem_min", "16384"),
    ("net.ipv4.tcp_fastopen", "3"),
    ("net.ipv4.tcp_mtu_probing", "1"),
    ("net.ipv4.tcp_slow_start_after_idle", "0"),
    ("net.ipv4.tcp_fin_timeout", "15"),
    ("net.ipv4.tcp_keepalive_time", "300"),
    ("net.ipv4.tcp_max_syn_backlog", "16384"),
    ("net.ipv4.ip_local_port_range", "10240 65535"),
    ("net.netfilter.nf_conntrack_max", "1048576"),
    ("fs.file-max", "2097152"),
]


def a_optimize_get(p):
    applied = os.path.isfile(SYSCTL_FILE)
    cc = sys_read("/proc/sys/net/ipv4/tcp_congestion_control")
    avail = sys_read("/proc/sys/net/ipv4/tcp_available_congestion_control")
    return {"applied": applied, "congestion": cc, "bbr_available": "bbr" in avail or applied,
            "qdisc": sys_read("/proc/sys/net/core/default_qdisc"), "file": SYSCTL_FILE}


def a_optimize(p):
    if p.get("off"):
        try:
            os.remove(SYSCTL_FILE)
        except OSError:
            pass
        run(["sysctl", "--system"], timeout=30)
        return {"log": ["فایل بهینه‌سازی حذف شد. مقادیر پیش‌فرض بعد از ری‌استارت سرور کامل برمی‌گردند."]}
    run(["modprobe", "tcp_bbr"])
    run(["modprobe", "nf_conntrack"])
    text = "# NETIFAY network optimisation\n" + "".join("%s = %s\n" % kv for kv in SYSCTL_SETTINGS)
    write_file(SYSCTL_FILE, text)
    rc, out = run(["sysctl", "-p", SYSCTL_FILE], timeout=30)
    bad = [l for l in out.splitlines() if "cannot" in l.lower() or "invalid" in l.lower() or "unknown" in l.lower()]
    log = ["%d تنظیم اعمال شد" % (len(SYSCTL_SETTINGS) - len(bad))] + ["رد شد: " + l for l in bad]
    lim = "/etc/security/limits.d/99-netifay.conf"
    write_file(lim, "* soft nofile 1048576\n* hard nofile 1048576\nroot soft nofile 1048576\nroot hard nofile 1048576\n")
    log.append("الگوریتم فعلی: " + sys_read("/proc/sys/net/ipv4/tcp_congestion_control"))
    return {"log": log}


# ---------------------------------------------------------------- panel config / auth
CONF = {}
SESSIONS = {}
FAILS = {}
SESSION_TTL = 12 * 3600        # absolute lifetime
SESSION_IDLE = 2 * 3600        # logged out after 2h without activity
FAIL_WINDOW = 600
FAIL_PER_IP = 5
FAIL_GLOBAL = 40               # across all IPs inside FAIL_WINDOW
GLOBAL_FAILS = []
AUTH_LOCK = threading.Lock()
TLS_DIR = os.path.dirname(PANEL_CONF) or "/etc/netifay"


def make_panel_cert():
    """Self-signed certificate for the panel's own HTTPS."""
    if not shutil.which("openssl"):
        raise ApiError("برای HTTPS برنامه openssl لازم است: apt install openssl")
    os.makedirs(TLS_DIR, exist_ok=True)
    os.chmod(TLS_DIR, 0o700)
    crt, key = os.path.join(TLS_DIR, "panel.crt"), os.path.join(TLS_DIR, "panel.key")
    rc, out = run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                   "-nodes", "-keyout", key, "-out", crt, "-days", "3650", "-subj", "/CN=netifay"], timeout=60)
    if rc != 0:
        rc, out = run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                       "-out", crt, "-days", "3650", "-subj", "/CN=netifay"], timeout=60)
    if rc != 0:
        raise ApiError("ساخت گواهی HTTPS ناموفق بود: " + out.strip()[-300:])
    os.chmod(key, 0o600)
    os.chmod(crt, 0o600)
    return crt, key


def set_https(on):
    if on:
        crt, key = make_panel_cert()
        CONF["cert"], CONF["key"] = crt, key
    else:
        CONF.pop("cert", None)
        CONF.pop("key", None)
    save_conf()


def restart_panel_later():
    def later():
        time.sleep(1.2)
        rc, _ = run(["systemctl", "restart", PANEL_UNIT])
        if rc != 0:
            os.execv(sys.executable, [sys.executable] + sys.argv)
    threading.Thread(target=later, daemon=True).start()


def prune_auth_state():
    now = time.time()
    with AUTH_LOCK:
        for sid in [k for k, v in SESSIONS.items() if v["exp"] < now or now - v["last"] > SESSION_IDLE]:
            SESSIONS.pop(sid, None)
        for ip in [k for k, v in FAILS.items() if now - v[1] > FAIL_WINDOW]:
            FAILS.pop(ip, None)
        while GLOBAL_FAILS and now - GLOBAL_FAILS[0] > FAIL_WINDOW:
            GLOBAL_FAILS.pop(0)


def load_conf():
    global CONF
    try:
        CONF = json.loads(read_file(PANEL_CONF, "{}") or "{}")
    except ValueError:
        CONF = {}
    return CONF


def save_conf():
    write_file(PANEL_CONF, json.dumps(CONF, indent=2), 0o600)
    try:
        os.chmod(os.path.dirname(PANEL_CONF), 0o700)
    except OSError:
        pass


def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200000).hex()


def set_credentials(user, pw):
    if not re.match(r"^[A-Za-z0-9_.\-]{3,32}$", user or ""):
        raise ApiError("نام کاربری باید 3 تا 32 کاراکتر انگلیسی/عدد باشد")
    if len(pw or "") < 8:
        raise ApiError("رمز باید حداقل 8 کاراکتر باشد")
    if len(pw) > 256:
        raise ApiError("رمز خیلی طولانی است")
    salt = secrets.token_hex(16)
    CONF["user"] = user
    CONF["salt"] = salt
    CONF["hash"] = hash_pw(pw, salt)


def check_pw(user, pw):
    if not CONF.get("hash"):
        return False
    ok_user = hmac.compare_digest(str(user).encode("utf-8"), str(CONF.get("user", "")).encode("utf-8"))
    ok_pw = hmac.compare_digest(hash_pw(str(pw), CONF["salt"]).encode(), str(CONF["hash"]).encode())
    return ok_user and ok_pw


def base_path():
    b = str(CONF.get("base", "")).strip("/")
    return ("/" + b) if b else ""


def a_settings_get(p):
    return {"user": CONF.get("user"), "port": CONF.get("port", 8800), "base": CONF.get("base", ""),
            "tls": bool(CONF.get("cert")), "listen": CONF.get("listen", "0.0.0.0"),
            "has_openssl": bool(shutil.which("openssl")), "repo": CONF.get("repo") or ""}



def _locked(fn):
    def w(p):
        with LOCK:
            return fn(p)
    w.__name__ = fn.__name__
    return w


@_locked
def a_set_credentials(p):
    if not check_pw(CONF.get("user"), p.get("current", "")):
        raise ApiError("رمز فعلی اشتباه است")
    set_credentials(str(p.get("user") or "").strip(), str(p.get("password") or ""))
    save_conf()
    SESSIONS.clear()
    return {}


@_locked
def a_panel_settings(p):
    port = v_int(p.get("port"), "پورت پنل", 1, 65535)
    base = str(p.get("base") or "").strip().strip("/")
    if base and not re.match(r"^[A-Za-z0-9_\-]{1,64}$", base):
        raise ApiError("مسیر مخفی فقط حروف انگلیسی، عدد، - و _")
    if port != int(CONF.get("port", 8800)) and port in listening("tcp"):
        raise ApiError("پورت %d در حال استفاده است" % port)
    for n in list_names():
        try:
            t = load_tunnel(n)
        except ApiError:
            continue
        for tp, proto, kind in _listener_ports(t):
            if proto == "tcp" and tp == port:
                raise ApiError("پورت %d توسط تانل %s رزرو شده است" % (port, n))
    CONF["port"] = port
    CONF["base"] = base
    save_conf()
    restart_panel_later()
    return {"port": port, "base": base, "https": bool(CONF.get("cert"))}


@_locked
def a_https(p):
    on = bool(p.get("on"))
    set_https(on)
    restart_panel_later()
    return {"https": on, "port": CONF.get("port", 8800), "base": CONF.get("base", "")}


@_locked
def a_external_off(p):
    CONF["listen"] = "127.0.0.1"
    save_conf()
    restart_panel_later()
    return {}


ACTIONS = {
    "list": a_list, "get": a_get, "create": a_create, "update": a_update,
    "action": a_action, "delete": a_delete, "logs": a_logs, "ping": a_ping,
    "gre_info": a_gre_info, "port_test": a_port_test, "cron": a_cron, "raw_get": a_raw_get, "raw_save": a_raw_save,
    "restart_all": a_restart_all, "core_info": a_core_info, "core_download": a_core_download,
    "settings_get": a_settings_get, "set_credentials": a_set_credentials,
    "panel_settings": a_panel_settings, "external_off": a_external_off, "https": a_https,
    "backup_list": a_backup_list, "backup_create": a_backup_create, "backup_info": a_backup_info,
    "backup_restore_saved": a_backup_restore_saved, "backup_delete": a_backup_delete,
    "bh_core_info": a_bh_core_info, "bh_core_download": a_bh_core_download,
    "cores": a_cores, "gen_core_download": a_gen_core_download, "core_remove": a_core_remove,
    "optimize_get": a_optimize_get, "optimize": a_optimize, "audit": a_audit,
}


JSON_LIMIT = 1024 * 1024
UPLOAD_LIMIT = 80 * 1024 * 1024
UPLOAD_ACTIONS = ("core_upload", "backup_upload", "bh_core_upload", "gen_core_upload")


# ---------------------------------------------------------------- i18n (English responses)
# Messages are written in Persian; when the browser asks for English (X-Lang: en) every
# Persian fragment in the JSON response is replaced by its English counterpart.
I18N_EN = {
 "این هسته را تانل‌های %s استفاده می‌کنند؛ اول آن تانل‌ها را حذف کنید": "Tunnels %s use this core; delete those tunnels first",
 "هسته‌ای برای حذف پیدا نشد": "No installed core found to remove",
 "اتصال تا سرور خارج کامل نشد: طرف مقابل اتصال را بست (سرویس اصلی روی این پورت در خارج جواب نمی‌دهد یا تانل این پورت وصل نیست)": "The connection did not reach the abroad server: the far side closed it (the main service abroad does not answer on this port, or this port's tunnel is not connected)",
 "پورت %d توسط تانل %s رزرو شده است": "Port %d is reserved by tunnel %s",
 "پورت": "Port",
 "%s نامعتبر است": "%s is invalid",
 "%s باید بین 23 تا 65535 باشد": "%s must be between 23 and 65535",
 "%s خالی است": "%s is empty",
 "%s نامعتبر است: %s": "%s is invalid: %s",
 "%s یک IPv4 معتبر نیست": "%s is not a valid IPv4",
 "%s باید بین %d و %d باشد": "%s must be between %d and %d",
 "IP داخلی %s آدرس شبکه/برادکست /30 است؛ آخرین عدد باید مثل 1 یا 2 باشد (نه مضرب 4 و نه مضرب 4 منهای 1)": "Inner IP %s is the network/broadcast address of the /30; the last number must be like 1 or 2 (not a multiple of 4 nor a multiple of 4 minus 1)",
 "نوع لینک باید GRE، IPIP یا 6to4 باشد": "Link type must be GRE, IPIP or 6to4",
 "نام تانل نامعتبر است": "Invalid tunnel name",
 "ثبت crontab ناموفق بود: ": "Saving crontab failed: ",
 "بازه زمانی نامعتبر است": "Invalid interval",
 "تانل %s پیدا نشد": "Tunnel %s not found",
 "نوع سرور را انتخاب کنید (ایران / خارج)": "Choose the server type (Iran / abroad)",
 "پورت تانل": "Tunnel port",
 "نوع تانل نامعتبر است": "Invalid tunnel type",
 "حالت CDN کلادفلر فقط با موتور Backhaul ساخته می‌شود؛ موتور را Backhaul انتخاب کنید": "Cloudflare CDN mode is only available with the Backhaul engine; choose Backhaul",
 "دامنه CDN": "CDN domain",
 "در حالت CDN باید دامنه (نه IP) وارد کنید؛ دامنه‌ای که در کلادفلر تیک پروکسی آن روشن است": "In CDN mode you must enter a domain (not an IP): a domain with the proxy toggle on in Cloudflare",
 "کلادفلر فقط این پورت‌ها را %s پروکسی می‌کند: %s. پورت تانل باید یکی از این‌ها باشد%s": "Cloudflare only proxies these ports %s: %s. The tunnel port must be one of them%s",
 "با TLS": "with TLS",
 "بدون TLS": "without TLS",
 "، ": ", ",
 "؛ برای تغییر پورت، تانل جدید بسازید": "; to change the port, create a new tunnel",
 "دامنه همین سرور": "This server's domain",
 "دامنه سرور مقابل": "Peer server domain",
 "IP داخلی این سرور": "This server's inner IP",
 "IP داخلی سرور ایران": "Iran server inner IP",
 "IP داخلی ایران (%s) با IP داخلی این سرور (%s) در یک شبکه /30 نیست. مقدار درست: %s": "The Iran inner IP (%s) is not in the same /30 network as this server's inner IP (%s). Correct value: %s",
 "توکن فقط می‌تواند شامل حروف انگلیسی، عدد و _ . - @ : + = باشد (حداکثر 128 کاراکتر)": "The token may only contain English letters, digits and _ . - @ : + = (max 128 characters)",
 "در حالت CDN باید Heartbeat روشن باشد؛ کلادفلر اتصال بیکار را بعد از حدود 100 ثانیه می‌بندد (ایران 30، خارج 40)": "Heartbeat must be on in CDN mode; Cloudflare closes idle connections after about 100 seconds (Iran 30, abroad 40)",
 "در حالت CDN مقدار Heartbeat ایران باید کمتر از 80 ثانیه باشد": "In CDN mode the Iran heartbeat must be under 80 seconds",
 "پورت سرویس": "Service port",
 "نوع پورت %d باید tcp یا udp باشد": "Type of port %d must be tcp or udp",
 "پورت %d تکراری است": "Port %d is duplicated",
 "پورت سرویس %d با پورت تانل یکی است": "Service port %d equals the tunnel port",
 "حداقل یک پورت سرویس وارد کنید": "Enter at least one service port",
 "پورت تانل %d در حال استفاده است": "Tunnel port %d is in use",
 "پورت %d/%s روی این سرور در حال استفاده است": "Port %d/%s is in use on this server",
 "شبکه داخلی %s با تانل %s (IP %s) تداخل دارد. برای هر تانل یک شبکه /30 جدا بدهید، مثلاً عدد سوم را عوض کنید.": "Inner network %s conflicts with tunnel %s (IP %s). Give each tunnel its own /30 network, e.g. change the third number.",
 "شبکه داخلی %s با اینترفیس %s (%s) روی این سرور تداخل دارد": "Inner network %s conflicts with interface %s (%s) on this server",
 "ریزالو دامنه ناموفق بود: %s → %s ، %s → %s": "Domain resolution failed: %s → %s , %s → %s",
 "برای حالت CDN با TLS، برنامه openssl لازم است: apt install openssl": "CDN mode with TLS needs openssl: apt install openssl",
 "ساخت گواهی ناموفق بود: ": "Creating the certificate failed: ",
 "ساخت فایل pkcs12 ناموفق بود: ": "Creating the pkcs12 file failed: ",
 "هشدار: دامنه %s ریزالو نشد": "Warning: domain %s did not resolve",
 "%s → %s (کلادفلر، تیک پروکسی روشن است ✓)": "%s → %s (Cloudflare, proxy is on ✓)",
 "هشدار: %s → %s که IP کلادفلر نیست؛ تیک پروکسی (ابر نارنجی) را روشن کنید": "Warning: %s → %s is not a Cloudflare IP; turn on the proxy (orange cloud)",
 "سرویس": "service",
 "تانل": "tunnel",
 "پورت %d (%s) پورت خود پنل NETIFAY است؛ پورت دیگری انتخاب کنید": "Port %d (%s) is the NETIFAY panel's own port; choose another port",
 "بین این سرور و %s قبلا یک لینک %s ساخته شده (تانل %s). لینوکس فقط یک لینک %s بین دو سرور مشخص اجازه می‌دهد. ": "Between this server and %s a %s link already exists (tunnel %s). Linux allows only one %s link between two given servers. ",
 "یا پورت‌ها را به همان تانل اضافه کنید، یا برای این تانل نوع لینک دیگری (GRE / IPIP / 6to4) انتخاب کنید، یا حالت «مستقیم».": "Either add the ports to that tunnel, choose another link type (GRE / IPIP / 6to4) for this tunnel, or use «direct» mode.",
 "پورت %d/%s (%s) قبلا توسط تانل %s (%s) روی این سرور رزرو شده است": "Port %d/%s (%s) is already reserved by tunnel %s (%s) on this server",
 "%s: کانفیگ خوانده نشد (%s)": "%s: config could not be read (%s)",
 "پورت %d/%s هم در تانل %s (%s) و هم در تانل %s (%s) استفاده شده است": "Port %d/%s is used both in tunnel %s (%s) and in tunnel %s (%s)",
 "پورت %d در تانل %s با پورت پنل یکی است": "Port %d in tunnel %s equals the panel port",
 "پورت %d/%s توسط iptables (تانل %s) فوروارد می‌شود ولی برنامه %s هم روی آن گوش می‌دهد؛ ترافیک ورودی به آن برنامه نمی‌رسد": "Port %d/%s is forwarded by iptables (tunnel %s) but program %s also listens on it; incoming traffic never reaches that program",
 "پورت %d/%s (%s تانل %s) توسط برنامه دیگری گرفته شده: %s": "Port %d/%s (%s of tunnel %s) is taken by another program: %s",
 "شبکه داخلی %s در دو تانل %s و %s تکراری است": "Inner network %s is duplicated in tunnels %s and %s",
 "شبکه داخلی %s (تانل %s) با اینترفیس %s (%s) روی سرور تداخل دارد": "Inner network %s (tunnel %s) conflicts with interface %s (%s) on the server",
 "تانل‌های %s و %s هر دو لینک %s به یک سرور (%s) دارند؛ فقط یکی از آن‌ها کار می‌کند": "Tunnels %s and %s both have a %s link to the same server (%s); only one of them works",
 "تانل %s به هسته rathole نیاز دارد که نصب نیست": "Tunnel %s needs the rathole core, which is not installed",
 "تانل %s به هسته Backhaul نیاز دارد که نصب نیست": "Tunnel %s needs the Backhaul core, which is not installed",
 "تانل %s به هسته %s نیاز دارد که نصب نیست": "Tunnel %s needs the %s core, which is not installed",
 "اسکریپت لینک تانل %s پیدا نشد؛ یک بار «ویرایش» و ذخیره کنید": "Link script of tunnel %s is missing; «Edit» and save once",
 "Heartbeat تانل %s روی %s است؛ اگر سمت ایران 30 باشد اتصال مدام قطع و وصل می‌شود (پیشنهاد: 40)": "Heartbeat of tunnel %s is %s; if the Iran side is 30 the connection keeps dropping (suggested: 40)",
 "سرویس تانل %s فعال نیست (%s)": "Service of tunnel %s is not active (%s)",
 "هیچ تداخل یا مشکلی پیدا نشد ✓ (%d تانل بررسی شد)": "No conflicts or problems found ✓ (%d tunnels checked)",
 "برای کلون باید دامنه CDN را تغییر دهید (الان همان %s است)": "For a clone you must change the CDN domain (it is still %s)",
 "برای کلون باید آدرس سرور مقابل را تغییر دهید (الان همان %s است)": "For a clone you must change the peer server address (it is still %s)",
 "برای کلون باید دامنه سرور مقابل را تغییر دهید (الان همان %s است)": "For a clone you must change the peer server domain (it is still %s)",
 "برای کلون باید IP داخلی GRE را به یک شبکه جدید تغییر دهید": "For a clone you must change the GRE inner IP to a new network",
 "هسته rathole نصب نیست. از بخش «هسته» نصبش کنید.": "The rathole core is not installed. Install it from the «Core» section.",
 "تانل %s از قبل وجود دارد": "Tunnel %s already exists",
 "هسته rathole فعلی از websocket پشتیبانی نمی‌کند؛ نسخه 0.5.0 یا بالاتر لازم است": "The current rathole core does not support websocket; version 0.5.0 or later is needed",
 "خطای systemd: ": "systemd error: ",
 "ساخته شد": "created",
 "بالا نیامد ": "did not come up ",
 "عملیات نامعتبر": "Invalid operation",
 "خطا در systemctl": "systemctl error",
 "(خالی)": "(empty)",
 "این تانل لینک شبکه (GRE/IPIP/6to4) ندارد؛ از «تست پورت‌ها» استفاده کنید": "This tunnel has no network link (GRE/IPIP/6to4); use «Test ports»",
 "IP داخلی طرف مقابل مشخص نیست": "The peer's inner IP is unknown",
 "سرویس تانل اجرا نیست": "The tunnel service is not running",
 "توکن با سرور مقابل یکی نیست": "The token does not match the peer server",
 "این پورت در کانفیگ سرور مقابل نیست": "This port is not in the peer server's config",
 "اتصال تانل این پورت برقرار نمی‌شود": "The tunnel connection for this port cannot be established",
 "قانون فوروارد iptables برای این پورت وجود ندارد": "There is no iptables forward rule for this port",
 "این پورت روی سرور ایران باز نشده (تانل این پورت وصل نیست)": "This port is not open on the Iran server (its tunnel is not connected)",
 "روی این سرور سرویسی (مثلا Xray) روی این پورت جواب نمی‌دهد": "No service (e.g. Xray) answers on this port on this server",
 "اتصال به سرویس محلی %d بار رد شد": "Connection to the local service was refused %d times",
 "قطع و وصل زیاد (%d بار early eof)": "Frequent reconnects (%d times early eof)",
 "سرور خارج به این تانل وصل نیست": "The abroad server is not connected to this tunnel",
 "به سرور ایران وصل نیست": "Not connected to the Iran server",
 "این تانل Backhaul در حالت اتصال مستقیم است و GRE ندارد.": "This Backhaul tunnel is in direct mode and has no GRE.",
 "این تانل در حالت CDN کلادفلر است و GRE ندارد.\nدامنه: %s\nTLS: %s": "This tunnel is in Cloudflare CDN mode and has no GRE.\nDomain: %s\nTLS: %s",
 "بله": "Yes",
 "خیر": "No",
 "تانل پیدا نشد": "Tunnel not found",
 "ویرایش مستقیم اسکریپت iptables مجاز نیست؛ از «ویرایش» استفاده کنید": "Editing the iptables script directly is not allowed; use «Edit»",
 "JSON نامعتبر است: %s": "Invalid JSON: %s",
 "فایل باید بخش %s داشته باشد": "The file must contain a %s section",
 "فایل خیلی بزرگ است": "File is too large",
 "فایل zip خراب است": "The zip file is broken",
 "داخل zip فایلی به اسم rathole نبود": "There was no file named rathole inside the zip",
 "فایل باینری لینوکس (ELF) نیست": "Not a Linux binary (ELF)",
 "کتابخانه‌ای که این نسخه لازم دارد روی سرور نیست (%s). نسخه musl یا هسته اسکریپت قبلی را آپلود کنید، یا «دانلود از GitHub» را بزنید که خودش نسخه سازگار را انتخاب می‌کند.": "A library this build needs is missing on the server (%s). Upload the musl build or the original script's core, or press «Download from GitHub», which picks a compatible build automatically.",
 "این باینری روی این معماری اجرا نمی‌شود: ": "This binary does not run on this architecture: ",
 "فایلی ارسال نشد": "No file was sent",
 "در Backhaul نوع اتصال باید GRE، مستقیم یا CDN باشد": "For Backhaul the connection type must be GRE, direct or CDN",
 "ترنسپورت نامعتبر است": "Invalid transport",
 "در حالت CDN ترنسپورت باید ws، wss، wsmux یا wssmux باشد (پیشنهادی: wssmux)": "In CDN mode the transport must be ws, wss, wsmux or wssmux (recommended: wssmux)",
 "با TLS (wss/wssmux)": "with TLS (wss/wssmux)",
 "بدون TLS (ws/wsmux)": "without TLS (ws/wsmux)",
 "؛ برای تغییر پورت، تانل جدید بسازید (یا کلون)": "; to change the port, create a new tunnel (or clone)",
 "در حالت CDN مقدار Heartbeat باید کمتر از 80 ثانیه باشد (کلادفلر اتصال بیکار را بعد از 100 ثانیه می‌بندد)": "In CDN mode the heartbeat must be under 80 seconds (Cloudflare closes idle connections after 100 seconds)",
 "آدرس سرور ایران (دامنه یا IP)": "Iran server address (domain or IP)",
 "UDP در Backhaul فقط با ترنسپورت tcp کار می‌کند (پورت %d)": "UDP in Backhaul only works with the tcp transport (port %d)",
 "شبکه داخلی %s با تانل %s (IP %s) تداخل دارد. برای هر تانل یک شبکه /30 جدا بدهید.": "Inner network %s conflicts with tunnel %s (IP %s). Give each tunnel its own /30 network.",
 "برای wss/wssmux برنامه openssl لازم است: apt install openssl": "wss/wssmux needs openssl: apt install openssl",
 "ساخت گواهی TLS ناموفق بود: ": "Creating the TLS certificate failed: ",
 "هسته Backhaul نصب نیست. از تب «هسته» آن را نصب کنید.": "The Backhaul core is not installed. Install it from the «Core» tab.",
 " (کلادفلر)": " (Cloudflare)",
 "نصب شده": "installed",
 "فایل tar.gz خراب است": "The tar.gz file is broken",
 "داخل فایل، باینری backhaul پیدا نشد": "No backhaul binary found in the file",
 "داخل zip باینری backhaul پیدا نشد": "No backhaul binary found in the zip",
 "این باینری روی این سرور اجرا نمی‌شود: ": "This binary does not run on this server: ",
 "برای ساخت گواهی TLS برنامه openssl لازم است: apt install openssl": "Creating a TLS certificate needs openssl: apt install openssl",
 "موتور نامعتبر است": "Invalid engine",
 "شماره تانل": "Tunnel number",
 "برای %s نوع اتصال باید لینک (GRE/IPIP/6to4) یا مستقیم باشد": "For %s the connection type must be a link (GRE/IPIP/6to4) or direct",
 "در iptables حالت مستقیم، سمت خارج هیچ تنظیمی لازم ندارد؛ فقط سرور ایران را بسازید": "For iptables in direct mode, the abroad side needs no setup; only build the Iran server",
 "iptables روی 6to4 (IPv6) کار نمی‌کند؛ لینک GRE یا IPIP را انتخاب کنید": "iptables does not work over 6to4 (IPv6); choose a GRE or IPIP link",
 "خارج": "abroad",
 "ایران": "Iran",
 "آدرس سرور %s (دامنه یا IP)": "%s server address (domain or IP)",
 "پروتکل FRP نامعتبر است": "Invalid FRP protocol",
 "ترنسپورت Gost نامعتبر است": "Invalid Gost transport",
 "رمز Obfs فقط حروف انگلیسی، عدد و _ . - @ : + =": "The obfs password may only contain English letters, digits and _ . - @ : + =",
 "SNI برای REALITY باید یک دامنه معتبر باشد (مثلا www.speedtest.net)": "The SNI for REALITY must be a valid domain (e.g. www.speedtest.net)",
 "%s فقط پورت‌های tcp را پشتیبانی می‌کند (پورت %d)": "%s only supports tcp ports (port %d)",
 "پورت تانل %d/%s روی این سرور در حال استفاده است": "Tunnel port %d/%s is in use on this server",
 "فایل تنظیمات تانل %s خراب است": "The settings file of tunnel %s is broken",
 "iptables روی این سرور نصب نیست: apt install iptables": "iptables is not installed on this server: apt install iptables",
 "هسته %s نصب نیست. از تب «هسته» آن را نصب کنید.": "The %s core is not installed. Install it from the «Core» tab.",
 "کلید عمومی REALITY (خودکار از توکن ساخته می‌شود؛ لازم نیست کپی کنید): ": "REALITY public key (derived from the token automatically; no need to copy it): ",
 "برای %s فایل tar.gz کامل (شامل %s) را آپلود کنید": "For %s, upload the complete tar.gz (containing %s)",
 " و ": " and ",
 "داخل فایل، باینری %s پیدا نشد": "No %s binary found in the file",
 "%s یک باینری لینوکس (ELF) نیست": "%s is not a Linux binary (ELF)",
 "%s روی این سرور اجرا نمی‌شود: %s": "%s does not run on this server: %s",
 "مخزن گیت‌هاب NETIFAY تنظیم نشده است. پنل را با لینک نصب رسمی دوباره نصب کنید یا هسته را دستی آپلود کنید.": "The NETIFAY GitHub repository is not configured. Reinstall the panel with the official install link or upload the core manually.",
 "دانلود از مخزن NETIFAY ناموفق بود (%s). اتصال سرور به github.com را چک کنید یا فایل را دستی آپلود کنید. %s": "Download from the NETIFAY repository failed (%s). Check the server's access to github.com or upload the file manually. %s",
 "نام فایل بکاپ نامعتبر است": "Invalid backup file name",
 "بکاپ پیدا نشد": "Backup not found",
 "فایل بکاپ خراب است یا tar.gz نیست": "The backup file is broken or not a tar.gz",
 "فایل بکاپ بیش از حد بزرگ/عجیب است": "The backup file is too large / unusual",
 "فایل بکاپ ناقص یا خراب است": "The backup file is incomplete or broken",
 "این فایل، بکاپ پنل NETIFAY نیست (manifest پیدا نشد)": "This is not a NETIFAY panel backup (manifest not found)",
 "manifest بکاپ خراب است": "The backup manifest is broken",
 "این فایل، بکاپ پنل NETIFAY نیست": "This is not a NETIFAY panel backup",
 "موتور این تانل برای این نسخه پنل ناشناخته است": "This tunnel's engine is unknown to this panel version",
 "فایل تنظیمات این تانل داخل بکاپ نیست": "This tunnel's settings file is not in the backup",
 "تانل %s با موتور %s روی این سرور هست؛ برای بازیابی، اول آن را حذف کنید": "Tunnel %s with engine %s exists on this server; delete it first to restore",
 "هسته %s روی این سرور نصب نیست": "The %s core is not installed on this server",
 "تانل فعلی با همین نام جایگزین می‌شود": "The current tunnel with the same name will be replaced",
 "فایل تنظیمات در بکاپ نبود": "The settings file was not in the backup",
 "فایل تنظیمات خراب است": "The settings file is broken",
 "فایل کانفیگ در بکاپ نبود": "The config file was not in the backup",
 "کانفیگ rathole نامعتبر است": "Invalid rathole config",
 "تانل CDN قدیمی روی rathole است؛ CDN حالا فقط روی Backhaul است. آن را با Backhaul (حالت CDN) دوباره بسازید": "This is a legacy CDN tunnel on rathole; CDN is now only on Backhaul. Recreate it with Backhaul (CDN mode)",
 "دامنه این سرور": "This server's domain",
 "IP داخلی": "Inner IP",
 "هیچ تانلی برای بازیابی انتخاب نشده است": "No tunnel was selected for restore",
 "هسته لازم روی این سرور نصب نیست — ": "A required core is not installed on this server — ",
 "؛ ": "; ",
 "%s (برای %s)": "%s (for %s)",
 ". اول از تب «هسته» نصبش کنید، یا این تانل‌ها را از انتخاب بردارید. هیچ تغییری اعمال نشد.": ". Install it from the «Core» tab first, or deselect these tunnels. Nothing was changed.",
 "این تانل‌ها قابل بازیابی نیستند (هیچ تغییری اعمال نشد): ": "These tunnels cannot be restored (nothing was changed): ",
 ". آن‌ها را از انتخاب بردارید.": ". Deselect them.",
 "بکاپ خودکار از وضعیت فعلی: ": "Automatic backup of the current state: ",
 "خطای داخلی: %s": "Internal error: %s",
 " — نسخه قبلی همین تانل برگردانده شد": " — the previous version of this tunnel was put back",
 " — برگرداندن نسخه قبلی هم ناموفق بود (%s)؛ از بکاپ خودکار استفاده کنید": " — putting back the previous version also failed (%s); use the automatic backup",
 "%s: بازیابی نشد، %s": "%s: not restored, %s",
 "بازیابی و اجرا شد": "restored and running",
 "بازیابی شد ولی اجرا نشد: ": "restored but not started: ",
 "هیچ تانلی بازیابی نشد": "No tunnel was restored",
 "کانفیگ Backhaul نامعتبر": "Invalid Backhaul config",
 "تانل دیگری با همین نام روی این سرور هست": "Another tunnel with the same name exists on this server",
 "هنوز تانلی روی این سرور نیست که بکاپ گرفته شود": "There are no tunnels on this server to back up yet",
 "این بکاپ هیچ تانلی ندارد": "This backup has no tunnels",
 "فایل بهینه‌سازی حذف شد. مقادیر پیش‌فرض بعد از ری‌استارت سرور کامل برمی‌گردند.": "The optimization file was removed. Defaults are fully restored after the server reboots.",
 "%d تنظیم اعمال شد": "%d settings applied",
 "رد شد: ": "Rejected: ",
 "الگوریتم فعلی: ": "Current algorithm: ",
 "برای HTTPS برنامه openssl لازم است: apt install openssl": "HTTPS needs openssl: apt install openssl",
 "ساخت گواهی HTTPS ناموفق بود: ": "Creating the HTTPS certificate failed: ",
 "نام کاربری باید 3 تا 32 کاراکتر انگلیسی/عدد باشد": "The username must be 3 to 32 English letters/digits",
 "رمز باید حداقل 8 کاراکتر باشد": "The password must be at least 8 characters",
 "رمز خیلی طولانی است": "The password is too long",
 "رمز فعلی اشتباه است": "The current password is wrong",
 "پورت پنل": "Panel port",
 "مسیر مخفی فقط حروف انگلیسی، عدد، - و _": "The secret path may only contain English letters, digits, - and _",
 "پورت %d در حال استفاده است": "Port %d is in use",
 "درخواست خیلی بزرگ است": "Request too large",
 "تلاش زیاد. 10 دقیقه دیگر امتحان کنید.": "Too many attempts. Try again in 10 minutes.",
 "نام کاربری یا رمز اشتباه است": "Wrong username or password",
 "درخواست نامعتبر": "Invalid request",
 "خطای داخلی سرور (جزئیات در لاگ پنل)": "Internal server error (details in the panel log)"
}
_FMT_RE = re.compile(r"%(?:\.\d+)?[sdf]")
_FA_RE = re.compile("[\u0600-\u06FF]")


def _build_pieces():
    out = {}
    for fa, en in I18N_EN.items():
        fp, ep = _FMT_RE.split(fa), _FMT_RE.split(en)
        if len(fp) != len(ep):
            fp, ep = [fa], [en]
        for a, b in zip(fp, ep):
            if a and _FA_RE.search(a) and a not in out:
                out[a] = b
    return sorted(out.items(), key=lambda kv: -len(kv[0]))


_TR_PIECES = _build_pieces()


def tr_en(s):
    if not isinstance(s, str) or not _FA_RE.search(s):
        return s
    for fa, en in _TR_PIECES:
        if fa in s:
            s = s.replace(fa, en)
    return s


def tr_deep(o):
    if isinstance(o, str):
        return tr_en(o)
    if isinstance(o, list):
        return [tr_deep(x) for x in o]
    if isinstance(o, dict):
        return {k: tr_deep(v) for k, v in o.items()}
    return o


class Handler(BaseHTTPRequestHandler):
    server_version = "nginx"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 60  # per-connection socket timeout (slowloris protection)

    def setup(self):
        # TLS handshake happens here, in the worker thread, not in the accept loop
        if isinstance(self.request, ssl.SSLSocket):
            self.request.settimeout(15)
            try:
                self.request.do_handshake()
            except (ssl.SSLError, OSError, socket.timeout):
                try:
                    self.request.close()
                except OSError:
                    pass
                raise
        BaseHTTPRequestHandler.setup(self)

    def log_message(self, fmt, *args):
        pass

    def client_ip(self):
        return self.client_address[0]

    def send(self, code, body, ctype="application/json; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if "Cache-Control" not in (headers or {}):
            self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def jsend(self, code, obj, headers=None):
        if (self.headers.get("X-Lang") or "").lower() == "en" and isinstance(obj, dict):
            fa_err = obj.get("error")
            obj = tr_deep(obj)
            if fa_err is not None:
                obj["error_fa"] = fa_err
        self.send(code, json.dumps(obj, ensure_ascii=False), headers=headers)

    def session(self):
        c = cookies.SimpleCookie()
        try:
            c.load(self.headers.get("Cookie", ""))
        except cookies.CookieError:
            return None
        m = c.get("rpsid")
        if not m:
            return None
        sid = m.value
        now = time.time()
        with AUTH_LOCK:
            s_ = SESSIONS.get(sid)
            if s_ and s_["exp"] > now and now - s_["last"] <= SESSION_IDLE:
                s_["last"] = now
                return sid
            SESSIONS.pop(sid, None)
        return None

    def cookie(self, sid, max_age):
        path = base_path() + "/"
        secure = "; Secure" if CONF.get("cert") else ""
        return "rpsid=%s; Path=%s; Max-Age=%d; HttpOnly; SameSite=Strict%s" % (sid, path, max_age, secure)

    def do_GET(self):
        path = urlparse(self.path).path
        b = base_path()
        if b and path == b:
            self.send(302, "", "text/plain", {"Location": b + "/"})
            return
        if path == b + "/font/vazirmatn.woff2":
            self.send(200, FONT_DATA, "font/woff2",
                      {"Cache-Control": "public, max-age=31536000, immutable"})
            return
        if path == b + "/" or path == b + "/index.html":
            nonce = secrets.token_urlsafe(16)
            csp = ("default-src 'none'; script-src 'nonce-%s'; style-src 'unsafe-inline'; "
                   "img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; "
                   "frame-ancestors 'none'; base-uri 'none'" % nonce)
            self.send(200, HTML.replace("__NONCE__", nonce), "text/html; charset=utf-8",
                      {"Content-Security-Policy": csp})
            return
        self.send(404, "Not Found", "text/plain")

    def do_POST(self):
        path = urlparse(self.path).path
        b = base_path()
        if not path.startswith(b + "/api/"):
            self.send(404, "Not Found", "text/plain")
            return
        action = path[len(b) + 5:]
        if self.headers.get("X-Panel") != "1":
            self.jsend(403, {"ok": False, "error": "forbidden"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        limit = UPLOAD_LIMIT if action in UPLOAD_ACTIONS else JSON_LIMIT
        if length < 0 or length > limit:
            self.close_connection = True
            self.jsend(413, {"ok": False, "error": "درخواست خیلی بزرگ است"})
            return
        prune_auth_state()

        if action == "login":
            raw = self.rfile.read(length) if length else b""
            ip = self.client_ip()
            now = time.time()
            with AUTH_LOCK:
                f = FAILS.get(ip, [0, now])
                blocked = (f[0] >= FAIL_PER_IP) or len(GLOBAL_FAILS) >= FAIL_GLOBAL
            if blocked:
                self.jsend(429, {"ok": False, "error": "تلاش زیاد. 10 دقیقه دیگر امتحان کنید."})
                return
            try:
                p = json.loads(raw.decode("utf-8") or "{}")
                if not isinstance(p, dict):
                    p = {}
            except (ValueError, UnicodeDecodeError):
                p = {}
            if check_pw(str(p.get("user", ""))[:64], str(p.get("password", ""))[:256]):
                sid = secrets.token_urlsafe(32)
                with AUTH_LOCK:
                    FAILS.pop(ip, None)
                    SESSIONS[sid] = {"exp": now + SESSION_TTL, "last": now}
                self.jsend(200, {"ok": True, "data": {}}, {"Set-Cookie": self.cookie(sid, SESSION_TTL)})
            else:
                with AUTH_LOCK:
                    f = FAILS.get(ip, [0, now])
                    FAILS[ip] = [f[0] + 1, f[1]]
                    GLOBAL_FAILS.append(now)
                time.sleep(1.0)
                self.jsend(401, {"ok": False, "error": "نام کاربری یا رمز اشتباه است"})
            return

        sid = self.session()
        if not sid:
            # do not read (possibly huge) bodies from unauthenticated clients
            self.close_connection = True
            self.jsend(401, {"ok": False, "error": "auth"})
            return
        raw = self.rfile.read(length) if length else b""
        if action == "logout":
            with AUTH_LOCK:
                SESSIONS.pop(sid, None)
            self.jsend(200, {"ok": True, "data": {}}, {"Set-Cookie": self.cookie("x", 0)})
            return
        try:
            if action == "core_upload":
                data = a_core_upload(raw)
            elif action == "bh_core_upload":
                data = a_bh_core_upload(raw)
            elif action == "gen_core_upload":
                data = a_gen_core_upload(raw, self.headers)
            elif action == "backup_upload":
                data = a_backup_upload(raw, self.headers)
            elif action == "backup_download":
                p = json.loads(raw.decode("utf-8") or "{}") if raw else {}
                path = bk_path(p.get("name"))
                with open(path, "rb") as f:
                    blob = f.read()
                self.send(200, blob, "application/gzip",
                          {"Content-Disposition": 'attachment; filename="%s"' % os.path.basename(path)})
                return
            else:
                fn = ACTIONS.get(action)
                if not fn:
                    self.jsend(404, {"ok": False, "error": "unknown action"})
                    return
                p = json.loads(raw.decode("utf-8") or "{}") if raw else {}
                if not isinstance(p, dict):
                    raise ApiError("bad request")
                data = fn(p)
            self.jsend(200, {"ok": True, "data": data})
        except ApiError as e:
            self.jsend(400, {"ok": False, "error": str(e)})
        except (ValueError, UnicodeDecodeError):
            self.jsend(400, {"ok": False, "error": "درخواست نامعتبر"})
        except Exception as e:  # noqa
            sys.stderr.write("[panel] error in %s: %r\n" % (action, e))
            sys.stderr.flush()
            self.jsend(500, {"ok": False, "error": "خطای داخلی سرور (جزئیات در لاگ پنل)"})


class PanelServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        pass  # failed TLS handshakes / dropped clients are not worth a traceback


HTML = r"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<title>NETIFAY</title>
<link rel="icon" href="data:image/png;base64,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">
<style>
:root{
  --bg:#0b1018;--bg2:#121a26;--card:#161f2d;--line:#243145;--line2:#35455f;--txt:#e6edf3;--mut:#8b98a9;
  --acc:#1a8cff;--acc2:#0d6be9;--grad:linear-gradient(135deg,#00c8f0 0%,#1a6cf0 55%,#2a3fe0 100%);
  --ok:#22c55e;--bad:#ef4444;--warn:#f59e0b;--ir:#10b981;--kh:#a855f7;
  --ok-t:#86efac;--ok-b:#1f4d33;--bad-t:#fca5a5;--bad-b:#5b2323;--warn-t:#fcd34d;--info-t:#7cc4ff;
  --hdr:rgba(11,16,24,.9);--code:#070b11;--toast:#1c2636;--shadow:0 8px 30px rgba(0,0,0,.4);
  --r:14px;color-scheme:dark;
}
:root[data-theme=light]{
  --bg:#f3f6fb;--bg2:#eef2f8;--card:#ffffff;--line:#dbe3ee;--line2:#c2cee0;--txt:#0f172a;--mut:#5b6b80;
  --acc:#0d6be9;--acc2:#0b5bd0;
  --ok:#16a34a;--bad:#dc2626;--warn:#d97706;--ir:#059669;--kh:#9333ea;
  --ok-t:#15803d;--ok-b:#bbf7d0;--bad-t:#b91c1c;--bad-b:#fecaca;--warn-t:#92400e;--info-t:#1d4ed8;
  --hdr:rgba(243,246,251,.9);--code:#f1f5f9;--toast:#ffffff;--shadow:0 8px 30px rgba(15,23,42,.12);
  color-scheme:light;
}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
@font-face{font-family:"Vazirmatn";src:url(font/vazirmatn.woff2) format("woff2");font-weight:100 900;font-style:normal;font-display:swap}
html,body{margin:0;background:var(--bg);color:var(--txt);font:14.5px/1.8 "Vazirmatn","Segoe UI",Tahoma,sans-serif;
  -webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility}
button,input,select,textarea{font-family:inherit}
a{color:var(--acc)}
.ltr{direction:ltr;unicode-bidi:embed;font-size:13.5px;font-variant-numeric:tabular-nums}
.mono,pre.out,.guide code{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
.hidden{display:none!important}
.secbar{display:flex;align-items:flex-start;gap:8px;border:1px solid rgba(245,158,11,.6);background:rgba(245,158,11,.07);color:var(--warn-t);
  border-radius:10px;padding:6px 10px;font-size:12.5px;line-height:1.7;margin:0 0 12px}
.secbar>.ic{color:var(--warn);margin-top:3px}
.secbar .sb-txt{flex:1;min-width:0}
.secbar a{color:inherit;font-weight:700;text-decoration:underline;cursor:pointer;white-space:nowrap}
.secbar .sb-x{background:none;border:0;color:inherit;opacity:.7;cursor:pointer;padding:0 2px;line-height:1}
.secbar .sb-x:hover{opacity:1}
.recbox{border:1px solid var(--acc);background:rgba(26,140,255,.07);border-radius:12px;padding:10px 12px;margin:4px 0 12px}
.recbox b.t{display:flex;align-items:center;gap:6px;color:var(--info-t);margin-bottom:4px}
.langBtn{font-weight:800;min-width:38px;font-size:12px;letter-spacing:.3px}
[dir=ltr] [style*="text-align:right"]{text-align:left!important}
[dir=ltr] nav#nav button.on{box-shadow:inset 0 -2px 0 var(--acc)}
@media(max-width:720px){[dir=ltr] nav#nav button.on{box-shadow:inset 3px 0 0 var(--acc)}}
.ic{width:16px;height:16px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;vertical-align:-3px;flex:none}
.ic.lg{width:40px;height:40px;stroke-width:1.5}.ic.sm{width:14px;height:14px}
.btn .ic{margin:0}
nav button{display:inline-flex;align-items:center;gap:6px}
#menuBtn,.curTab,.navBack{display:none}
@media(max-width:720px){
  header{position:sticky}
  #menuBtn{display:inline-flex}
  .curTab{display:inline-flex;align-items:center;gap:5px;font-size:12.5px;color:var(--mut);background:var(--bg2);border:1px solid var(--line);border-radius:999px;padding:2px 10px;white-space:nowrap;max-width:34vw;overflow:hidden;text-overflow:ellipsis}
  .hname .hsub{display:none}
  .hbar{gap:6px!important}
  nav#nav{position:absolute;top:100%;inset-inline:8px;margin:0;display:none;flex-direction:column;gap:2px;padding:6px;
    background:var(--card);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow);z-index:40;max-height:calc(100vh - 90px);overflow:auto}
  header.menu-open nav#nav{display:flex;animation:in .15s}
  nav#nav button{width:100%;justify-content:flex-start;padding:11px 12px;font-size:14.5px}
  nav#nav button .ic{width:18px;height:18px}
  nav#nav button.on{box-shadow:inset -3px 0 0 var(--acc)}
  .navBack{position:fixed;inset:0;z-index:15;background:rgba(0,0,0,.35)}
  header.menu-open~.navBack{display:block}
}
@media(max-width:380px){.htitle{font-size:14px}.hbar .btn.sm{padding:5px 7px}}
body{transition:background .25s,color .25s}
.guide summary .ic{color:var(--acc)}
.guide summary .chev{margin-inline-start:auto;color:var(--mut);transition:transform .2s}
.guide details[open] summary .chev{transform:rotate(180deg)}
header{position:sticky;top:0;z-index:20;background:var(--hdr);backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}
.hbar{max-width:1100px;margin:auto;display:flex;align-items:center;gap:10px;padding:10px 14px}
.logo{width:36px;height:36px;object-fit:contain;flex:none;filter:drop-shadow(0 2px 6px rgba(13,107,233,.35))}
.htitle{letter-spacing:.5px}
.htitle{font-weight:800;letter-spacing:.6px}.hsub{color:var(--mut);font-size:12px}
.grow{flex:1}
nav{max-width:1100px;margin:auto;display:flex;gap:4px;padding:0 10px 8px;overflow-x:auto}
nav button{flex:none;background:none;border:0;color:var(--mut);padding:7px 14px;border-radius:10px;font:inherit;cursor:pointer}
nav button.on{background:var(--card);color:var(--txt);box-shadow:inset 0 -2px 0 var(--acc)}
main{max-width:1100px;margin:auto;padding:14px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;border:1px solid var(--line);background:var(--bg2);color:var(--txt);border-radius:10px;padding:7px 12px;font:inherit;font-size:13px;cursor:pointer;white-space:nowrap}
.btn:hover{border-color:var(--line2)}
.btn.p{background:var(--grad);border-color:transparent;color:#fff}
.btn.p:hover{filter:brightness(1.08)}
.btn.d{color:var(--bad-t);border-color:var(--bad-b)}
.btn.g{color:var(--ok-t);border-color:var(--ok-b)}
.btn:disabled{opacity:.5;cursor:wait}
.btn.sm{padding:5px 10px;font-size:12px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:14px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:10px 12px}
.stat b{display:block;font-size:16px}.stat span{color:var(--mut);font-size:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:14px}
.ch{display:flex;align-items:center;gap:8px;margin-bottom:10px}
.badge{font-size:12px;padding:2px 9px;border-radius:99px;font-weight:700}
.b-ir{background:rgba(16,185,129,.15);color:var(--ir)}.b-kh{background:rgba(168,85,247,.15);color:var(--kh)}
.pill{display:inline-flex;align-items:center;gap:5px;font-size:12px;color:var(--mut)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--mut)}
.dot.ok{background:var(--ok);box-shadow:0 0 8px var(--ok)}.dot.bad{background:var(--bad)}.dot.warn{background:var(--warn)}
.kv{display:grid;grid-template-columns:auto 1fr;gap:3px 12px;font-size:13px;margin:8px 0}
.kv dt{color:var(--mut)}.kv dd{margin:0;overflow-wrap:anywhere}
.chips{display:flex;flex-wrap:wrap;gap:5px;margin:8px 0}
.chip{background:var(--bg2);border:1px solid var(--line);border-radius:8px;padding:1px 8px;font-size:12px}
.acts{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px;padding-top:10px;border-top:1px solid var(--line)}
.empty{text-align:center;color:var(--mut);padding:50px 10px}
h2{font-size:18px;margin:0 0 12px;font-weight:800}
h3{font-size:14px;margin:18px 0 8px;color:var(--mut);font-weight:600}
.form{max-width:760px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
@media(max-width:600px){.row{grid-template-columns:1fr}.grid{grid-template-columns:1fr}}
label.f{display:block;margin-bottom:10px}
label.f>span{display:block;color:var(--mut);font-size:12px;margin-bottom:4px}
input,select,textarea{width:100%;background:var(--bg2);border:1px solid var(--line);color:var(--txt);border-radius:10px;padding:9px 11px;font:inherit;outline:none}
input:focus,select:focus,textarea:focus{border-color:var(--acc);box-shadow:0 0 0 3px rgba(26,140,255,.15)}
input.ltr,textarea.ltr{text-align:left}
.hint{font-size:12px;color:var(--mut);margin-top:3px}
.hint.err{color:var(--bad-t)}.hint.ok{color:var(--ok-t)}
.seg{display:flex;background:var(--bg2);border:1px solid var(--line);border-radius:12px;padding:3px;gap:3px}
.seg button{flex:1;border:0;background:none;color:var(--mut);padding:9px;border-radius:9px;font:inherit;cursor:pointer}
.seg button.on{background:var(--card);color:var(--txt);box-shadow:0 0 0 1px var(--line)}
.seg button:disabled{cursor:not-allowed}
.sw{display:flex;align-items:center;justify-content:space-between;gap:10px;background:var(--bg2);border:1px solid var(--line);border-radius:10px;padding:9px 11px;margin-bottom:10px;cursor:pointer}
.sw input{width:auto;accent-color:var(--acc);transform:scale(1.25)}
.svc{display:flex;gap:6px;align-items:center;margin-bottom:6px}
.svc input{flex:1}.svc select{width:90px}
.inline{display:flex;gap:6px}
.inline>*:first-child{flex:1}
pre.out{background:var(--code);color:var(--txt);border:1px solid var(--line);border-radius:10px;padding:10px;max-height:60vh;overflow:auto;white-space:pre-wrap;word-break:break-all;direction:ltr;text-align:left;font:12px/1.55 ui-monospace,Menlo,Consolas,monospace;margin:0}
.ov{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:50;display:flex;align-items:flex-end;justify-content:center}
@media(min-width:700px){.ov{align-items:center}}
.md{background:var(--card);border:1px solid var(--line);border-radius:18px 18px 0 0;width:100%;max-width:760px;max-height:92vh;overflow:auto;padding:16px}
@media(min-width:700px){.md{border-radius:18px}}
.mh{display:flex;align-items:center;gap:8px;margin-bottom:12px}
.mh b{flex:1}
.mf{display:flex;gap:8px;justify-content:flex-start;margin-top:14px;flex-wrap:wrap}
#toasts{position:fixed;bottom:16px;left:50%;transform:translateX(-50%);z-index:90;display:flex;flex-direction:column;gap:8px;width:min(92vw,420px)}
.toast{background:var(--toast);color:var(--txt);border:1px solid var(--line);border-inline-start:4px solid var(--acc);border-radius:10px;padding:10px 12px;box-shadow:var(--shadow);animation:in .2s}
.toast.err{border-inline-start-color:var(--bad)}.toast.ok{border-inline-start-color:var(--ok)}
@keyframes in{from{opacity:0;transform:translateY(8px)}}
.login{min-height:100vh;display:grid;place-items:center;padding:20px}
.login .card{width:100%;max-width:360px;padding:24px}
.spin{width:14px;height:14px;border:2px solid rgba(128,128,128,.35);border-top-color:currentColor;border-radius:50%;animation:sp .7s linear infinite}
@keyframes sp{to{transform:rotate(360deg)}}
.bar{height:6px;background:var(--bg2);border-radius:9px;overflow:hidden;margin-top:6px}.bar i{display:block;height:100%;border-radius:9px;background:var(--ok);transition:width .6s}
.bk{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:10px 0;border-bottom:1px solid var(--line)}.bk:last-child{border-bottom:0}.bk .n{flex:1;min-width:180px}
.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
.toolbar input{flex:1;min-width:180px}
.seg.wrap{flex-wrap:wrap}.seg.wrap button{flex:1 1 30%;min-width:96px}
.seg.sm button{padding:6px 12px;font-size:13px}
.b-bh{background:rgba(26,140,255,.14);color:var(--info-t)}
.b-cdn{background:rgba(245,158,11,.15);color:var(--warn)}
.mut{color:var(--mut)}
.btn.ghost{background:none;border-color:transparent;color:var(--mut)}
.btn.sq{padding:7px 10px}
.btn.more{margin-inline-start:auto;font-size:16px;line-height:1;padding:5px 12px;border-color:var(--line)}
.tcard{transition:border-color .2s}
.tcard.down{border-color:rgba(239,68,68,.45)}
.morebox{display:none;margin-top:8px}
.tcard.open .morebox{display:block}
.acts.sub{border-top:1px dashed var(--line)}
input.mustchange{border-color:var(--warn);background:rgba(245,158,11,.06)}
.bad,input.bad{border-color:var(--bad)!important;box-shadow:0 0 0 3px rgba(239,68,68,.15)}
#svcList.bad{border:1px solid var(--bad);border-radius:10px;padding:6px}
.ferr{color:var(--bad-t);font-size:12px;margin-top:4px}
.savebar{position:sticky;bottom:0;display:flex;gap:8px;align-items:center;flex-wrap:wrap;background:linear-gradient(transparent,var(--bg) 30%);padding:18px 0 12px;margin-top:14px;z-index:5}
.banner{background:rgba(239,68,68,.1);border-bottom:1px solid rgba(239,68,68,.35);color:var(--bad-t);font-size:12.5px;text-align:center;padding:6px 12px}
.banner a{color:inherit;font-weight:700;cursor:pointer;text-decoration:underline}
.card h4{margin:0 0 6px;font-size:14px}
.guide details{background:var(--card);border:1px solid var(--line);border-radius:var(--r);margin-bottom:10px}
.guide summary{cursor:pointer;padding:12px 14px;font-weight:700;list-style:none;display:flex;align-items:center;gap:8px}
.guide summary::-webkit-details-marker{display:none}
.guide .gb{padding:0 14px 14px;font-size:13.5px}
.guide .gb h4{margin:12px 0 4px;font-size:13.5px;color:var(--info-t)}
.guide ul{margin:4px 0;padding-inline-start:20px}.guide li{margin:3px 0}
.guide table{width:100%;border-collapse:collapse;font-size:12.5px;margin:6px 0}
.guide th,.guide td{border:1px solid var(--line);padding:6px;text-align:start;vertical-align:top}
.guide th{background:var(--bg2)}
.guide code{direction:ltr;unicode-bidi:embed;background:var(--bg2);padding:1px 5px;border-radius:5px;font-size:12px}
.tag-ok{color:var(--ok-t)}.tag-no{color:var(--bad-t)}
.audit-item{display:flex;gap:8px;align-items:flex-start;padding:8px 0;border-bottom:1px solid var(--line)}
.audit-item:last-child{border-bottom:0}
.warnbox{background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.35);color:var(--warn-t);border-radius:10px;padding:9px 11px;font-size:13px;margin-bottom:12px}
</style>
</head>
<body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true"><symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></symbol><symbol id="i-eye" viewBox="0 0 24 24"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></symbol><symbol id="i-copy" viewBox="0 0 24 24"><rect x="8" y="8" width="14" height="14" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></symbol><symbol id="i-refresh" viewBox="0 0 24 24"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/></symbol><symbol id="i-x" viewBox="0 0 24 24"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></symbol><symbol id="i-check" viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5"/></symbol><symbol id="i-alert" viewBox="0 0 24 24"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/></symbol><symbol id="i-info" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></symbol><symbol id="i-menu" viewBox="0 0 24 24"><path d="M4 6h16"/><path d="M4 12h16"/><path d="M4 18h16"/></symbol><symbol id="i-more" viewBox="0 0 24 24"><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/></symbol><symbol id="i-chevUp" viewBox="0 0 24 24"><path d="m18 15-6-6-6 6"/></symbol><symbol id="i-chevDown" viewBox="0 0 24 24"><path d="m6 9 6 6 6-6"/></symbol><symbol id="i-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></symbol><symbol id="i-moon" viewBox="0 0 24 24"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></symbol><symbol id="i-logout" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/></symbol><symbol id="i-plus" viewBox="0 0 24 24"><path d="M5 12h14"/><path d="M12 5v14"/></symbol><symbol id="i-book" viewBox="0 0 24 24"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></symbol><symbol id="i-compass" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="m16.24 7.76-2.12 6.36-6.36 2.12 2.12-6.36 6.36-2.12z"/></symbol><symbol id="i-link" viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></symbol><symbol id="i-cloud" viewBox="0 0 24 24"><path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"/></symbol><symbol id="i-wrench" viewBox="0 0 24 24"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></symbol><symbol id="i-checklist" viewBox="0 0 24 24"><path d="m3 17 2 2 4-4"/><path d="m3 7 2 2 4-4"/><path d="M13 6h8"/><path d="M13 12h8"/><path d="M13 18h8"/></symbol><symbol id="i-lock" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></symbol><symbol id="i-layers" viewBox="0 0 24 24"><path d="M12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83Z"/><path d="m22 17.65-9.17 4.16a2 2 0 0 1-1.66 0L2 17.65"/><path d="m22 12.65-9.17 4.16a2 2 0 0 1-1.66 0L2 12.65"/></symbol><symbol id="i-network" viewBox="0 0 24 24"><rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/><path d="M12 12V8"/></symbol><symbol id="i-cpu" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6" rx="1"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/></symbol><symbol id="i-archive" viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="5" rx="1"/><path d="M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8"/><path d="M10 12h4"/></symbol><symbol id="i-sliders" viewBox="0 0 24 24"><path d="M4 21v-7"/><path d="M4 10V3"/><path d="M12 21v-9"/><path d="M12 8V3"/><path d="M20 21v-5"/><path d="M20 12V3"/><path d="M2 14h4"/><path d="M10 8h4"/><path d="M18 16h4"/></symbol><symbol id="i-edit" viewBox="0 0 24 24"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></symbol><symbol id="i-activity" viewBox="0 0 24 24"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></symbol><symbol id="i-play" viewBox="0 0 24 24"><path d="M6 3l14 9-14 9V3z"/></symbol><symbol id="i-stop" viewBox="0 0 24 24"><rect x="5" y="5" width="14" height="14" rx="2"/></symbol><symbol id="i-radio" viewBox="0 0 24 24"><path d="M4.9 19.1C1 15.2 1 8.8 4.9 4.9"/><path d="M7.8 16.2c-2.3-2.3-2.3-6.1 0-8.5"/><circle cx="12" cy="12" r="2"/><path d="M16.2 7.8c2.3 2.3 2.3 6.1 0 8.5"/><path d="M19.1 4.9C23 8.8 23 15.1 19.1 19"/></symbol><symbol id="i-clock" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></symbol><symbol id="i-file" viewBox="0 0 24 24"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="M9 13h6"/><path d="M9 17h6"/></symbol><symbol id="i-trash" viewBox="0 0 24 24"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2"/></symbol><symbol id="i-terminal" viewBox="0 0 24 24"><path d="m4 17 6-6-6-6"/><path d="M12 19h8"/></symbol><symbol id="i-down" viewBox="0 0 24 24"><path d="M12 5v14"/><path d="m19 12-7 7-7-7"/></symbol><symbol id="i-up" viewBox="0 0 24 24"><path d="M12 19V5"/><path d="m5 12 7-7 7 7"/></symbol><symbol id="i-download" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/></symbol><symbol id="i-upload" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5"/><path d="M12 3v12"/></symbol></svg>

<div id="loginView" class="login hidden">
  <form class="card" id="loginForm" autocomplete="on">
    <div style="display:flex;gap:10px;align-items:center;margin-bottom:18px">
      <img class="logo" alt="NETIFAY" src="data:image/png;base64,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"><div><div class="htitle">NETIFAY</div><div class="hsub">پنل مدیریت تانل</div></div><div class="grow"></div><button type="button" class="btn sm langBtn"></button><button type="button" class="btn sm themeBtn" title="تغییر تم روز / شب"></button>
    </div>
    <label class="f"><span>نام کاربری</span><input class="ltr" name="user" autocomplete="username" required></label>
    <label class="f"><span>رمز عبور</span><input class="ltr" name="password" type="password" autocomplete="current-password" required></label>
    <button class="btn p" style="width:100%;padding:10px">ورود</button>
    <div class="hint err hidden" id="loginHttp" style="margin-top:10px"><svg class="ic sm"><use href="#i-alert"/></svg> این اتصال HTTP است و رمز رمزنگاری نمی‌شود. بعد از ورود، HTTPS را از تنظیمات روشن کنید یا از SSH tunnel استفاده کنید.</div>
  </form>
</div>

<div id="app" class="hidden">
  <header>
    <div class="hbar">
      <img class="logo" alt="NETIFAY" src="data:image/png;base64,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">
      <div class="hname"><div class="htitle">NETIFAY</div><div class="hsub ltr" id="hostName" style="text-align:right"></div></div><span class="curTab" id="curTab"></span>
      <div class="grow"></div>
      <button class="btn sm langBtn"></button>
      <button class="btn sm themeBtn" title="تغییر تم روز / شب"></button>
      <button class="btn sm" id="refreshBtn" title="بروزرسانی"></button>
      <button class="btn sm" id="logoutBtn" title="خروج"></button>
      <button class="btn sm" id="menuBtn" title="منو" aria-label="منو" aria-expanded="false" aria-controls="nav"></button>
    </div>
    <nav id="nav">
      <button data-tab="tunnels" class="on">تانل‌ها</button>
      <button data-tab="form">ساخت تانل</button>
      <button data-tab="core">هسته</button>
      <button data-tab="backup">بکاپ</button>
      <button data-tab="guide">راهنما</button>
      <button data-tab="settings">تنظیمات</button>
    </nav>
  </header>
  <div class="navBack" id="navBack"></div>
  <main>
    <div class="secbar hidden" id="secBar"></div>
    <section id="tab-tunnels"></section>
    <section id="tab-form" class="hidden"></section>
    <section id="tab-core" class="hidden"></section>
    <section id="tab-backup" class="hidden"></section>
    <section id="tab-guide" class="hidden"></section>
    <section id="tab-settings" class="hidden"></section>
  </main>
</div>
<div id="toasts"></div>

<script nonce="__NONCE__">
/* ---- i18n (fa / en) ---- */
let LANG='fa';try{LANG=localStorage.getItem('nf-lang')==='en'?'en':'fa'}catch(e){}
const EN={"پیش‌فرض 0 (خاموش؛ قطعی را TCP keepalive تشخیص می‌دهد). اگر روشن می‌کنید، سمت خارج باید بیشتر از ایران باشد (مثلا ایران 30، خارج 40).":"Default 0 (off; dead connections are detected by TCP keepalive). If you turn it on, the abroad side must be larger than Iran (e.g. Iran 30, abroad 40).","پیش‌فرض 0 (خاموش). اگر روشن می‌کنید، باید از مقدار سمت ایران بیشتر باشد، نه مساوی (ایران 30 → خارج 40). دو طرف 0 هم درست است.":"Default 0 (off). If you turn it on, it must be larger than the Iran value, not equal (Iran 30 \u2192 abroad 40). Both sides 0 is also fine.","حذف هسته":"Remove core","از این سرور حذف شود؟":"be removed from this server?","فقط فایل اجرایی هسته پاک می‌شود. اگر تانلی از این هسته استفاده کند، حذف انجام نمی‌شود.":"Only the core binary is deleted. If any tunnel uses this core, it is not removed.","هسته حذف شد":"Core removed","اتصال تا خارج: ":"Reaches abroad: ","برقرار":"yes","برقرار نشد":"no"," همه موارد همین لحظه بررسی می‌شوند؛ سمت ایران برای هر پورت یک اتصال آزمایشی تا سرور خارج زده می‌شود.":" Everything is checked right now; on the Iran side a test connection is made through the tunnel to the abroad server for each port.","سمت ایران: بررسی می‌شود که تانل هر پورت وصل است، پورت باز است و اتصال تا سرویس سمت خارج می‌رسد.":"Iran side: checks that each port's tunnel is connected, the port is open, and a connection reaches the service abroad.","فایل <span class=\"ltr\">rathole.zip</span> یا خود باینری <span class=\"ltr\">rathole</span> را آپلود کنید (روی Ubuntu 20.04 نسخه musl). این هسته باید روی هر دو سرور نصب باشد.":"Upload <span class=\"ltr\">rathole.zip</span> or the <span class=\"ltr\">rathole</span> binary itself (musl build on Ubuntu 20.04). This core must be installed on both servers.","آپلود و نصب":"Upload & install","دانلود از مخزن NETIFAY":"Download from NETIFAY repository","نسخه سازگار با این سرور خودکار انتخاب می‌شود. سرور باید به github.com دسترسی داشته باشد.":"The build compatible with this server is picked automatically. The server needs access to github.com.","HTTPS (TLS) فعال نیست؛ رمز و کوکی پنل بدون رمزنگاری ارسال می‌شوند.":"HTTPS (TLS) is off; the panel password and cookie are sent unencrypted.","مسیر مخفی پنل تنظیم نشده است.":"No secret path is set for the panel.","بعد از تمام شدن کانفیگ‌ها، دسترسی وب از بیرون را از تنظیمات ببندید.":"When you finish configuring, close external web access in Settings.","امنیت پنل:":"Panel security:","رفتن به تنظیمات":"Go to Settings","پیشنهاد ما برای بیشتر سرورها: Rathole روی لینک GRE":"Our pick for most servers: Rathole over a GRE link","سبک، کم‌مصرف و پایدار است و در همین پنل بیشتر از همه آزموده شده. اگر مطمئن نیستید از همین شروع کنید؛ اگر دیتاسنتر GRE را بسته بود، همان Rathole را روی IPIP یا 6to4 بسازید. برای شرایط خاص جدول زیر را ببینید.":"Light, low on resources and stable, and the most tested engine in this panel. If unsure, start here; if the datacenter blocks GRE, build the same Rathole over IPIP or 6to4. See the table below for special cases."," — پورت‌های سرویس هم باید جدید باشند؛ روی یک سرور هر پورت فقط در یک تانل استفاده می‌شود":" \u2014 the service ports must be new too; on one server each port can be used by one tunnel only","تم شب": "Dark theme", "تم روز": "Light theme", "بدون ری‌استارت خودکار": "No auto restart", "هر 30 دقیقه": "Every 30 minutes", "هر 1 ساعت": "Every 1 hour", "هر 2 ساعت": "Every 2 hours", "هر 4 ساعت": "Every 4 hours", "هر 6 ساعت": "Every 6 hours", "هر 12 ساعت": "Every 12 hours", "هر 24 ساعت": "Every 24 hours", " روز ": "d ", " ساعت ": "h ", " دقیقه": "m", "ارتباط با سرور قطع است": "Connection to the server is lost", "پاسخ نامعتبر از سرور (": "Invalid response from server (", "دوباره وارد شوید": "Please log in again", "خطا": "Error", "</b><button class=\"btn sm\" data-x title=\"بستن\">": "</b><button class=\"btn sm\" data-x title=\"Close\">", "ویرایش تانل": "Edit tunnel", "ساخت تانل": "New tunnel", "<div class=\"toolbar\"><input id=\"tSearch\" class=\"ltr\" placeholder=\"جستجو: پورت، دامنه، IP…\" autocomplete=\"off\">": "<div class=\"toolbar\"><input id=\"tSearch\" class=\"ltr\" placeholder=\"Search: port, domain, IP…\" autocomplete=\"off\">", "<div class=\"seg sm\" id=\"tFilter\"><button data-f=\"all\" class=\"on\">همه</button><button data-f=\"iran\">ایران</button><button data-f=\"kharej\">خارج</button><button data-f=\"bad\">مشکل‌دار</button></div>": "<div class=\"seg sm\" id=\"tFilter\"><button data-f=\"all\" class=\"on\">All</button><button data-f=\"iran\">Iran</button><button data-f=\"kharej\">Abroad</button><button data-f=\"bad\">Problems</button></div>", "<select id=\"tEng\" style=\"width:auto\"><option value=\"\">همه موتورها</option>": "<select id=\"tEng\" style=\"width:auto\"><option value=\"\">All engines</option>", "<button class=\"btn\" id=\"tAudit\" title=\"بررسی تداخل پورت، IP و لینک بین همه تانل‌ها\">": "<button class=\"btn\" id=\"tAudit\" title=\"Check port, IP and link conflicts across all tunnels\">", "بررسی تداخل‌ها</button>": "Check conflicts</button>", "تانل جدید</button></div><div id=\"tGrid\"></div>": "New tunnel</button></div><div id=\"tGrid\"></div>", "<div class=\"stat\"><span>تانل‌های فعال</span><b style=\"color:": "<div class=\"stat\"><span>Active tunnels</span><b style=\"color:", "<div class=\"stat\"><span>هسته‌های نصب‌شده</span><b style=\"font-size:12.5px;line-height:1.9\">": "<div class=\"stat\"><span>Installed cores</span><b style=\"font-size:12.5px;line-height:1.9\">", " هسته)": " cores)", "رم": "RAM", "دیسک": "Disk", "<div class=\"stat\"><span>آپتایم سرور</span><b style=\"font-size:13px\">": "<div class=\"stat\"><span>Server uptime</span><b style=\"font-size:13px\">", "<div class=\"warnbox\">هیچ هسته‌ای نصب نیست. از تب «هسته» rathole یا Backhaul را نصب کنید.</div>": "<div class=\"warnbox\">No core is installed. Install rathole or Backhaul from the «Core» tab.</div>", "</div>هنوز تانلی ساخته نشده.<br><br><button class=\"btn p\" data-a=\"new\">": "</div>No tunnels yet.<br><br><button class=\"btn p\" data-a=\"new\">", "ساخت اولین تانل</button></div>": "Create your first tunnel</button></div>", "<div class=\"card empty\">تانلی با این فیلتر پیدا نشد.</div>": "<div class=\"card empty\">No tunnel matches this filter.</div>", "فعال": "Active", "در حال اتصال": "Connecting", "متوقف": "Stopped", "<span class=\"pill\">مستقیم</span>": "<span class=\"pill\">Direct</span>", "<dt>فوروارد به</dt><dd class=\"ltr\">": "<dt>Forward to</dt><dd class=\"ltr\">", "مقصد": "Target", "گوش دادن": "Listen", "<dt>دامنه CDN</dt><dd class=\"ltr\">": "<dt>CDN domain</dt><dd class=\"ltr\">", "<dt>اتصال</dt><dd>": "<dt>Connection</dt><dd>", "بدون TLS": "no TLS", "<dt>این سرور</dt><dd class=\"ltr\">": "<dt>This server</dt><dd class=\"ltr\">", "<dt>سرور مقابل</dt><dd class=\"ltr\">": "<dt>Peer server</dt><dd class=\"ltr\">", "<dt>IP داخلی</dt><dd class=\"ltr\">": "<dt>Inner IP</dt><dd class=\"ltr\">", "<dt>ترافیک</dt><dd class=\"ltr\">": "<dt>Traffic</dt><dd class=\"ltr\">", "<dt>ترنسپورت</dt><dd class=\"ltr\">": "<dt>Transport</dt><dd class=\"ltr\">", "<dt>اینترفیس</dt><dd class=\"ltr\">": "<dt>Interface</dt><dd class=\"ltr\">", "<dt>تنظیمات</dt><dd>": "<dt>Settings</dt><dd>", "بدون NoDelay": "no NoDelay", "<dt>ری‌استارت</dt><dd>": "<dt>Restart</dt><dd>", " بار ری‌استارت شده": " restarts", "کلون</button>": "Clone</button>", "تست پینگ</button><button class=\"btn sm\" data-a=\"gre\">": "Ping test</button><button class=\"btn sm\" data-a=\"gre\">", "لاگ</button>": "Logs</button>", "زمان‌بندی</button>": "Schedule</button>", "فایل کانفیگ</button>": "Config file</button>", "حذف</button></div>": "Delete</button></div>", "ایران": "Iran", "خارج": "Abroad", "<b>پورت <span class=\"ltr\">": "<b>Port <span class=\"ltr\">", "<div class=\"hint err\">اسکریپت لینک این تانل پیدا نشد؛ با «ویرایش» و ذخیره دوباره ساخته می‌شود.</div>": "<div class=\"hint err\">This tunnel's link script is missing; it is rebuilt by «Edit» and save.</div>", "ویرایش</button>": "Edit</button>", "تست پورت‌ها</button>": "Test ports</button>", "<button class=\"btn sm\" data-a=\"restart\" title=\"ری‌استارت\">": "<button class=\"btn sm\" data-a=\"restart\" title=\"Restart\">", "ری‌استارت</button>": "Restart</button>", "<button class=\"btn sm\" data-a=\"stop\" title=\"توقف\">": "<button class=\"btn sm\" data-a=\"stop\" title=\"Stop\">", "توقف</button>": "Stop</button>", "شروع</button>": "Start</button>", "<button class=\"btn sm ghost more\" data-a=\"more\" title=\"گزینه‌های بیشتر\">": "<button class=\"btn sm ghost more\" data-a=\"more\" title=\"More options\">", "انجام شد": "Done", "پینگ داخل لینک ": "Ping inside link ", " لینک شبکه برقرار است": " Network link is up", " پاسخی نیامد (لینک، فایروال یا مسدود بودن پروتکل GRE=47 / IPIP=4 / 6to4=41 را چک کنید)": " No reply (check the link, firewall, or whether protocol GRE=47 / IPIP=4 / 6to4=41 is blocked)", "اطلاعات لینک ": "Link info ", "ری‌استارت خودکار ": "Auto restart ", "<label class=\"f\"><span>بازه</span><select id=\"cronSel\">": "<label class=\"f\"><span>Interval</span><select id=\"cronSel\">", "</select></label><div class=\"hint\">فقط همین تانل ری‌استارت می‌شود و بقیه تانل‌ها قطع نمی‌شوند.</div>": "</select></label><div class=\"hint\">Only this tunnel is restarted; other tunnels are not interrupted.</div>", "ذخیره": "Save", "ذخیره شد": "Saved", "اسکریپت ": "Script ", " (فقط خواندنی)": " (read only)", "<div class=\"warnbox\">این اسکریپت از تنظیمات تانل ساخته می‌شود؛ برای تغییر از «ویرایش» استفاده کنید.</div><pre class=\"out\">": "<div class=\"warnbox\">This script is generated from the tunnel settings; use «Edit» to change it.</div><pre class=\"out\">", "ویرایش مستقیم کانفیگ ": "Edit config directly ", "<div class=\"warnbox\">ویرایش پیشرفته. نسخه قبلی با پسوند .bak ذخیره می‌شود و بعد از ذخیره سرویس ری‌استارت می‌شود.": "<div class=\"warnbox\">Advanced editing. The previous version is kept with a .bak extension and the service restarts after saving.", " توجه: این فایل از تنظیمات تانل ساخته می‌شود و با «ویرایش» فرم دوباره بازنویسی می‌شود.": " Note: this file is generated from the tunnel settings and is rewritten when you save the «Edit» form.", "ذخیره و ری‌استارت": "Save & restart", "ذخیره شد ولی: ": "Saved, but: ", "حذف تانل": "Delete tunnel", "<p>تانل <b class=\"ltr\">": "<p>Delete tunnel <b class=\"ltr\">", "</b> همراه با سرویس، اینترفیس لینک <span class=\"ltr\">": "</b> together with its service, link interface <span class=\"ltr\">", "</span>، کرون‌ها و فایل‌هایش حذف شود؟</p>": "</span>, cron jobs and files?</p>", "بله، حذف شود": "Yes, delete", "حذف شد": "Deleted", "انصراف": "Cancel", "<div class=\"stat\"><span>سرویس تانل</span><b style=\"color:": "<div class=\"stat\"><span>Tunnel service</span><b style=\"color:", "<div class=\"stat\"><span>اتصال‌های تانل": "<div class=\"stat\"><span>Tunnel connections", "<div class=\"stat\"><span>لینک تا <span class=\"ltr\">": "<div class=\"stat\"><span>Link to <span class=\"ltr\">", "وصل": "Up", "قطع": "Down", "<div class=\"stat\"><span>پورت‌های سالم</span><b style=\"color:": "<div class=\"stat\"><span>Healthy ports</span><b style=\"color:", "<div class=\"warnbox\">لینک شبکه قطع است؛ تا لینک وصل نشود هیچ پورتی کار نمی‌کند (دامنه‌ها، فایروال یا مسدود بودن پروتکل لینک در دیتاسنتر را چک کنید؛ می‌توانید نوع لینک را عوض کنید).</div>": "<div class=\"warnbox\">The network link is down; no port works until the link is up (check the domains, the firewall, or whether the datacenter blocks the link protocol; you can switch the link type).</div>", "خطای توکن": "Token error", "پورت در طرف مقابل نیست": "Port missing on peer", "لاگی نیست": "No logs", "تانل: ": "Tunnel: ", "باز روی ایران: ": "Open on Iran: ", "بله": "Yes", "خیر": "No", "سرویس محلی: ": "Local service: ", "جواب می‌دهد": "responds", "بسته است": "closed", " سالم</div>": " OK</div>", "تست پورت‌های ": "Port test of ", "سمت ایران: بررسی می‌شود که تانل هر پورت وصل است و rathole آن را باز کرده.": "Iran side: checks that the tunnel for each port is connected and rathole has opened it.", "سمت خارج: بررسی می‌شود که تانل هر پورت وصل است و سرویس اصلی (مثلا Xray) روی این سرور به آن پورت جواب می‌دهد.": "Abroad side: checks that the tunnel for each port is connected and the main service (e.g. Xray) on this server answers on that port.", " «اتصال‌های تانل» تعداد اتصال‌های برقرار بین دو سرور روی پورت تانل است.": " «Tunnel connections» is the number of established connections between the two servers on the tunnel port.", " وضعیت تانل از لاگ 15 دقیقه اخیر خوانده می‌شود.": " Tunnel status is read from the last 15 minutes of logs.", "تست دوباره": "Test again", "لاگ ": "Logs ", "\">سرویس تانل</button><button data-k=\"gre\" class=\"": "\">Tunnel service</button><button data-k=\"gre\" class=\"", "\">لینک</button></div><pre class=\"out\" id=\"logOut\">": "\">Link</button></div><pre class=\"out\" id=\"logOut\">", "بروزرسانی": "Refresh", "آخرین عدد نباید ": "The last number must not be ", " باشد (آدرس شبکه/برادکست). مثلا ": " (network/broadcast address). e.g. ", " یا ": " or ", "ویرایش تانل <span class=\"ltr\">": "Edit tunnel <span class=\"ltr\">", "کلون از <span class=\"ltr\">": "Clone of <span class=\"ltr\">", "ساخت تانل جدید": "Create new tunnel", "<div class=\"warnbox\">همه تنظیمات و پورت‌های سرویس از <b class=\"ltr\">": "<div class=\"warnbox\">All settings and service ports were copied from <b class=\"ltr\">", "</b> کپی شد. برای ذخیره باید این‌ها را عوض کنید: <b>پورت تانل</b>، ": "</b>. To save, change these: <b>tunnel port</b>, ", "<b>دامنه CDN</b>": "<b>CDN domain</b>", "<b>آدرس سرور مقابل</b>": "<b>peer server address</b>", "(در حالت مستقیم این سمت فقط پورت)": "(in direct mode, only the port on this side)", "<b>دامنه سرور مقابل</b> و <b>IP داخلی GRE</b>": "<b>peer server domain</b> and <b>GRE inner IP</b>", " (با رنگ زرد مشخص شده‌اند).</div>": " (highlighted in yellow).</div>", "<div class=\"seg\" id=\"roleSeg\"><button type=\"button\" data-r=\"iran\">سرور ایران</button><button type=\"button\" data-r=\"kharej\">سرور خارج</button></div>": "<div class=\"seg\" id=\"roleSeg\"><button type=\"button\" data-r=\"iran\">Iran server</button><button type=\"button\" data-r=\"kharej\">Abroad server</button></div>", "<div class=\"seg\" id=\"modeSeg\"><button type=\"button\" data-m=\"gre\">لینک شبکه</button><button type=\"button\" data-m=\"direct\">مستقیم</button><button type=\"button\" data-m=\"cdn\">CDN کلادفلر</button></div>": "<div class=\"seg\" id=\"modeSeg\"><button type=\"button\" data-m=\"gre\">Network link</button><button type=\"button\" data-m=\"direct\">Direct</button><button type=\"button\" data-m=\"cdn\">Cloudflare CDN</button></div>", "<div class=\"row\"><label class=\"f\"><span id=\"lPort\">پورت تانل</span><input class=\"ltr": "<div class=\"row\"><label class=\"f\"><span id=\"lPort\">Tunnel port</span><input class=\"ltr", " placeholder=\"پورت جدید\"": " placeholder=\"New port\"", "پورت تانل قابل تغییر نیست؛ برای تغییر، تانل جدید بسازید.": "The tunnel port cannot be changed; create a new tunnel instead.", "باید در هر دو سرور یکی باشد.": "Must be the same on both servers.", "<label class=\"f\" id=\"tokWrap\"><span>توکن امنیتی</span><div class=\"inline\"><input class=\"ltr\" name=\"token\" type=\"password\" autocomplete=\"off\" spellcheck=\"false\" value=\"": "<label class=\"f\" id=\"tokWrap\"><span>Security token</span><div class=\"inline\"><input class=\"ltr\" name=\"token\" type=\"password\" autocomplete=\"off\" spellcheck=\"false\" value=\"", "\"><button type=\"button\" class=\"btn sq\" id=\"eyeTok\" title=\"نمایش\">": "\"><button type=\"button\" class=\"btn sq\" id=\"eyeTok\" title=\"Show\">", "</button><button type=\"button\" class=\"btn sq\" id=\"copyTok\" title=\"کپی\">": "</button><button type=\"button\" class=\"btn sq\" id=\"copyTok\" title=\"Copy\">", "</button><button type=\"button\" class=\"btn\" id=\"genTok\">تصادفی</button></div><div class=\"hint\">باید در هر دو سرور یکی باشد.</div></label></div>": "</button><button type=\"button\" class=\"btn\" id=\"genTok\">Random</button></div><div class=\"hint\">Must be the same on both servers.</div></label></div>", "<div id=\"cdnSec\"><h3>تنظیمات CDN کلادفلر</h3>": "<div id=\"cdnSec\"><h3>Cloudflare CDN settings</h3>", "<label class=\"f\"><span>دامنه پروکسی‌شده (رکورد A به IP سرور ایران، ابر نارنجی روشن)</span><input class=\"ltr": "<label class=\"f\"><span>Proxied domain (A record to the Iran server IP, orange cloud on)</span><input class=\"ltr", "\"><div class=\"hint\">در هر دو سرور همین دامنه را وارد کنید.</div></label>": "\"><div class=\"hint\">Enter the same domain on both servers.</div></label>", "<label class=\"sw\" id=\"cdnTlsWrap\"><span>TLS (wss) <span class=\"hint\">(پیشنهادی؛ ترافیک داخل ایران رمزنگاری می‌شود)</span></span><input type=\"checkbox\" name=\"cdn_tls\"": "<label class=\"sw\" id=\"cdnTlsWrap\"><span>TLS (wss) <span class=\"hint\">(recommended; traffic inside Iran is encrypted)</span></span><input type=\"checkbox\" name=\"cdn_tls\"", "<div id=\"directSec\"><h3>اتصال مستقیم</h3>": "<div id=\"directSec\"><h3>Direct connection</h3>", "<label class=\"f\" id=\"rhWrap\"><span id=\"lRh\">آدرس سرور ایران (دامنه یا IP)</span><input class=\"ltr": "<label class=\"f\" id=\"rhWrap\"><span id=\"lRh\">Iran server address (domain or IP)</span><input class=\"ltr", "<div id=\"greSec\"><h3>تنظیمات لینک شبکه (بر اساس دامنه)</h3>": "<div id=\"greSec\"><h3>Network link settings (domain based)</h3>", "<label class=\"f\"><span>نوع لینک (هر دو سرور یکی)</span><select name=\"link\">": "<label class=\"f\"><span>Link type (same on both servers)</span><select name=\"link\">", "GRE (پروتکل 47)": "GRE (protocol 47)", "IPIP (پروتکل 4)": "IPIP (protocol 4)", "6to4 / SIT (پروتکل 41، IPv6 داخلی)": "6to4 / SIT (protocol 41, inner IPv6)", "\"><button type=\"button\" class=\"btn\" id=\"sugNet\" title=\"اولین شبکه آزاد را پیشنهاد بده\">پیشنهاد</button></div><div class=\"hint\" id=\"greHint\"></div></label>": "\"><button type=\"button\" class=\"btn\" id=\"sugNet\" title=\"Suggest the first free network\">Suggest</button></div><div class=\"hint\" id=\"greHint\"></div></label>", "<label class=\"f\" id=\"peerWrap\"><span>IP داخلی سرور ایران</span><input class=\"ltr\" name=\"peer_ip\" placeholder=\"خودکار\" value=\"": "<label class=\"f\" id=\"peerWrap\"><span>Iran server inner IP</span><input class=\"ltr\" name=\"peer_ip\" placeholder=\"Auto\" value=\"", "\"><div class=\"hint\">خالی بگذارید تا خودکار حساب شود.</div></label>": "\"><div class=\"hint\">Leave empty to calculate it automatically.</div></label>", "<div id=\"frpSec\" class=\"esec\"><h3>تنظیمات FRP</h3><div class=\"row\">": "<div id=\"frpSec\" class=\"esec\"><h3>FRP settings</h3><div class=\"row\">", "<label class=\"f\"><span>پروتکل (هر دو سرور یکی)</span><select name=\"protocol\">": "<label class=\"f\"><span>Protocol (same on both servers)</span><select name=\"protocol\">", "</select><div class=\"hint\">kcp و quic روی UDP هستند؛ برای لینک‌های پرافت.</div></label>": "</select><div class=\"hint\">kcp and quic run over UDP; for lossy links.</div></label>", "<label class=\"f fr-kh\"><span>Pool count (اتصال‌های آماده)</span><input class=\"ltr\" name=\"pool\" inputmode=\"numeric\" value=\"": "<label class=\"f fr-kh\"><span>Pool count (ready connections)</span><input class=\"ltr\" name=\"pool\" inputmode=\"numeric\" value=\"", "<label class=\"sw\"><span>TCP Mux (هر دو سرور یکی)</span><input type=\"checkbox\" name=\"tcp_mux\"": "<label class=\"sw\"><span>TCP Mux (same on both servers)</span><input type=\"checkbox\" name=\"tcp_mux\"", "<div id=\"gostSec\" class=\"esec\"><h3>تنظیمات Gost</h3><label class=\"f\"><span>ترنسپورت (هر دو سرور یکی)</span><select name=\"gtransport\">": "<div id=\"gostSec\" class=\"esec\"><h3>Gost settings</h3><label class=\"f\"><span>Transport (same on both servers)</span><select name=\"gtransport\">", "</select><div class=\"hint\">mtls / mwss = چندتایی‌سازی؛ ws/wss قابل عبور از CDN؛ kcp/quic روی UDP.</div></label></div>": "</select><div class=\"hint\">mtls / mwss = multiplexing; ws/wss pass through CDNs; kcp/quic run over UDP.</div></label></div>", "<div id=\"hySec\" class=\"esec\"><h3>تنظیمات Hysteria2</h3><label class=\"f\"><span>رمز Obfs (اختیاری، هر دو سرور یکی)</span><input class=\"ltr\" name=\"obfs\" value=\"": "<div id=\"hySec\" class=\"esec\"><h3>Hysteria2 settings</h3><label class=\"f\"><span>Obfs password (optional, same on both servers)</span><input class=\"ltr\" name=\"obfs\" value=\"", "\" placeholder=\"خالی = بدون obfs\"><div class=\"hint\">obfs (salamander) ترافیک QUIC را مبهم می‌کند. گواهی سمت خارج خودکار ساخته می‌شود. پورت تانل UDP است.</div></label></div>": "\" placeholder=\"empty = no obfs\"><div class=\"hint\">obfs (salamander) obscures QUIC traffic. The abroad-side certificate is created automatically. The tunnel port is UDP.</div></label></div>", "<div id=\"xrSec\" class=\"esec\"><h3>تنظیمات Xray Reverse</h3><div class=\"row\">": "<div id=\"xrSec\" class=\"esec\"><h3>Xray Reverse settings</h3><div class=\"row\">", "<label class=\"f\"><span>امنیت اتصال</span><select name=\"xsec\"><option value=\"reality\" selected>REALITY</option></select><div class=\"hint\">نسخه‌های جدید Xray اتصال VLESS بدون رمزنگاری را مسدود می‌کنند؛ فقط REALITY.</div></label>": "<label class=\"f\"><span>Connection security</span><select name=\"xsec\"><option value=\"reality\" selected>REALITY</option></select><div class=\"hint\">Newer Xray versions block unencrypted VLESS; REALITY only.</div></label>", "<label class=\"f\"><span>SNI (هر دو سرور یکی)</span><input class=\"ltr\" name=\"sni\" value=\"": "<label class=\"f\"><span>SNI (same on both servers)</span><input class=\"ltr\" name=\"sni\" value=\"", "<div class=\"hint\">UUID و کلیدهای REALITY خودکار از توکن ساخته می‌شوند؛ کافی است توکن دو طرف یکی باشد. هسته xray باید روی هر دو سرور نصب باشد.</div></div>": "<div class=\"hint\">UUID and REALITY keys are derived from the token automatically; the token just has to match on both sides. The xray core must be installed on both servers.</div></div>", "<div id=\"bhSec\"><h3>تنظیمات Backhaul</h3>": "<div id=\"bhSec\"><h3>Backhaul settings</h3>", "<div class=\"row\"><label class=\"f\"><span>ترنسپورت (هر دو سرور یکی)</span><select name=\"transport\">": "<div class=\"row\"><label class=\"f\"><span>Transport (same on both servers)</span><select name=\"transport\">", "<label class=\"f\"><span>Keepalive (ثانیه)</span><input class=\"ltr\" name=\"keepalive\" inputmode=\"numeric\" value=\"": "<label class=\"f\"><span>Keepalive (seconds)</span><input class=\"ltr\" name=\"keepalive\" inputmode=\"numeric\" value=\"", "<label class=\"f\"><span>Dial timeout (ثانیه)</span><input class=\"ltr\" name=\"dial_timeout\" inputmode=\"numeric\" value=\"": "<label class=\"f\"><span>Dial timeout (seconds)</span><input class=\"ltr\" name=\"dial_timeout\" inputmode=\"numeric\" value=\"", "<div class=\"row\"><label class=\"f bh-mux\"><span>Mux version (هر دو سرور یکی)</span><select name=\"mux_version\"><option": "<div class=\"row\"><label class=\"f bh-mux\"><span>Mux version (same on both servers)</span><select name=\"mux_version\"><option", "<label class=\"f bh-kh bh-ws\"><span>Edge IP کلادفلر (اختیاری)</span><input class=\"ltr\" name=\"edge_ip\" placeholder=\"188.114.96.0\" value=\"": "<label class=\"f bh-kh bh-ws\"><span>Cloudflare Edge IP (optional)</span><input class=\"ltr\" name=\"edge_ip\" placeholder=\"188.114.96.0\" value=\"", "<div id=\"commonSec\"><h3 id=\"rhTitle\">تنظیمات rathole</h3>": "<div id=\"commonSec\"><h3 id=\"rhTitle\">rathole settings</h3>", "<label class=\"f\" id=\"retryWrap\"><span>Retry interval (ثانیه)</span><input class=\"ltr\" name=\"retry\" inputmode=\"numeric\" value=\"": "<label class=\"f\" id=\"retryWrap\"><span>Retry interval (seconds)</span><input class=\"ltr\" name=\"retry\" inputmode=\"numeric\" value=\"", "<label class=\"sw\"><span>TCP_NODELAY <span class=\"hint\">(تاخیر کمتر، پهنای باند کمی کمتر)</span></span><input type=\"checkbox\" name=\"nodelay\"": "<label class=\"sw\"><span>TCP_NODELAY <span class=\"hint\">(lower latency, slightly less bandwidth)</span></span><input type=\"checkbox\" name=\"nodelay\"", "<label class=\"sw\" id=\"v6Wrap\"><span>گوش دادن روی IPv6 <span class=\"ltr\">[::]</span></span><input type=\"checkbox\" name=\"ipv6\"": "<label class=\"sw\" id=\"v6Wrap\"><span>Listen on IPv6 <span class=\"ltr\">[::]</span></span><input type=\"checkbox\" name=\"ipv6\"", "<h3>پورت‌های سرویس</h3>": "<h3>Service ports</h3>", "افزودن</button></div>": "Add</button></div>", "<div class=\"hint\">چند پورت را با کاما جدا کنید. پورت‌ها باید در هر دو سرور یکی باشند.</div>": "<div class=\"hint\">Separate multiple ports with commas. Ports must be the same on both servers.</div>", "ذخیره تغییرات": "Save changes", "ساخت کلون": "Create clone", "<button type=\"button\" class=\"btn\" id=\"cancelEdit\">انصراف</button>": "<button type=\"button\" class=\"btn\" id=\"cancelEdit\">Cancel</button>", "سرور ایران: پورت‌های سرویس روی این سرور باز می‌شوند و کاربران به آن وصل می‌شوند.": "Iran server: the service ports are opened on this server and users connect to it.", "سرور خارج: سرویس اصلی (مثلا Xray) روی این سرور است و تانل از این سرور به سرور ایران وصل می‌شود.": "Abroad server: the main service (e.g. Xray) runs on this server and the tunnel connects from here to the Iran server.", "دامنه همین سرور (": "This server's domain (", "دامنه سرور مقابل (": "Peer server domain (", "IP داخلی همین سرور (": "This server's inner IP (", "Heartbeat interval (ثانیه)": "Heartbeat interval (seconds)", "Heartbeat timeout (ثانیه)": "Heartbeat timeout (seconds)", "0 = خاموش. مقدار سمت خارج باید از این بیشتر باشد (پیش‌فرض: ایران 30، خارج 40).": "0 = off. The abroad-side value must be larger than this (default: Iran 30, abroad 40).", "0 = خاموش. باید از مقدار سمت ایران بیشتر باشد، نه مساوی (ایران 30 → خارج 40).": "0 = off. Must be larger than the Iran-side value, not equal (Iran 30 → abroad 40).", "Rathole: خارج به ایران وصل می‌شود (معکوس). روی لینک GRE/IPIP/6to4.": "Rathole: abroad connects to Iran (reverse). Over a GRE/IPIP/6to4 link.", "Backhaul: خارج به ایران وصل می‌شود؛ tcp / tcpmux / ws / wss و CDN کلادفلر.": "Backhaul: abroad connects to Iran; tcp / tcpmux / ws / wss and Cloudflare CDN.", "FRP: خارج (frpc) به ایران (frps) وصل می‌شود؛ پروتکل tcp / kcp / quic / websocket.": "FRP: abroad (frpc) connects to Iran (frps); protocol tcp / kcp / quic / websocket.", "Gost: ایران به خارج وصل می‌شود (رله)؛ tls / mtls / ws / wss / grpc / kcp / quic …": "Gost: Iran connects to abroad (relay); tls / mtls / ws / wss / grpc / kcp / quic …", "Hysteria2: ایران به خارج وصل می‌شود؛ روی QUIC/UDP، مناسب لینک‌های پرافت.": "Hysteria2: Iran connects to abroad; over QUIC/UDP, good for lossy links.", "Xray Reverse: خارج (bridge) به ایران (portal) وصل می‌شود؛ با REALITY مخفی‌ترین گزینه. فقط TCP.": "Xray Reverse: abroad (bridge) connects to Iran (portal); with REALITY the stealthiest option. TCP only.", "iptables: فوروارد مستقیم کرنل بدون برنامه تانل؛ کمترین سربار. فقط روی سرور ایران ساخته می‌شود (در حالت لینک، سمت خارج فقط لینک).": "iptables: direct kernel forwarding with no tunnel program; lowest overhead. Only created on the Iran server (in link mode the abroad side only needs the link).", " هسته ": " The ", " باید روی هر دو سرور نصب باشد.": " core must be installed on both servers.", "تنظیمات عمومی": "General settings", "تنظیمات rathole": "rathole settings", "شماره تانل": "Tunnel number", "پورت تانل": "Tunnel port", "فقط برای نام‌گذاری (10 تا 65535)؛ پورتی باز نمی‌شود.": "For naming only (10 to 65535); no port is opened.", "پورت UDP تانل؛ باید در هر دو سرور یکی باشد.": "UDP tunnel port; must be the same on both servers.", "ساده و کم‌سربار؛ پشتیبانی از UDP.": "Simple and low overhead; supports UDP.", "چندتایی‌سازی؛ برای لینک/مستقیم با تعداد کانکشن زیاد (پیشنهادی).": "Multiplexing; for link/direct with many connections (recommended).", "WebSocket؛ قابل عبور از CDN.": "WebSocket; passes through CDNs.", "WebSocket + TLS؛ گواهی سمت ایران خودکار ساخته می‌شود.": "WebSocket + TLS; the Iran-side certificate is created automatically.", "WebSocket + TLS + mux؛ بهترین گزینه برای CDN کلادفلر.": "WebSocket + TLS + mux; the best option for Cloudflare CDN.", "Heartbeat سرور Backhaul (ثانیه، حداقل 1). پیش‌فرض 40.": "Backhaul server heartbeat (seconds, minimum 1). Default 40.", "Heartbeat (ثانیه)": "Heartbeat (seconds)", "آدرس سرور ": "Address of the ", " (دامنه یا IP)": " server (domain or IP)", "پورت‌های سرویس روی این سرور به همین آدرس فوروارد می‌شوند.": "Service ports on this server are forwarded to this address.", "برای عبور از کلادفلر با ws/wss، دامنه‌ی پروکسی‌شده را وارد کنید.": "To go through Cloudflare with ws/wss, enter the proxied domain.", "این سرور روی همه آدرس‌ها روی پورت تانل گوش می‌دهد و سرور ": "This server listens on all addresses on the tunnel port and the ", " به آن وصل می‌شود؛ پورت تانل را در فایروال باز کنید.": " server connects to it; open the tunnel port in the firewall.", "اتصال مستقیم: سرور ": "Direct connection: ", "ایران مستقیم به خارج": "Iran connects directly to abroad", "خارج مستقیم به ایران": "abroad connects directly to Iran", " وصل می‌شود؛ لینک شبکه ساخته نمی‌شود.": "; no network link is created.", "Backhaul از طریق کلادفلر: سرور خارج با WebSocket (پیشنهادی wssmux) به دامنه کلادفلر وصل می‌شود؛ لینک شبکه ساخته نمی‌شود و IP سرور ایران پشت کلادفلر مخفی می‌ماند.": "Backhaul via Cloudflare: the abroad server connects over WebSocket (wssmux recommended) to the Cloudflare domain; no network link is created and the Iran server IP stays hidden behind Cloudflare.", "CDN قدیمی rathole (فقط ویرایش). برای تانل جدید از Backhaul استفاده کنید.": "Legacy rathole CDN (edit only). Use Backhaul for new tunnels.", "تانل داخل GRE بین دو سرور ساخته می‌شود.": "The tunnel runs inside a GRE link between the two servers.", "پورت‌های مجاز کلادفلر ": "Cloudflare allowed ports ", "با TLS": "with TLS", "، ": ", ", " — نباید با پورت‌های سرویس یکی باشد.": " — must not be one of the service ports.", "<b>تنظیمات کلادفلر:</b><br>• رکورد A دامنه به IP سرور <b>ایران</b> با ابر نارنجی (Proxied) روشن.<br>• Network ← WebSockets روشن باشد.<br>": "<b>Cloudflare settings:</b><br>• A record of the domain to the <b>Iran</b> server IP with the orange cloud (Proxied) on.<br>• Network ← WebSockets on.<br>", "• SSL/TLS ← حالت <b>Full</b> (نه Strict). گواهی سمت ایران خودکار ساخته می‌شود.": "• SSL/TLS ← <b>Full</b> mode (not Strict). The Iran-side certificate is created automatically.", "• «Always Use HTTPS» خاموش باشد، وگرنه اتصال برقرار نمی‌شود.": "• «Always Use HTTPS» must be off, otherwise the connection fails.", "<br>• فایروال سرور ایران باید پورت تانل را برای IPهای کلادفلر باز بگذارد.": "<br>• The Iran server firewall must keep the tunnel port open to Cloudflare IPs.", "<br>• روی سرور خارج می‌توانید یک IP تمیز کلادفلر را در «Edge IP» بگذارید تا اتصال به آن IP برود.<br>• Heartbeat سمت ایران زیر 80 ثانیه بماند (پیش‌فرض 40).": "<br>• On the abroad server you can put a clean Cloudflare IP in «Edge IP» so the connection goes to that IP.<br>• Keep the Iran-side heartbeat under 80 seconds (default 40).", "<br>• Heartbeat حتما روشن بماند (ایران 30، خارج 40)؛ کلادفلر اتصال بیکار را بعد از 100 ثانیه قطع می‌کند.": "<br>• Keep heartbeat on (Iran 30, abroad 40); Cloudflare drops idle connections after 100 seconds.", "پیش‌فرض و رایج. اگر دیتاسنتر GRE را بست، IPIP یا 6to4 را امتحان کنید.": "Default and most common. If the datacenter blocks GRE, try IPIP or 6to4.", "سبک‌تر از GRE (سربار 20 بایت). بعضی دیتاسنترها که GRE را می‌بندند IPIP را باز می‌گذارند.": "Lighter than GRE (20 bytes overhead). Some datacenters that block GRE leave IPIP open.", "IPv6 داخل IPv4. آدرس داخلی IPv6 خودکار از IP داخلی ساخته می‌شود. (برای iptables قابل استفاده نیست)": "IPv6 inside IPv4. The inner IPv6 address is derived from the inner IP automatically. (Not usable with iptables)", "برای هر تانل یک شبکه جدا بدهید (مثلا 10.10.1.1، تانل بعدی 10.10.2.1).": "Give each tunnel its own network (e.g. 10.10.1.1, next tunnel 10.10.2.1).", "IPv4 نامعتبر": "Invalid IPv4", "شبکه ": "Network ", " قبلا برای ": " is already used by ", " استفاده شده!": "!", " · IP داخلی سرور ": " · Inner IP of the ", " باید ": " server must be ", " باشد": "", " · IPv6 داخلی: ": " · Inner IPv6: ", "<div class=\"hint\">هنوز پورتی اضافه نشده.</div>": "<div class=\"hint\">No ports added yet.</div>", "\" title=\"حذف\">": "\" title=\"Remove\">", "بازه حداکثر 200 پورت": "Range of at most 200 ports", "پورت ": "Port ", " نامعتبر است": " is invalid", " پورت اضافه شد": " port(s) added", "کپی شد": "Copied", "کپی نشد": "Copy failed", "شبکه آزادی پیدا نشد": "No free network found", "پورت تانل را وارد کنید": "Enter the tunnel port", " را وارد کنید": ": enter it", "دامنه CDN را وارد کنید": "Enter the CDN domain", "دامنه همین سرور را وارد کنید": "Enter this server's domain", "دامنه سرور مقابل را وارد کنید": "Enter the peer server domain", "IP داخلی را وارد کنید": "Enter the inner IP", "توکن را وارد کنید": "Enter the token", " فقط پورت tcp را پشتیبانی می‌کند": " supports tcp ports only", "حداقل یک پورت سرویس اضافه کنید": "Add at least one service port", "پورت تانل کلون باید با ": "The clone's tunnel port must differ from ", " فرق کند": "", "دامنه CDN را تغییر دهید": "Change the CDN domain", "آدرس سرور ایران را تغییر دهید": "Change the Iran server address", "دامنه سرور مقابل را تغییر دهید": "Change the peer server domain", "IP داخلی را به یک شبکه جدید تغییر دهید (دکمه «پیشنهاد»)": "Change the inner IP to a new network («Suggest» button)", "ذخیره شد؛ لینک شبکه دوباره ساخته شد": "Saved; network link rebuilt", "ذخیره شد و سرویس ری‌استارت شد": "Saved and service restarted", "هشدار": "Warning", "تانل ": "Tunnel ", " ساخته شد": " created", "<div class=\"form\"><h2>هسته rathole</h2><div class=\"card\">": "<div class=\"form\"><h2>rathole core</h2><div class=\"card\">", "<dl class=\"kv\"><dt>وضعیت</dt><dd style=\"color:": "<dl class=\"kv\"><dt>Status</dt><dd style=\"color:", "نصب شده": "Installed", "نصب نیست": "Not installed", "<dt>نسخه</dt><dd class=\"ltr\">": "<dt>Version</dt><dd class=\"ltr\">", "</dd><dt>معماری</dt><dd class=\"ltr\">": "</dd><dt>Architecture</dt><dd class=\"ltr\">", "<dt>مسیر</dt><dd class=\"ltr\">": "<dt>Path</dt><dd class=\"ltr\">", "<dt>حجم</dt><dd class=\"ltr\">": "<dt>Size</dt><dd class=\"ltr\">", "<h3>آپلود هسته (پیشنهادی برای سرور ایران)</h3><div class=\"card\">": "<h3>Upload core (recommended for the Iran server)</h3><div class=\"card\">", "<div class=\"hint\" style=\"margin-bottom:8px\">فایل باینری <span class=\"ltr\">rathole</span> یا <span class=\"ltr\">rathole.zip</span> را انتخاب کنید.</div>": "<div class=\"hint\" style=\"margin-bottom:8px\">Choose the <span class=\"ltr\">rathole</span> binary or <span class=\"ltr\">rathole.zip</span>.</div>", "<div class=\"inline\"><input type=\"file\" id=\"coreFile\"><button class=\"btn p\" id=\"upBtn\">آپلود و نصب</button></div></div>": "<div class=\"inline\"><input type=\"file\" id=\"coreFile\"><button class=\"btn p\" id=\"upBtn\">Upload & install</button></div></div>", "<h3>دانلود از مخزن NETIFAY</h3><div class=\"card\"><div class=\"hint\" style=\"margin-bottom:8px\">نسخه سازگار با این سرور خودکار انتخاب می‌شود (روی Ubuntu 20.04 نسخه musl). سرور باید به github.com دسترسی داشته باشد.</div><button class=\"btn\" id=\"dlBtn\">دانلود و نصب</button></div>": "<h3>Download from the NETIFAY repository</h3><div class=\"card\"><div class=\"hint\" style=\"margin-bottom:8px\">The build compatible with this server is picked automatically (musl build on Ubuntu 20.04). The server needs access to github.com.</div><button class=\"btn\" id=\"dlBtn\">Download & install</button></div>", "<h2 style=\"margin-top:28px\">هسته Backhaul</h2><div class=\"card\" id=\"bhCoreBox\"><span class=\"spin\"></span></div>": "<h2 style=\"margin-top:28px\">Backhaul core</h2><div class=\"card\" id=\"bhCoreBox\"><span class=\"spin\"></span></div>", "<h2 style=\"margin-top:28px\">هسته‌های دیگر</h2><div id=\"genCores\"><div class=\"card\"><span class=\"spin\"></span></div></div>": "<h2 style=\"margin-top:28px\">Other cores</h2><div id=\"genCores\"><div class=\"card\"><span class=\"spin\"></span></div></div>", "<h3>اعمال هسته جدید</h3><div class=\"card\"><div class=\"hint\" style=\"margin-bottom:8px\">بعد از تعویض هسته، همه تانل‌ها باید ری‌استارت شوند.</div><button class=\"btn\" id=\"raBtn\">ری‌استارت همه تانل‌ها</button><pre class=\"out hidden\" id=\"raOut\" style=\"margin-top:10px\"></pre></div></div>": "<h3>Apply the new core</h3><div class=\"card\"><div class=\"hint\" style=\"margin-bottom:8px\">After replacing a core, all tunnels must be restarted.</div><button class=\"btn\" id=\"raBtn\">Restart all tunnels</button><pre class=\"out hidden\" id=\"raOut\" style=\"margin-top:10px\"></pre></div></div>", "فایلی انتخاب نشده": "No file selected", "نصب شد: ": "Installed: ", "تانلی نیست": "No tunnels", "frp_X_linux_amd64.tar.gz (شامل frps و frpc)": "frp_X_linux_amd64.tar.gz (contains frps and frpc)", "</h4><dl class=\"kv\"><dt>وضعیت</dt><dd style=\"color:": "</h4><dl class=\"kv\"><dt>Status</dt><dd style=\"color:", "نصب است": "Installed", "</dd><dt>نسخه</dt><dd class=\"ltr\">": "</dd><dt>Version</dt><dd class=\"ltr\">", "<div class=\"hint\">روی سرور بزنید: <span class=\"ltr\">apt install iptables</span></div>": "<div class=\"hint\">Run on the server: <span class=\"ltr\">apt install iptables</span></div>", "ناقص (": "Incomplete (", "</dd><dt>پوشه</dt><dd class=\"ltr\">": "</dd><dt>Folder</dt><dd class=\"ltr\">", "<div class=\"hint\" style=\"margin:6px 0\">فایل: <span class=\"ltr\">": "<div class=\"hint\" style=\"margin:6px 0\">File: <span class=\"ltr\">", "</span> (یا arm64)</div>": "</span> (or arm64)</div>", "<div class=\"inline\"><input type=\"file\" class=\"gcFile\"><button class=\"btn p\" data-gc=\"up\">آپلود</button><button class=\"btn\" data-gc=\"dl\">دانلود از مخزن NETIFAY</button></div></div>": "<div class=\"inline\"><input type=\"file\" class=\"gcFile\"><button class=\"btn p\" data-gc=\"up\">Upload</button><button class=\"btn\" data-gc=\"dl\">Download from NETIFAY repository</button></div></div>", " نصب شد: ": " installed: ", " نصب شد": " installed", " (ناقص: ": " (incomplete: ", "</dd><dt>مسیر</dt><dd class=\"ltr\">": "</dd><dt>Path</dt><dd class=\"ltr\">", "<div class=\"hint\" style=\"margin:8px 0\">فایل <span class=\"ltr\">backhaul_linux_amd64.tar.gz</span> (یا arm64)، zip یا خود باینری <span class=\"ltr\">backhaul</span> را آپلود کنید. این هسته باید روی هر دو سرور نصب باشد.</div>": "<div class=\"hint\" style=\"margin:8px 0\">Upload <span class=\"ltr\">backhaul_linux_amd64.tar.gz</span> (or arm64), a zip, or the <span class=\"ltr\">backhaul</span> binary itself. This core must be installed on both servers.</div>", "<div class=\"inline\"><input type=\"file\" id=\"bhFile\"><button class=\"btn p\" id=\"bhUp\">آپلود و نصب</button></div>": "<div class=\"inline\"><input type=\"file\" id=\"bhFile\"><button class=\"btn p\" id=\"bhUp\">Upload & install</button></div>", "<div style=\"margin-top:10px\"><button class=\"btn\" id=\"bhDl\">دانلود از مخزن NETIFAY</button> <span class=\"hint\">سرور باید به github.com دسترسی داشته باشد.</span></div>": "<div style=\"margin-top:10px\"><button class=\"btn\" id=\"bhDl\">Download from NETIFAY repository</button> <span class=\"hint\">The server needs access to github.com.</span></div>", "Backhaul نصب شد: ": "Backhaul installed: ", "<div class=\"form\"><h2>بکاپ و بازیابی</h2>": "<div class=\"form\"><h2>Backup & restore</h2>", " گرفتن بکاپ</h3><div class=\"card\">": " Create backup</h3><div class=\"card\">", "<div class=\"hint\" style=\"margin-bottom:10px\">فقط <b>کانفیگ تانل‌ها</b> ذخیره می‌شود: همه موتورها، تنظیمات لینک (نوع، دامنه‌ها، IP داخلی، MTU) و زمان‌بندی ری‌استارت. ": "<div class=\"hint\" style=\"margin-bottom:10px\">Only <b>tunnel configs</b> are saved: all engines, link settings (type, domains, inner IP, MTU) and the restart schedule. ", "هسته‌ها داخل بکاپ نیستند (چون برای هر سرور و معماری فرق دارند)؛ روی سرور جدید از تب «هسته» نصبشان کنید.</div>": "Cores are not included (they differ per server and architecture); install them on the new server from the «Core» tab.</div>", "بکاپ بگیر و دانلود کن</button><button class=\"btn\" id=\"bkSave\">": "Back up & download</button><button class=\"btn\" id=\"bkSave\">", "فقط روی سرور ذخیره کن</button></div></div>": "Save on server only</button></div></div>", " بازیابی از فایل</h3><div class=\"card\">": " Restore from file</h3><div class=\"card\">", "<div class=\"hint\" style=\"margin-bottom:8px\">فایل <span class=\"ltr\">.tar.gz</span> بکاپ NETIFAY را انتخاب کنید. بعد از آپلود، لیست تانل‌ها و وضعیت هسته هر کدام را می‌بینید و انتخاب می‌کنید کدام‌ها بازیابی شوند.</div>": "<div class=\"hint\" style=\"margin-bottom:8px\">Choose a NETIFAY backup <span class=\"ltr\">.tar.gz</span> file. After upload you see the list of tunnels and the core status of each, and choose which ones to restore.</div>", "آپلود و بررسی</button></div></div>": "Upload & check</button></div></div>", " بکاپ‌های روی سرور</h3><div class=\"card\" id=\"bkList\">": " Backups on the server</h3><div class=\"card\" id=\"bkList\">", " <span class=\"badge\" style=\"font-size:11px\">خودکار</span>": " <span class=\"badge\" style=\"font-size:11px\">auto</span>", "بازیابی</button><button class=\"btn sm\" data-b=\"dl\" title=\"دانلود\">": "Restore</button><button class=\"btn sm\" data-b=\"dl\" title=\"Download\">", "</button><button class=\"btn sm d\" data-b=\"del\" title=\"حذف\">": "</button><button class=\"btn sm d\" data-b=\"del\" title=\"Delete\">", "<div class=\"hint\">هنوز بکاپی روی سرور نیست.</div>": "<div class=\"hint\">No backups on the server yet.</div>", "<div class=\"hint\" style=\"margin-top:8px\">مسیر: <span class=\"ltr\">": "<div class=\"hint\" style=\"margin-top:8px\">Path: <span class=\"ltr\">", "</span> · بکاپ‌های «خودکار» قبل از هر بازیابی ساخته می‌شوند تا بتوانید برگردید.</div></div></div>": "</span> · «auto» backups are made before every restore so you can go back.</div></div></div>", "بکاپ با ": "Backup created with ", " تانل گرفته شد": " tunnel(s)", "ذخیره شد (": "Saved (", " تانل)": " tunnels)", "فایل بکاپ باید .tar.gz باشد": "The backup file must be .tar.gz", "حجم فایل برای بکاپ تانل‌ها غیرعادی است (بیش از 20MB)": "File size is unusual for a tunnel backup (over 20MB)", "آپلود و بررسی شد": "Uploaded and checked", "حذف بکاپ": "Delete backup", "</p><div class=\"hint\">این فایل برای همیشه پاک می‌شود.</div>": "</p><div class=\"hint\">This file will be deleted permanently.</div>", "حذف": "Delete", "دانلود ناموفق": "Download failed", "آماده": "Ready", "جایگزین تانل فعلی": "Replaces current tunnel", "هسته نصب نیست": "Core not installed", "نام تکراری": "Name taken", "خراب / ناقص": "Broken / incomplete", "<dl class=\"kv\"><dt>سرور مبدا</dt><dd class=\"ltr\">": "<dl class=\"kv\"><dt>Source server</dt><dd class=\"ltr\">", "</dd><dt>تاریخ</dt><dd>": "</dd><dt>Date</dt><dd>", "<dt>نسخه پنل</dt><dd class=\"ltr\">": "<dt>Panel version</dt><dd class=\"ltr\">", "</dd><dt>تعداد تانل</dt><dd>": "</dd><dt>Tunnels</dt><dd>", "این تانل‌ها به هسته‌ای نیاز دارند که روی این سرور نصب نیست و تا نصب نشود بازیابی نمی‌شوند: ": "These tunnels need a core that is not installed on this server, and cannot be restored until it is: ", "رفتن به تب هسته</button></div></div>": "Go to the Core tab</button></div></div>", " این بکاپ قدیمی هسته هم دارد؛ هسته‌های داخل بکاپ نادیده گرفته می‌شوند و فقط تانل‌ها بازیابی می‌شوند.</div>": " This old backup also contains a core; cores inside backups are ignored and only tunnels are restored.</div>", "<div class=\"inline\" style=\"justify-content:space-between;margin:12px 0 4px\"><b>تانل‌ها</b><span><button type=\"button\" class=\"btn sm\" id=\"rAll\">همه</button> <button type=\"button\" class=\"btn sm\" id=\"rNone\">هیچ</button></span></div>": "<div class=\"inline\" style=\"justify-content:space-between;margin:12px 0 4px\"><b>Tunnels</b><span><button type=\"button\" class=\"btn sm\" id=\"rAll\">All</button> <button type=\"button\" class=\"btn sm\" id=\"rNone\">None</button></span></div>", "<div class=\"hint\">این بکاپ تانلی ندارد.</div>": "<div class=\"hint\">This backup has no tunnels.</div>", "<div class=\"hint\" style=\"margin-top:8px\">تانل‌هایی که انتخاب نشوند یا در بکاپ نیستند دست نمی‌خورند. قبل از بازیابی، از وضعیت فعلی خودکار بکاپ گرفته می‌شود؛ ": "<div class=\"hint\" style=\"margin-top:8px\">Tunnels that are not selected or not in the backup are left untouched. Before restoring, the current state is backed up automatically; ", "اگر تانلی با تانل دیگری روی این سرور تداخل پورت/لینک داشته باشد، بازیابی همان تانل لغو و نسخه قبلی‌اش برگردانده می‌شود.</div>": "if a tunnel conflicts (port/link) with another tunnel on this server, restoring that tunnel is cancelled and its previous version is put back.</div>", "بازیابی بکاپ": "Restore backup", "بازیابی تانل‌های انتخاب‌شده": "Restore selected tunnels", "هیچ تانلی انتخاب نشده": "No tunnel selected", "بازیابی انجام شد؛ ": "Restore done; ", " تانل ناموفق": " tunnel(s) failed", "بازیابی انجام شد (": "Restore done (", "تایید: ": "Confirm: replace ", " تانل فعلی جایگزین شود": " current tunnel(s)", "تانل‌های ": "Tunnels ", " روی همین نام‌ها جایگزین می‌شوند؛ برای ادامه دوباره بزنید": " will be replaced under the same names; press again to continue", "بستن": "Close", " اعمال شده": " applied", "اعمال نشده": "Not applied", "<dt>کنترل ازدحام</dt><dd class=\"ltr\">": "<dt>Congestion control</dt><dd class=\"ltr\">", "<div class=\"hint\" style=\"margin-bottom:10px\">BBR + fq، بافرهای بزرگ‌تر TCP/UDP، صف اتصال بیشتر، حد فایل‌های باز بالا و فعال کردن ip_forward. برای سرورهای تانل با کاربر زیاد پیشنهاد می‌شود. روی هر دو سرور اعمال کنید.</div>": "<div class=\"hint\" style=\"margin-bottom:10px\">BBR + fq, larger TCP/UDP buffers, a longer connection queue, a high open-files limit and ip_forward enabled. Recommended for tunnel servers with many users. Apply on both servers.</div>", "اعمال دوباره": "Apply again", "اعمال بهینه‌سازی": "Apply optimization", "<button class=\"btn d\" id=\"optOff\">برگرداندن</button>": "<button class=\"btn d\" id=\"optOff\">Revert</button>", "بهینه‌سازی اعمال شد": "Optimization applied", "بررسی تداخل‌ها (": "Conflict check (", " مشکل جدی · ": " serious issue(s) · ", " هشدار</div>": " warning(s)</div>", "<div class=\"hint\" style=\"margin-top:8px\">بررسی می‌شود: پورت‌های تکراری بین تانل‌ها (حتی تانل‌های قطع)، پورت‌هایی که برنامه دیگری گرفته، تداخل با پورت پنل، شبکه داخلی تکراری یا هم‌پوشان با اینترفیس‌های سرور، دو لینک هم‌نوع به یک سرور، هسته نصب‌نشده و سرویس غیرفعال. روی هر دو سرور اجرا کنید.</div>": "<div class=\"hint\" style=\"margin-top:8px\">Checked: duplicate ports between tunnels (even disconnected ones), ports taken by other programs, clashes with the panel port, duplicate inner networks or overlaps with server interfaces, two links of the same type to one server, missing cores and inactive services. Run it on both servers.</div>", "بررسی دوباره": "Check again", "راهنمای تداخل‌ها": "Conflict guide", "</p><table><tr><th>جهت اتصال</th><td>": "</p><table><tr><th>Direction</th><td>", "</td></tr><tr><th>حالت‌ها</th><td>": "</td></tr><tr><th>Modes</th><td>", "</td></tr><tr><th>ترنسپورت / پروتکل</th><td>": "</td></tr><tr><th>Transport / protocol</th><td>", "</td></tr><tr><th>پورت باز لازم</th><td>": "</td></tr><tr><th>Open port needed</th><td>", "<h4>مزایا</h4><ul>": "<h4>Pros</h4><ul>", "</ul><h4>معایب / محدودیت‌ها</h4><ul>": "</ul><h4>Cons / limits</h4><ul>", "<h4>کی استفاده کنیم</h4><p>": "<h4>When to use</h4><p>", "</p><h4>نکات تنظیم</h4><ul>": "</p><h4>Tuning tips</h4><ul>", "<div class=\"form guide\"><h2>راهنمای کامل NETIFAY</h2>": "<div class=\"form guide\"><h2>NETIFAY complete guide</h2>", " مفاهیم پایه": " Basics", "<ul><li><b>سرور ایران:</b> کاربران به این سرور وصل می‌شوند؛ «پورت‌های سرویس» (مثلا 2070، 8443) روی این سرور باز می‌شوند.</li>": "<ul><li><b>Iran server:</b> users connect to this server; the «service ports» (e.g. 2070, 8443) are opened on it.</li>", "<li><b>سرور خارج:</b> سرویس اصلی (مثلا Xray / پنل فروش) روی این سرور است؛ تانل ترافیک را از ایران به همان پورت‌ها روی خارج می‌رساند.</li>": "<li><b>Abroad server:</b> the main service (e.g. Xray / sales panel) runs on this server; the tunnel carries traffic from Iran to the same ports on it.</li>", "<li><b>پورت تانل:</b> پورتی که دو سرور از طریق آن به هم وصل می‌شوند (کاربر با آن کاری ندارد). باید در هر دو سرور یکی باشد.</li>": "<li><b>Tunnel port:</b> the port the two servers use to connect to each other (users never touch it). Must be the same on both servers.</li>", "<li><b>پورت‌های سرویس:</b> همان پورت‌های کانفیگ‌های کاربران. در هر دو سرور باید یکی باشند.</li>": "<li><b>Service ports:</b> the ports of your users' configs. Must be the same on both servers.</li>", "<li><b>توکن:</b> رمز مشترک دو طرف تانل. اگر فرق کند خطای «Incorrect token» یا عدم اتصال می‌گیرید.</li>": "<li><b>Token:</b> the shared secret of both tunnel ends. If they differ you get «Incorrect token» or no connection.</li>", "<li><b>جهت اتصال:</b> در بعضی موتورها «خارج به ایران» وصل می‌شود (معکوس؛ وقتی ورودی ایران بسته است مفید است) و در بعضی «ایران به خارج».</li>": "<li><b>Direction:</b> some engines connect «abroad to Iran» (reverse; useful when inbound to Iran is blocked) and some «Iran to abroad».</li>", "<li><b>نوع اتصال:</b> <b>لینک شبکه</b> (یک اینترفیس مجازی GRE/IPIP/6to4 بین دو سرور که تانل داخلش می‌رود)، <b>مستقیم</b> (بدون لینک، روی IP/دامنه عمومی) یا <b>CDN کلادفلر</b> (فقط Backhaul).</li>": "<li><b>Connection type:</b> <b>network link</b> (a virtual GRE/IPIP/6to4 interface between the two servers that the tunnel runs inside), <b>direct</b> (no link, over the public IP/domain) or <b>Cloudflare CDN</b> (Backhaul only).</li>", "<li><b>IP داخلی:</b> در حالت لینک، هر تانل یک شبکه /30 جدا دارد (مثلا 10.10.1.1 ایران و 10.10.1.2 خارج). تانل بعدی: 10.10.2.x.</li></ul>": "<li><b>Inner IP:</b> in link mode each tunnel has its own /30 network (e.g. 10.10.1.1 Iran and 10.10.1.2 abroad). Next tunnel: 10.10.2.x.</li></ul>", " کدام تانل را انتخاب کنم؟": " Which tunnel should I choose?", "<table><tr><th>شرایط شما</th><th>پیشنهاد</th></tr>": "<table><tr><th>Your situation</th><th>Recommendation</th></tr>", "<tr><td>شروع کار، پایدار و ساده</td><td>Rathole یا Backhaul (tcpmux) روی لینک GRE</td></tr>": "<tr><td>Getting started, stable and simple</td><td>Rathole or Backhaul (tcpmux) over a GRE link</td></tr>", "<tr><td>کاربر و کانکشن خیلی زیاد</td><td>Backhaul با tcpmux یا FRP با tcpMux</td></tr>": "<tr><td>Very many users and connections</td><td>Backhaul with tcpmux or FRP with tcpMux</td></tr>", "<tr><td>دیتاسنتر GRE را بسته</td><td>همان موتور روی لینک IPIP یا 6to4، یا حالت مستقیم</td></tr>": "<tr><td>Datacenter blocks GRE</td><td>The same engine over an IPIP or 6to4 link, or direct mode</td></tr>", "<tr><td>می‌خواهید IP سرور ایران مخفی بماند / عبور از CDN</td><td>Backhaul حالت CDN کلادفلر با wssmux</td></tr>": "<tr><td>Keep the Iran server IP hidden / go through a CDN</td><td>Backhaul in Cloudflare CDN mode with wssmux</td></tr>", "<tr><td>لینک پرافت و نویزی بین دو سرور</td><td>Hysteria2، یا FRP با kcp/quic</td></tr>": "<tr><td>Lossy, noisy link between the two servers</td><td>Hysteria2, or FRP with kcp/quic</td></tr>", "<tr><td>بیشترین مخفی‌کاری در برابر فیلترینگ</td><td>Xray Reverse (REALITY)</td></tr>": "<tr><td>Maximum stealth against filtering</td><td>Xray Reverse (REALITY)</td></tr>", "<tr><td>کمترین سربار، بدون برنامه اضافه</td><td>iptables روی لینک GRE/IPIP</td></tr>": "<tr><td>Lowest overhead, no extra program</td><td>iptables over a GRE/IPIP link</td></tr>", "<tr><td>ورودی سرور ایران محدود است ولی ایران می‌تواند به خارج وصل شود</td><td>Gost یا Hysteria2 (ایران به خارج)</td></tr>": "<tr><td>Inbound to the Iran server is limited but Iran can reach abroad</td><td>Gost or Hysteria2 (Iran to abroad)</td></tr>", "<tr><td>ورودی خارج به ایران آزاد است</td><td>Rathole / Backhaul / FRP / Xray (خارج به ایران)</td></tr></table>": "<tr><td>Inbound from abroad to Iran is open</td><td>Rathole / Backhaul / FRP / Xray (abroad to Iran)</td></tr></table>", "<p class=\"hint\">قاعده طلایی: روی هر دو سرور یک تانل آزمایشی با یکی دو پورت بسازید، «تست پورت‌ها» را بزنید و بعد پورت‌های اصلی را اضافه کنید.</p>": "<p class=\"hint\">Golden rule: build a test tunnel with one or two ports on both servers, press «Test ports», then add your real ports.</p>", "<h3>موتورهای تانل</h3>": "<h3>Tunnel engines</h3>", "تانل معکوس سبک و سریع نوشته‌شده با Rust. همان موتور اسکریپت قبلی.": "A light, fast reverse tunnel written in Rust. The same engine as the original script.", "خارج ← ایران (خارج وصل می‌شود)": "Abroad → Iran (abroad connects)", "لینک شبکه (GRE / IPIP / 6to4)": "Network link (GRE / IPIP / 6to4)", "TCP (داخل لینک)": "TCP (inside the link)", "<span class=\"tag-ok\">دارد</span>": "<span class=\"tag-ok\">Yes</span>", "ایران: پورت تانل روی IP داخلی لینک": "Iran: tunnel port on the link's inner IP", "مصرف رم و CPU کم، تاخیر کم": "Low RAM and CPU use, low latency", "پایدار و آزموده‌شده در همین پنل": "Stable and well tested in this panel", "سازگار با فایل‌های اسکریپت قبلی": "Compatible with the original script's files", "نسخه 0.5.0 روی Ubuntu 20.04 کتابخانه libssl.so.3 ندارد (پنل خودکار نسخه musl را نصب می‌کند)": "Version 0.5.0 lacks libssl.so.3 on Ubuntu 20.04 (the panel installs the musl build automatically)", "هر اتصال کاربر یک کانکشن جدید بین دو سرور می‌سازد": "Every user connection creates a new connection between the two servers", "گزینه پیش‌فرض برای بیشتر سرورها.": "The default choice for most servers.", "<b>Heartbeat:</b> سمت خارج باید <u>بیشتر</u> از سمت ایران باشد (ایران 30، خارج 40) یا هر دو 0. مساوی بودن باعث قطع و وصل مداوم و خطای <code>early eof</code> می‌شود.": "<b>Heartbeat:</b> the abroad side must be <u>larger</u> than the Iran side (Iran 30, abroad 40) or both 0. Equal values cause constant reconnects and <code>early eof</code> errors.", "TCP_NODELAY را روشن نگه دارید (تاخیر کمتر).": "Keep TCP_NODELAY on (lower latency).", "نسخه هسته در دو سرور یکی باشد.": "Use the same core version on both servers.", "تانل معکوس با Go که برای تعداد کانکشن بالا و عبور از CDN طراحی شده.": "A Go reverse tunnel designed for many connections and for passing through CDNs.", "خارج ← ایران": "Abroad → Iran", "لینک شبکه، مستقیم، CDN کلادفلر": "Network link, direct, Cloudflare CDN", "tcp، tcpmux، ws، wss، wsmux، wssmux": "tcp, tcpmux, ws, wss, wsmux, wssmux", "فقط با ترنسپورت tcp": "only with the tcp transport", "ایران: پورت تانل": "Iran: tunnel port", "tcpmux/wsmux: چند صد کاربر روی چند کانکشن ثابت (کانکشن کمتر بین دو سرور)": "tcpmux/wsmux: hundreds of users over a few fixed connections (fewer connections between the servers)", "تنها موتور با حالت CDN کلادفلر و Edge IP": "The only engine with Cloudflare CDN mode and Edge IP", "گزینه‌های تنظیم زیاد (pool، mux، keepalive)": "Lots of tuning options (pool, mux, keepalive)", "تنظیمات بیشتر؛ ترنسپورت و mux_version باید دو طرف یکی باشد": "More settings; transport and mux_version must match on both sides", "UDP فقط روی tcp": "UDP only over tcp", "کاربر زیاد، یا نیاز به CDN / مخفی کردن IP ایران.": "Many users, or you need a CDN / to hide the Iran IP.", "برای لینک/مستقیم: tcpmux. برای CDN: wssmux.": "For link/direct: tcpmux. For CDN: wssmux.", "در CDN، Heartbeat سمت ایران زیر 80 ثانیه.": "With CDN, keep the Iran-side heartbeat under 80 seconds.", "Connection pool سمت خارج را برای کاربر زیاد 16 تا 32 کنید.": "For many users set the abroad-side connection pool to 16–32.", "یکی از قدیمی‌ترین و پرکاربردترین ابزارهای تانل معکوس (frps روی ایران، frpc روی خارج).": "One of the oldest and most widely used reverse tunnel tools (frps on Iran, frpc on abroad).", "خارج (frpc) ← ایران (frps)": "Abroad (frpc) → Iran (frps)", "لینک شبکه، مستقیم": "Network link, direct", "tcp، kcp، quic، websocket": "tcp, kcp, quic, websocket", "ایران: پورت تانل (برای kcp/quic به صورت UDP)": "Iran: tunnel port (UDP for kcp/quic)", "بسیار پخته و پایدار": "Very mature and stable", "tcpMux و Pool اتصال‌های آماده": "tcpMux and a pool of ready connections", "kcp و quic برای لینک‌های پرافت": "kcp and quic for lossy links", "پورت‌های سرویس فقط وقتی باز می‌شوند که frpc وصل باشد": "Service ports open only while frpc is connected", "سربار کمی بیشتر از rathole": "Slightly more overhead than rathole", "وقتی پایداری و پختگی مهم است یا لینک پرافت دارید (kcp/quic).": "When stability and maturity matter, or the link is lossy (kcp/quic).", "پروتکل و TCP Mux باید دو طرف یکی باشند.": "Protocol and TCP Mux must match on both sides.", "Pool count سمت خارج را برای کاربر زیاد بالاتر ببرید (16+).": "For many users raise the abroad-side pool count (16+).", "ابزار رله منعطف با ترنسپورت‌های زیاد. ایران پورت‌ها را می‌گیرد و از طریق رله به خارج می‌فرستد.": "A flexible relay with many transports. Iran takes the ports and relays them to abroad.", "ایران ← خارج (ایران وصل می‌شود)": "Iran → abroad (Iran connects)", "tls، mtls، ws، wss، mwss، grpc، h2، tcp، kcp، quic": "tls, mtls, ws, wss, mwss, grpc, h2, tcp, kcp, quic", "خارج: پورت تانل": "Abroad: tunnel port", "تنوع ترنسپورت بسیار زیاد": "A very wide range of transports", "mtls/mwss چندتایی‌سازی دارند": "mtls/mwss support multiplexing", "ws/wss قابل عبور از CDN": "ws/wss pass through CDNs", "جهت ایران به خارج؛ اگر خروجی ایران محدود باشد مشکل‌ساز است": "Iran-to-abroad direction; a problem if outbound traffic from Iran is restricted", "وقتی سرور خارج پورت ورودی آزاد دارد و می‌خواهید ترنسپورت خاصی (tls/grpc/…) را امتحان کنید.": "When the abroad server has an open inbound port and you want to try a specific transport (tls/grpc/…).", "ترنسپورت دو طرف باید یکی باشد.": "The transport must match on both sides.", "در حالت مستقیم، آدرس سرور خارج را روی سرور ایران وارد می‌کنید.": "In direct mode you enter the abroad server address on the Iran server.", "تانل روی QUIC (UDP) با کنترل ازدحام مخصوص لینک‌های پرافت. ایران کلاینت است و پورت‌ها را فوروارد می‌کند.": "A tunnel over QUIC (UDP) with congestion control made for lossy links. Iran is the client and forwards the ports.", "ایران ← خارج": "Iran → abroad", "خارج: پورت تانل UDP": "Abroad: UDP tunnel port", "سرعت بالا روی لینک‌های پرافت و دور": "High speed on lossy, long-distance links", "obfs برای مبهم کردن QUIC": "obfs to obscure QUIC", "اگر UDP/QUIC در مسیر محدود شود ضعیف می‌شود": "Weak if UDP/QUIC is throttled on the path", "«اتصال‌های تانل» در تست پورت قابل شمارش نیست (UDP)": "«Tunnel connections» cannot be counted in the port test (UDP)", "وقتی TCP بین دو سرور کند یا پرافت است ولی UDP آزاد است.": "When TCP between the servers is slow or lossy but UDP is open.", "رمز Obfs اختیاری است ولی دو طرف باید یکی باشد.": "The obfs password is optional but must match on both sides.", "پورت تانل UDP را در فایروال سرور خارج باز کنید.": "Open the UDP tunnel port in the abroad server's firewall.", "قابلیت reverse هسته Xray: خارج (bridge) به ایران (portal) با VLESS + REALITY وصل می‌شود.": "The reverse feature of the Xray core: abroad (bridge) connects to Iran (portal) with VLESS + REALITY.", "VLESS + REALITY (روی TCP)": "VLESS + REALITY (over TCP)", "<span class=\"tag-no\">ندارد</span> (فقط TCP)": "<span class=\"tag-no\">No</span> (TCP only)", "ترافیک بین دو سرور شبیه TLS عادی به یک سایت معتبر است": "Traffic between the servers looks like normal TLS to a reputable site", "کلیدها خودکار از توکن ساخته می‌شوند": "Keys are derived from the token automatically", "فقط TCP": "TCP only", "سربار بیشتر از rathole": "More overhead than rathole", "وقتی ترافیک بین دو سرور شناسایی و محدود می‌شود و مخفی‌کاری مهم است.": "When traffic between the servers is detected and throttled and stealth matters.", "SNI و توکن دو طرف باید یکی باشند.": "SNI and token must match on both sides.", "نسخه‌های جدید Xray اتصال بدون رمزنگاری را مسدود می‌کنند؛ پنل همیشه REALITY می‌سازد.": "Newer Xray versions block unencrypted connections; the panel always builds REALITY.", "فوروارد پورت در خود کرنل لینوکس (DNAT) بدون هیچ برنامه تانل.": "Port forwarding inside the Linux kernel (DNAT) with no tunnel program.", "ایران ← خارج (فوروارد مستقیم)": "Iran → abroad (direct forwarding)", "لینک شبکه (GRE/IPIP)، مستقیم": "Network link (GRE/IPIP), direct", "هیچ (فوروارد بسته‌ها)": "None (packet forwarding)", "کمترین تاخیر و سربار": "Lowest latency and overhead", "هیچ هسته‌ای لازم نیست": "No core needed", "رمزنگاری یا مبهم‌سازی ندارد": "No encryption or obfuscation", "در حالت مستقیم، اگر ارتباط ایران به خارج روی آن پورت فیلتر باشد کار نمی‌کند": "In direct mode it fails if Iran-to-abroad traffic on that port is filtered", "با 6to4 کار نمی‌کند": "Does not work with 6to4", "روی لینک GRE/IPIP وقتی فقط سرعت مهم است.": "Over a GRE/IPIP link when only speed matters.", "فقط سرور ایران ساخته می‌شود؛ در حالت لینک، سمت خارج فقط یک تانل لینک (هر موتوری یا iptables) لازم دارد.": "Created on the Iran server only; in link mode the abroad side just needs a link tunnel (any engine or iptables).", "iptables پورت را <u>قبل</u> از هر برنامه دیگری می‌گیرد؛ پنل اجازه نمی‌دهد پورت تکراری بسازید.": "iptables takes the port <u>before</u> any other program; the panel does not let you create a duplicate port.", "اگر IP دامنه عوض شود، قوانین هر 5 دقیقه خودکار به‌روز می‌شوند.": "If a domain's IP changes, the rules are updated automatically every 5 minutes.", "<h3>لینک‌ها و اتصال</h3>": "<h3>Links and connectivity</h3>", " لینک شبکه: GRE / IPIP / 6to4": " Network link: GRE / IPIP / 6to4", "<table><tr><th>نوع</th><th>پروتکل</th><th>MTU پیش‌فرض</th><th>توضیح</th></tr>": "<table><tr><th>Type</th><th>Protocol</th><th>Default MTU</th><th>Notes</th></tr>", "<tr><td>GRE</td><td>47</td><td>1476</td><td>رایج‌ترین. بعضی دیتاسنترها مسدودش می‌کنند.</td></tr>": "<tr><td>GRE</td><td>47</td><td>1476</td><td>Most common. Some datacenters block it.</td></tr>", "<tr><td>IPIP</td><td>4</td><td>1480</td><td>سبک‌تر؛ گاهی وقتی GRE بسته است باز است.</td></tr>": "<tr><td>IPIP</td><td>4</td><td>1480</td><td>Lighter; sometimes open when GRE is blocked.</td></tr>", "<tr><td>6to4 (SIT)</td><td>41</td><td>1480</td><td>IPv6 داخل IPv4؛ آدرس IPv6 داخلی خودکار از IP داخلی ساخته می‌شود. با iptables کار نمی‌کند.</td></tr></table>": "<tr><td>6to4 (SIT)</td><td>41</td><td>1480</td><td>IPv6 inside IPv4; the inner IPv6 address is derived from the inner IP. Does not work with iptables.</td></tr></table>", "<ul><li>لینک بر اساس <b>دامنه</b> ساخته می‌شود؛ اگر IP سرور عوض شود، هر 2 دقیقه خودکار به‌روز می‌شود.</li>": "<ul><li>The link is built from <b>domains</b>; if a server's IP changes it is updated automatically every 2 minutes.</li>", "<li>نوع لینک، دامنه‌ها و MTU باید دو طرف هماهنگ باشند (دامنه این سرور ↔ دامنه سرور مقابل جابه‌جا).</li>": "<li>Link type, domains and MTU must match on both sides (this server's domain ↔ peer server domain swapped).</li>", "<li>اگر «تست پینگ» جواب نداد: پروتکل لینک در فایروال/دیتاسنتر بسته است → نوع لینک را عوض کنید یا حالت مستقیم.</li></ul>": "<li>If «Ping test» gets no reply: the link protocol is blocked in the firewall/datacenter → switch the link type or use direct mode.</li></ul>", " CDN کلادفلر (Backhaul)": " Cloudflare CDN (Backhaul)", "<ol><li>رکورد A دامنه → IP سرور <b>ایران</b>، ابر نارنجی روشن.</li><li>Network → WebSockets روشن.</li>": "<ol><li>A record of the domain → <b>Iran</b> server IP, orange cloud on.</li><li>Network → WebSockets on.</li>", "<li>با wss/wssmux: SSL/TLS حالت <b>Full</b> (نه Strict). با ws/wsmux: «Always Use HTTPS» خاموش.</li>": "<li>With wss/wssmux: SSL/TLS mode <b>Full</b> (not Strict). With ws/wsmux: «Always Use HTTPS» off.</li>", "<li>پورت تانل از پورت‌های مجاز کلادفلر: با TLS <code>443 2053 2083 2087 2096 8443</code> · بدون TLS <code>80 8080 8880 2052 2082 2086 2095</code>.</li>": "<li>Tunnel port from Cloudflare's allowed ports: with TLS <code>443 2053 2083 2087 2096 8443</code> · without TLS <code>80 8080 8880 2052 2082 2086 2095</code>.</li>", "<li>پورت تانل نباید با پورت‌های سرویس یکی باشد.</li><li>Edge IP (اختیاری، سمت خارج): یک IP تمیز کلادفلر که به آن وصل شود.</li></ol>": "<li>The tunnel port must not be one of the service ports.</li><li>Edge IP (optional, abroad side): a clean Cloudflare IP to connect to.</li></ol>", "<h3>ترکیب چند تانل و تداخل‌ها</h3>": "<h3>Combining tunnels and conflicts</h3>", " ترکیب چند مدل تانل روی یک سرور (مهم)": " Running several tunnel types on one server (important)", "<h4>دو سر یک تانل (ایران و خارج) باید یکی باشند</h4><ul><li>موتور (مثلا هر دو Backhaul) — موتورها با هم سازگار نیستند.</li><li>پورت تانل، توکن، پورت‌های سرویس.</li><li>ترنسپورت/پروتکل، mux، نوع لینک، SNI و رمز obfs (هرکدام که دارد).</li><li>نسخه هسته (ترجیحا یکسان).</li></ul>": "<h4>Both ends of a tunnel (Iran and abroad) must match</h4><ul><li>Engine (e.g. both Backhaul) — engines are not compatible with each other.</li><li>Tunnel port, token, service ports.</li><li>Transport/protocol, mux, link type, SNI and obfs password (whichever apply).</li><li>Core version (preferably identical).</li></ul>", "<h4>روی یک سرور می‌توانید هم‌زمان داشته باشید</h4><ul><li>چند تانل با موتورهای مختلف (مثلا یک Rathole، یک Backhaul CDN، یک iptables).</li><li>چند تانل از سرور ایران به چند سرور خارج (هر کدام پورت تانل و شبکه داخلی جدا).</li><li>چند تانل سمت خارج که همه به یک پورت محلی (همان Xray) وصل می‌شوند.</li><li>بین یک جفت سرور: یک لینک GRE + یک IPIP + یک 6to4 هم‌زمان.</li></ul>": "<h4>On one server you can have at the same time</h4><ul><li>Several tunnels with different engines (e.g. one Rathole, one Backhaul CDN, one iptables).</li><li>Several tunnels from the Iran server to several abroad servers (each with its own tunnel port and inner network).</li><li>Several abroad-side tunnels that all connect to one local port (the same Xray).</li><li>Between one server pair: one GRE + one IPIP + one 6to4 link at once.</li></ul>", "<h4>تداخل‌هایی که پنل جلوی آن‌ها را می‌گیرد</h4><table><tr><th>تداخل</th><th>چرا مشکل است</th><th>راه حل</th></tr>": "<h4>Conflicts the panel prevents</h4><table><tr><th>Conflict</th><th>Why it is a problem</th><th>Fix</th></tr>", "<tr><td>پورت سرویس تکراری روی سرور ایران</td><td>دو تانل یک پورت را می‌خواهند؛ یکی کار نمی‌کند (rathole/FRP تا وصل نشوند پورت را باز نمی‌کنند، پس تداخل دیر دیده می‌شود)</td><td>هر پورت فقط در یک تانل</td></tr>": "<tr><td>Duplicate service port on the Iran server</td><td>Two tunnels want one port; one fails (rathole/FRP only open the port once connected, so the clash shows up late)</td><td>Each port in one tunnel only</td></tr>", "<tr><td>پورت تانل = پورت سرویس یا پورت تانل دیگر</td><td>دو برنامه یک پورت</td><td>پورت تانل جدا</td></tr>": "<tr><td>Tunnel port = a service port or another tunnel's port</td><td>Two programs on one port</td><td>A separate tunnel port</td></tr>", "<tr><td>پورت = پورت پنل</td><td>پنل یا تانل بالا نمی‌آید</td><td>پورت دیگر</td></tr>": "<tr><td>Port = panel port</td><td>The panel or the tunnel fails to start</td><td>Another port</td></tr>", "<tr><td>پورت را برنامه دیگری گرفته (مثلا Xray روی ایران)</td><td>تانل بالا نمی‌آید</td><td>پورت دیگر یا آزاد کردن آن</td></tr>": "<tr><td>Port taken by another program (e.g. Xray on Iran)</td><td>The tunnel fails to start</td><td>Another port or free it</td></tr>", "<tr><td>iptables روی پورتی که برنامه دیگری دارد</td><td>iptables ترافیک را قبل از برنامه می‌رباید</td><td>پورت جدا</td></tr>": "<tr><td>iptables on a port another program uses</td><td>iptables steals the traffic before the program</td><td>A separate port</td></tr>", "<tr><td>شبکه داخلی /30 تکراری یا هم‌پوشان (حتی با Docker/VPN سرور)</td><td>مسیریابی خراب می‌شود</td><td>هر تانل شبکه جدا (دکمه «پیشنهاد»)</td></tr>": "<tr><td>Duplicate or overlapping /30 inner network (even with the server's Docker/VPN)</td><td>Routing breaks</td><td>A separate network per tunnel («Suggest» button)</td></tr>", "<tr><td>دو لینک هم‌نوع به یک سرور مقابل</td><td>لینوکس فقط یکی را می‌سازد؛ ترافیک قاطی می‌شود</td><td>پورت‌ها را به همان تانل اضافه کنید یا نوع لینک دیگر</td></tr>": "<tr><td>Two links of the same type to one peer server</td><td>Linux creates only one; traffic gets mixed</td><td>Add the ports to the same tunnel or use another link type</td></tr>", "<tr><td>Heartbeat مساوی در rathole</td><td>قطع و وصل مداوم (<code>early eof</code>)</td><td>خارج بیشتر از ایران (30/40)</td></tr></table>": "<tr><td>Equal heartbeat in rathole</td><td>Constant reconnects (<code>early eof</code>)</td><td>Abroad larger than Iran (30/40)</td></tr></table>", "<p>دکمه <b>«بررسی تداخل‌ها»</b>  در صفحه تانل‌ها همه این موارد را روی تانل‌های موجود بررسی می‌کند. روی هر دو سرور اجرا کنید.</p>": "<p>The <b>«Check conflicts»</b> button  on the Tunnels page checks all of this for existing tunnels. Run it on both servers.</p>", "<h3>عیب‌یابی</h3>": "<h3>Troubleshooting</h3>", " خطاهای رایج و راه حل": " Common errors and fixes", "<table><tr><th>علامت / خطا</th><th>علت محتمل</th><th>راه حل</th></tr>": "<table><tr><th>Symptom / error</th><th>Likely cause</th><th>Fix</th></tr>", "<tr><td><code>Incorrect token</code></td><td>توکن دو طرف فرق دارد</td><td>یک طرف را ویرایش و توکن را یکی کنید</td></tr>": "<tr><td><code>Incorrect token</code></td><td>The tokens on the two sides differ</td><td>Edit one side and make the tokens match</td></tr>", "<tr><td><code>early eof</code> پشت سر هم</td><td>Heartbeat مساوی، یا دو کلاینت روی یک تانل</td><td>Heartbeat 30/40؛ بررسی تداخل‌ها</td></tr>": "<tr><td><code>early eof</code> repeatedly</td><td>Equal heartbeat, or two clients on one tunnel</td><td>Heartbeat 30/40; check conflicts</td></tr>", "<tr><td><code>Connection refused</code> سمت خارج</td><td>سرویس اصلی (Xray) روی آن پورت گوش نمی‌دهد</td><td>inbound آن پورت را در Xray روشن کنید</td></tr>": "<tr><td><code>Connection refused</code> on the abroad side</td><td>The main service (Xray) does not listen on that port</td><td>Enable that port's inbound in Xray</td></tr>", "<tr><td>تست پینگ لینک جواب نمی‌دهد</td><td>پروتکل لینک بسته، دامنه اشتباه، فایروال</td><td>دامنه‌ها را چک کنید؛ IPIP/6to4 یا حالت مستقیم</td></tr>": "<tr><td>Link ping test gets no reply</td><td>Link protocol blocked, wrong domain, firewall</td><td>Check the domains; IPIP/6to4 or direct mode</td></tr>", "<tr><td><code>libssl.so.3</code></td><td>هسته rathole 0.5.0 روی سرور قدیمی</td><td>«دانلود از مخزن NETIFAY» (نسخه سازگار خودکار)</td></tr>": "<tr><td><code>libssl.so.3</code></td><td>rathole 0.5.0 core on an old server</td><td>«Download from NETIFAY repository» (compatible build picked automatically)</td></tr>", "<tr><td>CDN وصل نمی‌شود</td><td>ابر نارنجی خاموش، پورت غیرمجاز، SSL Strict، WebSockets خاموش</td><td>بخش CDN همین راهنما</td></tr>": "<tr><td>CDN does not connect</td><td>Orange cloud off, disallowed port, SSL Strict, WebSockets off</td><td>The CDN section of this guide</td></tr>", "<tr><td>«اتصال‌های تانل: 0» در تست پورت</td><td>سرور مقابل وصل نیست</td><td>لاگ هر دو طرف، توکن، پورت تانل، فایروال</td></tr>": "<tr><td>«Tunnel connections: 0» in the port test</td><td>The peer server is not connected</td><td>Logs on both sides, token, tunnel port, firewall</td></tr>", "<tr><td>«پورت در حال استفاده است»</td><td>برنامه یا تانل دیگری آن را دارد</td><td>پورت دیگر؛ «بررسی تداخل‌ها»</td></tr></table>": "<tr><td>«Port is in use»</td><td>Another program or tunnel has it</td><td>Another port; «Check conflicts»</td></tr></table>", "<p class=\"hint\">ترتیب عیب‌یابی: ۱) «تست پینگ» (فقط حالت لینک) ← ۲) «تست پورت‌ها» ← ۳) «لاگ» هر دو سرور ← ۴) «بررسی تداخل‌ها».</p>": "<p class=\"hint\">Troubleshooting order: 1) «Ping test» (link mode only) → 2) «Test ports» → 3) «Logs» on both servers → 4) «Check conflicts».</p>", " چک‌لیست ساخت تانل": " Tunnel setup checklist", "<ol><li>هسته موتور را روی هر دو سرور نصب کنید (تب «هسته»).</li><li>«بهینه‌سازی شبکه» را روی هر دو سرور اعمال کنید (تنظیمات).</li>": "<ol><li>Install the engine's core on both servers («Core» tab).</li><li>Apply «Network optimization» on both servers (Settings).</li>", "<li>اول سرور ایران را بسازید، بعد خارج را با همان پورت تانل، توکن، پورت‌ها و تنظیمات.</li>": "<li>Build the Iran server first, then abroad with the same tunnel port, token, ports and settings.</li>", "<li>در حالت لینک: IP داخلی ایران x.x.x.1 و خارج x.x.x.2 (پنل مقدار درست را نشان می‌دهد).</li>": "<li>In link mode: Iran inner IP x.x.x.1 and abroad x.x.x.2 (the panel shows the right value).</li>", "<li>«تست پورت‌ها» و «بررسی تداخل‌ها» را روی هر دو سرور بزنید.</li><li>از هر دو سرور بکاپ بگیرید و دانلود کنید.</li></ol>": "<li>Run «Test ports» and «Check conflicts» on both servers.</li><li>Back up both servers and download the backups.</li></ol>", "<div class=\"form\"><h2>تنظیمات پنل</h2>": "<div class=\"form\"><h2>Panel settings</h2>", "<h3>تغییر نام کاربری و رمز</h3><form class=\"card\" id=\"credF\">": "<h3>Change username and password</h3><form class=\"card\" id=\"credF\">", "<label class=\"f\"><span>رمز فعلی</span><input class=\"ltr\" type=\"password\" name=\"current\" autocomplete=\"current-password\"></label>": "<label class=\"f\"><span>Current password</span><input class=\"ltr\" type=\"password\" name=\"current\" autocomplete=\"current-password\"></label>", "<div class=\"row\"><label class=\"f\"><span>نام کاربری جدید</span><input class=\"ltr\" name=\"user\" value=\"": "<div class=\"row\"><label class=\"f\"><span>New username</span><input class=\"ltr\" name=\"user\" value=\"", "<label class=\"f\"><span>رمز جدید</span><input class=\"ltr\" type=\"password\" name=\"password\" autocomplete=\"new-password\" minlength=\"8\" placeholder=\"حداقل 8 کاراکتر\"></label></div>": "<label class=\"f\"><span>New password</span><input class=\"ltr\" type=\"password\" name=\"password\" autocomplete=\"new-password\" minlength=\"8\" placeholder=\"At least 8 characters\"></label></div>", "<button class=\"btn p\">ذخیره</button></form>": "<button class=\"btn p\">Save</button></form>", "<h3>پورت و مسیر مخفی پنل</h3><form class=\"card\" id=\"portF\">": "<h3>Panel port and secret path</h3><form class=\"card\" id=\"portF\">", "<div class=\"row\"><label class=\"f\"><span>پورت پنل</span><input class=\"ltr\" name=\"port\" inputmode=\"numeric\" value=\"": "<div class=\"row\"><label class=\"f\"><span>Panel port</span><input class=\"ltr\" name=\"port\" inputmode=\"numeric\" value=\"", "<label class=\"f\"><span>مسیر مخفی (اختیاری)</span><input class=\"ltr\" name=\"base\" value=\"": "<label class=\"f\"><span>Secret path (optional)</span><input class=\"ltr\" name=\"base\" value=\"", "<div class=\"hint\" style=\"margin-bottom:10px\">آدرس پنل: <span class=\"ltr\" id=\"newUrl\"></span><br>بعد از ذخیره، پنل ری‌استارت می‌شود و به آدرس جدید منتقل می‌شوید.</div>": "<div class=\"hint\" style=\"margin-bottom:10px\">Panel address: <span class=\"ltr\" id=\"newUrl\"></span><br>After saving, the panel restarts and you are moved to the new address.</div>", "<button class=\"btn p\">ذخیره و ری‌استارت پنل</button></form>": "<button class=\"btn p\">Save & restart panel</button></form>", "<h3>بهینه‌سازی شبکه سرور</h3><div class=\"card\" id=\"optBox\"><span class=\"spin\"></span></div>": "<h3>Server network optimization</h3><div class=\"card\" id=\"optBox\"><span class=\"spin\"></span></div>", "<h3>HTTPS (رمزنگاری اتصال پنل)</h3><div class=\"card\">": "<h3>HTTPS (panel connection encryption)</h3><div class=\"card\">", "<div class=\"hint\" style=\"margin-bottom:10px\">وضعیت: <b style=\"color:": "<div class=\"hint\" style=\"margin-bottom:10px\">Status: <b style=\"color:", " روشن": " on", "خاموش": "Off", "</b><br>با روشن کردن، یک گواهی خودامضا ساخته می‌شود و رمز و کوکی رمزنگاری می‌شوند. مرورگر بار اول هشدار «Not secure / گواهی نامعتبر» می‌دهد؛ «Advanced → Proceed» را بزنید. این هشدار طبیعی است.</div>": "</b><br>Turning it on creates a self-signed certificate and encrypts the password and cookie. The first time, the browser warns «Not secure / invalid certificate»; press «Advanced → Proceed». This warning is normal.</div>", "<div class=\"warnbox\">برنامه openssl روی سرور نیست: <span class=\"ltr\">apt install openssl</span></div>": "<div class=\"warnbox\">openssl is not installed on the server: <span class=\"ltr\">apt install openssl</span></div>", "خاموش کردن HTTPS": "Turn HTTPS off", "روشن کردن HTTPS": "Turn HTTPS on", "<h3>دسترسی از بیرون</h3><div class=\"card\">": "<h3>External access</h3><div class=\"card\">", "<div class=\"hint\" style=\"margin-bottom:10px\">وقتی کارتان با پنل تمام شد، دسترسی از اینترنت را ببندید. پنل فقط روی خود سرور <span class=\"ltr\">(127.0.0.1)</span> در دسترس می‌ماند و تانل‌ها هیچ تغییری نمی‌کنند.<br>برای روشن کردن دوباره، در SSH دستور <b class=\"ltr\">netifay</b> را بزنید و گزینه 7 را انتخاب کنید.</div>": "<div class=\"hint\" style=\"margin-bottom:10px\">When you are done with the panel, close internet access to it. The panel stays reachable only on the server itself <span class=\"ltr\">(127.0.0.1)</span> and tunnels are not affected.<br>To turn it back on, run <b class=\"ltr\">netifay</b> over SSH and choose option 7.</div>", "<button class=\"btn d\" id=\"extOff\">بستن دسترسی وب از بیرون</button></div>": "<button class=\"btn d\" id=\"extOff\">Close external web access</button></div>", "<h3>درباره</h3><div class=\"card\"><dl class=\"kv\"><dt>نسخه پنل</dt><dd class=\"ltr\">NETIFAY ": "<h3>About</h3><div class=\"card\"><dl class=\"kv\"><dt>Panel version</dt><dd class=\"ltr\">NETIFAY ", "</dd><dt>مخزن</dt><dd class=\"ltr\">": "</dd><dt>Repository</dt><dd class=\"ltr\">", "</dd><dt>سرور</dt><dd class=\"ltr\">": "</dd><dt>Server</dt><dd class=\"ltr\">", "غیرفعال": "Disabled", "<div class=\"hint\">به‌روزرسانی پنل: در SSH دستور <b class=\"ltr\">netifay</b> → گزینه 1.</div></div></div>": "<div class=\"hint\">Update the panel: run <b class=\"ltr\">netifay</b> over SSH → option 1.</div></div></div>", "بستن دسترسی از بیرون": "Close external access", "<p>بعد از تایید، این صفحه دیگر باز نمی‌شود. برای روشن کردن دوباره باید با SSH وارد سرور شوید و دستور <b class=\"ltr\">netifay</b> → گزینه 7 را بزنید.</p>": "<p>After confirming, this page will no longer open. To turn it back on you must log in to the server over SSH and run <b class=\"ltr\">netifay</b> → option 7.</p>", "بله، ببند": "Yes, close it", "<br>دسترسی وب از بیرون بسته شد<br><br><span class=\"hint\">برای باز کردن: SSH ← <span class=\"ltr\">netifay</span> ← گزینه 7</span></div></div>": "<br>External web access closed<br><br><span class=\"hint\">To reopen: SSH ← <span class=\"ltr\">netifay</span> ← option 7</span></div></div>", "پنل ری‌استارت می‌شود و به آدرس <b class=\"ltr\">https://</b> منتقل می‌شوید. بعد از آن آدرس <span class=\"ltr\">http://</span> دیگر کار نمی‌کند.": "The panel restarts and you are moved to <b class=\"ltr\">https://</b>. After that the <span class=\"ltr\">http://</span> address no longer works.", "اتصال پنل دوباره HTTP ساده (بدون رمزنگاری) می‌شود.": "The panel connection goes back to plain HTTP (unencrypted).", "تایید": "Confirm", "در حال انتقال به ": "Moving to ", "ذخیره شد؛ دوباره وارد شوید": "Saved; please log in again", "پنل مدیریت تانل": "Tunnel management panel", "نام کاربری": "Username", "رمز عبور": "Password", "ورود": "Log in", "این اتصال HTTP است و رمز رمزنگاری نمی‌شود. بعد از ورود، HTTPS را از تنظیمات روشن کنید یا از SSH tunnel استفاده کنید.": "This connection is HTTP and your password is not encrypted. After logging in, turn on HTTPS in Settings or use an SSH tunnel.", "اتصال به پنل رمزنگاری نشده است (HTTP).": "The connection to the panel is not encrypted (HTTP).", "HTTPS را روشن کنید": "Turn on HTTPS", "تانل‌ها": "Tunnels", "هسته": "Core", "بکاپ": "Backup", "راهنما": "Guide", "تنظیمات": "Settings", "تغییر تم روز / شب": "Toggle day / night theme", "خروج": "Log out", "منو": "Menu"};
const _L=s=>LANG==='en'&&Object.prototype.hasOwnProperty.call(EN,s)?EN[s]:s;
document.documentElement.lang=LANG;document.documentElement.dir=LANG==='en'?'ltr':'rtl';
if(LANG==='en'){
  const tr=v=>{const k=v.trim();return k&&Object.prototype.hasOwnProperty.call(EN,k)?v.replace(k,EN[k]):v};
  const walk=n=>{if(n.nodeType===3){if(/[؀-ۿ]/.test(n.nodeValue))n.nodeValue=tr(n.nodeValue);return}
    if(n.nodeType!==1||n.tagName==='SCRIPT'||n.tagName==='STYLE')return;
    for(const at of ['title','placeholder','aria-label'])if(n.hasAttribute(at))n.setAttribute(at,tr(n.getAttribute(at)));
    n.childNodes.forEach(walk)};
  walk(document.body);
}
function setLangBtns(){document.querySelectorAll('.langBtn').forEach(b=>{b.textContent=LANG==='en'?'فا':'EN';b.title=LANG==='en'?'فارسی':'English'})}
document.addEventListener('click',e=>{if(!e.target.closest('.langBtn'))return;
  try{localStorage.setItem('nf-lang',LANG==='en'?'fa':'en')}catch(err){}location.reload()});

"use strict";
const $=(s,r)=>(r||document).querySelector(s);
const ic=(n,c)=>'<svg class="ic'+(c?' '+c:'')+'"><use href="#i-'+n+'"/></svg>';
/* ---- theme (day / night) ---- */
function getTheme(){let t=null;try{t=localStorage.getItem('nf-theme')}catch(e){}
  if(t!=='light'&&t!=='dark')t=(window.matchMedia&&matchMedia('(prefers-color-scheme: light)').matches)?'light':'dark';return t}
function applyTheme(t){document.documentElement.dataset.theme=t;
  document.querySelectorAll('.themeBtn').forEach(b=>{b.innerHTML=ic(t==='light'?'moon':'sun');b.title=t==='light'?_L('تم شب'):_L('تم روز')})}
applyTheme(getTheme());setLangBtns();
document.addEventListener('click',e=>{if(!e.target.closest('.themeBtn'))return;const t=document.documentElement.dataset.theme==='light'?'dark':'light';
  try{localStorage.setItem('nf-theme',t)}catch(err){}applyTheme(t)});
const $$=(s,r)=>Array.from((r||document).querySelectorAll(s));
const S={tab:'tunnels',tunnels:[],sys:{},form:null,timer:null};
const CRON={'':_L('بدون ری‌استارت خودکار'),'30m':_L('هر 30 دقیقه'),'1h':_L('هر 1 ساعت'),'2h':_L('هر 2 ساعت'),'4h':_L('هر 4 ساعت'),'6h':_L('هر 6 ساعت'),'12h':_L('هر 12 ساعت'),'24h':_L('هر 24 ساعت')};

function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function fb(n){n=+n||0;const u=['B','KB','MB','GB','TB'];let i=0;while(n>=1024&&i<4){n/=1024;i++}return (i?n.toFixed(1):n)+' '+u[i]}
function fdur(s){s=+s||0;const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return (d?d+_L(' روز '):'')+(h?h+_L(' ساعت '):'')+m+_L(' دقیقه')}
function toast(msg,type){const t=document.createElement('div');t.className='toast '+(type||'');t.textContent=msg;$('#toasts').appendChild(t);setTimeout(()=>t.remove(),type==='err'?7000:3500)}
function randTok(){const a=new Uint8Array(18);crypto.getRandomValues(a);return Array.from(a,b=>'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'[b%62]).join('')}

async function api(a,body,raw){
  const opt={method:'POST',credentials:'same-origin',headers:{'X-Panel':'1','X-Lang':LANG}};
  if(raw){opt.body=raw.body;Object.assign(opt.headers,raw.headers||{})}
  else{opt.headers['Content-Type']='application/json';opt.body=JSON.stringify(body||{})}
  let r,j;
  try{r=await fetch('api/'+a,opt)}catch(e){throw new Error(_L('ارتباط با سرور قطع است'))}
  try{j=await r.json()}catch(e){throw new Error(_L('پاسخ نامعتبر از سرور (')+r.status+')')}
  if(r.status===401&&a!=='login'){showLogin();throw new Error(_L('دوباره وارد شوید'))}
  if(!j.ok){const er=new Error(j.error||_L('خطا'));er.fa=j.error_fa||j.error;throw er}
  return j.data;
}
async function busy(btn,fn){
  if(btn){btn.disabled=true;btn._h=btn.innerHTML;btn.innerHTML='<span class="spin"></span>'}
  try{return await fn()}catch(e){toast(e.message,'err')}finally{if(btn){btn.disabled=false;btn.innerHTML=btn._h}}
}

/* ---------------- modal ---------------- */
function modal(title,html,buttons){
  closeModal();
  const ov=document.createElement('div');ov.className='ov';ov.id='ov';
  ov.innerHTML='<div class="md"><div class="mh"><b>'+esc(title)+_L('</b><button class="btn sm" data-x title="بستن">')+ic('x')+'</button></div><div class="mb">'+html+'</div><div class="mf"></div></div>';
  const mf=$('.mf',ov);
  (buttons||[]).forEach(b=>{const e=document.createElement('button');e.className='btn '+(b.cls||'');e.textContent=b.text;e.onclick=()=>b.fn(e);mf.appendChild(e)});
  if(!(buttons||[]).length)mf.remove();
  ov.addEventListener('click',e=>{if(e.target===ov||e.target.closest('[data-x]'))closeModal()});
  document.body.appendChild(ov);return ov;
}
function closeModal(){const o=$('#ov');if(o)o.remove()}

/* ---------------- auth ---------------- */
function showLogin(){$('#app').classList.add('hidden');$('#loginView').classList.remove('hidden');stopTimer();
  $('#loginHttp').classList.toggle('hidden',location.protocol==='https:'||/^(127\.0\.0\.1|localhost)$/.test(location.hostname))}
function showApp(){$('#loginView').classList.add('hidden');$('#app').classList.remove('hidden');
  const local=/^(127\.0\.0\.1|localhost|\[::1\])$/.test(location.hostname);
  renderSecBar(local);
  go(S.tab)}
function renderSecBar(local){
  const bar=$('#secBar');let hide=false;try{hide=sessionStorage.getItem('nf-secbar')==='1'}catch(e){}
  const items=[];
  if(location.protocol!=='https:')items.push(_L('HTTPS (TLS) فعال نیست؛ رمز و کوکی پنل بدون رمزنگاری ارسال می‌شوند.'));
  if(!/^\/[^/]+\/?/.test(location.pathname))items.push(_L('مسیر مخفی پنل تنظیم نشده است.'));
  items.push(_L('بعد از تمام شدن کانفیگ‌ها، دسترسی وب از بیرون را از تنظیمات ببندید.'));
  if(local||hide){bar.classList.add('hidden');return}
  bar.innerHTML=ic('alert')+'<span class="sb-txt"><b>'+_L('امنیت پنل:')+'</b> '+items.join(' · ')+' <a data-go="settings">'+_L('رفتن به تنظیمات')+'</a></span>'+
    '<button type="button" class="sb-x" title="'+_L('بستن')+'">'+ic('x','sm')+'</button>';
  bar.classList.remove('hidden');
  $('a[data-go]',bar).onclick=()=>go('settings');
  $('.sb-x',bar).onclick=()=>{bar.classList.add('hidden');try{sessionStorage.setItem('nf-secbar','1')}catch(e){}};
}
$('#loginForm').addEventListener('submit',async e=>{
  e.preventDefault();const f=e.target,b=$('button',f);
  await busy(b,async()=>{await api('login',{user:f.user.value.trim(),password:f.password.value});f.password.value='';showApp()});
});
$('#logoutBtn').onclick=async()=>{try{await api('logout')}catch(e){}showLogin()};
$('#refreshBtn').onclick=()=>go(S.tab);
$('#refreshBtn').innerHTML=ic('refresh');$('#logoutBtn').innerHTML=ic('logout');
function setMenu(o){const hd=$('header');hd.classList.toggle('menu-open',o);const mb=$('#menuBtn');mb.innerHTML=ic(o?'x':'menu');mb.setAttribute('aria-expanded',o?'true':'false')}
setMenu(false);
$('#menuBtn').onclick=()=>setMenu(!$('header').classList.contains('menu-open'));
$('#navBack').onclick=()=>setMenu(false);
document.addEventListener('keydown',e=>{if(e.key==='Escape')setMenu(false)});
addEventListener('resize',()=>{if(innerWidth>720)setMenu(false)});
{const NI={tunnels:'network',form:'plus',core:'cpu',backup:'archive',guide:'book',settings:'sliders'};
 $$('#nav button').forEach(b=>{b.dataset.label=b.textContent;b.innerHTML=ic(NI[b.dataset.tab]||'info')+'<span>'+b.textContent+'</span>'})}

/* ---------------- tabs ---------------- */
$('#nav').addEventListener('click',e=>{const t=e.target.closest('button');if(!t)return;if(t.dataset.tab==='form')S.form=null;go(t.dataset.tab)});
function go(tab){
  S.tab=tab;
  $$('#nav button').forEach(b=>b.classList.toggle('on',b.dataset.tab===tab));
  if(typeof setMenu==='function')setMenu(false);
  $$('main>section').forEach(s=>s.classList.toggle('hidden',s.id!=='tab-'+tab));
  $('#nav [data-tab=form] span').textContent=(tab==='form'&&S.form&&S.form.name)?_L('ویرایش تانل'):_L('ساخت تانل');
  {const nb=$('#nav [data-tab='+tab+']');if(nb)$('#curTab').innerHTML=nb.innerHTML}
  stopTimer();
  if(tab==='tunnels'){loadTunnels();S.timer=setInterval(()=>{if(!$('#ov')&&!document.hidden)loadTunnels(true)},5000)}
  if(tab==='form')renderForm();
  if(tab==='core')renderCore();
  if(tab==='backup')renderBackup();
  if(tab==='settings')renderSettings();
  if(tab==='guide')renderGuide();
  window.scrollTo(0,0);
}
function stopTimer(){if(S.timer){clearInterval(S.timer);S.timer=null}}

/* ---------------- tunnels list ---------------- */
async function loadTunnels(silent){
  try{const d=await api('list');S.tunnels=d.tunnels;S.sys=d.system;renderTunnels()}
  catch(e){if(!silent)toast(e.message,'err')}
}
function renderTunnels(){
  const s=S.sys,el=$('#tab-tunnels');
  $('#hostName').textContent=s.hostname||'';
  if(!$('#tStats')){
    el.innerHTML='<div id="tStats"></div><div id="tWarn"></div>'+
      _L('<div class="toolbar"><input id="tSearch" class="ltr" placeholder="جستجو: پورت، دامنه، IP…" autocomplete="off">')+
      _L('<div class="seg sm" id="tFilter"><button data-f="all" class="on">همه</button><button data-f="iran">ایران</button><button data-f="kharej">خارج</button><button data-f="bad">مشکل‌دار</button></div>')+
      _L('<select id="tEng" style="width:auto"><option value="">همه موتورها</option>')+Object.keys(ENG).map(k=>'<option value="'+k+'">'+ENG[k].label+'</option>').join('')+'</select>'+
      _L('<button class="btn" id="tAudit" title="بررسی تداخل پورت، IP و لینک بین همه تانل‌ها">')+ic('search')+_L('بررسی تداخل‌ها</button>')+
      '<button class="btn p" id="tNew">'+ic('plus')+_L('تانل جدید</button></div><div id="tGrid"></div>');
    $('#tSearch').addEventListener('input',()=>{S.q=$('#tSearch').value.trim().toLowerCase();renderGrid()});
    $('#tFilter').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;S.f=b.dataset.f;$$('#tFilter button').forEach(x=>x.classList.toggle('on',x===b));renderGrid()});
    $('#tNew').onclick=()=>{S.form=null;go('form')};
    $('#tEng').onchange=()=>{S.fe=$('#tEng').value;renderGrid()};
    $('#tAudit').onclick=e=>busy(e.currentTarget,runAudit);
  }
  const up=S.tunnels.filter(t=>t.state&&t.state.active==='active').length;
  $('#tStats').innerHTML='<div class="stats">'+
    _L('<div class="stat"><span>تانل‌های فعال</span><b style="color:')+(up===S.tunnels.length?'var(--ok)':'var(--warn)')+'">'+up+' / '+S.tunnels.length+'</b></div>'+
    _L('<div class="stat"><span>هسته‌های نصب‌شده</span><b style="font-size:12.5px;line-height:1.9">')+[['Rathole',s.core],['Backhaul',s.bh_core]].concat(Object.keys(s.cores||{}).map(k=>[(ENG[k]||{}).label||k,s.cores[k]])).filter(x=>x[1]).map(x=>'<span class="chip ltr" style="color:var(--ok)">'+esc(x[0])+'</span>').join(' ')+'</b></div>'+
    meter('CPU ('+(s.cpus||1)+_L(' هسته)'),(+s.cpu||0).toFixed(1)+'%',+s.cpu||0,'Load: '+(s.load||'-'))+
    meter(_L('رم'),fb(s.mem_used)+' / '+fb(s.mem_total),s.mem_total?100*s.mem_used/s.mem_total:0)+
    meter(_L('دیسک'),fb(s.disk_used)+' / '+fb(s.disk_total),s.disk_total?100*s.disk_used/s.disk_total:0)+
    _L('<div class="stat"><span>آپتایم سرور</span><b style="font-size:13px">')+fdur(s.uptime)+'</b></div></div>';
  $('#tWarn').innerHTML=(s.core||s.bh_core||Object.values(s.cores||{}).some(Boolean))?'':_L('<div class="warnbox">هیچ هسته‌ای نصب نیست. از تب «هسته» rathole یا Backhaul را نصب کنید.</div>');
  renderGrid();
}
function tunnelBad(t){if(t.error)return true;const st=t.state||{};return st.active!=='active'||(t.mode==='gre'&&!(st.gre_exists&&st.gre_state!=='down'))}
function renderGrid(){
  const g=$('#tGrid');if(!g)return;
  if(!S.tunnels.length){g.innerHTML='<div class="card empty"><div style="color:var(--acc);margin-bottom:8px">'+ic('layers','lg')+_L('</div>هنوز تانلی ساخته نشده.<br><br><button class="btn p" data-a="new">')+ic('plus')+_L('ساخت اولین تانل</button></div>');return}
  const q=S.q||'',f=S.f||'all';
  const list=S.tunnels.filter(t=>{
    if(f==='iran'&&t.role!=='iran')return false;
    if(f==='kharej'&&t.role!=='kharej')return false;
    if(S.fe&&(t.engine||'rathole')!==S.fe)return false;
    if(f==='bad'&&!tunnelBad(t))return false;
    if(!q)return true;
    const hay=[t.name,t.port,t.engine,t.transport,t.remote_host,t.local_domain,t.remote_domain,t.cdn_domain,t.gre_ip,t.peer_ip,t.peer_calc,(t.services||[]).map(s=>s.port).join(' ')].join(' ').toLowerCase();
    return hay.indexOf(q)>=0;
  });
  if(!list.length){g.innerHTML=_L('<div class="card empty">تانلی با این فیلتر پیدا نشد.</div>');return}
  const open=new Set($$('.card.open',g).map(c=>c.dataset.name));
  g.innerHTML='<div class="grid">'+list.map(t=>cardHtml(t,open.has(t.name))).join('')+'</div>';
}
function meter(label,val,pct,sub){
  pct=Math.max(0,Math.min(100,pct));const c=pct>85?'var(--bad)':pct>60?'var(--warn)':'var(--ok)';
  return '<div class="stat"><span>'+esc(label)+'</span><b class="ltr" style="text-align:right">'+esc(val)+'</b><div class="bar"><i style="width:'+pct.toFixed(1)+'%;background:'+c+'"></i></div>'+(sub?'<span class="ltr" style="display:block;text-align:right;margin-top:3px">'+esc(sub)+'</span>':'')+'</div>';
}
function cardHtml(t,isOpen){
  if(t.error)return '<div class="card"><b class="ltr">'+esc(t.name)+'</b><div class="hint err">'+esc(t.error)+'</div></div>';
  const st=t.state||{},ir=t.role==='iran',cdn=t.mode==='cdn',bh=t.engine==='backhaul',direct=t.mode==='direct';
  const act=st.active==='active',acting=st.active==='activating';
  const greOk=st.gre_exists&&st.gre_state!=='down';
  const peer=ir?t.peer_calc:t.peer_ip;
  const statusDot='<span class="pill"><span class="dot '+(act?'ok':acting?'warn':'bad')+'"></span>'+(act?_L('فعال'):acting?_L('در حال اتصال'):_L('متوقف'))+'</span>';
  const lkName={gre:'GRE',ipip:'IPIP',sit:'6to4'}[t.link||'gre']||'GRE';
  const linkPill=direct?_L('<span class="pill">مستقیم</span>'):cdn?'<span class="pill"><span class="dot '+(act?'ok':'bad')+'"></span>CDN</span>':'<span class="pill"><span class="dot '+(greOk?'ok':'bad')+'"></span>'+lkName+'</span>';
  let kv='';
  if(direct){
    const dialSide=t.role===((ENG[t.engine]||ENG.rathole).dialer);
    kv=t.engine==='iptables'?_L('<dt>فوروارد به</dt><dd class="ltr">')+esc(t.remote_host||'-')+'</dd>':
      '<dt>'+(dialSide?_L('مقصد'):_L('گوش دادن'))+'</dt><dd class="ltr">'+(dialSide?esc(t.remote_host||'-')+':'+esc(t.port):((t.ipv6?'[::]':'0.0.0.0')+':'+esc(t.port)))+'</dd>';
  }else if(cdn){
    kv=_L('<dt>دامنه CDN</dt><dd class="ltr">')+esc(t.cdn_domain||'-')+'</dd>'+
       _L('<dt>اتصال</dt><dd>')+(bh?'<span class="ltr">'+esc(t.transport)+'</span>'+(t.edge_ip?' · edge <span class="ltr">'+esc(t.edge_ip)+'</span>':''):'WebSocket '+(t.cdn_tls?'+ TLS':_L('بدون TLS')))+'</dd>';
  }else{
    kv=_L('<dt>این سرور</dt><dd class="ltr">')+esc(t.local_domain||'-')+(st.ep_local?' <span class="mut">('+esc(st.ep_local)+')</span>':'')+'</dd>'+
       _L('<dt>سرور مقابل</dt><dd class="ltr">')+esc(t.remote_domain||'-')+(st.ep_remote?' <span class="mut">('+esc(st.ep_remote)+')</span>':'')+'</dd>'+
       _L('<dt>IP داخلی</dt><dd class="ltr">')+esc(t.gre_ip||'-')+' ⇄ '+esc(peer||'-')+(t.link==='sit'&&t.gre_ip?'<br><span class="mut">'+esc(v6of(t.gre_ip))+'</span>':'')+'</dd>'+
       _L('<dt>ترافیک</dt><dd class="ltr">')+ic('down','sm')+' '+fb(st.rx)+' · '+ic('up','sm')+' '+fb(st.tx)+'</dd>';
  }
  const more='<dl class="kv">'+
    (t.engine==='frp'?'<dt>FRP</dt><dd class="ltr">'+esc(t.protocol)+(t.tcp_mux?' · mux':'')+(t.role==='kharej'?' · pool '+esc(t.pool):'')+'</dd>':'')+
    (t.engine==='gost'?'<dt>Gost</dt><dd class="ltr">relay+'+esc(t.transport)+'</dd>':'')+
    (t.engine==='hysteria'?'<dt>Hysteria2</dt><dd>QUIC/UDP'+(t.obfs?' · obfs':'')+'</dd>':'')+
    (t.engine==='xray'?'<dt>Xray</dt><dd class="ltr">VLESS REALITY · '+esc(t.sni)+'</dd>':'')+
    (bh?_L('<dt>ترنسپورت</dt><dd class="ltr">')+esc(t.transport)+(/mux$/.test(t.transport||'')?' · mux '+esc(ir?t.mux_con:t.conn_pool):'')+(t.edge_ip?' · edge '+esc(t.edge_ip):'')+'</dd>':'')+
    (cdn||direct?'':_L('<dt>اینترفیس</dt><dd class="ltr">')+esc(t.dev)+' · MTU '+esc(t.mtu)+'</dd>')+
    (t.engine&&['rathole','backhaul'].indexOf(t.engine)<0?'':_L('<dt>تنظیمات</dt><dd>')+(t.nodelay?'NoDelay':_L('بدون NoDelay'))+(bh&&!ir?'':' · Heartbeat '+esc(t.heartbeat))+(bh?' · Keepalive '+esc(t.keepalive):'')+(t.ipv6?' · IPv6':'')+'</dd>')+
    _L('<dt>ری‌استارت</dt><dd>')+esc(CRON[st.restart_cron]||st.restart_cron||'—')+(st.restarts&&+st.restarts>0?' · '+esc(st.restarts)+_L(' بار ری‌استارت شده'):'')+'</dd></dl>'+
    '<div class="acts sub">'+
    '<button class="btn sm" data-a="clone">'+ic('copy')+_L('کلون</button>')+
    (cdn||direct?'':'<button class="btn sm" data-a="ping">'+ic('radio')+_L('تست پینگ</button><button class="btn sm" data-a="gre">')+ic('link')+lkName+'</button>')+
    '<button class="btn sm" data-a="logs">'+ic('terminal')+_L('لاگ</button>')+
    '<button class="btn sm" data-a="cron">'+ic('clock')+_L('زمان‌بندی</button>')+
    '<button class="btn sm" data-a="raw">'+ic('file')+_L('فایل کانفیگ</button>')+
    '<button class="btn sm d" data-a="delete">'+ic('trash')+_L('حذف</button></div>');
  return '<div class="card tcard'+(isOpen?' open':'')+(act?'':' down')+'" data-name="'+esc(t.name)+'">'+
   '<div class="ch"><span class="badge '+(ir?'b-ir':'b-kh')+'">'+(ir?_L('ایران'):_L('خارج'))+'</span>'+(cdn?'<span class="badge b-cdn">CDN</span>':'')+(t.engine&&t.engine!=='rathole'?'<span class="badge b-bh">'+esc((ENG[t.engine]||{}).label||t.engine)+'</span>':'')+
   _L('<b>پورت <span class="ltr">')+esc(t.port)+'</span></b><div class="grow"></div>'+statusDot+linkPill+'</div>'+
   '<dl class="kv">'+kv+'</dl>'+
   '<div class="chips">'+t.services.map(s=>'<span class="chip ltr">'+esc(s.port)+'/'+esc(s.type)+'</span>').join('')+'</div>'+
   (!t.has_gre_script?_L('<div class="hint err">اسکریپت لینک این تانل پیدا نشد؛ با «ویرایش» و ذخیره دوباره ساخته می‌شود.</div>'):'')+
   '<div class="acts">'+
   '<button class="btn sm p" data-a="edit">'+ic('edit')+_L('ویرایش</button>')+
   '<button class="btn sm g" data-a="ports">'+ic('activity')+_L('تست پورت‌ها</button>')+
   _L('<button class="btn sm" data-a="restart" title="ری‌استارت">')+ic('refresh')+_L('ری‌استارت</button>')+
   (act||acting?_L('<button class="btn sm" data-a="stop" title="توقف">')+ic('stop')+_L('توقف</button>'):'<button class="btn sm g" data-a="start">'+ic('play')+_L('شروع</button>'))+
   _L('<button class="btn sm ghost more" data-a="more" title="گزینه‌های بیشتر">')+ic(isOpen?'chevUp':'more')+'</button>'+
   '</div><div class="morebox">'+more+'</div></div>';
}
$('#tab-tunnels').addEventListener('click',async e=>{
  const b=e.target.closest('button[data-a]');if(!b)return;
  if(b.dataset.a==='new'){S.form=null;go('form');return}
  const card=b.closest('[data-name]');if(!card)return;
  const name=card.dataset.name,a=b.dataset.a;
  const t=S.tunnels.find(x=>x.name===name);
  if(a==='more'){card.classList.toggle('open');b.innerHTML=ic(card.classList.contains('open')?'chevUp':'more');return}
  if(a==='edit'){S.form=JSON.parse(JSON.stringify(t));go('form');return}
  if(a==='clone'){S.form=Object.assign(JSON.parse(JSON.stringify(t)),{clone_of:t.name,name:''});go('form');return}
  if(['restart','start','stop'].includes(a)){
    await busy(b,async()=>{await api('action',{name,op:a});toast(_L('انجام شد'),'ok');await loadTunnels(true)});return}
  if(a==='ping'){await busy(b,async()=>{const d=await api('ping',{name});
    modal(_L('پینگ داخل لینک ')+((t.link||'gre')==='sit'?'6to4':(t.link||'gre').toUpperCase())+' → '+d.peer,'<div class="hint '+(d.ok?'ok':'err')+'" style="margin-bottom:8px">'+(d.ok?ic('check')+_L(' لینک شبکه برقرار است'):ic('x')+_L(' پاسخی نیامد (لینک، فایروال یا مسدود بودن پروتکل GRE=47 / IPIP=4 / 6to4=41 را چک کنید)'))+'</div><pre class="out">'+esc(d.text)+'</pre>')});return}
  if(a==='logs'){showLogs(name,'service');return}
  if(a==='ports'){await busy(b,()=>portTest(name));return}
  if(a==='gre'){await busy(b,async()=>{const d=await api('gre_info',{name});modal(_L('اطلاعات لینک ')+t.dev,'<pre class="out">'+esc(d.text)+'</pre>')});return}
  if(a==='cron'){
    const cur=t.state.restart_cron||'';
    const ov=modal(_L('ری‌استارت خودکار ')+name,_L('<label class="f"><span>بازه</span><select id="cronSel">')+Object.keys(CRON).map(k=>'<option value="'+k+'"'+(k===cur?' selected':'')+'>'+CRON[k]+'</option>').join('')+_L('</select></label><div class="hint">فقط همین تانل ری‌استارت می‌شود و بقیه تانل‌ها قطع نمی‌شوند.</div>'),
      [{text:_L('ذخیره'),cls:'p',fn:btn=>busy(btn,async()=>{await api('cron',{name,schedule:$('#cronSel').value});closeModal();toast(_L('ذخیره شد'),'ok');loadTunnels(true)})}]);
    return}
  if(a==='raw'){await busy(b,async()=>{const d=await api('raw_get',{name});
    if(d.readonly){modal(_L('اسکریپت ')+name+_L(' (فقط خواندنی)'),_L('<div class="warnbox">این اسکریپت از تنظیمات تانل ساخته می‌شود؛ برای تغییر از «ویرایش» استفاده کنید.</div><pre class="out">')+esc(d.text)+'</pre>');return}
    modal(_L('ویرایش مستقیم کانفیگ ')+name,_L('<div class="warnbox">ویرایش پیشرفته. نسخه قبلی با پسوند .bak ذخیره می‌شود و بعد از ذخیره سرویس ری‌استارت می‌شود.')+(d.generated?_L(' توجه: این فایل از تنظیمات تانل ساخته می‌شود و با «ویرایش» فرم دوباره بازنویسی می‌شود.'):'')+'</div><textarea id="rawTxt" class="ltr" rows="18" spellcheck="false" style="font:12px/1.5 ui-monospace,Menlo,monospace">'+esc(d.text)+'</textarea>',
      [{text:_L('ذخیره و ری‌استارت'),cls:'p',fn:btn=>busy(btn,async()=>{const r=await api('raw_save',{name,text:$('#rawTxt').value});closeModal();toast(r.warning?(_L('ذخیره شد ولی: ')+r.warning):_L('ذخیره شد'),r.warning?'err':'ok');loadTunnels(true)})}])});return}
  if(a==='delete'){
    modal(_L('حذف تانل'),_L('<p>تانل <b class="ltr">')+esc(name)+_L('</b> همراه با سرویس، اینترفیس لینک <span class="ltr">')+esc(t.dev)+_L('</span>، کرون‌ها و فایل‌هایش حذف شود؟</p>'),
      [{text:_L('بله، حذف شود'),cls:'d',fn:btn=>busy(btn,async()=>{await api('delete',{name});closeModal();toast(_L('حذف شد'),'ok');loadTunnels()})},{text:_L('انصراف'),fn:closeModal}]);
  }
});
async function portTest(name){
  const d=await api('port_test',{name}),ir=d.role==='iran';
  const head='<div class="stats" style="margin-bottom:10px">'+
    _L('<div class="stat"><span>سرویس تانل</span><b style="color:')+(d.active==='active'?'var(--ok)':'var(--bad)')+'">'+(d.active==='active'?_L('فعال'):esc(d.active))+'</b></div>'+
    _L('<div class="stat"><span>اتصال‌های تانل')+(d.engine==='hysteria'?' (UDP)':'')+'</span><b style="color:'+(d.tunnel_conns>0?'var(--ok)':d.tunnel_conns===0?'var(--bad)':'var(--mut)')+'">'+(d.tunnel_conns==null?'-':d.tunnel_conns)+'</b></div>'+
    (d.gre_ok===null?'':_L('<div class="stat"><span>لینک تا <span class="ltr">')+esc(d.peer||'-')+'</span></span><b style="color:'+(d.gre_ok?'var(--ok)':'var(--bad)')+'">'+(d.gre_ok?_L('وصل'):_L('قطع'))+'</b></div>')+
    _L('<div class="stat"><span>پورت‌های سالم</span><b style="color:')+(d.ok_count===d.total?'var(--ok)':'var(--warn)')+'">'+d.ok_count+' / '+d.total+'</b></div></div>'+
    (d.gre_ok===false?_L('<div class="warnbox">لینک شبکه قطع است؛ تا لینک وصل نشود هیچ پورتی کار نمی‌کند (دامنه‌ها، فایروال یا مسدود بودن پروتکل لینک در دیتاسنتر را چک کنید؛ می‌توانید نوع لینک را عوض کنید).</div>'):'');
  const ctrlTxt={ok:_L('وصل'),token:_L('خطای توکن'),missing:_L('پورت در طرف مقابل نیست'),error:_L('خطا'),'':_L('لاگی نیست')};
  const rows=d.rows.map(r=>'<div class="bk"><span class="dot '+(r.ok?'ok':'bad')+'"></span><div class="n"><b class="ltr">'+r.port+'/'+r.type+'</b> '+
    '<span class="hint">'+(d.engine==='backhaul'?'':_L('تانل: ')+ctrlTxt[r.ctrl]+' · ')+(ir?(_L('باز روی ایران: ')+(r.listen?_L('بله'):_L('خیر'))+(r.e2e?' · '+_L('اتصال تا خارج: ')+(r.e2e==='ok'?_L('برقرار'):_L('برقرار نشد')):'')):(_L('سرویس محلی: ')+(r.probe==='ok'?_L('جواب می‌دهد'):r.probe==='refused'?_L('بسته است'):esc(r.probe))))+'</span>'+
    (r.problems.length?'<div class="hint err">'+r.problems.map(esc).join(' · ')+'</div>':'<div class="hint ok">'+ic('check','sm')+_L(' سالم</div>'))+'</div></div>').join('');
  modal(_L('تست پورت‌های ')+name,head+'<div class="card" style="padding:4px 12px">'+rows+'</div>'+
    '<div class="hint" style="margin-top:8px">'+(ir?_L('سمت ایران: بررسی می‌شود که تانل هر پورت وصل است، پورت باز است و اتصال تا سرویس سمت خارج می‌رسد.'):_L('سمت خارج: بررسی می‌شود که تانل هر پورت وصل است و سرویس اصلی (مثلا Xray) روی این سرور به آن پورت جواب می‌دهد.'))+(d.engine==='backhaul'?_L(' «اتصال‌های تانل» تعداد اتصال‌های برقرار بین دو سرور روی پورت تانل است.'):_L(' همه موارد همین لحظه بررسی می‌شوند؛ سمت ایران برای هر پورت یک اتصال آزمایشی تا سرور خارج زده می‌شود.'))+'</div>',
    [{text:_L('تست دوباره'),cls:'p',fn:btn=>busy(btn,()=>portTest(name))}]);
}
async function showLogs(name,kind){
  try{
    const d=await api('logs',{name,kind,lines:300});
    const ov=modal(_L('لاگ ')+name,'<div class="seg" style="margin-bottom:10px"><button data-k="service" class="'+(kind==='service'?'on':'')+_L('">سرویس تانل</button><button data-k="gre" class="')+(kind==='gre'?'on':'')+_L('">لینک</button></div><pre class="out" id="logOut">')+esc(d.text)+'</pre>',
      [{text:_L('بروزرسانی'),fn:()=>showLogs(name,kind)}]);
    $$('.seg button',ov).forEach(b=>b.onclick=()=>showLogs(name,b.dataset.k));
    const o=$('#logOut');o.scrollTop=o.scrollHeight;
  }catch(e){toast(e.message,'err')}
}

/* ---------------- create / edit form ---------------- */
function v6of(ip){const o=ip.split('.').map(Number);return 'fd00:'+o[0].toString(16)+':'+o[1].toString(16)+':'+o[2].toString(16)+'::'+o[3].toString(16)}
function calc30(ip){
  const m=/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec((ip||'').trim());
  if(!m)return null;const o=m.slice(1).map(Number);if(o.some(x=>x>255))return null;
  const last=o[3],base=last&~3,r=last-base;
  if(r===0||r===3)return {err:_L('آخرین عدد نباید ')+last+_L(' باشد (آدرس شبکه/برادکست). مثلا ')+(base+1)+_L(' یا ')+(base+2)};
  return {peer:o.slice(0,3).join('.')+'.'+(r===1?base+2:base+1),net:o.slice(0,3).join('.')+'.'+base+'/30'};
}
function renderForm(){
  const e=S.form,edit=!!(e&&e.name),clone=!!(e&&e.clone_of);
  const f=e?{role:e.role,port:clone?'':e.port,local_domain:e.local_domain,remote_domain:e.remote_domain,gre_ip:e.gre_ip,peer_ip:e.peer_ip,mtu:e.mtu||1476,token:e.token,nodelay:e.nodelay,heartbeat:e.heartbeat,retry:e.retry||1,ipv6:e.ipv6,mode:e.mode||'gre',cdn_domain:e.cdn_domain||'',cdn_tls:e.mode==='cdn'?!!e.cdn_tls:true,services:(e.services||[]).map(s=>({port:s.port,type:s.type})),
      engine:e.engine||'rathole',transport:e.engine==='backhaul'?(e.transport||'tcpmux'):'tcpmux',keepalive:e.keepalive||75,channel_size:e.channel_size||2048,mux_con:e.mux_con||8,mux_version:e.mux_version||1,conn_pool:e.conn_pool||8,aggressive:!!e.aggressive,dial_timeout:e.dial_timeout||10,edge_ip:e.edge_ip||'',remote_host:e.remote_host||'',
      link:e.link||'gre',protocol:e.protocol||'tcp',tcp_mux:e.tcp_mux!==false,pool:e.pool||8,gtransport:e.engine==='gost'?(e.transport||'tls'):'tls',obfs:e.obfs||'',xsec:e.xsec||'reality',sni:e.sni||'www.speedtest.net'}
    :{role:'iran',port:'',local_domain:'',remote_domain:'',gre_ip:'',peer_ip:'',mtu:1476,token:randTok(),nodelay:true,heartbeat:0,retry:1,ipv6:false,mode:'gre',cdn_domain:'',cdn_tls:true,services:[],
      engine:'rathole',transport:'tcpmux',keepalive:75,channel_size:2048,mux_con:8,mux_version:1,conn_pool:8,aggressive:false,dial_timeout:10,edge_ip:'',remote_host:'',
      link:'gre',protocol:'tcp',tcp_mux:true,pool:8,gtransport:'tls',obfs:'',xsec:'reality',sni:'www.speedtest.net'};
  if(clone){f.peer_ip='';S.src=e;if(f.role==='iran')f.services=[]}else S.src=null;
  S.ff=f;
  const el=$('#tab-form');
  el.innerHTML='<div class="form">'+
   '<h2>'+(edit?_L('ویرایش تانل <span class="ltr">')+esc(e.name)+'</span>':clone?_L('کلون از <span class="ltr">')+esc(e.clone_of)+'</span>':_L('ساخت تانل جدید'))+'</h2>'+
   (clone?_L('<div class="warnbox">همه تنظیمات و پورت‌های سرویس از <b class="ltr">')+esc(e.clone_of)+_L('</b> کپی شد. برای ذخیره باید این‌ها را عوض کنید: <b>پورت تانل</b>، ')+(f.mode==='cdn'?_L('<b>دامنه CDN</b>'):f.mode==='direct'?(f.role===(ENG[f.engine]||ENG.rathole).dialer?_L('<b>آدرس سرور مقابل</b>'):_L('(در حالت مستقیم این سمت فقط پورت)')):_L('<b>دامنه سرور مقابل</b> و <b>IP داخلی GRE</b>'))+(f.role==='iran'?_L(' — پورت‌های سرویس هم باید جدید باشند؛ روی یک سرور هر پورت فقط در یک تانل استفاده می‌شود')+'':'')+_L(' (با رنگ زرد مشخص شده‌اند).</div>'):'')+
   '<div class="seg wrap" id="engSeg">'+Object.keys(ENG).map(k=>'<button type="button" data-e="'+k+'">'+ENG[k].label+'</button>').join('')+'</div>'+
   '<div class="hint" id="engHint" style="margin:6px 0 12px"></div>'+
   _L('<div class="seg" id="roleSeg"><button type="button" data-r="iran">سرور ایران</button><button type="button" data-r="kharej">سرور خارج</button></div>')+
   '<div class="hint" id="roleHint" style="margin:6px 0 12px"></div>'+
   _L('<div class="seg" id="modeSeg"><button type="button" data-m="gre">لینک شبکه</button><button type="button" data-m="direct">مستقیم</button><button type="button" data-m="cdn">CDN کلادفلر</button></div>')+
   '<div class="hint" id="modeHint" style="margin:6px 0 12px"></div>'+
   '<form id="tf" autocomplete="off">'+
   _L('<div class="row"><label class="f"><span id="lPort">پورت تانل</span><input class="ltr')+(clone?' mustchange':'')+'" name="port" inputmode="numeric" value="'+esc(f.port)+'"'+(edit?' disabled':'')+(clone?_L(' placeholder="پورت جدید"'):'')+'><div class="hint" id="portHint">'+(edit?_L('پورت تانل قابل تغییر نیست؛ برای تغییر، تانل جدید بسازید.'):_L('باید در هر دو سرور یکی باشد.'))+'</div></label>'+
   _L('<label class="f" id="tokWrap"><span>توکن امنیتی</span><div class="inline"><input class="ltr" name="token" type="password" autocomplete="off" spellcheck="false" value="')+esc(f.token)+_L('"><button type="button" class="btn sq" id="eyeTok" title="نمایش">')+ic('eye')+_L('</button><button type="button" class="btn sq" id="copyTok" title="کپی">')+ic('copy')+_L('</button><button type="button" class="btn" id="genTok">تصادفی</button></div><div class="hint">باید در هر دو سرور یکی باشد.</div></label></div>')+
   _L('<div id="cdnSec"><h3>تنظیمات CDN کلادفلر</h3>')+
   _L('<label class="f"><span>دامنه پروکسی‌شده (رکورد A به IP سرور ایران، ابر نارنجی روشن)</span><input class="ltr')+(clone?' mustchange':'')+'" name="cdn_domain" placeholder="cdn.example.com" value="'+esc(f.cdn_domain)+_L('"><div class="hint">در هر دو سرور همین دامنه را وارد کنید.</div></label>')+
   _L('<label class="sw" id="cdnTlsWrap"><span>TLS (wss) <span class="hint">(پیشنهادی؛ ترافیک داخل ایران رمزنگاری می‌شود)</span></span><input type="checkbox" name="cdn_tls"')+(f.cdn_tls?' checked':'')+'></label>'+
   '<div class="warnbox" id="cdnHelp"></div></div>'+
   _L('<div id="directSec"><h3>اتصال مستقیم</h3>')+
   _L('<label class="f" id="rhWrap"><span id="lRh">آدرس سرور ایران (دامنه یا IP)</span><input class="ltr')+(clone?' mustchange':'')+'" name="remote_host" placeholder="ir.example.com" value="'+esc(f.remote_host)+'"><div class="hint" id="rhHint"></div></label>'+
   '<div class="hint" id="directHint"></div></div>'+
   _L('<div id="greSec"><h3>تنظیمات لینک شبکه (بر اساس دامنه)</h3>')+
   _L('<label class="f"><span>نوع لینک (هر دو سرور یکی)</span><select name="link">')+[['gre',_L('GRE (پروتکل 47)')],['ipip',_L('IPIP (پروتکل 4)')],['sit',_L('6to4 / SIT (پروتکل 41، IPv6 داخلی)')]].map(x=>'<option value="'+x[0]+'"'+(x[0]===(f.link||'gre')?' selected':'')+'>'+x[1]+'</option>').join('')+'</select><div class="hint" id="linkHint"></div></label>'+
   '<div class="row"><label class="f"><span id="lLocal"></span><input class="ltr" name="local_domain" placeholder="ir.example.com" value="'+esc(f.local_domain)+'"></label>'+
   '<label class="f"><span id="lRemote"></span><input class="ltr'+(clone?' mustchange':'')+'" name="remote_domain" placeholder="de.example.com" value="'+esc(f.remote_domain)+'"></label></div>'+
   '<div class="row"><label class="f"><span id="lGre"></span><div class="inline"><input class="ltr'+(clone?' mustchange':'')+'" name="gre_ip" placeholder="10.10.1.1" value="'+esc(f.gre_ip)+_L('"><button type="button" class="btn" id="sugNet" title="اولین شبکه آزاد را پیشنهاد بده">پیشنهاد</button></div><div class="hint" id="greHint"></div></label>')+
   _L('<label class="f" id="peerWrap"><span>IP داخلی سرور ایران</span><input class="ltr" name="peer_ip" placeholder="خودکار" value="')+esc(f.peer_ip)+_L('"><div class="hint">خالی بگذارید تا خودکار حساب شود.</div></label>')+
   '<label class="f" id="mtuWrapA"><span>MTU</span><input class="ltr" name="mtu" inputmode="numeric" value="'+esc(f.mtu)+'"></label></div>'+
   '<label class="f hidden" id="mtuWrapB"><span>MTU</span><input class="ltr" name="mtu2" inputmode="numeric" value="'+esc(f.mtu)+'"></label></div>'+
   _L('<div id="frpSec" class="esec"><h3>تنظیمات FRP</h3><div class="row">')+
   _L('<label class="f"><span>پروتکل (هر دو سرور یکی)</span><select name="protocol">')+['tcp','kcp','quic','websocket'].map(x=>'<option'+(x===(f.protocol||'tcp')?' selected':'')+'>'+x+'</option>').join('')+_L('</select><div class="hint">kcp و quic روی UDP هستند؛ برای لینک‌های پرافت.</div></label>')+
   _L('<label class="f fr-kh"><span>Pool count (اتصال‌های آماده)</span><input class="ltr" name="pool" inputmode="numeric" value="')+esc(f.pool)+'"></label></div>'+
   _L('<label class="sw"><span>TCP Mux (هر دو سرور یکی)</span><input type="checkbox" name="tcp_mux"')+(f.tcp_mux?' checked':'')+'></label></div>'+
   _L('<div id="gostSec" class="esec"><h3>تنظیمات Gost</h3><label class="f"><span>ترنسپورت (هر دو سرور یکی)</span><select name="gtransport">')+GOST_TR.map(x=>'<option'+(x===(f.gtransport||'tls')?' selected':'')+'>'+x+'</option>').join('')+_L('</select><div class="hint">mtls / mwss = چندتایی‌سازی؛ ws/wss قابل عبور از CDN؛ kcp/quic روی UDP.</div></label></div>')+
   _L('<div id="hySec" class="esec"><h3>تنظیمات Hysteria2</h3><label class="f"><span>رمز Obfs (اختیاری، هر دو سرور یکی)</span><input class="ltr" name="obfs" value="')+esc(f.obfs)+_L('" placeholder="خالی = بدون obfs"><div class="hint">obfs (salamander) ترافیک QUIC را مبهم می‌کند. گواهی سمت خارج خودکار ساخته می‌شود. پورت تانل UDP است.</div></label></div>')+
   _L('<div id="xrSec" class="esec"><h3>تنظیمات Xray Reverse</h3><div class="row">')+
   _L('<label class="f"><span>امنیت اتصال</span><select name="xsec"><option value="reality" selected>REALITY</option></select><div class="hint">نسخه‌های جدید Xray اتصال VLESS بدون رمزنگاری را مسدود می‌کنند؛ فقط REALITY.</div></label>')+
   _L('<label class="f"><span>SNI (هر دو سرور یکی)</span><input class="ltr" name="sni" value="')+esc(f.sni)+'"></label></div>'+
   _L('<div class="hint">UUID و کلیدهای REALITY خودکار از توکن ساخته می‌شوند؛ کافی است توکن دو طرف یکی باشد. هسته xray باید روی هر دو سرور نصب باشد.</div></div>')+
   _L('<div id="bhSec"><h3>تنظیمات Backhaul</h3>')+
   _L('<div class="row"><label class="f"><span>ترنسپورت (هر دو سرور یکی)</span><select name="transport">')+['tcp','tcpmux','ws','wss','wsmux','wssmux'].map(x=>'<option'+(x===f.transport?' selected':'')+'>'+x+'</option>').join('')+'</select><div class="hint" id="trHint"></div></label>'+
   _L('<label class="f"><span>Keepalive (ثانیه)</span><input class="ltr" name="keepalive" inputmode="numeric" value="')+esc(f.keepalive)+'"></label></div>'+
   '<div class="row bh-ir"><label class="f"><span>Channel size</span><input class="ltr" name="channel_size" inputmode="numeric" value="'+esc(f.channel_size)+'"></label>'+
   '<label class="f bh-mux"><span>Mux connections</span><input class="ltr" name="mux_con" inputmode="numeric" value="'+esc(f.mux_con)+'"></label></div>'+
   '<div class="row bh-kh"><label class="f"><span>Connection pool</span><input class="ltr" name="conn_pool" inputmode="numeric" value="'+esc(f.conn_pool)+'"></label>'+
   _L('<label class="f"><span>Dial timeout (ثانیه)</span><input class="ltr" name="dial_timeout" inputmode="numeric" value="')+esc(f.dial_timeout)+'"></label></div>'+
   _L('<div class="row"><label class="f bh-mux"><span>Mux version (هر دو سرور یکی)</span><select name="mux_version"><option')+(+f.mux_version===1?' selected':'')+'>1</option><option'+(+f.mux_version===2?' selected':'')+'>2</option></select></label>'+
   _L('<label class="f bh-kh bh-ws"><span>Edge IP کلادفلر (اختیاری)</span><input class="ltr" name="edge_ip" placeholder="188.114.96.0" value="')+esc(f.edge_ip)+'"></label></div>'+
   '<label class="sw bh-kh"><span>Aggressive pool</span><input type="checkbox" name="aggressive"'+(f.aggressive?' checked':'')+'></label></div>'+
   _L('<div id="commonSec"><h3 id="rhTitle">تنظیمات rathole</h3>')+
   '<div class="row"><label class="f"><span id="lHb"></span><input class="ltr" name="heartbeat" inputmode="numeric" value="'+esc(f.heartbeat)+'"><div class="hint" id="hbHint"></div></label>'+
   _L('<label class="f" id="retryWrap"><span>Retry interval (ثانیه)</span><input class="ltr" name="retry" inputmode="numeric" value="')+esc(f.retry)+'"></label></div>'+
   _L('<label class="sw"><span>TCP_NODELAY <span class="hint">(تاخیر کمتر، پهنای باند کمی کمتر)</span></span><input type="checkbox" name="nodelay"')+(f.nodelay?' checked':'')+'></label>'+
   _L('<label class="sw" id="v6Wrap"><span>گوش دادن روی IPv6 <span class="ltr">[::]</span></span><input type="checkbox" name="ipv6"')+(f.ipv6?' checked':'')+'></label></div>'+
   _L('<h3>پورت‌های سرویس</h3>')+
   '<div id="svcList"></div>'+
   '<div class="inline" style="margin-top:6px"><input class="ltr" id="bulkPorts" placeholder="2070,2080,8443" inputmode="numeric"><select id="bulkType" style="width:90px"><option>tcp</option><option>udp</option></select><button type="button" class="btn" id="addPorts">'+ic('plus')+_L('افزودن</button></div>')+
   _L('<div class="hint">چند پورت را با کاما جدا کنید. پورت‌ها باید در هر دو سرور یکی باشند.</div>')+
   '<div class="savebar"><button class="btn p" id="saveBtn" style="padding:10px 22px">'+(edit?_L('ذخیره تغییرات'):clone?_L('ساخت کلون'):_L('ساخت تانل'))+'</button>'+
   (edit||clone?_L('<button type="button" class="btn" id="cancelEdit">انصراف</button>'):'')+'<span class="hint" id="saveHint"></span></div>'+
   '<pre class="out hidden" id="createLog" style="margin-top:12px"></pre>'+
   '</form></div>';
  S.ff.engine=f.engine;
  setRole(f.role,edit);setEngine(f.engine,edit||clone);renderSvcs();
  $('#engSeg').onclick=ev=>{const b=ev.target.closest('button');if(!b||edit||clone)return;collect();setEngine(b.dataset.e,false)};
  $('[name=link]').onchange=()=>{linkHint();greHint()};
  $('[name=transport]').onchange=()=>{S.ff.transport=$('[name=transport]').value;collect();setEngine(S.ff.engine,edit||clone)};
  $('#modeSeg').onclick=ev=>{const b=ev.target.closest('button');if(!b)return;collect();
    if(b.dataset.m==='cdn'&&!(+S.ff.heartbeat>0)){S.ff.heartbeat=(S.ff.role==='iran'&&S.ff.engine!=='backhaul')?30:40;$('[name=heartbeat]').value=S.ff.heartbeat}
    setMode(b.dataset.m)};
  $('[name=cdn_tls]').onchange=()=>{S.ff.cdn_tls=$('[name=cdn_tls]').checked;setMode(S.ff.mode)};
  $('#roleSeg').onclick=ev=>{const b=ev.target.closest('button');if(!b||edit||clone)return;collect();
    const r=b.dataset.r;if(r!==S.ff.role&&S.ff.engine!=='backhaul'){if(+S.ff.heartbeat===(S.ff.role==='iran'?30:40))S.ff.heartbeat=(r==='iran'?30:40);$('[name=heartbeat]').value=S.ff.heartbeat}
    setRole(r,edit)};
  $('#genTok').onclick=()=>{$('[name=token]').value=randTok()};
  $('[name=gre_ip]').addEventListener('input',greHint);
  $('#addPorts').onclick=addBulk;
  $('#bulkPorts').addEventListener('keydown',ev=>{if(ev.key==='Enter'){ev.preventDefault();addBulk()}});
  if(edit||clone)$('#cancelEdit').onclick=()=>{S.form=null;go('tunnels')};
  $('#eyeTok').onclick=()=>{const i=$('[name=token]');i.type=i.type==='password'?'text':'password'};
  $('#copyTok').onclick=()=>copyText($('[name=token]').value);
  $('#sugNet').onclick=()=>{const v=suggestNet($('[name=gre_ip]').value);if(v){$('[name=gre_ip]').value=v;clearErr('gre_ip');greHint()}};
  $('#tf').addEventListener('input',ev=>{if(ev.target.name)clearErr(ev.target.name)});
  if(clone&&f.role)$$('#roleSeg button').forEach(b=>b.disabled=b.dataset.r!==f.role);
  $('#tf').addEventListener('submit',submitForm);
}
function setRole(r,edit){
  S.ff.role=r;const ir=r==='iran';
  $$('#roleSeg button').forEach(b=>{b.classList.toggle('on',b.dataset.r===r);b.disabled=edit&&b.dataset.r!==r});
  $('#roleHint').textContent=ir?_L('سرور ایران: پورت‌های سرویس روی این سرور باز می‌شوند و کاربران به آن وصل می‌شوند.'):_L('سرور خارج: سرویس اصلی (مثلا Xray) روی این سرور است و تانل از این سرور به سرور ایران وصل می‌شود.');
  $('#lLocal').textContent=_L('دامنه همین سرور (')+(ir?_L('ایران'):_L('خارج'))+')';
  $('#lRemote').textContent=_L('دامنه سرور مقابل (')+(ir?_L('خارج'):_L('ایران'))+')';
  $('#lGre').textContent=_L('IP داخلی همین سرور (')+(ir?_L('ایران'):_L('خارج'))+')';
  $('#lHb').textContent=ir?_L('Heartbeat interval (ثانیه)'):_L('Heartbeat timeout (ثانیه)');
  $('#v6Wrap').classList.toggle('hidden',!ir);
  $('#hbHint').textContent=ir?_L('پیش‌فرض 0 (خاموش؛ قطعی را TCP keepalive تشخیص می‌دهد). اگر روشن می‌کنید، سمت خارج باید بیشتر از ایران باشد (مثلا ایران 30، خارج 40).'):_L('پیش‌فرض 0 (خاموش). اگر روشن می‌کنید، باید از مقدار سمت ایران بیشتر باشد، نه مساوی (ایران 30 → خارج 40). دو طرف 0 هم درست است.');
  $('#peerWrap').classList.toggle('hidden',ir);$('#retryWrap').classList.toggle('hidden',ir);
  $('#mtuWrapA').classList.toggle('hidden',ir);$('#mtuWrapB').classList.toggle('hidden',!ir);
  if($('#engSeg'))setEngine(S.ff.engine||'rathole',!!(S.form&&(S.form.name||S.form.clone_of)));else greHint();
}
const CF_TLS=[443,2053,2083,2087,2096,8443],CF_HTTP=[80,8080,8880,2052,2082,2086,2095];
const ENG={
  rathole:{label:'Rathole',modes:['gre'],dialer:'kharej',desc:_L('Rathole: خارج به ایران وصل می‌شود (معکوس). روی لینک GRE/IPIP/6to4.')},
  backhaul:{label:'Backhaul',modes:['gre','direct','cdn'],dialer:'kharej',desc:_L('Backhaul: خارج به ایران وصل می‌شود؛ tcp / tcpmux / ws / wss و CDN کلادفلر.')},
  frp:{label:'FRP',modes:['gre','direct'],dialer:'kharej',desc:_L('FRP: خارج (frpc) به ایران (frps) وصل می‌شود؛ پروتکل tcp / kcp / quic / websocket.')},
  gost:{label:'Gost',modes:['gre','direct'],dialer:'iran',desc:_L('Gost: ایران به خارج وصل می‌شود (رله)؛ tls / mtls / ws / wss / grpc / kcp / quic …')},
  hysteria:{label:'Hysteria2',modes:['gre','direct'],dialer:'iran',desc:_L('Hysteria2: ایران به خارج وصل می‌شود؛ روی QUIC/UDP، مناسب لینک‌های پرافت.')},
  xray:{label:'Xray Reverse',modes:['gre','direct'],dialer:'kharej',noudp:true,desc:_L('Xray Reverse: خارج (bridge) به ایران (portal) وصل می‌شود؛ با REALITY مخفی‌ترین گزینه. فقط TCP.')},
  iptables:{label:'iptables',modes:['gre','direct'],dialer:'iran',notoken:true,desc:_L('iptables: فوروارد مستقیم کرنل بدون برنامه تانل؛ کمترین سربار. فقط روی سرور ایران ساخته می‌شود (در حالت لینک، سمت خارج فقط لینک).')}};
const GOST_TR=['tls','mtls','ws','wss','mwss','grpc','h2','tcp','kcp','quic'];
function setEngine(e,locked){
  S.ff.engine=e;const bh=e==='backhaul',ir=S.ff.role==='iran',E=ENG[e]||ENG.rathole,gen=!(e==='rathole'||bh);
  $$('#engSeg button').forEach(b=>{b.classList.toggle('on',b.dataset.e===e);b.disabled=locked&&b.dataset.e!==e});
  $('#engHint').textContent=E.desc+(gen&&e!=='iptables'?_L(' هسته ')+E.label+_L(' باید روی هر دو سرور نصب باشد.'):'');
  const legacyCdn=e==='rathole'&&S.form&&S.form.name&&S.form.mode==='cdn';
  const modes=legacyCdn?['gre','cdn']:E.modes;
  $$('#modeSeg button').forEach(b=>b.classList.toggle('hidden',modes.indexOf(b.dataset.m)<0));
  $('#bhSec').classList.toggle('hidden',!bh);$('#rhTitle').textContent=bh?_L('تنظیمات عمومی'):_L('تنظیمات rathole');
  $('#commonSec').classList.toggle('hidden',gen);
  [['frp','#frpSec'],['gost','#gostSec'],['hysteria','#hySec'],['xray','#xrSec']].forEach(x=>$(x[1]).classList.toggle('hidden',e!==x[0]));
  $$('.fr-kh').forEach(x=>x.classList.toggle('hidden',ir));
  $('#tokWrap').classList.toggle('hidden',!!E.notoken);
  $('#lPort').textContent=e==='iptables'?_L('شماره تانل'):_L('پورت تانل');
  if(!(S.form&&S.form.name))$('#portHint').textContent=e==='iptables'?_L('فقط برای نام‌گذاری (10 تا 65535)؛ پورتی باز نمی‌شود.'):e==='hysteria'?_L('پورت UDP تانل؛ باید در هر دو سرور یکی باشد.'):_L('باید در هر دو سرور یکی باشد.');
  $('#bulkType').querySelector('option[value=udp],option:nth-child(2)').disabled=!!E.noudp;
  const tr=$('[name=transport]').value,mux=/mux$/.test(tr),ws=/^ws/.test(tr);
  $$('.bh-ir').forEach(x=>x.classList.toggle('hidden',!ir));$$('.bh-kh').forEach(x=>x.classList.toggle('hidden',ir));
  $$('.bh-mux').forEach(x=>x.classList.toggle('hidden',!mux));
  $$('.bh-ws').forEach(x=>x.classList.toggle('hidden',ir||!ws));
  $('#trHint').textContent={tcp:_L('ساده و کم‌سربار؛ پشتیبانی از UDP.'),tcpmux:_L('چندتایی‌سازی؛ برای لینک/مستقیم با تعداد کانکشن زیاد (پیشنهادی).'),ws:_L('WebSocket؛ قابل عبور از CDN.'),wss:_L('WebSocket + TLS؛ گواهی سمت ایران خودکار ساخته می‌شود.'),wsmux:'WebSocket + mux.',wssmux:_L('WebSocket + TLS + mux؛ بهترین گزینه برای CDN کلادفلر.')}[tr]||'';
  // heartbeat only exists on the Backhaul server; retry exists on client for both engines
  $('#lHb').parentNode.classList.toggle('hidden',bh&&!ir);
  const hbIn=$('[name=heartbeat]');
  if(bh){$('#hbHint').textContent=_L('Heartbeat سرور Backhaul (ثانیه، حداقل 1). پیش‌فرض 40.');$('#lHb').textContent=_L('Heartbeat (ثانیه)');
    if(ir&&(hbIn.value==='30'||hbIn.value==='0'||hbIn.value===''))hbIn.value='40'}
  else{$('#lHb').textContent=ir?_L('Heartbeat interval (ثانیه)'):_L('Heartbeat timeout (ثانیه)');
    $('#hbHint').textContent=ir?_L('پیش‌فرض 0 (خاموش؛ قطعی را TCP keepalive تشخیص می‌دهد). اگر روشن می‌کنید، سمت خارج باید بیشتر از ایران باشد (مثلا ایران 30، خارج 40).'):_L('پیش‌فرض 0 (خاموش). اگر روشن می‌کنید، باید از مقدار سمت ایران بیشتر باشد، نه مساوی (ایران 30 → خارج 40). دو طرف 0 هم درست است.');
    if(hbIn.value==='40'&&!(S.form&&S.form.name))hbIn.value='0'}
  let m=S.ff.mode;if(modes.indexOf(m)<0)m='gre';
  setMode(m);
}
function setMode(m){
  const bh=S.ff.engine==='backhaul',trSel=$('[name=transport]');
  if(bh){
    $$('option',trSel).forEach(o=>{o.disabled=m==='cdn'&&!/^ws/.test(o.value)});
    if(m==='cdn'&&!/^ws/.test(trSel.value)){trSel.value='wssmux';S.ff.transport='wssmux'}
    const tr=trSel.value;$$('.bh-mux').forEach(x=>x.classList.toggle('hidden',!/mux$/.test(tr)));
    $$('.bh-ws').forEach(x=>x.classList.toggle('hidden',S.ff.role==='iran'||!/^ws/.test(tr)));
  }
  S.ff.mode=m;const cdn=m==='cdn',direct=m==='direct',ir=S.ff.role==='iran',tls=bh?/^wss/.test(trSel.value):$('[name=cdn_tls]').checked;
  $('#cdnTlsWrap').classList.toggle('hidden',bh);
  $$('#modeSeg button').forEach(b=>b.classList.toggle('on',b.dataset.m===m));
  $('#cdnSec').classList.toggle('hidden',!cdn);$('#greSec').classList.toggle('hidden',cdn||direct);
  const E=ENG[S.ff.engine]||ENG.rathole,dialSide=S.ff.role===E.dialer,otherName=ir?_L('خارج'):_L('ایران');
  $('#directSec').classList.toggle('hidden',!direct);$('#rhWrap').classList.toggle('hidden',!dialSide);
  $('#lRh').textContent=_L('آدرس سرور ')+otherName+_L(' (دامنه یا IP)');
  $('#rhHint').textContent=S.ff.engine==='iptables'?_L('پورت‌های سرویس روی این سرور به همین آدرس فوروارد می‌شوند.'):(bh?_L('برای عبور از کلادفلر با ws/wss، دامنه‌ی پروکسی‌شده را وارد کنید.'):'');
  $('#directHint').textContent=dialSide?'':_L('این سرور روی همه آدرس‌ها روی پورت تانل گوش می‌دهد و سرور ')+otherName+_L(' به آن وصل می‌شود؛ پورت تانل را در فایروال باز کنید.');
  $('#v6Wrap').classList.toggle('hidden',!(ir&&(!bh||direct||cdn)));
  if(direct){$('#modeHint').textContent=_L('اتصال مستقیم: سرور ')+(E.dialer==='iran'?_L('ایران مستقیم به خارج'):_L('خارج مستقیم به ایران'))+_L(' وصل می‌شود؛ لینک شبکه ساخته نمی‌شود.');
    return}
  $('#modeHint').textContent=cdn?(bh?_L('Backhaul از طریق کلادفلر: سرور خارج با WebSocket (پیشنهادی wssmux) به دامنه کلادفلر وصل می‌شود؛ لینک شبکه ساخته نمی‌شود و IP سرور ایران پشت کلادفلر مخفی می‌ماند.'):_L('CDN قدیمی rathole (فقط ویرایش). برای تانل جدید از Backhaul استفاده کنید.')):_L('تانل داخل GRE بین دو سرور ساخته می‌شود.');
  const ports=tls?CF_TLS:CF_HTTP;
  if(!(S.form&&S.form.name))$('#portHint').textContent=cdn?(_L('پورت‌های مجاز کلادفلر ')+(tls?_L('با TLS'):_L('بدون TLS'))+': '+ports.join(_L('، '))+_L(' — نباید با پورت‌های سرویس یکی باشد.')):_L('باید در هر دو سرور یکی باشد.');
  $('#cdnHelp').innerHTML=_L('<b>تنظیمات کلادفلر:</b><br>• رکورد A دامنه به IP سرور <b>ایران</b> با ابر نارنجی (Proxied) روشن.<br>• Network ← WebSockets روشن باشد.<br>')+
    (tls?_L('• SSL/TLS ← حالت <b>Full</b> (نه Strict). گواهی سمت ایران خودکار ساخته می‌شود.'):_L('• «Always Use HTTPS» خاموش باشد، وگرنه اتصال برقرار نمی‌شود.'))+
    _L('<br>• فایروال سرور ایران باید پورت تانل را برای IPهای کلادفلر باز بگذارد.')+
    (bh?_L('<br>• روی سرور خارج می‌توانید یک IP تمیز کلادفلر را در «Edge IP» بگذارید تا اتصال به آن IP برود.<br>• Heartbeat سمت ایران زیر 80 ثانیه بماند (پیش‌فرض 40).'):_L('<br>• Heartbeat حتما روشن بماند (ایران 30، خارج 40)؛ کلادفلر اتصال بیکار را بعد از 100 ثانیه قطع می‌کند.'));
  if(!cdn){greHint();linkHint()}
}
function linkHint(){
  const lk=$('[name=link]').value,el=$('#linkHint');
  el.textContent={gre:_L('پیش‌فرض و رایج. اگر دیتاسنتر GRE را بست، IPIP یا 6to4 را امتحان کنید.'),ipip:_L('سبک‌تر از GRE (سربار 20 بایت). بعضی دیتاسنترها که GRE را می‌بندند IPIP را باز می‌گذارند.'),sit:_L('IPv6 داخل IPv4. آدرس داخلی IPv6 خودکار از IP داخلی ساخته می‌شود. (برای iptables قابل استفاده نیست)')}[lk];
  const mt=$('[name=mtu]'),mt2=$('[name=mtu2]'),def={gre:'1476',ipip:'1480',sit:'1480'};
  [mt,mt2].forEach(x=>{if(['1476','1480',''].indexOf(x.value)>=0)x.value=def[lk]});
}
function greHint(){
  const v=$('[name=gre_ip]').value,h=$('#greHint'),c=calc30(v),ir=S.ff.role==='iran';
  if(!v){h.className='hint';h.textContent=_L('برای هر تانل یک شبکه جدا بدهید (مثلا 10.10.1.1، تانل بعدی 10.10.2.1).');return}
  if(!c){h.className='hint err';h.textContent=_L('IPv4 نامعتبر');return}
  if(c.err){h.className='hint err';h.textContent=c.err;return}
  const clash=S.tunnels.find(t=>t.gre_ip&&(!S.form||t.name!==S.form.name)&&calc30(t.gre_ip)&&calc30(t.gre_ip).net===c.net);
  if(clash){h.className='hint err';h.textContent=_L('شبکه ')+c.net+_L(' قبلا برای ')+clash.name+_L(' استفاده شده!');return}
  h.className='hint ok';h.textContent=_L('شبکه ')+c.net+_L(' · IP داخلی سرور ')+(ir?_L('خارج'):_L('ایران'))+_L(' باید ')+c.peer+_L(' باشد')+($('[name=link]').value==='sit'?_L(' · IPv6 داخلی: ')+v6of(v):'');
}
function renderSvcs(){
  const l=$('#svcList');
  if(!S.ff.services.length){l.innerHTML=_L('<div class="hint">هنوز پورتی اضافه نشده.</div>');return}
  l.innerHTML=S.ff.services.map((s,i)=>'<div class="svc"><input class="ltr" data-i="'+i+'" data-f="port" value="'+esc(s.port)+'" inputmode="numeric"><select data-i="'+i+'" data-f="type"><option'+(s.type==='tcp'?' selected':'')+'>tcp</option><option'+(s.type==='udp'?' selected':'')+'>udp</option></select><button type="button" class="btn sm d" data-del="'+i+_L('" title="حذف">')+ic('x')+'</button></div>').join('');
  $$('[data-f]',l).forEach(x=>x.onchange=()=>{S.ff.services[+x.dataset.i][x.dataset.f]=x.value});
  $$('[data-del]',l).forEach(x=>x.onclick=()=>{S.ff.services.splice(+x.dataset.del,1);renderSvcs()});
}
function addBulk(){
  const v=$('#bulkPorts').value,ty=$('#bulkType').value;let n=0;
  v.split(/[,\s،]+/).filter(Boolean).forEach(p=>{
    if(/^\d+-\d+$/.test(p)){const [a,b]=p.split('-').map(Number);if(b-a>200){toast(_L('بازه حداکثر 200 پورت'),'err');return}for(let i=a;i<=b;i++)push(i)}
    else push(p)});
  function push(p){p=+p;if(!(p>22&&p<=65535)){toast(_L('پورت ')+p+_L(' نامعتبر است'),'err');return}
    if(S.ff.services.some(s=>+s.port===p&&s.type===ty))return;S.ff.services.push({port:p,type:ty});n++}
  $('#bulkPorts').value='';renderSvcs();if(n)toast(n+_L(' پورت اضافه شد'),'ok');
}
function copyText(t){
  if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(()=>toast(_L('کپی شد'),'ok'),()=>toast(_L('کپی نشد'),'err'));return}
  const ta=document.createElement('textarea');ta.value=t;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();
  try{document.execCommand('copy');toast(_L('کپی شد'),'ok')}catch(e){toast(_L('کپی نشد'),'err')}ta.remove();
}
function suggestNet(cur){
  const used=new Set(S.tunnels.filter(t=>t.gre_ip&&(!S.form||t.name!==S.form.name)).map(t=>(calc30(t.gre_ip)||{}).net));
  const m=/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec((cur||'').trim())||[0,10,10,0,S.ff.role==='iran'?1:2];
  const a=+m[1],b=+m[2],last=(+m[4]%4===2)?2:1;
  for(let i=1;i<=254;i++){const c=(+m[3]+i)%255;const ip=a+'.'+b+'.'+c+'.'+last;const n=calc30(ip);if(n&&!n.err&&!used.has(n.net))return ip}
  toast(_L('شبکه آزادی پیدا نشد'),'err');return '';
}
function fieldErr(name,msg){
  const el=name==='services'?$('#svcList'):$('[name='+name+']');if(!el)return false;
  el.classList.add('bad');const box=el.closest('label.f')||el.parentNode;
  let e=$('.ferr',box);if(!e){e=document.createElement('div');e.className='ferr';box.appendChild(e)}e.textContent=msg;
  el.scrollIntoView({behavior:'smooth',block:'center'});if(el.focus)el.focus({preventScroll:true});return true;
}
function clearErr(name){const el=$('[name='+name+']');if(!el)return;el.classList.remove('bad');const box=el.closest('label.f')||el.parentNode;const e=$('.ferr',box);if(e)e.remove()}
function clearAllErr(){$$('#tf .bad').forEach(x=>x.classList.remove('bad'));$$('#tf .ferr').forEach(x=>x.remove())}
function mapErr(msg,shown){
  const rules=[[/پورت تانل/,'port'],[/دامنه سرور مقابل/,'remote_domain'],[/دامنه همین سرور|دامنه این سرور/,'local_domain'],[/دامنه CDN|دامنه \(نه IP\)/,'cdn_domain'],
    [/IP داخلی ایران|IP داخلی GRE سرور ایران/,'peer_ip'],[/IP داخلی|شبکه داخلی/,'gre_ip'],[/توکن/,'token'],[/Heartbeat/,'heartbeat'],[/MTU/,S.ff.role==='iran'?'mtu2':'mtu'],
    [/کلادفلر فقط این پورت/,'port'],[/آدرس سرور (ایران|خارج)/,'remote_host'],[/شماره تانل/,'port'],[/Pool count/,'pool'],[/پروتکل FRP/,'protocol'],[/ترنسپورت Gost/,'gtransport'],[/Obfs/,'obfs'],[/SNI/,'sni'],[/6to4|نوع لینک/,'link'],[/Edge IP/,'edge_ip'],[/Keepalive/,'keepalive'],[/Connection pool/,'conn_pool'],[/Channel size/,'channel_size'],[/Mux connections/,'mux_con'],[/Dial timeout/,'dial_timeout'],[/ترنسپورت/,'transport'],[/پورت سرویس|پورت \d+/,'services']];
  for(const [re,f] of rules)if(re.test(msg))return fieldErr(f,shown||msg);
  return false;
}
function validateForm(){
  const f=S.ff,clone=!!S.src,cdn=f.mode==='cdn';let ok=true;
  const need=(n,m)=>{if(ok&&!String(f[n]||'').trim()){fieldErr(n,m);ok=false}};
  if(!(S.form&&S.form.name))need('port',_L('پورت تانل را وارد کنید'));
  const E=ENG[f.engine]||ENG.rathole;
  if(f.mode==='direct'){if(f.role===E.dialer)need('remote_host',_L('آدرس سرور ')+(f.role==='iran'?_L('خارج'):_L('ایران'))+_L(' را وارد کنید'))}
  else if(cdn)need('cdn_domain',_L('دامنه CDN را وارد کنید'));
  else{need('local_domain',_L('دامنه همین سرور را وارد کنید'));need('remote_domain',_L('دامنه سرور مقابل را وارد کنید'));need('gre_ip',_L('IP داخلی را وارد کنید'))}
  if(!E.notoken)need('token',_L('توکن را وارد کنید'));
  if(ok&&E.noudp&&f.services.some(s=>s.type==='udp')){fieldErr('services',E.label+_L(' فقط پورت tcp را پشتیبانی می‌کند'));ok=false}
  if(ok&&!f.services.length){fieldErr('services',_L('حداقل یک پورت سرویس اضافه کنید'));ok=false}
  if(ok&&clone){
    const s=S.src;
    if(String(f.port)===String(s.port)){fieldErr('port',_L('پورت تانل کلون باید با ')+s.port+_L(' فرق کند'));ok=false}
    else if(cdn&&s.mode==='cdn'&&f.cdn_domain.toLowerCase()===String(s.cdn_domain).toLowerCase()){fieldErr('cdn_domain',_L('دامنه CDN را تغییر دهید'));ok=false}
    else if(f.mode==='direct'&&s.mode==='direct'&&f.role===E.dialer&&f.remote_host.toLowerCase()===String(s.remote_host).toLowerCase()){fieldErr('remote_host',_L('آدرس سرور ایران را تغییر دهید'));ok=false}
    else if(f.mode==='gre'&&s.mode==='gre'&&f.remote_domain.toLowerCase()===String(s.remote_domain).toLowerCase()){fieldErr('remote_domain',_L('دامنه سرور مقابل را تغییر دهید'));ok=false}
    else if(f.mode==='gre'&&s.mode==='gre'&&calc30(f.gre_ip)&&calc30(s.gre_ip)&&calc30(f.gre_ip).net===calc30(s.gre_ip).net){fieldErr('gre_ip',_L('IP داخلی را به یک شبکه جدید تغییر دهید (دکمه «پیشنهاد»)'));ok=false}
  }
  return ok;
}
function collect(){
  const f=$('#tf');if(!f)return;const ir=S.ff.role==='iran';
  Object.assign(S.ff,{port:f.port.value.trim(),token:f.token.value.trim(),local_domain:f.local_domain.value.trim(),remote_domain:f.remote_domain.value.trim(),
    gre_ip:f.gre_ip.value.trim(),peer_ip:f.peer_ip.value.trim(),mtu:(ir?f.mtu2.value:f.mtu.value).trim(),heartbeat:f.heartbeat.value.trim(),retry:f.retry.value.trim(),
    nodelay:f.nodelay.checked,ipv6:f.ipv6.checked,cdn_domain:f.cdn_domain.value.trim(),cdn_tls:f.cdn_tls.checked,
    transport:f.transport.value,keepalive:f.keepalive.value.trim(),channel_size:f.channel_size.value.trim(),mux_con:f.mux_con.value.trim(),mux_version:f.mux_version.value,
    conn_pool:f.conn_pool.value.trim(),aggressive:f.aggressive.checked,dial_timeout:f.dial_timeout.value.trim(),edge_ip:f.edge_ip.value.trim(),remote_host:f.remote_host.value.trim(),
    link:f.link.value,protocol:f.protocol.value,tcp_mux:f.tcp_mux.checked,pool:f.pool.value.trim(),gtransport:f.gtransport.value,obfs:f.obfs.value.trim(),xsec:f.xsec.value,sni:f.sni.value.trim()});
  if(S.ff.engine==='gost')S.ff.transport=S.ff.gtransport;
  if(ir)f.mtu.value=S.ff.mtu;else f.mtu2.value=S.ff.mtu;
}
async function submitForm(ev){
  ev.preventDefault();collect();clearAllErr();
  if($('#bulkPorts').value.trim())addBulk();
  if(!validateForm())return;
  const edit=!!(S.form&&S.form.name),p=Object.assign({},S.ff);
  if(edit)p.name=S.form.name;
  if(S.src)p.clone_of=S.src.clone_of;
  const log=$('#createLog');
  await busy($('#saveBtn'),async()=>{
    let d;
    try{d=await api(edit?'update':'create',p)}catch(err){if(!mapErr(err.fa||err.message,err.message))throw err;toast(err.message,'err');return}
    if(edit){toast(d.gre_rebuilt?_L('ذخیره شد؛ لینک شبکه دوباره ساخته شد'):_L('ذخیره شد و سرویس ری‌استارت شد'),'ok');if(d.warning)toast(d.warning,'err');(d.log||[]).filter(x=>x.indexOf(_L('هشدار'))===0).forEach(x=>toast(x,'err'));S.form=null;go('tunnels')}
    else{log.classList.remove('hidden');log.textContent=(d.log||[]).join('\n');toast(_L('تانل ')+d.name+_L(' ساخته شد'),'ok');setTimeout(()=>{S.form=null;go('tunnels')},1800)}
  });
}

/* ---------------- core ---------------- */
const coreDelBtn=(on,eng)=>on?'<div style="margin-top:10px"><button type="button" class="btn sm d" data-coredel="'+eng+'">'+ic('trash')+_L('حذف هسته')+'</button></div>':'';
async function renderCore(){
  const el=$('#tab-core');el.innerHTML='<div class="card"><span class="spin"></span></div>';
  let c;try{c=await api('core_info')}catch(e){el.innerHTML='';toast(e.message,'err');return}
  el.innerHTML=_L('<div class="form"><h2>هسته rathole</h2><div class="card">')+
   _L('<dl class="kv"><dt>وضعیت</dt><dd style="color:')+(c.installed?'var(--ok)':'var(--bad)')+'">'+(c.installed?_L('نصب شده'):_L('نصب نیست'))+'</dd>'+
   _L('<dt>نسخه</dt><dd class="ltr">')+esc(c.version||'-')+_L('</dd><dt>معماری</dt><dd class="ltr">')+esc(c.arch)+'</dd>'+
   _L('<dt>مسیر</dt><dd class="ltr">')+esc(c.path)+'</dd>'+(c.size?_L('<dt>حجم</dt><dd class="ltr">')+fb(c.size)+'</dd>':'')+'</dl>'+
   '<div class="hint" style="margin:8px 0">'+_L('فایل <span class="ltr">rathole.zip</span> یا خود باینری <span class="ltr">rathole</span> را آپلود کنید (روی Ubuntu 20.04 نسخه musl). این هسته باید روی هر دو سرور نصب باشد.')+'</div>'+
   '<div class="inline"><input type="file" id="coreFile"><button class="btn p" id="upBtn">'+_L('آپلود و نصب')+'</button></div>'+
   '<div style="margin-top:10px"><button class="btn" id="dlBtn">'+_L('دانلود از مخزن NETIFAY')+'</button> <span class="hint">'+_L('نسخه سازگار با این سرور خودکار انتخاب می‌شود. سرور باید به github.com دسترسی داشته باشد.')+'</span></div>'+coreDelBtn(c.installed,'rathole')+'</div>'+
   _L('<h2 style="margin-top:28px">هسته Backhaul</h2><div class="card" id="bhCoreBox"><span class="spin"></span></div>')+
   _L('<h2 style="margin-top:28px">هسته‌های دیگر</h2><div id="genCores"><div class="card"><span class="spin"></span></div></div>')+
   _L('<h3>اعمال هسته جدید</h3><div class="card"><div class="hint" style="margin-bottom:8px">بعد از تعویض هسته، همه تانل‌ها باید ری‌استارت شوند.</div><button class="btn" id="raBtn">ری‌استارت همه تانل‌ها</button><pre class="out hidden" id="raOut" style="margin-top:10px"></pre></div></div>');
  $('#upBtn').onclick=e=>{const f=$('#coreFile').files[0];if(!f){toast(_L('فایلی انتخاب نشده'),'err');return}
    busy(e.currentTarget,async()=>{const d=await api('core_upload',null,{body:f,headers:{'Content-Type':'application/octet-stream'}});toast(_L('نصب شد: ')+(d.version||''),'ok');renderCore()})};
  $('#dlBtn').onclick=e=>busy(e.currentTarget,async()=>{const d=await api('core_download');toast(_L('نصب شد: ')+(d.version||''),'ok');renderCore()});
  renderBhCore();renderGenCores();
  el.onclick=e=>{const b=e.target.closest('[data-coredel]');if(!b)return;const eng=b.dataset.coredel;
    modal(_L('حذف هسته'),'<p>'+_L('هسته')+' <b class="ltr">'+esc(eng)+'</b> '+_L('از این سرور حذف شود؟')+'</p><div class="hint">'+_L('فقط فایل اجرایی هسته پاک می‌شود. اگر تانلی از این هسته استفاده کند، حذف انجام نمی‌شود.')+'</div>',
      [{text:_L('بله، حذف شود'),cls:'d',fn:x=>busy(x,async()=>{await api('core_remove',{engine:eng});closeModal();toast(_L('هسته حذف شد'),'ok');renderCore()})},{text:_L('انصراف'),fn:closeModal}])};
  $('#raBtn').onclick=e=>busy(e.currentTarget,async()=>{const d=await api('restart_all');const o=$('#raOut');o.classList.remove('hidden');o.textContent=(d.log||[]).join('\n')||_L('تانلی نیست')});
}

const CORE_FILES={frp:_L('frp_X_linux_amd64.tar.gz (شامل frps و frpc)'),gost:'gost_3.x_linux_amd64.tar.gz',hysteria:'hysteria-linux-amd64',xray:'Xray-linux-64.zip'};
async function renderGenCores(){
  const box=$('#genCores');if(!box)return;let c;
  try{c=await api('cores')}catch(e){box.textContent=e.message;return}
  box.innerHTML=Object.keys(c).map(k=>{const x=c[k];
    if(x.system)return '<div class="card" style="margin-bottom:10px"><h4>'+esc(x.label)+_L('</h4><dl class="kv"><dt>وضعیت</dt><dd style="color:')+(x.installed?'var(--ok)':'var(--bad)')+'">'+(x.installed?_L('نصب است'):_L('نصب نیست'))+_L('</dd><dt>نسخه</dt><dd class="ltr">')+esc(x.version||'-')+'</dd></dl>'+(x.installed?'':_L('<div class="hint">روی سرور بزنید: <span class="ltr">apt install iptables</span></div>'))+'</div>';
    return '<div class="card" style="margin-bottom:10px" data-eng="'+k+'"><h4>'+esc(x.label)+_L('</h4><dl class="kv"><dt>وضعیت</dt><dd style="color:')+(x.installed?'var(--ok)':'var(--bad)')+'">'+(x.installed?_L('نصب شده'):(x.have.length?_L('ناقص (')+esc(x.have.join(', '))+')':_L('نصب نیست')))+'</dd>'+
      _L('<dt>نسخه</dt><dd class="ltr">')+esc(x.version||'-')+_L('</dd><dt>پوشه</dt><dd class="ltr">')+esc(x.dir)+'</dd></dl>'+
      _L('<div class="hint" style="margin:6px 0">فایل: <span class="ltr">')+esc(CORE_FILES[k]||'')+_L('</span> (یا arm64)</div>')+
      _L('<div class="inline"><input type="file" class="gcFile"><button class="btn p" data-gc="up">آپلود</button><button class="btn" data-gc="dl">دانلود از مخزن NETIFAY</button></div></div>').replace(/<\/div>$/,'')+coreDelBtn(x.installed||(x.have&&x.have.length),k)+'</div>'}).join('');
  box.onclick=e=>{const b=e.target.closest('[data-gc]');if(!b)return;const card=b.closest('[data-eng]'),eng=card.dataset.eng;
    if(b.dataset.gc==='dl')return busy(b,async()=>{const d=await api('gen_core_download',{engine:eng});toast(eng+_L(' نصب شد: ')+(d.version||''),'ok');renderGenCores()});
    const f=$('.gcFile',card).files[0];if(!f){toast(_L('فایلی انتخاب نشده'),'err');return}
    busy(b,async()=>{const d=await api('gen_core_upload',null,{body:f,headers:{'Content-Type':'application/octet-stream','X-Engine':eng,'X-Filename':encodeURIComponent(f.name)}});
      toast(eng+_L(' نصب شد')+(d.missing&&d.missing.length?_L(' (ناقص: ')+d.missing.join(', ')+')':''),d.missing&&d.missing.length?'err':'ok');renderGenCores()})};
}
async function renderBhCore(){
  const box=$('#bhCoreBox');if(!box)return;let c;
  try{c=await api('bh_core_info')}catch(e){box.textContent=e.message;return}
  box.innerHTML=_L('<dl class="kv"><dt>وضعیت</dt><dd style="color:')+(c.installed?'var(--ok)':'var(--bad)')+'">'+(c.installed?_L('نصب شده'):_L('نصب نیست'))+'</dd>'+
   _L('<dt>نسخه</dt><dd class="ltr">')+esc(c.version||'-')+_L('</dd><dt>مسیر</dt><dd class="ltr">')+esc(c.path)+'</dd>'+(c.size?_L('<dt>حجم</dt><dd class="ltr">')+fb(c.size)+'</dd>':'')+'</dl>'+
   _L('<div class="hint" style="margin:8px 0">فایل <span class="ltr">backhaul_linux_amd64.tar.gz</span> (یا arm64)، zip یا خود باینری <span class="ltr">backhaul</span> را آپلود کنید. این هسته باید روی هر دو سرور نصب باشد.</div>')+
   _L('<div class="inline"><input type="file" id="bhFile"><button class="btn p" id="bhUp">آپلود و نصب</button></div>')+
   _L('<div style="margin-top:10px"><button class="btn" id="bhDl">دانلود از مخزن NETIFAY</button> <span class="hint">سرور باید به github.com دسترسی داشته باشد.</span></div>')+coreDelBtn(c.installed,'backhaul');
  $('#bhUp').onclick=e=>{const f=$('#bhFile').files[0];if(!f){toast(_L('فایلی انتخاب نشده'),'err');return}
    busy(e.currentTarget,async()=>{const d=await api('bh_core_upload',null,{body:f,headers:{'Content-Type':'application/octet-stream'}});toast(_L('Backhaul نصب شد: ')+(d.version||''),'ok');renderBhCore()})};
  $('#bhDl').onclick=e=>busy(e.currentTarget,async()=>{const d=await api('bh_core_download');toast(_L('Backhaul نصب شد: ')+(d.version||''),'ok');renderBhCore()});
}

/* ---------------- backup ---------------- */
function fdate(t){try{return new Date(t*1000).toLocaleString(LANG==='en'?'en-GB':'fa-IR')}catch(e){return ''}}
async function renderBackup(){
  const el=$('#tab-backup');el.innerHTML='<div class="card"><span class="spin"></span></div>';
  let d;try{d=await api('backup_list')}catch(e){el.innerHTML='';toast(e.message,'err');return}
  el.innerHTML=_L('<div class="form"><h2>بکاپ و بازیابی</h2>')+
   '<h3>'+ic('archive')+_L(' گرفتن بکاپ</h3><div class="card">')+
   _L('<div class="hint" style="margin-bottom:10px">فقط <b>کانفیگ تانل‌ها</b> ذخیره می‌شود: همه موتورها، تنظیمات لینک (نوع، دامنه‌ها، IP داخلی، MTU) و زمان‌بندی ری‌استارت. ')+
   _L('هسته‌ها داخل بکاپ نیستند (چون برای هر سرور و معماری فرق دارند)؛ روی سرور جدید از تب «هسته» نصبشان کنید.</div>')+
   '<div class="inline" style="gap:8px;flex-wrap:wrap"><button class="btn p" id="bkMake">'+ic('download')+_L('بکاپ بگیر و دانلود کن</button><button class="btn" id="bkSave">')+ic('archive')+_L('فقط روی سرور ذخیره کن</button></div></div>')+
   '<h3>'+ic('upload')+_L(' بازیابی از فایل</h3><div class="card">')+
   _L('<div class="hint" style="margin-bottom:8px">فایل <span class="ltr">.tar.gz</span> بکاپ NETIFAY را انتخاب کنید. بعد از آپلود، لیست تانل‌ها و وضعیت هسته هر کدام را می‌بینید و انتخاب می‌کنید کدام‌ها بازیابی شوند.</div>')+
   '<div class="inline"><input type="file" id="bkFile" accept=".gz,.tgz,application/gzip,application/x-gzip"><button class="btn p" id="bkUp">'+ic('upload')+_L('آپلود و بررسی</button></div></div>')+
   '<h3>'+ic('file')+_L(' بکاپ‌های روی سرور</h3><div class="card" id="bkList">')+
   (d.items.length?d.items.map(b=>'<div class="bk" data-n="'+esc(b.name)+'"><div class="n"><div class="ltr" style="text-align:right">'+esc(b.name)+
     (b.name.startsWith('auto-before-restore')?_L(' <span class="badge" style="font-size:11px">خودکار</span>'):'')+'</div><div class="hint">'+fdate(b.mtime)+' · '+fb(b.size)+'</div></div>'+
     '<button class="btn sm p" data-b="restore">'+ic('refresh')+_L('بازیابی</button><button class="btn sm" data-b="dl" title="دانلود">')+ic('download')+_L('</button><button class="btn sm d" data-b="del" title="حذف">')+ic('trash')+'</button></div>').join('')
     :_L('<div class="hint">هنوز بکاپی روی سرور نیست.</div>'))+
   _L('<div class="hint" style="margin-top:8px">مسیر: <span class="ltr">')+esc(d.dir)+_L('</span> · بکاپ‌های «خودکار» قبل از هر بازیابی ساخته می‌شوند تا بتوانید برگردید.</div></div></div>');
  $('#bkMake').onclick=e=>busy(e.currentTarget,async()=>{const r=await api('backup_create',{});await downloadBackup(r.name);toast(_L('بکاپ با ')+r.tunnels+_L(' تانل گرفته شد'),'ok');renderBackup()});
  $('#bkSave').onclick=e=>busy(e.currentTarget,async()=>{const r=await api('backup_create',{});toast(_L('ذخیره شد (')+r.tunnels+_L(' تانل)'),'ok');renderBackup()});
  $('#bkUp').onclick=e=>{const inp=$('#bkFile'),f=inp.files[0];
    if(!f){toast(_L('فایلی انتخاب نشده'),'err');return}
    if(!/\.(tar\.gz|tgz|gz)$/i.test(f.name)){toast(_L('فایل بکاپ باید .tar.gz باشد'),'err');return}
    if(f.size>20*1024*1024){toast(_L('حجم فایل برای بکاپ تانل‌ها غیرعادی است (بیش از 20MB)'),'err');return}
    busy(e.currentTarget,async()=>{const r=await api('backup_upload',null,{body:f,headers:{'Content-Type':'application/octet-stream'}});
      inp.value='';toast(_L('آپلود و بررسی شد'),'ok');await renderBackup();restoreDialog(r.name,r)})};
  $('#bkList').addEventListener('click',async e=>{
    const b=e.target.closest('button[data-b]');if(!b)return;const n=b.closest('[data-n]').dataset.n;
    if(b.dataset.b==='dl')busy(b,()=>downloadBackup(n));
    if(b.dataset.b==='del')modal(_L('حذف بکاپ'),'<p class="ltr">'+esc(n)+_L('</p><div class="hint">این فایل برای همیشه پاک می‌شود.</div>'),[{text:_L('حذف'),cls:'d',fn:x=>busy(x,async()=>{await api('backup_delete',{name:n});closeModal();toast(_L('حذف شد'),'ok');renderBackup()})},{text:_L('انصراف'),fn:closeModal}]);
    if(b.dataset.b==='restore')busy(b,async()=>{const r=await api('backup_info',{name:n});restoreDialog(n,r)});
  });
}
async function downloadBackup(name){
  const r=await fetch('api/backup_download',{method:'POST',credentials:'same-origin',headers:{'X-Panel':'1','X-Lang':LANG,'Content-Type':'application/json'},body:JSON.stringify({name})});
  if(!r.ok){let m=_L('دانلود ناموفق');try{m=(await r.json()).error||m}catch(e){}throw new Error(m)}
  const blob=await r.blob(),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;document.body.appendChild(a);a.click();
  setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove()},2000);
}
const RST={ok:['ok',_L('آماده')],replace:['warn',_L('جایگزین تانل فعلی')],nocore:['bad',_L('هسته نصب نیست')],taken:['bad',_L('نام تکراری')],bad:['bad',_L('خراب / ناقص')]};
function restoreDialog(name,info){
  const man=info.manifest||{},ts=info.tunnels||[];
  const can=t=>t.status==='ok'||t.status==='replace';
  const nocore={};ts.filter(t=>t.status==='nocore').forEach(t=>(nocore[t.label]=nocore[t.label]||[]).push(t.name));
  const nk=Object.keys(nocore);
  const html=_L('<dl class="kv"><dt>سرور مبدا</dt><dd class="ltr">')+esc(man.hostname||'-')+_L('</dd><dt>تاریخ</dt><dd>')+fdate(man.created)+'</dd>'+
     _L('<dt>نسخه پنل</dt><dd class="ltr">')+esc(man.version||'-')+_L('</dd><dt>تعداد تانل</dt><dd>')+ts.length+'</dd></dl>'+
    (nk.length?'<div class="ferr" style="display:block;margin:10px 0;padding:9px 11px;border:1px solid var(--bad-b);border-radius:10px">'+ic('alert')+' '+
      _L('این تانل‌ها به هسته‌ای نیاز دارند که روی این سرور نصب نیست و تا نصب نشود بازیابی نمی‌شوند: ')+
      nk.map(k=>'<b>'+esc(k)+'</b> <span class="ltr">('+nocore[k].map(esc).join(', ')+')</span>').join(_L('، '))+
      '<div style="margin-top:8px"><button type="button" class="btn sm" id="rGoCore">'+ic('cpu')+_L('رفتن به تب هسته</button></div></div>'):'')+
    (info.has_core?'<div class="hint" style="margin:6px 0">'+ic('info','sm')+_L(' این بکاپ قدیمی هسته هم دارد؛ هسته‌های داخل بکاپ نادیده گرفته می‌شوند و فقط تانل‌ها بازیابی می‌شوند.</div>'):'')+
    (ts.length?_L('<div class="inline" style="justify-content:space-between;margin:12px 0 4px"><b>تانل‌ها</b><span><button type="button" class="btn sm" id="rAll">همه</button> <button type="button" class="btn sm" id="rNone">هیچ</button></span></div>')+
      ts.map(t=>{const st=RST[t.status]||['bad',t.status];return '<label class="sw" style="align-items:flex-start'+(can(t)?'':';opacity:.75')+'"><span>'+
        '<span class="ltr"><b>'+esc(t.name)+'</b></span> <span class="badge" style="background:var(--bg2);border:1px solid var(--line)">'+esc(t.label)+'</span> '+
        '<span class="tag-'+(st[0]==='ok'?'ok':st[0]==='warn'?'':'no')+'" style="font-size:12px'+(st[0]==='warn'?';color:var(--warn-t)':'')+'">'+st[1]+'</span>'+
        (t.msg&&!can(t)?'<div class="hint" style="margin:2px 0 0">'+esc(t.msg)+'</div>':'')+'</span>'+
        '<input type="checkbox" class="rsel" value="'+esc(t.name)+'"'+(can(t)?' checked':' disabled')+'></label>'}).join('')
     :_L('<div class="hint">این بکاپ تانلی ندارد.</div>'))+
    _L('<div class="hint" style="margin-top:8px">تانل‌هایی که انتخاب نشوند یا در بکاپ نیستند دست نمی‌خورند. قبل از بازیابی، از وضعیت فعلی خودکار بکاپ گرفته می‌شود؛ ')+
    _L('اگر تانلی با تانل دیگری روی این سرور تداخل پورت/لینک داشته باشد، بازیابی همان تانل لغو و نسخه قبلی‌اش برگردانده می‌شود.</div>')+
    '<div class="ferr hidden" id="rErr" style="display:block;margin-top:8px"></div><pre class="out hidden" id="rLog" style="margin-top:10px"></pre>';
  let done=false;
  const ov=modal(_L('بازیابی بکاپ'),html,[{text:_L('بازیابی تانل‌های انتخاب‌شده'),cls:'p',fn:btn=>{
    const only=$$('.rsel').filter(x=>x.checked&&!x.disabled).map(x=>x.value);
    if(!only.length){toast(_L('هیچ تانلی انتخاب نشده'),'err');return}
    const repl=ts.filter(t=>only.includes(t.name)&&t.status==='replace').map(t=>t.name);
    const go2=()=>busy(btn,async()=>{const er=$('#rErr');er.classList.add('hidden');
      let r;try{r=await api('backup_restore_saved',{name,only})}catch(e){er.textContent=e.message;er.classList.remove('hidden');throw e}
      const o=$('#rLog');o.classList.remove('hidden');o.textContent=r.log.join('\n');btn.remove();done=true;
      $$('.rsel').forEach(x=>x.disabled=true);
      toast(r.failed&&r.failed.length?(_L('بازیابی انجام شد؛ ')+r.failed.length+_L(' تانل ناموفق')):_L('بازیابی انجام شد (')+r.restored.length+_L(' تانل)'),r.failed&&r.failed.length?'err':'ok')});
    if(repl.length&&!btn.dataset.ok){btn.dataset.ok='1';btn.textContent=_L('تایید: ')+repl.length+_L(' تانل فعلی جایگزین شود');toast(_L('تانل‌های ')+repl.join(_L('، '))+_L(' روی همین نام‌ها جایگزین می‌شوند؛ برای ادامه دوباره بزنید'),'err');return}
    go2()}},{text:_L('بستن'),fn:()=>{closeModal();if(S.tab==='backup')renderBackup();if(done)loadTunnels&&S.tab==='tunnels'&&loadTunnels()}}]);
  const sync=()=>{const n=$$('.rsel',ov).filter(x=>x.checked&&!x.disabled).length,b=$('.mf .btn.p',ov);if(b){b.disabled=!n;b.style.opacity=n?'':'.5'}};
  $$('.rsel',ov).forEach(x=>x.onchange=sync);sync();
  if($('#rAll',ov)){$('#rAll',ov).onclick=()=>{$$('.rsel',ov).forEach(x=>{if(!x.disabled)x.checked=true});sync()};
    $('#rNone',ov).onclick=()=>{$$('.rsel',ov).forEach(x=>x.checked=false);sync()}}
  if($('#rGoCore',ov))$('#rGoCore',ov).onclick=()=>{closeModal();go('core')};
}

async function renderOpt(){
  const box=$('#optBox');if(!box)return;let o;
  try{o=await api('optimize_get')}catch(e){box.textContent=e.message;return}
  box.innerHTML=_L('<dl class="kv"><dt>وضعیت</dt><dd style="color:')+(o.applied?'var(--ok)':'var(--mut)')+'">'+(o.applied?ic('check','sm')+_L(' اعمال شده'):_L('اعمال نشده'))+'</dd>'+
    _L('<dt>کنترل ازدحام</dt><dd class="ltr">')+esc(o.congestion||'-')+' · '+esc(o.qdisc||'-')+'</dd></dl>'+
    _L('<div class="hint" style="margin-bottom:10px">BBR + fq، بافرهای بزرگ‌تر TCP/UDP، صف اتصال بیشتر، حد فایل‌های باز بالا و فعال کردن ip_forward. برای سرورهای تانل با کاربر زیاد پیشنهاد می‌شود. روی هر دو سرور اعمال کنید.</div>')+
    '<div class="inline" style="gap:8px;flex-wrap:wrap"><button class="btn p" id="optOn">'+(o.applied?_L('اعمال دوباره'):_L('اعمال بهینه‌سازی'))+'</button>'+(o.applied?_L('<button class="btn d" id="optOff">برگرداندن</button>'):'')+'</div><pre class="out hidden" id="optLog" style="margin-top:10px"></pre>';
  const show=d=>{const l=$('#optLog');l.classList.remove('hidden');l.textContent=d.log.join('\n')};
  $('#optOn').onclick=e=>busy(e.currentTarget,async()=>{const d=await api('optimize');show(d);toast(_L('بهینه‌سازی اعمال شد'),'ok');setTimeout(renderOpt,800)});
  if($('#optOff'))$('#optOff').onclick=e=>busy(e.currentTarget,async()=>{const d=await api('optimize',{off:true});show(d);setTimeout(renderOpt,800)});
}


async function runAudit(){
  const d=await api('audit');
  const icon={err:'<span style="color:var(--bad)">'+ic('x')+'</span>',warn:'<span style="color:var(--warn)">'+ic('alert')+'</span>',ok:'<span style="color:var(--ok)">'+ic('check')+'</span>'};
  const errs=d.items.filter(x=>x.level==='err').length,warns=d.items.filter(x=>x.level==='warn').length;
  modal(_L('بررسی تداخل‌ها (')+d.count+_L(' تانل)'),
    (errs||warns?'<div class="hint" style="margin-bottom:8px">'+errs+_L(' مشکل جدی · ')+warns+_L(' هشدار</div>'):'')+
    '<div class="card" style="padding:4px 12px">'+d.items.map(x=>'<div class="audit-item">'+icon[x.level]+'<div>'+esc(x.msg)+'</div></div>').join('')+'</div>'+
    _L('<div class="hint" style="margin-top:8px">بررسی می‌شود: پورت‌های تکراری بین تانل‌ها (حتی تانل‌های قطع)، پورت‌هایی که برنامه دیگری گرفته، تداخل با پورت پنل، شبکه داخلی تکراری یا هم‌پوشان با اینترفیس‌های سرور، دو لینک هم‌نوع به یک سرور، هسته نصب‌نشده و سرویس غیرفعال. روی هر دو سرور اجرا کنید.</div>'),
    [{text:_L('بررسی دوباره'),cls:'p',fn:b=>busy(b,runAudit)},{text:_L('راهنمای تداخل‌ها'),fn:()=>{closeModal();go('guide');setTimeout(()=>{const x=$('#g-conflict');if(x){x.open=true;x.scrollIntoView({behavior:'smooth'})}},100)}}]);
}

function renderGuide(){
  const el=$('#tab-guide');if(el.dataset.done)return;el.dataset.done=1;
  const sec=(id,title,body,open)=>'<details id="'+id+'"'+(open?' open':'')+'><summary>'+title+ic('chevDown','chev')+'</summary><div class="gb">'+body+'</div></details>';
  const eng=(id,title,o)=>sec(id,ic('layers')+' '+title,
    '<p>'+o.what+_L('</p><table><tr><th>جهت اتصال</th><td>')+o.dir+_L('</td></tr><tr><th>حالت‌ها</th><td>')+o.modes+_L('</td></tr><tr><th>ترنسپورت / پروتکل</th><td>')+o.tr+'</td></tr><tr><th>UDP</th><td>'+o.udp+_L('</td></tr><tr><th>پورت باز لازم</th><td>')+o.ports+'</td></tr></table>'+
    _L('<h4>مزایا</h4><ul>')+o.pros.map(x=>'<li>'+x+'</li>').join('')+_L('</ul><h4>معایب / محدودیت‌ها</h4><ul>')+o.cons.map(x=>'<li>'+x+'</li>').join('')+'</ul>'+
    _L('<h4>کی استفاده کنیم</h4><p>')+o.when+_L('</p><h4>نکات تنظیم</h4><ul>')+o.tips.map(x=>'<li>'+x+'</li>').join('')+'</ul>');
  el.innerHTML=_L('<div class="form guide"><h2>راهنمای کامل NETIFAY</h2>')+
  sec('g-basics',ic('book')+_L(' مفاهیم پایه'),
   _L('<ul><li><b>سرور ایران:</b> کاربران به این سرور وصل می‌شوند؛ «پورت‌های سرویس» (مثلا 2070، 8443) روی این سرور باز می‌شوند.</li>')+
   _L('<li><b>سرور خارج:</b> سرویس اصلی (مثلا Xray / پنل فروش) روی این سرور است؛ تانل ترافیک را از ایران به همان پورت‌ها روی خارج می‌رساند.</li>')+
   _L('<li><b>پورت تانل:</b> پورتی که دو سرور از طریق آن به هم وصل می‌شوند (کاربر با آن کاری ندارد). باید در هر دو سرور یکی باشد.</li>')+
   _L('<li><b>پورت‌های سرویس:</b> همان پورت‌های کانفیگ‌های کاربران. در هر دو سرور باید یکی باشند.</li>')+
   _L('<li><b>توکن:</b> رمز مشترک دو طرف تانل. اگر فرق کند خطای «Incorrect token» یا عدم اتصال می‌گیرید.</li>')+
   _L('<li><b>جهت اتصال:</b> در بعضی موتورها «خارج به ایران» وصل می‌شود (معکوس؛ وقتی ورودی ایران بسته است مفید است) و در بعضی «ایران به خارج».</li>')+
   _L('<li><b>نوع اتصال:</b> <b>لینک شبکه</b> (یک اینترفیس مجازی GRE/IPIP/6to4 بین دو سرور که تانل داخلش می‌رود)، <b>مستقیم</b> (بدون لینک، روی IP/دامنه عمومی) یا <b>CDN کلادفلر</b> (فقط Backhaul).</li>')+
   _L('<li><b>IP داخلی:</b> در حالت لینک، هر تانل یک شبکه /30 جدا دارد (مثلا 10.10.1.1 ایران و 10.10.1.2 خارج). تانل بعدی: 10.10.2.x.</li></ul>'),true)+
  sec('g-choose',ic('compass')+_L(' کدام تانل را انتخاب کنم؟'),
   '<div class="recbox"><b class="t">'+ic('check')+_L('پیشنهاد ما برای بیشتر سرورها: Rathole روی لینک GRE')+'</b>'+
   _L('سبک، کم‌مصرف و پایدار است و در همین پنل بیشتر از همه آزموده شده. اگر مطمئن نیستید از همین شروع کنید؛ اگر دیتاسنتر GRE را بسته بود، همان Rathole را روی IPIP یا 6to4 بسازید. برای شرایط خاص جدول زیر را ببینید.')+'</div>'+
   _L('<table><tr><th>شرایط شما</th><th>پیشنهاد</th></tr>')+
   _L('<tr><td>شروع کار، پایدار و ساده</td><td>Rathole یا Backhaul (tcpmux) روی لینک GRE</td></tr>')+
   _L('<tr><td>کاربر و کانکشن خیلی زیاد</td><td>Backhaul با tcpmux یا FRP با tcpMux</td></tr>')+
   _L('<tr><td>دیتاسنتر GRE را بسته</td><td>همان موتور روی لینک IPIP یا 6to4، یا حالت مستقیم</td></tr>')+
   _L('<tr><td>می‌خواهید IP سرور ایران مخفی بماند / عبور از CDN</td><td>Backhaul حالت CDN کلادفلر با wssmux</td></tr>')+
   _L('<tr><td>لینک پرافت و نویزی بین دو سرور</td><td>Hysteria2، یا FRP با kcp/quic</td></tr>')+
   _L('<tr><td>بیشترین مخفی‌کاری در برابر فیلترینگ</td><td>Xray Reverse (REALITY)</td></tr>')+
   _L('<tr><td>کمترین سربار، بدون برنامه اضافه</td><td>iptables روی لینک GRE/IPIP</td></tr>')+
   _L('<tr><td>ورودی سرور ایران محدود است ولی ایران می‌تواند به خارج وصل شود</td><td>Gost یا Hysteria2 (ایران به خارج)</td></tr>')+
   _L('<tr><td>ورودی خارج به ایران آزاد است</td><td>Rathole / Backhaul / FRP / Xray (خارج به ایران)</td></tr></table>')+
   _L('<p class="hint">قاعده طلایی: روی هر دو سرور یک تانل آزمایشی با یکی دو پورت بسازید، «تست پورت‌ها» را بزنید و بعد پورت‌های اصلی را اضافه کنید.</p>'))+
  _L('<h3>موتورهای تانل</h3>')+
  eng('g-rathole','Rathole',{what:_L('تانل معکوس سبک و سریع نوشته‌شده با Rust. همان موتور اسکریپت قبلی.'),dir:_L('خارج ← ایران (خارج وصل می‌شود)'),modes:_L('لینک شبکه (GRE / IPIP / 6to4)'),tr:_L('TCP (داخل لینک)'),udp:_L('<span class="tag-ok">دارد</span>'),ports:_L('ایران: پورت تانل روی IP داخلی لینک'),
    pros:[_L('مصرف رم و CPU کم، تاخیر کم'),_L('پایدار و آزموده‌شده در همین پنل'),_L('سازگار با فایل‌های اسکریپت قبلی')],
    cons:[_L('نسخه 0.5.0 روی Ubuntu 20.04 کتابخانه libssl.so.3 ندارد (پنل خودکار نسخه musl را نصب می‌کند)'),_L('هر اتصال کاربر یک کانکشن جدید بین دو سرور می‌سازد')],
    when:_L('گزینه پیش‌فرض برای بیشتر سرورها.'),
    tips:[_L('<b>Heartbeat:</b> سمت خارج باید <u>بیشتر</u> از سمت ایران باشد (ایران 30، خارج 40) یا هر دو 0. مساوی بودن باعث قطع و وصل مداوم و خطای <code>early eof</code> می‌شود.'),_L('TCP_NODELAY را روشن نگه دارید (تاخیر کمتر).'),_L('نسخه هسته در دو سرور یکی باشد.')]})+
  eng('g-backhaul','Backhaul',{what:_L('تانل معکوس با Go که برای تعداد کانکشن بالا و عبور از CDN طراحی شده.'),dir:_L('خارج ← ایران'),modes:_L('لینک شبکه، مستقیم، CDN کلادفلر'),tr:_L('tcp، tcpmux، ws، wss، wsmux، wssmux'),udp:_L('فقط با ترنسپورت tcp'),ports:_L('ایران: پورت تانل'),
    pros:[_L('tcpmux/wsmux: چند صد کاربر روی چند کانکشن ثابت (کانکشن کمتر بین دو سرور)'),_L('تنها موتور با حالت CDN کلادفلر و Edge IP'),_L('گزینه‌های تنظیم زیاد (pool، mux، keepalive)')],
    cons:[_L('تنظیمات بیشتر؛ ترنسپورت و mux_version باید دو طرف یکی باشد'),_L('UDP فقط روی tcp')],
    when:_L('کاربر زیاد، یا نیاز به CDN / مخفی کردن IP ایران.'),
    tips:[_L('برای لینک/مستقیم: tcpmux. برای CDN: wssmux.'),_L('در CDN، Heartbeat سمت ایران زیر 80 ثانیه.'),_L('Connection pool سمت خارج را برای کاربر زیاد 16 تا 32 کنید.')]})+
  eng('g-frp','FRP',{what:_L('یکی از قدیمی‌ترین و پرکاربردترین ابزارهای تانل معکوس (frps روی ایران، frpc روی خارج).'),dir:_L('خارج (frpc) ← ایران (frps)'),modes:_L('لینک شبکه، مستقیم'),tr:_L('tcp، kcp، quic، websocket'),udp:_L('<span class="tag-ok">دارد</span>'),ports:_L('ایران: پورت تانل (برای kcp/quic به صورت UDP)'),
    pros:[_L('بسیار پخته و پایدار'),_L('tcpMux و Pool اتصال‌های آماده'),_L('kcp و quic برای لینک‌های پرافت')],
    cons:[_L('پورت‌های سرویس فقط وقتی باز می‌شوند که frpc وصل باشد'),_L('سربار کمی بیشتر از rathole')],
    when:_L('وقتی پایداری و پختگی مهم است یا لینک پرافت دارید (kcp/quic).'),
    tips:[_L('پروتکل و TCP Mux باید دو طرف یکی باشند.'),_L('Pool count سمت خارج را برای کاربر زیاد بالاتر ببرید (16+).')]})+
  eng('g-gost','Gost',{what:_L('ابزار رله منعطف با ترنسپورت‌های زیاد. ایران پورت‌ها را می‌گیرد و از طریق رله به خارج می‌فرستد.'),dir:_L('ایران ← خارج (ایران وصل می‌شود)'),modes:_L('لینک شبکه، مستقیم'),tr:_L('tls، mtls، ws، wss، mwss، grpc، h2، tcp، kcp، quic'),udp:_L('<span class="tag-ok">دارد</span>'),ports:_L('خارج: پورت تانل'),
    pros:[_L('تنوع ترنسپورت بسیار زیاد'),_L('mtls/mwss چندتایی‌سازی دارند'),_L('ws/wss قابل عبور از CDN')],
    cons:[_L('جهت ایران به خارج؛ اگر خروجی ایران محدود باشد مشکل‌ساز است')],
    when:_L('وقتی سرور خارج پورت ورودی آزاد دارد و می‌خواهید ترنسپورت خاصی (tls/grpc/…) را امتحان کنید.'),
    tips:[_L('ترنسپورت دو طرف باید یکی باشد.'),_L('در حالت مستقیم، آدرس سرور خارج را روی سرور ایران وارد می‌کنید.')]})+
  eng('g-hysteria','Hysteria2',{what:_L('تانل روی QUIC (UDP) با کنترل ازدحام مخصوص لینک‌های پرافت. ایران کلاینت است و پورت‌ها را فوروارد می‌کند.'),dir:_L('ایران ← خارج'),modes:_L('لینک شبکه، مستقیم'),tr:'QUIC / UDP (+obfs salamander)',udp:_L('<span class="tag-ok">دارد</span>'),ports:_L('خارج: پورت تانل UDP'),
    pros:[_L('سرعت بالا روی لینک‌های پرافت و دور'),_L('obfs برای مبهم کردن QUIC')],
    cons:[_L('اگر UDP/QUIC در مسیر محدود شود ضعیف می‌شود'),_L('«اتصال‌های تانل» در تست پورت قابل شمارش نیست (UDP)')],
    when:_L('وقتی TCP بین دو سرور کند یا پرافت است ولی UDP آزاد است.'),
    tips:[_L('رمز Obfs اختیاری است ولی دو طرف باید یکی باشد.'),_L('پورت تانل UDP را در فایروال سرور خارج باز کنید.')]})+
  eng('g-xray','Xray Reverse (REALITY)',{what:_L('قابلیت reverse هسته Xray: خارج (bridge) به ایران (portal) با VLESS + REALITY وصل می‌شود.'),dir:_L('خارج ← ایران'),modes:_L('لینک شبکه، مستقیم'),tr:_L('VLESS + REALITY (روی TCP)'),udp:_L('<span class="tag-no">ندارد</span> (فقط TCP)'),ports:_L('ایران: پورت تانل'),
    pros:[_L('ترافیک بین دو سرور شبیه TLS عادی به یک سایت معتبر است'),_L('کلیدها خودکار از توکن ساخته می‌شوند')],
    cons:[_L('فقط TCP'),_L('سربار بیشتر از rathole')],
    when:_L('وقتی ترافیک بین دو سرور شناسایی و محدود می‌شود و مخفی‌کاری مهم است.'),
    tips:[_L('SNI و توکن دو طرف باید یکی باشند.'),_L('نسخه‌های جدید Xray اتصال بدون رمزنگاری را مسدود می‌کنند؛ پنل همیشه REALITY می‌سازد.')]})+
  eng('g-iptables','iptables',{what:_L('فوروارد پورت در خود کرنل لینوکس (DNAT) بدون هیچ برنامه تانل.'),dir:_L('ایران ← خارج (فوروارد مستقیم)'),modes:_L('لینک شبکه (GRE/IPIP)، مستقیم'),tr:_L('هیچ (فوروارد بسته‌ها)'),udp:_L('<span class="tag-ok">دارد</span>'),ports:'—',
    pros:[_L('کمترین تاخیر و سربار'),_L('هیچ هسته‌ای لازم نیست')],
    cons:[_L('رمزنگاری یا مبهم‌سازی ندارد'),_L('در حالت مستقیم، اگر ارتباط ایران به خارج روی آن پورت فیلتر باشد کار نمی‌کند'),_L('با 6to4 کار نمی‌کند')],
    when:_L('روی لینک GRE/IPIP وقتی فقط سرعت مهم است.'),
    tips:[_L('فقط سرور ایران ساخته می‌شود؛ در حالت لینک، سمت خارج فقط یک تانل لینک (هر موتوری یا iptables) لازم دارد.'),_L('iptables پورت را <u>قبل</u> از هر برنامه دیگری می‌گیرد؛ پنل اجازه نمی‌دهد پورت تکراری بسازید.'),_L('اگر IP دامنه عوض شود، قوانین هر 5 دقیقه خودکار به‌روز می‌شوند.')]})+
  _L('<h3>لینک‌ها و اتصال</h3>')+
  sec('g-links',ic('link')+_L(' لینک شبکه: GRE / IPIP / 6to4'),
   _L('<table><tr><th>نوع</th><th>پروتکل</th><th>MTU پیش‌فرض</th><th>توضیح</th></tr>')+
   _L('<tr><td>GRE</td><td>47</td><td>1476</td><td>رایج‌ترین. بعضی دیتاسنترها مسدودش می‌کنند.</td></tr>')+
   _L('<tr><td>IPIP</td><td>4</td><td>1480</td><td>سبک‌تر؛ گاهی وقتی GRE بسته است باز است.</td></tr>')+
   _L('<tr><td>6to4 (SIT)</td><td>41</td><td>1480</td><td>IPv6 داخل IPv4؛ آدرس IPv6 داخلی خودکار از IP داخلی ساخته می‌شود. با iptables کار نمی‌کند.</td></tr></table>')+
   _L('<ul><li>لینک بر اساس <b>دامنه</b> ساخته می‌شود؛ اگر IP سرور عوض شود، هر 2 دقیقه خودکار به‌روز می‌شود.</li>')+
   _L('<li>نوع لینک، دامنه‌ها و MTU باید دو طرف هماهنگ باشند (دامنه این سرور ↔ دامنه سرور مقابل جابه‌جا).</li>')+
   _L('<li>اگر «تست پینگ» جواب نداد: پروتکل لینک در فایروال/دیتاسنتر بسته است → نوع لینک را عوض کنید یا حالت مستقیم.</li></ul>'))+
  sec('g-cdn',ic('cloud')+_L(' CDN کلادفلر (Backhaul)'),
   _L('<ol><li>رکورد A دامنه → IP سرور <b>ایران</b>، ابر نارنجی روشن.</li><li>Network → WebSockets روشن.</li>')+
   _L('<li>با wss/wssmux: SSL/TLS حالت <b>Full</b> (نه Strict). با ws/wsmux: «Always Use HTTPS» خاموش.</li>')+
   _L('<li>پورت تانل از پورت‌های مجاز کلادفلر: با TLS <code>443 2053 2083 2087 2096 8443</code> · بدون TLS <code>80 8080 8880 2052 2082 2086 2095</code>.</li>')+
   _L('<li>پورت تانل نباید با پورت‌های سرویس یکی باشد.</li><li>Edge IP (اختیاری، سمت خارج): یک IP تمیز کلادفلر که به آن وصل شود.</li></ol>'))+
  _L('<h3>ترکیب چند تانل و تداخل‌ها</h3>')+
  sec('g-conflict',ic('alert')+_L(' ترکیب چند مدل تانل روی یک سرور (مهم)'),
   _L('<h4>دو سر یک تانل (ایران و خارج) باید یکی باشند</h4><ul><li>موتور (مثلا هر دو Backhaul) — موتورها با هم سازگار نیستند.</li><li>پورت تانل، توکن، پورت‌های سرویس.</li><li>ترنسپورت/پروتکل، mux، نوع لینک، SNI و رمز obfs (هرکدام که دارد).</li><li>نسخه هسته (ترجیحا یکسان).</li></ul>')+
   _L('<h4>روی یک سرور می‌توانید هم‌زمان داشته باشید</h4><ul><li>چند تانل با موتورهای مختلف (مثلا یک Rathole، یک Backhaul CDN، یک iptables).</li><li>چند تانل از سرور ایران به چند سرور خارج (هر کدام پورت تانل و شبکه داخلی جدا).</li><li>چند تانل سمت خارج که همه به یک پورت محلی (همان Xray) وصل می‌شوند.</li><li>بین یک جفت سرور: یک لینک GRE + یک IPIP + یک 6to4 هم‌زمان.</li></ul>')+
   _L('<h4>تداخل‌هایی که پنل جلوی آن‌ها را می‌گیرد</h4><table><tr><th>تداخل</th><th>چرا مشکل است</th><th>راه حل</th></tr>')+
   _L('<tr><td>پورت سرویس تکراری روی سرور ایران</td><td>دو تانل یک پورت را می‌خواهند؛ یکی کار نمی‌کند (rathole/FRP تا وصل نشوند پورت را باز نمی‌کنند، پس تداخل دیر دیده می‌شود)</td><td>هر پورت فقط در یک تانل</td></tr>')+
   _L('<tr><td>پورت تانل = پورت سرویس یا پورت تانل دیگر</td><td>دو برنامه یک پورت</td><td>پورت تانل جدا</td></tr>')+
   _L('<tr><td>پورت = پورت پنل</td><td>پنل یا تانل بالا نمی‌آید</td><td>پورت دیگر</td></tr>')+
   _L('<tr><td>پورت را برنامه دیگری گرفته (مثلا Xray روی ایران)</td><td>تانل بالا نمی‌آید</td><td>پورت دیگر یا آزاد کردن آن</td></tr>')+
   _L('<tr><td>iptables روی پورتی که برنامه دیگری دارد</td><td>iptables ترافیک را قبل از برنامه می‌رباید</td><td>پورت جدا</td></tr>')+
   _L('<tr><td>شبکه داخلی /30 تکراری یا هم‌پوشان (حتی با Docker/VPN سرور)</td><td>مسیریابی خراب می‌شود</td><td>هر تانل شبکه جدا (دکمه «پیشنهاد»)</td></tr>')+
   _L('<tr><td>دو لینک هم‌نوع به یک سرور مقابل</td><td>لینوکس فقط یکی را می‌سازد؛ ترافیک قاطی می‌شود</td><td>پورت‌ها را به همان تانل اضافه کنید یا نوع لینک دیگر</td></tr>')+
   _L('<tr><td>Heartbeat مساوی در rathole</td><td>قطع و وصل مداوم (<code>early eof</code>)</td><td>خارج بیشتر از ایران (30/40)</td></tr></table>')+
   _L('<p>دکمه <b>«بررسی تداخل‌ها»</b>  در صفحه تانل‌ها همه این موارد را روی تانل‌های موجود بررسی می‌کند. روی هر دو سرور اجرا کنید.</p>'))+
  _L('<h3>عیب‌یابی</h3>')+
  sec('g-trouble',ic('wrench')+_L(' خطاهای رایج و راه حل'),
   _L('<table><tr><th>علامت / خطا</th><th>علت محتمل</th><th>راه حل</th></tr>')+
   _L('<tr><td><code>Incorrect token</code></td><td>توکن دو طرف فرق دارد</td><td>یک طرف را ویرایش و توکن را یکی کنید</td></tr>')+
   _L('<tr><td><code>early eof</code> پشت سر هم</td><td>Heartbeat مساوی، یا دو کلاینت روی یک تانل</td><td>Heartbeat 30/40؛ بررسی تداخل‌ها</td></tr>')+
   _L('<tr><td><code>Connection refused</code> سمت خارج</td><td>سرویس اصلی (Xray) روی آن پورت گوش نمی‌دهد</td><td>inbound آن پورت را در Xray روشن کنید</td></tr>')+
   _L('<tr><td>تست پینگ لینک جواب نمی‌دهد</td><td>پروتکل لینک بسته، دامنه اشتباه، فایروال</td><td>دامنه‌ها را چک کنید؛ IPIP/6to4 یا حالت مستقیم</td></tr>')+
   _L('<tr><td><code>libssl.so.3</code></td><td>هسته rathole 0.5.0 روی سرور قدیمی</td><td>«دانلود از مخزن NETIFAY» (نسخه سازگار خودکار)</td></tr>')+
   _L('<tr><td>CDN وصل نمی‌شود</td><td>ابر نارنجی خاموش، پورت غیرمجاز، SSL Strict، WebSockets خاموش</td><td>بخش CDN همین راهنما</td></tr>')+
   _L('<tr><td>«اتصال‌های تانل: 0» در تست پورت</td><td>سرور مقابل وصل نیست</td><td>لاگ هر دو طرف، توکن، پورت تانل، فایروال</td></tr>')+
   _L('<tr><td>«پورت در حال استفاده است»</td><td>برنامه یا تانل دیگری آن را دارد</td><td>پورت دیگر؛ «بررسی تداخل‌ها»</td></tr></table>')+
   _L('<p class="hint">ترتیب عیب‌یابی: ۱) «تست پینگ» (فقط حالت لینک) ← ۲) «تست پورت‌ها» ← ۳) «لاگ» هر دو سرور ← ۴) «بررسی تداخل‌ها».</p>'))+
  sec('g-check',ic('checklist')+_L(' چک‌لیست ساخت تانل'),
   _L('<ol><li>هسته موتور را روی هر دو سرور نصب کنید (تب «هسته»).</li><li>«بهینه‌سازی شبکه» را روی هر دو سرور اعمال کنید (تنظیمات).</li>')+
   _L('<li>اول سرور ایران را بسازید، بعد خارج را با همان پورت تانل، توکن، پورت‌ها و تنظیمات.</li>')+
   _L('<li>در حالت لینک: IP داخلی ایران x.x.x.1 و خارج x.x.x.2 (پنل مقدار درست را نشان می‌دهد).</li>')+
   _L('<li>«تست پورت‌ها» و «بررسی تداخل‌ها» را روی هر دو سرور بزنید.</li><li>از هر دو سرور بکاپ بگیرید و دانلود کنید.</li></ol>'))+
  '</div>';
}

/* ---------------- settings ---------------- */
async function renderSettings(){
  const el=$('#tab-settings');let c;
  try{c=await api('settings_get')}catch(e){toast(e.message,'err');return}
  el.innerHTML=_L('<div class="form"><h2>تنظیمات پنل</h2>')+
   _L('<h3>تغییر نام کاربری و رمز</h3><form class="card" id="credF">')+
   _L('<label class="f"><span>رمز فعلی</span><input class="ltr" type="password" name="current" autocomplete="current-password"></label>')+
   _L('<div class="row"><label class="f"><span>نام کاربری جدید</span><input class="ltr" name="user" value="')+esc(c.user)+'" autocomplete="username"></label>'+
   _L('<label class="f"><span>رمز جدید</span><input class="ltr" type="password" name="password" autocomplete="new-password" minlength="8" placeholder="حداقل 8 کاراکتر"></label></div>')+
   _L('<button class="btn p">ذخیره</button></form>')+
   _L('<h3>پورت و مسیر مخفی پنل</h3><form class="card" id="portF">')+
   _L('<div class="row"><label class="f"><span>پورت پنل</span><input class="ltr" name="port" inputmode="numeric" value="')+esc(c.port)+'"></label>'+
   _L('<label class="f"><span>مسیر مخفی (اختیاری)</span><input class="ltr" name="base" value="')+esc(c.base)+'" placeholder="mysecret"></label></div>'+
   _L('<div class="hint" style="margin-bottom:10px">آدرس پنل: <span class="ltr" id="newUrl"></span><br>بعد از ذخیره، پنل ری‌استارت می‌شود و به آدرس جدید منتقل می‌شوید.</div>')+
   _L('<button class="btn p">ذخیره و ری‌استارت پنل</button></form>')+
   _L('<h3>بهینه‌سازی شبکه سرور</h3><div class="card" id="optBox"><span class="spin"></span></div>')+
   _L('<h3>HTTPS (رمزنگاری اتصال پنل)</h3><div class="card">')+
   _L('<div class="hint" style="margin-bottom:10px">وضعیت: <b style="color:')+(c.tls?'var(--ok)':'var(--bad)')+'">'+(c.tls?ic('check','sm')+_L(' روشن'):_L('خاموش'))+_L('</b><br>با روشن کردن، یک گواهی خودامضا ساخته می‌شود و رمز و کوکی رمزنگاری می‌شوند. مرورگر بار اول هشدار «Not secure / گواهی نامعتبر» می‌دهد؛ «Advanced → Proceed» را بزنید. این هشدار طبیعی است.</div>')+
   (c.has_openssl||c.tls?'':_L('<div class="warnbox">برنامه openssl روی سرور نیست: <span class="ltr">apt install openssl</span></div>'))+
   '<button class="btn '+(c.tls?'d':'p')+'" id="httpsBtn">'+(c.tls?_L('خاموش کردن HTTPS'):_L('روشن کردن HTTPS'))+'</button></div>'+
   _L('<h3>دسترسی از بیرون</h3><div class="card">')+
   _L('<div class="hint" style="margin-bottom:10px">وقتی کارتان با پنل تمام شد، دسترسی از اینترنت را ببندید. پنل فقط روی خود سرور <span class="ltr">(127.0.0.1)</span> در دسترس می‌ماند و تانل‌ها هیچ تغییری نمی‌کنند.<br>برای روشن کردن دوباره، در SSH دستور <b class="ltr">netifay</b> را بزنید و گزینه 7 را انتخاب کنید.</div>')+
   _L('<button class="btn d" id="extOff">بستن دسترسی وب از بیرون</button></div>')+
   _L('<h3>درباره</h3><div class="card"><dl class="kv"><dt>نسخه پنل</dt><dd class="ltr">NETIFAY ')+esc(S.sys.version||'')+_L('</dd><dt>مخزن</dt><dd class="ltr">')+(c.repo?'<a href="https://github.com/'+esc(c.repo)+'" target="_blank" rel="noopener">'+esc(c.repo)+'</a>':'-')+_L('</dd><dt>سرور</dt><dd class="ltr">')+esc(S.sys.hostname||'')+'</dd><dt>HTTPS</dt><dd>'+(c.tls?_L('فعال'):_L('غیرفعال'))+'</dd></dl>'+
   _L('<div class="hint">به‌روزرسانی پنل: در SSH دستور <b class="ltr">netifay</b> → گزینه 1.</div></div></div>');
  $('#extOff').onclick=()=>modal(_L('بستن دسترسی از بیرون'),_L('<p>بعد از تایید، این صفحه دیگر باز نمی‌شود. برای روشن کردن دوباره باید با SSH وارد سرور شوید و دستور <b class="ltr">netifay</b> → گزینه 7 را بزنید.</p>'),
    [{text:_L('بله، ببند'),cls:'d',fn:btn=>busy(btn,async()=>{await api('external_off');closeModal();$('#app').innerHTML='<div class="login"><div class="card" style="text-align:center">'+ic('lock','lg')+_L('<br>دسترسی وب از بیرون بسته شد<br><br><span class="hint">برای باز کردن: SSH ← <span class="ltr">netifay</span> ← گزینه 7</span></div></div>');stopTimer()})},{text:_L('انصراف'),fn:closeModal}]);
  renderOpt();
  $('#httpsBtn').onclick=e=>{const on=!c.tls;
    modal(on?_L('روشن کردن HTTPS'):_L('خاموش کردن HTTPS'),'<p>'+(on?_L('پنل ری‌استارت می‌شود و به آدرس <b class="ltr">https://</b> منتقل می‌شوید. بعد از آن آدرس <span class="ltr">http://</span> دیگر کار نمی‌کند.'):_L('اتصال پنل دوباره HTTP ساده (بدون رمزنگاری) می‌شود.'))+'</p>',
      [{text:_L('تایید'),cls:on?'p':'d',fn:btn=>busy(btn,async()=>{const d=await api('https',{on});closeModal();
        const url=(d.https?'https:':'http:')+'//'+location.hostname+':'+d.port+'/'+(d.base?d.base+'/':'');
        toast(_L('در حال انتقال به ')+url,'ok');setTimeout(()=>location.href=url,3500)})},{text:_L('انصراف'),fn:closeModal}]);};
  const pf=$('#portF');
  const upd=()=>{const b=pf.base.value.trim().replace(/^\/+|\/+$/g,'');$('#newUrl').textContent=location.protocol+'//'+location.hostname+':'+pf.port.value.trim()+'/'+(b?b+'/':'')};
  pf.port.oninput=upd;pf.base.oninput=upd;upd();
  $('#credF').onsubmit=ev=>{ev.preventDefault();const f=ev.target;busy($('button',f),async()=>{await api('set_credentials',{current:f.current.value,user:f.user.value.trim(),password:f.password.value});toast(_L('ذخیره شد؛ دوباره وارد شوید'),'ok');showLogin()})};
  pf.onsubmit=ev=>{ev.preventDefault();busy($('button',pf),async()=>{const d=await api('panel_settings',{port:pf.port.value.trim(),base:pf.base.value.trim()});
    const url=(d.https?'https:':'http:')+'//'+location.hostname+':'+d.port+'/'+(d.base?d.base+'/':'');toast(_L('در حال انتقال به ')+url,'ok');setTimeout(()=>location.href=url,3000)})};
}

/* ---------------- boot ---------------- */
(async()=>{try{const d=await api('list');S.tunnels=d.tunnels;S.sys=d.system;showApp()}catch(e){showLogin()}})();
</script>
</body>
</html>
"""

# Vazirmatn (c) Saber Rastikerdar — SIL Open Font License 1.1 — served locally (no external CDN)
FONT_DATA = _b64.b64decode("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")


def harden_perms():
    """Older versions wrote some tunnel configs world-readable (they contain tokens)."""
    dirs = [CORE_DIR, BH_DIR] + [g["dir"] for g in GEN.values()]
    for d in dirs:
        try:
            os.chmod(d, 0o700)
            for f in os.listdir(d):
                if f.endswith((".toml", ".yaml", ".json", ".bak", ".key", ".p12", ".pem")):
                    p = os.path.join(d, f)
                    if os.path.isfile(p) and os.stat(p).st_mode & 0o077:
                        os.chmod(p, 0o600)
        except OSError:
            pass


def main():
    args = sys.argv[1:]
    if args and args[0] in ("--version", "-v"):
        print("NETIFAY %s" % VERSION)
        return
    load_conf()
    if args and args[0] == "--setup":
        # values come from env so the password never shows in `ps`
        user = os.environ.get("RP_USER", "admin")
        pw = os.environ.get("RP_PASS", "")
        try:
            set_credentials(user, pw)
        except ApiError as e:
            print("ERROR: %s" % e)
            sys.exit(1)
        if os.environ.get("RP_PORT"):
            try:
                port = int(os.environ["RP_PORT"])
                if not 1 <= port <= 65535:
                    raise ValueError
            except ValueError:
                print("ERROR: port must be a number between 1 and 65535")
                sys.exit(1)
            CONF["port"] = port
        if "RP_BASE" in os.environ:
            base = os.environ["RP_BASE"].strip().strip("/")
            if base and not re.match(r"^[A-Za-z0-9_\-]{1,64}$", base):
                print("ERROR: secret path may only contain English letters, digits, - and _")
                sys.exit(1)
            CONF["base"] = base
        CONF.setdefault("port", 8800)
        CONF.setdefault("base", "")
        save_conf()
        print("OK")
        return
    if args and args[0] == "--listen":
        if len(args) < 2 or args[1] not in ("public", "local"):
            print("usage: --listen public|local")
            sys.exit(1)
        CONF["listen"] = "0.0.0.0" if args[1] == "public" else "127.0.0.1"
        save_conf()
        print("OK")
        return
    if args and args[0] == "--repo":
        if len(args) < 2 or not re.match(r"^[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+$", args[1]):
            print("usage: --repo user/repo")
            sys.exit(1)
        CONF["repo"] = args[1]
        save_conf()
        print("OK")
        return
    if args and args[0] == "--https":
        if len(args) < 2 or args[1] not in ("on", "off"):
            print("usage: --https on|off")
            sys.exit(1)
        try:
            set_https(args[1] == "on")
        except ApiError as e:
            print("ERROR: %s" % e)
            sys.exit(1)
        print("OK")
        return
    if args and args[0] == "--show":
        out = {k: CONF.get(k) for k in ("user", "port", "base", "listen")}
        out["https"] = bool(CONF.get("cert"))
        print(json.dumps(out))
        return
    if not CONF.get("hash"):
        print("Panel is not configured. Run: RP_USER=admin RP_PASS=secret %s --setup" % sys.argv[0])
        sys.exit(1)
    port = int(CONF.get("port", 8800))
    host = CONF.get("listen", "0.0.0.0")
    threading.Thread(target=cpu_sampler, daemon=True).start()
    harden_perms()
    srv = PanelServer((host, port), Handler)
    if CONF.get("cert") and CONF.get("key"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(CONF["cert"], CONF["key"])
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    print("NETIFAY panel %s listening on %s:%d%s/" % (VERSION, host, port, base_path()))
    sys.stdout.flush()
    srv.serve_forever()


if __name__ == "__main__":
    main()

