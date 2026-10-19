#!/usr/bin/env python3
"""
iotscan.py - General-purpose IoT device security recon / light enumeration tool.

FOR AUTHORIZED TESTING ONLY. Use only against devices you own or have explicit,
documented permission to test. This tool performs passive/light enumeration and,
only when explicitly opted in, a small check of well-known DEFAULT credentials.
It does NOT brute force, does NOT exploit, and does NOT exfiltrate data.

Python 3, standard-library first. The only optional external dependency is the
`nmap` binary (used if present; a pure-Python TCP connect scan is the fallback).

Author: (your name)
"""

import argparse
import ipaddress
import json
import socket
import ssl
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urlparse

# --------------------------------------------------------------------------- #
# Configuration / constants
# --------------------------------------------------------------------------- #

VERSION = "1.0"

# Common IoT-relevant ports with friendly service labels.
IOT_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    53: "dns",
    80: "http",
    111: "rpcbind",
    443: "https",
    515: "printer-lpd",
    554: "rtsp",
    631: "ipp",
    1883: "mqtt",
    1900: "upnp-ssdp",
    3000: "http-alt",
    5000: "upnp/http-alt",
    5353: "mdns",
    5555: "adb",
    7000: "http-alt",
    7676: "samsung-smartview",
    8008: "chromecast-dial",
    8009: "chromecast-tls",
    8060: "roku-ecp",
    8080: "http-proxy",
    8443: "https-alt",
    8883: "mqtt-tls",
    9000: "http-alt",
    9080: "http-alt",
    9999: "http-alt",
    49152: "upnp-dynamic",
    49153: "upnp-dynamic",
    49154: "upnp-dynamic",
    49155: "upnp-dynamic",
    49156: "upnp-dynamic",
    49157: "upnp-dynamic",
    49158: "upnp-dynamic",
    49159: "upnp-dynamic",
    49160: "upnp-dynamic",
}

# Common HTTP admin / interesting paths to probe (GET only, read-only).
HTTP_PATHS = [
    "/",
    "/index.html",
    "/login",
    "/login.html",
    "/admin",
    "/admin/",
    "/admin/login",
    "/cgi-bin/",
    "/setup.cgi",
    "/system.ini",
    "/config",
    "/api",
    "/api/v1",
    "/status",
    "/info",
    "/device",
    "/apps",          # Roku/DIAL
    "/ssdp/device-desc.xml",
    "/description.xml",
    "/dd.xml",
]

# Well-known DEFAULT credentials for widespread IoT gear. This is intentionally
# tiny and documented - it is NOT a brute-force wordlist. OPT-IN only.
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("admin", "1234"),
    ("admin", "12345"),
    ("root", "root"),
    ("root", ""),
    ("root", "admin"),
    ("root", "12345"),
    ("user", "user"),
    ("guest", "guest"),
    ("support", "support"),
]

DEFAULT_TIMEOUT = 2.0
MAX_WORKERS = 50

# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat()


def log(msg, quiet=False):
    if not quiet:
        print(msg, flush=True)


class RateLimiter:
    """Simple minimum-interval limiter to be polite to target devices."""

    def __init__(self, min_interval=0.0):
        self.min_interval = min_interval
        self._last = 0.0

    def wait(self):
        if self.min_interval <= 0:
            return
        delta = time.time() - self._last
        if delta < self.min_interval:
            time.sleep(self.min_interval - delta)
        self._last = time.time()


# --------------------------------------------------------------------------- #
# Target expansion
# --------------------------------------------------------------------------- #


def expand_targets(target):
    """Accept a single IP, CIDR, or a-b range (e.g. 192.168.1.10-20)."""
    targets = []
    if "/" in target:
        net = ipaddress.ip_network(target, strict=False)
        targets = [str(h) for h in net.hosts()]
    elif "-" in target:
        base, _, tail = target.rpartition(".")
        start_s, _, end_s = tail.partition("-")
        start, end = int(start_s), int(end_s)
        targets = ["{}.{}".format(base, i) for i in range(start, end + 1)]
    else:
        # validate single IP / hostname
        targets = [target]
    return targets


# --------------------------------------------------------------------------- #
# Module: port scan (nmap or pure-python fallback)
# --------------------------------------------------------------------------- #


def have_nmap():
    try:
        subprocess.run(
            ["nmap", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return True
    except Exception:
        return False


def nmap_scan(ip, full=False, quiet=False):
    """Run nmap -sV and parse the (grepable) output into {port: {...}}."""
    ports = "-p-" if full else "-p" + ",".join(str(p) for p in sorted(IOT_PORTS))
    cmd = ["nmap", "-sV", "-T4", "-Pn", ports, "-oG", "-", ip]
    log("    [nmap] " + " ".join(cmd), quiet)
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600
        ).stdout
    except Exception as e:
        log("    [nmap] failed: {} - falling back".format(e), quiet)
        return python_scan(ip, full=full, quiet=quiet)

    results = {}
    for line in out.splitlines():
        if "Ports:" not in line:
            continue
        portblock = line.split("Ports:", 1)[1]
        for entry in portblock.split(","):
            fields = entry.strip().split("/")
            if len(fields) < 5:
                continue
            try:
                portnum = int(fields[0])
            except ValueError:
                continue
            state = fields[1]
            if state != "open":
                continue
            svc = fields[4] or IOT_PORTS.get(portnum, "unknown")
            version = fields[6] if len(fields) > 6 else ""
            results[portnum] = {
                "state": "open",
                "service": svc,
                "version": version.strip(),
                "banner": "",
            }
    return results


def grab_banner(ip, port, timeout=DEFAULT_TIMEOUT):
    """Best-effort passive banner grab on an open TCP port."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(256)
                return data.decode("latin-1", "replace").strip()
            except Exception:
                return ""
    except Exception:
        return ""


def python_scan(ip, full=False, quiet=False, limiter=None):
    """Pure-python TCP connect scan of the IoT port list (fallback)."""
    ports = list(range(1, 65536)) if full else sorted(IOT_PORTS)
    results = {}

    def check(port):
        if limiter:
            limiter.wait()
        try:
            with socket.create_connection((ip, port), timeout=DEFAULT_TIMEOUT):
                return port, True
        except Exception:
            return port, False

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(check, p): p for p in ports}
        for fut in as_completed(futs):
            port, is_open = fut.result()
            if is_open:
                banner = grab_banner(ip, port)
                results[port] = {
                    "state": "open",
                    "service": IOT_PORTS.get(port, "unknown"),
                    "version": "",
                    "banner": banner,
                }
    return results


# --------------------------------------------------------------------------- #
# Module: HTTP(S) enumeration
# --------------------------------------------------------------------------- #


def http_request(ip, port, path, tls=False, method="GET", timeout=DEFAULT_TIMEOUT):
    """Minimal read-only HTTP(S) request. Returns (status, headers, body)."""
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = HTTPSConnection(ip, port, timeout=timeout, context=ctx)
        else:
            conn = HTTPConnection(ip, port, timeout=timeout)
        conn.request(method, path, headers={"User-Agent": "iotscan/" + VERSION})
        resp = conn.getresponse()
        body = resp.read(8192).decode("latin-1", "replace")
        headers = {k.lower(): v for k, v in resp.getheaders()}
        status = resp.status
        conn.close()
        return status, headers, body
    except Exception:
        return None, {}, ""


def extract_title(body):
    low = body.lower()
    i = low.find("<title>")
    if i == -1:
        return ""
    j = low.find("</title>", i)
    if j == -1:
        return ""
    return body[i + 7:j].strip()[:120]


def enum_http(ip, port, tls, limiter, quiet=False):
    """Probe root + common admin paths; capture Server/title/auth hints."""
    info = {"port": port, "tls": tls, "paths": [], "server": "", "title": ""}
    for path in HTTP_PATHS:
        if limiter:
            limiter.wait()
        status, headers, body = http_request(ip, port, path, tls=tls)
        if status is None:
            continue
        rec = {
            "path": path,
            "status": status,
            "server": headers.get("server", ""),
            "www_authenticate": headers.get("www-authenticate", ""),
            "title": extract_title(body),
            "content_type": headers.get("content-type", ""),
        }
        if not info["server"] and rec["server"]:
            info["server"] = rec["server"]
        if path == "/" and rec["title"]:
            info["title"] = rec["title"]
        # Only keep interesting responses (not 404s) to reduce noise.
        if status in (200, 301, 302, 401, 403):
            info["paths"].append(rec)
    return info


# --------------------------------------------------------------------------- #
# Module: UPnP / SSDP M-SEARCH
# --------------------------------------------------------------------------- #


def ssdp_discover(timeout=3.0, quiet=False):
    """Send an SSDP M-SEARCH multicast and collect responders + LOCATIONs."""
    msg = "\r\n".join(
        [
            "M-SEARCH * HTTP/1.1",
            "HOST: 239.255.255.250:1900",
            'MAN: "ssdp:discover"',
            "MX: 2",
            "ST: ssdp:all",
            "",
            "",
        ]
    ).encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    responders = {}
    try:
        sock.sendto(msg, ("239.255.255.250", 1900))
        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            text = data.decode("latin-1", "replace")
            headers = {}
            for line in text.split("\r\n")[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()
            ipaddr = addr[0]
            responders.setdefault(ipaddr, []).append(
                {
                    "location": headers.get("location", ""),
                    "server": headers.get("server", ""),
                    "st": headers.get("st", ""),
                    "usn": headers.get("usn", ""),
                }
            )
    except Exception as e:
        log("    [ssdp] error: {}".format(e), quiet)
    finally:
        sock.close()
    return responders


def fetch_upnp_descriptor(location, quiet=False):
    """GET and lightly parse a UPnP device descriptor XML."""
    try:
        parsed = urlparse(location)
        tls = parsed.scheme == "https"
        port = parsed.port or (443 if tls else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        status, _, body = http_request(parsed.hostname, port, path, tls=tls)
        if status != 200:
            return {}
        # strip XML namespaces for easy tag matching
        body_ns = body
        root = ET.fromstring(body_ns.encode("latin-1", "replace"))

        def find(tag):
            for el in root.iter():
                if el.tag.split("}")[-1] == tag and el.text:
                    return el.text.strip()
            return ""

        return {
            "friendlyName": find("friendlyName"),
            "manufacturer": find("manufacturer"),
            "modelName": find("modelName"),
            "modelNumber": find("modelNumber"),
            "deviceType": find("deviceType"),
            "serialNumber": find("serialNumber"),
        }
    except Exception:
        return {}


# --------------------------------------------------------------------------- #
# Module: DIAL / Chromecast / Roku / RTSP
# --------------------------------------------------------------------------- #


def enum_dial(ip, quiet=False):
    """DIAL/Chromecast on 8008 - read device info endpoint (read-only)."""
    out = {}
    for path in ("/setup/eureka_info", "/ssdp/device-desc.xml", "/apps"):
        status, headers, body = http_request(ip, 8008, path)
        if status == 200:
            out[path] = body[:500]
    return out


def enum_roku(ip, quiet=False):
    """Roku ECP on 8060 - query device-info (read-only)."""
    status, headers, body = http_request(ip, 8060, "/query/device-info")
    if status == 200:
        return {"device-info": body[:1000]}
    return {}


def enum_rtsp(ip, port=554, timeout=DEFAULT_TIMEOUT, quiet=False):
    """Send an RTSP OPTIONS request to list supported methods."""
    req = (
        "OPTIONS rtsp://{}:{} RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        "User-Agent: iotscan/{}\r\n\r\n"
    ).format(ip, port, VERSION)
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(req.encode())
            data = s.recv(1024).decode("latin-1", "replace")
        methods = ""
        for line in data.split("\r\n"):
            if line.lower().startswith("public:"):
                methods = line.split(":", 1)[1].strip()
        return {"raw": data.strip()[:400], "methods": methods}
    except Exception:
        return {}


# --------------------------------------------------------------------------- #
# Module: opt-in default credential check (NON-destructive, limited)
# --------------------------------------------------------------------------- #


def try_default_creds(ip, port, tls, limiter, max_attempts=4, quiet=False):
    """
    OPT-IN ONLY. Tests a handful of documented default creds against HTTP Basic
    auth endpoints. Stops at the first success. Hard-capped attempts, no
    brute-forcing. Returns list of findings.
    """
    import base64

    findings = []
    # Find a path that challenges with Basic auth.
    target_path = "/"
    status, headers, _ = http_request(ip, port, "/", tls=tls)
    auth = headers.get("www-authenticate", "").lower()
    if "basic" not in auth:
        # try /admin
        status, headers, _ = http_request(ip, port, "/admin", tls=tls)
        if "basic" in headers.get("www-authenticate", "").lower():
            target_path = "/admin"
        else:
            return findings  # no basic-auth challenge found; skip

    attempts = 0
    for user, pw in DEFAULT_CREDS:
        if attempts >= max_attempts:
            break
        attempts += 1
        if limiter:
            limiter.wait()
        token = base64.b64encode("{}:{}".format(user, pw).encode()).decode()
        try:
            if tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = HTTPSConnection(ip, port, timeout=DEFAULT_TIMEOUT, context=ctx)
            else:
                conn = HTTPConnection(ip, port, timeout=DEFAULT_TIMEOUT)
            conn.request(
                "GET", target_path, headers={"Authorization": "Basic " + token}
            )
            resp = conn.getresponse()
            resp.read(64)
            conn.close()
            if resp.status not in (401, 403):
                findings.append(
                    {
                        "type": "default_credentials",
                        "severity": "critical",
                        "detail": "Default creds accepted on {}:{}{} -> {}:{}".format(
                            ip, port, target_path, user, pw or "(empty)"
                        ),
                    }
                )
                break
        except Exception:
            continue
    return findings


# =========================================================================== #
# Module: CVE matching (offline DB; optional online NVD lookup behind a flag)
# =========================================================================== #

import os
import re

DEFAULT_CVE_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_db.json")


def load_cve_db(path=None, quiet=False):
    """Load the offline, extensible CVE knowledge base (cve_db.json)."""
    path = path or DEFAULT_CVE_DB
    try:
        with open(path) as fh:
            db = json.load(fh)
        entries = db.get("entries", [])
        log("    [cve] loaded {} offline CVE entries from {}".format(
            len(entries), os.path.basename(path)), quiet)
        return entries
    except Exception as e:
        log("    [cve] could not load CVE DB ({}): {}".format(path, e), quiet)
        return []


def collect_fingerprints(device):
    """
    Gather all identifying strings from a scanned device into a normalized
    dict of fields so the CVE matcher has something to pattern-match against.
    Returns {"server":..,"banner":..,"manufacturer":..,"model":..,
             "version":..,"service":.., "_all":[all strings]}.
    """
    fp = {"server": [], "banner": [], "manufacturer": [], "model": [],
          "version": [], "service": []}

    for port, info in device.get("ports", {}).items():
        if info.get("service"):
            fp["service"].append(info["service"])
        if info.get("version"):
            fp["version"].append(info["version"])
        if info.get("banner"):
            fp["banner"].append(info["banner"])

    for h in device.get("http", []):
        if h.get("server"):
            fp["server"].append(h["server"])
        if h.get("title"):
            fp["banner"].append(h["title"])
        for rec in h.get("paths", []):
            if rec.get("server"):
                fp["server"].append(rec["server"])

    for desc in device.get("upnp", {}).get("descriptors", []):
        if desc.get("manufacturer"):
            fp["manufacturer"].append(desc["manufacturer"])
        for k in ("modelName", "modelNumber", "friendlyName"):
            if desc.get(k):
                fp["model"].append(desc[k])

    for r in device.get("upnp", {}).get("ssdp", []):
        if r.get("server"):
            fp["server"].append(r["server"])

    # Roku/DIAL blobs carry model info in free text.
    for blob in list(device.get("dial", {}).values()) + \
            list(device.get("roku", {}).values()):
        if isinstance(blob, str):
            fp["banner"].append(blob[:500])

    # flatten
    allstr = []
    for v in fp.values():
        allstr.extend(v)
    fp["_all"] = allstr
    return fp


def _field_matches(pattern, values):
    """True if regex `pattern` (case-insensitive) matches any string in values."""
    try:
        rx = re.compile(pattern, re.IGNORECASE)
    except re.error:
        rx = re.compile(re.escape(pattern), re.IGNORECASE)
    return any(rx.search(v) for v in values if v)


def match_cves(device, cve_entries, quiet=False):
    """
    Match a device's fingerprints against the offline CVE DB.
    Returns a list of {cve, severity, description, endpoints, references,
    matched_on} findings. Matching is advisory - verify manually.
    """
    fp = collect_fingerprints(device)
    hits = []
    for entry in cve_entries:
        match_rules = entry.get("match", {})
        matched_on = []
        for field, pattern in match_rules.items():
            if field == "any":
                if _field_matches(pattern, fp["_all"]):
                    matched_on.append("any~/{}/".format(pattern))
            elif field in fp:
                if _field_matches(pattern, fp[field]):
                    matched_on.append("{}~/{}/".format(field, pattern))
        # require every rule in the entry to match (AND semantics)
        if matched_on and len(matched_on) == len(match_rules):
            hits.append({
                "cve": entry.get("cve", "UNKNOWN"),
                "severity": entry.get("severity", "info"),
                "description": entry.get("description", ""),
                "endpoints": entry.get("endpoints", []),
                "references": entry.get("references", []),
                "matched_on": matched_on,
                # Knowledge-base flags: whether this device class is a known
                # botnet-recruitment target, and its typical ingress vector.
                "botnet": entry.get("botnet", False),
                "attack_vector": entry.get("attack_vector", ""),
            })
            log("    [cve] MATCH {} ({}) via {}".format(
                entry.get("cve"), entry.get("severity"),
                ", ".join(matched_on)), quiet)
    return hits


def nvd_online_lookup(keyword, quiet=False, timeout=8.0):
    """
    OPTIONAL online enrichment (behind --nvd-online). Queries the public NVD
    2.0 API for a keyword and returns a few recent CVE ids/summaries. Read-only,
    no auth, best-effort. Disabled by default so the tool stays offline.
    """
    import urllib.request
    import urllib.parse
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    url = base + "?" + urllib.parse.urlencode(
        {"keywordSearch": keyword, "resultsPerPage": 5})
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "iotscan"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        out = []
        for item in data.get("vulnerabilities", []):
            c = item.get("cve", {})
            descs = c.get("descriptions", [])
            summary = next((d["value"] for d in descs if d.get("lang") == "en"),
                           "")
            out.append({"cve": c.get("id", ""), "description": summary[:200]})
        log("    [cve/nvd] online lookup '{}' -> {} results".format(
            keyword, len(out)), quiet)
        return out
    except Exception as e:
        log("    [cve/nvd] online lookup failed: {}".format(e), quiet)
        return []


# =========================================================================== #
# Module: ADB foothold confirmation (opt-in, intrusive: --confirm-footholds)
# =========================================================================== #


def have_adb():
    try:
        subprocess.run(["adb", "version"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=True)
        return True
    except Exception:
        return False


def confirm_adb_foothold(ip, port=5555, quiet=False):
    """
    OPT-IN INTRUSIVE. If ADB is exposed, connect and run a few HARMLESS,
    read-only identifying commands to CONFIRM shell access, then disconnect.
    No persistence, no file drops, nothing destructive. Requires the `adb`
    binary. Returns a finding dict (or a note if adb is missing / no connect).
    """
    if not have_adb():
        return {
            "type": "adb_confirm",
            "severity": "critical",
            "confirmed": False,
            "detail": ("ADB open on {}:{} but the `adb` binary is not installed, "
                       "so shell access could not be confirmed. Install "
                       "android-tools-adb and re-run with --confirm-footholds."
                       ).format(ip, port),
        }

    target = "{}:{}".format(ip, port)
    info = {}
    connected = False
    try:
        # connect (short timeout; adb has its own retry we keep bounded)
        r = subprocess.run(["adb", "connect", target], capture_output=True,
                           text=True, timeout=15)
        out = (r.stdout + r.stderr).lower()
        connected = ("connected to" in out) and ("cannot" not in out) \
            and ("failed" not in out)
        log("    [adb] connect {} -> {}".format(
            target, r.stdout.strip() or r.stderr.strip()), quiet)

        if connected:
            # HARMLESS identifying commands only.
            cmds = {
                "model": ["adb", "-s", target, "shell",
                          "getprop", "ro.product.model"],
                "android_release": ["adb", "-s", target, "shell",
                                    "getprop", "ro.build.version.release"],
                "manufacturer": ["adb", "-s", target, "shell",
                                 "getprop", "ro.product.manufacturer"],
                "id": ["adb", "-s", target, "shell", "id"],
            }
            for key, cmd in cmds.items():
                try:
                    cr = subprocess.run(cmd, capture_output=True, text=True,
                                        timeout=10)
                    info[key] = cr.stdout.strip()
                except Exception as e:
                    info[key] = "(error: {})".format(e)
                log("    [adb] {} = {}".format(key, info.get(key, "")), quiet)
    except Exception as e:
        log("    [adb] error: {}".format(e), quiet)
    finally:
        # always clean up the connection we opened
        try:
            subprocess.run(["adb", "disconnect", target],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=10)
        except Exception:
            pass

    if connected and info:
        detail = ("CONFIRMED unauthenticated ADB shell on {} - "
                  "model='{}' manufacturer='{}' android='{}' id='{}'. "
                  "Full device shell with no auth. Next manual step: review what "
                  "this exposes and disable ADB-over-network on the device."
                  ).format(target, info.get("model", "?"),
                           info.get("manufacturer", "?"),
                           info.get("android_release", "?"),
                           info.get("id", "?"))
        return {"type": "adb_confirm", "severity": "critical",
                "confirmed": True, "device_info": info, "detail": detail}

    return {"type": "adb_confirm", "severity": "high", "confirmed": False,
            "detail": ("ADB port {} open but a shell could not be confirmed "
                       "(connection refused/unauthorized or device prompted for "
                       "RSA approval). Check the device screen for an auth "
                       "prompt.").format(target)}


# =========================================================================== #
# Module: Web-UI vulnerability probes (opt-in intrusive: --confirm-footholds)
# =========================================================================== #

# Protected paths that should normally require auth; a 200 here = possible bypass
PROTECTED_PATHS = [
    "/admin", "/admin/", "/admin/index.html", "/admin/config",
    "/config", "/system.ini", "/setup.cgi", "/cgi-bin/luci",
    "/api/v1/system", "/settings", "/management", "/password",
]

# Read-only path-traversal test targets (we only READ, never write).
TRAVERSAL_PAYLOADS = [
    "/../../../../../../etc/passwd",
    "/..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/cgi-bin/../../../../etc/passwd",
]

# Parameters commonly reflected / passed to shell on cheap IoT web UIs.
INJECTABLE_PARAMS = ["cmd", "command", "ip", "host", "ping", "target",
                     "query", "q", "search", "name", "file", "page"]


def _unique_nonce():
    import uuid
    return "iotscn" + uuid.uuid4().hex[:10]


def probe_auth_bypass(ip, port, tls, limiter, quiet=False):
    """
    Read-only: request known protected paths directly. A 200 with real content
    (not a login redirect) suggests an auth bypass / unprotected admin surface.
    """
    findings = []
    for path in PROTECTED_PATHS:
        if limiter:
            limiter.wait()
        status, headers, body = http_request(ip, port, path, tls=tls)
        if status == 200 and len(body) > 0:
            loc = headers.get("location", "")
            looks_login = ("login" in body.lower()[:400]) or \
                          ("password" in body.lower()[:400] and
                           "type=\"password\"" in body.lower())
            if not loc and not looks_login:
                findings.append({
                    "type": "auth_bypass_suspected", "severity": "high",
                    "confirmed": False,
                    "detail": ("Protected path {}:{}{} returned 200 with content "
                               "and no login form/redirect - possible unprotected "
                               "admin surface. Verify manually.").format(
                                   ip, port, path),
                })
    return findings


def probe_path_traversal(ip, port, tls, limiter, quiet=False):
    """
    Read-only path-traversal check. We request classic ../etc/passwd style
    paths and ONLY look for the tell-tale 'root:x:0:0:' signature. We never
    write, modify, or exfiltrate - a positive here is reported, not dumped.
    """
    findings = []
    for path in TRAVERSAL_PAYLOADS:
        if limiter:
            limiter.wait()
        status, _, body = http_request(ip, port, path, tls=tls)
        if status == 200 and re.search(r"root:.*:0:0:", body):
            findings.append({
                "type": "path_traversal", "severity": "critical",
                "confirmed": True,
                "detail": ("CONFIRMED path traversal: {}:{}{} returned a "
                           "/etc/passwd signature (root:...:0:0:). Read-only "
                           "proof only; contents not stored.").format(
                               ip, port, path),
            })
            break  # one confirmation is enough; don't hammer
    return findings


def probe_command_injection(ip, port, tls, limiter, quiet=False):
    """
    DETECTION-ONLY reflected command-injection check. We inject a BENIGN marker
    using a unique nonce (e.g. `;echo <nonce>` / `$(echo <nonce>)` / backticks)
    into common parameters and look for the bare nonce appearing in the
    response - which would only happen if the payload's echo executed. We do NOT
    run any real command beyond `echo <nonce>`; this proves injection without
    doing anything destructive. Bounded: a small fixed set of params/paths.
    """
    from urllib.parse import quote

    findings = []
    base_paths = ["/", "/cgi-bin/", "/api", "/status", "/ping.cgi",
                  "/diagnostic.cgi"]
    tested = 0
    MAX_TESTS = 40  # hard cap: no fuzzing storm

    for path in base_paths:
        for param in INJECTABLE_PARAMS:
            if tested >= MAX_TESTS:
                break
            nonce = _unique_nonce()
            # Benign payloads: each merely echoes the nonce if injection works.
            payloads = [
                ";echo {}".format(nonce),
                "$(echo {})".format(nonce),
                "`echo {}`".format(nonce),
                "|echo {}".format(nonce),
            ]
            for raw in payloads:
                if tested >= MAX_TESTS:
                    break
                tested += 1
                if limiter:
                    limiter.wait()
                qs = "{}?{}={}".format(path, param, quote(raw))
                status, _, body = http_request(ip, port, qs, tls=tls)
                if status is None or not body:
                    continue
                # Executed injection => the bare nonce (without echo/; wrappers)
                # shows up in output. Guard against trivial full-payload echo.
                if nonce in body and raw not in body:
                    findings.append({
                        "type": "command_injection", "severity": "critical",
                        "confirmed": True,
                        "detail": ("CONFIRMED reflected command injection at "
                                   "{}:{}{} param '{}': benign `echo {}` executed "
                                   "(nonce reflected in output). No real command "
                                   "run beyond echo.").format(
                                       ip, port, path, param, nonce),
                    })
                    return findings  # confirmed once; stop probing
    return findings


def probe_cve_endpoints(ip, port, tls, cve_hits, limiter, quiet=False):
    """
    Read-only corroboration of matched CVEs: GET the advisory's known endpoints
    and note which are reachable (status 200/401/403). We do NOT fire the
    exploit payloads - reachability is a manual-verification hint only.
    """
    findings = []
    seen = set()
    for hit in cve_hits:
        for ep in hit.get("endpoints", []):
            if ep in seen or not ep.startswith("/"):
                continue
            seen.add(ep)
            if limiter:
                limiter.wait()
            status, _, _ = http_request(ip, port, ep, tls=tls)
            if status in (200, 401, 403):
                findings.append({
                    "type": "cve_endpoint_reachable", "severity": "info",
                    "confirmed": False,
                    "detail": ("CVE-related endpoint reachable ({}): {}:{}{} "
                               "returned {}. Reachability only - exploit NOT "
                               "fired; verify manually.").format(
                                   hit.get("cve"), ip, port, ep, status),
                })
    return findings


def run_webvuln(ip, open_ports, cve_hits, limiter, quiet=False):
    """Orchestrate the opt-in, read-only/detection-only web-UI probes."""
    findings = []
    web_ports = [(80, False), (8080, False), (8008, False), (3000, False),
                 (9000, False), (7000, False), (443, True), (8443, True)]
    for port, tls in web_ports:
        if port not in open_ports:
            continue
        log("    [webvuln] probing {}:{} (read-only / detection-only)".format(
            ip, port), quiet)
        findings += probe_auth_bypass(ip, port, tls, limiter, quiet)
        findings += probe_path_traversal(ip, port, tls, limiter, quiet)
        findings += probe_command_injection(ip, port, tls, limiter, quiet)
        findings += probe_cve_endpoints(ip, port, tls, cve_hits, limiter, quiet)
    return findings


# =========================================================================== #
# Assessment summary (chains recon -> CVEs -> confirmed footholds)
# =========================================================================== #

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _is_botnet_cve(hit):
    """True if a matched CVE describes a device class known to be botnet-recruited."""
    text = (hit.get("description", "") + " " + hit.get("cve", "")).lower()
    return hit.get("botnet") is True or any(
        k in text for k in ("mirai", "botnet", "satori", "adb.miner",
                             "gafgyt", "mozi", "qbot"))


def botnet_exposure_audit(device):
    """
    REPORTING ONLY. Evaluate whether - and HOW - a device could be recruited
    into a botnet or persisted on, based STRICTLY on what recon already
    detected. This installs nothing, uploads nothing, and persists nothing:
    every item below is a descriptive *finding* with evidence and severity so
    the owner can understand and close the exposure. No exploitation beyond the
    safe, already-gated probes elsewhere in the tool.
    """
    ports = {int(p): info for p, info in device.get("ports", {}).items()}
    findings = device.get("findings", [])
    cve_hits = device.get("cve_matches", [])
    ip = device.get("ip", "")
    vectors = []

    def add(vector, severity, detail, evidence):
        vectors.append({"vector": vector, "severity": severity,
                        "detail": detail, "evidence": evidence})

    # --- Exposed remote-shell services (classic Mirai / ADB.Miner ingress) ---
    if 23 in ports:
        add("telnet_remote_shell", "high",
            "Telnet (23) exposed - the classic Mirai recruitment vector: a loader "
            "logs in over weak/default telnet and installs a bot binary. Exposure "
            "reported only; no login attempted here.",
            "tcp/23 open")
    if 22 in ports:
        add("ssh_remote_shell", "medium",
            "SSH (22) exposed - if it accepts weak/default credentials it is a "
            "remote-shell recruitment vector. Exposure reported only.",
            "tcp/22 open")
    if 5555 in ports:
        add("adb_remote_shell", "critical",
            "ADB (5555) exposed - an unauthenticated ADB shell is full device "
            "access and a persistence foothold (ADB.Miner-class worms recruit "
            "Android TV/boxes this way). Reported only; the adb module only "
            "confirms read-only.",
            "tcp/5555 open")

    # --- Default / weak credentials already observed ---
    for f in findings:
        if f.get("type") == "default_credentials":
            add("default_credentials", "critical",
                "Default/weak credentials were accepted - a direct recruitment "
                "vector: a bot loader can authenticate and install itself. "
                "Reported only.",
                f.get("detail", ""))

    # --- Unauthenticated control APIs (abuse surface, not a shell) ---
    if 8008 in ports or device.get("dial"):
        add("unauth_control_api", "medium",
            "Unauthenticated Cast/DIAL control API (8008) - abusable on the LAN "
            "for remote control/reboot/app-launch. Not a shell, but an abuse "
            "surface that mass-control campaigns have used.",
            "tcp/8008 open / DIAL info readable")
    if any(p in ports for p in (1900, 49152, 49153, 49154, 49155, 49156)):
        add("unauth_upnp", "medium",
            "UPnP control surface exposed - open SOAP control actions have been "
            "abused for NAT-injection / proxy botnets; audit the allowed actions.",
            "UPnP/SSDP port(s) open")

    # --- Writable upload / firmware-update endpoints = persistence vector ---
    upload_hits = []
    for h in device.get("http", []):
        for rec in h.get("paths", []):
            pth = (rec.get("path") or "").lower()
            if any(k in pth for k in ("upload", "firmware", "upgrade",
                                      "flash", "update")):
                upload_hits.append("{}:{}{}".format(
                    ip, h.get("port"), rec.get("path")))
    for hit in cve_hits:
        for ep in hit.get("endpoints", []):
            if any(k in ep.lower() for k in ("upgrade", "firmware", "upload",
                                             "update", "flash")):
                upload_hits.append("{} ({})".format(ep, hit.get("cve")))
    if upload_hits:
        add("firmware_upload_persistence", "high",
            "Upload / firmware / upgrade endpoint(s) discovered - a writable "
            "firmware path is a classic persistence vector (unsigned/malicious "
            "image survives reboot). REPORTED ONLY; nothing was uploaded.",
            "; ".join(sorted(set(upload_hits))[:5]))

    # --- Known botnet-target CVEs from the offline DB ---
    for hit in cve_hits:
        if _is_botnet_cve(hit):
            add("known_botnet_cve", hit.get("severity", "high"),
                "Fingerprint matches {} - a device class known to be recruited "
                "by IoT botnets. {}".format(
                    hit.get("cve"), (hit.get("description") or "")[:140]),
                "cve match: {}".format(hit.get("cve", "")))

    severity = (max((v["severity"] for v in vectors),
                    key=lambda s: _SEV_RANK.get(s, 0)) if vectors else "info")
    if vectors:
        summary = ("Recruitable: {} exposure vector(s) found - {}".format(
            len(vectors), ", ".join(sorted({v["vector"] for v in vectors}))))
    else:
        summary = ("No botnet-recruitment exposure detected from recon "
                   "(no exposed shell, default creds, writable firmware path, "
                   "or botnet-class CVE).")
    return {"recruitable": bool(vectors), "severity": severity,
            "vectors": vectors, "summary": summary}


def determine_attack_vector(device):
    """
    Pick the SINGLE most probable route in from the detected evidence, using a
    clear priority ordering (confirmed footholds first, then strong exposures).
    Returns (vector, human_sentence). Reporting only.
    """
    ports = set(int(p) for p in device.get("ports", {}))
    findings = device.get("findings", [])
    cve_hits = device.get("cve_matches", [])
    confirmed = {f.get("type") for f in findings if f.get("confirmed") is True}
    ftypes = {f.get("type") for f in findings}
    bvectors = {v["vector"] for v in
                device.get("botnet_exposure", {}).get("vectors", [])}
    ble = device.get("ble_pairing") or {}

    def V(vector, why):
        return vector, ("How this device would most likely be compromised: "
                        "{} - {}").format(vector, why)

    # 1. Confirmed footholds are the strongest evidence.
    if "command_injection" in confirmed:
        return V("web command injection",
                 "a benign nonce echo executed via the web UI (confirmed foothold).")
    if "path_traversal" in confirmed:
        return V("web path traversal",
                 "the webroot returned an /etc/passwd signature (confirmed).")
    if "adb_confirm" in confirmed:
        return V("ADB shell on 5555",
                 "an unauthenticated ADB shell was confirmed over the network.")
    # 2. Default credentials observed.
    if "default_credentials" in ftypes:
        return V("default credentials",
                 "a documented default login was accepted (recruitment-ready).")
    # 3. Weak BLE pairing, when BLE data is attached to this device.
    if ble.get("pairing") == "just_works":
        return V("BLE pairing (Just Works)",
                 "the device accepts unauthenticated BLE bonds, exposing control "
                 "characteristics post-pairing.")
    # 4. Telnet (Mirai's front door).
    if 23 in ports:
        return V("default credentials over Telnet",
                 "Telnet is exposed; Mirai-class loaders brute weak/default "
                 "telnet logins.")
    # 5. ADB exposed (unconfirmed).
    if 5555 in ports:
        return V("ADB shell on 5555",
                 "ADB-over-network is exposed and frequently allows an "
                 "unauthenticated shell.")
    # 6. Writable firmware / upload endpoint.
    if "firmware_upload_persistence" in bvectors:
        return V("web admin file-upload / firmware endpoint",
                 "an upload/firmware/upgrade endpoint is reachable - a persistence "
                 "vector.")
    # 7. Unauthenticated admin surface.
    if "http_admin_no_auth" in ftypes or "auth_bypass_suspected" in ftypes:
        return V("unauthenticated web admin",
                 "an admin/config page is reachable without authentication.")
    # 8. Unauthenticated control API (Cast/DIAL).
    if 8008 in ports or "unauth_control_api" in bvectors:
        return V("unauthenticated Cast/DIAL control API",
                 "the 8008 control API answers without auth - remote "
                 "control/reboot/launch on the LAN.")
    # 9. SSH exposed.
    if 22 in ports:
        return V("SSH remote shell",
                 "SSH is exposed; weak/default credentials would grant a shell.")
    # 10. UPnP control abuse.
    if "unauth_upnp" in bvectors:
        return V("UPnP control abuse",
                 "open UPnP SOAP control actions are exposed on the LAN.")
    # 11. RTSP camera stream.
    if 554 in ports:
        return V("unauthenticated RTSP stream",
                 "an RTSP camera stream is exposed; check for no-auth access.")
    # 12. Matched CVE fallback.
    if cve_hits:
        top = max(cve_hits, key=lambda c: _SEV_RANK.get(c.get("severity"), 0))
        return V("known-CVE exploit ({})".format(top.get("cve")),
                 (top.get("description") or "")[:120])
    return V("no obvious remote vector found",
             "no exposed shell, default creds, control API, or matched CVE "
             "was detected.")


def build_assessment(device):
    """
    Produce a per-device assessment summary that chains the three layers:
    what's EXPOSED (recon), what MIGHT be vulnerable (CVE matches), and what's
    CONFIRMED exploitable (footholds). Also suggests the next manual step.
    """
    findings = device.get("findings", [])
    cve_hits = device.get("cve_matches", [])

    exposed = sorted(int(p) for p in device.get("ports", {}))
    confirmed = [f for f in findings if f.get("confirmed") is True]
    suspected = [f for f in findings
                 if f.get("confirmed") is False and f.get("type") not in
                 ("cve_endpoint_reachable",)]

    # highest severity across everything
    all_sev = [f.get("severity", "info") for f in findings] + \
              [c.get("severity", "info") for c in cve_hits]
    worst = max(all_sev, key=lambda s: _SEV_RANK.get(s, 0)) if all_sev else "info"

    # Suggest a sensible next manual action.
    next_step = "Review exposed services; nothing confirmed exploitable yet."
    if confirmed:
        c0 = confirmed[0]
        if c0["type"] == "adb_confirm":
            next_step = ("Confirmed ADB shell - disable ADB-over-network on the "
                         "device and review installed apps/logs.")
        elif c0["type"] == "command_injection":
            next_step = ("Confirmed command injection - identify the vulnerable "
                         "binary/firmware version and patch or isolate the device.")
        elif c0["type"] == "path_traversal":
            next_step = ("Confirmed path traversal - update firmware; the webroot "
                         "leaks arbitrary files.")
        elif c0["type"] == "default_credentials":
            next_step = ("Default credentials work - change them immediately and "
                         "check for persistence.")
    elif cve_hits:
        top = max(cve_hits, key=lambda c: _SEV_RANK.get(c.get("severity"), 0))
        next_step = ("Fingerprint matched {} ({}). Re-run with "
                     "--confirm-footholds to safely corroborate, or verify the "
                     "advisory manually.").format(top["cve"], top["severity"])
    elif suspected:
        next_step = ("Suspected issue: {} - verify manually.".format(
            suspected[0]["detail"][:120]))

    vector, vector_summary = determine_attack_vector(device)
    botnet = device.get("botnet_exposure", {})

    return {
        "worst_severity": worst,
        "exposed_ports": exposed,
        "cve_matches": [c["cve"] for c in cve_hits],
        "confirmed_footholds": [f["type"] for f in confirmed],
        "suspected_issues": [f["type"] for f in suspected],
        "next_manual_step": next_step,
        # Single most-probable route in, derived from the evidence above.
        "likely_attack_vector": vector,
        "attack_path_summary": vector_summary,
        # Botnet-recruitment exposure rollup (reporting only).
        "botnet_recruitable": botnet.get("recruitable", False),
        "botnet_exposure_severity": botnet.get("severity", "info"),
        "botnet_vectors": [v["vector"] for v in botnet.get("vectors", [])],
    }


# --------------------------------------------------------------------------- #
# Findings / severity synthesis
# --------------------------------------------------------------------------- #


def synthesize_findings(device):
    """Turn raw results into a severity-tagged findings list."""
    findings = []
    ports = device.get("ports", {})

    for port, info in ports.items():
        p = int(port)
        svc = info.get("service", "")
        if p == 23:
            findings.append(
                {"type": "telnet_open", "severity": "high",
                 "detail": "Telnet open on 23 - plaintext creds, common IoT backdoor"}
            )
        if p == 5555:
            findings.append(
                {"type": "adb_open", "severity": "critical",
                 "detail": "ADB open on 5555 - possible unauthenticated full shell "
                           "(Android TV). Test manually with 'adb connect'; do NOT auto-exploit."}
            )
        if p == 21:
            findings.append(
                {"type": "ftp_open", "severity": "medium",
                 "detail": "FTP open on 21 - check for anonymous access / plaintext creds"}
            )
        if p in (1883,):
            findings.append(
                {"type": "mqtt_open", "severity": "medium",
                 "detail": "MQTT open on 1883 (plaintext) - check for anonymous subscribe"}
            )
        if p == 554:
            findings.append(
                {"type": "rtsp_open", "severity": "medium",
                 "detail": "RTSP open on 554 - camera stream; check for no-auth access"}
            )

    # HTTP admin panel heuristics
    for h in device.get("http", []):
        for rec in h.get("paths", []):
            if rec["status"] == 200 and any(
                k in rec["path"] for k in ("admin", "login", "setup", "config")
            ):
                findings.append(
                    {"type": "http_admin_panel", "severity": "info",
                     "detail": "Admin/config page reachable: {}:{}{} (status 200)".format(
                         device["ip"], h["port"], rec["path"])}
                )
            if rec["status"] == 200 and rec["path"] in ("/admin", "/admin/") \
                    and not rec["www_authenticate"]:
                findings.append(
                    {"type": "http_admin_no_auth", "severity": "high",
                     "detail": "Admin page {}:{}{} returned 200 with no auth header".format(
                         device["ip"], h["port"], rec["path"])}
                )

    findings.extend(device.get("cred_findings", []))
    return findings


# --------------------------------------------------------------------------- #
# Per-device orchestration
# --------------------------------------------------------------------------- #


def scan_device(ip, args, use_nmap, limiter):
    device = {"ip": ip, "scanned_at": now_iso(), "ports": {}, "http": [],
              "upnp": {}, "dial": {}, "roku": {}, "rtsp": {}, "cred_findings": [],
              "cve_matches": [], "foothold_findings": []}

    log("\n[+] Scanning {}".format(ip), args.quiet)

    # --- ports ---
    if "ports" in args.modules:
        if use_nmap:
            device["ports"] = nmap_scan(ip, full=args.full, quiet=args.quiet)
        else:
            device["ports"] = python_scan(ip, full=args.full, quiet=args.quiet,
                                          limiter=limiter)
        for p, info in sorted(device["ports"].items()):
            log("    open {:>5}/tcp  {:<16} {} {}".format(
                p, info["service"], info.get("version", ""),
                ("| " + info["banner"]) if info.get("banner") else ""), args.quiet)

    open_ports = set(int(p) for p in device["ports"])

    # --- HTTP(S) ---
    if "http" in args.modules:
        http_ports = [(80, False), (8008, False), (8080, False), (3000, False),
                      (8060, False), (9000, False), (7000, False),
                      (443, True), (8443, True)]
        for port, tls in http_ports:
            if port in open_ports:
                info = enum_http(ip, port, tls, limiter, quiet=args.quiet)
                if info["paths"] or info["server"]:
                    device["http"].append(info)
                    log("    [http] {}:{} server='{}' title='{}' ({} paths)".format(
                        ip, port, info["server"], info["title"],
                        len(info["paths"])), args.quiet)

    # --- UPnP/SSDP (host-level, best-effort) ---
    if "upnp" in args.modules:
        responders = ssdp_discover(timeout=args.ssdp_timeout, quiet=args.quiet)
        if ip in responders:
            device["upnp"]["ssdp"] = responders[ip]
            for r in responders[ip]:
                if r.get("location"):
                    desc = fetch_upnp_descriptor(r["location"], quiet=args.quiet)
                    if desc:
                        device["upnp"].setdefault("descriptors", []).append(desc)
                        log("    [upnp] {} - {} / {}".format(
                            desc.get("friendlyName", ""),
                            desc.get("manufacturer", ""),
                            desc.get("modelName", "")), args.quiet)

    # --- DIAL / Roku / RTSP ---
    if "media" in args.modules:
        if 8008 in open_ports:
            device["dial"] = enum_dial(ip, quiet=args.quiet)
            if device["dial"]:
                log("    [dial] Chromecast/DIAL info retrieved", args.quiet)
        if 8060 in open_ports:
            device["roku"] = enum_roku(ip, quiet=args.quiet)
            if device["roku"]:
                log("    [roku] ECP device-info retrieved", args.quiet)
        if 554 in open_ports:
            device["rtsp"] = enum_rtsp(ip, quiet=args.quiet)
            if device["rtsp"].get("methods"):
                log("    [rtsp] methods: {}".format(
                    device["rtsp"]["methods"]), args.quiet)
        if 5555 in open_ports:
            log("    [adb] 5555 open - Android TV ADB likely. Manual test only: "
                "'adb connect {}:5555'. Not auto-connecting.".format(ip),
                args.quiet)

    # --- OPT-IN default credential check ---
    if args.try_creds:
        for port, tls in [(80, False), (8080, False), (443, True), (8443, True)]:
            if port in open_ports:
                log("    [creds] OPT-IN default-cred check on {}:{} (limited)".format(
                    ip, port), args.quiet)
                device["cred_findings"].extend(
                    try_default_creds(ip, port, tls, limiter, quiet=args.quiet))

    # --- CVE matching (offline DB; optional online NVD enrichment) ---
    if "cve" in args.modules:
        cve_entries = getattr(args, "_cve_entries", None)
        if cve_entries is None:
            cve_entries = load_cve_db(args.cve_db, quiet=args.quiet)
            args._cve_entries = cve_entries
        device["cve_matches"] = match_cves(device, cve_entries, quiet=args.quiet)
        if args.nvd_online:
            fp = collect_fingerprints(device)
            kw = next((s for s in (fp["model"] + fp["manufacturer"] +
                                   fp["server"]) if s), None)
            if kw:
                device["nvd_online"] = nvd_online_lookup(kw, quiet=args.quiet)

    # --- ADB foothold confirmation (opt-in intrusive) ---
    if "adb" in args.modules and 5555 in open_ports:
        if args.confirm_footholds:
            log("    [adb] --confirm-footholds set: confirming shell access "
                "(harmless read-only commands only)", args.quiet)
            device["foothold_findings"].append(
                confirm_adb_foothold(ip, quiet=args.quiet))
        else:
            log("    [adb] 5555 open - add --confirm-footholds to safely confirm "
                "the shell. Not connecting without it.", args.quiet)

    # --- Web-UI vulnerability probes (opt-in intrusive) ---
    if "webvuln" in args.modules:
        if args.confirm_footholds:
            device["foothold_findings"].extend(
                run_webvuln(ip, open_ports, device.get("cve_matches", []),
                            limiter, quiet=args.quiet))
        else:
            log("    [webvuln] add --confirm-footholds to run the read-only / "
                "detection-only web probes. Skipping.", args.quiet)

    device["findings"] = synthesize_findings(device)
    device["findings"].extend(device.get("foothold_findings", []))
    # Botnet-exposure audit (reporting only) must run before the assessment so
    # the likely-attack-vector verdict can factor in its vectors.
    device["botnet_exposure"] = botnet_exposure_audit(device)
    device["assessment"] = build_assessment(device)
    return device


# --------------------------------------------------------------------------- #
# Banner / authorization gate
# --------------------------------------------------------------------------- #

BANNER = r"""
  _       _                         
 (_) ___ | |_ ___  ___ __ _ _ __    
 | |/ _ \| __/ __|/ __/ _` | '_ \   
 | | (_) | |_\__ \ (_| (_| | | | |  
 |_|\___/ \__|___/\___\__,_|_| |_|   v{ver}

 IoT recon / light enumeration - AUTHORIZED TESTING ONLY
 Use only on devices you own or have explicit written permission to test.
 This tool enumerates passively by default. Intrusive confirmation (default-cred
 check, ADB shell confirmation, web-UI probes) is OPT-IN behind explicit flags.
""".format(ver=VERSION)


def authorization_gate(args):
    print(BANNER)
    if args.i_have_authorization:
        print("[auth] --i-have-authorization supplied. Proceeding.\n")
        return True
    try:
        ans = input("Do you have authorization to test these targets? (yes/no): ")
    except EOFError:
        print("[auth] No TTY and no --i-have-authorization flag. Aborting.")
        return False
    if ans.strip().lower() in ("y", "yes"):
        return True
    print("[auth] Authorization not confirmed. Aborting.")
    return False


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #



# --------------------------------------------------------------------------- #
# Bluetooth / BLE modules
#
# These operate on the LOCAL host's Bluetooth adapter (bluez), not a remote
# IP target. They shell out to bluetoothctl / hcitool / gatttool and degrade
# gracefully (reporting "tool/adapter required") when bluez or an adapter is
# absent. Read-only by default; GATT writes are never performed unless the
# explicit --gatt-write flag is given, which carries its own warning.
# --------------------------------------------------------------------------- #

# Small, partial, extensible OUI -> vendor table for common IoT/BT makers.
# (First 3 MAC octets, upper-case, colon-separated.)
OUI_VENDORS = {
    "00:1A:7D": "Samsung", "5C:F3:70": "Samsung", "FC:A1:3E": "Samsung",
    "D8:78:78": "Ubee", "78:F2:35": "Sichuan AI-Link",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "00:0D:4B": "Roku", "CC:6D:A0": "Roku",
    "F4:F5:D8": "Google", "54:60:09": "Google", "1C:F2:9A": "Google",
    "00:17:88": "Philips Hue", "EC:B5:FA": "Philips Hue",
    "AC:BC:32": "Apple", "A4:83:E7": "Apple", "DC:2B:2A": "Apple",
    "00:12:4B": "Texas Instruments", "00:07:80": "Wi-Fi/BLE module",
    "D0:03:4B": "Apple", "18:B4:30": "Nest",
    "EC:FA:BC": "Espressif", "24:0A:C4": "Espressif", "A0:20:A6": "Espressif",
    "00:1B:DC": "Vencer/Camera", "B0:C5:54": "D-Link/Camera",
}


def oui_vendor(mac):
    """Best-effort vendor from the MAC OUI prefix."""
    if not mac or len(mac) < 8:
        return None
    return OUI_VENDORS.get(mac.upper()[:8])


def _which(binary):
    try:
        subprocess.run([binary, "--version"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def have_bluez():
    """Return dict of which bluez tools are present."""
    import shutil
    return {
        "bluetoothctl": shutil.which("bluetoothctl") is not None,
        "hcitool": shutil.which("hcitool") is not None,
        "gatttool": shutil.which("gatttool") is not None,
        "hciconfig": shutil.which("hciconfig") is not None,
    }


def bt_adapter_present():
    """True if at least one HCI adapter is up/known."""
    import shutil
    if shutil.which("hciconfig"):
        try:
            out = subprocess.run(["hciconfig"], capture_output=True, text=True,
                                 timeout=8).stdout
            return "hci" in out
        except (OSError, subprocess.SubprocessError):
            return False
    # bluetoothctl list as a fallback
    if shutil.which("bluetoothctl"):
        try:
            out = subprocess.run(["bluetoothctl", "list"], capture_output=True,
                                 text=True, timeout=8).stdout
            return "Controller" in out
        except (OSError, subprocess.SubprocessError):
            return False
    return False


def assess_ble_pairing(dev):
    """
    DESCRIPTIVE pairing/bonding-security assessment for a discovered BT/BLE
    device. We do NOT pair-then-manipulate; this only characterises posture
    from what is observable (advertisement + optional read-only connect result)
    and explains the associated risk. Returns {posture, note}.
    """
    pairing = dev.get("pairing")
    if pairing == "just_works":
        return {"posture": "just_works",
                "note": ("'Just Works' pairing (no PIN/passkey): the device "
                         "accepts unauthenticated bonds. A host it then 'trusts' "
                         "may reach control characteristics post-pairing - "
                         "reported as risk, not exercised.")}
    if pairing in ("pin", "passkey"):
        return {"posture": pairing,
                "note": "PIN/passkey pairing observed - stronger bonding posture."}
    if dev.get("unauth_connect_allowed"):
        return {"posture": "unauthenticated_connect",
                "note": ("Accepted a read-only connect without authentication; a "
                         "device that trusts an unauthenticated bond could expose "
                         "control characteristics post-pairing.")}
    return {"posture": "unknown",
            "note": ("Pairing/bonding posture not determinable from "
                     "advertisements alone. If it accepts an unauthenticated "
                     "connection, control characteristics could be reachable "
                     "post-pairing - use --gatt (with --confirm-footholds) for a "
                     "read-only connect test.")}


def _classify_bt(dev):
    """Produce severity-tagged findings for a discovered BT/BLE device,
    including a descriptive pairing-security note (reporting only)."""
    findings = []
    name = (dev.get("name") or "").strip()
    if dev.get("discoverable"):
        findings.append({"severity": "low",
                         "detail": "Device is discoverable/connectable: {}".format(
                             dev.get("mac"))})
    pa = assess_ble_pairing(dev)
    dev["pairing_posture"] = pa["posture"]
    if pa["posture"] == "just_works":
        findings.append({"severity": "medium",
                         "detail": "{} {}".format(dev.get("mac"), pa["note"])})
    elif pa["posture"] == "unauthenticated_connect":
        findings.append({"severity": "medium",
                         "detail": "{} {}".format(dev.get("mac"), pa["note"])})
    else:
        findings.append({"severity": "info",
                         "detail": "{} {}".format(dev.get("mac"), pa["note"])})
    return findings


def bt_scan_classic(duration=10, quiet=False):
    """Discover classic Bluetooth devices via hcitool scan (or bluetoothctl)."""
    import shutil
    result = {"type": "bt-classic", "devices": [], "error": None}
    if not bt_adapter_present():
        result["error"] = "no Bluetooth adapter found (bluez + local radio required)"
        log("    [!] {}".format(result["error"]), quiet)
        return result
    if shutil.which("hcitool"):
        try:
            out = subprocess.run(["hcitool", "scan", "--length={}".format(duration)],
                                 capture_output=True, text=True, timeout=duration + 15).stdout
        except (OSError, subprocess.SubprocessError) as e:
            result["error"] = "hcitool scan failed: {}".format(e)
            return result
        for line in out.splitlines():
            line = line.strip()
            parts = line.split("\t")
            if len(parts) >= 1 and ":" in parts[0] and len(parts[0]) == 17:
                mac = parts[0]
                name = parts[1] if len(parts) > 1 else ""
                dev = {"mac": mac, "name": name, "vendor": oui_vendor(mac),
                       "discoverable": True}
                dev["findings"] = _classify_bt(dev)
                result["devices"].append(dev)
    else:
        result["error"] = "hcitool not found (install bluez)"
    log("    [+] classic BT devices: {}".format(len(result["devices"])), quiet)
    return result


def ble_scan(duration=10, quiet=False):
    """Scan for BLE advertisements via bluetoothctl (preferred) or hcitool lescan."""
    import shutil
    result = {"type": "ble", "devices": [], "error": None}
    if not bt_adapter_present():
        result["error"] = "no Bluetooth adapter found (bluez + local radio required)"
        log("    [!] {}".format(result["error"]), quiet)
        return result
    devices = {}
    if shutil.which("bluetoothctl"):
        try:
            # scan on for `duration`, then list devices
            proc = subprocess.Popen(["bluetoothctl"], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    text=True)
            cmds = "power on\nscan on\n"
            proc.stdin.write(cmds)
            proc.stdin.flush()
            time.sleep(duration)
            proc.stdin.write("scan off\ndevices\nquit\n")
            proc.stdin.flush()
            out, _ = proc.communicate(timeout=duration + 15)
        except (OSError, subprocess.SubprocessError) as e:
            result["error"] = "bluetoothctl scan failed: {}".format(e)
            return result
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Device ") or "] Device " in line:
                # formats: "Device AA:BB.. Name" or "[NEW] Device AA:BB.. Name"
                idx = line.find("Device ")
                rest = line[idx + 7:].strip()
                bits = rest.split(" ", 1)
                mac = bits[0]
                name = bits[1] if len(bits) > 1 else ""
                if len(mac) == 17 and ":" in mac:
                    devices[mac] = name
    elif shutil.which("hcitool"):
        try:
            out = subprocess.run(["hcitool", "lescan", "--duplicates"],
                                 capture_output=True, text=True, timeout=duration + 10).stdout
        except (OSError, subprocess.SubprocessError) as e:
            result["error"] = ("hcitool lescan failed (needs sudo/CAP_NET_ADMIN): {}"
                               .format(e))
            return result
        for line in out.splitlines():
            line = line.strip()
            bits = line.split(" ", 1)
            if bits and len(bits[0]) == 17 and ":" in bits[0]:
                devices[bits[0]] = bits[1] if len(bits) > 1 else ""
    else:
        result["error"] = "neither bluetoothctl nor hcitool found (install bluez)"
        return result

    for mac, name in devices.items():
        dev = {"mac": mac, "name": name, "vendor": oui_vendor(mac),
               "discoverable": True}
        dev["findings"] = _classify_bt(dev)
        result["devices"].append(dev)
    log("    [+] BLE devices: {}".format(len(result["devices"])), quiet)
    return result


def gatt_enumerate(mac, allow_write=False, quiet=False):
    """Read-only GATT service/characteristic enumeration for a BLE MAC.

    Intrusive (connects to the device), so the CLI gates this behind
    --confirm-footholds. Writing is NEVER done unless allow_write is set.
    """
    import shutil
    result = {"type": "gatt", "mac": mac, "services": [], "characteristics": [],
              "error": None}
    if not shutil.which("gatttool"):
        result["error"] = "gatttool not found (install bluez)"
        log("    [!] {}".format(result["error"]), quiet)
        return result
    if not bt_adapter_present():
        result["error"] = "no Bluetooth adapter found"
        return result
    try:
        prim = subprocess.run(["gatttool", "-b", mac, "--primary"],
                              capture_output=True, text=True, timeout=25)
        for line in prim.stdout.splitlines():
            if "uuid:" in line:
                result["services"].append(line.strip())
        chars = subprocess.run(["gatttool", "-b", mac, "--characteristics"],
                               capture_output=True, text=True, timeout=25)
        for line in chars.stdout.splitlines():
            if "uuid:" in line:
                result["characteristics"].append(line.strip())
    except (OSError, subprocess.SubprocessError) as e:
        result["error"] = "gatttool enumeration failed: {}".format(e)
        return result
    # Pairing-security observation (reporting only): did an unpaired, read-only
    # connect succeed? That characterises bonding posture; we never pair-then-write.
    connected = bool(result["services"] or result["characteristics"])
    result["unauthenticated_connect_allowed"] = connected and not result["error"]
    if result["unauthenticated_connect_allowed"]:
        result["pairing_finding"] = {
            "severity": "medium",
            "detail": ("{} allowed a read-only GATT connect/enumerate WITHOUT "
                       "pairing/authentication - control characteristics may be "
                       "reachable post-pairing to a trusted host. Reported as "
                       "risk; no writes performed.").format(mac)}
    else:
        result["pairing_finding"] = {
            "severity": "info",
            "detail": ("{} refused/failed an unauthenticated GATT connect - it "
                       "does not expose services to an unpaired host.").format(mac)}
    if allow_write:
        log("    [!] --gatt-write given: writing to characteristics is intrusive "
            "and may alter device state. (Not auto-performed; use gatttool "
            "--char-write-req manually on a characteristic you understand.)", quiet)
    log("    [+] GATT: {} services, {} characteristics (unauth connect: {})".format(
        len(result["services"]), len(result["characteristics"]),
        result["unauthenticated_connect_allowed"]), quiet)
    return result


def run_bluetooth_mode(args):
    """Handle --bt-scan / --ble-scan / --gatt. Returns a report dict."""
    report = {
        "tool": "iotscan",
        "version": VERSION,
        "started": now_iso(),
        "mode": "bluetooth",
        "bluetooth": {},
    }
    tools = have_bluez()
    log("[*] bluez tools: {}".format(
        ", ".join(k for k, v in tools.items() if v) or "none found"), args.quiet)

    if args.bt_scan:
        report["bluetooth"]["classic"] = bt_scan_classic(
            duration=args.bt_duration, quiet=args.quiet)
    if args.ble_scan:
        report["bluetooth"]["ble"] = ble_scan(
            duration=args.bt_duration, quiet=args.quiet)
    if args.gatt:
        report["bluetooth"]["gatt"] = gatt_enumerate(
            args.gatt, allow_write=args.gatt_write, quiet=args.quiet)

    report["finished"] = now_iso()

    # Console summary
    print("\n" + "=" * 64)
    print("BLUETOOTH SUMMARY")
    print("=" * 64)
    for section in ("classic", "ble"):
        data = report["bluetooth"].get(section)
        if not data:
            continue
        print("\n{} scan:".format(section.upper()))
        if data.get("error"):
            print("  [!] {}".format(data["error"]))
            continue
        if not data["devices"]:
            print("  (no devices found)")
        for dev in data["devices"]:
            vend = " [{}]".format(dev["vendor"]) if dev.get("vendor") else ""
            print("  {}  {}{}".format(dev["mac"], dev.get("name") or "(no name)", vend))
            for f in dev.get("findings", []):
                print("     [{:^6}] {}".format(f["severity"].upper(), f["detail"]))
    g = report["bluetooth"].get("gatt")
    if g:
        print("\nGATT ({}):".format(g["mac"]))
        if g.get("error"):
            print("  [!] {}".format(g["error"]))
        else:
            print("  services: {}, characteristics: {}".format(
                len(g["services"]), len(g["characteristics"])))
            pf = g.get("pairing_finding")
            if pf:
                print("     [{:^6}] {}".format(
                    pf["severity"].upper(), pf["detail"]))
            for c in g["characteristics"]:
                print("     {}".format(c))

    with open(args.output, "w") as fh:
        json.dump(report, fh, indent=2)
    print("\n[*] JSON report written to {}".format(args.output))
    return 0



def main(argv=None):
    parser = argparse.ArgumentParser(
        description="General-purpose IoT device security recon tool "
                    "(authorized testing only).",
        epilog="Example: python3 iotscan.py 192.168.1.50 --modules ports,http,upnp,media -o report.json",
    )
    parser.add_argument("target", nargs="?",
                        help="Target IP, CIDR (192.168.1.0/24), or range (192.168.1.10-20)")
    parser.add_argument("--modules", default="ports,http,upnp,media,cve",
                        help="Comma list: ports,http,upnp,media,cve,adb,webvuln "
                             "(default: ports,http,upnp,media,cve). adb & webvuln "
                             "also need --confirm-footholds.")
    parser.add_argument("--full", action="store_true",
                        help="Full TCP port range scan (slow). Default: IoT port list.")
    parser.add_argument("--try-creds", action="store_true",
                        help="OPT-IN: test a few documented DEFAULT creds (intrusive).")
    parser.add_argument("--confirm-footholds", action="store_true",
                        help="OPT-IN INTRUSIVE: let the adb & webvuln modules "
                             "actively (but non-destructively) CONFIRM footholds. "
                             "Requires --i-have-authorization.")
    parser.add_argument("--cve-db", default=None,
                        help="Path to the offline CVE knowledge base "
                             "(default: cve_db.json next to this script).")
    parser.add_argument("--nvd-online", action="store_true",
                        help="OPT-IN: also query the public NVD API online for "
                             "extra CVE context (off by default; DB is offline).")
    parser.add_argument("--i-have-authorization", action="store_true",
                        help="Skip the interactive authorization prompt.")
    parser.add_argument("--rate", type=float, default=0.0,
                        help="Minimum seconds between probes (politeness rate limit).")
    parser.add_argument("--ssdp-timeout", type=float, default=3.0,
                        help="Seconds to listen for SSDP responders (default 3).")
    parser.add_argument("-o", "--output", default="iotscan_report.json",
                        help="JSON report output path (default: iotscan_report.json)")
    parser.add_argument("--no-nmap", action="store_true",
                        help="Force pure-Python scan even if nmap is installed.")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Reduce console output.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Validate config and target expansion, then exit.")
    parser.add_argument("--bt-scan", action="store_true",
                        help="Scan for nearby classic Bluetooth devices (local adapter).")
    parser.add_argument("--ble-scan", action="store_true",
                        help="Scan for nearby BLE advertisements (local adapter).")
    parser.add_argument("--gatt", default=None, metavar="MAC",
                        help="Enumerate GATT services/characteristics of a BLE device "
                             "(intrusive; requires --confirm-footholds).")
    parser.add_argument("--gatt-write", action="store_true",
                        help="Acknowledge GATT writes are intrusive (writes still not auto-performed).")
    parser.add_argument("--bt-duration", type=int, default=10,
                        help="Seconds to scan for BT/BLE devices (default 10).")
    args = parser.parse_args(argv)

    _bt_mode = args.bt_scan or args.ble_scan or bool(args.gatt)
    if not args.target and not _bt_mode:
        parser.print_help()
        return 1

    args.modules = [m.strip() for m in args.modules.split(",") if m.strip()]

    # Bluetooth modes run off the local adapter and take no IP target.
    bt_mode = args.bt_scan or args.ble_scan or bool(args.gatt)
    if bt_mode:
        if args.gatt and not args.confirm_footholds:
            print('[!] --gatt is intrusive (connects to the device) and requires '
                  '--confirm-footholds. Aborting.')
            return 4
        if args.confirm_footholds and not args.i_have_authorization:
            print('[!] --confirm-footholds requires --i-have-authorization. Aborting.')
            return 4
        if args.dry_run:
            print(BANNER)
            print('[dry-run] bluetooth mode: bt-scan={} ble-scan={} gatt={}'.format(
                args.bt_scan, args.ble_scan, args.gatt))
            print('[dry-run] bluez tools  : {}'.format(have_bluez()))
            print('[dry-run] adapter      : {}'.format(bt_adapter_present()))
            print('[dry-run] OK - no scan performed.')
            return 0
        if not authorization_gate(args):
            return 3
        return run_bluetooth_mode(args)

    try:
        targets = expand_targets(args.target)
    except Exception as e:
        print("[!] Could not parse target '{}': {}".format(args.target, e))
        return 2

    if args.dry_run:
        print(BANNER)
        print("[dry-run] modules      : {}".format(args.modules))
        print("[dry-run] targets ({:d}) : {}".format(
            len(targets), ", ".join(targets[:10]) + (" ..." if len(targets) > 10 else "")))
        print("[dry-run] nmap present : {}".format(have_nmap()))
        print("[dry-run] try-creds    : {}".format(args.try_creds))
        print("[dry-run] confirm-footholds: {}".format(args.confirm_footholds))
        print("[dry-run] cve-db       : {}".format(args.cve_db or "(default) cve_db.json"))
        print("[dry-run] nvd-online   : {}".format(args.nvd_online))
        print("[dry-run] adb present  : {}".format(have_adb()))
        print("[dry-run] output       : {}".format(args.output))
        print("[dry-run] OK - no packets sent.")
        return 0

    if args.confirm_footholds and not args.i_have_authorization:
        # Intrusive confirmation must never run on an un-affirmed target.
        print("[!] --confirm-footholds is intrusive and requires "
              "--i-have-authorization. Aborting.")
        return 4

    if not authorization_gate(args):
        return 3

    use_nmap = have_nmap() and not args.no_nmap
    log("[*] Port scanner: {}".format("nmap" if use_nmap else "pure-python fallback"),
        args.quiet)

    limiter = RateLimiter(args.rate)
    report = {
        "tool": "iotscan",
        "version": VERSION,
        "started": now_iso(),
        "target_spec": args.target,
        "modules": args.modules,
        "devices": [],
    }

    for ip in targets:
        try:
            device = scan_device(ip, args, use_nmap, limiter)
            report["devices"].append(device)
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user.")
            break
        except Exception as e:
            log("    [!] error scanning {}: {}".format(ip, e), args.quiet)

    report["finished"] = now_iso()

    # Console summary
    print("\n" + "=" * 64)
    print("SUMMARY")
    print("=" * 64)
    for d in report["devices"]:
        openp = ", ".join(str(p) for p in sorted(int(x) for x in d["ports"]))
        print("\n{}  ({} open ports)".format(d["ip"], len(d["ports"])))
        if openp:
            print("  ports: {}".format(openp))
        for c in d.get("cve_matches", []):
            print("  [{:^8}] CVE {}: {}".format(
                c["severity"].upper(), c["cve"], c["description"][:90]))
        for f in d.get("findings", []):
            tag = f["severity"].upper()
            mark = " (CONFIRMED)" if f.get("confirmed") is True else ""
            print("  [{:^8}] {}{}".format(tag, f["detail"], mark))
        if not d.get("findings") and not d.get("cve_matches"):
            print("  (no notable findings)")
        a = d.get("assessment")
        if a:
            print("  --- assessment ---")
            print("    worst severity : {}".format(a["worst_severity"].upper()))
            if a["cve_matches"]:
                print("    matched CVEs   : {}".format(", ".join(a["cve_matches"])))
            if a["confirmed_footholds"]:
                print("    CONFIRMED      : {}".format(
                    ", ".join(a["confirmed_footholds"])))
            if a.get("botnet_recruitable"):
                print("    BOTNET EXPOSURE: {} [{}] via {}".format(
                    "recruitable", a.get("botnet_exposure_severity", "info").upper(),
                    ", ".join(a.get("botnet_vectors", []))))
            else:
                print("    botnet exposure: none detected")
            # The headline verdict: single most-likely way in.
            print("    >>> {}".format(a.get("attack_path_summary", "")))
            print("    next step      : {}".format(a["next_manual_step"]))

    with open(args.output, "w") as fh:
        json.dump(report, fh, indent=2)
    print("\n[*] JSON report written to {}".format(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
