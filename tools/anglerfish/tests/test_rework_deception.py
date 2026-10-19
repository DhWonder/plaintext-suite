"""Tests for the anglerfish deception rework, ported onto the live tree.

Adapted for the public example persona (no Northwind / eu-west-1) and for live's
Sensor(persona=False, ...) + sshcrypto stack. DNS/TLS/DSM/events only.
"""

import json
import os
import socket
import struct
import tempfile
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
import sys
sys.path.insert(0, os.path.dirname(HERE))

_EVENTS = tempfile.mktemp(suffix="-events.jsonl")
os.environ["ANGLERFISH_EVENTS_PATH"] = _EVENTS
if os.path.exists(_EVENTS):
    os.remove(_EVENTS)

from anglerfish import bait, dsm, events as events_module, sshproto
from anglerfish.sensor import Sensor
import anglerfish.sensor as sensor_module

sensor_module.AUTH_FAIL_DELAY = 0.05
sensor_module.AUTH_FAIL_DELAY_MIN = 0.05
sensor_module.AUTH_FAIL_DELAY_MAX = 0.05
sensor_module.AUTH_LOCK_SECONDS = 0.05
sensor_module.STATUS_WRITE_MIN_GAP = 0.0

PLANTED_USER, PLANTED_PASS = bait.PLANTED_LOGINS[0]
HOST = "files01.example.net"


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close()
    return p


def http_exchange(port, request):
    conn = socket.create_connection(("127.0.0.1", port), timeout=5)
    conn.sendall(request)
    conn.settimeout(2)
    data = b""
    while True:
        try:
            chunk = conn.recv(8192)
        except socket.timeout:
            break
        except (ConnectionResetError, OSError):
            break
        if not chunk:
            break
        data += chunk
    try:
        conn.close()
    except OSError:
        pass
    return data


def check(name, ok):
    print("  %-62s %s" % (name, "ok" if ok else "FAILED"))
    return ok


def load_events():
    if not os.path.exists(_EVENTS):
        return []
    out = []
    with open(_EVENTS, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def make_sensor(**kwargs):
    kwargs.setdefault("persona", False)
    kwargs.setdefault("classroom", True)
    kwargs.setdefault("bind", "127.0.0.1")
    return Sensor(**kwargs)


def main():
    failures = 0
    if os.path.exists(_EVENTS):
        os.remove(_EVENTS)

    # --- unit: DSM helpers ---
    world, _ = bait.build()
    info = dsm.api_info_response("all")
    failures += not check("SYNO.API.Info returns success+catalog",
                          info.get("success") is True
                          and "SYNO.API.Auth" in info.get("data", {}))
    bad = dsm.auth_login_response(False)
    failures += not check("SYNO.API.Auth bad creds -> error 400",
                          bad.get("success") is False
                          and bad.get("error", {}).get("code") == 400)
    html = dsm.login_page_html(world, session_id="DEADBEEF")
    failures += not check("login SPA references JS assets + session",
                          "/webman/login.js" in html
                          and "Sign in" in html
                          and "DEADBEEF" in html
                          and "Example NAS" in html)
    failures += not check("login page has no Northwind",
                          "Northwind" not in html and "northwind" not in html.lower())
    failures += not check("login page not byte-identical across calls",
                          dsm.login_page_html(world) != dsm.login_page_html(world))
    sysinfo = dsm.system_info(world)
    failures += not check("DSM system_info timezone is UTC (live region)",
                          sysinfo["data"]["time_zone"] == "UTC")

    # --- SSH KEX list fingerprint (live sshcrypto advertisement) ---
    blob = sshproto._build_kexinit()
    for must in (b"curve25519-sha256", b"ssh-ed25519",
                 b"chacha20-poly1305@openssh.com",
                 b"hmac-sha2-256-etm@openssh.com"):
        failures += not check("KEXINIT advertises %s" % must.decode(),
                              must in blob)
    sshproto.crypto_self_test()
    failures += not check("crypto_self_test (live sshcrypto)", True)

    # --- live sensor ---
    port = free_port()
    sensor_module.SERVICE_BY_PORT[port] = "http"
    sensor = make_sensor(name="rework", ports=[port],
                         log_path=tempfile.mktemp(suffix=".log"),
                         status_path=tempfile.mktemp(suffix=".json"))
    sensor.start()
    time.sleep(0.2)

    page = http_exchange(
        port,
        ("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % HOST).encode())
    failures += not check("GET / issues Set-Cookie id= (DSM session)",
                          page.startswith(b"HTTP/1.1 200")
                          and b"Set-Cookie: id=" in page
                          and b"Set-Cookie: nas_session=" in page
                          and b"Sign in" in page
                          and b"Example NAS" in page)
    failures += not check("GET / login references JS (SPA shell)",
                          b"/webman/login.js" in page)
    failures += not check("GET / has no Northwind",
                          b"Northwind" not in page)

    info_page = http_exchange(
        port,
        ("GET /webapi/query.cgi?api=SYNO.API.Info&query=all HTTP/1.1\r\n"
         "Host: %s\r\nConnection: close\r\n\r\n" % HOST).encode())
    body = info_page.split(b"\r\n\r\n", 1)[-1]
    try:
        info_json = json.loads(body)
    except Exception:
        info_json = {}
    failures += not check("query.cgi?api=SYNO.API.Info returns catalog JSON",
                          info_page.startswith(b"HTTP/1.1 200")
                          and info_json.get("success") is True
                          and "SYNO.API.Auth" in (info_json.get("data") or {}))

    auth_bad = http_exchange(
        port,
        ("GET /webapi/auth.cgi?api=SYNO.API.Auth&method=login"
         "&account=admin&passwd=wrong HTTP/1.1\r\n"
         "Host: %s\r\nConnection: close\r\n\r\n" % HOST).encode())
    auth_body = json.loads(auth_bad.split(b"\r\n\r\n", 1)[-1] or b"{}")
    failures += not check("auth.cgi bad creds -> DSM error 400 JSON",
                          auth_body.get("success") is False
                          and auth_body.get("error", {}).get("code") == 400)

    auth_ok = http_exchange(
        port,
        ("GET /webapi/auth.cgi?api=SYNO.API.Auth&method=login"
         "&account=%s&passwd=%s HTTP/1.1\r\n"
         "Host: %s\r\nConnection: close\r\n\r\n" % (
             PLANTED_USER, PLANTED_PASS, HOST)).encode())
    auth_ok_body = json.loads(auth_ok.split(b"\r\n\r\n", 1)[-1] or b"{}")
    failures += not check("auth.cgi planted creds -> sid+synotoken",
                          auth_ok_body.get("success") is True
                          and "sid" in (auth_ok_body.get("data") or {})
                          and b"Set-Cookie: id=" in auth_ok)

    long_path = "/" + ("A" * 9000)
    r414 = http_exchange(
        port,
        ("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
         % (long_path, HOST)).encode())
    failures += not check("9000-char URI returns 414 like nginx",
                          r414.startswith(b"HTTP/1.1 414")
                          and b"Request-URI Too Large" in r414)

    default = http_exchange(
        port,
        b"GET / HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n")
    failures += not check("unknown Host gets nginx default-server page",
                          b"Welcome to nginx!" in default
                          and b"Sign in" not in default)

    cookie = ""
    for line in auth_ok.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:") and b"nas_session=" in line:
            cookie = line.split(b"nas_session=", 1)[1].split(b";", 1)[0].decode()
            break
    if not cookie:
        posted = ("username=%s&password=%s" % (PLANTED_USER, PLANTED_PASS)).encode()
        panel = http_exchange(
            port,
            (("POST / HTTP/1.1\r\nHost: %s\r\n"
              "Content-Type: application/x-www-form-urlencoded\r\n"
              "Content-Length: %d\r\nConnection: close\r\n\r\n") % (
                 HOST, len(posted))).encode() + posted)
        for line in panel.split(b"\r\n"):
            if line.lower().startswith(b"set-cookie:") and b"nas_session=" in line:
                cookie = line.split(b"nas_session=", 1)[1].split(b";", 1)[0].decode()
                break
    dl = http_exchange(
        port,
        ("GET /files/Deploy/docker-compose.yml HTTP/1.1\r\nHost: %s\r\n"
         "Cookie: nas_session=%s\r\nConnection: close\r\n\r\n" % (
             HOST, cookie)).encode())
    failures += not check("authed session can download bait file",
                          cookie and dl.startswith(b"HTTP/1.1 200")
                          and PLANTED_PASS.encode() in dl)

    # Live realism: anonymous /api/status stays gated
    status = http_exchange(
        port,
        ("GET /api/status HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
         % HOST).encode())
    failures += not check("anonymous /api/status still 401 (live realism)",
                          status.startswith(b"HTTP/1.1 401"))

    sensor.stop()
    time.sleep(0.2)

    # --- DNS facade ---
    dport = free_port()
    sensor_module.SERVICE_BY_PORT[dport] = "dns"
    dsensor = make_sensor(name="dns", ports=[dport],
                          log_path=tempfile.mktemp(suffix=".log"),
                          status_path=tempfile.mktemp(suffix=".json"))
    dsensor.start()
    time.sleep(0.2)

    def dns_query(qname, qtype, qclass=1):
        tid = b"\x12\x34"
        flags = b"\x01\x00"
        counts = struct.pack("!HHHH", 1, 0, 0, 0)
        name = b""
        for label in qname.split("."):
            raw = label.encode()
            name += bytes([len(raw)]) + raw
        name += b"\x00"
        return tid + flags + counts + name + struct.pack("!HH", qtype, qclass)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    sock.sendto(dns_query("version.bind", 16, 3), ("127.0.0.1", dport))
    try:
        resp, _ = sock.recvfrom(4096)
        dns_ok = len(resp) > 12 and b"dnsmasq" in resp
    except socket.timeout:
        resp = b""; dns_ok = False
    sock.close()
    failures += not check("DNS version.bind returns dnsmasq-looking TXT", dns_ok)
    dsensor.stop()

    evs = load_events()
    failures += not check("events.jsonl has entries", len(evs) >= 3)
    kinds = {e.get("event") for e in evs}
    failures += not check("events include http/syno_api/auth/dns",
                          "http" in kinds or "syno_api" in kinds)
    failures += not check("syno_api event carries syno_api field",
                          any(e.get("syno_api") == "SYNO.API.Info" for e in evs))
    failures += not check("auth_ok=true emitted for planted login",
                          any(e.get("event") == "auth" and e.get("auth_ok") is True
                              for e in evs))
    failures += not check("path_read emitted for bait download",
                          any(e.get("event") == "path_read"
                              and "docker-compose" in (e.get("path_read") or "")
                              for e in evs))
    failures += not check("first_bytes_len / uri_len present on long URI",
                          any(e.get("http_status") == 414 and e.get("uri_len", 0) > 8000
                              for e in evs))
    failures += not check("dns event has dns_qname",
                          any(e.get("event") == "dns"
                              and "version.bind" in (e.get("dns_qname") or "")
                              for e in evs))

    sample = next((e for e in evs if e.get("event") in ("http", "syno_api", "auth")), {})
    for key in ("ts", "schema_version", "sensor", "event", "service",
                "src_ip", "session_id"):
        failures += not check("event has core field %s" % key, key in sample)

    # Persona TLS paths (live): no tlsutil self-generated cert on this branch.
    failures += not check("no tlsutil module (use live persona cert)",
                          not os.path.exists(os.path.join(
                              os.path.dirname(HERE), "anglerfish", "tlsutil.py")))

    print()
    if failures:
        print("%d rework check(s) failed." % failures)
        return 1
    print("All rework checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
