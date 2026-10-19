"""Tests for stdlib-only TLS fingerprinting (JA3 / JA3S / SNI / ALPN)."""

import hashlib
import json
import os
import random
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

_TMP = tempfile.mkdtemp(prefix="anglerfish-tls-")
_EVENTS = os.path.join(_TMP, "events.jsonl")
os.environ["ANGLERFISH_EVENTS_PATH"] = _EVENTS

from anglerfish import tlsfp
from anglerfish.sensor import Sensor
import anglerfish.sensor as sensor_module

# Documented JA3 test vector (salesforce/ja3 README):
#   769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
#   -> ada70206e40642a3e4461f35503241d5
JA3_VECTOR_STR = "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
JA3_VECTOR_MD5 = "ada70206e40642a3e4461f35503241d5"
VECTOR_CIPHERS = [47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4]


def _ext(etype, body):
    return struct.pack("!HH", etype, len(body)) + body


def build_client_hello(version=0x0301, ciphers=VECTOR_CIPHERS, sni="files01.example.net",
                       groups=(23, 24, 25), point_formats=(0,), alpn=None,
                       grease=False, record_split=None):
    """Hand-build a ClientHello record (optionally with GREASE / ALPN)."""
    ciphers = list(ciphers)
    groups = list(groups)
    exts = []
    if grease:
        ciphers = [0x0A0A] + ciphers + [0xFAFA]
        groups = [0x2A2A] + groups
        exts.append(_ext(0x1A1A, b""))
    name = sni.encode()
    exts.append(_ext(0, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name))
    g = b"".join(struct.pack("!H", x) for x in groups)
    exts.append(_ext(10, struct.pack("!H", len(g)) + g))
    pf = bytes(point_formats)
    exts.append(_ext(11, struct.pack("!B", len(pf)) + pf))
    if alpn:
        lst = b"".join(struct.pack("!B", len(p)) + p.encode() for p in alpn)
        exts.append(_ext(16, struct.pack("!H", len(lst)) + lst))
    if grease:
        exts.append(_ext(0xBABA, b"\x00"))
    ext_block = b"".join(exts)
    cs = b"".join(struct.pack("!H", c) for c in ciphers)
    body = (struct.pack("!H", version) + bytes(range(32)) + b"\x00"
            + struct.pack("!H", len(cs)) + cs + b"\x01\x00"
            + struct.pack("!H", len(ext_block)) + ext_block)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    if record_split:
        a, b = hs[:record_split], hs[record_split:]
        return (b"\x16\x03\x01" + struct.pack("!H", len(a)) + a
                + b"\x16\x03\x01" + struct.pack("!H", len(b)) + b)
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def check(name, ok):
    print("  [%s] %s" % ("ok" if ok else "FAIL", name))
    return bool(ok)


def main():
    failures = 0
    print("TLS fingerprint checks")

    # --- documented JA3 vector ---
    failures += not check("md5(vector string) == documented hash",
                          hashlib.md5(JA3_VECTOR_STR.encode()).hexdigest() == JA3_VECTOR_MD5)
    hello = build_client_hello()
    info = tlsfp.parse_client_hello(hello)
    failures += not check("ClientHello parses", info is not None)
    info = info or {}
    failures += not check("SNI parsed", info.get("sni") == "files01.example.net")
    failures += not check("cipher list parsed", info.get("ciphers") == VECTOR_CIPHERS)
    failures += not check("client_version 769", info.get("client_version") == 769)
    failures += not check("JA3 string matches vector", info.get("ja3_str") == JA3_VECTOR_STR)
    failures += not check("JA3 md5 matches vector", info.get("ja3") == JA3_VECTOR_MD5)

    # --- GREASE stripping ---
    g = tlsfp.parse_client_hello(build_client_hello(grease=True)) or {}
    failures += not check("GREASE values present in raw cipher list",
                          0x0A0A in (g.get("ciphers") or []))
    failures += not check("GREASE stripped: JA3 unchanged", g.get("ja3") == JA3_VECTOR_MD5)
    failures += not check("all 16 GREASE values recognised",
                          len(tlsfp.GREASE) == 16 and all(tlsfp.is_grease(v) for v in
                          (0x0A0A, 0x1A1A, 0x2A2A, 0x7A7A, 0xFAFA))
                          and not tlsfp.is_grease(0x0A0B))

    # --- ALPN + multi-record ClientHello ---
    a = tlsfp.parse_client_hello(build_client_hello(alpn=["h2", "http/1.1"], record_split=40)) or {}
    failures += not check("ALPN parsed", a.get("alpn") == ["h2", "http/1.1"])
    failures += not check("ClientHello split across 2 records parses",
                          a.get("sni") == "files01.example.net" and 16 in a.get("extensions", []))

    # --- malformed input never raises ---
    rng = random.Random(1337)
    ok = True
    for i in range(len(hello)):
        try:
            if tlsfp.parse_client_hello(hello[:i]) is not None:
                ok = False
        except Exception:
            ok = False
    for _ in range(3000):
        m = bytearray(hello)
        for _ in range(rng.randint(1, 6)):
            m[rng.randrange(len(m))] = rng.randrange(256)
        try:
            tlsfp.parse_client_hello(bytes(m))
            tlsfp.find_server_hello(bytes(m))
        except Exception:
            ok = False
    for junk in (b"", b"GET / HTTP/1.1\r\n\r\n", b"\x16\x03\x01\xff\xff", os.urandom(4096),
                 b"\x16\x03\x01\x00\x04\x01\xff\xff\xff"):
        try:
            if tlsfp.parse_client_hello(junk) is not None:
                ok = False
        except Exception:
            ok = False
    failures += not check("truncated/mutated/junk input -> None, never raises", ok)

    # --- live sensor: MemoryBIO path end-to-end ---
    # Live uses the persona TLS cert under state_dir (no tlsutil). Mint a
    # short-lived self-signed cert into a temp state_dir for the test.
    import subprocess
    cert = os.path.join(_TMP, "tls-cert.pem")
    key = os.path.join(_TMP, "tls-key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "1",
         "-subj", "/O=Example Clinic/CN=files01.example.net"],
        check=True, capture_output=True, timeout=60)
    port = _free_port()
    sensor_module.SERVICE_BY_PORT[port] = "http"  # live maps 443/8443 as http+TLS
    # Force this test port into HTTPS_PORTS so the MemoryBIO path is used.
    sensor_module.HTTPS_PORTS = set(sensor_module.HTTPS_PORTS) | {port}
    sensor_module.TLS_PORTS = set(sensor_module.TLS_PORTS) | {port}
    sensor_module.AUTH_FAIL_DELAY_MIN = 0.05
    sensor_module.AUTH_FAIL_DELAY_MAX = 0.05
    sensor_module.STATUS_WRITE_MIN_GAP = 0.0
    sensor = Sensor(name="tls", ports=[port], persona=False, classroom=True,
                    state_dir=_TMP,
                    log_path=os.path.join(_TMP, "s.log"),
                    status_path=os.path.join(_TMP, "s.json"), bind="127.0.0.1")
    assert sensor._ssl_ctx is not None, "TLS context missing (cert not loaded)"
    sensor.start()
    time.sleep(0.3)

    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.check_hostname = False
    cctx.verify_mode = ssl.CERT_NONE
    cctx.set_alpn_protocols(["h2", "http/1.1"])
    for ver in (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_2):
        cctx.maximum_version = ver
        cctx.minimum_version = ver
        body = b""
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                with cctx.wrap_socket(raw, server_hostname="files01.example.net") as tls:
                    tls.sendall(b"GET / HTTP/1.1\r\nHost: files01.example.net\r\n\r\n")
                    tls.settimeout(3)
                    while b"</html>" not in body.lower():
                        chunk = tls.recv(8192)
                        if not chunk:
                            break
                        body += chunk
                    neg = tls.selected_alpn_protocol()
        except Exception as exc:
            print("  client error:", exc)
            neg = None
        failures += not check("%s: HTTP served over MemoryBIO TLS" % ver.name,
                              body.startswith(b"HTTP/1.1 200") or b"HTTP/1.1" in body[:20])
        failures += not check("%s: ALPN negotiated http/1.1" % ver.name, neg == "http/1.1")

    # plain HTTP on the TLS port -> fallback path, no crash, no ja3 fields
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            raw.sendall(b"GET / HTTP/1.1\r\n\r\n")
            raw.settimeout(3)
            try:
                raw.recv(100)
            except (socket.timeout, OSError):
                pass
    except OSError:
        pass
    # silent client that never sends a ClientHello must not block accept()
    idle = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with cctx.wrap_socket(raw, server_hostname="files01.example.net") as tls:
                tls.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                tls.settimeout(3)
                second_ok = tls.recv(16).startswith(b"HTTP/1.1")
    except Exception as exc:
        print("  second client error:", exc)
        second_ok = False
    idle.close()
    failures += not check("idle pre-handshake client does not block the listener", second_ok)
    time.sleep(0.5)
    sensor.stop()

    evs = []
    try:
        with open(_EVENTS) as fh:
            evs = [json.loads(l) for l in fh if l.strip()]
    except OSError:
        pass
    tls_ok = [e for e in evs if e.get("event") == "tls" and e.get("tls_handshake_ok")]
    for e in tls_ok[:2]:
        v = e.get("tls_version")
        failures += not check("%s event: tls_sni" % v, e.get("tls_sni") == "files01.example.net")
        failures += not check("%s event: tls_alpn" % v, e.get("tls_alpn") == ["h2", "http/1.1"])
        failures += not check("%s event: tls_ja3 is md5 of tls_ja3_str" % v,
                              e.get("tls_ja3") == hashlib.md5(
                                  (e.get("tls_ja3_str") or "x").encode()).hexdigest())
        failures += not check("%s event: tls_ja3s from real ServerHello" % v,
                              len(e.get("tls_ja3s") or "") == 32
                              and (e.get("tls_ja3s_str") or "").startswith("771,"))
        failures += not check("%s event: existing fields kept" % v,
                              e.get("tls_cipher") and e.get("tls_cert_fp_sha256")
                              and e.get("tls_fp_path") == "memory_bio")
        print("    ja3=%s ja3s=%s ja3s_str=%s" % (e.get("tls_ja3"), e.get("tls_ja3s"),
                                                  e.get("tls_ja3s_str")))
    failures += not check("two successful handshake events (1.3 + 1.2)", len(tls_ok) >= 2)
    fails = [e for e in evs if e.get("event") == "tls" and e.get("tls_handshake_ok") is False]
    failures += not check("plain-HTTP-on-443 -> tls-fail event without ja3/sni",
                          any(e.get("tls_fp_path") == "fallback" and "tls_ja3" not in e
                              and "tls_sni" not in e for e in fails))

    print()
    if failures:
        print("%d TLS check(s) failed." % failures)
        return 1
    print("All TLS fingerprint checks passed.")
    return 0


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close()
    return p


if __name__ == "__main__":
    sys.exit(main())
