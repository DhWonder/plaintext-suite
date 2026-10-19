"""
The honeypot itself: a machine that looks real, and writes down everything.

This is the door with something worth stealing behind it. When somebody knocks
it does not just log the knock, it lets them in to a machine that looks
ordinary and lived-in, and records every move they make: what they type, what
they read, what they try to take.

Ways in, because attackers try all of them:

  - SSH-2 on ports mapped to ssh: a real handshake, then a password prompt.
    Only the planted credentials open the shell. Everything else is refused
    with a short delay and logged.
  - a plain login (telnet-style) on telnet ports only. An SSH port that
    receives non-SSH bytes gets OpenSSH's "Protocol mismatch." and closes —
    it never falls through to a login prompt or the web page.
  - a web page that looks like a small NAS appliance on http ports.
  - thin SMTP and FTP banners on their ports: enough that a probe gets a
    real-looking greeting, attempts are logged, and nothing useful is given.

Every connection is a probe. Even a scanner that only opens the socket and
leaves is recorded with source IP, port, and the first bytes they sent. The
sensor writes a local status file of recent probe counts so you can see it is
catching traffic, and reports sessions to the console when one is configured.

The single most important thing about this file, and the reason it is safe to
run: it never executes anything the attacker sends. Not once. Every command
gets a scripted, believable answer from the fake filesystem in bait.py. The
attacker is typing into a puppet show. Whatever they run, the real machine does
nothing but write it down. The SSH code does not forward ports and does not
open any connection of its own.
"""

import json
import os
import random
import select
import socket
import ssl
import struct
import threading
import time
import urllib.parse
import urllib.request
import weakref
import base64
import binascii
import shlex

from . import bait
from . import dsm
from . import events as events_module
from . import persona as persona_module
from . import shellfake
from . import sshproto
from . import tlsfp

_EPHEMERAL_KEYS = None  # lazy HostKeys for tests (persona=False)


BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"  # overridden by bait.SSH_BANNER when a persona is loaded
READ_LIMIT = 4096
SESSION_IDLE = 120
HTTP_GLANCE = 0.35
PRELUDE_WAIT = 2.0
AUTH_FAIL_DELAY = 1.2  # overridden per-attempt with 2.0-3.5s jitter
AUTH_FAIL_DELAY_MIN = 2.0
AUTH_FAIL_DELAY_MAX = 3.5
AUTH_LOCK_AFTER = 8
AUTH_LOCK_SECONDS = 20
MAX_CONN_TOTAL = 256
MAX_CONN_PER_IP = 12
STATUS_WRITE_MIN_GAP = 0.5
LOG_ROTATE_BYTES = 50 * 1024 * 1024
TLS_PORTS = {443, 8443, 465}
# HTTP-over-TLS ports get ClientHello fingerprinting (JA3/JA3S/SNI/ALPN) via
# tlsfp + MemoryBIO on the connection's own thread. Other TLS_PORTS (465
# SMTPS) keep the plain stdlib wrap so SMTP over TLS stays simple.
HTTPS_PORTS = {443, 8443}
# Budget of TLS handshakes per source IP per minute, enforced *before*
# handshake so TLS cannot pin threads past normal backpressure.
TLS_HANDSHAKES_PER_IP_MIN = int(os.environ.get("ANGLERFISH_TLS_PER_IP_MIN", "60"))

# nginx large_client_header_buffers is ~8k; longer request lines get 414.
MAX_URI_LEN = 8190
# Capture caps (Blue hard-ask #1: >=2048 with true-length counters).
FIRST_BYTES_CAP = 2048
# Bound the cookie table so anonymous DSM cookie minting cannot grow forever.
MAX_WEB_SESSIONS = 4096

SERVICE_BY_PORT = {
    22: "ssh", 2222: "ssh",
    80: "http", 8080: "http", 8000: "http", 8888: "http",
    443: "http", 8443: "http",
    25: "smtp", 2525: "smtp", 587: "smtp", 465: "smtp",
    21: "ftp", 2121: "ftp",
    23: "telnet", 2323: "telnet",
    # Optional UDP DNS facade. Not in DEFAULT_PORTS / the live unit --ports;
    # only listens when 53 or 5353 is passed explicitly.
    53: "dns", 5353: "dns",
}

DEFAULT_PORTS = [2222, 8080, 2525, 2121, 2323]
DEFAULT_PORTS_PRIVILEGED = [22, 80, 443, 25, 21, 23, 53]

# Extra names treated as "ours" beyond the persona hostname/FQDN/domain.
KNOWN_HOST_EXTRA = ("localhost",)

# Opening any of these is a "GOTCHA": the visitor reached the prize bait.
REVEAL_EXACT = {
    "vault-staging.b64", "vault-cleartext.txt", "verify.b64.txt",
    "verify.rot13", "drop-channel.hex",
}
REVEAL_PREFIXES = ("domainadmin-creds-backup", "password-vault-export", "session-verify.")

# Guestbook lives on the IT share (post-auth only). Its header is the soft prompt.
GUESTBOOK_PATH = "/srv/shares/IT/guestbook.txt"
GUESTBOOK_HEADER = (
    "# IT share visitor log\n"
    "# one line each, newest last.\n"
)
GUESTBOOK_HEADER_CLASSROOM = (
    "# IT share visitor log - if you made it this far, sign below.\n"
    "# one line each, newest last. be nice.\n"
)
GUESTBOOK_NOTE_LIMIT = 500
GUESTBOOK_MAX_ENTRIES = 200

SHELL_GUESTBOOK_PROMPT = (
    "\n# leave a note for the next operator:\n"
    "#   echo \"<your note>\" >> %s\n" % GUESTBOOK_PATH
)
SHELL_GUESTBOOK_PROMPT_CLASSROOM = (
    "\n# psst - you found the good stuff. leave an 'I was here' for the next one:\n"
    "#   echo \"<your note>\" >> %s\n" % GUESTBOOK_PATH
)
WEB_GUESTBOOK_PROMPT = (
    "\n# --\n# leave a note in File Station (Guestbook form), "
    "or POST note=... to /guestbook\n"
)
WEB_GUESTBOOK_PROMPT_CLASSROOM = (
    "\n# --\n# you found it. leave an 'I was here' in File Station "
    "(Guestbook form), or POST note=... to /guestbook\n"
)


def is_reveal_path(path):
    leaf = (path or "").rsplit("/", 1)[-1]
    if leaf in REVEAL_EXACT:
        return True
    return any(leaf.startswith(prefix) for prefix in REVEAL_PREFIXES)


def _clean_note(text):
    """Keep a guestbook note printable, one line, and bounded."""
    text = (text or "").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = "".join(ch for ch in text if ch.isprintable())
    return text.strip()[:GUESTBOOK_NOTE_LIMIT]


class Sensor(object):
    """One honeypot machine, listening on one or more ports."""

    def __init__(self, name="", console="", log_path="", ports=None, bind="0.0.0.0",
                 status_path="", persona=None, classroom=False, console_token="",
                 state_dir="", drop_user="", config_path=""):
        self.name = name or socket.gethostname()
        self.console = console.rstrip("/")
        self.log_path = log_path or os.path.expanduser("~/.anglerfish/sessions.log")
        self.status_path = status_path or os.path.expanduser("~/.anglerfish/status.json")
        self.bind = bind or "0.0.0.0"
        self.ports = ports or list(DEFAULT_PORTS)
        self.classroom = bool(classroom)
        self.state_dir = state_dir or os.path.expanduser("~/.anglerfish")
        self.drop_user = drop_user or ""
        # Persona: mint or load a stable identity so installs are not twins.
        # Pass persona=False to keep the built-in example persona defaults (tests).
        if persona is None:
            persona = persona_module.load_or_create(
                self.state_dir, console_host=_host_of(self.console),
                note=lambda m: None, config_path=config_path)
        elif persona is False:
            persona = {}
        self.persona = persona or {}
        self.console_token = console_token or self.persona.get("console_token") or ""
        if self.persona.get("rsa") and self.persona.get("ed25519_seed"):
            self.host_keys = sshproto.HostKeys(
                persona_module.rsa_tuple(self.persona),
                persona_module.ed25519_seed(self.persona))
        else:
            # Ephemeral keys for tests / classroom without a persisted persona.
            # Cached so the suite does not mint a 2048-bit RSA key per Sensor().
            global _EPHEMERAL_KEYS
            if _EPHEMERAL_KEYS is None:
                _EPHEMERAL_KEYS = sshproto.HostKeys(
                    persona_module.generate_rsa(2048), os.urandom(32))
            self.host_keys = _EPHEMERAL_KEYS
        self.boot_time = self.persona.get("boot_time") or (time.time() - 47 * 86400)
        self.world, self.tokens = bait.build(
            console_host=_host_of(self.console), sensor_name=self.name,
            persona=self.persona or None, classroom=self.classroom)
        self.world["mac"] = self.persona.get("mac") or "06:3a:1f:9c:2d:88"
        self.world["boot_time"] = self.boot_time
        shellfake.seed_synthetic_dirs(self.world)
        self.logins = list(self.world.get("logins") or bait.PLANTED_LOGINS)
        self.running = False
        self.sessions = []
        self.probes = []
        self._lock = threading.Lock()
        self._threads = []
        self._counter = 0
        self._fail_counts = {}
        self._probe_seen = set()
        self._web_sessions = {}  # cookie -> {user, at, sid, synotoken, ...}
        self._open_conns = 0
        self._conns_per_ip = {}
        self._tls_hits = {}  # peer_ip -> [timestamps] for pre-handshake rate
        self._last_status_write = 0.0
        self.events = events_module.EventLog(
            path=os.environ.get("ANGLERFISH_EVENTS_PATH") or "",
            sensor=self.name,
            host=(self.world.get("fqdn") or self.world.get("hostname")
                  or self.name),
        )
        self._ssl_ctx = None
        self._tls_cert = self._tls_key = self._tls_fp = ""
        cert, key = persona_module.tls_paths(self.state_dir)
        if cert and key:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.load_cert_chain(cert, key)
                # nginx without http2 answers ALPN with http/1.1; this facade
                # speaks only that.
                try:
                    ctx.set_alpn_protocols(["http/1.1"])
                except (NotImplementedError, ssl.SSLError, AttributeError):
                    pass
                self._ssl_ctx = ctx
                self._tls_cert, self._tls_key = cert, key
                try:
                    with open(cert, "rb") as fh:
                        der = ssl.PEM_cert_to_DER_cert(fh.read().decode("ascii"))
                    import hashlib as _hl
                    self._tls_fp = _hl.sha256(der).hexdigest()
                except Exception:
                    self._tls_fp = ""
            except Exception:
                self._ssl_ctx = None
        self._stats = {
            "started": time.time(),
            "probes_total": 0,
            "by_port": {},
            "by_protocol": {},
            "auth_ok": 0,
            "auth_fail": 0,
            "recent": [],
            "gotcha_total": 0,
            "gotchas": [],
            "guestbook_total": 0,
            "guestbook": [],
        }
        base, _ext = os.path.splitext(self.log_path)
        self.reveals_path = base + "-reveals.log"
        self._seed_guestbook()
        self._register()

    def start(self):
        self.running = True
        for port in self.ports:
            if self.service_for(port) == "dns":
                target = self._serve_dns
            else:
                target = self._serve
            thread = threading.Thread(target=target, args=(port,), daemon=True)
            thread.start()
            self._threads.append(thread)
        return self._threads

    def stop(self):
        self.running = False
        self._write_status()

    def service_for(self, port):
        return SERVICE_BY_PORT.get(port, "ssh")

    def _serve(self, port):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.bind, port))
            server.listen(64)
            server.settimeout(1.0)
        except OSError as exc:
            self._note("could not open port %d: %s" % (port, exc))
            return

        tls = bool(self._ssl_ctx and port in TLS_PORTS)
        self._note("listening on %s:%d (%s%s)" % (
            self.bind, port, self.service_for(port), ", tls" if tls else ""))
        while self.running:
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self._lock:
                if self._open_conns >= MAX_CONN_TOTAL:
                    try: conn.close()
                    except OSError: pass
                    continue
                per = self._conns_per_ip.get(addr[0], 0)
                if per >= MAX_CONN_PER_IP:
                    try: conn.close()
                    except OSError: pass
                    continue
                self._open_conns += 1
                self._conns_per_ip[addr[0]] = per + 1
            # HTTPS: fingerprint ClientHello (JA3/SNI/ALPN) then handshake on
            # the connection's own thread so a slow client cannot stall accept().
            # Non-HTTPS TLS (SMTPS 465) keeps the plain wrap_socket path.
            if tls and port in HTTPS_PORTS:
                threading.Thread(target=self._handle_tls,
                                 args=(conn, addr, port, self._ssl_ctx),
                                 daemon=True).start()
                continue
            if tls:
                try:
                    conn = self._ssl_ctx.wrap_socket(conn, server_side=True)
                except Exception:
                    self._release_conn(addr[0])
                    try: conn.close()
                    except OSError: pass
                    continue
            threading.Thread(target=self._handle, args=(conn, addr, port),
                             daemon=True).start()
        server.close()

    def _release_conn(self, ip):
        with self._lock:
            self._open_conns = max(0, self._open_conns - 1)
            n = self._conns_per_ip.get(ip, 1) - 1
            if n <= 0:
                self._conns_per_ip.pop(ip, None)
            else:
                self._conns_per_ip[ip] = n

    def _tls_rate_allow(self, peer_ip):
        """Soft per-IP TLS-handshake budget before spending a BIO handshake."""
        now = time.time()
        with self._lock:
            hits = [t for t in self._tls_hits.get(peer_ip, []) if now - t < 60.0]
            if len(hits) >= TLS_HANDSHAKES_PER_IP_MIN:
                self._tls_hits[peer_ip] = hits
                return False
            hits.append(now)
            self._tls_hits[peer_ip] = hits
            # Bound the map so scanners cannot grow it forever.
            if len(self._tls_hits) > 5000:
                cutoff = now - 60.0
                self._tls_hits = {
                    ip: ts for ip, ts in self._tls_hits.items()
                    if any(t >= cutoff for t in ts)
                }
            return True

    def _handle_tls(self, conn, addr, port, ctx):
        """Fingerprint the ClientHello, finish TLS, then hand off to _handle.

        Primary path: MSG_PEEK the ClientHello, parse (JA3/SNI/ALPN), then
        drive the handshake via ssl.SSLObject + MemoryBIO so the real
        ServerHello can be read for JA3S. If the peek is not a valid
        ClientHello, fall back to plain ctx.wrap_socket (nothing consumed)
        and leave ja3/sni absent. Never raises. Per-IP TLS rate limits run
        before the handshake. Uses the persona TLS cert already loaded into
        ctx (no self-generated cert).
        """
        if not self._tls_rate_allow(addr[0]):
            self._release_conn(addr[0])
            try:
                conn.close()
            except OSError:
                pass
            return
        try:
            self._handle_tls_inner(conn, addr, port, ctx)
        except Exception:
            pass

    def _handle_tls_inner(self, conn, addr, port, ctx):
        base = dict(service="https", src_ip=addr[0], src_port=addr[1],
                    dst_port=port, listen_port=port, session_id="",
                    transport="tcp", tls=True)
        hello = None
        server_hello = None
        fp_path = "fallback"
        try:
            hello, hello_len = tlsfp.peek_client_hello(conn)
            if hello is not None and hello_len:
                fp_path = "memory_bio"
                tconn, server_hello = tlsfp.memory_bio_handshake(
                    ctx, conn, hello_len)
                tconn.server_hostname = hello.get("sni") or ""
                tls_conn = tconn
            else:
                conn.settimeout(tlsfp.HANDSHAKE_TIMEOUT)
                tls_conn = ctx.wrap_socket(conn, server_side=True)
        except Exception as exc:
            try:
                fields = dict(base)
                fields.update(tls_handshake_ok=False, tags=["tls-fail"],
                              tls_fp_path=fp_path,
                              tls_error=type(exc).__name__)
                fields.update(self._tls_hello_fields(hello))
                self.events.emit("tls", **fields)
            except Exception:
                pass
            self._release_conn(addr[0])
            try:
                conn.close()
            except OSError:
                pass
            return
        try:
            cipher = tls_conn.cipher() or ("", "", 0)
            fields = dict(base)
            fields.update(
                tls_version=tls_conn.version() or "",
                tls_cipher=cipher[0] or "",
                tls_cert_fp_sha256=self._tls_fp,
                tls_handshake_ok=True,
                tls_fp_path=fp_path,
            )
            try:
                fields["tls_alpn_selected"] = tls_conn.selected_alpn_protocol()
            except Exception:
                pass
            fields.update(self._tls_hello_fields(hello))
            if server_hello:
                fields["tls_ja3s"] = server_hello["ja3s"]
                fields["tls_ja3s_str"] = server_hello["ja3s_str"]
            self.events.emit("tls", **fields)
        except Exception:
            pass
        # Hand off: _handle's finally releases the connection slot and closes.
        self._handle(tls_conn, addr, port)

    @staticmethod
    def _tls_hello_fields(hello):
        if not hello:
            return {}
        out = {
            "tls_ja3": hello["ja3"],
            "tls_ja3_str": hello["ja3_str"],
            "tls_alpn": list(hello.get("alpn") or []) or None,
            "tls_client_versions": [
                v for v in (hello.get("supported_versions") or [])
                if not tlsfp.is_grease(v)
            ] or None,
        }
        if hello.get("sni"):
            out["tls_sni"] = hello["sni"]
        return out

    def _handle(self, conn, addr, port):
        conn.settimeout(SESSION_IDLE)
        with self._lock:
            self._counter += 1
            session_id = "%s-%d-%d" % (self.name, int(time.time()), self._counter)

        service = self.service_for(port)
        session = {
            "id": session_id, "sensor": self.name, "peer_ip": addr[0],
            "peer_port": addr[1], "local_port": port, "started": time.time(),
            "protocol": service, "service": service, "events": [],
            "credentials": [], "read_files": [], "commands": [],
            "first_bytes": "", "auth_ok": False,
            "ssh_client": "", "hassh": "", "pubkeys": [],
        }

        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

        self._record_probe(session, note="accepted")

        try:
            if service == "http":
                session["protocol"] = "http"
                try:
                    first = conn.recv(READ_LIMIT)
                except (socket.timeout, OSError):
                    first = b""
                self._capture_first(session, first)
                if first:
                    self._web(conn, first, session)
            elif service == "smtp":
                session["protocol"] = "smtp"
                self._smtp(conn, session)
            elif service == "ftp":
                session["protocol"] = "ftp"
                self._ftp(conn, session)
            elif service == "telnet":
                session["protocol"] = "telnet"
                self._telnet(conn, session)
            else:
                # SSH ports speak SSH only. Banner immediately (no delay),
                # then Protocol mismatch for anything that is not SSH-2.
                try:
                    conn.sendall((bait.SSH_BANNER + "\r\n").encode("ascii"))
                except OSError:
                    return
                intro = _read_prelude(conn)
                self._capture_first(session, intro)
                if intro.startswith(b"SSH-"):
                    session["protocol"] = "ssh"
                    self._ssh(conn, intro, session)
                else:
                    session["protocol"] = "ssh-reject"
                    session["events"].append(_event("ssh-reject", "protocol mismatch"))
                    try:
                        conn.sendall(b"Protocol mismatch.\r\n")
                    except OSError:
                        pass
        except (OSError, socket.timeout, EOFError, ssl.SSLError, sshproto.ProtocolError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
            self._release_conn(addr[0])
            session["ended"] = time.time()
            session["duration"] = round(session["ended"] - session["started"], 1)
            self._finish(session)

    def _capture_first(self, session, data):
        if not data:
            return
        text, encoding, true_len, truncated = events_module.capture_bytes(
            data, FIRST_BYTES_CAP)
        # sessions.log stays backward-compatible: first_bytes is still a string.
        # True length + truncation live alongside it and in events.jsonl.
        session["first_bytes"] = text[:FIRST_BYTES_CAP]
        session["first_bytes_encoding"] = encoding
        session["first_bytes_len"] = true_len
        session["first_bytes_truncated"] = truncated
        session["events"].append(_event("first-bytes", session["first_bytes"][:200]))
        try:
            self.events.emit(
                "first_bytes",
                service=session.get("service") or "",
                session=session,
                first_bytes=session["first_bytes"][:512],
                first_bytes_encoding=encoding,
                first_bytes_len=true_len,
                first_bytes_truncated=truncated,
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # GOTCHA reveals and the guestbook
    # ------------------------------------------------------------------
    def _seed_guestbook(self):
        files = self.world["files"]
        if GUESTBOOK_PATH not in files:
            header = GUESTBOOK_HEADER_CLASSROOM if self.classroom else GUESTBOOK_HEADER
            files[GUESTBOOK_PATH] = header
        self._refresh_tree()

    def _refresh_tree(self):
        files = self.world["files"]
        # Rebuild from files, but keep any synthetic dirs seed_synthetic_dirs
        # planted (empty /tmp, /proc, /sys, ...) so they are not wiped.
        derived = set(bait._directories_for(files))
        existing = set(self.world.get("dirs") or [])
        self.world["dirs"] = sorted(derived | existing)
        self.world["shares"] = bait._share_index(files)

    def _append_reveal_log(self, record):
        """One JSON line per GOTCHA / guestbook note, written immediately."""
        try:
            folder = os.path.dirname(self.reveals_path)
            if folder and not os.path.isdir(folder):
                os.makedirs(folder)
            with open(self.reveals_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except OSError:
            pass

    def _gotcha(self, session, path, via):
        """Record that a visitor opened prize bait. Returns True on the
        first reveal in this session, which is when the soft prompt shows."""
        now = time.time()
        record = {
            "kind": "gotcha",
            "at": now,
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
            "sensor": self.name,
            "session": session.get("id", ""),
            "peer_ip": session.get("peer_ip", "?"),
            "username": session.get("username", ""),
            "path": path,
            "via": via,
        }
        gotchas = session.setdefault("gotchas", [])
        first = not gotchas
        gotchas.append(record)
        session.setdefault("events", []).append(
            _event("gotcha", "%s via %s" % (path, via)))
        with self._lock:
            self._stats["gotcha_total"] += 1
            self._stats["gotchas"] = (self._stats["gotchas"] + [record])[-40:]
        self._append_reveal_log(record)
        self._note("GOTCHA %s opened %s via %s (session %s)"
                   % (record["peer_ip"], path, via, record["session"] or "-"))
        self._write_status()
        return first

    def _sign_guestbook(self, session, note, via):
        """Append a visitor note to the fake guestbook and log it. Returns the
        cleaned note, or "" when there was nothing to write."""
        note = _clean_note(note)
        if not note:
            return ""
        now = time.time()
        stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(now))
        # The file other visitors can read carries no IP; the log does.
        line = "[%s] %s\n" % (stamp, note)
        with self._lock:
            files = self.world["files"]
            current = files.get(GUESTBOOK_PATH, GUESTBOOK_HEADER)
            entries = current.splitlines(True)
            header = [ln for ln in entries if ln.startswith("#")]
            body = [ln for ln in entries if not ln.startswith("#")]
            body = (body + [line])[-GUESTBOOK_MAX_ENTRIES:]
            files[GUESTBOOK_PATH] = "".join(header + body)
        self._refresh_tree()
        record = {
            "kind": "guestbook",
            "at": now,
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
            "sensor": self.name,
            "session": session.get("id", ""),
            "peer_ip": session.get("peer_ip", "?"),
            "username": session.get("username", ""),
            "via": via,
            "note": note,
        }
        session.setdefault("guestbook", []).append(record)
        session.setdefault("events", []).append(_event("guestbook", note))
        with self._lock:
            self._stats["guestbook_total"] += 1
            self._stats["guestbook"] = (self._stats["guestbook"] + [record])[-20:]
        self._append_reveal_log(record)
        self._note("GUESTBOOK %s signed via %s: %s" % (record["peer_ip"], via, note))
        self._write_status()
        return note

    def _shell_read(self, session, target):
        """Bookkeeping for a shell file read. Returns the prompt suffix to show."""
        session.setdefault("read_files", []).append(target)
        session.setdefault("events", []).append(_event("read-file", target))
        try:
            self.events.emit(
                "path_read",
                service=session.get("service") or session.get("protocol") or "shell",
                session=session, path_read=target,
                username=session.get("username") or "",
                auth_ok=bool(session.get("auth_ok")),
                cred_source=session.get("cred_source") or "session",
                gotcha_id=target if is_reveal_path(target) else None,
            )
        except Exception:
            pass
        if is_reveal_path(target):
            if self._gotcha(session, target, "shell"):
                return (SHELL_GUESTBOOK_PROMPT_CLASSROOM if self.classroom
                        else SHELL_GUESTBOOK_PROMPT)
        return ""

    def _record_probe(self, session, note=""):
        peer = session["peer_ip"]
        port = session["local_port"]
        with self._lock:
            self._stats["probes_total"] += 1
            self._stats["by_port"][str(port)] = self._stats["by_port"].get(str(port), 0) + 1
            proto = session.get("protocol") or session.get("service") or "?"
            self._stats["by_protocol"][proto] = self._stats["by_protocol"].get(proto, 0) + 1
            is_new = peer not in self._probe_seen
            if is_new:
                self._probe_seen.add(peer)
                if len(self._probe_seen) > 5000:
                    # Drop an arbitrary half; set has no order, just bound memory.
                    self._probe_seen = set(list(self._probe_seen)[-2500:])
            entry = {
                "at": time.time(), "peer_ip": peer, "port": port,
                "protocol": proto, "new_ip": is_new, "note": note,
            }
            self._stats["recent"] = (self._stats["recent"] + [entry])[-40:]
            self.probes.append(entry)
        session["events"].append(_event("probe", "%s:%s %s" % (peer, port, note)))
        if is_new:
            self._note("new probe from %s on port %d (%s)" % (peer, port, proto))
        self._write_status()

    def _check_login(self, username, password):
        for user, pw in self.logins:
            if username == user and password == pw:
                return True
        return False

    def _record_password(self, session, service, username, password):
        """Log one try. Only planted / canary credentials are accepted.

        On success emit auth_ok=true as the highest-signal structured event
        (Blue Team R-rules). On failure keep live's per-attempt jittered
        delay (and the lock-after-N slowdown). Fail counts stay per-IP
        (live behaviour); do not share a lock clock across services by
        changing that here.
        """
        session["events"].append(_event("login-user", username))
        session["events"].append(_event("login-pass", password))
        session["credentials"].append({
            "username": username, "password": password, "service": service,
        })
        peer = session["peer_ip"]
        ok = self._check_login(username, password)
        source = "attacker"
        if ok:
            fixed = dict(bait.planted_password_map())
            if fixed.get(username) == password:
                source = "planted"
            else:
                source = "canary"
        if ok:
            with self._lock:
                self._fail_counts[peer] = 0
                self._stats["auth_ok"] += 1
            session["events"].append(_event("login-result", "ok"))
            session["auth_ok"] = True
            session["cred_source"] = source
            try:
                self.events.emit(
                    "auth", service=service, session=session,
                    username=username, password=password, auth_ok=True,
                    cred_source=source, auth_method="password",
                )
            except Exception:
                pass
            return True

        with self._lock:
            fails = self._fail_counts.get(peer, 0) + 1
            self._fail_counts[peer] = fails
            self._stats["auth_fail"] += 1
        session["events"].append(_event("login-result", "fail"))
        delay = random.uniform(AUTH_FAIL_DELAY_MIN, AUTH_FAIL_DELAY_MAX)
        reason = "fail"
        if fails >= AUTH_LOCK_AFTER:
            delay = AUTH_LOCK_SECONDS
            reason = "lock"
            session["events"].append(_event("auth-slowdown",
                                            "%d fails from %s" % (fails, peer)))
        time.sleep(delay)
        try:
            self.events.emit(
                "auth", service=service, session=session,
                username=username, password=password, auth_ok=False,
                cred_source="attacker", auth_method="password",
                tarpit_ms=int(delay * 1000), tarpit_reason=reason,
            )
        except Exception:
            pass
        return False

    def _telnet(self, conn, session):
        """Telnet port: IAC negotiate, then a login prompt. Never on SSH ports."""
        # Refuse options politely so telnet clients settle.
        try:
            # IAC WONT ECHO / IAC WONT SUPPRESS-GO-AHEAD / IAC DO TERMINAL-TYPE
            conn.sendall(bytes([255, 252, 1, 255, 252, 3, 255, 253, 24]))
        except OSError:
            pass
        issue = self.world["files"].get("/etc/issue", "Ubuntu 22.04.4 LTS\n")
        issue = (issue.replace("\\n", self.world["hostname"])
                      .replace("\\l", "tty1")
                      .replace("\\m", "x86_64")
                      .replace("\\r", "5.15.0-101-generic")
                      .replace("\\s", "Linux")
                      .replace("\\v", "5.15.0"))
        _send(conn, "\r\n%s\r\n" % issue.strip())
        self._console(conn, b"", session, banner_first=True)

    def _console(self, conn, intro, session, banner_first=True):
        """A serial-console / telnet login (telnet ports only)."""
        send = lambda text: _send(conn, text)
        if not banner_first:
            send("\r\n%s\r\n\r\n" % self.world["files"].get("/etc/issue", "").strip())
        pending = intro
        while self.running:
            send("%s login: " % self.world["hostname"])
            username = _line(conn, pending)
            pending = b""
            if username is None:
                return
            send("Password: ")
            password = _line(conn)
            if password is None:
                return
            if not self._record_password(session, session.get("protocol") or "console",
                                         username, password):
                send("\r\nLogin incorrect\r\n")
                continue
            session["username"] = username
            send("\r\n" + self._live_motd(session, username) + "\r\n")
            self._console_shell(conn, session, username=username)
            return

    def _console_shell(self, conn, session, username="deploy"):
        send = lambda text: _send(conn, text)
        home = "/home/%s" % username if username in ("deploy", "admin") else "/home/deploy"
        if home not in self.world["dirs"] and home + "/" not in "".join(self.world["dirs"]):
            home = "/home/deploy"
        cwd = home if home in self.world["dirs"] else "/home/deploy"
        session["username"] = username
        while self.running:
            send(self._prompt(cwd, username=username))
            line = _line(conn)
            if line is None:
                break
            reply, cwd, done = self._shell_answer(line, cwd, session, username=username)
            if reply:
                send(reply if reply.endswith("\n") else reply + "\n")
            if done:
                send("logout\r\n")
                break

    def _prompt(self, cwd, username="deploy"):
        return "%s@%s:%s$ " % (username, self.world["hostname"], _short(cwd, username=username))

    def _shell_answer(self, line, cwd, session, username="deploy"):
        line = line.strip()
        if not line:
            return "", cwd, False
        if len(line) > 2000:
            line = line[:2000]
        session["commands"].append(line)
        session["events"].append(_event("command", line))
        return self._run_fake(line, cwd, session, username=username)

    def _ssh(self, conn, intro, session):
        state = {"cwd": "/home/deploy", "user": "deploy"}

        def banner(ident):
            session["ssh_client"] = ident
            session["events"].append(_event("ssh-client", ident))

        def kexinit(info):
            # Live sshproto already computes HASSH and passes a dict; keep that
            # crypto stack and only emit the structured event on top.
            session["hassh"] = info.get("hassh") or ""
            session["ssh_kex_algs"] = list(info.get("kex") or [])
            session["events"].append(_event("ssh-hassh", session["hassh"]))
            session["events"].append(
                _event("ssh-kex", ",".join((info.get("kex") or [])[:6])))
            try:
                self.events.emit(
                    "ssh_kex", service="ssh", session=session,
                    ssh_client_version=session.get("ssh_client") or "",
                    ssh_kex_algs=",".join(info.get("kex") or []),
                    ssh_host_key_algs=",".join(info.get("host_key") or []),
                    ssh_enc_algs_ctos=",".join(info.get("ciphers_c2s") or []),
                    ssh_mac_algs_ctos=",".join(info.get("macs_c2s") or []),
                    ssh_comp_algs_ctos=",".join(info.get("comp_c2s") or []),
                    hassh=session["hassh"],
                )
            except Exception:
                pass

        def pubkey(username, algo, fp):
            session.setdefault("pubkeys", []).append(
                {"username": username, "algo": algo, "fingerprint": fp})
            session["events"].append(_event("ssh-pubkey", "%s %s %s" % (username, algo, fp)))

        def password(username, password):
            ok = self._record_password(session, "ssh", username, password)
            if ok:
                state["user"] = username or "deploy"
                session["username"] = state["user"]
                home = "/home/%s" % state["user"]
                if home in self.world["dirs"]:
                    state["cwd"] = home
            return ok

        def greeting():
            return self._live_motd(session, state["user"])

        def prompt():
            return self._prompt(state["cwd"], username=state["user"])

        def line(text):
            reply, cwd, done = self._shell_answer(
                text, state["cwd"], session, username=state["user"])
            state["cwd"] = cwd
            return reply, done

        def exec_cmd(command):
            reply, cwd, _done = self._shell_answer(
                command, state["cwd"], session, username=state["user"])
            state["cwd"] = cwd
            return reply or ""

        sshproto.serve(conn, intro, bait.SSH_BANNER, {
            "banner": banner,
            "kexinit": kexinit,
            "pubkey": pubkey,
            "password": password,
            "greeting": greeting,
            "prompt": prompt,
            "line": line,
            "exec": exec_cmd,
        }, keys=self.host_keys)

    def _smtp(self, conn, session):
        fqdn = self.world.get("fqdn") or self.world["hostname"]
        _send(conn, bait.smtp_banner() + "\r\n")
        while self.running:
            line = _line(conn)
            if line is None:
                return
            session["events"].append(_event("smtp", line[:200]))
            if not session["first_bytes"]:
                session["first_bytes"] = line[:120]
            upper = line.upper().strip()
            if upper.startswith("EHLO") or upper.startswith("HELO"):
                _send(conn, "250-%s\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n"
                            "250-STARTTLS\r\n250-ENHANCEDSTATUSCODES\r\n"
                            "250-8BITMIME\r\n250 CHUNKING\r\n" % fqdn)
            elif upper.startswith("MAIL"):
                session["events"].append(_event("smtp-mail", line[:200]))
                session["_smtp_mail"] = True
                # Accept MAIL, refuse at RCPT — matches a real closed relay.
                _send(conn, "250 2.1.0 Ok\r\n")
            elif upper.startswith("RCPT"):
                if session.get("_smtp_mail"):
                    _send(conn, "554 5.7.1 <%s>: Relay access denied\r\n"
                          % (line.split(":", 1)[-1].strip() or "unknown"))
                else:
                    _send(conn, "503 5.5.1 Error: need MAIL command\r\n")
            elif upper.startswith("DATA"):
                if session.get("_smtp_mail"):
                    _send(conn, "554 5.7.1 Error: no valid recipients\r\n")
                else:
                    _send(conn, "503 5.5.1 Error: need MAIL command\r\n")
            elif upper.startswith("STARTTLS"):
                # On non-TLS listeners, refuse; on 465 the socket is already TLS.
                _send(conn, "454 4.7.0 TLS not available due to local problem\r\n")
            elif upper.startswith("AUTH"):
                session["credentials"].append({"service": "smtp", "raw": line[:200]})
                _send(conn, "535 5.7.8 Error: authentication failed\r\n")
            elif upper in ("QUIT",):
                _send(conn, "221 2.0.0 Bye\r\n")
                return
            elif upper in ("RSET", "NOOP"):
                _send(conn, "250 2.0.0 Ok\r\n")
            else:
                _send(conn, "502 5.5.2 Error: command not recognized\r\n")

    def _ftp(self, conn, session):
        fqdn = self.world.get("fqdn") or self.world["hostname"]
        _send(conn, bait.ftp_banner() + "\r\n")
        user = ""
        while self.running:
            line = _line(conn)
            if line is None:
                return
            session["events"].append(_event("ftp", line[:200]))
            if not session["first_bytes"]:
                session["first_bytes"] = line[:120]
            parts = line.strip().split(None, 1)
            cmd = (parts[0] if parts else "").upper()
            arg = parts[1] if len(parts) > 1 else ""
            if not cmd:
                # vsftpd >= 2.0.8 silently ignores blank lines (nmap keys on this).
                continue
            if cmd == "USER":
                user = arg
                session["events"].append(_event("login-user", user))
                _send(conn, "331 Please specify the password.\r\n")
            elif cmd == "PASS" and not user:
                _send(conn, "503 Login with USER first.\r\n")
                self._emit_ftp(session, cmd, arg, 503)
            elif cmd == "PASS":
                # Planted/canary creds record auth_ok for Blue; transfer is still
                # refused below (no real files leave the box). Pre-auth FEAT/
                # SYST/blank-line behaviour is unchanged (realism #4c).
                ok = self._record_password(session, "ftp", user, arg)
                if ok:
                    _send(conn, "230 Login successful.\r\n")
                    self._emit_ftp(session, cmd, arg, 230)
                    session["_ftp_user"] = user
                else:
                    _send(conn, "530 Login incorrect.\r\n")
                    self._emit_ftp(session, cmd, arg, 530)
                user = ""
            elif cmd == "FEAT":
                # Stock vsftpd 3.0.5 feature list (answered pre-login).
                _send(conn, "211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n"
                            " REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n")
            elif cmd == "OPTS" and arg.upper().startswith("UTF8"):
                _send(conn, "200 Always in UTF8 mode.\r\n")
            elif cmd == "AUTH":
                _send(conn, "530 Please login with USER and PASS.\r\n")
            elif cmd in ("QUIT",):
                _send(conn, "221 Goodbye.\r\n")
                self._emit_ftp(session, cmd, arg, 221)
                return
            else:
                if session.get("auth_ok"):
                    # Authed but we never open a data channel or serve files.
                    _send(conn, "550 Failed to open file.\r\n")
                    self._emit_ftp(session, cmd, arg, 550)
                else:
                    # Real vsftpd refuses SYST/PWD/LIST/anything else until login.
                    _send(conn, "530 Please login with USER and PASS.\r\n")
                    self._emit_ftp(session, cmd, arg, 530)

    def _emit_ftp(self, session, cmd, arg, reply):
        try:
            self.events.emit(
                "ftp", service="ftp", session=session,
                ftp_cmd=cmd, ftp_arg=(arg or "")[:200], ftp_reply_code=reply,
            )
        except Exception:
            pass

    def _run_fake(self, line, cwd, session, username="deploy"):
        """Answer a shell command from the fake filesystem. Runs nothing."""
        sh = shellfake.FakeShell(
            self.world, self.ports, classroom=self.classroom,
            peer_ip=session.get("peer_ip") or "",
            read_hook=lambda path: self._shell_read(session, path),
            sign_guestbook=self._sign_guestbook,
            event_hook=lambda kind, detail: None,
            boot_time=self.boot_time,
        )
        # Replay sudo state across calls within a session
        pending = session.get("_sudo_pending")
        if pending:
            sh._sudo_pending = pending
        reply, cwd, done = sh.run_line(line, cwd, session, username=username)
        if sh._sudo_pending:
            session["_sudo_pending"] = sh._sudo_pending
        else:
            session.pop("_sudo_pending", None)
        return reply, cwd, done

    def _live_motd(self, session, username):
        """MOTD that reflects the live session (user count, peer, uptime)."""
        days, pretty = persona_module.uptime_fields(
            {"boot_time": self.boot_time})
        ip = self.world.get("internal_ip") or "10.0.0.21"
        return (
            "Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)\n\n"
            " * Support:        https://ubuntu.com/advantage\n\n"
            "  System load:  0.08              Processes:             128\n"
            "  Usage of /:   61.2%% of 78.4GB  Users logged in:       1\n"
            "  IP address:   %s               Hostname:              %s\n\n"
            "  %s file share — NAS UI on https://%s/\n\n"
            "Last login: %s from %s\n"
            % (ip, self.world["hostname"], self.world.get("company") or "",
               self.world.get("fqdn") or self.world["hostname"],
               time.strftime("%a %b %d %H:%M:%S %Y"),
               session.get("peer_ip") or "10.0.0.14")
        )

    def _list(self, path):
        files = self.world["files"]
        dirs = self.world["dirs"]
        entries = set()
        base = path.rstrip("/") or ""
        for other in dirs:
            if other != base and other.rsplit("/", 1)[0] == (base or ""):
                entries.add(other.rsplit("/", 1)[1] + "/")
        for path_name in files:
            if path_name.rsplit("/", 1)[0] == (base or ""):
                entries.add(path_name.rsplit("/", 1)[1])
        if not entries:
            return ""
        return "  ".join(sorted(entries))

    def _issue_web_session(self, username, provisional=False):
        """Mint a session cookie. provisional=True: pre-auth tracking cookie
        (DSM issues id= on the login GET before anyone authenticates)."""
        token = binascii.hexlify(os.urandom(16)).decode("ascii")
        sid = binascii.hexlify(os.urandom(8)).decode("ascii").upper()
        synotoken = binascii.hexlify(os.urandom(8)).decode("ascii").upper()
        with self._lock:
            self._web_sessions[token] = {
                "user": username or "",
                "at": time.time(),
                "sid": sid,
                "synotoken": synotoken,
                "provisional": bool(provisional),
                "auth_ok": bool(username) and not provisional,
            }
            # Drop sessions older than a day; also bound total size.
            cutoff = time.time() - 86400
            stale = [k for k, v in self._web_sessions.items() if v["at"] < cutoff]
            for k in stale:
                self._web_sessions.pop(k, None)
            if len(self._web_sessions) > MAX_WEB_SESSIONS:
                # Drop oldest half of provisional sessions first.
                items = sorted(self._web_sessions.items(), key=lambda kv: kv[1]["at"])
                for k, _ in items[:len(items) // 2]:
                    self._web_sessions.pop(k, None)
        return token

    def _web_user_from_headers(self, head):
        """Return (username, nas_session_token, row). Empty user when provisional."""
        cookie = ""
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"cookie:"):
                cookie = line.split(b":", 1)[1].decode("latin-1", "replace").strip()
                break
        token = ""
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("nas_session="):
                token = part.split("=", 1)[1].strip()
                break
            if part.startswith("id=") and not token:
                sid = part.split("=", 1)[1].strip()
                with self._lock:
                    for tok, row in self._web_sessions.items():
                        if row.get("sid") == sid:
                            token = tok
                            break
        if not token:
            return "", "", {}
        with self._lock:
            row = dict(self._web_sessions.get(token) or {})
        if not row:
            return "", "", {}
        if row.get("provisional") and not row.get("auth_ok"):
            return "", token, row
        if row.get("user") and row.get("auth_ok"):
            return row["user"], token, row
        return "", token, row

    def _known_host(self, host_header):
        """True when Host looks like this NAS; False -> nginx default-server."""
        if not host_header:
            return True
        host = host_header.split(":")[0].strip().lower()
        if not host or host in KNOWN_HOST_EXTRA or host in ("127.0.0.1", "::1"):
            return True
        if "." not in host:
            return True
        if all(c in "0123456789." for c in host):
            return True
        fqdn = (self.world.get("fqdn") or "").lower()
        hostname = (self.world.get("hostname") or "").lower()
        domain = (self.world.get("domain") or "").lower()
        if host == fqdn or host == hostname or host.startswith(hostname + "."):
            return True
        if domain and (host == domain or host.endswith("." + domain)):
            return True
        return False

    def _web(self, conn, first, session):
        head, body = _http_head_and_body(conn, first)
        request_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        session["events"].append(_event("http", request_line[:500]))
        ua = host_header = referer = content_type = ""
        for line in head.split(b"\r\n"):
            low = line.lower()
            if low.startswith(b"user-agent:"):
                ua = line.split(b":", 1)[1].decode("latin-1", "replace").strip()
                session["http_user_agent"] = ua
                session["events"].append(_event("http-ua", ua[:200]))
            elif low.startswith(b"host:"):
                host_header = line.split(b":", 1)[1].decode("latin-1", "replace").strip()
                session["http_host"] = host_header
            elif low.startswith(b"referer:"):
                referer = line.split(b":", 1)[1].decode("latin-1", "replace").strip()
            elif low.startswith(b"content-type:"):
                content_type = line.split(b":", 1)[1].decode("latin-1", "replace").strip()
        try:
            method, path, version = request_line.split(" ", 2)
        except ValueError:
            parts = request_line.split(" ", 2)
            method = parts[0] if parts else "GET"
            path = parts[1] if len(parts) > 1 else request_line
            version = parts[2] if len(parts) > 2 else "HTTP/1.0"
            if len(request_line) > MAX_URI_LEN:
                path = request_line
        method = method.upper()
        uri_len = len(path)

        # 414 before anything else (nginx large_client_header_buffers).
        if uri_len > MAX_URI_LEN or len(request_line) > MAX_URI_LEN + 32:
            payload = dsm.nginx_414_html().encode("utf-8")
            _send_raw(conn, _http_response(414, "text/html", payload, head_only=False))
            try:
                self.events.emit(
                    "http", service="http", session=session,
                    http_method=method, http_path=path[:200], http_status=414,
                    uri_len=uri_len, request_line=request_line[:512],
                    request_line_truncated=True, user_agent=ua[:200],
                    host_header=host_header,
                )
            except Exception:
                pass
            return

        # CONNECT must never look like an open proxy.
        if method == "CONNECT":
            session["events"].append(_event("http-connect", path[:120]))
            payload = _nginx_error(400, "Bad Request")
            _send_raw(conn, _http_response(400, "text/html", payload, head_only=False))
            return
        if method == "TRACE":
            payload = _nginx_error(405, "Method Not Allowed")
            _send_raw(conn, _http_response(405, "text/html", payload, head_only=False,
                                           extra="Allow: GET, POST, HEAD\r\n"))
            return
        if method not in ("GET", "POST", "HEAD", "OPTIONS"):
            payload = _nginx_error(400, "Bad Request")
            _send_raw(conn, _http_response(400, "text/html", payload, head_only=False))
            return

        # Unknown Host -> nginx default-server (deception tell).
        if not self._known_host(host_header):
            payload = dsm.nginx_default_html().encode("utf-8")
            _send_raw(conn, _http_response(200, "text/html", payload, head_only=False))
            try:
                self.events.emit(
                    "http", service="http", session=session,
                    http_method=method, http_path=path[:200], http_status=200,
                    uri_len=uri_len, host_header=host_header, user_agent=ua[:200],
                    tags=["default-server"],
                )
            except Exception:
                pass
            return

        if method == "POST" and body:
            posted = body.decode("latin-1", "replace")
            session["events"].append(_event(
                "http-post", "%s %s" % (path, posted[:200])))
            user, pw = _form_user_pass(posted)
            if user is not None or pw is not None:
                session["credentials"].append({
                    "username": user or "", "password": pw or "", "service": "web",
                    "raw": posted[:200],
                })
            _tag_http_exploit(session, path, posted)

        _tag_http_exploit(session, path, "")

        web_user, web_token, web_row = self._web_user_from_headers(head)
        if web_user:
            session["auth_ok"] = True
            session["username"] = web_user

        if method == "OPTIONS":
            _send_raw(conn, _http_response(204, "text/plain", b"", head_only=True,
                                           extra="Allow: GET, POST, HEAD, OPTIONS\r\n"))
            return

        page, ctype, code, set_cookie, extra_headers = self._page(
            path, session, method, body, web_user=web_user,
            web_token=web_token, web_row=web_row)

        clean_path = path.split("?", 1)[0]
        query = path.split("?", 1)[1] if "?" in path else ""
        syno_api = syno_method = syno_version = ""
        if "/webapi/" in clean_path or clean_path.startswith("/webman/"):
            qs = urllib.parse.parse_qs(query, keep_blank_values=True)
            syno_api = (qs.get("api") or [""])[0]
            syno_method = (qs.get("method") or [""])[0]
            syno_version = (qs.get("version") or [""])[0]
        req_line_cap = request_line[:events_module.REQUEST_LINE_CAP]
        body_text, body_enc, body_len, _body_trunc = events_module.capture_bytes(
            body or b"", events_module.BODY_CAP)
        try:
            self.events.emit(
                "syno_api" if syno_api else "http",
                service=session.get("service") or "http", session=session,
                http_method=method, http_path=clean_path[:500],
                http_query=query[:500], http_version=version,
                host_header=host_header, user_agent=ua[:300],
                referer=referer[:300], content_type=content_type,
                content_length=len(body or b""), http_status=code,
                uri_len=uri_len, request_line=req_line_cap,
                request_line_truncated=(
                    len(request_line) > events_module.REQUEST_LINE_CAP),
                body_len=body_len, body_first_bytes=body_text[:256],
                body_encoding=body_enc,
                syno_api=syno_api or None,
                syno_method=syno_method or None,
                syno_version=syno_version or None,
                session_cookie=web_token or None,
                syno_token=(web_row or {}).get("synotoken") if web_row else None,
                session_material_presented=bool(web_token),
                session_material_valid=bool(web_user),
            )
        except Exception:
            pass

        extra = ""
        if set_cookie:
            row = {}
            with self._lock:
                row = dict(self._web_sessions.get(set_cookie) or {})
            sid = row.get("sid") or set_cookie[:16]
            extra += "Set-Cookie: id=%s; Path=/; HttpOnly\r\n" % sid
            extra += "Set-Cookie: nas_session=%s; Path=/; HttpOnly\r\n" % set_cookie
            if row.get("auth_ok"):
                extra += "Set-Cookie: stay_login=1; Path=/\r\n"
        if code == 302:
            extra += "Location: /files/\r\n"
        for hdr in (extra_headers or []):
            extra += hdr if hdr.endswith("\r\n") else (hdr + "\r\n")
        if isinstance(page, (bytes, bytearray)):
            payload = bytes(page)
        else:
            payload = page.encode("utf-8")
        _send_raw(conn, _http_response(code, ctype, payload,
                                       head_only=(method == "HEAD"), extra=extra))

    def _web_revealed(self, token):
        if not token:
            return False
        with self._lock:
            row = self._web_sessions.get(token)
            return bool(row and row.get("revealed"))

    def _mark_web_revealed(self, token):
        if not token:
            return
        with self._lock:
            row = self._web_sessions.get(token)
            if row is not None:
                row["revealed"] = True

    def _page(self, path, session, method="GET", body=b"", web_user="",
              web_token="", web_row=None):
        """Return (body, content_type, status_code, set_cookie_token, extra_headers).

        set_cookie_token is our internal nas_session token (or "" if none);
        _web turns it into DSM-style Set-Cookie headers (id= + nas_session=).
        Live realism: /api/status stays gated; unknown paths stay nginx 404.
        """
        clean = path.split("?", 1)[0]
        query = path.split("?", 1)[1] if "?" in path else ""
        qs = urllib.parse.parse_qs(query, keep_blank_values=True)
        files = self.world["files"]
        shares = self.world.get("shares") or {}
        authed = bool(web_user) or bool(session.get("auth_ok"))
        set_cookie = ""
        web_row = web_row or {}

        # ---- Synology DSM webapi / webman (deception: Synology surface) ----
        if clean in ("/webapi/query.cgi", "/webapi/entry.cgi",
                     "/webapi/auth.cgi", "/webman/login.cgi",
                     "/webapi/auth.cgi/", "/webapi/query.cgi/"):
            return self._dsm_api(clean, qs, method, body, session,
                                web_user, web_token, web_row)

        if clean in ("/webman/login.js", "/scripts/synology/dist/login.js"):
            return (dsm.login_js(), "application/javascript; charset=utf-8",
                    200, "", [])
        if clean == "/webman/login.cgi" and (qs.get("css") or [""])[0]:
            return dsm.login_css(), "text/css; charset=utf-8", 200, "", []

        # Health probe stays public but says nothing about the box (like a
        # load-balancer check). Full status (internal IP, services, ports) is
        # session-only: a real NAS never hands that to an anonymous visitor.
        if clean == "/health":
            return '{"status":"ok"}\n', "application/json", 200, "", []
        if clean in ("/api/status", "/api/system"):
            if not authed:
                session.setdefault("events", []).append(
                    _event("http-unauth", "%s without session" % clean))
                return ('{"success":false,"error":{"code":401,'
                        '"message":"authentication required"}}\n',
                        "application/json", 401, "", [])
            return _status_json(self.world, self.ports), "application/json", 200, "", []

        # Share file download: /files/<share>/<name> — share tree only.
        if clean.startswith("/files/") and clean not in ("/files/", "/files"):
            if not authed:
                set_cookie = web_token or self._issue_web_session(
                    "", provisional=True)
                return (dsm.login_page_html(self.world, session_id=set_cookie),
                        "text/html; charset=utf-8", 200, set_cookie, [])
            rel = clean[len("/files/"):]
            target = _resolve_share_path(rel, files, shares)
            if target and target in files:
                session["read_files"].append(target)
                session["events"].append(_event("read-file", target))
                try:
                    self.events.emit(
                        "path_read", service="http", session=session,
                        path_read=target,
                        username=web_user or session.get("username"),
                        auth_ok=True,
                        cred_source=session.get("cred_source") or "session",
                        gotcha_id=target if is_reveal_path(target) else None,
                    )
                except Exception:
                    pass
                content = files[target]
                if is_reveal_path(target):
                    self._gotcha(session, target, "web")
                    self._mark_web_revealed(web_token)
                    if isinstance(content, str):
                        prompt = (WEB_GUESTBOOK_PROMPT_CLASSROOM
                                  if self.classroom else WEB_GUESTBOOK_PROMPT)
                        content = content.rstrip("\n") + "\n" + prompt
                if target.endswith(".png"):
                    ctype = "image/png"
                elif target.endswith(".csv"):
                    ctype = "text/csv; charset=utf-8"
                else:
                    ctype = "text/plain; charset=utf-8"
                return content, ctype, 200, "", []
            return (_not_found_page(self.world),
                    "text/html; charset=utf-8", 404, "", [])

        posted = body.decode("latin-1", "replace") if body else ""
        if clean == "/guestbook":
            if not authed:
                set_cookie = web_token or self._issue_web_session(
                    "", provisional=True)
                return (dsm.login_page_html(self.world, session_id=set_cookie),
                        "text/html; charset=utf-8", 200, set_cookie, [])
            if method == "POST":
                note = ""
                for pair in posted.split("&"):
                    key, _eq, value = pair.partition("=")
                    if urllib.parse.unquote_plus(key) in ("note", "message", "msg"):
                        note = urllib.parse.unquote_plus(value)
                        break
                signed = self._sign_guestbook(session, note, "web")
                return (_dashboard_page(self.world, guestbook_form=True,
                                        signed=bool(signed)),
                        "text/html; charset=utf-8", 200, "", [])
            return (_dashboard_page(self.world, guestbook_form=True),
                    "text/html; charset=utf-8", 200, "", [])

        if method == "POST" and clean in ("/", "/login", "/admin"):
            user, pw = _form_user_pass(posted)
            if user is not None and pw is not None:
                if self._record_password(session, "web", user, pw):
                    session["username"] = user
                    set_cookie = self._issue_web_session(user, provisional=False)
                    return (_dashboard_page(self.world),
                            "text/html; charset=utf-8", 200, set_cookie, [])
                set_cookie = web_token or self._issue_web_session(
                    "", provisional=True)
                return (dsm.login_page_html(self.world, failed=True,
                                            session_id=set_cookie),
                        "text/html; charset=utf-8", 200, set_cookie, [])
            set_cookie = web_token or self._issue_web_session(
                "", provisional=True)
            return (dsm.login_page_html(self.world, failed=True,
                                        session_id=set_cookie),
                    "text/html; charset=utf-8", 200, set_cookie, [])

        if clean in ("/dashboard", "/admin/dashboard", "/files", "/files/",
                     "/shares"):
            if authed:
                return (_dashboard_page(
                            self.world,
                            guestbook_form=self._web_revealed(web_token)),
                        "text/html; charset=utf-8", 200, "", [])
            set_cookie = web_token or self._issue_web_session(
                "", provisional=True)
            return (dsm.login_page_html(self.world, session_id=set_cookie),
                    "text/html; charset=utf-8", 200, set_cookie, [])

        if clean in ("/", "/login", "/admin", "/index.html"):
            if authed:
                return (_dashboard_page(
                            self.world,
                            guestbook_form=self._web_revealed(web_token)),
                        "text/html; charset=utf-8", 200, "", [])
            # DSM issues a session cookie on the login GET.
            set_cookie = web_token or self._issue_web_session(
                "", provisional=True)
            return (dsm.login_page_html(self.world, session_id=set_cookie),
                    "text/html; charset=utf-8", 200, set_cookie, [])

        # Real nginx: unknown paths are 404, not the login page.
        return _nginx_error(404, "Not Found"), "text/html", 404, "", []

    def _dsm_api(self, clean, qs, method, body, session, web_user, web_token,
                 web_row):
        """Scripted Synology DSM webapi/webman answers. Never executes input;
        planted/canary creds mint a sandboxed File Station session only."""
        api = (qs.get("api") or [""])[0]
        meth = (qs.get("method") or [""])[0]
        posted = {}
        if body:
            posted = urllib.parse.parse_qs(
                body.decode("latin-1", "replace"), keep_blank_values=True)
            api = api or (posted.get("api") or [""])[0]
            meth = meth or (posted.get("method") or [""])[0]

        if clean.startswith("/webman/login.cgi") and not (qs.get("css") or [""])[0]:
            set_cookie = web_token or self._issue_web_session(
                "", provisional=True)
            html = dsm.login_page_html(self.world, session_id=set_cookie)
            return html, "text/html; charset=utf-8", 200, set_cookie, []

        if clean.endswith("query.cgi") or api == "SYNO.API.Info":
            query = (qs.get("query") or posted.get("query") or ["all"])[0]
            payload = json.dumps(dsm.api_info_response(query))
            return payload, "application/json; charset=utf-8", 200, "", []

        if clean.endswith("auth.cgi") or api == "SYNO.API.Auth":
            if meth.lower() == "logout":
                return (json.dumps(dsm.auth_logout_response()),
                        "application/json; charset=utf-8", 200, "", [])
            account = ((qs.get("account") or posted.get("account")
                        or qs.get("username") or posted.get("username")
                        or [""])[0])
            passwd = ((qs.get("passwd") or posted.get("passwd")
                       or qs.get("password") or posted.get("password")
                       or [""])[0])
            if account or passwd:
                ok = self._record_password(session, "http", account, passwd)
                if ok:
                    session["username"] = account
                    set_cookie = self._issue_web_session(
                        account, provisional=False)
                    with self._lock:
                        row = self._web_sessions.get(set_cookie) or {}
                    resp = dsm.auth_login_response(
                        True, sid=row.get("sid"),
                        synotoken=row.get("synotoken"))
                    return (json.dumps(resp),
                            "application/json; charset=utf-8", 200,
                            set_cookie, [])
                resp = dsm.auth_login_response(False)
                set_cookie = web_token or self._issue_web_session(
                    "", provisional=True)
                return (json.dumps(resp),
                        "application/json; charset=utf-8", 200, set_cookie, [])
            return (json.dumps(dsm.auth_login_response(False)),
                    "application/json; charset=utf-8", 200, "", [])

        if clean.endswith("entry.cgi"):
            if not web_user:
                return (json.dumps(dsm.entry_need_auth()),
                        "application/json; charset=utf-8", 200, "", [])
            if api == "SYNO.Core.System" or meth.lower() in ("info", "get"):
                if "System" in api or meth.lower() == "info":
                    return (json.dumps(dsm.system_info(self.world)),
                            "application/json; charset=utf-8", 200, "", [])
            if (api.startswith("SYNO.FileStation")
                    or meth.lower() in ("list", "list_share")):
                folder = ((qs.get("folder_path") or posted.get("folder_path")
                           or ["/"])[0])
                if folder in ("/", ""):
                    return (json.dumps(dsm.entry_list_shares(self.world)),
                            "application/json; charset=utf-8", 200, "", [])
                return (json.dumps(dsm.filestation_list(
                            self.world, folder,
                            self.world.get("shares") or {})),
                        "application/json; charset=utf-8", 200, "", [])
            return (json.dumps(dsm.system_info(self.world)),
                    "application/json; charset=utf-8", 200, "", [])

        return (json.dumps({"success": False, "error": {"code": 105}}),
                "application/json; charset=utf-8", 404, "", [])


    def _finish(self, session):
        session["credential_count"] = len(session["credentials"])
        with self._lock:
            self.sessions.append(session)
            proto = session.get("protocol") or "?"
            self._stats["by_protocol"][proto] = self._stats["by_protocol"].get(proto, 0)
        self._write_local(session)
        self._write_status()
        self._report(session)
        session["gotcha_count"] = len(session.get("gotchas", []))
        taken = ", ".join(f.rsplit("/", 1)[1] for f in session["read_files"]) or "nothing"
        self._note("session %s from %s on port %d (%s): %d commands, read %s"
                   % (session["id"], session["peer_ip"], session["local_port"],
                      session.get("protocol"), len(session["commands"]), taken))

    def _write_local(self, session):
        try:
            folder = os.path.dirname(self.log_path)
            if folder and not os.path.isdir(folder):
                os.makedirs(folder)
            try:
                if os.path.exists(self.log_path) and os.path.getsize(self.log_path) > LOG_ROTATE_BYTES:
                    os.replace(self.log_path, self.log_path + ".1")
            except OSError:
                pass
            # Cap in-memory session history so a long-lived sensor cannot grow forever.
            with self._lock:
                if len(self.sessions) > 500:
                    self.sessions = self.sessions[-250:]
                if len(self.probes) > 1000:
                    self.probes = self.probes[-400:]
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(session, default=str) + "\n")
        except OSError:
            pass

    def _write_status(self):
        """Local probe counters so you can see the sensor is catching traffic."""
        now = time.time()
        if now - self._last_status_write < STATUS_WRITE_MIN_GAP:
            return
        self._last_status_write = now
        try:
            folder = os.path.dirname(self.status_path)
            if folder and not os.path.isdir(folder):
                os.makedirs(folder)
            with self._lock:
                payload = {
                    "sensor": self.name,
                    "bind": self.bind,
                    "ports": self.ports,
                    "updated": time.time(),
                    "uptime_seconds": round(time.time() - self._stats["started"], 1),
                    "probes_total": self._stats["probes_total"],
                    "by_port": dict(self._stats["by_port"]),
                    "by_protocol": dict(self._stats["by_protocol"]),
                    "auth_ok": self._stats["auth_ok"],
                    "auth_fail": self._stats["auth_fail"],
                    "sessions": len(self.sessions),
                    "recent": list(self._stats["recent"][-20:]),
                    "gotcha_total": self._stats["gotcha_total"],
                    "gotchas": list(self._stats["gotchas"][-20:]),
                    "guestbook_total": self._stats["guestbook_total"],
                    "guestbook": list(self._stats["guestbook"][-20:]),
                    "reveals_log": self.reveals_path,
                }
            temporary = self.status_path + ".tmp"
            with open(temporary, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
            os.replace(temporary, self.status_path)
        except OSError:
            pass

    def _report(self, session):
        if not self.console:
            return
        self._post("/api/report", {"kind": "session", "sensor": self.name,
                                   "session": session})

    def _register(self):
        if not self.console:
            return
        light = [{"id": t["id"], "kind": t["kind"], "label": t["label"]}
                 for t in self.tokens]
        self._post("/api/register", {"sensor": self.name, "tokens": light,
                                     "hostname": self.world["hostname"]})

    def _post(self, path, payload):
        try:
            data = json.dumps(payload).encode("utf-8")
            headers = {"Content-Type": "application/json",
                       "User-Agent": "python-urllib3/1.26"}
            if self.console_token:
                headers["X-Anglerfish-Token"] = self.console_token
            request = urllib.request.Request(
                self.console + path, data=data, headers=headers)
            urllib.request.urlopen(request, timeout=5).read()
        except Exception:
            pass

    def _note(self, text):
        line = "%s  %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), text)
        print(line, flush=True)


    def _serve_dns(self, port):
        """Minimal UDP DNS facade: log queries, return canned answers.

        Not enabled by default (not in DEFAULT_PORTS / live unit). Only listens
        when 53 or 5353 is passed on --ports. Never recursively resolves.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.bind, port))
            sock.settimeout(1.0)
        except OSError as exc:
            self._note("could not open DNS port %d: %s" % (port, exc))
            return
        self._note("listening on %s:%d (dns/udp)" % (self.bind, port))
        while self.running:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handle_dns(sock, data, addr, port)
            except Exception as exc:
                self._note("dns handler error: %s" % exc)
        sock.close()

    def _handle_dns(self, sock, data, addr, port):
        if len(data) < 12:
            return
        dns_id = struct.unpack("!H", data[0:2])[0]
        flags = struct.unpack("!H", data[2:4])[0]
        opcode = (flags >> 11) & 0xF
        qname, qtype, offset = _dns_parse_question(data)
        session = {
            "id": "%s-dns-%d-%d" % (self.name, int(time.time()), dns_id),
            "peer_ip": addr[0], "peer_port": addr[1],
            "local_port": port, "service": "dns", "protocol": "dns",
        }
        rcode = 0
        answers = b""
        ancount = 0
        if qname.lower().rstrip(".") == "version.bind" and qtype == 16:
            txt = "dnsmasq-2.85"
            rdata = bytes([len(txt)]) + txt.encode("ascii")
            answers = _dns_rr(qname, 16, 3, 60, rdata)  # CHAOS=3
            ancount = 1
        elif qtype == 252:  # AXFR — refuse
            rcode = 5
        elif qtype in (1, 255):  # A / ANY -> bait internal IP
            ip = self.world.get("internal_ip") or "10.0.0.21"
            parts = [int(x) for x in ip.split(".")]
            rdata = struct.pack("BBBB", *parts)
            answers = _dns_rr(qname, 1, 1, 60, rdata)
            ancount = 1
        else:
            rcode = 3  # NXDOMAIN
        try:
            self.events.emit(
                "dns", service="dns", session=session, transport="udp",
                dns_qname=qname, dns_qtype=qtype, dns_opcode=opcode,
                dns_rcode=rcode, dns_id=dns_id,
            )
        except Exception:
            pass
        resp_flags = 0x8400 | (opcode << 11) | rcode
        header = struct.pack("!HHHHHH", dns_id, resp_flags, 1, ancount, 0, 0)
        question = data[12:offset] if offset > 12 else data[12:]
        try:
            sock.sendto(header + question + answers, addr)
        except OSError:
            pass




def _dns_parse_question(data):
    """Return (qname, qtype, offset_after_question)."""
    labels = []
    i = 12
    while i < len(data):
        n = data[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0 == 0xC0:
            i += 2
            break
        labels.append(data[i + 1:i + 1 + n].decode("latin-1", "replace"))
        i += 1 + n
    qname = ".".join(labels)
    if i + 4 > len(data):
        return qname, 0, i
    qtype, _qclass = struct.unpack("!HH", data[i:i + 4])
    return qname, qtype, i + 4


def _dns_encode_name(name):
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii", "replace")[:63]
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _dns_rr(name, rtype, rclass, ttl, rdata):
    return (_dns_encode_name(name)
            + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata))
            + rdata)


def _event(kind, detail):
    return {"at": time.time(), "kind": kind, "detail": detail}


def _send(conn, text):
    _send_raw(conn, text.replace("\n", "\r\n").encode("latin-1", "replace")
              if "\r\n" not in text else text.encode("latin-1", "replace"))


def _send_raw(conn, data):
    try:
        conn.sendall(data)
    except OSError:
        pass


_PENDING = weakref.WeakKeyDictionary()


def _line(conn, pre=b""):
    buffer = bytearray(_PENDING.pop(conn, b""))
    if pre:
        buffer.extend(pre)
    while b"\n" not in buffer and len(buffer) < READ_LIMIT:
        try:
            chunk = conn.recv(256)
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buffer.extend(chunk)
    if b"\n" in buffer:
        raw = bytes(buffer)
        line, _, rest = raw.partition(b"\n")
        if rest:
            _PENDING[conn] = rest
        return line.decode("latin-1", "replace").rstrip("\r")
    return bytes(buffer).decode("latin-1", "replace").rstrip("\r")

def _http_head_and_body(conn, first):
    # Allow a larger head so over-long URIs can fire a 414 instead of being
    # silently truncated. Body remains capped at READ_LIMIT.
    head_cap = max(READ_LIMIT, MAX_URI_LEN + 2048)
    data = bytearray(first)
    while b"\r\n\r\n" not in data and len(data) < head_cap:
        try:
            chunk = conn.recv(min(2048, head_cap - len(data)))
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        data.extend(chunk)
        if b"\r\n" not in data and len(data) > MAX_URI_LEN + 32:
            break
    raw = bytes(data)
    if b"\r\n\r\n" not in raw:
        return raw, b""
    head, body = raw.split(b"\r\n\r\n", 1)
    length = None
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            try:
                length = int(line.split(b":", 1)[1].strip() or b"0")
            except ValueError:
                length = None
            break
    if length is None or length < 0:
        return head, body
    if length > READ_LIMIT:
        length = READ_LIMIT
    body = bytearray(body)
    while len(body) < length:
        try:
            chunk = conn.recv(min(256, length - len(body)))
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        body.extend(chunk)
    return head, bytes(body[:length])


def _client_looks_like_http(conn):
    ready, _write, _err = select.select([conn], [], [], HTTP_GLANCE)
    if not ready:
        return False
    try:
        peeked = conn.recv(8, socket.MSG_PEEK)
    except OSError:
        return False
    return _looks_like_http(peeked)


def _read_prelude(conn):
    conn.settimeout(PRELUDE_WAIT)
    buf = bytearray()
    try:
        while len(buf) < 512:
            try:
                chunk = conn.recv(256)
            except socket.timeout:
                break
            if not chunk:
                break
            buf.extend(chunk)
            if b"\n" in buf:
                break
            if buf and not (b"SSH-".startswith(bytes(buf)) or buf.startswith(b"SSH-")):
                break
    finally:
        conn.settimeout(SESSION_IDLE)
    return bytes(buf)


def _form_user_pass(posted):
    user = pw = None
    for pair in posted.split("&"):
        if "=" not in pair:
            continue
        key, value = pair.split("=", 1)
        key = urllib.parse.unquote_plus(key).lower()
        value = urllib.parse.unquote_plus(value)
        if "user" in key and user is None:
            user = value
        if "pass" in key and pw is None:
            pw = value
    return user, pw


def _form_has_login(posted):
    user, pw = _form_user_pass(posted)
    return bool(user or pw)


def _looks_like_http(data):
    return data[:8].split(b" ", 1)[0] in (b"GET", b"POST", b"HEAD", b"PUT",
                                          b"OPTIONS", b"DELETE")


def _resolve(cwd, arg):
    if arg.startswith("/"):
        path = arg
    else:
        path = cwd.rstrip("/") + "/" + arg
    parts = []
    for piece in path.split("/"):
        if piece in ("", "."):
            continue
        if piece == "..":
            if parts:
                parts.pop()
            continue
        parts.append(piece)
    return "/" + "/".join(parts)


def _short(path, username="deploy"):
    home = "/home/%s" % (username if username in ("deploy", "admin") else "deploy")
    if path == home:
        return "~"
    if path.startswith(home + "/"):
        return "~" + path[len(home):]
    return path


def _resolve_share_path(rel, files, shares):
    """Map a /files/... URL path onto a bait filesystem path.

    Only paths under /srv/shares/<share>/ are served. Never /etc, /root, or
    arbitrary bait files outside the share tree — that was a fingerprint and a
    story break (File Station does not export /etc/passwd).
    """
    rel = urllib.parse.unquote(rel).lstrip("/")
    if not rel or ".." in rel.split("/"):
        return ""
    parts = [p for p in rel.split("/") if p]
    if not parts:
        return ""
    share = parts[0]
    if share not in shares:
        return ""
    candidate = "/srv/shares/" + "/".join(parts)
    if candidate in files:
        return candidate
    # Allow bare leaf within that share only.
    if len(parts) == 2:
        leaf = parts[1]
        for row in shares[share]:
            if row["name"] == leaf:
                return row["path"]
    return ""


def _status_json(world, ports):
    shares = world.get("shares") or {}
    boot = world.get("boot_time") or (time.time() - 47 * 86400)
    uptime_days = int(max(0, (time.time() - boot) // 86400))
    payload = {
        "hostname": world["hostname"],
        "fqdn": world.get("fqdn"),
        "company": world.get("company"),
        "model": world.get("nas_model") or "DS220+",
        "firmware": world.get("nas_firmware") or "5.0.1.2376",
        "ip": world.get("internal_ip") or "10.0.0.21",
        "uptime_days": uptime_days,
        "shares_ok": True,
        "shares": sorted(shares.keys()),
        "services": {
            "nginx": "active",
            "sshd": "active",
            "postfix": "active",
            "vsftpd": "active",
            "php-fpm": "active",
        },
        # Advertise the real service ports a NAS would show, not the high-port
        # classroom remaps the sensor may be listening on.
        "listen_ports": [22, 80, 443, 25, 21],
    }
    return json.dumps(payload, indent=2) + "\n"


def _host_of(console):
    if not console:
        return ""
    host = console
    for prefix in ("http://", "https://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
    return host.rstrip("/")


def _fake_processes():
    return (
        "  PID TTY          TIME CMD\n"
        "    1 ?        00:00:02 systemd\n"
        "  512 ?        00:00:01 sshd\n"
        " 1042 ?        00:00:03 nginx\n"
        " 1043 ?        00:00:00 nginx\n"
        " 1088 ?        00:04:17 puma\n"
        " 1129 ?        00:00:41 postgres\n"
        " 1201 ?        00:00:12 postfix\n"
        " 1210 ?        00:00:02 qmgr\n"
        " 1304 ?        00:00:01 vsftpd\n"
        " 2231 pts/0    00:00:00 bash\n"
        " 2240 pts/0    00:00:00 ps")


def _fake_netstat(ports=None):
    ports = ports or DEFAULT_PORTS
    lines = [
        "Active Internet connections (only servers)",
        "Proto Local Address           Foreign Address         State",
        "tcp   0.0.0.0:22              0.0.0.0:*               LISTEN",
        "tcp   0.0.0.0:80              0.0.0.0:*               LISTEN",
        "tcp   0.0.0.0:25              0.0.0.0:*               LISTEN",
        "tcp   0.0.0.0:21              0.0.0.0:*               LISTEN",
        "tcp   127.0.0.1:5432         0.0.0.0:*               LISTEN",
        "tcp   0.0.0.0:443            0.0.0.0:*               LISTEN",
    ]
    for p in ports:
        if p not in (22, 80, 25, 21, 443):
            lines.append("tcp   0.0.0.0:%-5d          0.0.0.0:*               LISTEN" % p)
    return "\n".join(lines)


def _fake_ifconfig():
    return (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "        inet 10.0.0.21  netmask 255.255.255.0  broadcast 10.0.0.255\n"
        "        ether 06:3a:1f:9c:2d:88  txqueuelen 1000  (Ethernet)\n"
        "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
        "        inet 127.0.0.1  netmask 255.0.0.0")


def _fake_df():
    return (
        "Filesystem      Size  Used Avail Use% Mounted on\n"
        "/dev/root        79G   48G   28G  64% /\n"
        "tmpfs           1.9G     0  1.9G   0% /dev/shm\n"
        "/dev/xvda15     105M  6.1M   99M   6% /boot/efi")


def _fake_free():
    return (
        "               total        used        free      shared  buff/cache   available\n"
        "Mem:         3923056      812440     1240880        2144     1869736     2861124\n"
        "Swap:              0           0           0")


def _fake_last():
    return (
        "deploy   pts/0        10.0.0.14        %s - %s  (01:02)\n"
        "deploy   pts/0        10.0.0.14        %s - %s  (00:18)\n"
        "reboot   system boot  5.15.0-101-gener %s   still running\n"
        % (time.strftime("%a %b %e %H:%M"), time.strftime("%H:%M"),
           time.strftime("%a %b %e %H:%M", time.localtime(time.time() - 86400)),
           time.strftime("%H:%M", time.localtime(time.time() - 86400 + 1080)),
           time.strftime("%a %b %e %H:%M", time.localtime(time.time() - 47 * 86400)))
    )


def _fake_env(world):
    return (
        "SHELL=/bin/bash\n"
        "PWD=/home/deploy\n"
        "LOGNAME=deploy\n"
        "HOME=/home/deploy\n"
        "USER=deploy\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        "LANG=en_US.UTF-8\n"
        "HOSTNAME=%s\n"
        % world["hostname"]
    )




def _http_response(code, ctype, payload, head_only=False, extra=""):
    statuses = {
        200: "200 OK", 204: "204 No Content", 302: "302 Found",
        400: "400 Bad Request", 401: "401 Unauthorized", 403: "403 Forbidden",
        404: "404 Not Found",
        405: "405 Method Not Allowed",
        414: "414 Request-URI Too Large",
        500: "500 Internal Server Error",
    }
    status = statuses.get(code, "%d" % code)
    date = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    headers = ("HTTP/1.1 %s\r\n"
               "Server: %s\r\n"
               "Date: %s\r\n"
               "Content-Type: %s\r\n"
               "Content-Length: %d\r\n"
               "Connection: close\r\n"
               "%s\r\n" % (status, bait.HTTP_SERVER, date, ctype, len(payload), extra))
    if head_only:
        return headers.encode("ascii", "replace")
    return headers.encode("ascii", "replace") + payload


def _nginx_error(code, reason):
    body = (
        "<html>\r\n<head><title>%d %s</title></head>\r\n"
        "<body>\r\n<center><h1>%d %s</h1></center>\r\n"
        "<hr><center>%s</center>\r\n"
        "</body>\r\n</html>\r\n" % (code, reason, code, reason, bait.HTTP_SERVER)
    )
    return body.encode("ascii")


def _tag_http_exploit(session, path, body):
    """Tag real exploitation shapes as T1190 instead of generic recon."""
    text = ("%s %s" % (path or "", body or "")).lower()
    markers = (
        ("${jndi:", "log4j JNDI"),
        ("../", "path traversal"),
        ("..%2f", "path traversal"),
        ("/etc/passwd", "path traversal"),
        ("/.env", "dotenv probe"),
        ("/wp-login.php", "wordpress probe"),
        ("/cgi-bin/", "cgi probe"),
        ("() {", "shellshock"),
        ("/vendor/phpunit", "phpunit rce probe"),
        ("/actuator", "spring actuator probe"),
    )
    for needle, label in markers:
        if needle in text:
            session.setdefault("events", []).append(
                _event("http-exploit", "%s (%s)" % (label, (path or "")[:80])))
            return

def _login_page(world, failed=False):
    company = world.get("company") or "Example Clinic"
    model = world.get("nas_model") or "DS220+"
    firmware = world.get("nas_firmware") or "5.0.1.2376"
    host = world.get("hostname") or "files01"
    brand = "%s NAS" % (company.split()[0] if company else "File")
    error = ""
    if failed:
        error = "<p class=err>The username or password was not recognised.</p>"
    return (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<title>%s</title><style>"
        "body{margin:0;background:#e6e6e6;font-family:Verdana,sans-serif;color:#222}"
        ".top{background:#4a4a4a;color:#fff;padding:14px 22px}"
        ".top b{font-size:18px}.top span{float:right;font-size:12px;color:#ccc;padding-top:4px}"
        ".card{width:360px;margin:48px auto;background:#fff;border:1px solid #c8c8c8}"
        ".card h1{font-size:15px;font-weight:normal;margin:0;padding:12px 16px;"
        "background:#f3f3f3;border-bottom:1px solid #ddd}"
        "form{padding:8px 16px 18px}label{display:block;font-size:12px;margin:12px 0 4px}"
        "input{width:100%%;padding:7px;box-sizing:border-box;border:1px solid #bbb}"
        "button{margin-top:16px;background:#5c6b73;color:#fff;border:0;padding:8px 18px}"
        ".err{color:#8a2a2a;font-size:12px;padding:10px 16px 0}"
        ".foot{text-align:center;color:#888;font-size:11px}"
        "</style></head><body>"
        "<div class=top><b>%s</b><span>%s &nbsp; firmware %s &nbsp; %s</span></div>"
        "<div class=card><h1>Sign in</h1>"
        "%s"
        "<form method=post action=/>"
        "<label>Username</label><input name=username autocomplete=username autofocus>"
        "<label>Password</label><input name=password type=password autocomplete=current-password>"
        "<button type=submit>Log in</button></form></div>"
        "<p class=foot>%s &middot; internal storage on %s</p>"
        "</body></html>"
    ) % (brand, brand, model, firmware, host, error, company, host)


def _not_found_page(world):
    return (
        "<!doctype html><html><head><meta charset=utf-8><title>Not found</title></head>"
        "<body style='font-family:Verdana,sans-serif;padding:24px'>"
        "<h1 style='font-size:16px'>File not found</h1>"
        "<p><a href='/files/'>Back to File Station</a></p></body></html>"
    )


def _guestbook_form(signed=False):
    thanks = ""
    if signed:
        thanks = "<p style='color:#2a6a2a;font-size:13px'>Signed. Thanks for stopping by.</p>"
    return (
        "<div style='background:#fff;border:1px solid #ccc;padding:12px 16px;margin:16px 0'>"
        "<b style='font-size:13px'>Guestbook</b>"
        "<p class=meta>Found what you were looking for? Leave an &lsquo;I was here&rsquo; "
        "for the next visitor (IT share &rsaquo; guestbook.txt).</p>"
        + thanks +
        "<form method=post action=/guestbook>"
        "<input name=note maxlength=500 style='width:70%;padding:6px;border:1px solid #bbb'> "
        "<button type=submit style='background:#5c6b73;color:#fff;border:0;padding:7px 14px'>"
        "Sign</button></form></div>"
    )


def _dashboard_page(world, guestbook_form=False, signed=False):
    company = world.get("company") or "Example Clinic"
    host = world.get("hostname") or "files01"
    model = world.get("nas_model") or "DS220+"
    firmware = world.get("nas_firmware") or "5.0.1.2376"
    shares = world.get("shares") or {}
    sections = []
    for share in sorted(shares.keys()):
        rows = []
        for row in shares[share]:
            href = "/files/%s/%s" % (share, row["name"])
            rows.append(
                "<tr><td><a href='%s'>%s</a></td><td>%s</td><td>%d B</td></tr>"
                % (href, row["name"], row["path"], row["size"])
            )
        sections.append(
            "<h2 style='font-size:14px;font-weight:normal;margin:22px 0 8px'>"
            "Share: <b>%s</b></h2>"
            "<table><tr><th>Name</th><th>Path</th><th>Size</th></tr>%s</table>"
            % (share, "".join(rows))
        )
    return (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<title>File Station — %s</title>"
        "<style>body{margin:0;background:#e6e6e6;font-family:Verdana,sans-serif;color:#222}"
        ".top{background:#4a4a4a;color:#fff;padding:14px 22px}.top b{font-size:18px}"
        ".top span{float:right;font-size:12px;color:#ccc;padding-top:4px}"
        ".wrap{margin:24px}table{background:#fff;border-collapse:collapse;width:100%%;"
        "border:1px solid #ccc}td,th{text-align:left;padding:8px 10px;border-bottom:1px solid #eee;"
        "font-size:13px}th{background:#f3f3f3;font-weight:normal}"
        "a{color:#1a4f72;text-decoration:none}"
        ".meta{color:#555;font-size:13px}</style></head><body>"
        "<div class=top><b>%s NAS</b><span>%s &nbsp; firmware %s &nbsp; %s</span></div>"
        "<div class=wrap><h1 style='font-size:16px;font-weight:normal'>File Station</h1>"
        "<p class=meta>%s shared folders on <code>%s</code>. "
        "Health: <a href='/api/status'>/api/status</a>. Handle exports with care.</p>"
        "%s%s</div></body></html>"
    ) % (host, company, model, firmware, host, company, host,
         _guestbook_form(signed) if guestbook_form else "", "".join(sections))
