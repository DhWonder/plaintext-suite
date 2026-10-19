"""
The console: one place to watch everything your sensors see.

Deploy a sensor on a few machines and each one records what happens to it. This
is where they all report, so you watch every attacker across every sensor from
one screen instead of reading log files on scattered boxes.

It is worth being exact about what this is, because it is the shape of a thing
that has a bad name. A command-and-control server controls machines that are
not yours, without permission, to do harm. This does the opposite in every way
that matters: the agents reporting in are your own sensors, on your own
machines, that you deployed on purpose, and all they send is a record of what
somebody did to them. The console never sends a command back to anything. It
receives, it stores, it shows. Reports flow one way, inward.

One thing does leave, and only if you ask for it: the console can email you
when a sensor is touched or a token fires. That is the console sending you a
summary of what it was told, not the console reaching out to anything else.
The sensors themselves never send mail, deliberately, because a honeypot is a
machine you have decided to treat as untrusted and it has no business holding
a mail password.

It also catches the tokens. Every piece of bait a sensor plants carries a
canary token, and each token can point at this console. If an attacker takes a
fake credential and later uses it somewhere that touches the token, the token
calls here, and you learn that the bait was used and roughly from where. That is
how you follow an attacker's activity without ever going near their machine:
you left something that phones you, and it did.

Standard library only. Binds to localhost unless you say otherwise, because a
list of who is attacking you is not something to expose by accident.
"""

import json
import os
import posixpath
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

from . import analyze as analyze_module
from . import reputation as reputation_module
from . import store as store_module


class Console(object):
    def __init__(self, db_path, notifier=None, reputation_keys=None, shared_token=""):
        self.store = store_module.Store(db_path)
        self.db_path = db_path
        self.notifier = notifier
        # Keys live here and only here. A sensor sits where attackers can reach
        # it, so it holds no key and makes no lookup; the console does the
        # asking and the sensors never know it happened.
        self.reputation_keys = reputation_keys
        # Shared token the sensor must present on /api/report and /api/register.
        # Empty means "accept anything" (local demos); set it for real deploys.
        self.shared_token = shared_token or ""
        self.lock = threading.Lock()

    # ------------------------------------------------------------------
    def enrich_attackers(self, overview, limit=8):
        """Say, for each attacker, whether you were swept up or picked out.

        A honeypot session is already proof of somebody doing what they should
        not. What the databases add is the one thing the session cannot say:
        whether this address knocks on every door on the internet, or whether
        it came looking for you. Those two lead completely different places.
        """
        if self.reputation_keys is None:
            return overview

        checker = reputation_module.Checker(keys=self.reputation_keys,
                                            store=self.store)
        addresses = [a["peer_ip"] for a in overview.get("top_attackers", [])][:limit]
        try:
            found = checker.enrich(addresses)
        except Exception:
            return overview

        for attacker in overview.get("top_attackers", []):
            result = found.get(attacker["peer_ip"])
            if not result:
                continue
            headline, sentence, attention = reputation_module.honeypot_verdict(result)
            attacker["reputation"] = {
                "level": result.get("level", "unknown"),
                "scanner": result.get("scanner", ""),
                "headline": headline,
                "sentence": sentence,
                "attention": attention,
                "sources": [
                    {"source": r.get("source", ""), "why": r.get("why", ""),
                     "known": bool(r.get("known")), "benign": bool(r.get("benign")),
                     "ok": bool(r.get("ok"))}
                    for r in result.get("sources", []) if not r.get("skipped")
                ],
            }
        overview["reputation_coverage"] = checker.coverage()
        return overview

    # ------------------------------------------------------------------
    def all_session_details(self, limit=500):
        """Every stored session as its full detail dict, for analysis."""
        out = []
        for row in self.store.sessions(limit=limit):
            full = self.store.session(row["id"])
            if full:
                full.setdefault("id", row["id"])
                full.setdefault("sensor", row.get("sensor", ""))
                out.append(full)
        return out

    def audit(self, limit=500):
        return analyze_module.audit(self.all_session_details(limit=limit))

    def graffiti(self, limit=500):
        """Just the 'I was here' wall, newest first."""
        return self.audit(limit=limit).get("graffiti_wall", [])

    def register(self, payload):
        sensor = payload.get("sensor", "unknown")
        self.store.upsert_sensor(sensor, payload.get("hostname", ""))
        for token in payload.get("tokens", []):
            self.store.add_token(token["id"], sensor, token.get("kind", ""),
                                 token.get("label", ""))
        return {"ok": True}

    def report(self, payload):
        """A sensor telling the console what happened to it.

        An unrecognised report is refused rather than answered with ok. Saying
        "fine" to something you then throw away is how a sensor ends up
        reporting into a void for a month while the console shows nothing, and
        nobody finds out until they need the record.
        """
        kind = payload.get("kind")
        if kind != "session":
            return {"ok": False,
                    "error": "This console only takes reports of kind 'session'. "
                             "It was sent %s." % (repr(kind) if kind else "nothing")}
        if not payload.get("sensor") or not payload.get("session"):
            return {"ok": False,
                    "error": "A session report needs both 'sensor' and 'session'."}

        self.store.save_session(payload["sensor"], payload["session"])
        self._notify_session(payload["sensor"], payload["session"])
        return {"ok": True}

    def token_triggered(self, token_id, source_ip, detail=""):
        """A planted token was just used. This is the moment worth having."""
        token = self.store.token(token_id)
        self.store.record_trigger(token_id, source_ip, detail)
        self._notify_trigger(token, token_id, source_ip, detail)
        return token

    # -- telling you about it ------------------------------------------
    def _notify_session(self, sensor, session):
        """Somebody connected to a honeypot. Nobody legitimate does that.

        One email per address per sensor per quiet period. A scanner that
        knocks two hundred times in an hour is one fact, not two hundred, and
        the console is still recording every one of them either way.
        """
        if self.notifier is None or not self.notifier.available:
            return
        peer = session.get("peer_ip", "unknown")
        key = "anglerfish-session:%s:%s" % (sensor, peer)
        if not self.notifier.allow(key, gap_seconds=3600):
            return

        commands = session.get("commands") or []
        credentials = session.get("credentials") or []
        files = session.get("read_files") or []

        lines = ["Somebody connected to the honeypot. Nobody has a legitimate",
                 "reason to, so this is either a scanner or somebody inside your",
                 "network having a look around.", ""]
        lines.append("They stayed %s seconds and typed %d command(s)."
                     % (session.get("duration", 0), len(commands)))
        if credentials:
            lines.append("")
            lines.append("Logins they tried:")
            for item in credentials[:5]:
                if item.get("username") is not None:
                    lines.append("  %s / %s" % (item.get("username", ""),
                                                item.get("password", "")))
                else:
                    lines.append("  %s" % str(item.get("raw", ""))[:80])
            if len(credentials) > 5:
                lines.append("  and %d more" % (len(credentials) - 5))
        if commands:
            lines.append("")
            lines.append("What they typed:")
            for line in commands[:10]:
                lines.append("  %s" % str(line)[:100])
            if len(commands) > 10:
                lines.append("  and %d more" % (len(commands) - 10))
        if files:
            lines.append("")
            lines.append("Bait they read: %s"
                         % ", ".join(str(f).rsplit("/", 1)[-1] for f in files[:8]))
        lines.append("")
        lines.append("Nothing they typed was run. The whole session is in the console:")
        lines.append("  python3 anglerfish_cli.py report")

        self.notifier.send_async(
            "%s connected to anglerfish sensor %s" % (peer, sensor),
            lines,
            context={"sensor": sensor, "source": peer,
                     "port": session.get("local_port", ""),
                     "protocol": session.get("protocol", "")})

    def _notify_trigger(self, token, token_id, source_ip, detail):
        """A piece of bait was used somewhere else. This is the big one.

        A connection to the sensor means somebody knocked. A token firing
        means they took a fake credential away and tried it, which is a much
        later and much more serious point in the story, so the quiet period is
        short and the subject line says so plainly.
        """
        if self.notifier is None or not self.notifier.available:
            return
        label = (token or {}).get("label") or token_id
        sensor = (token or {}).get("sensor") or "unknown sensor"
        lines = ["A canary token was just used.", "",
                 "This is bait: a fake credential planted on the honeypot, that",
                 "exists for no reason except to be stolen. Somebody has taken it",
                 "and tried to use it, so they had access to that machine and are",
                 "now working through what they found on it.", "",
                 "Bait:    %s" % label,
                 "Kind:    %s" % ((token or {}).get("kind") or "unknown"),
                 "Used by: %s" % source_ip,
                 "Seen as: %s" % (detail or "no other detail"), "",
                 "Nothing was reached into to learn this. The token called here.",
                 "Treat the sensor's network as compromised until you know better."]
        self.notifier.send_async(
            "canary token used: %s" % label, lines,
            key="anglerfish-token:%s" % token_id, gap_seconds=300,
            context={"sensor": sensor, "source": source_ip, "token": token_id})


class Handler(BaseHTTPRequestHandler):
    server_version = "nginx"
    console = None
    ui_path = None

    def log_message(self, fmt, *args):
        pass

    # ------------------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = posixpath.normpath(unquote(parsed.path))
        try:
            if path in ("/", "/index.html"):
                return self._serve_ui()
            if path == "/api/overview":
                return self._json(self.console.enrich_attackers(
                    self.console.store.overview()))
            if path == "/api/sessions":
                return self._json({"sessions": self.console.store.sessions(limit=200)})
            if path.startswith("/api/session/"):
                found = self.console.store.session(path.rsplit("/", 1)[1])
                if found:
                    try:
                        found["analysis"] = analyze_module.analyze_session(found)
                    except Exception as exc:
                        found["analysis"] = {"error": str(exc)}
                return self._json(found or {"error": "no such session"},
                                  200 if found else 404)
            if path == "/api/analysis":
                return self._json(self.console.audit())
            if path == "/api/graffiti":
                return self._json({"graffiti": self.console.graffiti()})
            if path == "/api/tokens":
                return self._json({"tokens": self.console.store.tokens()})
            if path == "/api/triggers":
                return self._json({"triggers": self.console.store.triggers()})

            # The beacon. A token calling home lands here. It is a GET because
            # it has to work when something as dumb as an image tag loads it.
            if path.startswith("/t/"):
                return self._beacon(path.rsplit("/", 1)[1])

            return self._json({"error": "no such endpoint"}, 404)
        except BrokenPipeError:
            return
        except Exception as exc:
            return self._json({"error": "%s: %s" % (type(exc).__name__, exc)}, 500)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = posixpath.normpath(unquote(parsed.path))
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except ValueError:
            return self._json({"error": "not valid JSON"}, 400)

        try:
            if path in ("/api/register", "/api/report"):
                if not self._token_ok():
                    return self._json({"error": "unauthorized"}, 401)
            if path == "/api/register":
                return self._json(self.console.register(payload))
            if path == "/api/report":
                return self._json(self.console.report(payload))
            return self._json({"error": "no such endpoint"}, 404)
        except Exception as exc:
            return self._json({"error": "%s: %s" % (type(exc).__name__, exc)}, 500)

    def _token_ok(self):
        expected = getattr(self.console, "shared_token", "") or ""
        if not expected:
            return True
        got = self.headers.get("X-Anglerfish-Token", "")
        return got == expected

    # ------------------------------------------------------------------
    def _beacon(self, token_id):
        # Never trust X-Forwarded-For here: anyone can forge it and poison the
        # trigger log. The TCP peer is the only source we record; if you put
        # the console behind a reverse proxy, set ANGLERFISH_TRUST_PROXY=1 and we
        # will honour the header from that peer only.
        source = self.client_address[0]
        if os.environ.get("ANGLERFISH_TRUST_PROXY") == "1":
            forwarded = self.headers.get("X-Forwarded-For", "")
            if forwarded:
                source = forwarded.split(",")[0].strip() or source
        detail = self.headers.get("User-Agent", "")[:200]
        token = self.console.token_triggered(token_id, source, detail)

        # Answer with something that looks like nothing, so whoever is holding
        # the token learns nothing from the reply. A 1x1 gif is the classic.
        pixel = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00"
                 b"!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01"
                 b"\x00\x00\x02\x02D\x01\x00;")
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Content-Length", str(len(pixel)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(pixel)

    def _serve_ui(self):
        if not self.ui_path or not os.path.exists(self.ui_path):
            body = ("<h1>anglerfish console</h1><p>The browser view was not found. "
                    "The API is up: try /api/overview.</p>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        with open(self.ui_path, "rb") as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload, code=200):
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def serve(db_path, host="127.0.0.1", port=8770, ui_path=None, notifier=None,
          reputation_keys=None, shared_token=""):
    console = Console(db_path, notifier=notifier, reputation_keys=reputation_keys,
                      shared_token=shared_token)
    handler = type("Bound", (Handler,), {"console": console, "ui_path": ui_path})
    httpd = ThreadingHTTPServer((host, port), handler)

    if host not in ("127.0.0.1", "localhost", "::1"):
        print()
        print("  WARNING: the console is listening on %s, not just this machine." % host)
        print("  This is the list of who is attacking you and the bait you planted.")
        print("  Only do this on a network you control, behind something that limits")
        print("  who can reach it, and stop it when you are done.")
        print()

    where = "http://%s:%d/" % (host if host != "0.0.0.0" else "127.0.0.1", port)
    print("anglerfish console at %s" % where)
    print("Database: %s" % db_path)
    print("Point sensors at it with:  --console %s" % where.rstrip("/"))
    if notifier is not None and notifier.enabled:
        print(notifier.describe())
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        httpd.server_close()
        console.store.close()
