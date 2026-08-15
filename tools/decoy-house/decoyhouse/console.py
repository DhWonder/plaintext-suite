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

from . import store as store_module


class Console(object):
    def __init__(self, db_path):
        self.store = store_module.Store(db_path)
        self.db_path = db_path
        self.lock = threading.Lock()

    def register(self, payload):
        sensor = payload.get("sensor", "unknown")
        self.store.upsert_sensor(sensor, payload.get("hostname", ""))
        for token in payload.get("tokens", []):
            self.store.add_token(token["id"], sensor, token.get("kind", ""),
                                 token.get("label", ""))
        return {"ok": True}

    def report(self, payload):
        if payload.get("kind") == "session":
            self.store.save_session(payload["sensor"], payload["session"])
        return {"ok": True}

    def token_triggered(self, token_id, source_ip, detail=""):
        """A planted token was just used. This is the moment worth having."""
        token = self.store.token(token_id)
        self.store.record_trigger(token_id, source_ip, detail)
        return token


class Handler(BaseHTTPRequestHandler):
    server_version = "decoy-house console"
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
                return self._json(self.console.store.overview())
            if path == "/api/sessions":
                return self._json({"sessions": self.console.store.sessions(limit=200)})
            if path.startswith("/api/session/"):
                found = self.console.store.session(path.rsplit("/", 1)[1])
                return self._json(found or {"error": "no such session"},
                                  200 if found else 404)
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
            if path == "/api/register":
                return self._json(self.console.register(payload))
            if path == "/api/report":
                return self._json(self.console.report(payload))
            return self._json({"error": "no such endpoint"}, 404)
        except Exception as exc:
            return self._json({"error": "%s: %s" % (type(exc).__name__, exc)}, 500)

    # ------------------------------------------------------------------
    def _beacon(self, token_id):
        source = self.headers.get("X-Forwarded-For", "") or self.client_address[0]
        source = source.split(",")[0].strip()
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
            body = ("<h1>decoy-house console</h1><p>The browser view was not found. "
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


def serve(db_path, host="127.0.0.1", port=8770, ui_path=None):
    console = Console(db_path)
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
    print("decoy-house console at %s" % where)
    print("Database: %s" % db_path)
    print("Point sensors at it with:  --console %s" % where.rstrip("/"))
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        httpd.server_close()
        console.store.close()
