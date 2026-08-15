"""
A small web server so the browser view can read the database.

This exists so the same page can show you a capture from last month and the
traffic going past right now, without either of them being a different tool.

It binds to 127.0.0.1 on purpose. This thing can show you every address talking
to a machine, which is exactly the sort of thing that should not be reachable
from the network by accident. Binding it anywhere else takes an explicit flag
and prints a warning, because if you are going to do that you should have to
mean it.

Standard library only. No framework, no dependencies, nothing to keep updated.
"""

import json
import os
import posixpath
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from . import analyse, capture, live, store as store_module

HERE = os.path.dirname(os.path.abspath(__file__))

# Where the browser page might be sitting, in order of preference.
# Where the browser page might be sitting, in order of preference. The tool has
# to work whether it is run from inside the project, from a copy of just this
# folder, or from wherever somebody unpacked it.
UI_CANDIDATES = [
    os.path.join(HERE, "..", "web", "traffic-analyzer.html"),
    os.path.join(HERE, "..", "traffic-analyzer.html"),
    os.path.join(HERE, "..", "..", "..", "website", "traffic-analyzer.html"),
    os.path.join(HERE, "..", "..", "..", "..", "website", "traffic-analyzer.html"),
]


def find_ui():
    for path in UI_CANDIDATES:
        full = os.path.abspath(path)
        if os.path.exists(full):
            return full
    return None


class State(object):
    """Everything the request handlers need, in one place."""

    def __init__(self, db_path, ui_path=None, allow_live=True, monitor=None):
        # A capture may already be running, started before the server came up.
        # In that case share its database handle rather than opening a second.
        self.store = monitor.store if monitor is not None and monitor.store else \
            store_module.Store(db_path)
        self.db_path = db_path
        self.ui_path = ui_path or find_ui()
        self.allow_live = allow_live
        self.monitor = monitor
        self.lock = threading.Lock()

    # -- live control ---------------------------------------------------
    def start_live(self, interface, log_path=None, note=""):
        with self.lock:
            if self.monitor is not None and self.monitor.running:
                return {"ok": False, "error": "A live capture is already running."}
            monitor = live.LiveMonitor(interface, store=self.store,
                                       log_path=log_path, note=note)
            monitor.start_background()
            self.monitor = monitor

        # Give it a moment so an immediate permission failure is reported here
        # rather than silently leaving a dead capture behind.
        for _ in range(20):
            if monitor.running or monitor.error:
                break
            time.sleep(0.05)
        if monitor.error:
            return {"ok": False, "error": monitor.error}
        return {"ok": True, "session_id": monitor.session_id, "interface": interface}

    def stop_live(self):
        with self.lock:
            monitor = self.monitor
        if monitor is None or not monitor.running:
            return {"ok": False, "error": "Nothing is running."}
        monitor.stop()
        monitor.join(5.0)
        return {"ok": True, "session_id": monitor.session_id}

    def live_source(self, ip):
        """Everything known about one address in the capture running right now.

        The live analysis lives in the monitor's own analyzer, in memory, not in
        the database yet, so the browser cannot reach it the way it reaches a
        saved session. Without this the detail panel for a live address came back
        empty and the page said "nothing recorded for that address", which is the
        one moment you most want to know what it is doing.
        """
        with self.lock:
            monitor = self.monitor
        if monitor is None or monitor.analyzer is None:
            return {"detail": None, "related": {}, "rule": None,
                    "error": "No live capture is running."}
        analyzer = monitor.analyzer
        with monitor._lock:
            detail = analyzer.detail(ip)
            if detail is None:
                return {"detail": None, "related": {}, "rule": None}
            rows = analyzer.rows()
            related = analyzer.context_for(ip, rows=rows)
        row = next((r for r in rows if r["ip"] == ip), None)
        rule = list(analyse.rule_for(row)) if row is not None else None
        return {"detail": detail, "related": related, "rule": rule}

    def import_file(self, path, note=""):
        if not os.path.exists(path):
            return {"ok": False, "error": "No such file: %s" % path}
        analyzer = analyse.Analyzer()
        analyzer.origin = os.path.basename(path)
        stats = capture.ReadStats()
        try:
            for packet in capture.read_packets(path, stats):
                analyzer.ingest(packet["ts"], packet)
        except capture.CaptureError as exc:
            return {"ok": False, "error": str(exc)}
        if not analyzer.total_packets:
            return {"ok": False, "error": stats.explain() or "Nothing usable in that file."}
        analyzer.names = stats.names
        rows = analyzer.rows()
        summary = analyzer.summarise(rows=rows)
        summary["read"] = read_stats_dict(stats)
        session_id = self.store.record_analysis(os.path.basename(path), "file",
                                                analyzer, summary, rows, note)
        return {"ok": True, "session_id": session_id,
                "packets": analyzer.total_packets, "sources": len(analyzer.sources)}


def read_stats_dict(stats):
    return {
        "format": stats.format,
        "compressed": stats.compressed,
        "frames": stats.frames,
        "used": stats.used,
        "truncated": stats.truncated,
        "skipped": stats.skipped,
        "interfaces": stats.interfaces,
        "link_types": {str(k): v for k, v in stats.link_types.items()},
        "explain": stats.explain(),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "traffic-analyzer"
    state = None                      # set on the server instance

    # Quieten the default logging, it writes a line per request to stderr.
    def log_message(self, fmt, *args):
        pass

    # ------------------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = posixpath.normpath(unquote(parsed.path))
        query = parse_qs(parsed.query)

        try:
            if path in ("/", "/index.html", "/ui"):
                return self.serve_ui()
            if path == "/api/health":
                return self.json({"ok": True, "database": self.state.db_path,
                                  "ui": bool(self.state.ui_path),
                                  "interfaces": capture.list_interfaces()})
            if path == "/api/sessions":
                return self.json({"sessions": self.state.store.sessions(
                    limit=int(first(query, "limit", 100)))})
            if path == "/api/live":
                monitor = self.state.monitor
                if monitor is None:
                    return self.json({"running": False, "never_started": True})
                return self.json(monitor.snapshot(top_n=int(first(query, "top", 250))))
            if path.startswith("/api/live/source/"):
                ip = unquote(path[len("/api/live/source/"):])
                return self.json(self.state.live_source(ip))

            if path.startswith("/api/session/"):
                return self.session_route(path, query)

            return self.error_json(404, "No such endpoint: %s" % path)
        except BrokenPipeError:
            return
        except Exception as exc:                      # never take the server down
            return self.error_json(500, "%s: %s" % (type(exc).__name__, exc))

    # ------------------------------------------------------------------
    def session_route(self, path, query):
        parts = [p for p in path.split("/") if p]
        # api / session / <id> / [rest...]
        if len(parts) < 3:
            return self.error_json(400, "Which session?")
        try:
            session_id = int(parts[2])
        except ValueError:
            return self.error_json(400, "Session ids are numbers.")

        rest = parts[3:]
        db = self.state.store

        if not rest:
            record = db.session(session_id)
            if record is None:
                return self.error_json(404, "No session %d." % session_id)
            return self.json(record)

        if rest[0] == "sources":
            return self.json(db.sources(
                session_id,
                offset=int(first(query, "offset", 0)),
                limit=min(int(first(query, "limit", 100)), 1000),
                order=first(query, "order", "score"),
                level=first(query, "level", None),
                query=first(query, "q", None),
                network=first(query, "network", None),
                fingerprint=first(query, "fingerprint", None)))

        if rest[0] == "source" and len(rest) > 1:
            ip = unquote("/".join(rest[1:]))
            detail = db.source_detail(session_id, ip)
            if detail is None:
                return self.error_json(404, "%s is not in that session." % ip)
            related = db.related(session_id, ip) or {}
            return self.json({"detail": detail, "related": related})

        if rest[0] == "buckets":
            return self.json({"buckets": db.buckets(
                session_id,
                since=first(query, "since", None),
                until=first(query, "until", None),
                points=int(first(query, "points", 1200)))})

        if rest[0] == "alerts":
            since = first(query, "since", None)
            return self.json({"alerts": db.alerts(
                session_id, limit=int(first(query, "limit", 200)),
                since=float(since) if since else None)})

        if rest[0] == "networks":
            return self.json({"networks": db.networks(session_id)})

        return self.error_json(404, "No such endpoint.")

    # ------------------------------------------------------------------
    def do_POST(self):
        parsed = urlparse(self.path)
        path = posixpath.normpath(unquote(parsed.path))
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except ValueError:
            return self.error_json(400, "That was not valid JSON.")

        try:
            if path == "/api/live/start":
                if not self.state.allow_live:
                    return self.error_json(403, "Live capture is switched off on this server.")
                return self.json(self.state.start_live(
                    body.get("interface", "any"),
                    log_path=body.get("log"),
                    note=body.get("note", "")))
            if path == "/api/live/stop":
                return self.json(self.state.stop_live())
            if path == "/api/import":
                return self.json(self.state.import_file(body.get("path", ""),
                                                        body.get("note", "")))
            if path == "/api/session/delete":
                self.state.store.delete_session(int(body.get("id", 0)))
                return self.json({"ok": True})
            return self.error_json(404, "No such endpoint: %s" % path)
        except Exception as exc:
            return self.error_json(500, "%s: %s" % (type(exc).__name__, exc))

    # ------------------------------------------------------------------
    def serve_ui(self):
        if not self.state.ui_path or not os.path.exists(self.state.ui_path):
            return self.error_json(
                404, "The browser page was not found. Point --ui at traffic-analyzer-ui.html.")
        with open(self.state.ui_path, "rb") as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def json(self, payload, code=200):
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def error_json(self, code, message):
        self.json({"error": message}, code)


def first(query, key, default=None):
    values = query.get(key)
    if not values:
        return default
    return values[0]


def serve(db_path, host="127.0.0.1", port=8724, ui_path=None, allow_live=True,
          open_browser=False, monitor=None):
    state = State(db_path, ui_path=ui_path, allow_live=allow_live, monitor=monitor)

    handler = type("BoundHandler", (Handler,), {"state": state})
    httpd = ThreadingHTTPServer((host, port), handler)

    if host not in ("127.0.0.1", "localhost", "::1"):
        print("")
        print("  WARNING: this is listening on %s, not just this machine." % host)
        print("  Anyone who can reach that address can see every address in your")
        print("  captures. Only do this on a network you control, and stop it after.")
        print("")

    where = "http://%s:%d/" % (host if host != "0.0.0.0" else "127.0.0.1", port)
    print("traffic-analyzer is at %s" % where)
    print("Database: %s" % db_path)
    if state.ui_path:
        print("Page:     %s" % state.ui_path)
    else:
        print("Page:     not found. The API works, but there is no browser view.")
        print("          Pass --ui /path/to/traffic-analyzer-ui.html to fix that.")
    print("Press Ctrl+C to stop.")

    if open_browser:
        try:
            import webbrowser
            threading.Timer(0.6, lambda: webbrowser.open(where)).start()
        except Exception:
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        if state.monitor is not None and state.monitor.running:
            state.monitor.stop()
            state.monitor.join(5.0)
        httpd.server_close()
        state.store.close()
