"""
A small web server so the whole tool can be used from a browser.

Why this is not the same shape as traffic-analyzer's browser view: that one
parses captures in JavaScript on the page, so it works from a file:// URL with
no server at all. This one cannot honestly do that. The work here is a hand
written Outlook Compound File reader, a structural inspection of every
attachment, and a pile of careful wording checks, all of it Python. Rewriting
that in JavaScript would mean two copies of the same judgement, drifting apart,
and the browser copy would be the one giving a client an answer.

So the page is a face and this is the tool. The email goes to 127.0.0.1, Python
does exactly what the command line does, and the answer comes back as JSON. The
promise that nothing is uploaded still holds, because the only thing listening
is this machine.

It binds to 127.0.0.1 on purpose. Anything else takes an explicit host and
prints a warning, because an email somebody is asking you about is usually the
most sensitive thing on the disk that day.

Standard library only. No framework, no dependencies, nothing to keep updated.
"""

import base64
import json
import os
import posixpath
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

from . import analyze, breach, passwords, read

HERE = os.path.dirname(os.path.abspath(__file__))

# An email is small. A mailbox export is not, but it is still nothing next to a
# packet capture, and refusing early beats running out of memory later.
MAX_UPLOAD = 64 * 1024 * 1024

# Where the browser page might be sitting, in order of preference. The tool has
# to work whether it is run from inside the project, from a copy of just this
# folder, or from wherever somebody unpacked it.
UI_CANDIDATES = [
    os.path.join(HERE, "..", "web", "email-checker.html"),
    os.path.join(HERE, "..", "email-checker.html"),
    os.path.join(HERE, "..", "..", "..", "website", "email-checker.html"),
    os.path.join(HERE, "..", "..", "..", "..", "website", "email-checker.html"),
]


def find_ui():
    for path in UI_CANDIDATES:
        full = os.path.abspath(path)
        if os.path.exists(full):
            return full
    return None


class State(object):
    """Everything the request handlers need, in one place."""

    def __init__(self, ui_path=None, allow_online=True):
        self.ui_path = ui_path or find_ui()
        self.allow_online = allow_online
        self.lock = threading.Lock()

    # -- the three things the page can ask for --------------------------
    def check_email(self, body):
        """Analyse one email, however the page got hold of it."""
        offline = bool(body.get("offline")) or not self.allow_online
        want_domain = body.get("domain")
        check_domain = (not offline) if want_domain is None else bool(want_domain)
        if check_domain and not self.allow_online:
            check_domain = False

        blob, text, origin = None, None, body.get("name") or "pasted text"
        if body.get("data"):
            try:
                blob = base64.b64decode(body["data"])
            except Exception:
                return {"error": "That upload was not readable."}
            if len(blob) > MAX_UPLOAD:
                return {"error": "That file is larger than %d MB."
                                 % (MAX_UPLOAD // (1024 * 1024))}
        elif body.get("text"):
            text = body["text"]
        else:
            return {"error": "Nothing was sent to check."}

        try:
            loaded_list = read.load(path=body.get("name") or "", data=blob, text=text)
        except Exception as exc:
            return {"error": "Could not read that email: %s. Save it as .eml, "
                             ".emlx, .mbox or .msg from your mail program and try "
                             "again." % exc}

        # A mailbox can hold thousands. Analysing all of them on one click is a
        # good way to look broken, so the page asks for a window of them.
        offset = max(0, int(body.get("offset") or 0))
        limit = min(int(body.get("limit") or 25), 200)
        window = loaded_list[offset:offset + limit]

        reports = []
        for loaded in window:
            reports.append(analyze.analyze_one(
                loaded, offline=offline,
                vt_key=body.get("vt_key", ""), mb_key=body.get("mb_key", ""),
                check_domain=check_domain))
        return {
            "origin": origin,
            "total": len(loaded_list),
            "offset": offset,
            "reports": reports,
            "offline": offline,
            "domain_checked": check_domain,
        }

    def check_password(self, body):
        """Strength, and optionally whether it is already in the breach data.

        The password reaches this process and is used, then dropped. It is never
        written down, never logged, and the request line never contains it.
        """
        secret = body.get("password") or ""
        if not secret:
            return {"error": "Nothing was entered."}
        offline = bool(body.get("offline")) or not self.allow_online

        notes, good, penalty, guess_time = passwords.analyse(secret)
        result = {
            "guess_time": guess_time,
            "good": good,
            "notes": notes,
            "penalty": penalty,
            "offline": offline,
            "count": None,
            "note": "",
        }
        if not offline:
            count, error = passwords.breach_count(secret)
            if error:
                result["note"] = error + ". The strength answer above still stands."
            else:
                _state, explanation = passwords.describe_breach(count)
                result["count"] = count
                result["note"] = explanation
        del secret
        return result

    def check_breach(self, body):
        """An address lookup. This one genuinely sends the address out, so it
        does not happen without the page saying the person agreed."""
        address = (body.get("email") or "").strip()
        if not breach.looks_like_email(address):
            return {"error": "That does not look like an email address."}
        if not self.allow_online:
            return {"error": "This server was started with --offline, so it will "
                             "not send anything anywhere."}
        if not body.get("consent"):
            return {"error": "The address was not sent, because the confirmation "
                             "was not given."}
        return breach.check(address, hibp_key=body.get("hibp_key", ""))


class Handler(BaseHTTPRequestHandler):
    server_version = "email-checker"
    state = None                      # set on the server instance

    # Quieten the default logging. It writes a line per request to stderr, and
    # on this tool those lines would name the files somebody is checking.
    def log_message(self, fmt, *args):
        pass

    # ------------------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = posixpath.normpath(unquote(parsed.path))
        try:
            if path in ("/", "/ui", "/email-checker.html"):
                return self.serve_ui()
            if path == "/index.html":
                # The page has a "back to the main site" link. When the site is
                # sitting next to the tool, honour it rather than silently
                # reloading the checker under a different name.
                return self.serve_sibling("index.html")
            if path == "/api/health":
                return self.json({
                    "ok": True,
                    "online": self.state.allow_online,
                    "ui": bool(self.state.ui_path),
                    "sources": {
                        "breach": [list(s) for s in breach.SOURCES],
                    },
                })
            return self.error_json(404, "No such endpoint: %s" % path)
        except BrokenPipeError:
            return
        except Exception as exc:                      # never take the server down
            return self.error_json(500, "%s: %s" % (type(exc).__name__, exc))

    # ------------------------------------------------------------------
    def do_POST(self):
        parsed = urlparse(self.path)
        path = posixpath.normpath(unquote(parsed.path))
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_UPLOAD:
            return self.error_json(413, "That is larger than this tool will take.")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except ValueError:
            return self.error_json(400, "That was not valid JSON.")

        try:
            if path == "/api/check":
                return self.json(self.state.check_email(body))
            if path == "/api/password":
                return self.json(self.state.check_password(body))
            if path == "/api/breach":
                return self.json(self.state.check_breach(body))
            return self.error_json(404, "No such endpoint: %s" % path)
        except BrokenPipeError:
            return
        except Exception as exc:
            return self.error_json(500, "%s: %s" % (type(exc).__name__, exc))

    # ------------------------------------------------------------------
    def serve_ui(self):
        if not self.state.ui_path or not os.path.exists(self.state.ui_path):
            return self.error_json(
                404, "The browser page was not found. Point --ui at email-checker.html.")
        with open(self.state.ui_path, "rb") as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def serve_sibling(self, name):
        """One named file from the folder the page lives in, and nothing else.

        The name is fixed in the code, never taken from the request, so there is
        no path to traverse out of. This is deliberately not a static file
        server: it serves the page, and it serves the site's front page if that
        happens to be sitting beside it.
        """
        if not self.state.ui_path:
            return self.error_json(404, "Nothing to serve there.")
        target = os.path.join(os.path.dirname(self.state.ui_path), name)
        if not os.path.exists(target):
            return self.error_json(
                404, "The main site is not next to this tool, so there is nowhere "
                     "to go back to. Close the tab instead.")
        with open(target, "rb") as fh:
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


def serve(host="127.0.0.1", port=8730, ui_path=None, allow_online=True,
          open_browser=False):
    state = State(ui_path=ui_path, allow_online=allow_online)

    handler = type("BoundHandler", (Handler,), {"state": state})
    httpd = ThreadingHTTPServer((host, port), handler)

    if host not in ("127.0.0.1", "localhost", "::1"):
        print("")
        print("  WARNING: this is listening on %s, not just this machine." % host)
        print("  Anyone who can reach that address could send emails through it")
        print("  and read the answers. Only do this on a network you control.")
        print("")

    where = "http://%s:%d/" % (host if host != "0.0.0.0" else "127.0.0.1", port)
    print("email-checker is at %s" % where)
    if state.ui_path:
        print("Page:     %s" % state.ui_path)
    else:
        print("Page:     not found. The API works, but there is no browser view.")
        print("          Pass --ui /path/to/email-checker.html to fix that.")
    print("Network:  %s" % ("lookups allowed" if allow_online else
                            "offline, nothing will be sent anywhere"))
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
        httpd.server_close()
