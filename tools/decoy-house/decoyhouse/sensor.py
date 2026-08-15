"""
The honeypot itself: a machine that looks real, and writes down everything.

This is the door with something worth stealing behind it. When somebody knocks
it does not just log the knock, it lets them in to a machine that looks
ordinary and lived-in, and records every move they make: what they type, what
they read, what they try to take.

Two ways in, because attackers try both:

  - a login shell over a plain line protocol, the way an exposed SSH or telnet
    service looks once you are past the banner. Any password works, because the
    point is to watch what they do next, not to keep them out.
  - a web admin panel, the way a forgotten internal tool looks. A weak login,
    and behind it the same tempting files.

The single most important thing about this file, and the reason it is safe to
run: it never executes anything the attacker sends. Not once. Every command
gets a scripted, believable answer from the fake filesystem in bait.py. The
attacker is typing into a puppet show. Whatever they run, the real machine does
nothing but write it down.

Sessions are recorded locally, always, and reported to the console when one is
configured. Local first means a lost console never loses you a session.
"""

import json
import os
import socket
import threading
import time
import urllib.request

from . import bait

BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
READ_LIMIT = 4096          # never read more than this from one line
SESSION_IDLE = 120         # drop a session after this long with no input


class Sensor(object):
    """One honeypot machine, listening on one or more ports."""

    def __init__(self, name="", console="", log_path="", ports=None):
        self.name = name or socket.gethostname()
        self.console = console.rstrip("/")
        self.log_path = log_path or os.path.expanduser("~/.decoy-house/sessions.log")
        self.ports = ports or []
        self.world, self.tokens = bait.build(
            console_host=_host_of(self.console), sensor_name=self.name)
        self.running = False
        self.sessions = []
        self._lock = threading.Lock()
        self._threads = []
        self._counter = 0

        # Tell the console we exist and hand it the tokens, so a trigger later
        # can be tied back to this sensor and this piece of bait.
        self._register()

    # ------------------------------------------------------------------
    def start(self):
        self.running = True
        for port in self.ports:
            thread = threading.Thread(target=self._serve, args=(port,), daemon=True)
            thread.start()
            self._threads.append(thread)
        return self._threads

    def stop(self):
        self.running = False

    # ------------------------------------------------------------------
    def _serve(self, port):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", port))
            server.listen(16)
            server.settimeout(1.0)
        except OSError as exc:
            self._note("could not open port %d: %s" % (port, exc))
            return

        while self.running:
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr, port),
                             daemon=True).start()
        server.close()

    def _handle(self, conn, addr, port):
        conn.settimeout(SESSION_IDLE)
        peer = "%s:%d" % (addr[0], addr[1])
        with self._lock:
            self._counter += 1
            session_id = "%s-%d-%d" % (self.name, int(time.time()), self._counter)

        session = {
            "id": session_id, "sensor": self.name, "peer_ip": addr[0],
            "peer_port": addr[1], "local_port": port, "started": time.time(),
            "protocol": "?", "events": [], "credentials": [],
            "read_files": [], "commands": [],
        }

        try:
            first = conn.recv(READ_LIMIT)
        except (socket.timeout, OSError):
            first = b""

        try:
            if _looks_like_http(first):
                session["protocol"] = "http"
                self._web(conn, first, session)
            else:
                session["protocol"] = "shell"
                self._shell(conn, first, session)
        except (OSError, socket.timeout):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
            session["ended"] = time.time()
            session["duration"] = round(session["ended"] - session["started"], 1)
            self._finish(session)

    # ------------------------------------------------------------------
    # The fake shell.
    # ------------------------------------------------------------------
    def _shell(self, conn, first, session):
        send = lambda text: _send(conn, text)

        send(BANNER + "\r\n")
        send("\r\n%s login: " % self.world["hostname"])
        username = _line(conn, first)
        session["events"].append(_event("login-user", username))
        send("Password: ")
        password = _line(conn)
        session["events"].append(_event("login-pass", password))
        session["credentials"].append({"username": username, "password": password,
                                        "service": "shell"})

        # Any password is accepted. Keeping them out is not the job; watching
        # what they reach for is.
        send("\r\n" + self.world["files"]["/etc/motd"] + "\r\n")

        cwd = "/home/deploy"
        prompt = lambda: send("deploy@%s:%s$ " % (self.world["hostname"], _short(cwd)))
        prompt()

        while self.running:
            line = _line(conn)
            if line is None:
                break
            line = line.strip()
            if not line:
                prompt()
                continue
            session["commands"].append(line)
            session["events"].append(_event("command", line))

            reply, cwd, done = self._run_fake(line, cwd, session)
            if reply:
                send(reply if reply.endswith("\n") else reply + "\r\n")
            if done:
                send("logout\r\n")
                break
            prompt()

    def _run_fake(self, line, cwd, session):
        """Answer a shell command from the fake filesystem. Runs nothing.

        Returns (reply, new_cwd, should_disconnect).
        """
        parts = line.split()
        cmd = parts[0]
        args = parts[1:]
        files = self.world["files"]
        dirs = self.world["dirs"]

        if cmd in ("exit", "logout", "quit"):
            return "", cwd, True

        if cmd == "pwd":
            return cwd, cwd, False

        if cmd == "whoami":
            return "deploy", cwd, False

        if cmd == "id":
            return "uid=1000(deploy) gid=1000(deploy) groups=1000(deploy),27(sudo)", cwd, False

        if cmd == "uname":
            return "Linux %s 5.15.0-101-generic #111-Ubuntu SMP x86_64 GNU/Linux" % self.world["hostname"], cwd, False

        if cmd in ("ls", "dir"):
            target = _resolve(cwd, args[-1]) if args and not args[-1].startswith("-") else cwd
            return self._list(target), cwd, False

        if cmd == "cd":
            if not args:
                return "", "/home/deploy", False
            target = _resolve(cwd, args[0])
            if target in dirs:
                return "", target, False
            if target in files:
                return "bash: cd: %s: Not a directory" % args[0], cwd, False
            return "bash: cd: %s: No such file or directory" % args[0], cwd, False

        if cmd in ("cat", "less", "more", "head", "tail", "nano", "vi", "vim"):
            if not args:
                return "", cwd, False
            target = _resolve(cwd, args[-1])
            if target in files:
                # This is the moment that matters: they are reading bait.
                session["read_files"].append(target)
                session["events"].append(_event("read-file", target))
                return files[target].rstrip("\n"), cwd, False
            if target in dirs:
                return "cat: %s: Is a directory" % args[-1], cwd, False
            return "cat: %s: No such file or directory" % args[-1], cwd, False

        if cmd in ("wget", "curl"):
            # A very common next step: pull down a payload. We do not fetch
            # anything, we record what they tried to bring in.
            session["events"].append(_event("download-attempt", line))
            if cmd == "wget":
                return ("--%s--  %s\nResolving... failed: Temporary failure in name resolution."
                        % (time.strftime("%Y-%m-%d %H:%M:%S"), args[-1] if args else "")), cwd, False
            return "curl: (6) Could not resolve host", cwd, False

        if cmd == "sudo":
            return "[sudo] password for deploy: ", cwd, False

        if cmd in ("ps", "top"):
            return _fake_processes(), cwd, False

        if cmd == "netstat" or cmd == "ss":
            return _fake_netstat(), cwd, False

        if cmd == "ifconfig" or (cmd == "ip" and "addr" in args):
            return _fake_ifconfig(), cwd, False

        if cmd == "history":
            return files.get("/home/deploy/.bash_history", "").rstrip("\n"), cwd, False

        if cmd in ("echo",):
            return " ".join(args), cwd, False

        if cmd in ("clear",):
            return "", cwd, False

        # Anything else gets the answer a real shell gives for a typo, which
        # keeps them believing and keeps us recording.
        return "%s: command not found" % cmd, cwd, False

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

    # ------------------------------------------------------------------
    # The fake web panel.
    # ------------------------------------------------------------------
    def _web(self, conn, first, session):
        request_line = first.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        session["events"].append(_event("http", request_line))
        try:
            method, path, _ = request_line.split(" ", 2)
        except ValueError:
            method, path = "GET", "/"

        body = first.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in first else b""
        if method == "POST" and body:
            posted = body.decode("latin-1", "replace")
            session["events"].append(_event("http-post", "%s %s" % (path, posted[:200])))
            for pair in posted.split("&"):
                if "user" in pair.lower() or "pass" in pair.lower():
                    session["credentials"].append({"service": "web", "raw": posted[:200]})
                    break

        page, ctype = self._page(path, session)
        _send_raw(conn, ("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\n"
                         "Content-Type: %s\r\nConnection: close\r\n"
                         "Content-Length: %d\r\n\r\n" % (ctype, len(page.encode()))).encode()
                  + page.encode())

    def _page(self, path, session):
        clean = path.split("?", 1)[0]
        files = self.world["files"]

        # The bait files are reachable by their name under a fake admin area,
        # which is how a real leaky panel behaves.
        for stored in files:
            leaf = stored.rsplit("/", 1)[1]
            if clean.endswith("/" + leaf) or clean == "/files/" + leaf:
                session["read_files"].append(stored)
                session["events"].append(_event("read-file", stored))
                return files[stored], "text/plain; charset=utf-8"

        if clean in ("/", "/login", "/admin", "/admin/"):
            return _login_page(self.world["company"]), "text/html; charset=utf-8"
        if clean in ("/dashboard", "/admin/dashboard", "/files", "/files/"):
            return _dashboard_page(files), "text/html; charset=utf-8"
        return _login_page(self.world["company"]), "text/html; charset=utf-8"

    # ------------------------------------------------------------------
    def _finish(self, session):
        session["credential_count"] = len(session["credentials"])
        with self._lock:
            self.sessions.append(session)
        self._write_local(session)
        self._report(session)
        taken = ", ".join(f.rsplit("/", 1)[1] for f in session["read_files"]) or "nothing"
        self._note("session %s from %s on port %d: %d commands, read %s"
                   % (session["id"], session["peer_ip"], session["local_port"],
                      len(session["commands"]), taken))

    def _write_local(self, session):
        try:
            folder = os.path.dirname(self.log_path)
            if folder and not os.path.isdir(folder):
                os.makedirs(folder)
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(session) + "\n")
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
            request = urllib.request.Request(
                self.console + path, data=data,
                headers={"Content-Type": "application/json",
                         "User-Agent": "decoy-house sensor"})
            urllib.request.urlopen(request, timeout=5).read()
        except Exception:
            # A console that is down must never take a sensor down with it.
            pass

    def _note(self, text):
        line = "%s  %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), text)
        print(line, flush=True)


# ---------------------------------------------------------------------------
# Small helpers, kept out of the class so they are easy to read and test.
# ---------------------------------------------------------------------------
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


def _line(conn, pre=b""):
    """Read one line, starting from anything already received."""
    buffer = bytearray(pre)
    if b"\n" in buffer:
        line, _, rest = bytes(buffer).partition(b"\n")
        return line.decode("latin-1", "replace").rstrip("\r")
    while len(buffer) < READ_LIMIT:
        try:
            chunk = conn.recv(256)
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buffer += chunk
        if b"\n" in buffer:
            break
    line = bytes(buffer).split(b"\n", 1)[0]
    return line.decode("latin-1", "replace").rstrip("\r")


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


def _short(path):
    home = "/home/deploy"
    if path == home:
        return "~"
    if path.startswith(home + "/"):
        return "~" + path[len(home):]
    return path


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
        " 1042 ?        00:00:03 nginx\n"
        " 1088 ?        00:04:17 puma\n"
        " 1129 ?        00:00:41 postgres\n"
        " 2231 pts/0    00:00:00 bash\n"
        " 2240 pts/0    00:00:00 ps")


def _fake_netstat():
    return (
        "Active Internet connections (only servers)\n"
        "Proto Local Address           Foreign Address         State\n"
        "tcp   0.0.0.0:22              0.0.0.0:*               LISTEN\n"
        "tcp   0.0.0.0:80              0.0.0.0:*               LISTEN\n"
        "tcp   127.0.0.1:5432         0.0.0.0:*               LISTEN\n"
        "tcp   0.0.0.0:443            0.0.0.0:*               LISTEN")


def _fake_ifconfig():
    return (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "        inet 10.0.0.21  netmask 255.255.255.0  broadcast 10.0.0.255\n"
        "        ether 06:3a:1f:9c:2d:88  txqueuelen 1000  (Ethernet)\n"
        "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
        "        inet 127.0.0.1  netmask 255.0.0.0")


def _login_page(company):
    return (
        "<!doctype html><html><head><meta charset=utf-8><title>%s admin</title>"
        "<style>body{font-family:Arial,sans-serif;background:#eef1f5;margin:0}"
        ".box{max-width:340px;margin:8%% auto;background:#fff;padding:28px;border-radius:6px;"
        "box-shadow:0 2px 10px rgba(0,0,0,.1)}input{width:100%%;padding:9px;margin:6px 0;"
        "box-sizing:border-box;border:1px solid #ccc;border-radius:4px}"
        "button{width:100%%;padding:10px;background:#2b6cb0;color:#fff;border:0;border-radius:4px}"
        "h2{margin:0 0 4px}small{color:#888}</style></head><body>"
        "<div class=box><h2>%s</h2><small>Internal administration</small>"
        "<form method=post action=/admin/dashboard>"
        "<input name=username placeholder=Username autofocus>"
        "<input name=password type=password placeholder=Password>"
        "<button>Sign in</button></form></div></body></html>"
        % (company, company))


def _dashboard_page(files):
    links = "".join("<li><a href='/files/%s'>%s</a></li>"
                    % (path.rsplit("/", 1)[1], path) for path in sorted(files))
    return (
        "<!doctype html><html><head><meta charset=utf-8><title>Files</title></head>"
        "<body style='font-family:Arial;margin:24px'><h2>Shared files</h2>"
        "<p>Backups and exports. Handle with care.</p><ul>%s</ul></body></html>"
        % links)
