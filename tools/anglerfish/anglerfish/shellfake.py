"""
The fake shell the attacker types into.

Nothing here is executed on the host. Every command is answered from the bait
filesystem, with enough of a parser that Mirai-style and cowrie-detection probes
(`uname -m`, `busybox`, `;`/`&&`/`||`/`|`, `$HOME`, `~`, globs, `sudo`) get the
answers a real Ubuntu box would give instead of the one-word hiccups that
fingerprint a honeypot.
"""

import base64
import binascii
import fnmatch
import os
import random
import re
import shlex
import time

from . import shelldata

# Commands that bots probe for. Returning the right shape matters more than
# implementing them fully. The inventory is a realistic Ubuntu 22.04 cloud image.
KNOWN_BINARIES = shelldata.KNOWN_BINARIES

def _writable(path, home):
    """Only /tmp, /var/tmp, and the user home are writable in the fake FS."""
    if path.startswith("/tmp/") or path == "/tmp":
        return True
    if path.startswith("/var/tmp/") or path == "/var/tmp":
        return True
    if path.startswith(home.rstrip("/") + "/") or path == home.rstrip("/"):
        return True
    if path == "/srv/shares/IT/guestbook.txt":
        return True
    return False




_FD_REDIRECT = re.compile(
    r"(?:(?<=\s)|^)(?:&>>?\s*/dev/null|[12]?>>?\s*/dev/null|2>&1|1>&2|>&2)(?=\s|$)")


def _strip_fd_redirects(cmd):
    """Remove unquoted fd redirections. Returns (cmd, drop_out, drop_err, merge)."""
    if not cmd or (">" not in cmd):
        return cmd, False, False, False
    # Leave quoted text alone: only operate when no quotes surround a '>'.
    out = []
    drop_out = drop_err = merge = False
    i = 0
    quote = None
    buf = ""
    segs = []  # (text, quoted)
    for ch in cmd:
        if quote:
            buf += ch
            if ch == quote:
                quote = None
                segs.append((buf, True))
                buf = ""
            continue
        if ch in ("'", '"'):
            if buf:
                segs.append((buf, False))
            buf = ch
            quote = ch
            continue
        buf += ch
    if buf:
        segs.append((buf, bool(quote)))
    for text, quoted in segs:
        if quoted:
            out.append(text)
            continue
        for m in _FD_REDIRECT.finditer(text):
            tok = m.group(0).replace(" ", "")
            if tok == "2>&1":
                merge = True
            elif tok in ("1>&2", ">&2"):
                pass
            elif tok.startswith("&>"):
                drop_out = drop_err = True
            elif tok.startswith("2>"):
                drop_err = True
            else:
                drop_out = True
        out.append(_FD_REDIRECT.sub("", text))
    new = re.sub(r"\s{2,}", " ", "".join(out)).strip()
    if new == cmd.strip():
        return cmd, False, False, False
    return new, drop_out, drop_err, merge


def _unquoted_redirect(cmd):
    """Find the first unquoted '>' or '>>'. Returns (left, op, target) or None."""
    quote = None
    i = 0
    while i < len(cmd):
        ch = cmd[i]
        if quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == ">":
            op = ">>" if cmd[i:i + 2] == ">>" else ">"
            left = cmd[:i].rstrip()
            rest = cmd[i + len(op):].strip().split()
            if left.endswith(("1", "2")) and (len(left) == 1 or left[-2] == " "):
                left = left[:-1].rstrip()
            return left, op, (rest[0] if rest else "")
        i += 1
    return None


_ERR_MARKERS = ("No such file or directory", "command not found", "Permission denied",
                "Temporary failure", "Could not resolve", "Is a directory",
                "Not a directory", "invalid option", "Connection timed out",
                "usage error", "cannot access")


def _looks_like_err(line):
    return any(m in line for m in _ERR_MARKERS)


def split_pipeline(line):
    """Split on unquoted ; / && / || / | while keeping each segment."""
    # Rough tokenizer that respects single/double quotes.
    parts = []
    buf = []
    i = 0
    quote = None
    while i < len(line):
        ch = line[i]
        if quote:
            buf.append(ch)
            if ch == quote and (quote == "'" or line[i - 1:i] != "\\"):
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if line[i:i + 2] in ("&&", "||"):
            parts.append(("".join(buf).strip(), line[i:i + 2]))
            buf = []
            i += 2
            continue
        if ch in (";", "|"):
            parts.append(("".join(buf).strip(), ch))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    parts.append(("".join(buf).strip(), None))
    return [(cmd, op) for cmd, op in parts if cmd]


def _arith(expr, env):
    """Evaluate a bash $(( )) arithmetic expression, safely and integer-only."""
    expr = (expr or "").strip()
    expr = re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?",
                  lambda m: str(env.get(m.group(1), "0") or "0"), expr)
    # bash bare names inside $(( )) are variable refs too
    expr = re.sub(r"(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)",
                  lambda m: str(env.get(m.group(1), "0") or "0"), expr)
    expr = expr.strip()
    if not re.fullmatch(r"[0-9\s+\-*/%()&|^<>=!~]*", expr or ""):
        return "0"
    try:
        import ast as _ast
        node = _ast.parse(expr, mode="eval")
        allowed = (_ast.Expression, _ast.BinOp, _ast.UnaryOp, _ast.Constant,
                   _ast.Add, _ast.Sub, _ast.Mult, _ast.FloorDiv, _ast.Div,
                   _ast.Mod, _ast.Pow, _ast.USub, _ast.UAdd, _ast.Invert,
                   _ast.BitAnd, _ast.BitOr, _ast.BitXor, _ast.LShift, _ast.RShift)
        for n in _ast.walk(node):
            if not isinstance(n, allowed):
                return "0"
        val = eval(compile(node, "<arith>", "eval"))  # noqa: S307 - whitelisted nodes only
        return str(int(val))
    except Exception:
        return "0"


def expand_vars(text, env):
    def repl_braced(m):
        return env.get(m.group(1), "")

    def repl_plain(m):
        return env.get(m.group(1), "")

    # Arithmetic expansion first: $(( expr ))
    while "$((" in text:
        start = text.index("$((")
        depth = 0
        i = start + 3
        end = -1
        while i < len(text):
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                if depth == 0 and text[i:i + 2] == "))":
                    end = i
                    break
                depth -= 1
            i += 1
        if end == -1:
            break
        inner = text[start + 3:end]
        text = text[:start] + _arith(inner, env) + text[end + 2:]

    text = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", repl_braced, text)
    text = re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)", repl_plain, text)
    return text


def expand_home(arg, home):
    if arg == "~":
        return home
    if arg.startswith("~/"):
        return home + arg[1:]
    return arg


def _expand_arith_inline(text, env):
    while "$((" in text:
        start = text.index("$((")
        depth = 0
        i = start + 3
        end = -1
        while i < len(text):
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                if depth == 0 and text[i:i + 2] == "))":
                    end = i
                    break
                depth -= 1
            i += 1
        if end == -1:
            break
        inner = text[start + 3:end]
        text = text[:start] + _arith(inner, env) + text[end + 2:]
    return text


def tokenize(cmd, env, home):
    # Arithmetic expansion happens at the whole-line level so that
    # "echo $(( 7 * 6 ))" (with spaces) collapses before word splitting.
    cmd = _expand_arith_inline(cmd, env)
    try:
        parts = shlex.split(cmd, posix=True)
    except ValueError:
        parts = cmd.split()
    out = []
    for p in parts:
        p = expand_vars(p, env)
        p = expand_home(p, home)
        out.append(p)
    return out


def resolve(cwd, arg):
    if not arg:
        return cwd
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


def short_path(path, home):
    if path == home:
        return "~"
    if path.startswith(home + "/"):
        return "~" + path[len(home):]
    return path


def match_glob(pattern, names):
    if any(ch in pattern for ch in "*?["):
        return [n for n in names if fnmatch.fnmatch(n, pattern)]
    return [pattern] if pattern in names or True else []



def _pipe_filter(text, right_cmd):
    """Apply a tiny set of right-side filters so `ls | wc -l` looks real."""
    try:
        parts = shlex.split(right_cmd, posix=True)
    except ValueError:
        parts = right_cmd.split()
    if not parts:
        return None
    name = parts[0].rsplit("/", 1)[-1]
    args = parts[1:]
    lines = text.splitlines()
    if name == "wc":
        if "-l" in args or args == ["-l"] or (len(args) == 1 and args[0] == "-l"):
            return "%7d" % len(lines)
        if not args:
            n_words = len(text.split())
            return "%7d %7d %7d" % (len(lines), n_words, len(text.encode("utf-8")))
        return "%7d" % len(lines)
    if name == "head":
        n = 10
        for i, a in enumerate(args):
            if a.startswith("-") and a[1:].isdigit():
                n = int(a[1:])
            elif a == "-n" and i + 1 < len(args):
                try: n = int(args[i + 1])
                except ValueError: pass
        return "\n".join(lines[:n])
    if name == "tail":
        n = 10
        for i, a in enumerate(args):
            if a.startswith("-") and a[1:].isdigit():
                n = int(a[1:])
            elif a == "-n" and i + 1 < len(args):
                try: n = int(args[i + 1])
                except ValueError: pass
        return "\n".join(lines[-n:])
    if name == "grep" and args:
        pat = [a for a in args if not a.startswith("-")]
        if not pat:
            return ""
        return "\n".join(ln for ln in lines if pat[0] in ln)
    if name == "sort":
        return "\n".join(sorted(lines))
    if name == "uniq":
        out, prev = [], object()
        for ln in lines:
            if ln != prev:
                out.append(ln)
                prev = ln
        return "\n".join(out)
    if name == "cut" and args:
        # very small: cut -d: -f1
        delim = "\t"
        field = 1
        for i, a in enumerate(args):
            if a == "-d" and i + 1 < len(args):
                delim = args[i + 1]
            elif a.startswith("-d") and len(a) > 2:
                delim = a[2:]
            elif a == "-f" and i + 1 < len(args):
                try: field = int(args[i + 1])
                except ValueError: pass
            elif a.startswith("-f") and a[2:].isdigit():
                field = int(a[2:])
        out = []
        for ln in lines:
            parts = ln.split(delim)
            if 1 <= field <= len(parts):
                out.append(parts[field - 1])
        return "\n".join(out)
    return None


class FakeShell(object):
    """Stateful fake shell bound to one sensor world."""

    def __init__(self, world, ports, classroom=False, peer_ip="",
                 read_hook=None, sign_guestbook=None, event_hook=None,
                 boot_time=None):
        self.world = world
        self.ports = ports or []
        self.classroom = classroom
        self.peer_ip = peer_ip or "10.0.0.14"
        self.read_hook = read_hook or (lambda path: "")
        self.sign_guestbook = sign_guestbook
        self.event_hook = event_hook or (lambda kind, detail: None)
        self.boot_time = boot_time
        self.env = {
            "SHELL": "/bin/bash", "TERM": "xterm-256color",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "en_US.UTF-8", "HOSTNAME": world["hostname"],
            "USER": "deploy", "LOGNAME": "deploy", "HOME": "/home/deploy",
            "PWD": "/home/deploy",
        }
        self._sudo_pending = None  # (username,) when waiting for sudo password

    def prompt(self, cwd, username):
        return "%s@%s:%s$ " % (username, self.world["hostname"],
                               short_path(cwd, "/home/%s" % username
                                          if username in ("deploy", "admin", "ubuntu")
                                          else "/home/deploy"))

    def run_line(self, line, cwd, session, username="deploy"):
        """Run one typed line (may contain ; && || |). Returns (reply, cwd, done)."""
        line = (line or "").strip()
        if not line:
            return "", cwd, False
        if len(line) > 4000:
            line = line[:4000]

        # sudo password follow-up
        if self._sudo_pending is not None:
            user = self._sudo_pending
            self._sudo_pending = None
            session.setdefault("credentials", []).append({
                "username": user, "password": line, "service": "sudo",
            })
            session.setdefault("events", []).append({"at": time.time(), "kind": "login-pass",
                                                     "detail": line})
            session.setdefault("events", []).append({"at": time.time(), "kind": "login-result",
                                                     "detail": "fail"})
            time.sleep(random.uniform(1.6, 2.4))
            return "Sorry, try again.\n[sudo] password for %s: " % user, cwd, False

        # Tiny believable per-command jitter (bots look for zero latency).
        time.sleep(random.uniform(0.015, 0.08))

        home = "/home/%s" % username if username in ("deploy", "admin", "ubuntu") else "/home/deploy"
        self.env["USER"] = username
        self.env["LOGNAME"] = username
        self.env["HOME"] = home
        self.env["PWD"] = cwd

        segments = split_pipeline(line)
        replies = []
        done = False
        last_ok = True
        i = 0
        while i < len(segments):
            cmd, op = segments[i]
            if op == "&&" and not last_ok:
                i += 1
                continue
            if op == "||" and last_ok:
                i += 1
                continue
            # Pipe into `sudo -S`: feed left stdout as the password, then run sudo's command.
            if op == "|" and i + 1 < len(segments):
                nxt, _nop = segments[i + 1]
                nxt_parts = nxt.split()
                if nxt_parts and nxt_parts[0].rsplit("/", 1)[-1] == "sudo" and "-S" in nxt_parts:
                    left_out, cwd, done = self._one(cmd, cwd, session, username)
                    # Consume the password without echoing it; record it.
                    session.setdefault("credentials", []).append({
                        "username": username, "password": (left_out or "").strip(),
                        "service": "sudo",
                    })
                    session.setdefault("events", []).append(
                        {"at": time.time(), "kind": "login-pass", "detail": (left_out or "").strip()})
                    session.setdefault("events", []).append(
                        {"at": time.time(), "kind": "login-result", "detail": "fail"})
                    time.sleep(random.uniform(0.4, 0.9))
                    # Real sudo -S with a wrong password: "Sorry, try again." then exit 1.
                    # We never escalate. Drop the rest of the sudo argv.
                    replies.append("Sorry, try again.")
                    last_ok = False
                    i += 2
                    if done:
                        break
                    continue
                # Generic pipe: run left. If right is wc -l / head / tail / grep /
                # sort / uniq / cut, filter left stdout the way a real pipe would.
                left_out, cwd, done = self._one(cmd, cwd, session, username)
                right_cmd = nxt
                filtered = _pipe_filter(left_out or "", right_cmd)
                if filtered is not None:
                    replies.append(filtered)
                elif left_out:
                    replies.append(left_out)
                last_ok = True
                i += 2  # skip right side
                if done:
                    break
                continue
            reply, cwd, done = self._one(cmd, cwd, session, username)
            if reply:
                replies.append(reply)
            last_ok = not (reply.startswith("bash:") or "command not found" in reply
                           or "No such file" in reply or reply.startswith("sudo:"))
            if done:
                break
            i += 1
        return "\n".join(r.rstrip("\n") for r in replies if r is not None), cwd, done

    def _one(self, cmd, cwd, session, username):
        """Run one segment, honouring bash fd redirections.

        `2>&1`, `2>/dev/null`, `>/dev/null`, `&>/dev/null` are consumed here
        instead of reaching the command as stray filenames; `cmd > file`
        (non-echo) lands the output in the in-memory overlay. Nothing touches
        the real host.
        """
        stripped, drop_out, drop_err, merge = _strip_fd_redirects(cmd)
        if stripped != cmd:
            if not stripped.strip():
                return "", cwd, False
            reply, cwd, done = self._one(stripped, cwd, session, username)
            reply = reply or ""
            if drop_out and (merge or drop_err):
                return "", cwd, done
            if drop_out:
                return "\n".join(l for l in reply.splitlines() if _looks_like_err(l)), cwd, done
            if drop_err:
                return "\n".join(l for l in reply.splitlines() if not _looks_like_err(l)), cwd, done
            return reply, cwd, done
        # Generic `cmd > file` / `cmd >> file` (echo/printf keep their own path).
        target_op = _unquoted_redirect(cmd)
        if target_op:
            left, op, target = target_op
            first = (left.split() or [""])[0].rsplit("/", 1)[-1]
            if first not in ("echo", "printf") and target:
                env = dict(self.env)
                dest = resolve(cwd, target)
                home = env.get("HOME") or "/home/deploy"
                if not _writable(dest, home):
                    return "bash: %s: Permission denied" % target, cwd, False
                out, cwd, done = self._one(left, cwd, session, username)
                out = out or ""
                errs = [l for l in out.splitlines() if _looks_like_err(l)]
                body = "\n".join(l for l in out.splitlines() if not _looks_like_err(l))
                body = body + "\n" if body else ""
                if op == ">>" and dest in self.world["files"]:
                    prev = self.world["files"][dest]
                    if isinstance(prev, (bytes, bytearray)):
                        prev = prev.decode("latin-1", "replace")
                    body = prev + body
                self.world["files"][dest] = body
                self.world.setdefault("overlay", {})[dest] = body
                parent = dest.rsplit("/", 1)[0] or "/"
                if parent not in self.world["dirs"]:
                    self.world["dirs"] = sorted(set(self.world["dirs"]) | {parent})
                return "\n".join(errs), cwd, done
        return self._one_inner(cmd, cwd, session, username)

    def _one_inner(self, cmd, cwd, session, username):
        env = dict(self.env)
        env["PWD"] = cwd
        parts = tokenize(cmd, env, env["HOME"])
        if not parts:
            return "", cwd, False
        rawcmd = parts[0]
        name = rawcmd.rsplit("/", 1)[-1]
        args = parts[1:]
        files = self.world["files"]
        dirs = self.world["dirs"]
        user = username
        # ubuntu=1000, deploy=1001, admin=1002 (matches bait._passwd)
        uid = {"ubuntu": "1000", "deploy": "1001", "admin": "1002"}.get(user, "1001")
        home = env["HOME"]

        if name in ("exit", "logout", "quit"):
            return "", cwd, True
        if name == "pwd":
            return cwd, cwd, False
        if name == "whoami":
            return user, cwd, False
        if name == "id":
            return ("uid=%s(%s) gid=%s(%s) groups=%s(%s),27(sudo),4(adm)"
                    % (uid, user, uid, user, uid, user)), cwd, False
        if name == "groups":
            return "%s sudo adm" % user, cwd, False
        if name == "hostname":
            if args and args[0] in ("-f", "--fqdn"):
                return self.world.get("fqdn") or self.world["hostname"], cwd, False
            return self.world["hostname"], cwd, False
        if name == "uname":
            return self._uname(args), cwd, False
        if name == "nproc":
            return "2", cwd, False
        if name == "date":
            return time.strftime("%a %b %e %H:%M:%S %Z %Y"), cwd, False
        if name == "uptime":
            return self._uptime_line(), cwd, False
        if name == "df":
            return _fake_df(), cwd, False
        if name == "free":
            return _fake_free(args), cwd, False
        if name in ("last", "lastlog"):
            return _fake_last(self.world, self.boot_time, user), cwd, False
        if name in ("w", "who"):
            return self._w_line(user), cwd, False
        if name == "env" or (name == "printenv" and not args):
            return "\n".join("%s=%s" % (k, env[k]) for k in
                             ("SHELL", "PWD", "LOGNAME", "HOME", "USER", "PATH", "LANG", "HOSTNAME")), cwd, False
        if name == "printenv" and args:
            return env.get(args[0], ""), cwd, False
        if name in ("ls", "dir"):
            return self._ls(cwd, args, files, dirs), cwd, False
        if name == "cd":
            if not args:
                return "", home if home in dirs else "/home/deploy", False
            target = resolve(cwd, args[0])
            if target in dirs:
                return "", target, False
            if target in files:
                return "bash: cd: %s: Not a directory" % args[0], cwd, False
            return "bash: cd: %s: No such file or directory" % args[0], cwd, False
        if name in ("cat", "less", "more", "nano", "vi", "vim"):
            return self._read_cmd(name, args, cwd, session, files, dirs), cwd, False
        if name in ("head", "tail"):
            return self._head_tail(name, args, cwd, session, files, dirs), cwd, False
        if name == "find":
            return self._find(args, cwd, files, dirs), cwd, False
        if name == "openssl":
            return self._openssl(args, cwd, session, files), cwd, False
        if name in ("wget", "curl"):
            self.event_hook("download-attempt", cmd)
            session.setdefault("events", []).append(
                {"at": time.time(), "kind": "download-attempt", "detail": cmd})
            if name == "wget":
                return ("--%s--  %s\nResolving... failed: Temporary failure in name resolution."
                        % (time.strftime("%Y-%m-%d %H:%M:%S"), args[-1] if args else "")), cwd, False
            return "curl: (6) Could not resolve host", cwd, False
        if name == "sudo":
            # Real sudo reads a password (or waits ~2s then fails). We never escalate.
            self._sudo_pending = user
            session.setdefault("events", []).append(
                {"at": time.time(), "kind": "command", "detail": "sudo " + " ".join(args)})
            return "[sudo] password for %s: " % user, cwd, False
        if name in ("ps", "top"):
            return _fake_processes(user), cwd, False
        if name in ("netstat", "ss"):
            return _fake_netstat(self.ports), cwd, False
        if name in ("ifconfig", "ip"):
            return _fake_ifconfig(self.world.get("internal_ip") or "10.0.0.21",
                                  self.world.get("mac") or "06:3a:1f:9c:2d:88"), cwd, False
        if name == "history":
            hist = files.get("/home/%s/.bash_history" % user) or files.get(
                "/home/deploy/.bash_history", "")
            return hist.rstrip("\n"), cwd, False
        if name in ("echo", "printf") and _unquoted_redirect(cmd):
            return self._redirect(cmd, rawcmd, cwd, session), cwd, False
        if name == "base64" and args:
            return self._base64(args, cwd, session, files), cwd, False
        if name == "file" and args:
            return self._file(args, cwd, session, files), cwd, False
        if name == "echo":
            return " ".join(args), cwd, False
        if name == "printf":
            return " ".join(args).replace("\\n", "\n"), cwd, False
        if name == "clear":
            return "", cwd, False
        if name == "which":
            hits = []
            for a in args:
                leaf = a.rsplit("/", 1)[-1]
                if leaf in KNOWN_BINARIES:
                    hits.append(KNOWN_BINARIES[leaf])
            return "\n".join(hits), cwd, False
        if name == "wc":
            return self._wc(args, cwd, files, dirs), cwd, False
        if name == "grep":
            return self._grep(args, cwd, files), cwd, False
        if name == "mount":
            return shelldata.MOUNTS.rstrip("\n"), cwd, False
        if name == "crontab":
            return self._crontab(args, user), cwd, False
        if name == "systemd-detect-virt":
            # On AWS EC2 this returns "xen" (older) or "amazon" / "kvm" depending
            # on the instance; "xen" is still what Ubuntu 22.04 cloud images report.
            return "xen", cwd, False
        if name == "lscpu":
            return _fake_lscpu(), cwd, False
        if name == "dpkg":
            return self._dpkg(args), cwd, False
        if name == "arp":
            return _fake_arp(self.world.get("internal_ip") or "10.0.0.21"), cwd, False
        if name in ("true", ":"):
            return "", cwd, False
        if name == "false":
            return "", cwd, False
        if name in ("test", "["):
            # Minimal: always "succeed" so && chains keep going; bots rarely care.
            return "", cwd, False
        if name == "sleep":
            try:
                secs = float(args[0]) if args else 0
            except ValueError:
                secs = 0
            time.sleep(min(max(secs, 0), 2.0))
            return "", cwd, False
        if name == "type":
            hits = []
            for a in args:
                leaf = a.rsplit("/", 1)[-1]
                if leaf in KNOWN_BINARIES:
                    hits.append("%s is %s" % (leaf, KNOWN_BINARIES[leaf]))
                elif leaf in ("cd", "pwd", "export", "unset", "alias", "echo", "printf",
                              "exit", "logout", "history", "source", "."):
                    hits.append("%s is a shell builtin" % leaf)
                else:
                    hits.append("bash: type: %s: not found" % leaf)
            return "\n".join(hits), cwd, False
        if name == "command" and args and args[0] == "-v":
            leaf = args[1].rsplit("/", 1)[-1] if len(args) > 1 else ""
            if leaf in KNOWN_BINARIES:
                return KNOWN_BINARIES[leaf], cwd, False
            return "", cwd, False
        if name in ("rm", "rmdir", "mkdir", "touch", "chmod", "chown", "cp", "mv", "ln"):
            # Mutating commands succeed silently so a written /tmp/foo sticks via
            # the overlay; we never touch the real host.
            return self._mutate(name, args, cwd, session, files, dirs), cwd, False
        if name == "busybox":
            return ("BusyBox v1.30.1 (Ubuntu 1:1.30.1-7ubuntu3) multi-call binary.\n"
                    "BusyBox is copyrighted by many authors between 1998-2015.\n"
                    "Usage: busybox [function] [arguments]...\n"
                    "   or: busybox --list\n"
                    "Currently defined functions:\n"
                    "[, [[, awk, cat, chmod, chown, cp, cut, date, df, dmesg, echo, "
                    "egrep, false, fgrep, find, free, grep, gunzip, gzip, head, hostname, "
                    "id, ifconfig, kill, ln, ls, mkdir, mknod, more, mount, mv, netstat, "
                    "nice, nslookup, ping, ping6, ps, pwd, rm, rmdir, sed, sh, sleep, "
                    "sort, sync, tail, tar, touch, tr, true, umount, uname, uptime, "
                    "wget, which, xargs, yes, zcat"), cwd, False
        if name in ("ping", "ping6"):
            return self._ping(args, cmd, session), cwd, False
        if name in ("nc", "netcat", "nc.openbsd", "ncat"):
            return self._nc(args, cmd, session), cwd, False
        if name == "passwd":
            return "Changing password for %s.\nCurrent password: " % user, cwd, False
        # Permission / missing paths that bots probe.
        if name in ("cat",) or True:
            pass
        return "%s: command not found" % rawcmd, cwd, False

    # -- helpers ------------------------------------------------------
    def _net_event(self, cmd, session):
        self.event_hook("download-attempt", cmd)
        session.setdefault("events", []).append(
            {"at": time.time(), "kind": "download-attempt", "detail": cmd})

    def _ping(self, args, cmd, session):
        """Egress is blocked: names fail to resolve, IPs get 100% loss."""
        self._net_event(cmd, session)
        count = 4
        host = ""
        skip = False
        for idx, a in enumerate(args):
            if skip:
                skip = False
                continue
            if a == "-c" and idx + 1 < len(args):
                try:
                    count = max(1, min(int(args[idx + 1]), 10))
                except ValueError:
                    return "ping: invalid argument: '%s'" % args[idx + 1]
                skip = True
                continue
            if a in ("-W", "-w", "-i", "-s", "-I", "-t") and idx + 1 < len(args):
                skip = True
                continue
            if a.startswith("-c") and a[2:].isdigit():
                count = max(1, min(int(a[2:]), 10))
                continue
            if a.startswith("-"):
                continue
            host = a
        if not host:
            return ("ping: usage error: Destination address required")
        if not re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", host):
            time.sleep(random.uniform(0.6, 1.2))
            return "ping: %s: Temporary failure in name resolution" % host
        wait = min(count, 3)
        time.sleep(wait + random.uniform(0.1, 0.4))
        ms = count * 1000 + random.randint(5, 60) - 1000
        return ("PING %s (%s) 56(84) bytes of data.\n\n"
                "--- %s ping statistics ---\n"
                "%d packets transmitted, 0 received, 100%% packet loss, time %dms\n"
                % (host, host, host, count, max(ms, 0)))

    def _nc(self, args, cmd, session):
        """No egress: names fail, IPs time out, listeners never see a peer."""
        self._net_event(cmd, session)
        positional = []
        listen = False
        skip = False
        for idx, a in enumerate(args):
            if skip:
                skip = False
                continue
            if a in ("-w", "-p", "-s", "-e", "-c", "-x", "-X", "-i", "-q") and idx + 1 < len(args):
                skip = True
                continue
            if a.startswith("-"):
                if "l" in a[1:]:
                    listen = True
                continue
            positional.append(a)
        if listen:
            time.sleep(2.0)
            return ""
        if not positional:
            return ("usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]\n"
                    "\t  [-m minttl] [-O length] [-P proxy_username] [-p source_port]\n"
                    "\t  [-q seconds] [-s sourceaddr] [-T keyword] [-V rtable] [-W recvlimit]\n"
                    "\t  [-w timeout] [-X proxy_protocol] [-x proxy_address[:port]]\n"
                    "\t  [destination] [port]")
        host = positional[0]
        port = positional[1] if len(positional) > 1 else ""
        if not re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", host):
            time.sleep(random.uniform(0.6, 1.2))
            return "nc: getaddrinfo for host \"%s\" port %s: Temporary failure in name resolution" % (
                host, port or "0")
        time.sleep(random.uniform(2.0, 2.6))
        return "nc: connect to %s port %s (tcp) failed: Connection timed out" % (host, port or "0")

    def _uname(self, args):
        host = self.world["hostname"]
        if "-a" in args or not args:
            return ("Linux %s 5.15.0-101-generic #111-Ubuntu SMP "
                    "Thu Mar 14 13:07:54 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux" % host)
        if "-m" in args:
            return "x86_64"
        if "-r" in args:
            return "5.15.0-101-generic"
        if "-n" in args:
            return host
        if "-s" in args:
            return "Linux"
        if "-p" in args or "-i" in args:
            return "x86_64"
        return "Linux"

    def _uptime_fields(self):
        now = time.time()
        boot = self.boot_time or (now - 47 * 86400)
        secs = max(60, now - boot)
        days = int(secs // 86400)
        rem = int(secs % 86400)
        hours = rem // 3600
        mins = (rem % 3600) // 60
        pretty = ("%d days, %d:%02d" % (days, hours, mins)) if days else ("%d:%02d" % (hours, mins))
        return pretty

    def _uptime_line(self):
        return (" %s up %s,  1 user,  load average: 0.08, 0.03, 0.01"
                % (time.strftime("%H:%M:%S"), self._uptime_fields()))

    def _w_line(self, user):
        return (
            " %s up %s,  1 user,  load average: 0.08, 0.03, 0.01\n"
            "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            "%-8s pts/0    %-16s %s    0.00s  0.04s  0.00s -bash"
            % (time.strftime("%H:%M:%S"), self._uptime_fields(),
               user, self.peer_ip, time.strftime("%H:%M")))

    def _ls(self, cwd, args, files, dirs):
        long_fmt = any(a in ("-l", "-la", "-al", "-lah", "-hal", "-hl") for a in args)
        path_args = [a for a in args if not a.startswith("-")]
        target = resolve(cwd, path_args[-1]) if path_args else cwd
        # Glob support on the last component
        if path_args and any(ch in path_args[-1] for ch in "*?["):
            parent = resolve(cwd, os.path.dirname(path_args[-1]) or ".")
            pat = os.path.basename(path_args[-1])
            names = self._entries(parent, files, dirs)
            matched = [n.rstrip("/") for n in names if fnmatch.fnmatch(n.rstrip("/"), pat)]
            if not matched:
                return "ls: cannot access '%s': No such file or directory" % path_args[-1]
            if long_fmt:
                return "\n".join(self._ls_long_one(parent, n, files, dirs) for n in matched)
            return "\n".join(sorted(matched))
        if target not in dirs and target not in files:
            return "ls: cannot access '%s': No such file or directory" % (path_args[-1] if path_args else target)
        if target in files:
            name = target.rsplit("/", 1)[-1]
            return self._ls_long_one(target.rsplit("/", 1)[0] or "/", name, files, dirs) if long_fmt else name
        entries = self._entries(target, files, dirs)
        if long_fmt:
            total = len(entries)
            lines = ["total %d" % total]
            for name in sorted(entries):
                lines.append(self._ls_long_one(target, name, files, dirs))
            return "\n".join(lines)
        # One entry per line. Real `ls` uses columns only on a tty; over SSH
        # exec (no pty) and when piped (`ls | wc -l`) it prints one per line.
        # Emitting columns here made `ls /usr/bin | wc -l` return 1, a classic
        # honeypot tell.
        return "\n".join(sorted(e.rstrip("/") for e in entries))

    def _entries(self, path, files, dirs):
        entries = set()
        base = path.rstrip("/") or ""
        for other in dirs:
            if other != base and other.rsplit("/", 1)[0] == (base or ""):
                entries.add(other.rsplit("/", 1)[1] + "/")
        for path_name in files:
            if path_name.rsplit("/", 1)[0] == (base or ""):
                entries.add(path_name.rsplit("/", 1)[1])
        return entries

    def _ls_long_one(self, parent, name, files, dirs):
        is_dir = name.endswith("/")
        leaf = name.rstrip("/")
        full = (parent.rstrip("/") + "/" + leaf) if parent != "/" else "/" + leaf
        if parent in ("", "/"):
            full = "/" + leaf
        size = 4096
        if full in files:
            content = files[full]
            size = len(content if isinstance(content, (bytes, bytearray)) else content.encode("utf-8"))
            is_dir = False
        mode = "drwxr-xr-x" if is_dir or full in dirs else "-rw-r--r--"
        if leaf.startswith(".") and not is_dir:
            mode = "-rw-------"
        stamp = time.strftime("%b %e %H:%M")
        return "%s 1 deploy deploy %6d %s %s" % (mode, size, stamp, leaf)

    def _read_cmd(self, name, args, cwd, session, files, dirs):
        if not args:
            return ""
        # Special: /etc/shadow always Permission denied
        target = resolve(cwd, args[-1])
        if target == "/etc/shadow" or target.endswith("/shadow"):
            return "%s: %s: Permission denied" % (name, args[-1])
        # Inject /proc and /bin listings via synthetic content
        if target in _SYNTHETIC:
            return _SYNTHETIC[target]
        if target in files:
            suffix = self.read_hook(target) or ""
            data = files[target]
            if isinstance(data, (bytes, bytearray)):
                return "<binary %d bytes>" % len(data) + suffix
            return data.rstrip("\n") + suffix
        if target in dirs:
            return "%s: %s: Is a directory" % (name, args[-1])
        # /proc/self/* shape
        if target.startswith("/proc/"):
            return self._proc(target, name, args[-1])
        return "%s: %s: No such file or directory" % (name, args[-1])

    def _proc(self, target, name, arg):
        if target in ("/proc/cpuinfo",):
            return shelldata.CPUINFO.rstrip("\n")
        if target in ("/proc/meminfo",):
            return shelldata.MEMINFO.rstrip("\n")
        if target in ("/proc/version",):
            return ("Linux version 5.15.0-101-generic (buildd@lcy02-amd64-001) "
                    "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld "
                    "(GNU Binutils for Ubuntu) 2.38) "
                    "#111-Ubuntu SMP Thu Mar 14 13:07:54 UTC 2024")
        if target in ("/proc/uptime",):
            boot = self.boot_time or (time.time() - 47 * 86400)
            return "%.2f 12345.67" % (time.time() - boot)
        if target in ("/proc/1/cgroup", "/proc/self/cgroup"):
            return shelldata.CGROUP_V1.rstrip("\n")
        if target in ("/proc/mounts", "/proc/self/mounts"):
            return shelldata.MOUNTS.rstrip("\n")
        if target in self.world["files"]:
            data = self.world["files"][target]
            return (data if isinstance(data, str) else data.decode("latin-1", "replace")).rstrip("\n")
        return "%s: %s: No such file or directory" % (name, arg)

    def _head_tail(self, name, args, cwd, session, files, dirs):
        if not args:
            return ""
        n = 10
        path_arg = args[-1]
        for i, a in enumerate(args):
            if a.startswith("-n") and a != "-n":
                try: n = int(a[2:])
                except ValueError: pass
            elif a == "-n" and i + 1 < len(args):
                try: n = int(args[i + 1])
                except ValueError: pass
            elif a.startswith("-") and a[1:].isdigit():
                n = int(a[1:])
        target = resolve(cwd, path_arg)
        if target == "/etc/shadow":
            return "%s: cannot open '%s' for reading: Permission denied" % (name, path_arg)
        if target in files:
            suffix = self.read_hook(target) or ""
            data = files[target]
            if isinstance(data, (bytes, bytearray)):
                return "<binary %d bytes>" % len(data) + suffix
            lines = data.splitlines()
            chunk = lines[:n] if name == "head" else lines[-n:]
            return "\n".join(chunk) + suffix
        if target in dirs:
            return "%s: error reading %s: Is a directory" % (name, path_arg)
        if target in _SYNTHETIC:
            lines = _SYNTHETIC[target].splitlines()
            chunk = lines[:n] if name == "head" else lines[-n:]
            return "\n".join(chunk)
        return "%s: cannot open '%s' for reading: No such file or directory" % (name, path_arg)

    def _find(self, args, cwd, files, dirs):
        start = resolve(cwd, args[0]) if args and not args[0].startswith("-") else cwd
        name = None
        for i, a in enumerate(args):
            if a == "-name" and i + 1 < len(args):
                name = args[i + 1]
        hits = []
        for path in sorted(list(files) + list(dirs)):
            if path == start or path.startswith(start.rstrip("/") + "/"):
                leaf = path.rsplit("/", 1)[-1]
                if name is None or fnmatch.fnmatch(leaf, name):
                    hits.append(path)
        return "\n".join(hits[:80])

    def _openssl(self, args, cwd, session, files):
        joined = " ".join(args)
        if "vault-staging.b64" in joined:
            clear_path = "/home/deploy/notes/vault-cleartext.txt"
            clear = files.get(clear_path, "")
            self.event_hook("openssl-unwrap", "vault-staging.b64")
            suffix = self.read_hook(clear_path) or ""
            if "-out" in args:
                return suffix.lstrip("\n")
            return (clear if isinstance(clear, str) else "").rstrip("\n") + suffix
        return ("openssl: Error reading input\n"
                "1400000000:error:0909006C:PEM routines:get_name:no start line:pem_lib.c:745:")

    def _redirect(self, cmd, rawcmd, cwd, session):
        text_part, op, target_part = cmd.partition(">>")
        if not op:
            text_part, op, target_part = cmd.partition(">")
        target_words = target_part.strip().split()
        dest = resolve(cwd, target_words[0]) if target_words else ""
        if dest.rsplit("/", 1)[-1] == "guestbook.txt" and self.sign_guestbook:
            body = text_part.strip()[len(rawcmd):].strip()
            try:
                body = " ".join(shlex.split(body))
            except ValueError:
                body = body.strip("'\"")
            if body.startswith("-n ") or body.startswith("-e "):
                body = body[3:]
            body = body.replace("\\n", " ")
            self.sign_guestbook(session, body, "shell")
            return ""
        # Persist the write into the in-memory fake filesystem so a follow-up
        # `cat` sees it. Never touches the real host.
        body = text_part.strip()
        # strip the echo/printf command word
        if body.startswith(rawcmd):
            body = body[len(rawcmd):].strip()
        try:
            body = " ".join(shlex.split(body)) if body else ""
        except ValueError:
            body = body.strip("'\"")
        if body.startswith("-n ") or body.startswith("-e "):
            flag, _, body = body.partition(" ")
            if "-e" in flag:
                body = body.replace("\\n", "\n").replace("\\t", "\t")
        if not body.endswith("\n"):
            body = body + "\n"
        if dest:
            home = self.env.get("HOME") or "/home/deploy"
            if not _writable(dest, home):
                return "bash: %s: Permission denied" % dest
            if op == ">>" and dest in self.world["files"]:
                prev = self.world["files"][dest]
                if isinstance(prev, (bytes, bytearray)):
                    prev = prev.decode("latin-1", "replace")
                body = prev + body
            self.world["files"][dest] = body
            self.world.setdefault("overlay", {})[dest] = body
            parent = dest.rsplit("/", 1)[0] or "/"
            if parent not in self.world["dirs"]:
                self.world["dirs"] = sorted(set(self.world["dirs"]) | {parent})
        return ""

    def _base64(self, args, cwd, session, files):
        target = resolve(cwd, args[-1])
        if target not in files:
            return "base64: %s: No such file or directory" % args[-1]
        suffix = self.read_hook(target) or ""
        data = files[target]
        if "-d" in args or "--decode" in args:
            if isinstance(data, (bytes, bytearray)):
                return "base64: invalid input" + suffix
            payload = "".join(ln.strip() for ln in data.splitlines()
                              if ln.strip() and not ln.startswith("#")
                              and not ln.startswith("U2FsdGVk"))
            try:
                raw = base64.b64decode(payload, validate=False)
            except (ValueError, binascii.Error):
                return "base64: invalid input" + suffix
            try:
                return raw.decode("utf-8").rstrip("\n") + suffix
            except UnicodeDecodeError:
                return "<binary %d bytes>" % len(raw) + suffix
        raw = data if isinstance(data, (bytes, bytearray)) else data.encode("utf-8")
        return base64.b64encode(raw[:3000]).decode("ascii") + suffix

    def _file(self, args, cwd, session, files):
        target = resolve(cwd, args[-1])
        if target not in files:
            return "%s: cannot open `%s' (No such file or directory)" % (args[-1], args[-1])
        suffix = self.read_hook(target) or ""
        data = files[target]
        if isinstance(data, (bytes, bytearray)) and data[:8] == b"\x89PNG\r\n\x1a\n":
            kind = "PNG image data"
        else:
            kind = "ASCII text"
        return "%s: %s" % (args[-1], kind) + suffix



    # -- newly added helpers ------------------------------------------
    def _wc(self, args, cwd, files, dirs):
        flags = [a for a in args if a.startswith("-")]
        paths = [a for a in args if not a.startswith("-")]
        want_l = not flags or any(f for f in flags if "l" in f)
        want_w = any(f for f in flags if "w" in f)
        want_c = any(f for f in flags if "c" in f) and not want_l and not want_w
        if not flags:
            want_l = want_w = want_c = True
        # No path: count stdin is not supported; bots usually pass a path or pipe.
        # For `ls /usr/bin | wc -l` the pipe handler currently drops the right
        # side and returns left. To make `wc -l` alone after a pipe look right,
        # when no paths are given answer with the inventory count for /usr/bin
        # if that is a common probe shape. Safer: 0.
        if not paths:
            # Common bot probe: `ls /usr/bin | wc -l` - our pipe returns left
            # only, so this branch rarely runs. Return 0 rather than invent.
            return "0"
        lines_out = []
        for path_arg in paths:
            target = resolve(cwd, path_arg)
            data = files.get(target)
            if data is None and target in dirs:
                # `wc` of a directory: error
                lines_out.append("wc: %s: Is a directory" % path_arg)
                continue
            if data is None:
                lines_out.append("wc: %s: No such file or directory" % path_arg)
                continue
            if isinstance(data, (bytes, bytearray)):
                raw = data
                text = data.decode("latin-1", "replace")
            else:
                text = data
                raw = data.encode("utf-8")
            n_lines = text.count("\n") + (0 if text.endswith("\n") or not text else 1)
            n_words = len(text.split())
            n_bytes = len(raw)
            parts = []
            if want_l and (want_w or want_c or not flags or flags == ["-l"] or any("l" in f for f in flags)):
                # Always include -l when -l present or default
                pass
            # Match GNU wc column order: lines words bytes name
            show_l = (not flags) or any("l" in f for f in flags)
            show_w = (not flags) or any("w" in f for f in flags)
            show_c = (not flags) or any("c" in f for f in flags)
            if flags == ["-l"] or (len(flags) == 1 and flags[0] == "-l"):
                lines_out.append("%7d %s" % (n_lines, path_arg))
                continue
            cols = []
            if show_l: cols.append("%7d" % n_lines)
            if show_w: cols.append("%7d" % n_words)
            if show_c: cols.append("%7d" % n_bytes)
            cols.append(path_arg)
            lines_out.append(" ".join(cols))
        return "\n".join(lines_out)

    def _grep(self, args, cwd, files):
        # Minimal grep: grep [flags] PATTERN FILE
        flags = [a for a in args if a.startswith("-") and a != "--"]
        rest = [a for a in args if not a.startswith("-") or a == "--"]
        if not rest:
            return "Usage: grep [OPTION]... PATTERNS [FILE]..."
        pattern = rest[0]
        paths = rest[1:]
        if not paths:
            return ""  # stdin not supported
        out = []
        for path_arg in paths:
            target = resolve(cwd, path_arg)
            data = files.get(target)
            if data is None:
                out.append("grep: %s: No such file or directory" % path_arg)
                continue
            if isinstance(data, (bytes, bytearray)):
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    out.append("grep: %s: binary file matches" % path_arg)
                    continue
            else:
                text = data
            for line in text.splitlines():
                if pattern in line:
                    out.append(line)
        return "\n".join(out)

    def _crontab(self, args, user):
        if not args or args == ["-l"]:
            content = self.world["files"].get(
                "/var/spool/cron/crontabs/%s" % user) or shelldata.CRONTAB_DEPLOY
            return content.rstrip("\n")
        if args[:1] == ["-e"]:
            return ""  # pretend editor opened and closed
        if args[:1] == ["-r"]:
            return ""
        return "crontab: usage error: unrecognized option"

    def _dpkg(self, args):
        if not args or args[0] in ("-l", "--list"):
            return (
                "Desired=Unknown/Install/Remove/Purge/Hold\n"
                "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n"
                "|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n"
                "||/ Name              Version            Architecture Description\n"
                "+++-=================-==================-============-=================================\n"
                "ii  nginx             1.18.0-6ubuntu14.4 amd64        small, powerful, scalable web server\n"
                "ii  openssh-server    1:8.9p1-3ubuntu0.6 amd64       secure shell (SSH) server\n"
                "ii  postfix           3.6.4-1ubuntu1.3  amd64        High-performance mail transport agent\n"
                "ii  postgresql        14+238             all          object-relational SQL database\n"
                "ii  python3           3.10.6-1~22.04     amd64        interactive high-level object-oriented language\n"
                "ii  vsftpd            3.0.5-0ubuntu1     amd64        lightweight, efficient FTP server written"
            )
        return "dpkg: error: need an action option"

    def _mutate(self, name, args, cwd, session, files, dirs):
        """Pretend to mutate the fake filesystem; never touch the real host.

        Writes land in world['overlay'] (and files) so a subsequent cat/ls
        sees them for the rest of this sensor process. That stops the classic
        honeypot tell where `echo hi > /tmp/x && cat /tmp/x` fails.
        Sensitive paths (/etc, /bin, ...) refuse with Permission denied.
        """
        overlay = self.world.setdefault("overlay", {})
        home = self.env.get("HOME") or "/home/deploy"
        if name == "mkdir":
            for a in [a for a in args if not a.startswith("-")]:
                target = resolve(cwd, a)
                if not _writable(target, home):
                    return "mkdir: cannot create directory '%s': Permission denied" % a
                if target not in dirs:
                    dirs_list = list(self.world["dirs"])
                    dirs_list.append(target)
                    self.world["dirs"] = sorted(set(dirs_list))
            return ""
        if name == "touch":
            for a in [a for a in args if not a.startswith("-")]:
                target = resolve(cwd, a)
                if not _writable(target, home):
                    return "touch: cannot touch '%s': Permission denied" % a
                files.setdefault(target, "")
                overlay[target] = files[target]
            return ""
        if name in ("rm", "rmdir"):
            for a in [a for a in args if not a.startswith("-")]:
                target = resolve(cwd, a)
                if not _writable(target, home):
                    return "rm: cannot remove '%s': Permission denied" % a
                files.pop(target, None)
                overlay.pop(target, None)
                if target in self.world["dirs"]:
                    self.world["dirs"] = [d for d in self.world["dirs"] if d != target]
            return ""
        if name in ("chmod", "chown"):
            return ""
        if name in ("cp", "mv", "ln") and len([a for a in args if not a.startswith("-")]) >= 2:
            positional = [a for a in args if not a.startswith("-")]
            src, dst = resolve(cwd, positional[0]), resolve(cwd, positional[-1])
            if not _writable(dst, home):
                return "%s: cannot create '%s': Permission denied" % (name, positional[-1])
            if src in files:
                files[dst] = files[src]
                overlay[dst] = files[dst]
                if name == "mv":
                    if not _writable(src, home):
                        return "%s: cannot move '%s': Permission denied" % (name, positional[0])
                    files.pop(src, None)
                    overlay.pop(src, None)
            return ""
        return ""


# ---------------------------------------------------------------------------
# Synthetic filesystem content Mirai / cowrie probes look for.
# ---------------------------------------------------------------------------
_CPUINFO = shelldata.CPUINFO
_MEMINFO = shelldata.MEMINFO
_SYNTHETIC = {
    "/proc/cpuinfo": shelldata.CPUINFO,
    "/proc/meminfo": shelldata.MEMINFO,
    "/proc/1/cgroup": shelldata.CGROUP_V1,
    "/proc/self/cgroup": shelldata.CGROUP_V1,
    "/proc/mounts": shelldata.MOUNTS,
}


def seed_synthetic_dirs(world):
    """Populate a believable Ubuntu 22.04 rootfs so ls/find/which look real."""
    dirs = set(world["dirs"])
    files = world["files"]
    for d in (
        "/bin", "/sbin", "/usr", "/usr/bin", "/usr/sbin", "/usr/local",
        "/usr/local/bin", "/usr/local/sbin", "/tmp", "/var/tmp",
        "/proc", "/proc/1", "/proc/self", "/proc/sys", "/proc/sys/kernel",
        "/sys", "/sys/class", "/sys/devices", "/dev", "/dev/shm", "/dev/pts",
        "/run", "/run/user", "/run/user/1001", "/opt", "/mnt", "/media",
        "/boot", "/boot/efi", "/lib", "/lib64", "/home/ubuntu",
        "/var/spool", "/var/spool/cron", "/var/spool/cron/crontabs",
        "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
        "/etc/cron.weekly", "/etc/cron.monthly",
    ):
        dirs.add(d)
    # Populate bin inventories. Empty stub files: `file` says ASCII text, fine
    # for bots that only `ls` / `which` / `command -v`.
    for name in shelldata.BIN_CLASSIC:
        path = "/bin/" + name
        files.setdefault(path, "")
    for name in shelldata.SBIN_CLASSIC:
        path = "/sbin/" + name
        files.setdefault(path, "")
    for name in shelldata.USR_BIN:
        path = "/usr/bin/" + name
        files.setdefault(path, "")
    for name in shelldata.USR_SBIN:
        path = "/usr/sbin/" + name
        files.setdefault(path, "")
    # /proc synthetic files
    files["/proc/cpuinfo"] = shelldata.CPUINFO
    files["/proc/meminfo"] = shelldata.MEMINFO
    files["/proc/mounts"] = shelldata.MOUNTS
    files["/proc/1/cgroup"] = shelldata.CGROUP_V1
    files["/proc/self/cgroup"] = shelldata.CGROUP_V1
    files["/proc/version"] = (
        "Linux version 5.15.0-101-generic (buildd@lcy02-amd64-001) "
        "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) "
        "#111-Ubuntu SMP Thu Mar 14 13:07:54 UTC 2024"
    )
    files["/proc/uptime"] = "0.00 0.00"  # rewritten live by FakeShell._proc
    files["/proc/sys/kernel/hostname"] = world.get("hostname", "localhost") + "\n"
    files["/proc/sys/kernel/osrelease"] = "5.15.0-101-generic\n"
    # cron
    files.setdefault("/etc/crontab", shelldata.ETC_CRONTAB)
    files.setdefault("/var/spool/cron/crontabs/deploy", shelldata.CRONTAB_DEPLOY)
    # A hidden placeholder keeps /tmp in the directory tree even if something
    # later rebuilds dirs from files alone.
    files.setdefault("/tmp/.keep", "")
    files.setdefault("/var/tmp/.keep", "")
    # /etc/shadow exists but is unreadable (Permission denied on cat).
    if "/etc/shadow" not in files:
        files["/etc/shadow"] = (
            "root:*:19755:0:99999:7:::\n"
            "daemon:*:19755:0:99999:7:::\n"
            "ubuntu:!:19755:0:99999:7:::\n"
            "deploy:$6$rounds=4096$xxxxxxxx$yyyy:19755:0:99999:7:::\n"
            "admin:$6$rounds=4096$xxxxxxxx$zzzz:19755:0:99999:7:::\n"
        )
    # Per-session writable overlay lives on the Sensor, not here.
    world["dirs"] = sorted(dirs)
    world.setdefault("overlay", {})  # path -> content, written during a session


def _fake_processes(user="deploy"):
    return (
        "  PID TTY          TIME CMD\n"
        "    1 ?        00:00:02 systemd\n"
        "  512 ?        00:00:01 sshd\n"
        " 1042 ?        00:00:03 nginx\n"
        " 1043 ?        00:00:00 nginx\n"
        " 1088 ?        00:01:17 php-fpm\n"
        " 1090 ?        00:00:44 php-fpm\n"
        " 1129 ?        00:00:41 postgres\n"
        " 1201 ?        00:00:12 postfix\n"
        " 1210 ?        00:00:02 qmgr\n"
        " 1304 ?        00:00:01 vsftpd\n"
        " 2231 pts/0    00:00:00 bash\n"
        " 2240 pts/0    00:00:00 ps")


def _fake_netstat(ports=None):
    # Always present the well-known service ports an attacker expects on a
    # small-business NAS, never the high-port redirects the sensor actually
    # listens on. Listing 2222/8080/2525 would fingerprint the honeypot.
    lines = [
        "Active Internet connections (only servers)",
        "Proto Local Address           Foreign Address         State",
        "tcp   0.0.0.0:22              0.0.0.0:*               LISTEN",
        "tcp   0.0.0.0:80              0.0.0.0:*               LISTEN",
        "tcp   0.0.0.0:443            0.0.0.0:*               LISTEN",
        "tcp   0.0.0.0:25              0.0.0.0:*               LISTEN",
        "tcp   0.0.0.0:21              0.0.0.0:*               LISTEN",
        "tcp   127.0.0.1:5432         0.0.0.0:*               LISTEN",
        "tcp   0.0.0.0:873            0.0.0.0:*               LISTEN",
    ]
    return "\n".join(lines)


def _fake_ifconfig(ip, mac):
    return (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001\n"
        "        inet %s  netmask 255.255.255.0  broadcast %s\n"
        "        ether %s  txqueuelen 1000  (Ethernet)\n"
        "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
        "        inet 127.0.0.1  netmask 255.0.0.0"
        % (ip, ip.rsplit(".", 1)[0] + ".255", mac))


def _fake_df():
    return shelldata.DF_H.rstrip("\n")


def _fake_free(args=None):
    args = args or []
    if "-h" in args or "--human" in args:
        return shelldata.FREE_H.rstrip("\n")
    if "-m" in args:
        return shelldata.FREE_M.rstrip("\n")
    if "-g" in args:
        return shelldata.FREE_G.rstrip("\n")
    if "-b" in args:
        return shelldata.FREE_B.rstrip("\n")
    # default is kilobytes
    return shelldata.FREE_K.rstrip("\n")


def _fake_lscpu():
    return (
        "Architecture:                    x86_64\n"
        "CPU op-mode(s):                  32-bit, 64-bit\n"
        "Address sizes:                   46 bits physical, 48 bits virtual\n"
        "Byte Order:                      Little Endian\n"
        "CPU(s):                          2\n"
        "On-line CPU(s) list:             0,1\n"
        "Vendor ID:                       GenuineIntel\n"
        "Model name:                      Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz\n"
        "Thread(s) per core:              2\n"
        "Core(s) per socket:              1\n"
        "Socket(s):                       1\n"
        "Stepping:                        7\n"
        "CPU max MHz:                     2500.0000\n"
        "CPU min MHz:                     2500.0000\n"
        "BogoMIPS:                        4999.99\n"
        "Hypervisor vendor:               Xen\n"
        "Virtualization type:             full\n"
        "L1d cache:                       32 KiB\n"
        "L1i cache:                       32 KiB\n"
        "L2 cache:                        1 MiB\n"
        "L3 cache:                        35.8 MiB\n"
        "NUMA node(s):                    1\n"
        "NUMA node0 CPU(s):               0,1"
    )


def _fake_arp(ip):
    net = ip.rsplit(".", 1)[0]
    return (
        "? (%s.1) at 06:a1:b2:c3:d4:e5 [ether] on eth0\n"
        "%s.1 (%s.1) at 06:a1:b2:c3:d4:e5 [ether] on eth0"
        % (net, net, net)
    )


def _fake_last(world, boot_time, user="deploy"):
    boot = boot_time or (time.time() - 47 * 86400)
    return (
        "%-8s pts/0        10.0.0.14        %s - %s  (01:02)\n"
        "%-8s pts/0        10.0.0.14        %s - %s  (00:18)\n"
        "reboot   system boot  5.15.0-101-gener %s   still running\n"
        % (user, time.strftime("%a %b %e %H:%M"), time.strftime("%H:%M"),
           user,
           time.strftime("%a %b %e %H:%M", time.localtime(time.time() - 86400)),
           time.strftime("%H:%M", time.localtime(time.time() - 86400 + 1080)),
           time.strftime("%a %b %e %H:%M", time.localtime(boot)))
    )
