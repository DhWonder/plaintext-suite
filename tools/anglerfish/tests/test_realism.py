"""
Regression checks for the 2026-10-18 realism fixes (see REALISM-FIXES-2026-10-18.md).

    python3 tests/test_realism.py

  1. one company identity across all bait, for every persona in the pool
  2. stated AWS region matches the deployment (us-east-1)
  3. /api/status does not leak internals without a session
  4. fake shell honours fd redirections; ping/nc "run" but get nowhere
  5. vsftpd refuses SYST/PWD before login
"""

import os
import re
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from anglerfish import bait, persona as persona_module, shellfake
from anglerfish import sensor as sensor_module
from anglerfish.sensor import Sensor

sensor_module.AUTH_FAIL_DELAY_MIN = 0.01
sensor_module.AUTH_FAIL_DELAY_MAX = 0.01

FAIL = []


def check(label, ok):
    print("  %-62s %s" % (label, "ok" if ok else "FAIL"))
    if not ok:
        FAIL.append(label)
    return ok


def text_of(world):
    return "\n".join(v for v in world["files"].values() if isinstance(v, str))


# Synthetic personas for the consistency check. Identity lives in the operator's
# persona YAML at deploy time; these stand in for a few different installs.
PERSONA_POOL = [
    {"hostname": "files01", "company": "Example Clinic", "domain": "example.net"},
    {"hostname": "fs01", "company": "Meridian Logistics", "domain": "meridian-example.com"},
    {"hostname": "nas-prod", "company": "Castlebridge Media", "domain": "castlebridge.example"},
    {"hostname": "data01", "company": "Peregrine Analytics", "domain": "peregrine.example"},
]
OTHER_BRANDS = [p["company"].split()[0] for p in PERSONA_POOL] + ["Northwind", "Larkfield"]

# 1 + 2. Persona consistency across several identities.
for base in PERSONA_POOL:
    p = dict(base)
    p["fqdn"] = "%s.%s" % (p["hostname"], p["domain"])
    p["internal_ip"] = "10.0.18.13"
    brand = p["company"].split()[0]
    p["planted_logins"] = [
        ["deploy", persona_module.mint_password(brand)],
        ["admin", persona_module.mint_password()],
    ]
    p["canary_seed"] = "seed-for-%s" % brand.lower()
    world, _ = bait.build(console_host="127.0.0.1:8770", sensor_name="t", persona=p)
    blob = text_of(world)
    foreign = [b for b in OTHER_BRANDS if b != brand and re.search(r"\b%s\b" % re.escape(b), blob)]
    check("%s: no foreign company names in bait" % brand, not foreign)
    check("%s: no Northwind/NW tells" % brand,
          not re.search(r"northwind|nw-vault|n0rthw1nd", blob, re.I))
    check("%s: no eu-west-1, region is us-east-1" % brand,
          "eu-west-1" not in blob and "us-east-1" in blob)
    check("%s: no loopback console port in bait" % brand,
          "127.0.0.1:8770" not in blob and ":8770" not in blob)
    deploy_pass = dict(world["logins"])["deploy"]
    compose = world["files"]["/var/www/nas/docker-compose.yml"]
    check("%s: deploy login (%s) planted in compose and accepted" % (brand, deploy_pass),
          deploy_pass in compose and ("deploy", deploy_pass) in world["logins"])

bait.apply_persona(None)
check("default planted logins are deploy+admin with non-empty passwords",
      bait.PLANTED_LOGINS[0][0] == "deploy"
      and bait.PLANTED_LOGINS[1][0] == "admin"
      and len(bait.PLANTED_LOGINS[0][1]) >= 8
      and len(bait.PLANTED_LOGINS[1][1]) >= 8
      and bait.PLANTED_LOGINS[0][1] != bait.PLANTED_LOGINS[1][1])


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def exchange(port, data, read_until_close=True):
    c = socket.create_connection(("127.0.0.1", port), timeout=5)
    c.sendall(data)
    out = b""
    c.settimeout(3)
    try:
        while True:
            chunk = c.recv(65536)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        pass
    c.close()
    return out


hport, fport = free_port(), free_port()
s = Sensor(name="realism", persona=False, classroom=False, bind="127.0.0.1",
           ports=[hport, fport], log_path="/tmp/anglerfish-realism.log",
           status_path="/tmp/anglerfish-realism.json")
# 3. /api/status gating (call the page router directly: protocol-agnostic).
sess = {"events": [], "read_files": [], "credentials": []}
page, ctype, code, _cookie, _hdrs = s._page("/api/status", sess, "GET", b"")
check("anonymous /api/status -> 401", code == 401)
check("anonymous /api/status leaks no internal IP / ports",
      s.world["internal_ip"] not in page and "listen_ports" not in page)
page, ctype, code, _cookie, _hdrs = s._page("/health", sess, "GET", b"")
check("/health -> 200 bare ok", code == 200 and s.world["internal_ip"] not in page)
page, ctype, code, _cookie, _hdrs = s._page("/api/status", sess, "GET", b"", web_user="deploy")
check("signed-in /api/status -> 200 full status", code == 200 and "shares_ok" in page)

# 4. Shell redirections and network tools.
sh = shellfake.FakeShell(s.world, [22, 80], classroom=False, peer_ip="1.2.3.4",
                         read_hook=lambda p: None, sign_guestbook=lambda *a: None,
                         event_hook=lambda *a: None, boot_time=time.time() - 86400)
ss = {"events": [], "commands": [], "read_files": []}
r, _, _ = sh.run_line("ls /nope 2>&1", "/home/deploy", ss)
check("2>&1 is a redirect, not a filename", "2>&1" not in r and "No such file" in r)
r, _, _ = sh.run_line("ls /nope 2>/dev/null", "/home/deploy", ss)
check("2>/dev/null hides the error", r == "")
r, _, _ = sh.run_line("uname -a > /tmp/u.txt; cat /tmp/u.txt", "/home/deploy", ss)
check("cmd > file lands in the overlay", "Linux" in r)
r, _, _ = sh.run_line("ping -c 1 8.8.8.8", "/home/deploy", ss)
check("ping runs with 100% packet loss", "100% packet loss" in r and "not found" not in r)
r, _, _ = sh.run_line("nc -zv evil.example 4444", "/home/deploy", ss)
check("nc runs but cannot resolve", "Temporary failure" in r and "not found" not in r)
check("ping/nc logged as download attempts",
      sum(1 for e in ss["events"] if e["kind"] == "download-attempt") >= 2)
check("nothing escaped to the host", not os.path.exists("/tmp/u.txt"))

# 5. FTP pre-auth: drive _ftp over a socketpair.
a, b = socket.socketpair()
sess_f = {"events": [], "credentials": [], "first_bytes": ""}
s.running = True
import threading
t = threading.Thread(target=s._ftp, args=(a, sess_f), daemon=True)
t.start()
b.settimeout(3)
def ftp(cmd):
    b.sendall(cmd.encode() + b"\r\n")
    time.sleep(0.15)
    return b.recv(4096).decode()
b.recv(4096)  # banner
b.sendall(b"\r\n\r\n")  # nmap GenericLines: vsftpd 3.x must stay silent
check("FTP SYST before login -> 530 (blank lines ignored)", ftp("SYST") == "530 Please login with USER and PASS.\r\n")
check("FTP PWD before login -> 530", ftp("PWD").startswith("530"))
check("FTP FEAT answered pre-login", ftp("FEAT").startswith("211-"))
ftp("QUIT")
b.close()

s.running = False

print()
if FAIL:
    print("%d realism check(s) FAILED" % len(FAIL))
    sys.exit(1)
print("All realism checks passed.")
