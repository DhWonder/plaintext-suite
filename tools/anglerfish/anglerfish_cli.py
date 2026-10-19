#!/usr/bin/env python3
"""
anglerfish: a machine that looks worth breaking into, and tells on whoever does.

A honeypot. You open what looks like an ordinary, slightly careless small
business server: a login that only planted credentials open, an admin panel
somebody forgot about, and files on it that a thief wants. Real people have no reason to touch
it, so anyone who does is either scanning you or up to something, and now you
are watching them do it in detail instead of guessing.

The files on it are bait. Every secret is fake and unique to that sensor.
The URL bait is a /t/<id> link on your console, so if somebody opens it the
console records which piece was used. AWS-shaped keys and passwords do not
phone home. You never go near the attacker's machine.

USAGE

  Run a sensor: the honeypot itself, on a machine you want to watch
      sudo python3 anglerfish_cli.py sensor --ports 22 80 25 21 23
      python3 anglerfish_cli.py sensor --ports 2222 8080 2525 2121 2323
      python3 anglerfish_cli.py sensor --bind 127.0.0.1 --ports 2222 8080
      python3 anglerfish_cli.py sensor --console http://10.0.0.9:8770

  Run the console: where your sensors report, watched in a browser
      python3 anglerfish_cli.py console
      python3 anglerfish_cli.py console --port 8770 --open

  See what has happened, from the command line
      python3 anglerfish_cli.py report

  A tagged forensic audit: every move, tagged to MITRE ATT&CK, scored
      python3 anglerfish_cli.py audit

  Get an email when somebody touches a sensor, or takes the bait
      python3 anglerfish_cli.py notify setup     write the settings file
      python3 anglerfish_cli.py notify test      prove it can send
      python3 anglerfish_cli.py console --notify

OPTIONS

  --ports N [N ...]   which ports the sensor listens on. Default without root
                      is 2222 8080 2525 2121 2323 (ssh/http/smtp/ftp/telnet
                      facades on high ports). Prefer 22 80 25 21 23 with sudo
                      so scanners actually hit you. A port something else
                      already holds is reported and skipped. Do not move sshd
                      off 22 to make room while that is how you reach the machine.
  --bind ADDRESS      what the sensor listens on (default 0.0.0.0). That means
                      reachable on the network; use 127.0.0.1 for a local-only
                      test. Binding to 0.0.0.0 is an explicit choice to catch
                      probes.
  --console URL       where this sensor reports. Without it, the sensor still
                      records everything locally.
  --name NAME         a name for this sensor, so the console can tell them apart
  --db FILE           the console database (default ~/.anglerfish/console.db)
  --log FILE          the sensor's local session log
  --host ADDRESS      what the console listens on (default 127.0.0.1, leave it)
  --port N            the console's port (default 8770)
  --open              open the console in a browser
  --notify            email you when a sensor is connected to and when a
                      canary token fires. Console only, and off unless you
                      pass it. Needs ~/.plaintext/notify.conf, which
                      `notify setup` writes for you.
  --notify-config FILE  use a different settings file than the default

WHY ONLY THE CONSOLE SENDS MAIL

  The sensor is a machine you have decided to treat as untrusted, and the
  README tells you to give it no credentials for anything. A mail password
  sitting on it would be exactly the thing an attacker who got in another way
  would take. So the sensors report inward to the console, and the console,
  which lives somewhere you do trust, is what emails you.

SAFE BY DESIGN

  The sensor never runs anything an attacker sends. Every command gets a
  scripted answer from a fake filesystem. Whatever they type, the real machine
  does nothing but write it down. It is a puppet show with a notebook, not a
  trap that fights back, and it cannot be turned against you or anyone else.

  The console only ever receives. Your sensors report to it; it never sends a
  command to anything. Reports flow one way, inward.

WHAT THIS WILL NOT DO

  It will not touch an attacker's machine. Following someone by breaking into
  their computer is illegal wherever you are, and it is not what this is for.
  The tokens are the honest way to follow them: you leave bait that calls home,
  and you wait.

Written by DhWonder for Plaintext IT. MIT licensed.
Run it on machines you own, on a network you control.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from anglerfish import notify
from anglerfish import store as store_module


def _safe(text):
    """Strip control/escape chars before printing attacker-controlled text."""
    text = str(text or "")
    return "".join(ch if (ch.isprintable() or ch in "\t") else "?" for ch in text)


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        print(__doc__.strip())
        return 0

    options, positional = parse_options(args)
    command = positional[0] if positional else ""

    if command == "sensor":
        return run_sensor(options)
    if command == "console":
        return run_console(options)
    if command in ("report", "sessions"):
        return run_report(options)
    if command in ("audit", "analyze"):
        return run_audit(options)
    if command == "notify":
        # Same settings, same commands, as every other tool in the suite.
        return notify.main(positional[1:] or ["show"])

    print("I do not know that command. Try:")
    print("  python3 anglerfish_cli.py sensor --ports 2222 8080 2525 2121 2323")
    print("  python3 anglerfish_cli.py console")
    print("  python3 anglerfish_cli.py report")
    print("  python3 anglerfish_cli.py audit")
    print("  python3 anglerfish_cli.py notify test")
    return 2


def parse_options(args):
    options, positional = {}, []
    index = 0
    while index < len(args):
        item = args[index]
        if item == "--ports":
            ports = []
            index += 1
            while index < len(args) and args[index].isdigit():
                ports.append(int(args[index]))
                index += 1
            options["ports"] = ports
            continue
        if item in ("--console", "--name", "--db", "--log", "--host", "--port",
                    "--bind", "--notify-config", "--vt-key", "--abuseipdb-key",
                    "--greynoise-key", "--state-dir", "--token", "--persona"):
            options[item.lstrip("-")] = args[index + 1] if index + 1 < len(args) else ""
            index += 2
            continue
        if item.startswith("--"):
            options[item.lstrip("-")] = True
            index += 1
            continue
        positional.append(item)
        index += 1
    return options, positional


# ---------------------------------------------------------------------------
def run_sensor(options):
    from anglerfish import bait
    from anglerfish.sensor import Sensor, DEFAULT_PORTS, DEFAULT_PORTS_PRIVILEGED, SERVICE_BY_PORT

    ports = options.get("ports") or list(DEFAULT_PORTS)
    bind = options.get("bind") or "0.0.0.0"
    if isinstance(bind, bool):
        bind = "0.0.0.0"
    low = [p for p in ports if p < 1024]
    if low and hasattr(os, "geteuid") and os.geteuid() != 0:
        print("Ports %s need administrator rights. Either run with sudo, or use high"
              % ", ".join(str(p) for p in low))
        print("ports like %s, which still get the same facades."
              % " ".join(str(p) for p in DEFAULT_PORTS))
        print("Recommended with sudo so scanners actually hit you: %s"
              % " ".join(str(p) for p in DEFAULT_PORTS_PRIVILEGED))
        return 2

    if options.get("notify"):
        # Better to refuse clearly than to accept the flag and send nothing.
        print("The sensor does not send email, on purpose. This machine is the one you")
        print("have decided to treat as untrusted, so it holds no mail password. Run")
        print("the console with --notify instead, and point this sensor at it:")
        print("  python3 anglerfish_cli.py console --notify")
        print("  python3 anglerfish_cli.py sensor --ports %s --console http://your-console:8770"
              % " ".join(str(p) for p in ports))
        return 2

    classroom = bool(options.get("classroom"))
    state_dir = options.get("state-dir") or ""
    token = options.get("token") or ""
    config_path = options.get("persona") or ""
    sensor = Sensor(name=options.get("name", ""), console=options.get("console", ""),
                    log_path=options.get("log", ""), ports=ports, bind=bind,
                    classroom=classroom, state_dir=state_dir, console_token=token,
                    config_path=config_path)

    print("anglerfish sensor '%s' listening on %s port(s) %s"
          % (sensor.name, bind, ", ".join(str(p) for p in ports)))
    print("  persona: %s (%s)  host key %s"
          % (sensor.world["hostname"], sensor.world.get("fqdn"),
             sensor.host_keys.fingerprint_sha256()))
    for p in ports:
        print("  %5d  %s" % (p, SERVICE_BY_PORT.get(p, "ssh")))
    if bind == "0.0.0.0":
        print("Bound to 0.0.0.0 (reachable on the network). Use --bind 127.0.0.1 for local-only.")
    if sensor.console:
        print("Reporting to console at %s" % sensor.console)
        if sensor.console_token:
            print("  (shared token set; console must be started with the same --token)")
    else:
        print("No console set, recording locally to %s" % sensor.log_path)
    print("Probe status: %s" % sensor.status_path)
    print("Planted %d canary tokens in the bait." % len(sensor.tokens))
    print("Planted logins (also in the README):")
    for user, pw in bait.PLANTED_LOGINS:
        print("  %s / %s" % (user, pw))
    if classroom:
        print("Classroom mode: playful GOTCHA prompts enabled.")
    print("Wrong passwords are refused and logged. Nothing here runs attacker input.")
    print("Ctrl+C to stop.")
    print()

    sensor.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sensor.stop()
        print("\nStopped. %d session(s) recorded this run." % len(sensor.sessions))
    return 0


def run_console(options):
    from anglerfish import console as console_module

    db_path = options.get("db") or store_module.DEFAULT_PATH
    host = options.get("host") or "127.0.0.1"
    port = int(options.get("port") or 8770)
    ui = find_ui()
    shared_token = options.get("token") or ""

    notifier, said = notify.from_options("anglerfish", options)
    if said:
        print(said.strip())

    if options.get("open"):
        try:
            import webbrowser
            import threading
            where = "http://%s:%d/" % (host if host != "0.0.0.0" else "127.0.0.1", port)
            threading.Timer(0.6, lambda: webbrowser.open(where)).start()
        except Exception:
            pass

    # Keys are read here, on the console, and never handed to a sensor. A
    # sensor is a machine left where attackers can reach it; it holds nothing
    # of yours worth taking.
    def pick(option, *names):
        value = options.get(option)
        if value is True or not value:
            for name in names:
                if os.environ.get(name):
                    return os.environ[name]
            return ""
        return value

    keys = {
        "vt": pick("vt-key", "VT_API_KEY", "VIRUSTOTAL_API_KEY"),
        "abuseipdb": pick("abuseipdb-key", "ABUSEIPDB_API_KEY"),
        "greynoise": pick("greynoise-key", "GREYNOISE_API_KEY"),
    }
    # GreyNoise and the blocklists need no key, so --reputation on its own is
    # enough to answer the question that matters here: swept up, or picked out.
    reputation_keys = keys if (options.get("reputation") or any(keys.values())) else None
    if reputation_keys is not None:
        print("Reputation: attacker addresses will be crossed against the databases,")
        print("            to say whether you were swept up in a scan or picked out.")
        print("            Only the address is sent, and only from this console.")

    if shared_token:
        print("Shared token required for sensor reports (X-Anglerfish-Token).")
    console_module.serve(db_path, host=host, port=port, ui_path=ui, notifier=notifier,
                         reputation_keys=reputation_keys, shared_token=shared_token)
    return 0


def run_report(options):
    db_path = options.get("db") or store_module.DEFAULT_PATH
    if not os.path.exists(db_path):
        print("No console database yet at %s." % db_path)
        print("Run the console and point a sensor at it first.")
        return 1
    store = store_module.Store(db_path)
    overview = store.overview()
    counts = overview["counts"]

    print()
    print("  anglerfish, what your sensors have seen")
    print("  " + "-" * 54)
    print("  Sensors reporting:   %d" % counts["sensors"])
    print("  Sessions in total:   %s  (%d in the last day)"
          % (counts["sessions"], counts["sessions_today"]))
    print("  Distinct attackers:  %d" % counts["attackers"])
    print("  Logins captured:     %d" % counts["credentials"])
    print("  Tokens triggered:    %d of %d planted"
          % (counts["triggers"], counts["tokens"]))
    print()

    if overview["top_attackers"]:
        print("  Busiest sources")
        print("  %-20s %-9s %-9s %s" % ("ADDRESS", "SESSIONS", "COMMANDS", "LAST SEEN"))
        for row in overview["top_attackers"]:
            print("  %-20s %-9s %-9s %s"
                  % (row["peer_ip"], row["sessions"], row["commands"] or 0,
                     time.strftime("%d %b %H:%M", time.localtime(row["last"]))))
        print()

    if overview["recent_triggers"]:
        print("  Bait that was used (this is the part that matters)")
        for trigger in overview["recent_triggers"][:8]:
            print("  %s  %s used from %s"
                  % (time.strftime("%d %b %H:%M", time.localtime(trigger["at"])),
                     trigger.get("label") or trigger["token_id"], trigger["source_ip"]))
        print()

    store.close()
    return 0



def run_audit(options):
    """A tagged, scored forensic audit of everything the sensors recorded.

    Read-only. Reaches nothing. Turns the raw event stream into MITRE
    ATT&CK-tagged movements, a per-session verdict, and the graffiti wall.
    """
    from anglerfish import analyze as analyze_module
    db_path = options.get("db") or store_module.DEFAULT_PATH
    if not os.path.exists(db_path):
        print("No console database yet at %s." % db_path)
        print("Run the console and point a sensor at it first.")
        return 1
    store = store_module.Store(db_path)
    details = []
    for row in store.sessions(limit=500):
        full = store.session(row["id"])
        if full:
            full.setdefault("id", row["id"])
            full.setdefault("sensor", row.get("sensor", ""))
            details.append(full)
    report = analyze_module.audit(details)
    store.close()

    t = report["totals"]
    print()
    print("  anglerfish forensic audit")
    print("  " + "=" * 54)
    print("  Sessions analysed:   %d from %d distinct source(s)"
          % (t["sessions"], t["attackers"]))
    print("  ATT&CK techniques:   %d across %d tactic(s)"
          % (t["techniques"], t["tactics"]))
    print("  Average threat score: %d / 100" % t["avg_score"])
    print("  Graffiti left:       %d note(s)" % t["graffiti"])
    print()

    print("  Who came knocking")
    for actor, n in sorted(report["by_actor"].items(), key=lambda kv: -kv[1]):
        print("    %-22s %d" % (actor, n))
    print()

    print("  Severity of sessions")
    for sev in reversed(analyze_module.SEVERITY_ORDER):
        n = report["by_severity"].get(sev, 0)
        if n:
            print("    %-10s %s" % (sev, "#" * n + "  " + str(n)))
    print()

    print("  MITRE ATT&CK coverage (what they actually did)")
    print("  %-10s %-11s %-9s %s" % ("SEVERITY", "TECHNIQUE", "SESSIONS", "WHAT"))
    for c in report["attack_coverage"]:
        print("  %-10s %-11s %-9d %s / %s"
              % (c["severity"], c["technique_id"], c["sessions"],
                 c["tactic"], c["technique"]))
    print()

    if report["top_bait"]:
        print("  Bait that was taken")
        for b in report["top_bait"][:10]:
            print("    %3dx  %s" % (b["count"], b["path"]))
        print()

    print("  Highest-threat sessions")
    for s in report["sessions"][:8]:
        when = time.strftime("%d %b %H:%M", time.localtime(s["started"]))
        print("    [%3d] %-15s %s  %s"
              % (s["score"], s["peer_ip"], when, s["verdict"]))
        for h in s["highlights"][:3]:
            print("          - %s" % h)
    print()

    wall = report["graffiti_wall"]
    print("  Graffiti wall -- 'I was here' (%d)" % len(wall))
    if not wall:
        print("    (nobody has signed yet)")
    for g in wall[:15]:
        when = time.strftime("%d %b %H:%M", time.localtime(g.get("at", 0)))
        print("    %s  %-15s  \"%s\""
              % (when, g.get("peer_ip", "?"), _safe((g.get("note") or "")[:80])))
    print()

    print("  Full event timeline: %d tagged movement(s). Open the console for the"
          % len(report["timeline"]))
    print("  replay and per-event tags:  python3 anglerfish_cli.py console --open")
    print()
    return 0


def find_ui():
    """Where the console page might be sitting, in order of preference.

    The page ships inside the package, next to the code that serves it, so a
    copy of just this folder still has a working console. The other paths are
    for when it has been unpacked somewhere else or is being served from the
    website copy.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "anglerfish", "console.html"),
        os.path.join(here, "web", "anglerfish-console.html"),
        os.path.join(here, "console.html"),
        os.path.join(here, "..", "..", "website", "anglerfish-console.html"),
    ]
    for path in candidates:
        full = os.path.abspath(path)
        if os.path.exists(full):
            return full
    return None


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
