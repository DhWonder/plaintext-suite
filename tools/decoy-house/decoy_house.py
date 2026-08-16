#!/usr/bin/env python3
"""
decoy-house: a machine that looks worth breaking into, and tells on whoever does.

A honeypot. You open what looks like an ordinary, slightly careless small
business server: a login that lets anyone in, an admin panel somebody forgot
about, and files on it that a thief wants. Real people have no reason to touch
it, so anyone who does is either scanning you or up to something, and now you
are watching them do it in detail instead of guessing.

The files on it are bait. Every secret is a canary token: fake, unique, and
wired so that if it is ever used it phones your console and tells you. That is
how you follow an attacker after they leave, without ever going near their
machine. You left something that calls you, and it did.

USAGE

  Run a sensor: the honeypot itself, on a machine you want to watch
      sudo python3 decoy_house.py sensor --ports 22 80 2222
      python3 decoy_house.py sensor --ports 2222 8080 --console http://10.0.0.9:8770

  Run the console: where your sensors report, watched in a browser
      python3 decoy_house.py console
      python3 decoy_house.py console --port 8770 --open

  See what has happened, from the command line
      python3 decoy_house.py report

  Get an email when somebody touches a sensor, or takes the bait
      python3 decoy_house.py notify setup     write the settings file
      python3 decoy_house.py notify test      prove it can send
      python3 decoy_house.py console --notify

OPTIONS

  --ports N [N ...]   which ports the sensor listens on. Ports under 1024 (like
                      22 and 80, the ones attackers actually try) need sudo. A
                      port something else already holds is reported and skipped,
                      so check the startup lines. Do not move sshd off 22 to
                      make room while that is how you reach the machine.
  --console URL       where this sensor reports. Without it, the sensor still
                      records everything locally.
  --name NAME         a name for this sensor, so the console can tell them apart
  --db FILE           the console database (default ~/.decoy-house/console.db)
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

from decoyhouse import notify
from decoyhouse import store as store_module


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
    if command == "notify":
        # Same settings, same commands, as every other tool in the suite.
        return notify.main(positional[1:] or ["show"])

    print("I do not know that command. Try:")
    print("  python3 decoy_house.py sensor --ports 2222 8080")
    print("  python3 decoy_house.py console")
    print("  python3 decoy_house.py report")
    print("  python3 decoy_house.py notify test")
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
                    "--notify-config"):
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
    from decoyhouse.sensor import Sensor

    ports = options.get("ports") or [2222, 8080]
    low = [p for p in ports if p < 1024]
    if low and hasattr(os, "geteuid") and os.geteuid() != 0:
        print("Ports %s need administrator rights. Either run with sudo, or use high"
              % ", ".join(str(p) for p in low))
        print("ports like 2222 and 8080, which port scanners check anyway.")
        return 2

    if options.get("notify"):
        # Better to refuse clearly than to accept the flag and send nothing.
        print("The sensor does not send email, on purpose. This machine is the one you")
        print("have decided to treat as untrusted, so it holds no mail password. Run")
        print("the console with --notify instead, and point this sensor at it:")
        print("  python3 decoy_house.py console --notify")
        print("  python3 decoy_house.py sensor --ports %s --console http://your-console:8770"
              % " ".join(str(p) for p in ports))
        return 2

    sensor = Sensor(name=options.get("name", ""), console=options.get("console", ""),
                    log_path=options.get("log", ""), ports=ports)

    print("decoy-house sensor '%s' listening on port(s) %s"
          % (sensor.name, ", ".join(str(p) for p in ports)))
    if sensor.console:
        print("Reporting to console at %s" % sensor.console)
    else:
        print("No console set, recording locally to %s" % sensor.log_path)
    print("Planted %d canary tokens in the bait." % len(sensor.tokens))
    print("Nothing here runs anything an attacker sends. Ctrl+C to stop.")
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
    from decoyhouse import console as console_module

    db_path = options.get("db") or store_module.DEFAULT_PATH
    host = options.get("host") or "127.0.0.1"
    port = int(options.get("port") or 8770)
    ui = find_ui()

    notifier, said = notify.from_options("decoy-house", options)
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

    console_module.serve(db_path, host=host, port=port, ui_path=ui, notifier=notifier)
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
    print("  decoy-house, what your sensors have seen")
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


def find_ui():
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "console.html"),
        os.path.join(here, "..", "..", "website", "decoy-house-console.html"),
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
