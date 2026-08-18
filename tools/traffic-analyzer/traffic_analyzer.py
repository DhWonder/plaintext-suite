#!/usr/bin/env python3
"""
traffic-analyzer: work out who is flooding you, and say so in plain English.

Reads a capture file, or listens to a network card, works out which sources are
a problem and why, and tells you what to change. Every finding comes with the
sentence that explains it, because a score nobody understands is a score nobody
acts on.

USAGE

  Read a capture file
      python3 traffic_analyzer.py attack.pcap
      python3 traffic_analyzer.py attack.pcapng.gz --html report.html
      python3 traffic_analyzer.py attack.pcap --save

  Watch a network card as it happens (Linux, needs sudo)
      sudo python3 traffic_analyzer.py live eth0
      sudo python3 traffic_analyzer.py live any --seconds 60 --save

  Open the browser view, which shows both the past and the present
      python3 traffic_analyzer.py watch
      sudo python3 traffic_analyzer.py watch --live eth0

  Check that websites are up and their certificates are not about to expire
      python3 traffic_analyzer.py sites shop.example.com mail.example.com
      python3 traffic_analyzer.py sites clients.txt --save

  See what has been recorded already
      python3 traffic_analyzer.py sessions
      python3 traffic_analyzer.py show 3
      python3 traffic_analyzer.py sites --history shop.example.com

  Get an email when somebody is attacking you, or a site of yours is down
      python3 traffic_analyzer.py notify setup     write the settings file
      python3 traffic_analyzer.py notify test      prove it can send
      sudo python3 traffic_analyzer.py live eth0 --notify
      python3 traffic_analyzer.py sites clients.txt --notify

OPTIONS

  --html FILE      also write the self contained HTML dashboard
  --json FILE      also write the raw findings as JSON
  --save           record this run in the database so you can look at it later
  --db FILE        which database to use (default ~/.traffic-analyzer/history.db)
  --seconds N      stop a live capture after N seconds
  --log FILE       append alerts to a plain text log while capturing live
  --port N         port for the browser view (default 8724)
  --host ADDRESS   what to listen on (default 127.0.0.1, and leave it there)
  --ui FILE        path to traffic-analyzer-ui.html if it is not found automatically
  --open           open the browser once the view is up
  --top N          how many sources to print (default 12)
  --vt-key KEY     a VirusTotal key. With it, the flagged sources (and only those)
                   are looked up against VirusTotal to see if they are already
                   known attackers. Only the address is sent, never any traffic.
                   Answers are cached so a re-run costs nothing, and it pauses to
                   stay inside the free key's four-a-minute limit. The key can also
                   come from the VT_API_KEY environment variable, to keep it out of
                   your shell history.
  --notify         email you when a live capture finds a hostile source, or a
                   site check finds one down or with a dying certificate. Off
                   unless you pass it, and it needs ~/.plaintext/notify.conf,
                   which `notify setup` writes for you.
  --notify-config FILE  use a different settings file than the default one

It reads pcap and pcapng, either of them gzipped, IPv4 and IPv6, over Ethernet,
raw IP, Linux cooked capture and loopback. Nothing needs installing.

Written by DhWonder for Plaintext IT. MIT licensed.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from trafficanalyzer import analyse, capture, notify, report
from trafficanalyzer import store as store_module


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        print(__doc__.strip())
        return 0

    options, positional = parse_options(args)

    command = positional[0] if positional else ""
    if command == "notify":
        # Setting up, testing and inspecting the notification email settings
        # is the same job for every tool in the suite, so it is the same code.
        return notify.main(positional[1:] or ["show"])
    if command in ("live", "--live"):
        return command_live(positional[1:], options)
    if command in ("watch", "serve", "--serve"):
        return command_watch(options)
    if command == "sites":
        return command_sites(positional[1:], options)
    if command in ("sessions", "--list"):
        return command_sessions(options)
    if command == "show":
        return command_show(positional[1:], options)
    return command_file(positional, options)


# ---------------------------------------------------------------------------
def parse_options(args):
    """Pull the --flags out, leave everything else alone."""
    takes_value = {"--html", "--json", "--db", "--seconds", "--log", "--port",
                   "--host", "--ui", "--top", "--note", "--live", "--history",
                   "--notify-config", "--vt-key"}
    options = {}
    positional = []
    index = 0
    while index < len(args):
        item = args[index]
        if item in takes_value:
            value = args[index + 1] if index + 1 < len(args) else ""
            options[item.lstrip("-")] = value
            index += 2
            continue
        if item.startswith("--"):
            options[item.lstrip("-")] = True
            index += 1
            continue
        positional.append(item)
        index += 1
    return options, positional


def database(options):
    return store_module.Store(options.get("db") or store_module.DEFAULT_PATH)


# ---------------------------------------------------------------------------
# Reading a file
# ---------------------------------------------------------------------------
def command_file(positional, options):
    if not positional:
        print("Which file? Try: python3 traffic_analyzer.py attack.pcap")
        return 2
    path = positional[0]
    if not os.path.exists(path):
        print("No such file: %s" % path)
        return 2

    analyzer = analyse.Analyzer()
    analyzer.origin = os.path.basename(path)
    stats = capture.ReadStats()

    size = os.path.getsize(path)
    show_progress = size > 20 * 1024 * 1024 and sys.stdout.isatty()
    started = time.time()

    def tick(current):
        elapsed = max(time.time() - started, 0.001)
        sys.stdout.write("\r  reading... %s frames, %s used, %s per second   "
                         % ("{:,}".format(current.frames), "{:,}".format(current.used),
                            "{:,.0f}".format(current.frames / elapsed)))
        sys.stdout.flush()

    try:
        for packet in capture.read_packets(path, stats, tick if show_progress else None):
            analyzer.ingest(packet["ts"], packet)
    except capture.CaptureError as exc:
        print("Could not read that capture: %s" % exc)
        return 2
    except KeyboardInterrupt:
        print("\n  stopped early, reporting on what was read so far")

    if show_progress:
        sys.stdout.write("\r" + " " * 70 + "\r")

    analyzer.names = stats.names

    if not analyzer.total_packets:
        print("\nNothing usable in that capture.")
        print()
        for line in report.wrap(stats.explain(), 72):
            print("  " + line)
        print()
        return 1

    rows = analyzer.rows()
    summary = analyzer.summarise(top_n=max(int(options.get("top", 12) or 12), 12), rows=rows)
    summary["read"] = {
        "format": stats.format, "compressed": stats.compressed,
        "frames": stats.frames, "used": stats.used, "truncated": stats.truncated,
        "skipped": stats.skipped, "interfaces": stats.interfaces,
    }

    enrich_reputation(summary, options)

    report.print_report(summary, show=int(options.get("top", 12) or 12))
    print_read_notes(stats)
    write_outputs(summary, options)

    if options.get("save"):
        db = database(options)
        session_id = db.record_analysis(os.path.basename(path), "file", analyzer,
                                        summary, rows, options.get("note", ""))
        db.close()
        print("  Saved as session %d in %s"
              % (session_id, options.get("db") or store_module.DEFAULT_PATH))
        print("  See it again with: python3 traffic_analyzer.py watch")
    print()
    return 0


def enrich_reputation(summary, options):
    """If a VirusTotal key is given, look up the flagged sources and only those.

    The key can come from --vt-key or, so it stays out of shell history, from the
    VT_API_KEY or VIRUSTOTAL_API_KEY environment variable. Without one, nothing
    here runs and the report is exactly as it was.
    """
    key = options.get("vt-key")
    if key is True or not key:
        key = os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY") or ""
    if not key:
        return

    from trafficanalyzer import analyse, reputation

    local = set(summary.get("local_ips") or ())

    def is_public(ip):
        return (not analyse.is_private(ip) and not analyse.is_loopback(ip)
                and ip not in local)

    sources = summary.get("sources") or []
    flagged = [r for r in sources
               if r.get("level") in ("critical", "high") and is_public(r["ip"])]
    if not flagged:
        print("  VirusTotal: no flagged public addresses to look up.")
        print()
        return

    # On the free key each live lookup waits its turn, so checking a hundred
    # flagged sources would sit there for half an hour. In a flood the flagged
    # sources are usually the same botnet anyway, so the first handful already
    # tell the story. Check the busiest ones (they are sorted worst first) and
    # say plainly when more were flagged than were looked up.
    LOOKUP_CAP = 10
    extra = 0
    if len(flagged) > LOOKUP_CAP:
        extra = len(flagged) - LOOKUP_CAP
        flagged = flagged[:LOOKUP_CAP]

    db = database(options)
    checker = reputation.Checker(key=key, store=db, is_public=is_public)

    total = len(flagged)

    def progress(ip, n):
        # Only worth saying while it actually has to wait on the network.
        sys.stdout.write("\r  VirusTotal: looking up %s (%d of %d)      " % (ip, n, total))
        sys.stdout.flush()

    print("  VirusTotal: checking %d flagged address%s. Only the flagged ones are"
          % (total, "" if total == 1 else "es"))
    print("              sent, and only the address, never any traffic.")
    if extra:
        print("              (%d more were flagged; not looked up, to stay within the"
              % extra)
        print("              free key's limit.)")
    results = checker.enrich([r["ip"] for r in flagged], progress=progress)
    sys.stdout.write("\r" + " " * 72 + "\r")

    for row in sources:
        found = results.get(row["ip"])
        if found:
            row["reputation"] = found
    coverage = checker.coverage()
    if extra:
        coverage = (coverage + ", " if coverage else "") + \
            "%d more flagged sources not looked up" % extra
    summary["reputation_coverage"] = coverage
    db.close()


def print_read_notes(stats):
    """Say what the file actually was, and mention anything that was dropped."""
    what = stats.format
    if stats.compressed:
        what += ", gzipped"
    links = ", ".join(sorted(set(
        capture.LINK_NAMES.get(lt, "link type %d" % lt) for lt in stats.link_types)))
    print("  Capture format:   %s over %s" % (what, links or "unknown"))
    if stats.frames != stats.used:
        dropped = stats.frames - stats.used
        print("  Frames not used:  %s of %s" % ("{:,}".format(dropped),
                                                "{:,}".format(stats.frames)))
        for reason, count in sorted(stats.skipped.items(), key=lambda kv: -kv[1])[:3]:
            print("                    %s: %s" % (reason, "{:,}".format(count)))
    if stats.truncated:
        print("  Note:             the file ends mid packet, so it was cut short when")
        print("                    it was saved. Everything up to that point was read.")
    if stats.names:
        print("  Hostnames:        %d carried inside the capture file" % len(stats.names))
    print()


def write_outputs(summary, options):
    if options.get("html"):
        report.render_html(summary, options["html"])
        print("  Dashboard written to %s" % options["html"])
    if options.get("json"):
        import json
        with open(options["json"], "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=1, default=str)
        print("  Data written to %s" % options["json"])


# ---------------------------------------------------------------------------
# Live capture in the terminal
# ---------------------------------------------------------------------------
def command_live(positional, options):
    from trafficanalyzer import live as live_module

    interface = positional[0] if positional else "any"
    seconds = int(options.get("seconds") or 0)
    db = database(options) if options.get("save") else None
    log_path = options.get("log")

    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0:
        print("Live capture needs administrator rights. Try:")
        print("  sudo python3 traffic_analyzer.py live %s" % interface)
        print()

    available = capture.list_interfaces()
    if available and interface != "any" and interface not in available:
        print("There is no interface called %s on this machine." % interface)
        print("Available: %s" % ", ".join(available))
        return 2

    # Say where the emails will go, or why they will not, before the capture
    # starts. Finding out afterwards that nothing was ever going to arrive is
    # the failure worth designing out.
    notifier, said = notify.from_options("traffic-analyzer", options)
    if said:
        print(said)
        print()

    summary = live_module.run_terminal(interface, seconds, store=db, log_path=log_path,
                                       notifier=notifier)
    if summary is None:
        if db:
            db.close()
        return 1

    report.print_report(summary)
    write_outputs(summary, options)
    if db:
        print("  Saved to %s" % (options.get("db") or store_module.DEFAULT_PATH))
        db.close()
    print()
    return 0


# ---------------------------------------------------------------------------
# The browser view
# ---------------------------------------------------------------------------
def command_watch(options):
    from trafficanalyzer import server

    db_path = options.get("db") or store_module.DEFAULT_PATH
    port = int(options.get("port") or 8724)
    host = options.get("host") or "127.0.0.1"

    interface = options.get("live")
    if interface is True:
        interface = "any"

    notifier, said = notify.from_options("traffic-analyzer", options)
    if said:
        print(said)

    monitor = None
    if interface:
        # Start capturing straight away rather than making them click a button.
        from trafficanalyzer import live as live_module
        monitor = live_module.LiveMonitor(interface,
                                          store=store_module.Store(db_path),
                                          log_path=options.get("log"),
                                          notifier=notifier)
        monitor.start_background()
        time.sleep(0.5)
        if monitor.error:
            print(monitor.error)
            return 2
        print("Live capture running on %s." % interface)

    return server.serve(db_path, host=host, port=port,
                        ui_path=options.get("ui"),
                        open_browser=bool(options.get("open")),
                        monitor=monitor, notifier=notifier)


# ---------------------------------------------------------------------------
# Looking at what was recorded before
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Websites and certificates
# ---------------------------------------------------------------------------
def command_sites(positional, options):
    from trafficanalyzer import services

    if options.get("history"):
        db = database(options)
        host = services.tidy(options["history"] if isinstance(options["history"], str)
                             else (positional[0] if positional else ""))
        rows = db.check_history(host)
        db.close()
        if not rows:
            print("Nothing recorded for %s yet." % host)
            return 1
        print()
        print("  %-20s %-11s %-9s %-8s %s" % ("WHEN", "STATE", "ANSWERED", "CERT", "HEADLINE"))
        print("  " + "-" * 72)
        for row in rows:
            print("  %-20s %-11s %-9s %-8s %s"
                  % (time.strftime("%d %b %H:%M", time.localtime(row["checked_at"])),
                     row["level"], row["status"] or "-",
                     ("%dd" % row["cert_days"]) if row["cert_days"] is not None else "-",
                     row["headline"]))
        print()
        return 0

    hosts = services.load_hosts(positional)
    if not hosts:
        print("Which sites? Try: python3 traffic_analyzer.py sites shop.example.com")
        print("Or put one hostname per line in a file and pass the file.")
        return 2

    print()
    print("  Checking %d site%s. This asks each one for its front page, the same as a browser."
          % (len(hosts), "" if len(hosts) == 1 else "s"))
    print()

    results = services.check_all(hosts)
    worst = {"critical": 0, "high": 0, "watch": 0, "normal": 0}

    for result in results:
        worst[result["level"]] = worst.get(result["level"], 0) + 1
        print("  %s  %s" % (report.paint("%-11s" % result["level"].upper(), result["level"]),
                            result["host"]))
        for note in result["notes"]:
            if not note:
                continue
            for index, line in enumerate(report.wrap(note, 66)):
                print("      %s%s" % ("- " if index == 0 else "  ", line))
        print()

    trouble = worst["critical"] + worst["high"]
    if trouble:
        print("  %d of %d need attention." % (trouble, len(results)))
    else:
        print("  All %d fine." % len(results))

    if options.get("save"):
        db = database(options)
        db.save_checks(results)
        db.close()
        print("  Saved to %s" % (options.get("db") or store_module.DEFAULT_PATH))
    if options.get("notify"):
        notify_sites(results, options)
    print()
    return 1 if trouble else 0


def notify_sites(results, options):
    """Email about sites that are down, or whose certificate is going.

    One message for all of them, because five sites behind the same failing
    server is one problem and five emails about it is one problem too many.

    A site that is merely slow does not email. That is worth knowing at nine in
    the morning, not at three, and the report on screen already says it. Only
    the two things a customer would notice get you woken up: the site is not
    answering, or the browser is telling visitors it is dangerous.
    """
    notifier, said = notify.from_options("traffic-analyzer", options)
    if said:
        print(said)
    if not notifier.available:
        print()
        return

    worth_saying = []
    for result in results:
        if result["level"] not in ("critical", "high"):
            continue
        # A certificate with three weeks left does not need a daily reminder.
        # A site that is down right now does. The headline is part of the key,
        # so a site that gets worse emails again straight away rather than
        # waiting out the quiet period it earned while it was merely expiring.
        gap = 6 * 3600 if result["level"] == "critical" else 24 * 3600
        if notifier.allow("site:%s:%s" % (result["host"], result["headline"]), gap):
            worth_saying.append(result)

    if not worth_saying:
        print("  Nothing emailed: these were all in the last notification.")
        print()
        return

    lines = []
    for result in worth_saying:
        lines.append("%s  %s" % (result["level"].upper(), result["host"]))
        lines.append("  %s" % result["headline"])
        for note in result["notes"]:
            if not note:
                continue
            for index, line in enumerate(report.wrap(note, 68)):
                lines.append("    %s%s" % ("- " if index == 0 else "  ", line))
        lines.append("")
    lines.append("Checked the way a browser checks: asked each site for its front")
    lines.append("page and read the certificate it presented. Nothing was scanned.")

    if len(worth_saying) == 1:
        subject = "%s: %s" % (worth_saying[0]["host"],
                              worth_saying[0]["headline"].lower())
    else:
        subject = "%d sites need attention" % len(worth_saying)

    print("  %s" % notifier.send(subject, lines).detail)


def command_sessions(options):
    db = database(options)
    sessions = db.sessions()
    if not sessions:
        print("Nothing recorded yet. Add --save when you read a capture, or run:")
        print("  sudo python3 traffic_analyzer.py live any --save --seconds 60")
        db.close()
        return 0

    print()
    print("  %-4s %-11s %-26s %-11s %-9s %-8s %s"
          % ("ID", "WHEN", "WHAT", "PACKETS", "SOURCES", "HOSTILE", "STATE"))
    print("  " + "-" * 84)
    for record in sessions:
        when = time.strftime("%d %b %H:%M", time.localtime(record["created_at"]))
        state = "running" if record["running"] else "finished"
        print("  %-4d %-11s %-26s %-11s %-9s %-8s %s"
              % (record["id"], when, record["label"][:26],
                 "{:,}".format(record["packets"] or 0),
                 "{:,}".format(record["sources"] or 0),
                 "{:,}".format(record["hostile"] or 0), state))
    print()
    print("  Look at one with:  python3 traffic_analyzer.py show <id>")
    print("  Or in the browser: python3 traffic_analyzer.py watch")
    print()
    db.close()
    return 0


def command_show(positional, options):
    if not positional:
        print("Which session? Run: python3 traffic_analyzer.py sessions")
        return 2
    db = database(options)
    try:
        record = db.session(int(positional[0]))
    except ValueError:
        print("Session ids are numbers.")
        db.close()
        return 2
    if record is None:
        print("No session with that id.")
        db.close()
        return 2

    summary = record["summary"]
    if not summary:
        print("That session has no saved report. It may still be running.")
        db.close()
        return 1
    report.print_report(summary, show=int(options.get("top", 12) or 12))
    write_outputs(summary, options)
    db.close()
    print()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
