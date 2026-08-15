#!/usr/bin/env python3
"""
decoy-door - a fake door that writes down who rattles the handle.

This is a honeypot, which is a simpler idea than the name suggests:
you open a door on your network that nothing legitimate ever uses.
Real users have no reason to touch it, so ANYONE who knocks is either
scanning your network or up to something. The door leads nowhere -
it just writes down who knocked, when, and what they said.

Why bother? Two reasons I've seen pay off in practice:

  1. It answers "is anyone actually poking at us?" with data instead
     of guesses. (Spoiler for internet-facing machines: yes, within
     minutes, from everywhere. Watching that happen live changes how
     seriously people take their passwords.)
  2. Inside an office network it works as a tripwire. Nothing should
     ever touch it - so the day something does, you want to know.

What this deliberately is NOT: it never answers with a shell, never
runs anything it receives, and reads at most a few hundred bytes per
visitor before closing the door. It is a doorbell log, not a trap
that fights back.

Usage:
    python3 decoy_door.py listen 2222 2323 8080     # open fake doors
    python3 decoy_door.py report                    # who knocked?

Ports below 1024 (like the real SSH port 22) need administrator
rights on most systems. The high ports above are fine for a first
run - port scanners check them anyway.

DhWonder, Plaintext IT - MIT license.
"""

import datetime
import selectors
import socket
import sys
from collections import Counter

LOG_FILE = "decoy-door.log"

# How much we let a visitor "say" before we close the connection.
# Enough to identify what tool is knocking; far too little to matter.
MAX_PEEK_BYTES = 256

# How long we wait for that first message before closing anyway.
PEEK_TIMEOUT_SECONDS = 5.0


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_line(text):
    """Every event goes to the screen and to the log file, timestamped."""
    line = "%s  %s" % (now(), text)
    print(line, flush=True)
    with open(LOG_FILE, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def printable_preview(data):
    """Turn whatever bytes a visitor sent into something safe to print.
    Anything non-printable becomes a dot - we never trust visitor input,
    not even to display it."""
    text = data.decode("ascii", errors="replace")
    cleaned = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text)
    return cleaned[:120]


# ----------------------------------------------------------------------
# listen mode
# ----------------------------------------------------------------------

def listen(ports):
    """Open a listening socket on each requested port and wait.

    Everything runs in one thread using selectors, which keeps the code
    small and easy to follow: we're a doorbell, not a web server."""

    sel = selectors.DefaultSelector()
    opened = []

    for port in ports:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("0.0.0.0", port))
        except PermissionError:
            print("Port %d needs administrator rights (ports under 1024 do). "
                  "Skipping it - try a high port like %d instead." % (port, port + 2200))
            continue
        except OSError as exc:
            print("Could not open port %d: %s. Skipping it." % (port, exc))
            continue
        server.listen(16)
        server.setblocking(False)
        sel.register(server, selectors.EVENT_READ, data=None)
        opened.append(port)

    if not opened:
        print("No ports could be opened. Nothing to do.")
        sys.exit(2)

    log_line("decoy-door listening on port(s): %s" % ", ".join(map(str, opened)))
    print("(press Ctrl+C to stop; every visit is written to %s)" % LOG_FILE)

    # visitors we're currently "peeking" at: socket -> (address, port, deadline)
    peeking = {}

    try:
        while True:
            events = sel.select(timeout=1.0)
            for key, _ in events:
                if key.data is None:
                    # A new knock on one of the doors.
                    server = key.fileobj
                    conn, addr = server.accept()
                    conn.setblocking(False)
                    port = conn.getsockname()[1]
                    deadline = _monotonic() + PEEK_TIMEOUT_SECONDS
                    peeking[conn] = (addr[0], port, deadline)
                    sel.register(conn, selectors.EVENT_READ, data="visitor")
                    log_line("KNOCK  port %-5d from %s" % (port, addr[0]))
                else:
                    # A visitor said something. Note it, close the door.
                    conn = key.fileobj
                    ip, port, _ = peeking.get(conn, ("?", 0, 0))
                    try:
                        data = conn.recv(MAX_PEEK_BYTES)
                    except OSError:
                        data = b""
                    if data:
                        log_line('SAID   port %-5d from %s: "%s"'
                                 % (port, ip, printable_preview(data)))
                    _close(sel, peeking, conn)

            # Close doors on visitors who connected but said nothing.
            expired = [c for c, (_, _, dl) in peeking.items() if _monotonic() > dl]
            for conn in expired:
                _close(sel, peeking, conn)

    except KeyboardInterrupt:
        print()
        log_line("decoy-door stopped.")
        for conn in list(peeking):
            _close(sel, peeking, conn)


def _monotonic():
    import time
    return time.monotonic()


def _close(sel, peeking, conn):
    try:
        sel.unregister(conn)
    except (KeyError, ValueError):
        pass
    peeking.pop(conn, None)
    try:
        conn.close()
    except OSError:
        pass


# ----------------------------------------------------------------------
# report mode
# ----------------------------------------------------------------------

def report():
    """Read the log and answer the human question: who's been knocking?"""
    try:
        with open(LOG_FILE, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        print("No log file yet (%s). Run 'listen' first and give it time." % LOG_FILE)
        sys.exit(2)

    knocks = []
    for line in lines:
        if "KNOCK" in line:
            parts = line.split()
            # format: date time KNOCK port N from IP
            try:
                port = int(parts[4])
                ip = parts[6]
                day = parts[0]
                knocks.append((day, port, ip))
            except (IndexError, ValueError):
                continue

    if not knocks:
        print("The log exists but records no visits yet. On a machine facing")
        print("the internet that usually changes within the hour.")
        return

    by_ip = Counter(ip for _, _, ip in knocks)
    by_port = Counter(port for _, port, _ in knocks)
    by_day = Counter(day for day, _, _ in knocks)

    print("decoy-door report")
    print("=" * 50)
    print("Total knocks on doors nothing should ever touch: %d" % len(knocks))
    print()
    print("Most persistent visitors:")
    for ip, count in by_ip.most_common(5):
        print("  %-18s %d visit(s)" % (ip, count))
    print()
    print("Most tried doors:")
    for port, count in by_port.most_common(5):
        print("  port %-6d %d knock(s)" % (port, count))
    print()
    print("Busiest days:")
    for day, count in sorted(by_day.items())[-7:]:
        print("  %s  %s" % (day, "#" * min(count, 40)))
    print()
    print("Remember what this means: every single one of these visits was")
    print("uninvited. If a visitor above is an address from INSIDE your own")
    print("network, stop and investigate that machine today.")


# ----------------------------------------------------------------------

def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "listen":
        try:
            ports = [int(p) for p in sys.argv[2:]]
        except ValueError:
            print("Ports must be numbers, e.g.: python3 decoy_door.py listen 2222 8080")
            sys.exit(2)
        listen(ports)
    elif len(sys.argv) == 2 and sys.argv[1] == "report":
        report()
    else:
        print(__doc__.strip())
        sys.exit(2)


if __name__ == "__main__":
    main()
