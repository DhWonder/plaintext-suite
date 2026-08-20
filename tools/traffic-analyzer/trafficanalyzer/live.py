"""
Watching a network card as it happens, and writing down what happened.

The file mode answers "what hit us last Tuesday". This answers "what is hitting
us right now", and because it writes everything into the same database as the
file mode, tomorrow it answers the first question too.

Three things are produced while it runs:

  - a rolling picture of the last minute, which is what the live view shows
  - the full session totals, flushed into SQLite every few seconds
  - a plain text log file, one line per alert, appended and never rewritten

The log matters more than it looks. A database is convenient but a text file
is what you can hand to somebody, grep on a broken machine, or keep as
evidence. If the database is ever lost the log still tells the story.
"""

import os
import threading
import time
from collections import Counter, deque

from . import analyse, capture, packets

FLUSH_SECONDS = 3.0          # how often state reaches the database
WINDOW_SECONDS = 60          # how far back "right now" looks
ALERT_REPEAT_SECONDS = 300   # do not shout about the same address every second


class LiveMonitor(object):
    """Captures from an interface until told to stop."""

    def __init__(self, interface="any", store=None, log_path=None,
                 label=None, note="", include_loopback=False, find_public=True,
                 keep_packets=False,
                 notifier=None):
        self.interface = interface or "any"
        self.store = store
        # Optional, and off unless asked for: somebody to email when a source
        # turns hostile. Nothing here changes if it is None.
        self.notifier = notifier
        self.label = label or ("live: " + self.interface)
        self.note = note
        self.log_path = log_path
        # Who this machine is. Without it the tool cannot tell your own
        # downloads apart from somebody sending traffic at you, and it ends up
        # calling your own laptop an attacker.
        self.local_ips = capture.local_addresses()
        # The packet browser's data for a live capture. Off unless asked,
        # because keeping every packet is the one thing that makes this use
        # memory in proportion to how long it runs.
        self.packet_log = packets.PacketLog(live=True) if keep_packets else None
        self.public_ip = capture.public_address() if find_public else ""

        self.analyzer = analyse.Analyzer(
            local_ips=self.local_ips, mode="live",
            drop_loopback=not include_loopback)
        self.analyzer.origin = self.label
        self.session_id = None

        self.started = None
        self.running = False
        self.stopping = False
        self.error = ""

        # The rolling window. One entry per second, oldest dropped.
        self.window = deque(maxlen=WINDOW_SECONDS)
        self.current_second = None
        self.current_packets = 0
        self.current_bytes = 0
        self.current_hostile = 0
        self.current_sources = set()
        self.hostile_ips = set()        # refreshed each flush, used to colour the trace

        self.pending_buckets = []       # waiting to be written to the database
        self.announced = {}             # ip -> when we last logged an alert for it
        self.recent_alerts = deque(maxlen=200)
        self.packets_seen = 0
        self.frames_skipped = 0

        self._lock = threading.Lock()
        self._thread = None

    # ------------------------------------------------------------------
    def start_background(self):
        """Run the capture on its own thread and return straight away."""
        self._thread = threading.Thread(target=self.run, name="traffic-analyzer-live")
        self._thread.daemon = True
        self._thread.start()
        return self._thread

    def stop(self):
        self.stopping = True

    def join(self, timeout=10.0):
        if self._thread is not None:
            self._thread.join(timeout)

    # ------------------------------------------------------------------
    def run(self, seconds=0, on_tick=None):
        """The capture loop. Blocks until stopped, or until `seconds` elapse."""
        try:
            sock = capture.open_live(self.interface)
        except capture.CaptureError as exc:
            self.error = str(exc)
            self.running = False
            return

        self.running = True
        self.started = time.time()
        stats = capture.ReadStats()

        if self.store is not None:
            self.session_id = self.store.start_session(self.label, "live", self.note)
        self._log("started listening on %s" % self.interface)

        buffer = bytearray(65535)
        view = memoryview(buffer)
        last_flush = time.time()

        try:
            while not self.stopping:
                now = time.time()
                if seconds and now - self.started >= seconds:
                    break

                try:
                    length = sock.recv_into(buffer, 65535)
                except OSError:
                    length = 0

                if length:
                    packet = capture.parse_frame(view, 0, length, capture.LINK_ETHERNET, stats)
                    if packet is not None:
                        timestamp = time.time()
                        packet["ts"] = timestamp
                        with self._lock:
                            before = self.analyzer.total_packets
                            self.analyzer.ingest(timestamp, packet)
                            if self.analyzer.total_packets > before:
                                self._roll(timestamp, packet)
                                self.packets_seen += 1
                                # Keep the packet itself too, if somebody asked
                                # to be able to look at them. A live capture has
                                # no file to read back from, so the bytes are
                                # kept here or they are gone.
                                if self.packet_log is not None:
                                    self.packet_log.add(
                                        packet, caplen=length,
                                        link=capture.LINK_ETHERNET,
                                        raw=bytes(view[:min(length, packets.LIVE_SNAP)]))
                    else:
                        self.frames_skipped += 1

                now = time.time()
                # Keep the clock moving even when nothing is arriving, so a
                # quiet period shows as quiet rather than as a frozen graph.
                with self._lock:
                    self._advance(now)

                if now - last_flush >= FLUSH_SECONDS:
                    last_flush = now
                    self.flush()
                    if on_tick is not None:
                        on_tick(self)
        except KeyboardInterrupt:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass
            self.flush(final=True)
            self.running = False
            self._log("stopped after %s packets" % "{:,}".format(self.packets_seen))

    # ------------------------------------------------------------------
    def _roll(self, timestamp, packet):
        """Add one packet to the second currently being filled."""
        self._advance(timestamp)
        self.current_packets += 1
        self.current_bytes += packet["size"]
        if packet["src"] in self.hostile_ips:
            self.current_hostile += 1
        if len(self.current_sources) < 20000:
            self.current_sources.add(packet["src"])

    def _advance(self, now):
        """Close out every second that has finished, quiet ones included.

        This has to be driven by the clock rather than by packets arriving.
        If it only ran when a packet turned up then traffic stopping would
        freeze the graph at its last value, which is exactly the moment you
        most want to see it drop to zero.
        """
        second = int(now)
        if self.current_second is None:
            self.current_second = second
            return
        if second <= self.current_second:
            return

        # A long quiet gap, or a clock that jumped, should not spin here.
        if second - self.current_second > WINDOW_SECONDS * 2:
            self.current_second = second - 1

        while self.current_second < second:
            self.window.append({
                "second": self.current_second,
                "packets": self.current_packets,
                "bytes": self.current_bytes,
                "hostile": self.current_hostile,
                "sources": len(self.current_sources),
            })
            self.pending_buckets.append((
                self.current_second, self.current_packets, self.current_bytes,
                self.current_hostile, len(self.current_sources)))
            self.current_second += 1
            self.current_packets = 0
            self.current_bytes = 0
            self.current_hostile = 0
            self.current_sources = set()

    # ------------------------------------------------------------------
    def flush(self, final=False):
        """Push the current state into the database and the log."""
        with self._lock:
            self._advance(time.time())
            rows = self.analyzer.rows()
            summary = self.analyzer.summarise(rows=rows)
            buckets = self.pending_buckets
            self.pending_buckets = []
            self.hostile_ips = set(r["ip"] for r in rows
                                   if r["level"] in ("critical", "high"))

        # Anything newly hostile gets an alert, once, then not again for a while.
        now = time.time()
        fresh = []
        for row in rows:
            if row["level"] not in ("critical", "high"):
                continue
            last = self.announced.get(row["ip"], 0)
            if now - last < ALERT_REPEAT_SECONDS:
                continue
            self.announced[row["ip"]] = now
            rule, message = analyse.rule_for(row)
            fresh.append((now, row["level"], rule, row["ip"], message))
            self.recent_alerts.appendleft({
                "at": now, "level": row["level"], "rule": rule,
                "ip": row["ip"], "message": message,
            })
            self._log("%-8s %-24s %-39s %s"
                      % (row["level"].upper(), rule, row["ip"], message))

        if fresh and self.notifier is not None:
            self._notify(fresh)

        if self.store is not None and self.session_id is not None:
            if buckets:
                self.store.save_buckets(self.session_id, buckets)
            if fresh:
                self.store.add_alerts(self.session_id, fresh)
            self.store.save_sources(self.session_id, rows, self.analyzer)
            if final:
                self.store.finish_session(self.session_id, summary)
            else:
                self.store.touch_session(self.session_id, summary)

        return summary

    # ------------------------------------------------------------------
    def snapshot(self, top_n=25):
        """What the live view draws. Cheap enough to call once a second."""
        with self._lock:
            rows = self.analyzer.rows()
            summary = self.analyzer.summarise(top_n=top_n, rows=rows)
            window = list(self.window)
            current = {
                "second": self.current_second,
                "packets": self.current_packets,
                "sources": len(self.current_sources),
            }

        recent_rate = 0
        if window:
            recent_rate = sum(w["packets"] for w in window[-10:]) / float(min(len(window), 10))

        return {
            "running": self.running,
            "error": self.error,
            "interface": self.interface,
            "session_id": self.session_id,
            "local_ips": sorted(self.local_ips),
            "public_ip": self.public_ip,
            "loopback_dropped": self.analyzer.dropped_loopback,
            "started": self.started,
            "elapsed": (time.time() - self.started) if self.started else 0,
            "packets": self.packets_seen,
            "frames_skipped": self.frames_skipped,
            "window": window,
            "current": current,
            "packets_per_second_now": round(recent_rate, 1),
            "alerts": list(self.recent_alerts)[:40],
            "summary": summary,
        }

    # ------------------------------------------------------------------
    def _notify(self, fresh):
        """Email about sources that have just turned hostile.

        Five new attackers inside the same three second flush is one thing
        happening, so it is one email listing all five rather than five
        emails. The notifier remembers which addresses it has already
        mentioned, so a flood that lasts an hour does not mail you all hour.

        It sends on a thread of its own. A mail server that takes ten seconds
        to answer must not stop the capture for ten seconds; going deaf during
        an attack to send an email about the attack would be a poor trade.
        """
        worth_saying = [item for item in fresh
                        if self.notifier.allow("traffic:%s" % item[3])]
        if not worth_saying:
            return

        lines = []
        for _at, level, rule, ip, message in worth_saying:
            lines.append("%-8s  %s" % (level.upper(), ip))
            lines.append("          %s" % message)
            lines.append("          (%s)" % rule)
            lines.append("")
        lines.append("Seen on %s, %s packets into this capture."
                     % (self.interface, "{:,}".format(self.packets_seen)))
        lines.append("The full picture, with what to change, is in the report:")
        lines.append("  python3 traffic_analyzer.py watch")

        if len(worth_saying) == 1:
            subject = "%s is attacking %s" % (worth_saying[0][3], self.interface)
        else:
            subject = "%d sources attacking %s" % (len(worth_saying), self.interface)

        self.notifier.send_async(
            subject, lines,
            context={"interface": self.interface,
                     "session": self.session_id or "not being saved"},
            done=lambda result: self._log("notification: %s" % result.detail))

    # ------------------------------------------------------------------
    def _log(self, message):
        if not self.log_path:
            return
        line = "%s  %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), message)
        try:
            folder = os.path.dirname(os.path.abspath(self.log_path))
            if folder and not os.path.isdir(folder):
                os.makedirs(folder)
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# The plain terminal view, for when you are on a server over SSH and there is
# no browser. Deliberately simple: no cursor tricks, no colours beyond the
# level, nothing that breaks on a strange terminal.
# ---------------------------------------------------------------------------
def run_terminal(interface, seconds, store=None, log_path=None, refresh=2.0,
                 notifier=None):
    monitor = LiveMonitor(interface, store=store, log_path=log_path,
                          notifier=notifier)
    last_draw = [0.0]

    def tick(mon):
        now = time.time()
        if now - last_draw[0] < refresh:
            return
        last_draw[0] = now
        _draw(mon)

    print("Listening on %s. Press Ctrl+C to stop and print the full report."
          % (interface or "all interfaces"))
    monitor.run(seconds=seconds, on_tick=tick)

    if monitor.error:
        print(monitor.error)
        return None
    if not monitor.packets_seen:
        print("\nNo packets were captured.")
        return None
    return monitor.analyzer.summarise()


def _draw(monitor):
    snapshot = monitor.snapshot(top_n=10)
    summary = snapshot["summary"]
    os.system("clear" if os.name != "nt" else "cls")
    print("traffic-analyzer, live on %s. %0.0f seconds, %s packets, %d sources, %s now per second."
          % (monitor.interface, snapshot["elapsed"],
             "{:,}".format(summary["total_packets"]), summary["sources_total"],
             "{:,.0f}".format(snapshot["packets_per_second_now"])))
    print("Target under most pressure: %s" % summary["main_target"])
    print()
    print("%-16s %-9s %-9s %-10s %s" % ("SOURCE", "LEVEL", "PACKETS", "RATE/S", "WHY"))
    print("-" * 78)
    for row in summary["sources"][:10]:
        why = row["reasons"][0][:34] if row["reasons"] else ""
        print("%-16s %-9s %-9s %-10s %s"
              % (row["ip"][:16], row["level"].upper(), "{:,}".format(row["packets"]),
                 row["rate"], why))
    print()
    if snapshot["alerts"]:
        print("Latest alerts:")
        for alert in snapshot["alerts"][:4]:
            print("  %s  %-22s %-39s %s"
                  % (time.strftime("%H:%M:%S", time.localtime(alert["at"])),
                     alert["rule"], alert["ip"], alert["message"]))
    print()
    print("Ctrl+C to stop and print the full report with recommendations.")
