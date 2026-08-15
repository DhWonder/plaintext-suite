"""
Where traffic-analyzer keeps what it has seen.

One SQLite file. No server to install, no service to keep running, and the
client can email you the whole history as a single attachment if you ask for
it. Every run of the tool, whether it read a file or listened to a network
card, becomes a session in here. That is what makes "watch the past" possible
at all: without somewhere to put the results, every run is thrown away the
moment it prints.

Two things are deliberate:

  - the raw packets are never stored, only the counts and the per source
    summaries. Storing traffic contents would turn this tool into a privacy
    problem and a legal one.
  - the schema is boring and readable. If I am not around, somebody else can
    open this file with any SQLite browser and understand it.
"""

import json
import os
import sqlite3
import time

SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS session (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    label       TEXT NOT NULL,          -- file name, or the interface listened on
    kind        TEXT NOT NULL,          -- 'file' or 'live'
    note        TEXT DEFAULT '',        -- whatever the operator wants to remember
    created_at  REAL NOT NULL,          -- wall clock when this run happened
    started_at  REAL,                   -- first packet time
    ended_at    REAL,                   -- last packet time
    running     INTEGER DEFAULT 0,      -- 1 while a live capture is still going
    packets     INTEGER DEFAULT 0,
    bytes       INTEGER DEFAULT 0,
    sources     INTEGER DEFAULT 0,
    hostile     INTEGER DEFAULT 0,
    summary     TEXT DEFAULT ''         -- the full report, as JSON
);

CREATE TABLE IF NOT EXISTS source (
    session_id  INTEGER NOT NULL,
    ip          TEXT NOT NULL,
    level       TEXT,
    score       INTEGER,
    packets     INTEGER,
    bytes       INTEGER,
    rate        REAL,
    protocol    TEXT,
    top_dport   INTEGER,
    top_sport   INTEGER,
    ports_touched INTEGER,
    region      TEXT,
    network     TEXT,
    fingerprint TEXT,
    hostname    TEXT DEFAULT '',
    family      INTEGER DEFAULT 4,
    first_seen  REAL,
    last_seen   REAL,
    syn         INTEGER DEFAULT 0,
    ack         INTEGER DEFAULT 0,
    detail      TEXT DEFAULT '',        -- the drill down panel, as JSON
    PRIMARY KEY (session_id, ip)
);

CREATE TABLE IF NOT EXISTS bucket (
    session_id  INTEGER NOT NULL,
    second      INTEGER NOT NULL,       -- absolute unix second
    packets     INTEGER DEFAULT 0,
    bytes       INTEGER DEFAULT 0,
    hostile     INTEGER DEFAULT 0,
    sources     INTEGER DEFAULT 0,
    PRIMARY KEY (session_id, second)
);

CREATE TABLE IF NOT EXISTS alert (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL,
    at          REAL NOT NULL,
    level       TEXT,
    rule        TEXT,
    ip          TEXT,
    message     TEXT
);

CREATE TABLE IF NOT EXISTS service_check (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host        TEXT NOT NULL,
    checked_at  REAL NOT NULL,
    level       TEXT,
    headline    TEXT,
    reachable   INTEGER,
    status      INTEGER,
    response_ms INTEGER,
    cert_ok     INTEGER,
    cert_days   INTEGER,
    cert_expires TEXT,
    issuer      TEXT,
    notes       TEXT
);

CREATE INDEX IF NOT EXISTS service_by_host ON service_check (host, checked_at DESC);

CREATE INDEX IF NOT EXISTS source_by_score ON source (session_id, score DESC);
CREATE INDEX IF NOT EXISTS source_by_level ON source (session_id, level);
CREATE INDEX IF NOT EXISTS source_by_net   ON source (session_id, network);
CREATE INDEX IF NOT EXISTS source_by_print ON source (session_id, fingerprint);
CREATE INDEX IF NOT EXISTS alert_by_time   ON alert  (session_id, at DESC);
"""

DEFAULT_PATH = os.path.expanduser("~/.traffic-analyzer/history.db")


class Store(object):
    def __init__(self, path=DEFAULT_PATH):
        self.path = path
        folder = os.path.dirname(os.path.abspath(path))
        if folder and not os.path.isdir(folder):
            os.makedirs(folder)
        self.db = sqlite3.connect(path, timeout=20.0, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()

    def close(self):
        self.db.close()

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------
    def start_session(self, label, kind, note=""):
        cursor = self.db.execute(
            "INSERT INTO session (label, kind, note, created_at, running) VALUES (?,?,?,?,?)",
            (label, kind, note, time.time(), 1 if kind == "live" else 0))
        self.db.commit()
        return cursor.lastrowid

    def finish_session(self, session_id, summary):
        self.db.execute(
            """UPDATE session SET running=0, started_at=?, ended_at=?, packets=?,
                      bytes=?, sources=?, hostile=?, summary=? WHERE id=?""",
            (summary.get("started_at"), summary.get("ended_at"),
             summary.get("total_packets", 0), summary.get("total_bytes", 0),
             summary.get("sources_total", 0), summary.get("hostile_sources", 0),
             json.dumps(summary), session_id))
        self.db.commit()

    def touch_session(self, session_id, summary):
        """Update a live session in place without marking it finished."""
        self.db.execute(
            """UPDATE session SET started_at=?, ended_at=?, packets=?, bytes=?,
                      sources=?, hostile=?, summary=? WHERE id=?""",
            (summary.get("started_at"), summary.get("ended_at"),
             summary.get("total_packets", 0), summary.get("total_bytes", 0),
             summary.get("sources_total", 0), summary.get("hostile_sources", 0),
             json.dumps(summary), session_id))
        self.db.commit()

    def sessions(self, limit=100):
        rows = self.db.execute(
            """SELECT id, label, kind, note, created_at, started_at, ended_at,
                      running, packets, bytes, sources, hostile
               FROM session ORDER BY id DESC LIMIT ?""", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def session(self, session_id):
        row = self.db.execute("SELECT * FROM session WHERE id=?", (session_id,)).fetchone()
        if row is None:
            return None
        record = dict(row)
        record["summary"] = json.loads(record["summary"]) if record["summary"] else {}
        return record

    def delete_session(self, session_id):
        for table in ("source", "bucket", "alert"):
            self.db.execute("DELETE FROM %s WHERE session_id=?" % table, (session_id,))
        self.db.execute("DELETE FROM session WHERE id=?", (session_id,))
        self.db.commit()

    # ------------------------------------------------------------------
    # Sources
    # ------------------------------------------------------------------
    def save_sources(self, session_id, rows, analyzer=None):
        """Write every scored source. Detail is stored for the busiest ones only.

        Keeping a full drill down blob for a million addresses would make the
        database enormous for very little gain, so the detail is kept where
        somebody would actually click.
        """
        with_detail = set()
        if analyzer is not None:
            for row in rows[:2000]:
                with_detail.add(row["ip"])

        payload = []
        for row in rows:
            detail = ""
            if analyzer is not None and row["ip"] in with_detail:
                found = analyzer.detail(row["ip"])
                if found:
                    detail = json.dumps(found)
            payload.append((
                session_id, row["ip"], row["level"], row["score"], row["packets"],
                row["bytes"], row["rate"], row["protocol"], row["top_dport"],
                row["top_sport"], row.get("ports_touched", 0), row["region"],
                row["network"], row["fingerprint"], row.get("hostname", ""),
                row.get("family", 4), row.get("first"), row.get("last"),
                row.get("syn", 0), row.get("ack", 0), detail))

        self.db.executemany(
            """INSERT OR REPLACE INTO source
               (session_id, ip, level, score, packets, bytes, rate, protocol,
                top_dport, top_sport, ports_touched, region, network, fingerprint,
                hostname, family, first_seen, last_seen, syn, ack, detail)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", payload)
        self.db.commit()

    def sources(self, session_id, offset=0, limit=100, order="score",
                level=None, query=None, network=None, fingerprint=None):
        """A page of sources, filtered and sorted the way the table asks."""
        columns = {
            "score": "score DESC, packets DESC",
            "packets": "packets DESC",
            "bytes": "bytes DESC",
            "rate": "rate DESC",
            "ip": "ip ASC",
            "first": "first_seen ASC",
            "last": "last_seen DESC",
            "ports": "ports_touched DESC",
        }
        order_by = columns.get(order, columns["score"])

        where = ["session_id=?"]
        params = [session_id]
        if level and level != "all":
            where.append("level=?")
            params.append(level)
        if network:
            where.append("network=?")
            params.append(network)
        if fingerprint:
            where.append("fingerprint=?")
            params.append(fingerprint)
        if query:
            where.append("(ip LIKE ? OR hostname LIKE ? OR region LIKE ? OR network LIKE ?)")
            like = "%" + query + "%"
            params.extend([like, like, like, like])

        clause = " AND ".join(where)
        total = self.db.execute(
            "SELECT COUNT(*) FROM source WHERE " + clause, params).fetchone()[0]
        rows = self.db.execute(
            """SELECT ip, level, score, packets, bytes, rate, protocol, top_dport,
                      top_sport, ports_touched, region, network, fingerprint,
                      hostname, family, first_seen, last_seen, syn, ack
               FROM source WHERE """ + clause + " ORDER BY " + order_by + " LIMIT ? OFFSET ?",
            params + [limit, offset]).fetchall()
        return {"total": total, "rows": [dict(r) for r in rows]}

    def source_detail(self, session_id, ip):
        row = self.db.execute(
            "SELECT detail FROM source WHERE session_id=? AND ip=?",
            (session_id, ip)).fetchone()
        if row is None:
            return None
        return json.loads(row["detail"]) if row["detail"] else {}

    def related(self, session_id, ip, limit=8):
        """Peers, neighbours and co-targets, worked out in the database."""
        me = self.db.execute(
            "SELECT ip, network, fingerprint FROM source WHERE session_id=? AND ip=?",
            (session_id, ip)).fetchone()
        if me is None:
            return None

        def fetch(clause, value):
            total = self.db.execute(
                "SELECT COUNT(*) FROM source WHERE session_id=? AND %s=? AND ip!=?" % clause,
                (session_id, value, ip)).fetchone()[0]
            rows = self.db.execute(
                """SELECT ip, level, score, packets, rate, region FROM source
                   WHERE session_id=? AND %s=? AND ip!=? ORDER BY score DESC, packets DESC
                   LIMIT ?""" % clause, (session_id, value, ip, limit)).fetchall()
            return total, [dict(r) for r in rows]

        peer_total, peers = fetch("fingerprint", me["fingerprint"])
        neighbour_total, neighbours = fetch("network", me["network"])
        return {
            "peers": peers, "peer_total": peer_total,
            "neighbours": neighbours, "neighbour_total": neighbour_total,
        }

    def networks(self, session_id, limit=20):
        rows = self.db.execute(
            """SELECT network, COUNT(*) AS addresses, SUM(packets) AS packets,
                      SUM(CASE WHEN level IN ('critical','high') THEN 1 ELSE 0 END) AS hostile
               FROM source WHERE session_id=? GROUP BY network
               ORDER BY packets DESC LIMIT ?""", (session_id, limit)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Per second traffic
    # ------------------------------------------------------------------
    def save_buckets(self, session_id, buckets):
        """buckets: iterable of (second, packets, bytes, hostile, sources)."""
        self.db.executemany(
            """INSERT INTO bucket (session_id, second, packets, bytes, hostile, sources)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(session_id, second) DO UPDATE SET
                 packets = packets + excluded.packets,
                 bytes   = bytes + excluded.bytes,
                 hostile = hostile + excluded.hostile,
                 sources = MAX(sources, excluded.sources)""",
            [(session_id,) + tuple(b) for b in buckets])
        self.db.commit()

    def buckets(self, session_id, since=None, until=None, points=1200):
        where = ["session_id=?"]
        params = [session_id]
        if since is not None:
            where.append("second>=?")
            params.append(int(since))
        if until is not None:
            where.append("second<=?")
            params.append(int(until))
        clause = " AND ".join(where)
        rows = self.db.execute(
            "SELECT second, packets, bytes, hostile FROM bucket WHERE " + clause
            + " ORDER BY second", params).fetchall()
        rows = [dict(r) for r in rows]
        if len(rows) <= points:
            return rows
        # Too many points to draw. Fold neighbouring seconds together rather
        # than dropping any, so peaks survive.
        step = len(rows) // points + 1
        folded = []
        for index in range(0, len(rows), step):
            chunk = rows[index:index + step]
            folded.append({
                "second": chunk[0]["second"],
                "packets": sum(c["packets"] for c in chunk),
                "bytes": sum(c["bytes"] for c in chunk),
                "hostile": sum(c["hostile"] for c in chunk),
                "span": len(chunk),
            })
        return folded

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------
    def add_alerts(self, session_id, alerts):
        """alerts: iterable of (at, level, rule, ip, message)."""
        self.db.executemany(
            "INSERT INTO alert (session_id, at, level, rule, ip, message) VALUES (?,?,?,?,?,?)",
            [(session_id,) + tuple(a) for a in alerts])
        self.db.commit()

    def alerts(self, session_id, limit=200, since=None):
        where = ["session_id=?"]
        params = [session_id]
        if since is not None:
            where.append("at>?")
            params.append(since)
        rows = self.db.execute(
            "SELECT id, at, level, rule, ip, message FROM alert WHERE "
            + " AND ".join(where) + " ORDER BY at DESC, id DESC LIMIT ?",
            params + [limit]).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Website and certificate checks
    # ------------------------------------------------------------------
    def save_checks(self, results):
        """Keep every site check, so "when did this start" has an answer."""
        self.db.executemany(
            """INSERT INTO service_check
               (host, checked_at, level, headline, reachable, status, response_ms,
                cert_ok, cert_days, cert_expires, issuer, notes)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            [(r["host"], r["checked_at"], r["level"], r["headline"],
              1 if r["reachable"] else 0, r["status"], r["response_ms"],
              None if r["certificate_ok"] is None else (1 if r["certificate_ok"] else 0),
              r["certificate_days"], r["certificate_expires"], r["issuer"],
              json.dumps(r["notes"])) for r in results])
        self.db.commit()

    def latest_checks(self, limit=50):
        """The most recent result for each site, worst first."""
        rows = self.db.execute(
            """SELECT s.* FROM service_check s
               JOIN (SELECT host, MAX(checked_at) AS newest FROM service_check GROUP BY host) latest
                 ON s.host = latest.host AND s.checked_at = latest.newest
               ORDER BY CASE s.level WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                        WHEN 'watch' THEN 2 ELSE 3 END, s.host LIMIT ?""", (limit,)).fetchall()
        out = []
        for row in rows:
            record = dict(row)
            record["notes"] = json.loads(record["notes"]) if record["notes"] else []
            out.append(record)
        return out

    def check_history(self, host, limit=200):
        rows = self.db.execute(
            """SELECT checked_at, level, headline, reachable, status, response_ms, cert_days
               FROM service_check WHERE host=? ORDER BY checked_at DESC LIMIT ?""",
            (host, limit)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    def record_analysis(self, label, kind, analyzer, summary, rows=None, note=""):
        """Save a completed run in one go. Used by the file path."""
        rows = rows if rows is not None else analyzer.rows()
        session_id = self.start_session(label, kind, note)
        self.save_sources(session_id, rows, analyzer)

        hostile_ips = set(r["ip"] for r in rows if r["level"] in ("critical", "high"))
        buckets = []
        hostile_per_second = {}
        for ip in hostile_ips:
            stats = analyzer.sources.get(ip)
            if not stats:
                continue
            for second, count in stats["buckets"].items():
                hostile_per_second[second] = hostile_per_second.get(second, 0) + count
        for second, count in sorted(analyzer.per_second.items()):
            buckets.append((second, count, 0, hostile_per_second.get(second, 0), 0))
        if buckets:
            self.save_buckets(session_id, buckets)

        alerts = []
        for row in rows:
            if row["level"] not in ("critical", "high"):
                continue
            rule, message = _rule_for(row)
            alerts.append((row.get("first") or summary.get("started_at") or time.time(),
                           row["level"], rule, row["ip"], message))
        if alerts:
            self.add_alerts(session_id, alerts[:5000])

        self.finish_session(session_id, summary)
        return session_id


def _rule_for(row):
    from . import analyse
    return analyse.rule_for(row)
