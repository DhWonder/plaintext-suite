"""
Where the console keeps what the sensors tell it.

One SQLite file. Sensors, the sessions they recorded, the tokens they planted,
and the moments those tokens were triggered. No packet contents, no attacker
machine reached into, nothing but a record of what came to your doors and what
happened to the bait you left out.
"""

import json
import os
import sqlite3
import time

SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS sensor (
    name       TEXT PRIMARY KEY,
    hostname   TEXT,
    first_seen REAL,
    last_seen  REAL
);

CREATE TABLE IF NOT EXISTS session (
    id            TEXT PRIMARY KEY,
    sensor        TEXT,
    peer_ip       TEXT,
    local_port    INTEGER,
    protocol      TEXT,
    started       REAL,
    ended         REAL,
    duration      REAL,
    commands      INTEGER,
    read_files    INTEGER,
    credentials   INTEGER,
    detail        TEXT
);

CREATE TABLE IF NOT EXISTS token (
    id       TEXT PRIMARY KEY,
    sensor   TEXT,
    kind     TEXT,
    label    TEXT,
    created  REAL
);

CREATE TABLE IF NOT EXISTS trigger_event (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id  TEXT,
    at        REAL,
    source_ip TEXT,
    detail    TEXT
);

CREATE TABLE IF NOT EXISTS ip_reputation (
    ip          TEXT PRIMARY KEY,       -- the attacker address asked about
    checked_at  REAL NOT NULL,
    level       TEXT DEFAULT '',        -- known-bad, disputed, benign, clean...
    scanner     TEXT DEFAULT '',        -- the name, when it is a known scanner
    attention   INTEGER DEFAULT 0,      -- 0 background noise, 2 read this today
    detail      TEXT DEFAULT ''         -- every source and what it said, as JSON
);

CREATE INDEX IF NOT EXISTS session_by_time ON session (started DESC);
CREATE INDEX IF NOT EXISTS session_by_ip   ON session (peer_ip);
CREATE INDEX IF NOT EXISTS trigger_by_time ON trigger_event (at DESC);
"""

DEFAULT_PATH = os.path.expanduser("~/.anglerfish/console.db")


class Store(object):
    def __init__(self, path=DEFAULT_PATH):
        folder = os.path.dirname(os.path.abspath(path))
        if folder and not os.path.isdir(folder):
            os.makedirs(folder)
        self.db = sqlite3.connect(path, timeout=20.0, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()
        self._lock_note = path

    def close(self):
        self.db.close()

    # -- sensors -------------------------------------------------------
    def upsert_sensor(self, name, hostname):
        now = time.time()
        self.db.execute(
            """INSERT INTO sensor (name, hostname, first_seen, last_seen)
               VALUES (?,?,?,?)
               ON CONFLICT(name) DO UPDATE SET last_seen=excluded.last_seen,
                 hostname=excluded.hostname""",
            (name, hostname, now, now))
        self.db.commit()

    def sensors(self):
        rows = self.db.execute("SELECT * FROM sensor ORDER BY last_seen DESC").fetchall()
        return [dict(r) for r in rows]

    # -- sessions ------------------------------------------------------
    def save_session(self, sensor, session):
        self.upsert_sensor(sensor, session.get("hostname", ""))
        self.db.execute(
            """INSERT OR REPLACE INTO session
               (id, sensor, peer_ip, local_port, protocol, started, ended,
                duration, commands, read_files, credentials, detail)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (session["id"], sensor, session.get("peer_ip", ""),
             session.get("local_port", 0), session.get("protocol", ""),
             session.get("started", 0), session.get("ended", 0),
             session.get("duration", 0), len(session.get("commands", [])),
             len(session.get("read_files", [])), len(session.get("credentials", [])),
             json.dumps(session)))
        self.db.commit()

    def sessions(self, limit=200):
        rows = self.db.execute(
            """SELECT id, sensor, peer_ip, local_port, protocol, started, duration,
                      commands, read_files, credentials
               FROM session ORDER BY started DESC LIMIT ?""", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def session(self, session_id):
        row = self.db.execute("SELECT detail FROM session WHERE id=?",
                              (session_id,)).fetchone()
        return json.loads(row["detail"]) if row else None

    # -- tokens --------------------------------------------------------
    def add_token(self, token_id, sensor, kind, label):
        self.db.execute(
            """INSERT OR IGNORE INTO token (id, sensor, kind, label, created)
               VALUES (?,?,?,?,?)""", (token_id, sensor, kind, label, time.time()))
        self.db.commit()

    def token(self, token_id):
        row = self.db.execute("SELECT * FROM token WHERE id=?", (token_id,)).fetchone()
        return dict(row) if row else None

    def tokens(self):
        rows = self.db.execute(
            """SELECT t.*, COUNT(e.id) AS triggers
               FROM token t LEFT JOIN trigger_event e ON e.token_id = t.id
               GROUP BY t.id ORDER BY triggers DESC, t.created DESC""").fetchall()
        return [dict(r) for r in rows]

    # -- triggers ------------------------------------------------------
    def record_trigger(self, token_id, source_ip, detail):
        self.db.execute(
            "INSERT INTO trigger_event (token_id, at, source_ip, detail) VALUES (?,?,?,?)",
            (token_id, time.time(), source_ip, detail))
        self.db.commit()

    def triggers(self, limit=200):
        rows = self.db.execute(
            """SELECT e.*, t.label, t.kind, t.sensor
               FROM trigger_event e LEFT JOIN token t ON t.id = e.token_id
               ORDER BY e.at DESC LIMIT ?""", (limit,)).fetchall()
        return [dict(r) for r in rows]

    # -- the summary the console front page needs ----------------------
    # ------------------------------------------------------------------
    # What everybody else knows about an attacker address. Console only:
    # a sensor is a machine we have decided to treat as untrusted, so it
    # never holds a key and never makes one of these lookups.
    # ------------------------------------------------------------------
    def get_reputation(self, ip, max_age=None):
        row = self.db.execute(
            "SELECT checked_at, detail FROM ip_reputation WHERE ip=?", (ip,)).fetchone()
        if row is None or not row["detail"]:
            return None
        if max_age is not None and (time.time() - (row["checked_at"] or 0)) > max_age:
            return None
        try:
            result = json.loads(row["detail"])
        except ValueError:
            return None
        result["from_cache"] = True
        return result

    def save_reputation(self, ip, result):
        if not result or not result.get("ok"):
            return
        self.db.execute(
            """INSERT OR REPLACE INTO ip_reputation
               (ip, checked_at, level, scanner, attention, detail)
               VALUES (?,?,?,?,?,?)""",
            (ip, result.get("checked_at") or time.time(),
             result.get("level", ""), result.get("scanner", "") or "",
             int(result.get("attention", 0) or 0), json.dumps(result)))
        self.db.commit()

    def overview(self):
        one_day = time.time() - 86400
        counts = {
            "sensors": self.db.execute("SELECT COUNT(*) FROM sensor").fetchone()[0],
            "sessions": self.db.execute("SELECT COUNT(*) FROM session").fetchone()[0],
            "sessions_today": self.db.execute(
                "SELECT COUNT(*) FROM session WHERE started >= ?", (one_day,)).fetchone()[0],
            "attackers": self.db.execute(
                "SELECT COUNT(DISTINCT peer_ip) FROM session").fetchone()[0],
            "credentials": self.db.execute(
                "SELECT COALESCE(SUM(credentials),0) FROM session").fetchone()[0],
            "tokens": self.db.execute("SELECT COUNT(*) FROM token").fetchone()[0],
            "triggers": self.db.execute("SELECT COUNT(*) FROM trigger_event").fetchone()[0],
        }
        top_attackers = [dict(r) for r in self.db.execute(
            """SELECT peer_ip, COUNT(*) AS sessions, SUM(commands) AS commands,
                      SUM(read_files) AS files, MAX(started) AS last
               FROM session GROUP BY peer_ip ORDER BY sessions DESC LIMIT 10""").fetchall()]
        return {
            "counts": counts,
            "sensors": self.sensors(),
            "top_attackers": top_attackers,
            "recent_sessions": self.sessions(limit=25),
            "recent_triggers": self.triggers(limit=25),
        }
