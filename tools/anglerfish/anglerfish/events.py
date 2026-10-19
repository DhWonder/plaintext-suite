"""
Structured NDJSON event log for Blue Team shipping.

Every high-signal action (auth, HTTP, Synology API, FTP/SMTP command, SSH
handshake, TLS, DNS, path_read, tarpit) is written immediately as one JSON
object per line to events.jsonl, using the field names in BLUE-LOG-SCHEMA.md.
sessions.log stays backward-compatible; this file is additive.
"""

import hashlib
import json
import os
import threading
import time

SCHEMA_VERSION = 1

# Blue Team ships this path on the live box; locally we honour ANGLERFISH_EVENTS_PATH
# so tests don't need /opt/anglerfish.
DEFAULT_EVENTS_PATH = "/opt/anglerfish/log/events.jsonl"

# Capture caps (tell #7 / Blue hard-ask #1).
FIRST_BYTES_CAP = 8192
REQUEST_LINE_CAP = 8192
BODY_CAP = 2048


class EventLog(object):
    """Thread-safe NDJSON writer. Never raises into the sensor loop."""

    def __init__(self, path="", sensor="", host=""):
        self.path = path or os.environ.get("ANGLERFISH_EVENTS_PATH") or DEFAULT_EVENTS_PATH
        self.sensor = sensor or ""
        self.host = host or ""
        self._lock = threading.Lock()
        self._seq = 0
        self._ensure_dir()

    def _ensure_dir(self):
        folder = os.path.dirname(self.path)
        if folder and not os.path.isdir(folder):
            try:
                os.makedirs(folder, mode=0o755)
            except OSError:
                pass

    def emit(self, event, service="", session=None, **fields):
        """Write one structured event. `session` supplies src/dst/session_id."""
        row = {
            "ts": time.time(),
            "schema_version": SCHEMA_VERSION,
            "sensor": self.sensor,
            "host": self.host,
            "event": event,
            "service": service or (session or {}).get("service") or "",
        }
        if session:
            row.setdefault("src_ip", session.get("peer_ip") or "")
            row.setdefault("src_port", session.get("peer_port") or 0)
            row.setdefault("dst_port", session.get("local_port") or 0)
            row.setdefault("listen_port", session.get("local_port") or 0)
            row.setdefault("session_id", session.get("id") or "")
            row.setdefault("transport", "tcp")
        for key, value in fields.items():
            if value is None:
                continue
            row[key] = value
        with self._lock:
            self._seq += 1
            row["seq"] = self._seq
            try:
                line = json.dumps(row, separators=(",", ":"), default=_json_default)
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError:
                pass
        return row


def _json_default(obj):
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj).decode("latin-1", "replace")
    return str(obj)


def capture_bytes(data, cap=FIRST_BYTES_CAP):
    """Return (text, encoding, true_len, truncated) for first_bytes fields."""
    raw = data or b""
    if isinstance(raw, str):
        raw = raw.encode("latin-1", "replace")
    true_len = len(raw)
    clipped = raw[:cap]
    truncated = true_len > cap
    try:
        text = clipped.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        text = clipped.hex()
        encoding = "hex"
    return text, encoding, true_len, truncated


def hassh_from_kexinit(kex, enc_ctos, mac_ctos, comp_ctos):
    """HASSH = MD5 of 'kex;enc;mac;comp' (client→server lists, comma-joined)."""
    def join(names):
        return ",".join(names or [])
    material = ";".join([
        join(kex), join(enc_ctos), join(mac_ctos), join(comp_ctos),
    ])
    return hashlib.md5(material.encode("ascii", "replace")).hexdigest()
