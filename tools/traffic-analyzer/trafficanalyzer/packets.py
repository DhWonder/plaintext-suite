"""
Keeping the packets themselves, so you can look at one.

The rest of this tool counts. It watches a million packets go past and tells you
that 98% of them were a flood from one botnet, which is the answer somebody
usually wants. But sometimes the answer they want is "show me the actual packet",
and until now this tool could not, because it threw every packet away the moment
it had finished counting it. That is what a streaming analyser does, and it is
why it can read a capture larger than memory.

So this keeps a record of each packet, and it keeps it small on purpose:

  - the fields worth filtering on are held in memory, about a hundred bytes each
  - the packet's own bytes are NOT held. What is held is where in the file they
    were. When you click a packet, those bytes are read back off the disk, right
    then, and decoded. A capture is on the disk already; copying it into memory a
    second time to display forty of them would be a strange way to spend a
    gigabyte.

That trade is the whole design. It means the packet list is bounded and fast, the
detail view is exact rather than truncated, and a live capture (where there is no
file to read back from) keeps the recent bytes itself and says so.

WHAT THIS IS NOT

  It is not Wireshark. Wireshark dissects two thousand protocols; this decodes
  the ones this tool already understands, which is Ethernet, IPv4, IPv6, TCP, UDP
  and ICMP, and shows everything above that as bytes. For working out who is
  attacking you that is enough, and pretending otherwise would be the kind of
  claim this project does not make.
"""

import os
import socket
import struct

# TCP flag bits, in the order Wireshark prints them.
TCP_FLAGS = [
    (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
    (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"),
]

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 2: "IGMP", 47: "GRE",
               50: "ESP", 51: "AH", 89: "OSPF", 132: "SCTP"}

# Ports worth naming in the summary line. Not a full list, just the ones that
# turn up when somebody is looking at a small business network.
PORT_NAMES = {
    20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 111: "portmapper",
    123: "NTP", 135: "RPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "syslog", 587: "SMTP", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1433: "SQL Server", 1521: "Oracle", 1723: "PPTP",
    1900: "SSDP", 3306: "MySQL", 3389: "Remote Desktop", 5060: "SIP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP alt",
    8443: "HTTPS alt", 9200: "Elasticsearch", 11211: "memcached", 27017: "MongoDB",
}

# How many packet records to keep. Past this the oldest are dropped and the log
# says so, because a list that silently stopped being complete is a liar.
DEFAULT_LIMIT = 500000

# For live capture there is no file to re-read, so the bytes are kept. This caps
# how much of each frame, and how much in total.
LIVE_SNAP = 2048
LIVE_BYTE_BUDGET = 64 * 1024 * 1024


def proto_name(number):
    return PROTO_NAMES.get(number, "IP protocol %d" % number)


def port_name(port):
    return PORT_NAMES.get(port, "")


def flag_names(flags):
    return [name for bit, name in TCP_FLAGS if flags & bit]


class PacketLog(object):
    """Every packet that was read, in order, small enough to keep.

    A record is a plain dict so the JSON API can hand it straight out:

        n        1-based position in the capture, the number people quote
        ts       timestamp
        src dst  addresses
        proto    IP protocol number
        sport dport  ports, or None
        flags    TCP flag bits
        size     length on the wire
        ttl      time to live / hop limit
        family   4 or 6
        stream   which conversation this belongs to, or None
        at       byte offset of the frame in the file, for reading back
        caplen   how many bytes were actually saved in the file
        link     link type, needed to decode it
    """

    def __init__(self, path="", limit=DEFAULT_LIMIT, live=False):
        self.path = path
        self.limit = limit
        self.live = live
        self.records = []
        self.dropped = 0

        # Conversations. The key is direction-independent, so a request and its
        # reply land in the same stream, which is what "follow" means.
        self.streams = {}
        self.stream_list = []

        # Only used for live capture, where there is no file to read back from.
        self._bytes = {}
        self._byte_total = 0

    # ------------------------------------------------------------------
    def stream_key(self, packet):
        """A key that is the same for both directions of one conversation."""
        proto = packet.get("proto")
        if proto not in (6, 17):
            # Anything else is grouped by host pair alone. Two machines pinging
            # each other is one conversation, not one per packet.
            ends = tuple(sorted([packet.get("src", ""), packet.get("dst", "")]))
            return (proto, ends, None)
        a = (packet.get("src", ""), packet.get("sport"))
        b = (packet.get("dst", ""), packet.get("dport"))
        ends = tuple(sorted([a, b]))
        return (proto, ends, "ports")

    def add(self, packet, at=None, caplen=None, link=None, raw=None):
        """Record one packet. Returns the record, or None once the log is full."""
        if len(self.records) >= self.limit:
            self.dropped += 1
            return None

        key = self.stream_key(packet)
        stream = self.streams.get(key)
        if stream is None:
            stream = len(self.stream_list)
            self.streams[key] = stream
            self.stream_list.append({
                "stream": stream,
                "proto": packet.get("proto"),
                "a": packet.get("src", ""), "a_port": packet.get("sport"),
                "b": packet.get("dst", ""), "b_port": packet.get("dport"),
                "packets": 0, "bytes": 0,
                "first": packet.get("ts", 0.0), "last": packet.get("ts", 0.0),
            })
        entry = self.stream_list[stream]
        entry["packets"] += 1
        entry["bytes"] += packet.get("size", 0) or 0
        entry["last"] = packet.get("ts", 0.0)

        number = len(self.records) + 1
        record = {
            "n": number,
            "ts": packet.get("ts", 0.0),
            "src": packet.get("src", ""),
            "dst": packet.get("dst", ""),
            "proto": packet.get("proto", 0),
            "sport": packet.get("sport"),
            "dport": packet.get("dport"),
            "flags": packet.get("flags", 0) or 0,
            "size": packet.get("size", 0) or 0,
            "ttl": packet.get("ttl", 0) or 0,
            "family": packet.get("family", 4),
            "stream": stream,
            "at": at,
            "caplen": caplen,
            "link": link,
        }
        if packet.get("window") is not None:
            record["window"] = packet.get("window")
        if packet.get("fragment"):
            record["fragment"] = True
        if packet.get("icmp_type") is not None:
            record["icmp_type"] = packet.get("icmp_type")
        self.records.append(record)

        # Live capture has no file behind it, so keep the bytes, within a budget.
        if raw is not None and self._byte_total < LIVE_BYTE_BUDGET:
            kept = bytes(raw[:LIVE_SNAP])
            self._bytes[number] = kept
            self._byte_total += len(kept)

        return record

    # ------------------------------------------------------------------
    def __len__(self):
        return len(self.records)

    def get(self, number):
        if 1 <= number <= len(self.records):
            return self.records[number - 1]
        return None

    def frame_bytes(self, number):
        """The packet's own bytes, read back off the disk, or kept if live.

        Returns (data, note). `note` explains anything the reader should know,
        such as the frame having been cut short when it was captured.
        """
        record = self.get(number)
        if record is None:
            return b"", "There is no packet with that number."

        kept = self._bytes.get(number)
        if kept is not None:
            note = ""
            if record.get("caplen") and len(kept) < record["caplen"]:
                note = ("Only the first %d bytes of this packet were kept, because a live "
                        "capture has no file to read back from." % len(kept))
            return kept, note

        at, caplen = record.get("at"), record.get("caplen")
        if at is None or not self.path or not os.path.exists(self.path):
            return b"", ("The bytes for this packet are not available. That happens with a live "
                         "capture once the kept buffer has moved on, or if the capture file has "
                         "been moved since it was read.")
        try:
            with open(self.path, "rb") as fh:
                fh.seek(at)
                data = fh.read(caplen or 0)
        except OSError as exc:
            return b"", "Could not read the capture file back: %s" % exc

        note = ""
        if record["size"] and caplen and caplen < record["size"]:
            note = ("This packet was %d bytes on the wire but only %d were saved, because the "
                    "capture was taken with a snap length. Everything past that was never "
                    "written down." % (record["size"], caplen))
        return data, note

    def stream(self, number):
        """Every packet in the same conversation as this one."""
        record = self.get(number)
        if record is None:
            return []
        target = record["stream"]
        return [r for r in self.records if r["stream"] == target]

    def streams_summary(self, limit=200):
        entries = sorted(self.stream_list, key=lambda s: s["packets"], reverse=True)
        return entries[:limit]


# ---------------------------------------------------------------------------
# Saying what a packet is, in one line
# ---------------------------------------------------------------------------
def summary(record):
    """The line the packet list shows. Wireshark's 'Info' column, in words."""
    proto = record["proto"]
    sport, dport = record.get("sport"), record.get("dport")

    if proto == 6:
        names = flag_names(record.get("flags", 0))
        marks = "[%s]" % ", ".join(names) if names else "[no flags]"
        service = port_name(dport) or port_name(sport)
        tail = (" (%s)" % service) if service else ""
        return "%s to %s %s%s" % (sport, dport, marks, tail)

    if proto == 17:
        service = port_name(dport) or port_name(sport)
        tail = (" (%s)" % service) if service else ""
        return "%s to %s, UDP%s" % (sport, dport, tail)

    if proto in (1, 58):
        kind = record.get("icmp_type")
        return "%s %s" % (proto_name(proto), _icmp_name(kind, proto))

    return proto_name(proto)


ICMP4_TYPES = {0: "echo reply", 3: "destination unreachable", 4: "source quench",
               5: "redirect", 8: "echo request (ping)", 11: "time exceeded",
               12: "parameter problem", 13: "timestamp", 14: "timestamp reply"}
ICMP6_TYPES = {1: "destination unreachable", 2: "packet too big", 3: "time exceeded",
               4: "parameter problem", 128: "echo request (ping)", 129: "echo reply",
               133: "router solicitation", 134: "router advertisement",
               135: "neighbour solicitation", 136: "neighbour advertisement"}


def _icmp_name(kind, proto):
    if kind is None:
        return ""
    table = ICMP6_TYPES if proto == 58 else ICMP4_TYPES
    return table.get(kind, "type %d" % kind)


def explain(record):
    """A sentence about what this packet is doing, for somebody who is not sure.

    The packet list is a table of numbers. This is the part that makes it
    readable by somebody who has never used a packet tool, which is most of the
    people these reports get shown to.
    """
    proto = record["proto"]
    if proto == 6:
        names = set(flag_names(record.get("flags", 0)))
        service = port_name(record.get("dport")) or ""
        where = (" on %s" % service) if service else ""
        if names == {"SYN"}:
            return ("An attempt to open a connection%s. Nothing has been agreed yet: this is the "
                    "first of the three messages that set one up." % where)
        if names == {"SYN", "ACK"}:
            return "The other side agreeing to open the connection%s." % where
        if "RST" in names:
            return ("A refusal. Whatever was asked for, this side said no and closed the "
                    "connection%s." % where)
        if "FIN" in names:
            return "One side saying it has finished sending%s." % where
        if "PSH" in names:
            return "Data being sent, with a nudge to hand it to the program straight away."
        if names == {"ACK"}:
            return "An acknowledgement: this side confirming it received what was sent."
        return "A TCP packet%s." % where
    if proto == 17:
        service = port_name(record.get("dport")) or ""
        if service:
            return ("A UDP message to %s. UDP has no connection to set up, so each message "
                    "stands alone." % service)
        return "A UDP message. There is no connection here, each one stands alone."
    if proto in (1, 58):
        kind = _icmp_name(record.get("icmp_type"), proto)
        if "echo request" in kind:
            return "A ping: one machine asking another whether it is there."
        if "echo reply" in kind:
            return "A ping answer: the machine saying it is there."
        if "unreachable" in kind:
            return "A message saying the destination could not be reached."
        if "time exceeded" in kind:
            return "A message saying the packet ran out of hops before it arrived."
        return "An %s control message (%s)." % (proto_name(proto), kind or "unknown type")
    return "An %s packet." % proto_name(proto)


# ---------------------------------------------------------------------------
# Taking a frame apart, layer by layer
# ---------------------------------------------------------------------------
def dissect(data, link_type):
    """Decode a frame into layers, each with the byte range it occupies.

    Returns a list of layers:

        {"name": ..., "start": n, "length": n, "summary": ...,
         "fields": [{"name":..., "value":..., "start":n, "length":n, "note":...}]}

    Every field carries where it sits, so clicking it can highlight those bytes.
    Anything not decoded is returned as a final payload layer rather than being
    quietly dropped.
    """
    layers = []
    offset = 0
    end = len(data)
    if end == 0:
        return layers

    ethertype = None
    if link_type == 1:                       # Ethernet
        if end < 14:
            return [_raw_layer(data, 0, "Frame too short to be Ethernet")]
        dst = _mac(data, 0)
        src = _mac(data, 6)
        ethertype = (data[12] << 8) | data[13]
        layers.append({
            "name": "Ethernet",
            "start": 0, "length": 14,
            "summary": "%s to %s" % (src, dst),
            "fields": [
                _field("Destination", dst, 0, 6, "the card this frame was addressed to"),
                _field("Source", src, 6, 6, "the card that sent it"),
                _field("Type", "0x%04x (%s)" % (ethertype, _ethertype_name(ethertype)), 12, 2),
            ],
        })
        offset = 14
        while ethertype in (0x8100, 0x88a8) and offset + 4 <= end:
            tag = (data[offset] << 8) | data[offset + 1]
            vlan = tag & 0x0FFF
            ethertype = (data[offset + 2] << 8) | data[offset + 3]
            layers.append({
                "name": "VLAN tag", "start": offset, "length": 4,
                "summary": "VLAN %d" % vlan,
                "fields": [_field("VLAN id", str(vlan), offset, 2,
                                  "the virtual network this frame was travelling on")],
            })
            offset += 4
    elif link_type in (101, 12, 14):
        ethertype = 0x0800 if (data[0] >> 4) == 4 else 0x86dd
    elif link_type == 228:
        ethertype = 0x0800
    elif link_type == 229:
        ethertype = 0x86dd
    elif link_type in (113, 276):            # Linux cooked capture v1 / v2
        header = 16 if link_type == 113 else 20
        if end < header:
            return [_raw_layer(data, 0, "Frame too short for a Linux cooked header")]
        ethertype = ((data[14] << 8) | data[15]) if link_type == 113 else ((data[0] << 8) | data[1])
        layers.append({
            "name": "Linux cooked capture", "start": 0, "length": header,
            "summary": "captured on any interface",
            "fields": [_field("Protocol", "0x%04x (%s)" % (ethertype, _ethertype_name(ethertype)),
                              14 if link_type == 113 else 0, 2)],
        })
        offset = header
    elif link_type in (0, 108):              # loopback
        if end < 4:
            return [_raw_layer(data, 0, "Frame too short for a loopback header")]
        fmt = "=I" if link_type == 0 else ">I"
        family = struct.unpack(fmt, bytes(data[0:4]))[0]
        ethertype = 0x0800 if family == 2 else 0x86dd
        layers.append({
            "name": "Loopback", "start": 0, "length": 4,
            "summary": "traffic that never left this machine",
            "fields": [_field("Family", str(family), 0, 4)],
        })
        offset = 4
    else:
        version = (data[0] >> 4) if end else 0
        ethertype = 0x0800 if version == 4 else (0x86dd if version == 6 else None)

    if ethertype == 0x0800:
        offset, proto = _dissect_ipv4(data, offset, end, layers)
    elif ethertype == 0x86dd:
        offset, proto = _dissect_ipv6(data, offset, end, layers)
    else:
        layers.append(_raw_layer(data, offset,
                                 "Not IP (%s), so this tool does not decode it"
                                 % _ethertype_name(ethertype)))
        return layers

    if proto is None:
        return layers

    if proto == 6:
        offset = _dissect_tcp(data, offset, end, layers)
    elif proto == 17:
        offset = _dissect_udp(data, offset, end, layers)
    elif proto in (1, 58):
        offset = _dissect_icmp(data, offset, end, layers, proto)

    if offset is not None and offset < end:
        layers.append(_payload_layer(data, offset, end))
    return layers


def _field(name, value, start, length, note=""):
    entry = {"name": name, "value": value, "start": start, "length": length}
    if note:
        entry["note"] = note
    return entry


def _mac(data, at):
    return ":".join("%02x" % b for b in data[at:at + 6])


def _ethertype_name(value):
    return {0x0800: "IPv4", 0x86dd: "IPv6", 0x0806: "ARP", 0x8100: "VLAN",
            0x88cc: "LLDP", 0x8847: "MPLS"}.get(value, "unknown")


def _raw_layer(data, offset, why):
    return {"name": "Undecoded", "start": offset, "length": max(len(data) - offset, 0),
            "summary": why, "fields": []}


def _payload_layer(data, offset, end):
    length = end - offset
    body = bytes(data[offset:end])
    layer = {
        "name": "Payload", "start": offset, "length": length,
        "summary": "%d bytes this tool does not decode" % length,
        "fields": [],
    }
    guess = _guess_payload(body)
    if guess:
        layer["summary"] = "%d bytes, %s" % (length, guess)
    text = _printable(body)
    if text:
        layer["text"] = text
    return layer


def _guess_payload(body):
    """A cautious guess at what the payload is, from its first bytes only."""
    if len(body) < 4:
        return ""
    head = bytes(body[:8])
    if head[:5] in (b"HTTP/",):
        return "an HTTP reply"
    for verb in (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS"):
        if head.startswith(verb):
            return "an HTTP request"
    if head[0] == 0x16 and head[1] == 0x03:
        return "the start of a TLS handshake, so the rest is encrypted"
    if head[0] == 0x17 and head[1] == 0x03:
        return "encrypted TLS data"
    if body[:4] == b"\x00\x00\x00\x00":
        return "zero padding"
    printable = sum(1 for b in body[:64] if 32 <= b < 127 or b in (9, 10, 13))
    if printable > len(body[:64]) * 0.85:
        return "readable text"
    return ""


def _printable(body, limit=2048):
    """The payload as text, if it mostly is text. Otherwise nothing."""
    chunk = bytes(body[:limit])
    if not chunk:
        return ""
    printable = sum(1 for b in chunk if 32 <= b < 127 or b in (9, 10, 13))
    if printable < len(chunk) * 0.75:
        return ""
    return "".join(chr(b) if (32 <= b < 127 or b in (9, 10, 13)) else "." for b in chunk)


def _dissect_ipv4(data, offset, end, layers):
    if offset + 20 > end:
        layers.append(_raw_layer(data, offset, "Cut short before the IPv4 header finished"))
        return None, None
    ihl = (data[offset] & 0x0F) * 4
    total = (data[offset + 2] << 8) | data[offset + 3]
    proto = data[offset + 9]
    ttl = data[offset + 8]
    flags = data[offset + 6] >> 5
    frag = ((data[offset + 6] << 8) | data[offset + 7]) & 0x1FFF
    src = socket.inet_ntoa(bytes(data[offset + 12:offset + 16]))
    dst = socket.inet_ntoa(bytes(data[offset + 16:offset + 20]))
    _initial, os_guess, hops = _ttl_guess(ttl)

    layers.append({
        "name": "IPv4", "start": offset, "length": ihl,
        "summary": "%s to %s" % (src, dst),
        "fields": [
            _field("Version", "4", offset, 1),
            _field("Header length", "%d bytes" % ihl, offset, 1),
            _field("Total length", "%d bytes" % total, offset + 2, 2),
            _field("Flags", _ip_flags(flags), offset + 6, 1),
            _field("Fragment offset", str(frag), offset + 6, 2),
            _field("Time to live", str(ttl), offset + 8, 1,
                   "about %d hops away, and the starting value suggests %s" % (hops, os_guess)),
            _field("Protocol", "%d (%s)" % (proto, proto_name(proto)), offset + 9, 1),
            _field("Source", src, offset + 12, 4),
            _field("Destination", dst, offset + 16, 4),
        ],
    })
    if frag:
        # Later fragments carry no ports, so there is no L4 header to find.
        return offset + ihl, None
    return offset + ihl, proto


def _ip_flags(flags):
    names = []
    if flags & 0x2:
        names.append("do not fragment")
    if flags & 0x1:
        names.append("more fragments")
    return ", ".join(names) if names else "none"


def _ttl_guess(ttl):
    for start, name in ((64, "Linux, Unix or a phone"), (128, "Windows"),
                        (255, "network equipment")):
        if ttl <= start:
            return start, name, start - ttl
    return 255, "unknown", 0


def _dissect_ipv6(data, offset, end, layers):
    if offset + 40 > end:
        layers.append(_raw_layer(data, offset, "Cut short before the IPv6 header finished"))
        return None, None
    payload_length = (data[offset + 4] << 8) | data[offset + 5]
    next_header = data[offset + 6]
    hop_limit = data[offset + 7]
    try:
        src = socket.inet_ntop(socket.AF_INET6, bytes(data[offset + 8:offset + 24]))
        dst = socket.inet_ntop(socket.AF_INET6, bytes(data[offset + 24:offset + 40]))
    except (OSError, ValueError):
        layers.append(_raw_layer(data, offset, "Unreadable IPv6 addresses"))
        return None, None

    layers.append({
        "name": "IPv6", "start": offset, "length": 40,
        "summary": "%s to %s" % (src, dst),
        "fields": [
            _field("Version", "6", offset, 1),
            _field("Payload length", "%d bytes" % payload_length, offset + 4, 2),
            _field("Next header", "%d (%s)" % (next_header, proto_name(next_header)),
                   offset + 6, 1),
            _field("Hop limit", str(hop_limit), offset + 7, 1),
            _field("Source", src, offset + 8, 16),
            _field("Destination", dst, offset + 24, 16),
        ],
    })
    return offset + 40, next_header


def _dissect_tcp(data, offset, end, layers):
    if offset + 20 > end:
        layers.append(_raw_layer(data, offset, "Cut short before the TCP header finished"))
        return None
    sport = (data[offset] << 8) | data[offset + 1]
    dport = (data[offset + 2] << 8) | data[offset + 3]
    seq = struct.unpack(">I", bytes(data[offset + 4:offset + 8]))[0]
    ack = struct.unpack(">I", bytes(data[offset + 8:offset + 12]))[0]
    data_offset = (data[offset + 12] >> 4) * 4
    flags = data[offset + 13]
    window = (data[offset + 14] << 8) | data[offset + 15]
    names = flag_names(flags)

    service = port_name(dport) or port_name(sport)
    summary_text = "%d to %d [%s]" % (sport, dport, ", ".join(names) or "no flags")
    if service:
        summary_text += " (%s)" % service

    layers.append({
        "name": "TCP", "start": offset, "length": max(data_offset, 20),
        "summary": summary_text,
        "fields": [
            _field("Source port", "%d%s" % (sport, _port_note(sport)), offset, 2),
            _field("Destination port", "%d%s" % (dport, _port_note(dport)), offset + 2, 2),
            _field("Sequence number", str(seq), offset + 4, 4,
                   "where this packet's data sits in the stream"),
            _field("Acknowledgement", str(ack), offset + 8, 4,
                   "everything before this has been received"),
            _field("Header length", "%d bytes" % data_offset, offset + 12, 1),
            _field("Flags", ", ".join(names) or "none", offset + 13, 1,
                   _flag_note(names)),
            _field("Window", str(window), offset + 14, 2,
                   "how much more this side is willing to receive right now"),
        ],
    })
    return offset + max(data_offset, 20)


def _port_note(port):
    name = port_name(port)
    return " (%s)" % name if name else ""


def _flag_note(names):
    have = set(names)
    if have == {"SYN"}:
        return "asking to open a connection"
    if have == {"SYN", "ACK"}:
        return "agreeing to open it"
    if "RST" in have:
        return "refusing or tearing down the connection"
    if "FIN" in have:
        return "finished sending"
    return ""


def _dissect_udp(data, offset, end, layers):
    if offset + 8 > end:
        layers.append(_raw_layer(data, offset, "Cut short before the UDP header finished"))
        return None
    sport = (data[offset] << 8) | data[offset + 1]
    dport = (data[offset + 2] << 8) | data[offset + 3]
    length = (data[offset + 4] << 8) | data[offset + 5]
    service = port_name(dport) or port_name(sport)
    summary_text = "%d to %d" % (sport, dport)
    if service:
        summary_text += " (%s)" % service
    layers.append({
        "name": "UDP", "start": offset, "length": 8,
        "summary": summary_text,
        "fields": [
            _field("Source port", "%d%s" % (sport, _port_note(sport)), offset, 2),
            _field("Destination port", "%d%s" % (dport, _port_note(dport)), offset + 2, 2),
            _field("Length", "%d bytes" % length, offset + 4, 2),
        ],
    })
    return offset + 8


def _dissect_icmp(data, offset, end, layers, proto):
    if offset + 4 > end:
        layers.append(_raw_layer(data, offset, "Cut short before the ICMP header finished"))
        return None
    kind = data[offset]
    code = data[offset + 1]
    name = _icmp_name(kind, proto)
    layers.append({
        "name": proto_name(proto), "start": offset, "length": 8 if offset + 8 <= end else 4,
        "summary": name,
        "fields": [
            _field("Type", "%d (%s)" % (kind, name), offset, 1),
            _field("Code", str(code), offset + 1, 1),
        ],
    })
    return offset + (8 if offset + 8 <= end else 4)


# ---------------------------------------------------------------------------
def hexdump(data, width=16):
    """The classic three column view: offset, bytes, and the readable characters."""
    lines = []
    for start in range(0, len(data), width):
        chunk = bytes(data[start:start + width])
        hexed = " ".join("%02x" % b for b in chunk)
        # A gap in the middle, the way every hex viewer does it, so the eye can count.
        if width == 16 and len(chunk) > 8:
            hexed = " ".join("%02x" % b for b in chunk[:8]) + "  " + \
                    " ".join("%02x" % b for b in chunk[8:])
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append({"offset": start, "hex": hexed, "text": text})
    return lines
