"""
Working out what each source address is doing, and whether it is a problem.

The scoring rules are unchanged from the first version of traffic-analyzer. What is
new is that this can now survive a capture bigger than memory, and that it
keeps enough per source detail to answer "tell me everything about this one
address" without a second pass over the file.

Two things guard memory, because a real flood has spoofed source addresses and
you can easily meet a capture with two million of them:

  - the number of addresses tracked in full is capped, and everything past the
    cap is still counted, just grouped by network instead of by address
  - the counters inside each source are pruned when they get silly, keeping
    the busiest entries

Both caps are reported in the output. A number that quietly stopped being
exact is worse than no number.
"""

import time
from collections import Counter, defaultdict

# ---------------------------------------------------------------------------
# Ports worth commenting on.
#
# The first group are services that can be abused to reflect and amplify
# traffic: an attacker sends a small forged request and the service sends a
# much larger answer to the victim. A lot of traffic arriving FROM these source
# ports is almost always a reflection attack.
# ---------------------------------------------------------------------------
AMPLIFIER_PORTS = {
    53: "DNS", 123: "NTP", 1900: "SSDP", 11211: "memcached",
    161: "SNMP", 389: "CLDAP", 19: "chargen", 111: "portmapper",
    137: "NetBIOS", 27015: "game server",
}

# Services that hurt a business most when knocked over or broken into.
SENSITIVE_PORTS = {
    22: "SSH remote access", 3389: "Remote Desktop", 445: "Windows file sharing",
    25: "mail", 80: "website", 443: "website (secure)", 3306: "database",
    5432: "database", 1433: "database",
}

# Common services, used only to describe traffic in the detail panel.
PORT_NAMES = dict(SENSITIVE_PORTS)
PORT_NAMES.update({
    53: "DNS", 123: "NTP", 143: "IMAP", 993: "IMAP (secure)", 995: "POP3 (secure)",
    110: "POP3", 587: "mail submission", 465: "mail submission (secure)",
    21: "FTP", 23: "Telnet", 161: "SNMP", 389: "LDAP", 636: "LDAP (secure)",
    1900: "SSDP", 11211: "memcached", 5060: "SIP", 8080: "web (alternate)",
    8443: "web (secure, alternate)", 27015: "game server", 19: "chargen",
    111: "portmapper", 137: "NetBIOS", 139: "NetBIOS", 6379: "Redis",
    27017: "MongoDB", 9200: "Elasticsearch", 5900: "VNC",
})

# Doors that should never face the open internet. Repeated knocking on these
# means something different from repeated knocking on a web port.
ADMIN_PORTS = {22, 3389, 445, 3306, 5432, 1433, 5900, 23}

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6", 132: "SCTP"}

# TCP flag bits, used to tell a real connection from a flood of half opens.
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20

LEVELS = [
    ("critical", "#FB7185"),
    ("high",     "#FBBF24"),
    ("watch",    "#22D3EE"),
    ("normal",   "#34D399"),
]
LEVEL_ORDER = {"critical": 0, "high": 1, "watch": 2, "normal": 3}

# Safety valves.
MAX_SOURCES = 150000        # addresses tracked individually
MAX_COUNTER = 400           # entries kept inside one per source counter
COUNTER_KEEP = 120          # what survives a prune
MAX_BUCKETS = 900           # per source activity buckets before coarsening
RECENT_PACKETS = 12         # sample kept per source for the detail panel


# ---------------------------------------------------------------------------
# Which registry region an address belongs to.
#
# Worked out from the way IANA handed out the address space, so it needs no
# database and no internet. Enough to answer "is this traffic coming from
# places our customers actually live". Not city level, and the report says so.
# ---------------------------------------------------------------------------
REGION_BLOCKS = [
    ("AFRINIC (Africa)",            [41, 102, 105, 154, 196, 197]),
    ("LACNIC (Latin America)",      [177, 179, 181, 186, 187, 189, 190, 191, 200, 201]),
    ("APNIC (Asia Pacific)",        [1, 14, 27, 36, 39, 42, 43, 49, 58, 59, 60, 61, 101, 103,
                                     106, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120,
                                     121, 122, 123, 124, 125, 126, 133, 150, 153, 163, 171, 175,
                                     180, 182, 183, 202, 203, 210, 211, 218, 219, 220, 221, 222, 223]),
    ("RIPE (Europe, Middle East)",  [2, 5, 25, 31, 37, 46, 51, 53, 57, 62, 77, 78, 79, 80, 81, 82,
                                     83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 109, 141,
                                     145, 151, 176, 178, 185, 188, 193, 194, 195, 212, 213, 217]),
]

_REGION_LOOKUP = {}
for _name, _blocks in REGION_BLOCKS:
    for _first in _blocks:
        _REGION_LOOKUP[_first] = _name


def region_of(ip):
    """Return the registry region for an address, or a sensible fallback."""
    if ":" in ip:
        return _region_of_ipv6(ip)
    try:
        first = int(ip.split(".", 1)[0])
    except (ValueError, IndexError):
        return "unknown"
    if first in (10, 127, 172, 192, 169):
        return "private or local"
    return _REGION_LOOKUP.get(first, "ARIN (North America)")


def _region_of_ipv6(ip):
    head = ip.lower().split(":", 1)[0]
    if ip.startswith("fe80") or ip.startswith("fc") or ip.startswith("fd") or ip == "::1":
        return "private or local"
    if head.startswith("2001") and ip.lower().startswith("2001:db8"):
        return "documentation range"
    try:
        value = int(head or "0", 16)
    except ValueError:
        return "unknown"
    # Rough split of the global unicast space by the registry that received it.
    if 0x2001 <= value <= 0x2001:
        return "RIPE (Europe, Middle East)"
    if 0x2400 <= value < 0x2500:
        return "APNIC (Asia Pacific)"
    if 0x2600 <= value < 0x2700:
        return "ARIN (North America)"
    if 0x2800 <= value < 0x2900:
        return "LACNIC (Latin America)"
    if 0x2a00 <= value < 0x2b00:
        return "RIPE (Europe, Middle East)"
    if 0x2c00 <= value < 0x2d00:
        return "AFRINIC (Africa)"
    return "unknown"


def network_of(ip):
    """The neighbourhood an address sits in: /24 for IPv4, /48 for IPv6."""
    if ":" in ip:
        parts = ip.split(":")
        return ":".join(parts[:3]) + "::/48"
    parts = ip.split(".")
    if len(parts) != 4:
        return ip
    return ".".join(parts[:3]) + ".0/24"


def is_loopback(ip):
    if ":" in ip:
        return ip == "::1" or ip == "0:0:0:0:0:0:0:1"
    return ip.startswith("127.")


def is_private(ip):
    if ":" in ip:
        low = ip.lower()
        return low == "::1" or low.startswith("fe80") or low.startswith("fc") or low.startswith("fd")
    try:
        a, b = (int(x) for x in ip.split(".")[:2])
    except (ValueError, IndexError):
        return False
    return (a == 10 or a == 127 or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168) or a == 169)


def guess_initial_ttl(ttl):
    """Most stacks start at 64, 128 or 255. Which one tells you roughly what it is."""
    for start, name in ((64, "Linux, Unix or a phone"), (128, "Windows"),
                        (255, "network equipment or an appliance")):
        if ttl <= start:
            return start, name, start - ttl
    return 255, "unknown", 0


def port_name(port):
    return PORT_NAMES.get(port)


def _prune(counter):
    """Keep a counter from growing without bound on a hostile capture."""
    if len(counter) <= MAX_COUNTER:
        return counter
    kept = Counter(dict(counter.most_common(COUNTER_KEEP)))
    return kept


def _new_source():
    return {
        "packets": 0, "bytes": 0, "first": None, "last": None,
        "protocols": Counter(), "dports": Counter(), "sports": Counter(),
        "sizes": Counter(), "ttls": Counter(), "targets": Counter(),
        "syn": 0, "ack": 0, "rst": 0, "fin": 0, "other_flags": 0,
        "buckets": Counter(), "recent": [], "pruned": False,
        "family": 4, "fragments": 0,
    }


class Analyzer(object):
    """Builds a picture of the traffic one packet at a time."""

    def __init__(self, max_sources=MAX_SOURCES, bucket_seconds=1,
                 local_ips=None, mode="file", drop_loopback=False):
        # Who we are, and what kind of capture this is. Both change what the
        # numbers mean. Traffic arriving at a web server from a thousand
        # strangers is not the same thing as your own laptop downloading a
        # film, and without this the tool cannot tell them apart.
        self.local_ips = set(local_ips or ())
        self.mode = mode
        self.drop_loopback = drop_loopback
        self.sent_to = Counter()      # packets this machine sent to each address
        self.dropped_loopback = 0

        self.sources = {}
        self.per_second = Counter()
        self.total_packets = 0
        self.total_bytes = 0
        self.first_seen = None
        self.last_seen = None
        self.dest_counter = Counter()
        self.max_sources = max_sources
        self.bucket_seconds = bucket_seconds

        # Anything past the source cap still gets counted, grouped by network.
        self.overflow_networks = Counter()
        self.overflow_packets = 0
        self.overflow_sources = set()
        self.capped = False

        self.names = {}              # from the capture file, when it carries them
        self.origin = ""             # file name or interface, for the report

    # ------------------------------------------------------------------
    def ingest(self, ts, packet):
        src = packet["src"]
        dst = packet["dst"]

        # A machine talking to itself is not a visitor and cannot be an
        # attacker. Counting loopback as a source is how 127.0.0.1 ends up
        # at the top of a threat list, which is nonsense.
        if self.drop_loopback and (is_loopback(src) or is_loopback(dst)):
            self.dropped_loopback += 1
            return

        # Count what was addressed to each machine. This is what later tells a
        # conversation apart from a one sided flood: in a flood the sender does
        # not care whether anything comes back, and usually nothing does.
        self.sent_to[dst] += 1

        source = self.sources.get(src)

        if source is None:
            if len(self.sources) >= self.max_sources:
                # Past the cap. Keep counting, lose the per address detail.
                self.capped = True
                self.overflow_networks[network_of(src)] += 1
                self.overflow_packets += 1
                if len(self.overflow_sources) < 100000:
                    self.overflow_sources.add(src)
                self._ingest_totals(ts, packet)
                return
            source = self.sources[src] = _new_source()
            source["family"] = packet.get("family", 4)

        size = packet["size"]
        source["packets"] += 1
        source["bytes"] += size
        if source["first"] is None or ts < source["first"]:
            source["first"] = ts
        if source["last"] is None or ts > source["last"]:
            source["last"] = ts

        source["protocols"][PROTO_NAMES.get(packet["proto"], str(packet["proto"]))] += 1
        source["sizes"][size] += 1
        source["ttls"][packet["ttl"]] += 1
        source["targets"][packet["dst"]] += 1
        if packet.get("fragment"):
            source["fragments"] += 1

        dport = packet["dport"]
        sport = packet["sport"]
        if dport is not None:
            source["dports"][dport] += 1
        if sport is not None:
            source["sports"][sport] += 1

        flags = packet["flags"]
        if flags:
            if flags & SYN and not flags & ACK:
                source["syn"] += 1
            elif flags & ACK:
                source["ack"] += 1
            elif flags & RST:
                source["rst"] += 1
            else:
                source["other_flags"] += 1
            if flags & FIN:
                source["fin"] += 1

        source["buckets"][int(ts) // self.bucket_seconds] += 1

        # A short sample of what this address actually sent, for the panel that
        # opens when you click it. Kept small on purpose.
        if len(source["recent"]) < RECENT_PACKETS:
            source["recent"].append({
                "ts": round(ts, 4), "dst": packet["dst"], "proto": packet["proto"],
                "sport": sport, "dport": dport, "flags": flags, "size": size,
                "ttl": packet["ttl"],
            })

        # Housekeeping, only when a counter has actually got out of hand.
        if source["packets"] % 512 == 0:
            for key in ("dports", "sports", "sizes", "targets"):
                if len(source[key]) > MAX_COUNTER:
                    source[key] = _prune(source[key])
                    source["pruned"] = True
            if len(source["buckets"]) > MAX_BUCKETS:
                self._coarsen_buckets(source)

        self._ingest_totals(ts, packet)

    def _ingest_totals(self, ts, packet):
        self.dest_counter[packet["dst"]] += 1
        self.per_second[int(ts)] += 1
        self.total_packets += 1
        self.total_bytes += packet["size"]
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts

    def _coarsen_buckets(self, source):
        """Halve the resolution of one source's timeline rather than drop it."""
        merged = Counter()
        for bucket, count in source["buckets"].items():
            merged[bucket // 2] += count
        source["buckets"] = merged

    # ------------------------------------------------------------------
    # Scoring one source address.
    #
    # Every point added comes with a sentence explaining it, because a score
    # nobody understands is a score nobody acts on.
    # ------------------------------------------------------------------
    def is_conversation(self, ip, stats):
        """Did this machine talk back? Then it is an exchange, not an assault.

        A download, a video call and a backup upload all look like a lot of
        packets from one address. What separates them from a flood is that we
        answered, and the other end kept the conversation going. A flood does
        not care whether anyone answers, which is exactly why it is a flood.
        """
        outbound = self.sent_to.get(ip, 0)
        if outbound < 3:
            return False

        # Half open connections stay suspicious no matter how much came back.
        # A SYN flood makes the server send a pile of answers nobody completes,
        # and a port scan gets a reset from every closed port. Neither is a
        # conversation just because packets travelled in both directions.
        if stats["syn"] >= 15 and stats["ack"] == 0:
            return False

        # Nor is knocking on a remote access door over and over. Password
        # guessing completes connections on purpose, so it would otherwise
        # look like the politest traffic in the capture.
        top_dport = stats["dports"].most_common(1)
        if top_dport and top_dport[0][0] in ADMIN_PORTS and stats["syn"] >= 15:
            return False

        # Nor is a DNS tunnel. Data leaving inside name lookups is a
        # conversation by design, which is exactly what makes it work.
        if top_dport and top_dport[0][0] == 53 and stats["packets"] >= 80:
            if stats["bytes"] / float(stats["packets"]) > 110:
                return False

        # Reflected traffic arrives from a service we barely spoke to.
        top_sport = stats["sports"].most_common(1)
        if top_sport and top_sport[0][0] in AMPLIFIER_PORTS:
            if outbound < stats["packets"] * 0.02:
                return False
        return True

    def score(self, ip, stats):
        # Our own address is not a visitor. It turns up in a live capture
        # because we are the ones sending, and scoring it as a threat is how
        # a tool ends up accusing the machine it is running on.
        if ip in self.local_ips:
            return ("normal", 0,
                    ["this is this machine's own traffic going out, not somebody sending to you"],
                    stats["packets"] / max((stats["last"] or 0) - (stats["first"] or 0), 1.0))

        score = 0
        reasons = []

        duration = max((stats["last"] or 0) - (stats["first"] or 0), 0.001)
        rate = stats["packets"] / max(duration, 1.0)

        # A device on your own network is not a visitor, so "busier than a
        # visitor" says nothing about it. Printers, TVs, phones and backup
        # software are all noisy by nature. Scanning and flooding still count
        # against it below, because a device of yours doing that is worth
        # knowing about. Raw chattiness is not.
        indoors = is_private(ip) and ip not in self.local_ips

        # 1. Sheer volume from a single address.
        indoors_note = ""
        if indoors:
            if rate >= 50:
                indoors_note = ("busy, at about %d packets a second, which is normal for a device on "
                                "your own network rather than something to worry about" % rate)
        elif rate >= 200:
            score += 45
            reasons.append("sending about %d packets a second, far above anything a normal visitor does" % rate)
        elif rate >= 50:
            score += 30
            reasons.append("sending about %d packets a second, much faster than a person browsing" % rate)
        elif rate >= 12:
            score += 12
            reasons.append("sending about %d packets a second, busier than a typical visitor" % rate)

        # 2. Half open connections.
        #
        # A SYN flood and a port scan look similar at first glance: both open
        # connections and never finish them. The difference is where they aim.
        # A flood hammers one or two ports to exhaust the server, a scan walks
        # across many looking for something left open. Different answers, so
        # they are separated here.
        syn, ack = stats["syn"], stats["ack"]
        distinct_ports = len(stats["dports"])
        is_scan = syn >= 15 and distinct_ports >= 10

        if is_scan:
            score += 45
            reasons.append("knocked on %d different ports without completing a single connection, "
                           "which is somebody mapping out what you have running rather than "
                           "flooding you" % distinct_ports)
        elif syn >= 20 and ack == 0 and distinct_ports <= 3:
            score += 40
            reasons.append("opened %d connections and never completed a single one, all against the "
                           "same service, which is the signature of a SYN flood" % syn)
        elif syn >= 10 and ack < syn / 10.0 and distinct_ports <= 3:
            score += 25
            reasons.append("started %d connections but finished almost none of them" % syn)

        # 3. Reflection and amplification.
        top_sport = stats["sports"].most_common(1)
        if top_sport:
            sport, count = top_sport[0]
            if sport in AMPLIFIER_PORTS and count > 5:
                average = stats["bytes"] / float(stats["packets"])
                score += 40
                reasons.append("traffic is arriving from %s (port %d) at an average of %d bytes a "
                               "packet, which means this server is being used to reflect and "
                               "amplify an attack" % (AMPLIFIER_PORTS[sport], sport, average))

        # 4. Machine generated traffic tends to be identical every time.
        if not indoors and stats["packets"] >= 20 and stats["sizes"]:
            most_common_size = stats["sizes"].most_common(1)[0][1]
            if most_common_size / float(stats["packets"]) > 0.95:
                score += 15
                reasons.append("every packet is exactly the same size, so this is generated by a "
                               "tool rather than a real browser")

        # 5. Hitting something that matters.
        top_dport_all = stats["dports"].most_common(1)
        top_dport_all = top_dport_all[0] if top_dport_all else None
        for port, count in stats["dports"].most_common(3):
            if port in SENSITIVE_PORTS and count > 5:
                if port in (22, 3389, 445):
                    score += 20
                    reasons.append("aimed at %s (port %d), which should not be open to the whole "
                                   "internet in the first place" % (SENSITIVE_PORTS[port], port))
                else:
                    score += 5
                    reasons.append("aimed at your %s (port %d)" % (SENSITIVE_PORTS[port], port))
                break

        # 5b. Knocking on a remote access door over and over.
        #
        # Brute force does not look like a flood. The traffic is polite, the
        # connections complete, and the volume is low on purpose. What gives it
        # away is doing it hundreds of times to a door that should not be open.
        if top_dport_all and top_dport_all[0] in ADMIN_PORTS and stats["syn"] >= 20:
            completed = stats["syn"]
            score += 35
            reasons.append("opened %d separate connections to %s. Traffic this repetitive against "
                           "a login is password guessing, not somebody using the service"
                           % (completed, SENSITIVE_PORTS.get(top_dport_all[0], "a remote access port")))

        # 5c. Far more name lookups than looking up names needs.
        #
        # Data can be smuggled out of a network inside DNS questions, because
        # DNS is the one thing almost nobody blocks. It does not look like an
        # attack: the volume is low and the traffic is legitimate in shape.
        # What gives it away is the size. Real hostnames are short.
        if top_dport_all and top_dport_all[0] == 53 and stats["packets"] >= 80:
            average = stats["bytes"] / float(stats["packets"])
            if average > 110:
                score += 45
                reasons.append("sent %s name lookups averaging %d bytes each. Real hostnames are "
                               "short, so questions this long usually mean data is being carried "
                               "out of the network inside DNS"
                               % ("{:,}".format(stats["packets"]), average))

        # 6. Note when a flood is spread across the whole port range.
        #
        # Deliberately skips reflected traffic. Answers bounced off a DNS or NTP
        # server arrive on whatever random port the forged request used, so a
        # wide spread there is normal for the attack and says nothing extra.
        reflected = bool(top_sport) and top_sport[0][0] in AMPLIFIER_PORTS
        if not indoors and not is_scan and not reflected and distinct_ports >= 15 and stats["packets"] >= 30:
            score += 15
            reasons.append("spread its traffic across %d different ports, so a simple rule blocking "
                           "one port will not stop it" % distinct_ports)

        # 7. ICMP floods.
        if stats["protocols"].get("ICMP", 0) + stats["protocols"].get("ICMPv6", 0) > 50:
            score += 20
            reasons.append("flooding with ping traffic, which is only ever used to consume your "
                           "bandwidth")

        # 8. Was this a conversation we were part of?
        #
        # This runs last on purpose. Everything above measures how the traffic
        # looks; this asks what it actually was. A film downloading at two
        # thousand packets a second trips several of the rules above, and it is
        # still just a film downloading.
        if self.is_conversation(ip, stats):
            score = min(score, 12)
            outbound = self.sent_to.get(ip, 0)
            reasons.insert(0, "your machine sent %s packets to this address as well, so this is a "
                              "two way conversation your side started rather than traffic being "
                              "aimed at you" % "{:,}".format(outbound))

        if indoors_note:
            reasons.append(indoors_note)

        if score >= 70:
            level = "critical"
        elif score >= 40:
            level = "high"
        elif score >= 15:
            level = "watch"
        else:
            level = "normal"
            if not reasons:
                reasons.append("behaving like an ordinary visitor")

        return level, min(score, 100), reasons, rate

    # ------------------------------------------------------------------
    def fingerprint(self, row, stats):
        """A short label describing how this source behaves.

        Two addresses with the same fingerprint are doing the same thing, which
        in a flood usually means they are the same botnet or the same tool. It
        is what lets the detail panel say "and 340 others just like it".
        """
        size = stats["sizes"].most_common(1)[0][0] if stats["sizes"] else 0
        ttl = stats["ttls"].most_common(1)[0][0] if stats["ttls"] else 0
        initial, _label, _hops = guess_initial_ttl(ttl)

        if row["syn"] and not row["ack"]:
            shape = "syn-only"
        elif row["ack"]:
            shape = "established"
        elif stats["rst"]:
            shape = "reset"
        else:
            shape = "stateless"

        rate = row["rate"]
        if rate >= 200:
            band = "very-fast"
        elif rate >= 50:
            band = "fast"
        elif rate >= 12:
            band = "steady"
        else:
            band = "slow"

        return "|".join([
            row["protocol"],
            "dport:%s" % (row["top_dport"] if row["top_dport"] is not None else "-"),
            "sport:%s" % ("random" if len(stats["sports"]) > 20 else
                          (row["top_sport"] if row["top_sport"] is not None else "-")),
            "size:%d" % size,
            "ttl:%d" % initial,
            shape,
            band,
        ])

    # ------------------------------------------------------------------
    def rows(self):
        """Score every tracked source and return the full list, worst first."""
        scored = []
        for ip, stats in self.sources.items():
            level, score, reasons, rate = self.score(ip, stats)
            is_scan = stats["syn"] >= 15 and len(stats["dports"]) >= 10
            row = {
                "ip": ip,
                "scan": is_scan,
                "region": region_of(ip),
                "network": network_of(ip),
                "level": level,
                "score": score,
                "reasons": reasons,
                "packets": stats["packets"],
                "bytes": stats["bytes"],
                "rate": round(rate, 1),
                "first": stats["first"],
                "last": stats["last"],
                "protocol": (stats["protocols"].most_common(1) or [("none", 0)])[0][0],
                "top_dport": (stats["dports"].most_common(1) or [(None, 0)])[0][0],
                "top_sport": (stats["sports"].most_common(1) or [(None, 0)])[0][0],
                "ports_touched": len(stats["dports"]),
                "targets_touched": len(stats["targets"]),
                "syn": stats["syn"],
                "ack": stats["ack"],
                "rst": stats["rst"],
                "family": stats["family"],
                "hostname": self.names.get(ip, ""),
            }
            row["fingerprint"] = self.fingerprint(row, stats)
            scored.append(row)

        scored.sort(key=lambda r: (r["score"], r["packets"]), reverse=True)
        return scored

    # ------------------------------------------------------------------
    def detail(self, ip):
        """Everything known about one address. This is what the panel shows."""
        stats = self.sources.get(ip)
        if stats is None:
            return None

        level, score, reasons, rate = self.score(ip, stats)
        is_scan = stats["syn"] >= 15 and len(stats["dports"]) >= 10
        row = {
            "ip": ip, "scan": is_scan, "level": level, "score": score,
            "reasons": reasons, "rate": round(rate, 1),
            "packets": stats["packets"], "bytes": stats["bytes"],
            "protocol": (stats["protocols"].most_common(1) or [("none", 0)])[0][0],
            "top_dport": (stats["dports"].most_common(1) or [(None, 0)])[0][0],
            "top_sport": (stats["sports"].most_common(1) or [(None, 0)])[0][0],
            "syn": stats["syn"], "ack": stats["ack"], "rst": stats["rst"],
        }
        signature = self.fingerprint(row, stats)

        ttl = stats["ttls"].most_common(1)[0][0] if stats["ttls"] else 0
        initial, os_guess, hops = guess_initial_ttl(ttl)

        base = int(self.first_seen or 0)
        timeline = sorted((bucket * self.bucket_seconds - base, count)
                          for bucket, count in stats["buckets"].items())

        return {
            "ip": ip,
            "hostname": self.names.get(ip, ""),
            "family": stats["family"],
            "level": level,
            "score": score,
            "reasons": reasons,
            "rate": round(rate, 1),
            "packets": stats["packets"],
            "bytes": stats["bytes"],
            "first": stats["first"],
            "last": stats["last"],
            "duration": round((stats["last"] or 0) - (stats["first"] or 0), 3),
            "share_of_capture": round(100.0 * stats["packets"] / max(self.total_packets, 1), 2),
            "region": region_of(ip),
            "network": network_of(ip),
            "private": is_private(ip),
            "fingerprint": signature,
            "scan": is_scan,
            "fragments": stats["fragments"],
            "counters_pruned": stats["pruned"],
            "host": {
                "observed_ttl": ttl,
                "initial_ttl": initial,
                "os_guess": os_guess,
                "hops_away": hops,
                "distinct_ttls": len(stats["ttls"]),
            },
            "flags": {
                "syn": stats["syn"], "ack": stats["ack"], "rst": stats["rst"],
                "fin": stats["fin"], "other": stats["other_flags"],
            },
            "protocols": stats["protocols"].most_common(6),
            "dports": [(p, n, port_name(p)) for p, n in stats["dports"].most_common(12)],
            "sports": [(p, n, port_name(p)) for p, n in stats["sports"].most_common(8)],
            "targets": stats["targets"].most_common(10),
            "sizes": stats["sizes"].most_common(6),
            "timeline": timeline,
            "recent": stats["recent"],
        }

    # ------------------------------------------------------------------
    def context_for(self, ip, rows=None, limit=8):
        """The addresses worth looking at next to this one.

        Three relationships, because they mean different things:
        peers behave identically, neighbours sit in the same network block,
        and co-targets are aiming at the same machine.
        """
        rows = rows if rows is not None else self.rows()
        by_ip = {r["ip"]: r for r in rows}
        me = by_ip.get(ip)
        if me is None:
            return {"peers": [], "neighbours": [], "co_targets": [], "peer_total": 0}

        peers, neighbours = [], []
        network = me["network"]
        for row in rows:
            if row["ip"] == ip:
                continue
            if row["fingerprint"] == me["fingerprint"]:
                peers.append(row)
            if row["network"] == network:
                neighbours.append(row)

        stats = self.sources.get(ip)
        main_target = stats["targets"].most_common(1)[0][0] if stats and stats["targets"] else None
        co_targets = []
        if main_target:
            for row in rows:
                if row["ip"] == ip:
                    continue
                other = self.sources.get(row["ip"])
                if other and main_target in other["targets"]:
                    co_targets.append(row)

        trim = lambda items: [{
            "ip": r["ip"], "level": r["level"], "packets": r["packets"],
            "rate": r["rate"], "region": r["region"], "score": r["score"],
        } for r in items[:limit]]

        return {
            "peers": trim(peers),
            "peer_total": len(peers),
            "peer_packets": sum(r["packets"] for r in peers),
            "neighbours": trim(neighbours),
            "neighbour_total": len(neighbours),
            "co_targets": trim(co_targets),
            "co_target_total": len(co_targets),
            "main_target": main_target,
        }

    # ------------------------------------------------------------------
    def cohorts(self, rows=None, minimum=3):
        """Group sources that behave identically. In a flood these are the botnet."""
        rows = rows if rows is not None else self.rows()
        groups = defaultdict(list)
        for row in rows:
            groups[row["fingerprint"]].append(row)

        out = []
        for signature, members in groups.items():
            if len(members) < minimum:
                continue
            hostile = [m for m in members if m["level"] in ("critical", "high")]
            out.append({
                "fingerprint": signature,
                "members": len(members),
                "packets": sum(m["packets"] for m in members),
                "hostile": len(hostile),
                "level": members[0]["level"],
                "example": members[0]["ip"],
                "description": describe_fingerprint(signature),
                "regions": Counter(m["region"] for m in members).most_common(3),
            })
        out.sort(key=lambda g: g["packets"], reverse=True)
        return out

    # ------------------------------------------------------------------
    def summarise(self, top_n=40, rows=None):
        window = max((self.last_seen or 0) - (self.first_seen or 0), 1.0)
        scored = rows if rows is not None else self.rows()

        counts = Counter(r["level"] for r in scored)
        hostile = [r for r in scored if r["level"] in ("critical", "high")]
        hostile_packets = sum(r["packets"] for r in hostile)

        # Which attack patterns are present, so we can recommend fixes.
        vectors = set()
        for r in hostile:
            if r["scan"]:
                vectors.add("port_scan")
            elif r["syn"] > 10 and r["ack"] == 0:
                vectors.add("syn_flood")
            if r["top_sport"] in AMPLIFIER_PORTS:
                vectors.add("amplification_" + AMPLIFIER_PORTS[r["top_sport"]])
            if r["protocol"] in ("ICMP", "ICMPv6"):
                vectors.add("icmp_flood")
            if r["top_dport"] in ADMIN_PORTS:
                vectors.add("exposed_admin_port")
                if r["syn"] >= 20:
                    vectors.add("brute_force")
            if r["top_dport"] == 53 and r["packets"] >= 80:
                vectors.add("dns_tunnel")
            if r["protocol"] == "UDP" and r["top_sport"] not in AMPLIFIER_PORTS:
                vectors.add("udp_flood")

        timeline = []
        if self.per_second:
            start, end = min(self.per_second), max(self.per_second)
            # Never emit more than a few thousand points, however long the capture.
            span = end - start + 1
            step = max(1, span // 4000)
            for second in range(start, end + 1, step):
                total = 0
                for offset in range(step):
                    total += self.per_second.get(second + offset, 0)
                timeline.append(total)

        regions = Counter()
        hostile_regions = Counter()
        for r in scored:
            regions[r["region"]] += r["packets"]
            if r["level"] in ("critical", "high"):
                hostile_regions[r["region"]] += r["packets"]

        protocols = Counter()
        ports = Counter()
        for ip, stats in self.sources.items():
            for name, n in stats["protocols"].items():
                protocols[name] += n
            for port, n in stats["dports"].items():
                ports[port] += n

        target = self.dest_counter.most_common(1)
        total_sources = len(self.sources) + len(self.overflow_sources)

        summary = {
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "origin": self.origin,
            "mode": self.mode,
            "local_ips": sorted(self.local_ips),
            "dropped_loopback": self.dropped_loopback,
            "duration_seconds": round(window, 1),
            "started_at": self.first_seen,
            "ended_at": self.last_seen,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "sources_total": total_sources,
            "counts": dict(counts),
            "hostile_sources": len(hostile),
            "hostile_packets": hostile_packets,
            "hostile_share": round(100.0 * hostile_packets / max(self.total_packets, 1), 1),
            "peak_per_second": max(timeline) if timeline else 0,
            "average_per_second": round(self.total_packets / max(window, 1.0), 1),
            "main_target": target[0][0] if target else "unknown",
            "targets": self.dest_counter.most_common(8),
            "timeline": timeline,
            "timeline_step": max(1, (max(self.per_second) - min(self.per_second) + 1) // 4000)
                             if self.per_second else 1,
            "sources": scored[:top_n],
            "all_source_count": len(scored),
            "regions": regions.most_common(8),
            "hostile_regions": hostile_regions.most_common(8),
            "protocols": protocols.most_common(6),
            "ports": [(p, n) for p, n in ports.most_common(8)],
            "vectors": sorted(vectors),
            "cohorts": self.cohorts(scored)[:6],
            "verdict": self.verdict(vectors, len(hostile), hostile_packets,
                                    self.total_packets, hostile),
            "recommendations": recommendations(vectors, hostile_regions, scored),
        }

        if self.capped:
            summary["capped"] = {
                "tracked": len(self.sources),
                "extra_sources_seen": len(self.overflow_sources),
                "extra_packets": self.overflow_packets,
                "top_networks": self.overflow_networks.most_common(8),
                "note": ("This capture had more source addresses than the tool tracks "
                         "individually (%s). Everything past that point is still counted, "
                         "but grouped by network instead of by address. The totals are "
                         "right, the per address list is the busiest ones."
                         % "{:,}".format(self.max_sources)),
            }
        return summary

    # ------------------------------------------------------------------
    def verdict(self, vectors, hostile_count, hostile_packets, total, hostile=None):
        """Say what this is, and do not say more than the evidence supports.

        The word "attack" has to be earned. Traffic that does not look like a
        person browsing is not the same thing as somebody attacking you: it is
        also what a backup, a game, a software update and a smart TV look like.
        Calling all of that an attack is the security industry's worst habit
        and it trains people to ignore the warning that matters.
        """
        hostile = hostile or []

        # Which of the busy addresses are actually strangers on the internet?
        outside = [r for r in hostile
                   if not is_private(r["ip"]) and not is_loopback(r["ip"])
                   and r["ip"] not in self.local_ips]
        indoors = [r for r in hostile if r not in outside]

        if not vectors or hostile_count == 0:
            return ("Nothing here looks like an attack",
                    "Every address in this capture behaves the way ordinary use looks. That is the "
                    "answer most of the time, and it is worth having in writing.")

        if not outside:
            # A device of your own scanning or flooding is a different thing
            # from a device of your own being chatty, and it deserves saying.
            misbehaving = [r for r in indoors if r.get("scan") or r.get("syn", 0) > 20]
            if misbehaving:
                which = ", ".join(r["ip"] for r in misbehaving[:3])
                return ("Nobody is attacking you, but look at one of your own devices",
                        "Nothing is coming at you from outside. What did stand out is on your own "
                        "network: %s %s behaving in a way an ordinary device does not, by knocking "
                        "on many ports or opening connections it never finishes. That is worth "
                        "identifying. It is usually a scanner somebody installed, a security tool "
                        "doing its job, or a device that has been taken over. Open it in the list "
                        "to see exactly what it did."
                        % (which, "is" if len(misbehaving) == 1 else "are"))

            where = "your own network" if indoors else "this machine"
            return ("Nothing here looks like an attack",
                    "Some addresses are busier than a person browsing, but all of them are on %s. "
                    "Devices on your own network are busy for ordinary reasons: backups, updates, "
                    "streaming, phones syncing photos. Have a look at the list if you want to know "
                    "what yours are doing, but there is no sign of anybody attacking you here."
                    % where)

        share = 100.0 * hostile_packets / max(total, 1)
        amplified = any(v.startswith("amplification_") for v in vectors)
        # Volume is not the only thing that makes something an attack. Password
        # guessing and data leaving the building are both quiet by design.
        deliberate = "brute_force" in vectors or "dns_tunnel" in vectors
        real_flood = (len(outside) >= 5 or amplified or deliberate
                      or (share > 50 and len(outside) >= 2))

        if not real_flood:
            names = ", ".join(r["ip"] for r in outside[:3])
            return ("Worth a look, but not an attack",
                    "%d address%s from outside your network (%s) sent traffic that does not look "
                    "like ordinary browsing. That is not enough to call it an attack. One busy "
                    "address is usually a download, an update server, a badly behaved app or a "
                    "scanner having a quick look at everything on the internet. Open it in the list "
                    "and the reasons are spelled out."
                    % (len(outside), "" if len(outside) == 1 else "es", names))

        kinds = []
        if "syn_flood" in vectors:
            kinds.append("a SYN flood, which fills up the connection table so real customers cannot get in")
        amp = sorted(v.split("_", 1)[1] for v in vectors if v.startswith("amplification_"))
        if amp:
            names = " and ".join(amp) if len(amp) < 3 else ", ".join(amp[:-1]) + " and " + amp[-1]
            kinds.append("a reflection attack bounced off %s servers, which multiplies the attacker's "
                         "bandwidth against you" % names)
        if "udp_flood" in vectors:
            kinds.append("a plain UDP flood aimed at saturating the line")
        if "icmp_flood" in vectors:
            kinds.append("a ping flood")
        if "port_scan" in vectors:
            kinds.append("at least one host scanning your ports, which is a separate problem from the "
                         "flood and worth looking at once the dust settles")
        if "brute_force" in vectors:
            kinds.append("password guessing against a login that faces the internet, which is "
                         "patient rather than loud and works eventually if nobody is watching")
        elif "exposed_admin_port" in vectors:
            kinds.append("probing of remote access ports that are open to the internet")
        if "dns_tunnel" in vectors:
            kinds.append("name lookups being used to carry data out of the network, which is how "
                         "information leaves a building that blocks everything else")

        # Count the strangers, not the printer. Saying "under attack from 40
        # sources" when 36 of them are your own devices is the kind of number
        # that gets a tool quietly ignored.
        if deliberate and len(outside) < 5 and not amplified:
            headline = "Deliberate, and not loud enough to notice by accident"
        else:
            headline = ("Under attack from %d source%s"
                        % (len(outside), "" if len(outside) == 1 else "s"))
        if len(kinds) == 1:
            what = kinds[0]
            lead = "What is happening: "
        else:
            what = ", ".join(kinds[:-1]) + ", and finally " + kinds[-1]
            lead = "There is more than one thing going on at once here: "
        body = ("About %.0f%% of all traffic in this capture comes from addresses that do not "
                "behave like visitors. %s%s. It is arriving from several addresses at the same "
                "time, which is what makes it distributed, and why blocking them by hand as they "
                "appear will never catch up." % (share, lead, what))
        if indoors:
            body += (" %d busy address%s on your own network %s counted separately, because a "
                     "device of yours being busy is not an attack."
                     % (len(indoors), "" if len(indoors) == 1 else "es",
                        "is" if len(indoors) == 1 else "are"))
        return (headline, body)


def rule_for(row):
    """The short rule name and sentence for one source.

    These are the names that appear in the alert feed. They read like the rule
    names in a real monitoring console on purpose, because that is what the
    client's other suppliers will show them, but each one carries a plain
    sentence next to it so nobody has to look anything up.
    """
    if row["scan"]:
        return ("FLOOD.SCAN.PORTSWEEP",
                "walked across %d ports looking for something open" % row.get("ports_touched", 0))
    sport = row.get("top_sport")
    if sport in AMPLIFIER_PORTS:
        return ("FLOOD.AMP." + AMPLIFIER_PORTS[sport].upper().replace(" ", ""),
                "reflected off a %s server, arriving already multiplied" % AMPLIFIER_PORTS[sport])
    if row.get("syn", 0) > 10 and not row.get("ack", 0):
        return ("FLOOD.TCP.SYN",
                "opened %d connections and finished none of them" % row["syn"])
    if row.get("protocol") in ("ICMP", "ICMPv6"):
        return ("FLOOD.ICMP.ECHO", "ping traffic sent only to use up bandwidth")
    if row.get("top_dport") in (22, 3389, 445):
        return ("PROBE.ADMIN.PORT",
                "probing %s, which should not face the internet"
                % SENSITIVE_PORTS.get(row["top_dport"], "a remote access port"))
    if row.get("protocol") == "UDP":
        return ("FLOOD.UDP.GENERIC", "one way UDP aimed at filling the line")
    if row.get("level") in ("critical", "high"):
        return ("TRAFFIC.HOSTILE", "behaving unlike a normal visitor")
    return ("TRAFFIC.OBSERVED", "ordinary traffic")


def describe_fingerprint(signature):
    """Turn the machine readable signature into a sentence.

    Two cohorts that differ only in the operating system underneath must read
    differently here, otherwise the report shows the same sentence twice and
    looks broken. So every field that can separate two groups gets a mention.
    """
    chunks = signature.split("|")
    parts = {}
    order = []
    for chunk in chunks:
        if ":" in chunk:
            key, value = chunk.split(":", 1)
            parts[key] = value
        else:
            order.append(chunk)

    protocol = chunks[0]
    dport = parts.get("dport", "-")
    sport = parts.get("sport", "-")
    size = parts.get("size", "0")
    shape = order[1] if len(order) > 1 else ""
    band = order[2] if len(order) > 2 else ""

    where = "port %s" % dport if dport not in ("-", "None") else "no fixed port"
    how = {
        "syn-only": "opening connections and never finishing them",
        "established": "completing normal connections",
        "reset": "sending resets",
        "stateless": "sending one way traffic",
    }.get(shape, shape)
    speed = {
        "very-fast": "very fast", "fast": "fast", "steady": "steadily", "slow": "slowly",
    }.get(band, band)

    try:
        initial = int(parts.get("ttl", "0"))
    except ValueError:
        initial = 0
    system = {64: "Linux or Unix", 128: "Windows",
              255: "network gear"}.get(initial, "an unknown system")

    if sport == "random":
        from_where = "from random source ports"
    elif sport not in ("-", "None"):
        from_where = "from port %s" % sport
    else:
        from_where = "with no source port"

    return ("%s at %s %s, %s, %s, packets of %s bytes, sent by %s"
            % (protocol, where, from_where, how, speed, size, system))


# ---------------------------------------------------------------------------
# Turning findings into things to actually change.
# ---------------------------------------------------------------------------
def recommendations(vectors, hostile_regions, scored):
    out = []

    if "syn_flood" in vectors:
        out.append(("Turn on SYN cookies and connection rate limits",
                    "Your server is holding open thousands of half finished connections. Enabling "
                    "SYN cookies lets it answer without reserving memory for each one, and a "
                    "connection rate limit per address stops any single source hogging the queue. "
                    "This is a configuration change, not new hardware.",
                    "high"))
        out.append(("Put the website behind a filtering service",
                    "A service like Cloudflare absorbs this kind of flood before it reaches your "
                    "line. For a small business the entry plans cost little and this is the single "
                    "most effective change available.",
                    "high"))

    amp = [v.split("_", 1)[1] for v in vectors if v.startswith("amplification_")]
    if amp:
        out.append(("Ask your provider to filter reflected %s traffic upstream" % ", ".join(amp),
                    "Reflected traffic is already using up your line before you can drop it, so "
                    "filtering has to happen upstream at your internet provider. Send them the "
                    "source list from this report and ask for a filter on that traffic.",
                    "high"))
        out.append(("Check that none of your own servers can be used this way",
                    "The same services being abused against you (%s) are often left open on other "
                    "people's networks by accident. Any of these running on your side should only "
                    "answer to your own addresses, never to the whole internet." % ", ".join(amp),
                    "medium"))

    if "udp_flood" in vectors:
        out.append(("Drop unexpected UDP at the edge",
                    "Your business does not need to accept UDP traffic on ports it does not run a "
                    "service on. A default deny rule on the firewall for unused UDP removes a whole "
                    "category of this traffic.",
                    "medium"))

    if "icmp_flood" in vectors:
        out.append(("Rate limit ping traffic",
                    "Ping is useful for diagnostics, so rather than blocking it completely, limit it "
                    "to a few packets a second. That keeps it working for you and useless for them.",
                    "low"))

    if "port_scan" in vectors:
        out.append(("Look at what the scanner found, not just that it scanned",
                    "One host walked across your ports looking for a way in. Scanning is constant "
                    "background noise on the internet, so the useful question is what it would have "
                    "found. Anything answering that does not need to face the internet should be "
                    "closed or moved behind a VPN.",
                    "medium"))

    if "exposed_admin_port" in vectors:
        out.append(("Close remote access to the open internet",
                    "Remote Desktop and SSH should never be reachable by everyone. Put them behind a "
                    "VPN, or restrict them to the specific addresses your team works from. This is "
                    "urgent regardless of the flood, because these ports get broken into constantly.",
                    "high"))

    # Regional recommendation, only when the traffic is genuinely lopsided.
    if hostile_regions:
        top_region, top_packets = hostile_regions.most_common(1)[0]
        total_hostile = sum(hostile_regions.values())
        if total_hostile and top_packets / float(total_hostile) > 0.5 and "private" not in top_region:
            out.append(("Consider limiting traffic from %s while the attack is running" % top_region,
                        "Most of the hostile traffic was allocated in %s. If your customers are not "
                        "there, a temporary geographic limit is a quick way to cut the volume. Check "
                        "your real customer list first, and treat it as a temporary measure rather "
                        "than a permanent policy." % top_region,
                        "medium"))

    out.append(("Write down what normal looks like",
                "The reason this analysis works is that we can compare against ordinary traffic. "
                "Keeping a baseline of your typical packet rates and busiest hours means the next "
                "incident gets diagnosed in minutes instead of hours.",
                "low"))

    out.append(("Agree who calls the provider, before the next time",
                "In an attack, most of the delay is not technical. It is working out who is allowed "
                "to phone the internet provider and authorise emergency filtering. Decide that now "
                "and write the number on the emergency sheet.",
                "low"))

    return out
