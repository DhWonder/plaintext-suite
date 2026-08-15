"""
Reading capture files, and reading packets off a live network card.

This is the part that decides whether traffic-analyzer works on the file somebody
actually hands you, so it is deliberately forgiving. It reads:

  - classic pcap, both byte orders, microsecond and nanosecond stamps
  - pcapng, which is what Wireshark saves by default these days
  - either of those compressed with gzip (.pcap.gz, .pcapng.gz)
  - IPv4 and IPv6
  - Ethernet, raw IP, Linux cooked capture v1 and v2, loopback, PPP

When it cannot use a frame it does not silently drop it. It counts why it
skipped, so instead of "no packets found" you get "17,000 frames were IPv6
over a link type I do not read". A tool that tells you why it failed is worth
more than one that just fails.

Nothing here needs anything installed. Standard library only.
"""

import gzip
import socket
import struct
import sys

# ---------------------------------------------------------------------------
# Link types. These numbers come from the pcap standard and say what the first
# few bytes of every frame are before the IP header starts.
# ---------------------------------------------------------------------------
LINK_NULL      = 0      # BSD loopback, 4 byte family field in host order
LINK_ETHERNET  = 1      # by far the most common
LINK_PPP       = 9
LINK_RAW_12    = 12     # raw IP, no link layer at all
LINK_RAW_14    = 14
LINK_RAW_101   = 101
LINK_LOOP      = 108    # OpenBSD loopback, 4 byte family big endian
LINK_SLL       = 113    # Linux cooked capture, what "tcpdump -i any" produces
LINK_PPP_ETHER = 51
LINK_IPV4      = 228
LINK_IPV6      = 229
LINK_SLL2      = 276    # Linux cooked capture v2, newer tcpdump -i any

LINK_NAMES = {
    LINK_NULL: "BSD loopback",
    LINK_ETHERNET: "Ethernet",
    LINK_PPP: "PPP",
    LINK_RAW_12: "raw IP",
    LINK_RAW_14: "raw IP",
    LINK_RAW_101: "raw IP",
    LINK_LOOP: "OpenBSD loopback",
    LINK_SLL: "Linux cooked capture",
    LINK_SLL2: "Linux cooked capture v2",
    LINK_IPV4: "raw IPv4",
    LINK_IPV6: "raw IPv6",
    105: "bare 802.11 wireless",
    127: "802.11 with radiotap headers",
    143: "DOCSIS",
    195: "802.15.4",
}

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
ETHERTYPE_MPLS = 0x8847

# IPv6 headers that sit between the IP header and TCP or UDP. We walk past
# them to find the real protocol underneath.
IPV6_EXTENSIONS = {0: 8, 43: 8, 60: 8, 51: 8, 135: 8}
IPV6_FRAGMENT = 44
IPV6_NO_NEXT = 59


class CaptureError(Exception):
    """Raised when a file cannot be read at all, with a sentence a human can act on."""


class ReadStats(object):
    """What happened while reading. Reported to the user when little came through."""

    def __init__(self):
        self.frames = 0            # frames present in the file
        self.used = 0              # frames we understood
        self.link_types = {}       # link type number -> frames seen
        self.skipped = {}          # plain english reason -> count
        self.truncated = False     # file ended mid packet
        self.format = "unknown"    # pcap or pcapng
        self.compressed = False
        self.names = {}            # ip -> hostname, when the file carries them
        self.interfaces = []       # descriptions from pcapng

    def skip(self, reason):
        self.skipped[reason] = self.skipped.get(reason, 0) + 1

    def note_link(self, link_type):
        self.link_types[link_type] = self.link_types.get(link_type, 0) + 1

    def explain(self):
        """One paragraph saying why a capture produced nothing useful."""
        if self.used:
            return ""
        if not self.frames:
            return "The file opened but contained no packet records at all."
        parts = []
        for reason, count in sorted(self.skipped.items(), key=lambda kv: -kv[1]):
            parts.append("%s (%d frames)" % (reason, count))
        unknown = [lt for lt in self.link_types if not _link_supported(lt)]
        if unknown:
            names = ", ".join("%s (link type %d)" % (LINK_NAMES.get(lt, "unrecognised"), lt)
                              for lt in unknown)
            parts.append("the capture is %s, which this tool does not decode" % names)
        if not parts:
            return "The frames were readable but none of them carried IP traffic."
        return "Read %d frames, used none. " % self.frames + "; ".join(parts) + "."


def _link_supported(link_type):
    return link_type in (LINK_NULL, LINK_ETHERNET, LINK_PPP, LINK_RAW_12, LINK_RAW_14,
                         LINK_RAW_101, LINK_LOOP, LINK_SLL, LINK_SLL2, LINK_IPV4, LINK_IPV6)


# ---------------------------------------------------------------------------
# Opening the file, whatever wrapping it arrived in.
# ---------------------------------------------------------------------------
def _open_maybe_gzip(path, stats):
    """Open the file, transparently un-gzipping it if that is what it is."""
    fh = open(path, "rb")
    head = fh.read(2)
    fh.seek(0)
    if head == b"\x1f\x8b":
        fh.close()
        stats.compressed = True
        return gzip.open(path, "rb")
    return fh


def read_packets(path, stats=None, progress=None):
    """Yield one dictionary per usable packet, in file order.

    Streams the file rather than loading it, so a capture larger than memory
    is fine. The dictionary is deliberately flat and boring:

        ts, src, dst, proto, ttl, size, sport, dport, flags, family
    """
    if stats is None:
        stats = ReadStats()

    fh = _open_maybe_gzip(path, stats)
    try:
        magic = fh.read(4)
        if len(magic) < 4:
            raise CaptureError("That file is too short to be a capture.")

        if magic == b"\x0a\x0d\x0d\x0a":
            stats.format = "pcapng"
            for item in _read_pcapng(fh, stats, progress):
                yield item
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
                       b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"):
            stats.format = "pcap"
            for item in _read_pcap(fh, magic, stats, progress):
                yield item
        else:
            raise CaptureError(
                "That does not look like a capture file. traffic-analyzer reads pcap and "
                "pcapng files, the kind Wireshark and tcpdump write, optionally gzipped.")
    finally:
        fh.close()


# ---------------------------------------------------------------------------
# Classic pcap: a 24 byte file header, then 16 bytes and a frame, over and over.
# ---------------------------------------------------------------------------
def _read_pcap(fh, magic, stats, progress):
    rest = fh.read(20)
    if len(rest) < 20:
        raise CaptureError("That file has a capture header but nothing after it.")

    if magic == b"\xa1\xb2\xc3\xd4":
        endian, divisor = ">", 1000000.0
    elif magic == b"\xd4\xc3\xb2\xa1":
        endian, divisor = "<", 1000000.0
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, divisor = ">", 1000000000.0
    else:
        endian, divisor = "<", 1000000000.0

    link_type = struct.unpack(endian + "I", rest[16:20])[0]
    stats.interfaces.append({"link_type": link_type,
                             "name": LINK_NAMES.get(link_type, "link type %d" % link_type)})
    record = struct.Struct(endian + "IIII")
    read = fh.read

    while True:
        head = read(16)
        if len(head) < 16:
            if head:
                stats.truncated = True
            return
        ts_sec, ts_frac, incl_len, orig_len = record.unpack(head)

        # A sane guard. Without it a corrupt length field asks for a 4GB read.
        if incl_len > 0x400000:
            stats.skip("a packet claimed an impossible size, so reading stopped here")
            stats.truncated = True
            return

        data = read(incl_len)
        if len(data) < incl_len:
            stats.truncated = True
            return

        stats.frames += 1
        stats.note_link(link_type)
        packet = parse_frame(data, 0, len(data), link_type, stats)
        if packet is not None:
            packet["ts"] = ts_sec + ts_frac / divisor
            stats.used += 1
            yield packet
        if progress is not None and (stats.frames & 0x3FFF) == 0:
            progress(stats)


# ---------------------------------------------------------------------------
# pcapng: a stream of typed blocks. This is what modern Wireshark saves, and
# not reading it was the single biggest reason captures were being rejected.
#
# Every block is: type, total length, body, total length again. That trailing
# length means we can walk the file without understanding every block type,
# which is exactly what we do.
# ---------------------------------------------------------------------------
BLOCK_SHB = 0x0A0D0D0A
BLOCK_IDB = 0x00000001
BLOCK_PACKET_OLD = 0x00000002
BLOCK_SPB = 0x00000003
BLOCK_NRB = 0x00000004
BLOCK_EPB = 0x00000006


def _read_pcapng(fh, stats, progress):
    read = fh.read
    interfaces = []          # per interface: link type and timestamp resolution
    endian = "<"

    # The caller already read the four magic bytes of the section header block.
    # The byte order mark inside it tells us how to read every number after,
    # so that comes first and everything else follows from it.
    opening = read(8)
    if len(opening) < 8:
        raise CaptureError("That pcapng file stops inside its first block.")
    # The mark is always the value 0x1A2B3C4D. Which way round its four bytes
    # land on disk is exactly what tells us the byte order of the whole section.
    mark = opening[4:8]
    if mark == b"\x4d\x3c\x2b\x1a":
        endian = "<"
    elif mark == b"\x1a\x2b\x3c\x4d":
        endian = ">"
    else:
        raise CaptureError("That pcapng file has a damaged section header.")
    total_len = struct.unpack(endian + "I", opening[0:4])[0]
    if total_len < 16 or len(read(total_len - 12)) < total_len - 12:
        raise CaptureError("That pcapng file has a damaged section header.")

    while True:
        header = read(8)
        if len(header) < 8:
            if header:
                stats.truncated = True
            return
        block_type, total_len = struct.unpack(endian + "II", header)
        if total_len < 12 or total_len > 0x4000000:
            stats.truncated = True
            return
        body = read(total_len - 12)
        if len(body) < total_len - 12:
            stats.truncated = True
            return
        trailer = read(4)
        if len(trailer) < 4:
            stats.truncated = True
            return

        if block_type == BLOCK_SHB:
            # A new section starts. Byte order may differ from the last one,
            # and the interface list starts again from zero.
            mark = body[0:4]
            if mark == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif mark == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            interfaces = []

        elif block_type == BLOCK_IDB:
            link_type = struct.unpack(endian + "H", body[0:2])[0]
            options = _pcapng_options(body[8:], endian)
            # Option 9 is the timestamp resolution. Without it, microseconds.
            resolution = 1000000.0
            raw = options.get(9)
            if raw and raw[0]:
                value = raw[0][0]
                if value & 0x80:
                    resolution = float(2 ** (value & 0x7F))
                else:
                    resolution = float(10 ** value)
            name = b""
            if 2 in options:
                name = options[2][0]
            interfaces.append({"link_type": link_type, "resolution": resolution})
            stats.interfaces.append({
                "link_type": link_type,
                "name": (name.decode("utf-8", "replace") if name else
                         LINK_NAMES.get(link_type, "link type %d" % link_type)),
            })

        elif block_type == BLOCK_EPB:
            if len(body) < 20:
                continue
            iface_id, ts_hi, ts_lo, incl_len = struct.unpack(endian + "IIII", body[0:16])
            iface = interfaces[iface_id] if iface_id < len(interfaces) else {
                "link_type": LINK_ETHERNET, "resolution": 1000000.0}
            stats.frames += 1
            stats.note_link(iface["link_type"])
            if 20 + incl_len <= len(body):
                packet = parse_frame(body, 20, incl_len, iface["link_type"], stats)
                if packet is not None:
                    packet["ts"] = ((ts_hi << 32) | ts_lo) / iface["resolution"]
                    stats.used += 1
                    yield packet

        elif block_type == BLOCK_SPB:
            # Simple packet block: no timestamp, no interface id, always interface 0.
            iface = interfaces[0] if interfaces else {"link_type": LINK_ETHERNET,
                                                      "resolution": 1000000.0}
            stats.frames += 1
            stats.note_link(iface["link_type"])
            packet = parse_frame(body, 4, len(body) - 4, iface["link_type"], stats)
            if packet is not None:
                packet["ts"] = 0.0
                packet["no_time"] = True
                stats.used += 1
                yield packet

        elif block_type == BLOCK_PACKET_OLD:
            if len(body) < 20:
                continue
            iface_id, _drops, ts_hi, ts_lo, incl_len = struct.unpack(endian + "HHIII", body[0:16])
            iface = interfaces[iface_id] if iface_id < len(interfaces) else {
                "link_type": LINK_ETHERNET, "resolution": 1000000.0}
            stats.frames += 1
            stats.note_link(iface["link_type"])
            if 20 + incl_len <= len(body):
                packet = parse_frame(body, 20, incl_len, iface["link_type"], stats)
                if packet is not None:
                    packet["ts"] = ((ts_hi << 32) | ts_lo) / iface["resolution"]
                    stats.used += 1
                    yield packet

        elif block_type == BLOCK_NRB:
            # Name resolution. Free hostnames for the addresses in the capture,
            # recorded by whoever took it. Worth having for the detail panel.
            _read_name_records(body, endian, stats)

        if progress is not None and stats.frames and (stats.frames & 0x3FFF) == 0:
            progress(stats)


def _pcapng_options(blob, endian):
    """Parse the option list that trails most pcapng blocks."""
    options = {}
    offset = 0
    while offset + 4 <= len(blob):
        code, length = struct.unpack(endian + "HH", blob[offset:offset + 4])
        offset += 4
        if code == 0:
            break
        value = blob[offset:offset + length]
        options.setdefault(code, []).append(value)
        offset += length + ((4 - length % 4) % 4)
    return options


def _read_name_records(body, endian, stats):
    offset = 0
    while offset + 4 <= len(body):
        rec_type, length = struct.unpack(endian + "HH", body[offset:offset + 4])
        offset += 4
        if rec_type == 0:
            break
        value = body[offset:offset + length]
        offset += length + ((4 - length % 4) % 4)
        try:
            if rec_type == 1 and length >= 5:
                ip = socket.inet_ntoa(value[0:4])
                name = value[4:].split(b"\x00")[0].decode("utf-8", "replace")
                if name:
                    stats.names[ip] = name
            elif rec_type == 2 and length >= 17:
                ip = socket.inet_ntop(socket.AF_INET6, value[0:16])
                name = value[16:].split(b"\x00")[0].decode("utf-8", "replace")
                if name:
                    stats.names[ip] = name
        except (OSError, ValueError):
            pass


# ---------------------------------------------------------------------------
# Turning one frame into the handful of fields the analysis cares about.
# ---------------------------------------------------------------------------
def parse_frame(data, start, length, link_type, stats):
    """Return a packet dictionary, or None if there is nothing here we can use.

    `data` is the whole buffer, `start` and `length` say where this frame sits
    inside it, so no slicing and no copying happens on the hot path.
    """
    offset = start
    end = start + length

    if link_type == LINK_ETHERNET:
        if length < 14:
            stats.skip("frames shorter than an Ethernet header")
            return None
        ethertype = (data[offset + 12] << 8) | data[offset + 13]
        offset += 14
        # Hop over VLAN tags, including stacked ones the switch left on.
        hops = 0
        while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ) and offset + 4 <= end and hops < 4:
            ethertype = (data[offset + 2] << 8) | data[offset + 3]
            offset += 4
            hops += 1
        if ethertype == ETHERTYPE_MPLS:
            # Walk the label stack, then guess IP version from the next nibble.
            while offset + 4 <= end:
                bottom = data[offset + 2] & 0x01
                offset += 4
                if bottom:
                    break
            if offset >= end:
                return None
            ethertype = ETHERTYPE_IPV4 if (data[offset] >> 4) == 4 else ETHERTYPE_IPV6
        if ethertype == ETHERTYPE_IPV4:
            return _parse_ipv4(data, offset, end, stats)
        if ethertype == ETHERTYPE_IPV6:
            return _parse_ipv6(data, offset, end, stats)
        stats.skip("frames carrying something other than IP, such as ARP")
        return None

    if link_type in (LINK_RAW_12, LINK_RAW_14, LINK_RAW_101):
        if offset >= end:
            return None
        version = data[offset] >> 4
        if version == 4:
            return _parse_ipv4(data, offset, end, stats)
        if version == 6:
            return _parse_ipv6(data, offset, end, stats)
        stats.skip("raw frames that are neither IPv4 nor IPv6")
        return None

    if link_type == LINK_IPV4:
        return _parse_ipv4(data, offset, end, stats)

    if link_type == LINK_IPV6:
        return _parse_ipv6(data, offset, end, stats)

    if link_type == LINK_NULL:
        if length < 4:
            return None
        family = struct.unpack("=I", bytes(data[offset:offset + 4]))[0]
        offset += 4
        if family == 2:
            return _parse_ipv4(data, offset, end, stats)
        if family in (24, 28, 30):
            return _parse_ipv6(data, offset, end, stats)
        stats.skip("loopback frames that are not IP")
        return None

    if link_type == LINK_LOOP:
        if length < 4:
            return None
        family = struct.unpack(">I", bytes(data[offset:offset + 4]))[0]
        offset += 4
        if family == 2:
            return _parse_ipv4(data, offset, end, stats)
        if family in (24, 28, 30):
            return _parse_ipv6(data, offset, end, stats)
        stats.skip("loopback frames that are not IP")
        return None

    if link_type == LINK_SLL:
        if length < 16:
            return None
        protocol = (data[offset + 14] << 8) | data[offset + 15]
        offset += 16
        if protocol == ETHERTYPE_IPV4:
            return _parse_ipv4(data, offset, end, stats)
        if protocol == ETHERTYPE_IPV6:
            return _parse_ipv6(data, offset, end, stats)
        stats.skip("frames carrying something other than IP, such as ARP")
        return None

    if link_type == LINK_SLL2:
        if length < 20:
            return None
        protocol = (data[offset] << 8) | data[offset + 1]
        offset += 20
        if protocol == ETHERTYPE_IPV4:
            return _parse_ipv4(data, offset, end, stats)
        if protocol == ETHERTYPE_IPV6:
            return _parse_ipv6(data, offset, end, stats)
        stats.skip("frames carrying something other than IP, such as ARP")
        return None

    if link_type == LINK_PPP:
        if length < 4:
            return None
        protocol = (data[offset + 2] << 8) | data[offset + 3]
        offset += 4
        if protocol == 0x0021:
            return _parse_ipv4(data, offset, end, stats)
        if protocol == 0x0057:
            return _parse_ipv6(data, offset, end, stats)
        stats.skip("PPP frames that are not carrying IP")
        return None

    stats.skip("frames from a link type this tool does not decode")
    return None


def _ports(data, payload, end, proto, packet):
    """Fill in ports and TCP flags when the protocol has them."""
    if proto == 6 and payload + 20 <= end:
        packet["sport"] = (data[payload] << 8) | data[payload + 1]
        packet["dport"] = (data[payload + 2] << 8) | data[payload + 3]
        packet["flags"] = data[payload + 13]
        packet["window"] = (data[payload + 14] << 8) | data[payload + 15]
    elif proto == 17 and payload + 8 <= end:
        packet["sport"] = (data[payload] << 8) | data[payload + 1]
        packet["dport"] = (data[payload + 2] << 8) | data[payload + 3]
    elif proto in (1, 58) and payload + 2 <= end:
        packet["icmp_type"] = data[payload]


def _parse_ipv4(data, offset, end, stats):
    if offset + 20 > end:
        stats.skip("frames cut short before the IP header finished")
        return None
    first = data[offset]
    if first >> 4 != 4:
        return None
    ihl = (first & 0x0F) * 4
    if ihl < 20 or offset + ihl > end:
        stats.skip("frames with a damaged IP header")
        return None

    total_length = (data[offset + 2] << 8) | data[offset + 3]
    frag = ((data[offset + 6] << 8) | data[offset + 7]) & 0x1FFF
    proto = data[offset + 9]

    packet = {
        "src": socket.inet_ntoa(bytes(data[offset + 12:offset + 16])),
        "dst": socket.inet_ntoa(bytes(data[offset + 16:offset + 20])),
        "proto": proto,
        "ttl": data[offset + 8],
        "size": total_length or (end - offset),
        "sport": None,
        "dport": None,
        "flags": 0,
        "family": 4,
    }
    # Only the first fragment carries the ports. Later ones genuinely have none.
    if frag == 0:
        _ports(data, offset + ihl, end, proto, packet)
    else:
        packet["fragment"] = True
    return packet


def _parse_ipv6(data, offset, end, stats):
    if offset + 40 > end:
        stats.skip("frames cut short before the IPv6 header finished")
        return None
    if data[offset] >> 4 != 6:
        return None

    payload_length = (data[offset + 4] << 8) | data[offset + 5]
    next_header = data[offset + 6]
    hop_limit = data[offset + 7]

    try:
        src = socket.inet_ntop(socket.AF_INET6, bytes(data[offset + 8:offset + 24]))
        dst = socket.inet_ntop(socket.AF_INET6, bytes(data[offset + 24:offset + 40]))
    except (OSError, ValueError):
        stats.skip("frames with an unreadable IPv6 address")
        return None

    packet = {
        "src": src, "dst": dst, "proto": next_header, "ttl": hop_limit,
        "size": payload_length + 40, "sport": None, "dport": None,
        "flags": 0, "family": 6,
    }

    # Walk past any extension headers to find TCP, UDP or ICMPv6.
    payload = offset + 40
    proto = next_header
    walked = 0
    while walked < 8:
        if proto in IPV6_EXTENSIONS:
            if payload + 2 > end:
                return packet
            length = (data[payload + 1] + 1) * 8
            proto = data[payload]
            payload += length
            walked += 1
            continue
        if proto == IPV6_FRAGMENT:
            if payload + 8 > end:
                return packet
            frag_offset = ((data[payload + 2] << 8) | data[payload + 3]) & 0xFFF8
            proto = data[payload]
            payload += 8
            walked += 1
            if frag_offset:
                packet["fragment"] = True
                packet["proto"] = proto
                return packet
            continue
        break

    if proto == IPV6_NO_NEXT:
        return packet
    packet["proto"] = proto
    _ports(data, payload, end, proto, packet)
    return packet


# ---------------------------------------------------------------------------
# Live capture off a network card. Linux only, and it needs root, because
# reading other people's packets is a privileged thing to be able to do.
# ---------------------------------------------------------------------------
def open_live(interface="any"):
    """Return a raw socket listening to everything on the wire."""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    except AttributeError:
        raise CaptureError(
            "Live capture uses raw sockets, which only exist on Linux. On another "
            "system, capture with Wireshark or tcpdump and run traffic-analyzer on the file.")
    except PermissionError:
        raise CaptureError("Live capture needs administrator rights. Try again with sudo.")

    if interface and interface != "any":
        try:
            sock.bind((interface, 0))
        except OSError as exc:
            raise CaptureError("Could not listen on %s: %s" % (interface, exc))
    sock.settimeout(1.0)
    return sock


def list_interfaces():
    """Names of the network cards on this machine, best effort."""
    names = []
    try:
        with open("/proc/net/dev", "r") as fh:
            for line in fh.read().splitlines()[2:]:
                name = line.split(":", 1)[0].strip()
                if name:
                    names.append(name)
    except OSError:
        pass
    return names


def local_addresses():
    """Every address this machine answers to.

    This matters more than it looks. Without it the tool cannot tell the
    difference between somebody sending traffic at you and your own machine
    downloading something, and it ends up calling your own laptop an attacker.
    """
    found = set()

    # IPv4, asked of each interface directly.
    try:
        import fcntl
        SIOCGIFADDR = 0x8915
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for name in list_interfaces():
            try:
                packed = fcntl.ioctl(
                    sock.fileno(), SIOCGIFADDR,
                    struct.pack("256s", name[:15].encode("utf-8")))
                found.add(socket.inet_ntoa(packed[20:24]))
            except OSError:
                continue
        sock.close()
    except (ImportError, OSError):
        pass

    # IPv6, which the kernel lists in one place.
    try:
        with open("/proc/net/if_inet6", "r") as fh:
            for line in fh:
                parts = line.split()
                if not parts:
                    continue
                raw = parts[0]
                groups = [raw[i:i + 4] for i in range(0, 32, 4)]
                try:
                    found.add(socket.inet_ntop(
                        socket.AF_INET6, socket.inet_pton(socket.AF_INET6, ":".join(groups))))
                except (OSError, ValueError):
                    continue
    except OSError:
        pass

    found.add("127.0.0.1")
    found.add("::1")
    return found


def public_address(timeout=2.5):
    """Ask a public DNS resolver what address the world sees us as.

    This is the one thing in traffic-analyzer that talks to the outside, so it is
    never done unless somebody asks for it, and this is the whole of it: a
    single DNS query to OpenDNS, which answers with the address your traffic
    appears to come from. No web request, no third party analytics, nothing
    that logs a page view.
    """
    query = bytearray()
    query += struct.pack("!HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0)
    for label in (b"myip", b"opendns", b"com"):
        query += bytes([len(label)]) + label
    query += b"\x00"
    query += struct.pack("!HH", 1, 1)          # A record, IN class

    for resolver in ("208.67.222.222", "208.67.220.220"):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(bytes(query), (resolver, 53))
            data, _ = sock.recvfrom(512)
            sock.close()
        except OSError:
            continue

        # Walk to the end of the question, then read the first answer.
        offset = 12
        while offset < len(data) and data[offset]:
            offset += data[offset] + 1
        offset += 5                              # null label, type, class
        if offset + 12 > len(data):
            continue
        offset += 2                              # compressed name pointer
        rtype = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 8                              # type, class, ttl
        length = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2
        if rtype == 1 and length == 4 and offset + 4 <= len(data):
            return socket.inet_ntoa(data[offset:offset + 4])
    return ""
