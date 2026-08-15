"""
Build capture files in every shape traffic-analyzer claims to read.

The point of this script is honesty. It is easy to say "supports pcapng" in a
readme. This writes real files in each format and each link type, so the test
script can prove the reader actually handles them instead of taking my word
for it.

    python3 tests/make_test_captures.py            writes into tests/captures/

Everything here is synthetic. No real network traffic, nobody's addresses.
"""

import gzip
import os
import random
import socket
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "captures")

LINK_ETHERNET = 1
LINK_RAW = 101
LINK_SLL = 113
LINK_SLL2 = 276
LINK_NULL = 0


# ---------------------------------------------------------------------------
# Building packets
# ---------------------------------------------------------------------------
def ipv4_header(src, dst, proto, payload_len, ttl=64, ident=0, frag=0):
    total = 20 + payload_len
    header = struct.pack("!BBHHHBBH4s4s",
                         0x45, 0, total, ident, frag, ttl, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    return header


def ipv6_header(src, dst, next_header, payload_len, hop=64):
    return struct.pack("!IHBB16s16s",
                       0x60000000, payload_len, next_header, hop,
                       socket.inet_pton(socket.AF_INET6, src),
                       socket.inet_pton(socket.AF_INET6, dst))


def tcp_segment(sport, dport, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 8192, 0, 0) + payload


def udp_segment(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def ethernet(payload, ethertype=0x0800):
    return b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66" + struct.pack("!H", ethertype) + payload


def vlan_ethernet(payload, ethertype=0x0800, tag=42):
    return (b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66"
            + struct.pack("!HHH", 0x8100, tag, ethertype) + payload)


def sll(payload, protocol=0x0800):
    return struct.pack("!HHH8sH", 0, 1, 6, b"\x11\x22\x33\x44\x55\x66\x00\x00", protocol) + payload


def sll2(payload, protocol=0x0800):
    return struct.pack("!HHIHBB8s", protocol, 0, 2, 1, 0, 6,
                       b"\x11\x22\x33\x44\x55\x66\x00\x00") + payload


def null_loopback(payload, family=2):
    return struct.pack("=I", family) + payload


# ---------------------------------------------------------------------------
# Writing the two file formats
# ---------------------------------------------------------------------------
def write_pcap(path, packets, link_type=LINK_ETHERNET, nanosecond=False,
               big_endian=False, compress=False):
    endian = ">" if big_endian else "<"
    if nanosecond:
        magic = 0xa1b23c4d
        scale = 1000000000
    else:
        magic = 0xa1b2c3d4
        scale = 1000000

    blob = [struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, link_type)]
    for ts, frame in packets:
        seconds = int(ts)
        fraction = int(round((ts - seconds) * scale))
        blob.append(struct.pack(endian + "IIII", seconds, fraction, len(frame), len(frame)))
        blob.append(frame)
    data = b"".join(blob)

    opener = gzip.open if compress else open
    with opener(path, "wb") as fh:
        fh.write(data)


def _option(code, value):
    padding = (4 - len(value) % 4) % 4
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * padding


def write_pcapng(path, packets, link_type=LINK_ETHERNET, names=None,
                 compress=False, simple_blocks=False):
    out = []

    # Section header block.
    body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    body += _option(3, b"traffic-analyzer test writer")
    body += _option(0, b"")
    out.append(_block(0x0A0D0D0A, body))

    # Interface description block, with an explicit microsecond resolution.
    body = struct.pack("<HHI", link_type, 0, 65535)
    body += _option(2, b"test0")
    body += _option(9, b"\x06")
    body += _option(0, b"")
    out.append(_block(0x00000001, body))

    if names:
        body = b""
        for ip, hostname in names.items():
            body += struct.pack("<HH", 1, 4 + len(hostname) + 1)
            raw = socket.inet_aton(ip) + hostname.encode() + b"\x00"
            padding = (4 - len(raw) % 4) % 4
            body += raw + b"\x00" * padding
        body += struct.pack("<HH", 0, 0)
        out.append(_block(0x00000004, body))

    for ts, frame in packets:
        padding = (4 - len(frame) % 4) % 4
        if simple_blocks:
            body = struct.pack("<I", len(frame)) + frame + b"\x00" * padding
            out.append(_block(0x00000003, body))
        else:
            stamp = int(ts * 1000000)
            body = struct.pack("<IIIII", 0, stamp >> 32, stamp & 0xFFFFFFFF,
                               len(frame), len(frame))
            body += frame + b"\x00" * padding
            out.append(_block(0x00000006, body))

    data = b"".join(out)
    opener = gzip.open if compress else open
    with opener(path, "wb") as fh:
        fh.write(data)


def _block(block_type, body):
    total = len(body) + 12
    return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)


# ---------------------------------------------------------------------------
# The traffic itself: a small, obvious SYN flood plus a little normal traffic.
# ---------------------------------------------------------------------------
def build_traffic(seed=7, attackers=12, per_attacker=60, family=4):
    random.seed(seed)
    packets = []
    start = 1700000000.0

    if family == 4:
        victim = "203.0.113.10"
        sources = ["198.51.100.%d" % (n + 3) for n in range(attackers)]
        normal = ["192.0.2.%d" % (n + 20) for n in range(4)]
    else:
        victim = "2001:db8:beef::10"
        sources = ["2001:db8:bad::%x" % (n + 3) for n in range(attackers)]
        normal = ["2001:db8:cafe::%x" % (n + 20) for n in range(4)]

    ts = start
    for round_number in range(per_attacker):
        for source in sources:
            ts += 0.0008
            segment = tcp_segment(random.randint(1024, 65535), 80, 0x02)
            if family == 4:
                packets.append((ts, ipv4_header(source, victim, 6, len(segment)) + segment))
            else:
                packets.append((ts, ipv6_header(source, victim, 6, len(segment)) + segment))

    # A handful of ordinary looking visitors so the report has a contrast.
    for source in normal:
        for n in range(6):
            ts += 0.05
            segment = tcp_segment(40000 + n, 443, 0x18, b"x" * 200)
            if family == 4:
                packets.append((ts, ipv4_header(source, victim, 6, len(segment)) + segment))
            else:
                packets.append((ts, ipv6_header(source, victim, 6, len(segment)) + segment))

    packets.sort(key=lambda item: item[0])
    return packets


def main():
    if not os.path.isdir(OUT):
        os.makedirs(OUT)

    ipv4 = build_traffic()
    ipv6 = build_traffic(family=6)
    written = []

    def note(name, count):
        written.append((name, count))

    # Classic pcap, the shape that already worked. The baseline.
    write_pcap(os.path.join(OUT, "classic.pcap"),
               [(ts, ethernet(f)) for ts, f in ipv4])
    note("classic.pcap", len(ipv4))

    # Big endian and nanosecond variants of the same file.
    write_pcap(os.path.join(OUT, "bigendian.pcap"),
               [(ts, ethernet(f)) for ts, f in ipv4], big_endian=True)
    note("bigendian.pcap", len(ipv4))

    write_pcap(os.path.join(OUT, "nanosecond.pcap"),
               [(ts, ethernet(f)) for ts, f in ipv4], nanosecond=True)
    note("nanosecond.pcap", len(ipv4))

    # Gzipped, which is how captures usually arrive by email.
    write_pcap(os.path.join(OUT, "classic.pcap.gz"),
               [(ts, ethernet(f)) for ts, f in ipv4], compress=True)
    note("classic.pcap.gz", len(ipv4))

    # pcapng, what Wireshark saves by default. This is the one that used to
    # be rejected outright.
    write_pcapng(os.path.join(OUT, "modern.pcapng"),
                 [(ts, ethernet(f)) for ts, f in ipv4],
                 names={"198.51.100.3": "botnode-3.example", "203.0.113.10": "shop.example"})
    note("modern.pcapng", len(ipv4))

    write_pcapng(os.path.join(OUT, "modern.pcapng.gz"),
                 [(ts, ethernet(f)) for ts, f in ipv4], compress=True)
    note("modern.pcapng.gz", len(ipv4))

    write_pcapng(os.path.join(OUT, "simpleblocks.pcapng"),
                 [(ts, ethernet(f)) for ts, f in ipv4], simple_blocks=True)
    note("simpleblocks.pcapng", len(ipv4))

    # IPv6, which used to be dropped on the floor entirely.
    write_pcapng(os.path.join(OUT, "ipv6.pcapng"),
                 [(ts, ethernet(f, 0x86DD)) for ts, f in ipv6])
    note("ipv6.pcapng", len(ipv6))

    # VLAN tags, left on by a switch.
    write_pcap(os.path.join(OUT, "vlan.pcap"),
               [(ts, vlan_ethernet(f)) for ts, f in ipv4])
    note("vlan.pcap", len(ipv4))

    # Link types other than Ethernet.
    write_pcap(os.path.join(OUT, "cooked.pcap"),
               [(ts, sll(f)) for ts, f in ipv4], link_type=LINK_SLL)
    note("cooked.pcap", len(ipv4))

    write_pcapng(os.path.join(OUT, "cooked2.pcapng"),
                 [(ts, sll2(f)) for ts, f in ipv4], link_type=LINK_SLL2)
    note("cooked2.pcapng", len(ipv4))

    write_pcap(os.path.join(OUT, "rawip.pcap"), ipv4, link_type=LINK_RAW)
    note("rawip.pcap", len(ipv4))

    write_pcap(os.path.join(OUT, "loopback.pcap"),
               [(ts, null_loopback(f)) for ts, f in ipv4], link_type=LINK_NULL)
    note("loopback.pcap", len(ipv4))

    # A file that stops in the middle of a packet, the way a capture does when
    # the disk fills or somebody kills tcpdump.
    with open(os.path.join(OUT, "classic.pcap"), "rb") as fh:
        whole = fh.read()
    with open(os.path.join(OUT, "truncated.pcap"), "wb") as fh:
        fh.write(whole[:len(whole) // 2])
    note("truncated.pcap", 0)

    # Something that is not a capture at all.
    with open(os.path.join(OUT, "notacapture.pcap"), "wb") as fh:
        fh.write(b"This is a text file somebody renamed.\n" * 40)
    note("notacapture.pcap", 0)

    # A large one, to prove memory stays flat. Roughly 400,000 packets.
    big = build_traffic(seed=11, attackers=200, per_attacker=2000)
    write_pcap(os.path.join(OUT, "large.pcap"),
               [(ts, ethernet(f)) for ts, f in big])
    note("large.pcap", len(big))

    print("Wrote %d capture files into %s\n" % (len(written), OUT))
    for name, count in written:
        size = os.path.getsize(os.path.join(OUT, name))
        print("  %-24s %9s bytes  %s packets" % (name, "{:,}".format(size), "{:,}".format(count)))


if __name__ == "__main__":
    main()
