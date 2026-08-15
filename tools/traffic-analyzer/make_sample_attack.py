#!/usr/bin/env python3
"""
make_sample_attack.py - builds a realistic capture file to try traffic-analyzer on.

You should not need a real attack to see whether a tool works, so this writes a
genuine pcap file containing a mixed scene: ordinary customers browsing a
website, plus three different attacks running at the same time. The packets are
real packets in the real file format, they are simply written by this script
instead of captured off a wire.

    python3 make_sample_attack.py samples/attack.pcap
    python3 traffic_analyzer.py samples/attack.pcap --html report.html

What it builds:
  * normal visitors, browsing over HTTPS at human speed
  * a SYN flood from a botnet spread across the world
  * a DNS reflection attack bounced off open resolvers
  * a smaller NTP reflection attack
  * one host quietly scanning many ports, which is a different problem again

DhWonder, Plaintext IT. MIT licence.
"""

import random
import socket
import struct
import sys

random.seed(20260812)          # fixed so the file is identical every time

VICTIM = "203.0.113.10"        # the business being attacked (a documentation range)
START = 1765000000             # a fixed start time, in seconds


def ip_bytes(addr):
    return socket.inet_aton(addr)


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def ipv4(src, dst, proto, payload, ttl=64):
    total_len = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s",
                         0x45, 0, total_len, random.randint(0, 65535), 0,
                         ttl, proto, 0, ip_bytes(src), ip_bytes(dst))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def tcp(sport, dport, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, random.randint(0, 2**32 - 1),
                       0, 0x50, flags, 8192, 0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp_echo(payload):
    return struct.pack("!BBHHH", 8, 0, 0, 1, 1) + payload


def ethernet(payload):
    return (b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb"
            + struct.pack("!H", 0x0800) + payload)


SNAPLEN = 54      # how much of each packet we keep


class PcapWriter(object):
    """Writes a classic pcap file.

    Like tcpdump, we only store the first part of every packet. The headers are
    all we need and they live at the front, so this keeps the file small while
    staying a completely valid capture. The real length is recorded separately,
    so nothing reading the file is misled about how big the packets were."""

    def __init__(self, path):
        self.fh = open(path, "wb")
        self.fh.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, SNAPLEN, 1))
        self.count = 0

    def write(self, ts, frame):
        sec = int(ts)
        usec = int((ts - sec) * 1000000)
        stored = frame[:SNAPLEN]
        self.fh.write(struct.pack("<IIII", sec, usec, len(stored), len(frame)))
        self.fh.write(stored)
        self.count += 1

    def close(self):
        self.fh.close()


def random_ip(prefixes):
    first = random.choice(prefixes)
    return "%d.%d.%d.%d" % (first, random.randint(0, 255),
                            random.randint(0, 255), random.randint(1, 254))


def build(path):
    out = PcapWriter(path)
    packets = []          # (timestamp, frame)

    # ---------------------------------------------------------------
    # 1. Ordinary customers. Modest packet counts, mixed sizes, and
    #    proper handshakes that actually complete.
    # ---------------------------------------------------------------
    visitors = [random_ip([2, 5, 31, 62, 77, 84, 90, 176, 185, 193, 212, 217]) for _ in range(14)]
    for ip in visitors:
        sport = random.randint(20000, 60000)
        t = START + random.uniform(0, 60)
        # handshake
        packets.append((t, ethernet(ipv4(ip, VICTIM, 6, tcp(sport, 443, 0x02)))))
        packets.append((t + 0.05, ethernet(ipv4(ip, VICTIM, 6, tcp(sport, 443, 0x10)))))
        # a handful of real requests with varied payload sizes
        for _ in range(random.randint(6, 22)):
            t += random.uniform(0.2, 3.0)
            size = random.randint(120, 1400)
            packets.append((t, ethernet(ipv4(ip, VICTIM, 6,
                            tcp(sport, 443, 0x18, b"\x00" * size)))))
        packets.append((t + 0.4, ethernet(ipv4(ip, VICTIM, 6, tcp(sport, 443, 0x11)))))

    # ---------------------------------------------------------------
    # 2. The SYN flood. Many addresses, each sending identical tiny
    #    packets, opening connections and never finishing one.
    # ---------------------------------------------------------------
    botnet = [random_ip([1, 14, 27, 36, 42, 58, 101, 110, 115, 118, 121, 175, 180, 202, 210, 220])
              for _ in range(90)]
    botnet += [random_ip([41, 102, 154, 196]) for _ in range(12)]
    botnet += [random_ip([177, 186, 190, 200]) for _ in range(10)]

    for ip in botnet:
        burst_start = START + random.uniform(18, 24)
        count = random.randint(60, 200)
        for i in range(count):
            t = burst_start + i * random.uniform(0.002, 0.02)
            if t > START + 60:
                break
            packets.append((t, ethernet(ipv4(ip, VICTIM, 6,
                            tcp(random.randint(1024, 65535), 443, 0x02), ttl=random.choice([48, 52, 116])))))

    # ---------------------------------------------------------------
    # 3. DNS reflection. Traffic arrives FROM port 53 on real servers
    #    that were tricked into answering a forged request, and the
    #    answers are large.
    # ---------------------------------------------------------------
    resolvers = [random_ip([8, 24, 64, 66, 72, 96, 104, 173, 199, 208]) for _ in range(22)]
    for ip in resolvers:
        start = START + random.uniform(20, 26)
        count = random.randint(40, 120)
        for i in range(count):
            t = start + i * random.uniform(0.004, 0.03)
            if t > START + 60:
                break
            packets.append((t, ethernet(ipv4(ip, VICTIM, 17,
                            udp(53, random.randint(1024, 65535), b"\x00" * 3000)))))

    # ---------------------------------------------------------------
    # 4. A smaller NTP reflection running alongside it.
    # ---------------------------------------------------------------
    ntp_hosts = [random_ip([80, 85, 91, 188, 195, 213]) for _ in range(8)]
    for ip in ntp_hosts:
        start = START + random.uniform(26, 32)
        for i in range(random.randint(30, 70)):
            t = start + i * random.uniform(0.01, 0.05)
            if t > START + 60:
                break
            packets.append((t, ethernet(ipv4(ip, VICTIM, 17,
                            udp(123, random.randint(1024, 65535), b"\x00" * 440)))))

    # ---------------------------------------------------------------
    # 5. One host quietly scanning ports. Not part of the flood, but
    #    worth telling the owner about.
    # ---------------------------------------------------------------
    scanner = "198.51.100.77"
    t = START + 5
    for port in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                 1433, 1723, 3306, 3389, 5432, 5900, 8080, 8443]:
        for _ in range(3):
            t += random.uniform(0.05, 0.4)
            packets.append((t, ethernet(ipv4(scanner, VICTIM, 6,
                            tcp(random.randint(30000, 60000), port, 0x02)))))

    # ---------------------------------------------------------------
    # 6. A short ping flood from a couple of hosts.
    # ---------------------------------------------------------------
    for ip in [random_ip([103, 119]) for _ in range(3)]:
        start = START + random.uniform(35, 40)
        for i in range(random.randint(80, 160)):
            t = start + i * random.uniform(0.005, 0.02)
            if t > START + 60:
                break
            packets.append((t, ethernet(ipv4(ip, VICTIM, 1, icmp_echo(b"\x00" * 1000)))))

    packets.sort(key=lambda p: p[0])
    for ts, frame in packets:
        out.write(ts, frame)
    out.close()

    print("Wrote %s" % path)
    print("  %d packets" % out.count)
    print("  %d ordinary visitors" % len(visitors))
    print("  %d flooding hosts, %d reflecting resolvers, %d NTP hosts"
          % (len(botnet), len(resolvers), len(ntp_hosts)))
    print()
    print("Now try:  python3 traffic_analyzer.py %s --html report.html" % path)


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "samples/attack.pcap")
