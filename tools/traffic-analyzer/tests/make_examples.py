"""
Build the example captures that ship inside the browser tool.

These exist so somebody can see what each kind of attack actually looks like
without having to be attacked first. They are synthetic, and the page says so,
but synthetic does not have to mean fake looking. Traffic generated in a naive
loop has a tell: every packet the same size, arriving at exactly even
intervals, from addresses that count upwards. Real traffic does none of that.

So this generator does the boring work properly:

  - gaps between packets are drawn from an exponential distribution, which is
    what arrival times actually look like, rather than a fixed step
  - every host gets a starting TTL of 64, 128 or 255 and a hop count, so the
    TTL you see is the sort of number a real trace has
  - source ports come from the right ephemeral range for the operating system
  - packet sizes follow the shape real traffic has: a lot of small
    acknowledgements, a lot of full sized data packets, few in between
  - addresses are drawn from ranges that are really allocated to the regions
    they claim to be from
  - every capture has ordinary background traffic running underneath the
    attack, because a capture containing nothing but an attack is a capture
    nobody has ever taken

    python3 tests/make_examples.py            writes into tests/examples/
"""

import gzip
import os
import random
import socket
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "examples")
sys.path.insert(0, HERE)

from make_test_captures import ipv4_header, tcp_segment, udp_segment, ethernet, write_pcap

# Address ranges that really are allocated where they say. Using them means the
# region column in the report says something true rather than something made up.
REGIONS = {
    "ARIN (North America)":       [(3, 8), (23, 24), (50, 52), (63, 76), (98, 100), (172, 173)],
    "RIPE (Europe, Middle East)": [(31, 31), (46, 46), (77, 95), (176, 178), (185, 185), (212, 213)],
    "APNIC (Asia Pacific)":       [(1, 1), (14, 14), (27, 27), (36, 43), (58, 61), (110, 126),
                                   (202, 203), (218, 223)],
    "LACNIC (Latin America)":     [(177, 177), (179, 181), (186, 191), (200, 201)],
    "AFRINIC (Africa)":           [(41, 41), (102, 102), (105, 105), (154, 154), (196, 197)],
}

# What a machine's TTL starts at, and roughly how far away it is.
STACKS = [(64, "linux", 0.55), (128, "windows", 0.35), (255, "gear", 0.10)]

SYN, ACK, PSH, FIN, RST = 0x02, 0x10, 0x08, 0x01, 0x04


class Wire(object):
    """Collects packets and keeps the clock moving the way a real one does."""

    def __init__(self, seed, start=1723200000.0):
        self.rng = random.Random(seed)
        self.packets = []
        self.now = start

    # -- timing --------------------------------------------------------
    def wait(self, mean_gap):
        """Advance the clock by a random gap averaging `mean_gap` seconds.

        Exponential, because arrivals cluster. A fixed step is the single
        most obvious sign that a capture was generated rather than recorded.
        """
        self.now += self.rng.expovariate(1.0 / max(mean_gap, 1e-9))

    # -- hosts ---------------------------------------------------------
    def address(self, region=None):
        region = region or self.rng.choice(list(REGIONS))
        low, high = self.rng.choice(REGIONS[region])
        return "%d.%d.%d.%d" % (self.rng.randint(low, high), self.rng.randint(0, 255),
                                self.rng.randint(0, 255), self.rng.randint(1, 254))

    def stack(self):
        roll = self.rng.random()
        running = 0.0
        for initial, name, weight in STACKS:
            running += weight
            if roll <= running:
                hops = self.rng.randint(4, 22)
                return initial - hops, name
        return 64 - self.rng.randint(4, 22), "linux"

    def ephemeral(self, kind="linux"):
        if kind == "windows":
            return self.rng.randint(49152, 65535)
        return self.rng.randint(32768, 60999)

    # -- packets -------------------------------------------------------
    def tcp(self, src, dst, sport, dport, flags, ttl, payload=0):
        segment = tcp_segment(sport, dport, flags, b"\x00" * payload)
        self.packets.append((self.now, ethernet(
            ipv4_header(src, dst, 6, len(segment), ttl=ttl,
                        ident=self.rng.randint(0, 65535)) + segment)))

    def udp(self, src, dst, sport, dport, ttl, payload=0):
        segment = udp_segment(sport, dport, b"\x00" * payload)
        self.packets.append((self.now, ethernet(
            ipv4_header(src, dst, 17, len(segment), ttl=ttl,
                        ident=self.rng.randint(0, 65535)) + segment)))

    def icmp(self, src, dst, ttl, payload=56):
        body = struct.pack("!BBHHH", 8, 0, 0, self.rng.randint(0, 65535), 1) + b"\x00" * payload
        self.packets.append((self.now, ethernet(
            ipv4_header(src, dst, 1, len(body), ttl=ttl) + body)))

    def write(self, name):
        self.packets.sort(key=lambda item: item[0])
        path = os.path.join(OUT, name)
        write_pcap(path, self.packets)
        with open(path, "rb") as fh:
            raw = fh.read()
        with gzip.open(path + ".gz", "wb", compresslevel=9) as fh:
            fh.write(raw)
        os.remove(path)
        return path + ".gz", len(self.packets)


# ---------------------------------------------------------------------------
# Ordinary traffic. Every example gets some, because no real capture is pure.
# ---------------------------------------------------------------------------
def background(wire, server, seconds, visitors=14, resolver="9.9.9.9"):
    """Real visitors browsing, DNS lookups, and a bit of housekeeping."""
    for _ in range(visitors):
        ttl, kind = wire.stack()
        client = wire.address()
        port = wire.ephemeral(kind)
        wire.now += wire.rng.uniform(0, seconds * 0.8)

        # A name lookup first, the way a browser really starts.
        wire.udp(client, resolver, wire.ephemeral(kind), 53, ttl, wire.rng.randint(28, 44))
        wire.wait(0.02)
        wire.udp(resolver, client, 53, port, 58, wire.rng.randint(60, 180))

        # Then the handshake, then a page: a few requests, many data packets
        # coming back, an acknowledgement for roughly every other one.
        wire.wait(0.03)
        wire.tcp(client, server, port, 443, SYN, ttl)
        wire.wait(0.04)
        wire.tcp(server, client, 443, port, SYN | ACK, 62)
        wire.wait(0.001)
        wire.tcp(client, server, port, 443, ACK, ttl)

        for _ in range(wire.rng.randint(3, 11)):
            wire.wait(wire.rng.uniform(0.05, 0.4))
            wire.tcp(client, server, port, 443, PSH | ACK, ttl, wire.rng.randint(120, 700))
            for chunk in range(wire.rng.randint(2, 14)):
                wire.wait(wire.rng.uniform(0.0004, 0.004))
                size = 1400 if wire.rng.random() < 0.8 else wire.rng.randint(80, 1300)
                wire.tcp(server, client, 443, port, PSH | ACK, 62, size)
                if chunk % 2:
                    wire.tcp(client, server, port, 443, ACK, ttl)

        wire.wait(wire.rng.uniform(0.2, 1.5))
        wire.tcp(client, server, port, 443, FIN | ACK, ttl)
        wire.wait(0.03)
        wire.tcp(server, client, 443, port, FIN | ACK, 62)


# ---------------------------------------------------------------------------
# The examples themselves.
# ---------------------------------------------------------------------------
def syn_flood():
    """A botnet opening connections it never finishes, against a web server."""
    wire = Wire(seed=101)
    server = "203.0.113.20"
    background(wire, server, seconds=30, visitors=6)

    # The botnet. Machines vary: some push hard, most are modest home routers
    # and cameras, and they do not all start or stop together.
    bots = []
    for _ in range(70):
        ttl, kind = wire.stack()
        bots.append({
            "ip": wire.address(wire.rng.choice(
                ["APNIC (Asia Pacific)", "APNIC (Asia Pacific)", "LACNIC (Latin America)",
                 "RIPE (Europe, Middle East)", "AFRINIC (Africa)", "ARIN (North America)"])),
            "ttl": ttl, "kind": kind,
            "rate": wire.rng.uniform(4, 30),
            "joins": 4 + wire.rng.expovariate(1 / 2.5),
            "leaves": 0,
        })
    for bot in bots:
        bot["leaves"] = bot["joins"] + wire.rng.uniform(12, 22)

    start = wire.now = 1723200000.0
    clock = start
    end = start + 30
    while clock < end:
        clock += wire.rng.expovariate(1 / 0.0035)
        live = [b for b in bots if start + b["joins"] <= clock <= start + b["leaves"]]
        if not live:
            continue
        bot = wire.rng.choice(live)
        wire.now = clock
        wire.tcp(bot["ip"], server, wire.ephemeral(bot["kind"]), 443, SYN, bot["ttl"])
        # The server answers, and nobody ever completes it.
        if wire.rng.random() < 0.9:
            wire.now = clock + wire.rng.uniform(0.0002, 0.002)
            wire.tcp(server, bot["ip"], 443, wire.ephemeral(), SYN | ACK, 64)
    return wire, "syn-flood.pcap"


def dns_amplification():
    """Someone forged our address to open resolvers, and the answers come to us."""
    wire = Wire(seed=202)
    victim = "203.0.113.20"
    background(wire, victim, seconds=26, visitors=5)

    resolvers = []
    for _ in range(34):
        ttl, _kind = wire.stack()
        resolvers.append({"ip": wire.address(), "ttl": ttl})

    start = wire.now = 1723200000.0
    clock = start
    while clock < start + 26:
        clock += wire.rng.expovariate(1 / 0.0045)
        # The attack builds, holds, then stops when upstream filtering lands.
        into = clock - start
        if into < 4 or into > 22:
            continue
        wire.now = clock
        resolver = wire.rng.choice(resolvers)
        # An ANY answer is big. That is the whole point of the technique.
        size = wire.rng.choice([1400, 1400, 1400, 2300, 3100, 980])
        wire.udp(resolver["ip"], victim, 53, wire.rng.randint(1024, 65535),
                 resolver["ttl"], size)
    return wire, "dns-amplification.pcap"


def port_scan():
    """One host walking the ports, quietly, the way a real scan does."""
    wire = Wire(seed=303)
    target = "203.0.113.20"
    background(wire, target, seconds=120, visitors=6)

    scanner = wire.address("RIPE (Europe, Middle East)")
    ttl, kind = wire.stack()
    wire.now = 1723200000.0 + 30

    # Common ports first, then a spread. A scanner does not walk 1 to 1000 in
    # order, it works from a list, and it pauses so as not to be obvious.
    common = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
              1433, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017]
    ports = common + [wire.rng.randint(1, 65535) for _ in range(150)]
    wire.rng.shuffle(ports)

    for port in ports:
        wire.wait(wire.rng.uniform(0.02, 0.35))
        wire.tcp(scanner, target, wire.ephemeral(kind), port, SYN, ttl)
        # Closed ports answer with a reset. Two open ones answer properly.
        if port in (443, 22):
            wire.wait(0.001)
            wire.tcp(target, scanner, port, wire.ephemeral(kind), SYN | ACK, 64)
        else:
            wire.wait(0.0008)
            wire.tcp(target, scanner, port, wire.ephemeral(kind), RST | ACK, 64)
    return wire, "port-scan.pcap"


def brute_force():
    """Password guessing against SSH, slow enough to hope nobody notices."""
    wire = Wire(seed=404)
    server = "203.0.113.20"
    background(wire, server, seconds=200, visitors=5)

    attackers = []
    for _ in range(4):
        ttl, kind = wire.stack()
        attackers.append({"ip": wire.address(), "ttl": ttl, "kind": kind})

    wire.now = 1723200000.0 + 10
    for _ in range(150):
        attacker = wire.rng.choice(attackers)
        wire.wait(wire.rng.uniform(0.3, 1.8))
        port = wire.ephemeral(attacker["kind"])
        wire.tcp(attacker["ip"], server, port, 22, SYN, attacker["ttl"])
        wire.wait(0.03)
        wire.tcp(server, attacker["ip"], 22, port, SYN | ACK, 64)
        wire.wait(0.001)
        wire.tcp(attacker["ip"], server, port, 22, ACK, attacker["ttl"])
        # The banner, then a couple of attempts, then the server hangs up.
        wire.wait(0.02)
        wire.tcp(server, attacker["ip"], 22, port, PSH | ACK, 64, 41)
        for _ in range(wire.rng.randint(1, 3)):
            wire.wait(wire.rng.uniform(0.05, 0.3))
            wire.tcp(attacker["ip"], server, port, 22, PSH | ACK,
                     attacker["ttl"], wire.rng.randint(80, 320))
            wire.wait(wire.rng.uniform(0.4, 1.2))
            wire.tcp(server, attacker["ip"], 22, port, PSH | ACK, 64, wire.rng.randint(40, 90))
        wire.wait(0.05)
        wire.tcp(server, attacker["ip"], 22, port, FIN | ACK, 64)
    return wire, "brute-force.pcap"


def dns_tunnel():
    """Data leaving the building disguised as name lookups."""
    wire = Wire(seed=505)
    server = "203.0.113.20"
    inside = "203.0.113.44"
    background(wire, server, seconds=150, visitors=5)

    resolver = "9.9.9.9"
    ttl, kind = wire.stack()
    wire.now = 1723200000.0 + 20

    # The tell is the shape: constant lookups to one domain, questions far
    # longer than a real hostname, answers that carry payload back.
    for _ in range(420):
        wire.wait(wire.rng.uniform(0.05, 0.55))
        port = wire.ephemeral(kind)
        wire.udp(inside, resolver, port, 53, ttl, wire.rng.randint(180, 240))
        wire.wait(wire.rng.uniform(0.01, 0.06))
        wire.udp(resolver, inside, 53, port, 58, wire.rng.randint(200, 420))
    return wire, "dns-tunnel.pcap"


def ddos():
    """The real thing: many machines, several methods, all landing at once.

    The SYN-flood example is one botnet doing one thing. A distributed denial of
    service in the wild is rarely that tidy. This is what an operator actually
    sees: a large botnet opening connections it never finishes, a plain UDP flood
    filling the line from other hosts, DNS answers reflected off open resolvers,
    and a handful of machines adding a ping flood on top. No single rule blocks
    it, which is the whole point, and it is spread across every region so a
    country block does not catch it either.
    """
    wire = Wire(seed=707)
    victim = "203.0.113.20"
    background(wire, victim, seconds=40, visitors=8)

    every_region = list(REGIONS)
    start = 1723200000.0
    end = start + 40

    # 1. The SYN flood: a botnet, joining and leaving unevenly, each host modest
    #    on its own but overwhelming together. This is the bulk of the traffic.
    bots = []
    for _ in range(80):
        ttl, kind = wire.stack()
        bots.append({"ip": wire.address(wire.rng.choice(every_region)),
                     "ttl": ttl, "kind": kind,
                     "joins": wire.rng.uniform(2, 14),
                     "leaves": 0})
    for bot in bots:
        bot["leaves"] = bot["joins"] + wire.rng.uniform(18, 32)

    wire.now = start
    clock = start
    while clock < end:
        clock += wire.rng.expovariate(1 / 0.004)
        alive = [b for b in bots if start + b["joins"] <= clock <= start + b["leaves"]]
        if not alive:
            continue
        bot = wire.rng.choice(alive)
        wire.now = clock
        wire.tcp(bot["ip"], victim, wire.ephemeral(bot["kind"]), 443, SYN, bot["ttl"])
        if wire.rng.random() < 0.9:                       # the server answers, nobody completes
            wire.now = clock + wire.rng.uniform(0.0002, 0.002)
            wire.tcp(victim, bot["ip"], 443, wire.ephemeral(), SYN | ACK, 64)

    # 2. A plain UDP flood, aimed at saturating the line rather than any one
    #    service, so each host lands hard across a spread of random ports.
    for _ in range(22):
        ttl, _kind = wire.stack()
        host = wire.address(wire.rng.choice(every_region))
        wire.now = start + wire.rng.uniform(6, 16)
        for _ in range(wire.rng.randint(140, 240)):
            wire.wait(wire.rng.uniform(0.004, 0.02))
            if wire.now > end:
                break
            wire.udp(host, victim, wire.rng.randint(1024, 65535),
                     wire.rng.randint(1, 65535), ttl, wire.rng.choice([64, 512, 1400, 1400]))

    # 3. DNS reflection layered on top: big answers from real resolvers.
    resolvers = []
    for _ in range(18):
        ttl, _kind = wire.stack()
        resolvers.append({"ip": wire.address(), "ttl": ttl})
    clock = start + 10
    while clock < end - 4:
        clock += wire.rng.expovariate(1 / 0.008)
        resolver = wire.rng.choice(resolvers)
        wire.now = clock
        wire.udp(resolver["ip"], victim, 53, wire.rng.randint(1024, 65535),
                 resolver["ttl"], wire.rng.choice([1400, 1400, 2300, 3100]))

    # 4. A ping flood from a few more hosts, because a real DDoS throws
    #    everything it has. Each host bursts hard enough to stand out on its own.
    for _ in range(10):
        ttl, _kind = wire.stack()
        host = wire.address(wire.rng.choice(every_region))
        wire.now = start + wire.rng.uniform(8, 20)
        for _ in range(wire.rng.randint(90, 150)):
            wire.wait(wire.rng.uniform(0.004, 0.016))
            if wire.now > end:
                break
            wire.icmp(host, victim, ttl, payload=wire.rng.choice([56, 1000, 1400]))

    return wire, "ddos.pcap"


def quiet_day():
    """What normal looks like. The most useful capture anybody never takes."""
    wire = Wire(seed=606)
    server = "203.0.113.20"
    background(wire, server, seconds=240, visitors=18)

    # Housekeeping: time sync, a mail poll, the odd ping.
    wire.now = 1723200000.0
    for _ in range(14):
        wire.wait(wire.rng.uniform(4, 20))
        client = wire.address()
        ttl, kind = wire.stack()
        wire.udp(client, "216.239.35.0", wire.ephemeral(kind), 123, ttl, 48)
        wire.wait(0.04)
        wire.udp("216.239.35.0", client, 123, wire.ephemeral(kind), 55, 48)
    for _ in range(9):
        wire.wait(wire.rng.uniform(6, 25))
        wire.icmp(wire.address(), server, wire.stack()[0])
    return wire, "quiet-day.pcap"


BUILDERS = [
    (ddos, "Distributed denial of service",
     "The real thing: a botnet SYN flood, a UDP flood, reflected DNS answers and a ping flood, all landing at once from every region."),
    (syn_flood, "SYN flood",
     "A botnet opening thousands of connections it never finishes, so the server runs out of room for real customers."),
    (dns_amplification, "DNS amplification",
     "Someone forged this server's address to open DNS resolvers worldwide. The big answers all arrive here at once."),
    (port_scan, "Port scan",
     "One machine knocking on every port in turn, looking for something left open. Reconnaissance, not a flood."),
    (brute_force, "SSH brute force",
     "Slow, patient password guessing against remote access, spread over a few addresses to stay under the radar."),
    (dns_tunnel, "DNS tunnelling",
     "Data leaving the network disguised as name lookups. Quiet, low volume, and easy to miss."),
    (quiet_day, "A quiet day",
     "No attack at all. This is what ordinary traffic looks like, which is the thing worth recognising first."),
]


def main():
    if not os.path.isdir(OUT):
        os.makedirs(OUT)

    print("%-26s %-9s %-11s %s" % ("FILE", "PACKETS", "GZIPPED", "WHAT IT SHOWS"))
    print("-" * 96)
    for builder, title, _blurb in BUILDERS:
        wire, name = builder()
        path, count = wire.write(name)
        print("%-26s %-9s %-11s %s" % (os.path.basename(path), "{:,}".format(count),
                                       "{:,} B".format(os.path.getsize(path)), title))


if __name__ == "__main__":
    main()
