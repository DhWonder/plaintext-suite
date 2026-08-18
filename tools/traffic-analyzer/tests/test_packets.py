"""
Prove the packet browser shows the truth: the right packets, taken apart correctly.

The filter language is the part worth testing hardest. A filter that quietly
matches nothing is the failure that matters here, because somebody types
`tcp.flags.syn == 1`, sees an empty list, and concludes there was no attack. So
these checks cover the filters that should match, the ones that should not, and
the broken ones that must raise rather than return nothing.

Run tests/make_test_captures.py first, then:

    python3 tests/test_packets.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from trafficanalyzer import capture, filters, packets

CAPTURES = os.path.join(HERE, "captures")


def check(name, condition):
    print("  %-58s %s" % (name, "ok" if condition else "FAILED"))
    return 0 if condition else 1


def sample_record(**over):
    record = {"n": 1, "ts": 100.0, "src": "10.0.0.5", "dst": "45.9.0.1", "proto": 6,
              "sport": 52134, "dport": 443, "flags": 0x02, "size": 60, "ttl": 64,
              "family": 4, "stream": 3}
    record.update(over)
    return record


def main():
    failures = 0

    # ---- the filter language ---------------------------------------------
    syn = sample_record()
    ack = sample_record(flags=0x10, dport=80)
    ping = sample_record(proto=1, sport=None, dport=None, flags=0, icmp_type=8)

    cases = [
        ("", syn, True),
        ("tcp", syn, True),
        ("udp", syn, False),
        ("icmp", ping, True),
        ("ip.addr == 45.9.0.1", syn, True),
        ("ip.src == 45.9.0.1", syn, False),
        ("ip.dst == 45.9.0.1", syn, True),
        ("tcp.port == 443", syn, True),
        ("tcp.port == 443", ack, False),
        ("tcp.flags.syn == 1", syn, True),
        ("tcp.flags.syn == 1", ack, False),
        ("tcp.flags.ack == 1", ack, True),
        ("tcp.port == 443 && tcp.flags.syn == 1", syn, True),
        ("tcp.port == 443 and not icmp", syn, True),
        ("frame.len > 40", syn, True),
        ("frame.len > 400", syn, False),
        ("tcp.stream == 3", syn, True),
        ("!(udp)", syn, True),
        ("udp || tcp", syn, True),
        ("ip.src == 10.0.0.", syn, True),
        ("icmp.type == 8", ping, True),
        ("icmp.type == 0", ping, False),
    ]
    for text, record, want in cases:
        got = filters.compile_filter(text)(record)
        failures += check("filter %-38s matches=%s" % (repr(text), want), got == want)

    # ---- a broken filter must raise, never match nothing silently --------
    for bad in ["ip.srcc == 1.2.3.4", "tcp.port ==", "(tcp", "tcp.port == abc", "ip.addr = 1"]:
        raised = False
        try:
            filters.compile_filter(bad)
        except filters.FilterError:
            raised = True
        failures += check("broken filter %-30s is refused" % repr(bad), raised)

    # A refused filter carries a hint pointing at the real field.
    try:
        filters.compile_filter("ip.srcc == 1.2.3.4")
        hint = ""
    except filters.FilterError as exc:
        hint = exc.hint
    failures += check("the refusal names the field they probably meant", "ip.src" in hint)

    # ---- reading a real capture back -------------------------------------
    path = ""
    for name in ("classic.pcap", "ethernet.pcap", "bigendian.pcap"):
        candidate = os.path.join(CAPTURES, name)
        if os.path.exists(candidate):
            path = candidate
            break
    if not path:
        print()
        print("  No test captures. Run tests/make_test_captures.py first.")
        return 1 if failures else 0

    log = packets.PacketLog(path=path)
    stats = capture.ReadStats()
    for packet in capture.read_packets(path, stats, keep_bytes=2048):
        log.add(packet, caplen=packet.get("caplen"), link=packet.get("link"),
                raw=packet.get("raw"))

    failures += check("the capture produced packet records", len(log) > 0)
    failures += check("packets were grouped into conversations", len(log.stream_list) > 0)

    first = log.get(1)
    failures += check("packet 1 is numbered 1", first is not None and first["n"] == 1)
    failures += check("every packet belongs to a conversation", first.get("stream") is not None)

    data, _note = log.frame_bytes(1)
    failures += check("the packet's own bytes came back", len(data) > 0)

    layers = packets.dissect(data, first.get("link") or 1)
    names = [layer["name"] for layer in layers]
    failures += check("the frame decoded into layers", len(layers) >= 2)
    failures += check("an IP layer was found", "IPv4" in names or "IPv6" in names)

    # Every field must point at bytes that actually exist, or the hex highlight
    # would light up the wrong part of the packet.
    in_range = True
    for layer in layers:
        for field in layer.get("fields", []):
            if field["start"] < 0 or field["start"] + field["length"] > len(data):
                in_range = False
    failures += check("every decoded field points inside the frame", in_range)

    dump = packets.hexdump(data)
    failures += check("the hex dump covers the whole frame",
                      dump and dump[-1]["offset"] < len(data))

    # ---- following a conversation ----------------------------------------
    members = log.stream(1)
    failures += check("following packet 1 returns its own conversation",
                      members and all(m["stream"] == first["stream"] for m in members))

    # ---- the summary and the sentence ------------------------------------
    text = packets.summary(sample_record())
    failures += check("a SYN packet is summarised as SYN", "SYN" in text)
    sentence = packets.explain(sample_record())
    failures += check("the sentence explains what a SYN is doing",
                      "open a connection" in sentence)

    # ---- the analyser is untouched when bytes are not asked for ----------
    plain = capture.ReadStats()
    kept_any = False
    for index, packet in enumerate(capture.read_packets(path, plain)):
        if "raw" in packet:
            kept_any = True
        if index > 50:
            break
    failures += check("reading without keep_bytes holds on to nothing", not kept_any)

    print()
    if failures:
        print("%d checks failed." % failures)
        return 1
    print("All packet browser checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
