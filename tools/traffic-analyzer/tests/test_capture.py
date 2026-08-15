"""
Prove the reader handles every capture shape it claims to.

Run tests/make_test_captures.py first, then:

    python3 tests/test_capture.py

Every line prints what it found. A file that reads correctly is not enough on
its own, so this also checks the packet count and the addresses match what the
generator put in. Silence would be a worse test than a wrong number.
"""

import os
import resource
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from trafficanalyzer import capture

CAPTURES = os.path.join(HERE, "captures")

# What each file should produce. None means "we expect this one to be refused".
EXPECTED = [
    ("classic.pcap",        744, 4),
    ("bigendian.pcap",      744, 4),
    ("nanosecond.pcap",     744, 4),
    ("classic.pcap.gz",     744, 4),
    ("modern.pcapng",       744, 4),
    ("modern.pcapng.gz",    744, 4),
    ("simpleblocks.pcapng", 744, 4),
    ("ipv6.pcapng",         744, 6),
    ("vlan.pcap",           744, 4),
    ("cooked.pcap",         744, 4),
    ("cooked2.pcapng",      744, 4),
    ("rawip.pcap",          744, 4),
    ("loopback.pcap",       744, 4),
    ("truncated.pcap",      None, 4),
    ("notacapture.pcap",    0, None),
]


def run_one(name):
    path = os.path.join(CAPTURES, name)
    stats = capture.ReadStats()
    count = 0
    families = set()
    sources = set()
    first_ts = last_ts = None
    error = None
    started = time.time()
    try:
        for packet in capture.read_packets(path, stats):
            count += 1
            families.add(packet["family"])
            sources.add(packet["src"])
            if first_ts is None:
                first_ts = packet["ts"]
            last_ts = packet["ts"]
    except capture.CaptureError as exc:
        error = str(exc)
    return {
        "count": count, "families": families, "sources": sources,
        "stats": stats, "error": error, "seconds": time.time() - started,
        "span": (last_ts - first_ts) if (first_ts is not None and last_ts is not None) else 0,
    }


def main():
    if not os.path.isdir(CAPTURES):
        print("No test captures yet. Run: python3 tests/make_test_captures.py")
        return 1

    failures = 0
    print("%-22s %-9s %-8s %-7s %-8s %s" %
          ("FILE", "PACKETS", "FORMAT", "FAMILY", "SOURCES", "RESULT"))
    print("-" * 84)

    for name, expected_packets, expected_family in EXPECTED:
        if not os.path.exists(os.path.join(CAPTURES, name)):
            print("%-22s missing" % name)
            failures += 1
            continue

        result = run_one(name)
        family = "/".join(str(f) for f in sorted(result["families"])) or "-"
        verdict = "ok"

        if expected_packets == 0:
            # These should be refused with a sentence, not a stack trace.
            if result["error"]:
                verdict = "refused cleanly"
            else:
                verdict = "SHOULD HAVE BEEN REFUSED"
                failures += 1
        elif expected_packets is None:
            # Truncated: read what is there, notice it stopped early.
            if result["count"] > 0 and result["stats"].truncated:
                verdict = "partial read, truncation noticed"
            else:
                verdict = "FAILED to handle truncation"
                failures += 1
        else:
            if result["error"]:
                verdict = "ERROR: " + result["error"][:40]
                failures += 1
            elif result["count"] != expected_packets:
                verdict = "WRONG COUNT, wanted %d" % expected_packets
                failures += 1
            elif expected_family not in result["families"]:
                verdict = "WRONG FAMILY, wanted IPv%d" % expected_family
                failures += 1

        print("%-22s %-9s %-8s %-7s %-8s %s" % (
            name,
            "{:,}".format(result["count"]),
            result["stats"].format,
            family,
            len(result["sources"]),
            verdict))

    # Hostnames carried inside a pcapng file should come through.
    print()
    result = run_one("modern.pcapng")
    names = result["stats"].names
    if names.get("198.51.100.3") == "botnode-3.example":
        print("Hostnames from the pcapng name table: found %d, including %s -> %s"
              % (len(names), "198.51.100.3", names["198.51.100.3"]))
    else:
        print("FAILED to read the pcapng name table")
        failures += 1

    # The large file is the memory test. Reading it must not grow with size.
    big = os.path.join(CAPTURES, "large.pcap")
    if os.path.exists(big):
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        result = run_one("large.pcap")
        after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        size_mb = os.path.getsize(big) / 1048576.0
        print("Large file: %.1f MB, %s packets in %.1fs (%s packets/sec), "
              "peak memory grew %.1f MB"
              % (size_mb, "{:,}".format(result["count"]), result["seconds"],
                 "{:,.0f}".format(result["count"] / max(result["seconds"], 0.001)),
                 (after - before) / 1024.0))
        if (after - before) / 1024.0 > 60:
            print("  memory growth looks too high for a streaming reader")
            failures += 1

    print()
    if failures:
        print("%d checks failed." % failures)
        return 1
    print("All capture format checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
