"""
Prove the browser version and the command line version agree.

traffic-analyzer says on the website that the page in your browser and the Python
program produce the same answer. That is a claim worth being able to back up,
so this runs both over the same set of capture files and compares the numbers
that matter.

    python3 tests/make_test_captures.py       build the files
    python3 tests/test_parity.py              compare both engines

Needs node and playwright for the browser half. If they are not installed it
says so and checks the Python half on its own rather than pretending to pass.
"""

import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from trafficanalyzer import analyse, capture

CAPTURES = os.path.join(HERE, "captures")
PAGE = os.path.abspath(os.path.join(ROOT, "..", "..", "website", "traffic-analyzer.html"))

FILES = ["classic.pcap", "bigendian.pcap", "nanosecond.pcap", "classic.pcap.gz",
         "modern.pcapng", "modern.pcapng.gz", "simpleblocks.pcapng", "ipv6.pcapng",
         "vlan.pcap", "cooked.pcap", "cooked2.pcapng", "rawip.pcap", "loopback.pcap",
         "large.pcap"]


def python_numbers(path):
    analyzer = analyse.Analyzer()
    stats = capture.ReadStats()
    for packet in capture.read_packets(path, stats):
        analyzer.ingest(packet["ts"], packet)
    analyzer.names = stats.names
    rows = analyzer.rows()
    summary = analyzer.summarise(rows=rows)
    return {
        "packets": summary["total_packets"],
        "sources": summary["sources_total"],
        "hostile": summary["hostile_sources"],
        "peak": summary["peak_per_second"],
        "vectors": len(summary["vectors"]),
        "verdict": summary["verdict"][0],
        "counts": summary["counts"],
        "vectorList": summary["vectors"],
        "framesUsed": stats.used,
        "format": stats.format,
    }


def browser_numbers(paths):
    if not shutil.which("node"):
        return None, "node is not installed"
    if not os.path.exists(PAGE):
        return None, "cannot find the page at %s" % PAGE
    script = os.path.join(HERE, "browser_numbers.js")
    try:
        result = subprocess.run(
            ["node", script, PAGE] + paths,
            capture_output=True, text=True, timeout=900, cwd=ROOT)
    except subprocess.TimeoutExpired:
        return None, "the browser run timed out"
    if result.returncode != 0:
        return None, (result.stderr or "").strip().splitlines()[-1:] or "node failed"
    try:
        return json.loads(result.stdout), None
    except ValueError:
        return None, "could not read what the browser printed"


def main():
    if not os.path.isdir(CAPTURES):
        print("No test captures yet. Run: python3 tests/make_test_captures.py")
        return 1

    present = [f for f in FILES if os.path.exists(os.path.join(CAPTURES, f))]
    if not present:
        print("No capture files found in %s" % CAPTURES)
        return 1

    print("Reading %d captures with the Python engine..." % len(present))
    python_side = {}
    for name in present:
        python_side[name] = python_numbers(os.path.join(CAPTURES, name))

    print("Reading the same captures in a real browser...")
    browser_side, problem = browser_numbers([os.path.join(CAPTURES, f) for f in present])

    if browser_side is None:
        print("Skipped the browser half: %s" % problem)
        print()
        print("%-22s %-10s %-9s %-8s %s" % ("FILE", "PACKETS", "SOURCES", "HOSTILE", "VERDICT"))
        print("-" * 78)
        for name in present:
            p = python_side[name]
            print("%-22s %-10s %-9s %-8s %s" % (name, "{:,}".format(p["packets"]),
                                                p["sources"], p["hostile"], p["verdict"][:28]))
        print()
        print("Python side read every file. Install node and playwright to compare the browser.")
        return 0

    if browser_side.get("_pageErrors"):
        print("The page threw errors:")
        for message in browser_side["_pageErrors"]:
            print("  " + message)

    fields = ["packets", "sources", "hostile", "peak", "vectors", "verdict", "framesUsed"]
    failures = 0

    print()
    print("%-22s %-10s %-9s %-8s %-7s %s" %
          ("FILE", "PACKETS", "SOURCES", "HOSTILE", "PEAK", "AGREE"))
    print("-" * 76)

    for name in present:
        p = python_side[name]
        b = browser_side.get(name)
        if b is None:
            print("%-22s %-10s the browser never reported on this file" % (name, ""))
            failures += 1
            continue
        if b.get("error"):
            print("%-22s browser refused it: %s" % (name, b["error"][:40]))
            failures += 1
            continue

        differences = [f for f in fields if p.get(f) != b.get(f)]
        if p.get("counts") != b.get("counts"):
            differences.append("counts")
        if sorted(p.get("vectorList") or []) != sorted(b.get("vectorList") or []):
            differences.append("vectorList")

        verdict = "yes" if not differences else "NO: " + ", ".join(differences)
        if differences:
            failures += 1
        print("%-22s %-10s %-9s %-8s %-7s %s" %
              (name, "{:,}".format(p["packets"]), p["sources"], p["hostile"],
               p["peak"], verdict))
        for field in differences:
            print("%24s%-14s python=%s browser=%s" % ("", field, p.get(field), b.get(field)))

    print()
    if failures:
        print("%d of %d captures disagreed." % (failures, len(present)))
        return 1
    print("Both engines agree on all %d captures, every field." % len(present))
    return 0


if __name__ == "__main__":
    sys.exit(main())
