"""
Prove the reputation lookups behave, without ever touching the network.

Every network call is replaced with a fake, so this runs offline and fast and is
deterministic. What it checks is the part that matters when real keys are in
play: that several databases are crossed rather than trusted one at a time, that
a disagreement between them is reported as the useful thing it is, that a second
run reads the cache instead of spending a lookup, and that a local address is
never sent anywhere.

The disagreement case is the one worth reading. An address that VirusTotal calls
malicious and GreyNoise calls a known scanner is internet noise, not an attack
aimed at you, and a tool that only asked VirusTotal would have got that wrong.

    python3 tests/test_reputation.py
"""

import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from trafficanalyzer import analyse, reputation, store


def public(ip):
    return not analyse.is_private(ip) and not analyse.is_loopback(ip)


def check(name, condition):
    print("  %-62s %s" % (name, "ok" if condition else "FAILED"))
    return 0 if condition else 1


# -- fake sources, in the shape the real ones return -------------------------
def src(source, ok=True, known=False, benign=False, why="", **extra):
    entry = {"source": source, "ok": ok, "known": known, "benign": benign, "why": why}
    entry.update(extra)
    return entry


def main():
    reputation.time.sleep = lambda seconds: None      # do not pace during tests
    failures = 0
    tmp = tempfile.mkdtemp()
    db = store.Store(os.path.join(tmp, "history.db"))

    # ---- crossing the sources --------------------------------------------
    # Two independent databases agreeing is the strongest case.
    agreed = reputation.combine([
        src("GreyNoise", known=True, why="classed malicious"),
        src("Spamhaus", known=True, why="listed"),
        src("VirusTotal", known=False, why="nothing"),
    ])
    failures += check("two databases agreeing reads as known bad",
                      agreed["level"] == "known-bad")
    failures += check("the agreeing databases are named",
                      set(agreed["bad_sources"]) == {"GreyNoise", "Spamhaus"})

    # One source alone is weaker, and must say so.
    alone = reputation.combine([
        src("VirusTotal", known=True, why="4 vendors"),
        src("Spamhaus", known=False, why="not listed"),
        src("GreyNoise", known=False, why="never seen"),
    ])
    failures += check("one database alone reads as a single report",
                      alone["level"] == "single-report")
    failures += check("the single report says it is weaker than agreement",
                      "weaker" in alone["verdict"][1])

    # The disagreement that matters: bad AND a known scanner.
    disputed = reputation.combine([
        src("VirusTotal", known=True, why="12 vendors"),
        src("GreyNoise", benign=True, name="Shodan", why="known scanner"),
    ])
    failures += check("bad plus known-scanner reads as disputed",
                      disputed["level"] == "disputed")
    failures += check("the disputed verdict explains it is internet wide noise",
                      "internet wide" in disputed["verdict"][1])
    failures += check("the disputed verdict names the scanner",
                      "Shodan" in disputed["verdict"][1])

    # A known harmless scanner, with nobody against it.
    benign = reputation.combine([
        src("GreyNoise", benign=True, name="Censys", why="known scanner"),
        src("Spamhaus", known=False, why="not listed"),
    ])
    failures += check("a known scanner alone reads as harmless",
                      benign["level"] == "benign")

    # Nothing known. Must not be reported as safe.
    clean = reputation.combine([
        src("GreyNoise", known=False, why="never seen"),
        src("Spamhaus", known=False, why="not listed"),
    ])
    failures += check("nothing known reads as not reported", clean["level"] == "clean")
    failures += check("not reported is explicitly not the same as safe",
                      "not the same as safe" in clean["verdict"][1])

    # Nobody answered at all.
    silent = reputation.combine([
        src("GreyNoise", ok=False, why="timed out"),
        src("Spamhaus", ok=False, why="timed out"),
    ])
    failures += check("no answers at all reads as could not check",
                      silent["level"] == "unknown")
    failures += check("a failed lookup says the traffic judgement still stands",
                      "still stands" in silent["verdict"][1])

    # ---- a source being down must not take the run with it ----------------
    partial = reputation.combine([
        src("GreyNoise", ok=False, why="down"),
        src("Spamhaus", known=True, why="listed"),
        src("VirusTotal", known=True, why="9 vendors"),
    ])
    failures += check("one source failing does not stop the others counting",
                      partial["level"] == "known-bad" and partial["answered"] == 2)

    # ---- the checker: one lookup, then the cache --------------------------
    calls = []

    def fake_check(ip):
        calls.append(ip)
        return dict(reputation.combine([
            src("GreyNoise", known=True, why="classed malicious"),
            src("Spamhaus", known=True, why="listed"),
        ]), ip=ip, ok=True, known=True, checked_at=time.time(),
            sources=[src("GreyNoise", known=True, why="classed malicious"),
                     src("Spamhaus", known=True, why="listed")])

    c1 = reputation.Checker(keys={"vt": "k"}, store=db, pause=0,
                            lookup=fake_check, is_public=public)
    res = c1.enrich(["45.9.0.1", "203.0.113.9", "10.0.0.5"])
    failures += check("a public flagged address is looked up",
                      res.get("45.9.0.1", {}).get("level") == "known-bad")
    failures += check("a private address is never sent", "10.0.0.5" not in res)
    failures += check("the local address was counted as skipped", c1.skipped_private == 1)
    failures += check("two public addresses meant two lookups", len(calls) == 2)

    before = len(calls)
    c2 = reputation.Checker(keys={"vt": "k"}, store=db, pause=0,
                            lookup=fake_check, is_public=public)
    res2 = c2.enrich(["45.9.0.1", "203.0.113.9"])
    failures += check("a second run makes no new network calls", len(calls) == before)
    failures += check("the second run's answers came from the cache", c2.from_cache == 2)
    failures += check("a cached answer is marked as cached",
                      res2["45.9.0.1"].get("from_cache") is True)
    failures += check("the cached answer kept every source",
                      len(res2["45.9.0.1"].get("sources", [])) == 2)

    # ---- the cache respects its age ---------------------------------------
    fresh = db.get_reputation("45.9.0.1", max_age=10 ** 9)
    failures += check("a fresh cached answer is returned",
                      fresh is not None and fresh["level"] == "known-bad")
    failures += check("an answer older than the limit is ignored",
                      db.get_reputation("45.9.0.1", max_age=-1) is None)

    # ---- which sources would be asked, given the keys ---------------------
    asked = dict(reputation._sources_asked({}))
    failures += check("GreyNoise is asked with no key at all",
                      "no key" in asked.get("GreyNoise", ""))
    failures += check("VirusTotal says it is skipped without a key",
                      "skipped" in asked.get("VirusTotal", ""))
    asked_with = dict(reputation._sources_asked({"vt": "x"}))
    failures += check("VirusTotal is asked once a key is given",
                      asked_with.get("VirusTotal") == "asked")

    # ---- coverage line is honest ------------------------------------------
    c3 = reputation.Checker(keys={}, store=db, pause=0, lookup=fake_check, is_public=public)
    c3.enrich(["198.51.100.7", "10.0.0.9"])
    failures += check("the coverage line mentions the skipped local address",
                      "local" in c3.coverage())

    # ---- a blocklist answer is read the right way round -------------------
    listed = reputation.blocklist(
        "1.2.3.4", "Spamhaus", "zen.spamhaus.org", "listed",
        timeout=0.001)
    failures += check("a blocklist that cannot be reached says so, not 'clean'",
                      listed["ok"] is False)

    db.close()
    print()
    if failures:
        print("%d checks failed." % failures)
        return 1
    print("All reputation checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
