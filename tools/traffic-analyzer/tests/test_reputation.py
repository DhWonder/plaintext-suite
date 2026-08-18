"""
Prove the VirusTotal address lookups behave, without ever touching the network.

Every network call is replaced with a fake, so this runs offline and fast and is
deterministic. What it actually checks is the part that matters when a real key
is in play: that the wording is right, that a second run reads the cache instead
of spending a lookup, that a spent key stops the run instead of hammering on, and
that a local address is never sent anywhere.

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
    print("  %-58s %s" % (name, "ok" if condition else "FAILED"))
    return 0 if condition else 1


def known_bad(ip):
    return {"source": "VirusTotal", "ok": True, "known": True, "malicious": 31,
            "suspicious": 0, "total": 70, "reputation": -55, "country": "NL",
            "asn": "202425", "as_owner": "IP Volume inc", "checked_at": time.time()}


def unseen(ip):
    return {"source": "VirusTotal", "ok": True, "known": False, "unseen": True,
            "checked_at": time.time()}


def main():
    # The pacing is real behaviour, but a test should not sit and wait for it.
    reputation.time.sleep = lambda seconds: None

    failures = 0
    tmp = tempfile.mkdtemp()
    db = store.Store(os.path.join(tmp, "history.db"))

    # ---- the verdict wording ----------------------------------------------
    head, body = reputation.verdict(known_bad("x"))
    failures += check("known-bad reads as known bad", head == "Known bad" and "malicious" in body)
    failures += check("known-bad names the country and AS", "NL" in body and "202425" in body)

    head, _ = reputation.verdict({"ok": True, "known": False, "unseen": True})
    failures += check("never-seen address reads as new, not safe", head == "New to VirusTotal")

    head, _ = reputation.verdict({"ok": True, "known": False, "suspicious": 3})
    failures += check("suspicious-only reads as suspicious", head == "Reported suspicious")

    head, _ = reputation.verdict({"ok": False, "quota": True, "error": "limit"})
    failures += check("a spent key reads as not checked", head == "Not checked")

    # ---- the checker: one lookup, then the cache --------------------------
    calls = []

    def counting_known_bad(ip):
        calls.append(ip)
        return known_bad(ip)

    c1 = reputation.Checker(key="k", store=db, pause=0, lookup=counting_known_bad, is_public=public)
    res = c1.enrich(["45.9.0.1", "203.0.113.9", "10.0.0.5"])
    failures += check("a public flagged address is looked up", res.get("45.9.0.1", {}).get("known") is True)
    failures += check("a private address is never sent", "10.0.0.5" not in res)
    failures += check("the local address was counted as skipped", c1.skipped_private == 1)
    failures += check("two public addresses meant two lookups", len(calls) == 2)

    before = len(calls)
    c2 = reputation.Checker(key="k", store=db, pause=0, lookup=counting_known_bad, is_public=public)
    res2 = c2.enrich(["45.9.0.1", "203.0.113.9"])
    failures += check("a second run makes no new network calls", len(calls) == before)
    failures += check("the second run's answers came from the cache", c2.from_cache == 2)
    failures += check("a cached answer is marked as cached", res2["45.9.0.1"].get("from_cache") is True)

    # ---- a spent key stops the run ----------------------------------------
    def quota(ip):
        calls.append(ip)
        return {"source": "VirusTotal", "ok": False, "known": False, "quota": True,
                "error": "the free key's limit was reached"}

    spent = len(calls)
    c3 = reputation.Checker(key="k", store=db, pause=0, lookup=quota, is_public=public)
    res3 = c3.enrich(["8.8.8.8", "1.1.1.1", "9.9.9.9"])
    failures += check("the first spent-key answer stops further calls", len(calls) - spent == 1)
    failures += check("every remaining address is marked not checked",
                      all(res3[ip].get("quota") for ip in res3))
    failures += check("the run remembers it hit the quota", c3.quota_hit is True)

    # ---- the cache respects its age ---------------------------------------
    fresh = db.get_reputation("45.9.0.1", max_age=10 ** 9)
    failures += check("a fresh cached answer is returned", fresh is not None and fresh["malicious"] == 31)
    stale = db.get_reputation("45.9.0.1", max_age=-1)
    failures += check("an answer older than the limit is ignored", stale is None)

    # ---- coverage line is honest ------------------------------------------
    c4 = reputation.Checker(key="k", store=db, pause=0, lookup=unseen, is_public=public)
    c4.enrich(["198.51.100.7", "10.0.0.9"])
    line = c4.coverage()
    failures += check("the coverage line mentions the skipped local address", "local" in line)

    db.close()
    print()
    if failures:
        print("%d checks failed." % failures)
        return 1
    print("All reputation checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
