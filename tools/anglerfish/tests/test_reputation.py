"""
Prove the console reads an attacker address the way a honeypot should.

No network. Every lookup is replaced with a fake.

The distinction being tested is the whole reason this exists. A honeypot
session is already proof of somebody doing what they should not, so "is this
address bad" is not the useful question here: it walked into a decoy, of course
it is. The useful question is whether you were swept up in a scan of the whole
internet or picked out, and those two lead completely different places.

The case that matters most is the counter-intuitive one: an address **nobody**
has ever heard of should raise more attention than a known attacker, not less.
Mass scanners are known to the databases precisely because they scan everybody.
An address no database has seen, that found a machine which exists only as bait,
has not been scanning everybody.

    python3 tests/test_reputation.py
"""

import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from anglerfish import console as console_module
from anglerfish import reputation


def check(name, condition):
    print("  %-64s %s" % (name, "ok" if condition else "FAILED"))
    return 0 if condition else 1


def crossed(level, scanner="", ok=True, sources=None):
    return {"ok": ok, "level": level, "scanner": scanner,
            "sources": sources or [], "checked_at": time.time()}


def main():
    reputation.time.sleep = lambda seconds: None
    failures = 0

    # ---- swept up, or picked out -----------------------------------------
    head, body, attention = reputation.honeypot_verdict(crossed("benign", "Shodan"))
    failures += check("a known mass scanner is background noise", attention == 0)
    failures += check("it says you were not picked out", "not picked out" in head)
    failures += check("it names the scanner", "Shodan" in body)

    head, body, attention = reputation.honeypot_verdict(crossed("clean"))
    failures += check("an address nobody has seen is the one to read first",
                      attention == 2)
    failures += check("it explains why unknown is more interesting here",
                      "has not been scanning everybody" in body)

    head, body, attention = reputation.honeypot_verdict(crossed("known-bad"))
    failures += check("a known attacker raises attention", attention == 2)
    failures += check("but it does not overclaim that you were targeted",
                      "does not by itself mean you were targeted" in body)

    head, body, attention = reputation.honeypot_verdict(crossed("disputed", "Censys"))
    failures += check("a disputed address resolves towards sweeping", attention == 1)

    head, body, attention = reputation.honeypot_verdict(crossed("single-report"))
    failures += check("one report plus a honeypot hit is worth reading", attention == 2)

    head, body, attention = reputation.honeypot_verdict({"ok": False})
    failures += check("a failed lookup does not silence the session",
                      "still the finding" in body)

    # An unknown address must never be ranked below a known scanner. This is
    # the ordering the whole module exists to get right.
    _h, _b, unknown = reputation.honeypot_verdict(crossed("clean"))
    _h, _b, scanner = reputation.honeypot_verdict(crossed("benign", "Shodan"))
    failures += check("an unknown address outranks a known scanner", unknown > scanner)

    # ---- the console puts it on the attackers, and caches it --------------
    calls = []

    def fake_check(ip, keys=None, timeout=15, lookups=None):
        calls.append(ip)
        if ip == "45.9.0.1":
            return dict(crossed("benign", "Shodan"), ip=ip)
        return dict(crossed("clean"), ip=ip)

    original = reputation.check
    reputation.check = fake_check
    try:
        path = os.path.join(tempfile.mkdtemp(), "console.db")
        console = console_module.Console(path, reputation_keys={})
        console.register({"sensor": "nas", "hostname": "nas01", "tokens": []})
        now = time.time()
        for ip in ("45.9.0.1", "203.0.113.7"):
            console.report({"kind": "session", "sensor": "nas", "session": {
                "id": "s-" + ip, "peer_ip": ip, "protocol": "shell",
                "started": now - 10, "ended": now,
                "commands": [{"at": now, "line": "ls"}],
                "credentials": [], "read_files": [], "downloads": []}})

        overview = console.enrich_attackers(console.store.overview())
        by_ip = {a["peer_ip"]: a for a in overview["top_attackers"]}

        failures += check("every attacker carries a crossed answer",
                          all("reputation" in a for a in overview["top_attackers"]))
        failures += check("the scanner is marked as background noise",
                          by_ip["45.9.0.1"]["reputation"]["attention"] == 0)
        failures += check("the unknown address is marked as worth reading",
                          by_ip["203.0.113.7"]["reputation"]["attention"] == 2)

        before = len(calls)
        again = console_module.Console(path, reputation_keys={})
        again.enrich_attackers(again.store.overview())
        failures += check("a second look costs no new lookups", len(calls) == before)

        # Off by default: no keys and no flag means no address leaves at all.
        quiet_calls = len(calls)
        quiet = console_module.Console(path, reputation_keys=None)
        result = quiet.enrich_attackers(quiet.store.overview())
        failures += check("with reputation off, nothing is looked up",
                          len(calls) == quiet_calls)
        failures += check("with reputation off, no verdicts are attached",
                          all("reputation" not in a for a in result["top_attackers"]))
    finally:
        reputation.check = original

    print()
    if failures:
        print("%d checks failed." % failures)
        return 1
    print("All honeypot reputation checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
