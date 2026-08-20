"""
Prove the link checks cross their sources, and that a bad link changes the answer.

No network. Every lookup is replaced with a fake, so this is fast and
deterministic and can run anywhere.

The case worth reading is the last one: two identical messages, differing only in
where the link goes, must come out with opposite verdicts. That is the whole
point of looking the domain up. A message that reads perfectly normally and
carries a link to a domain registered on Tuesday is exactly the message people
click, and nothing in the wording checks would ever have caught it.

    python3 tests/test_links.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from emailchecker import analyze, links, read


def check(name, condition):
    print("  %-62s %s" % (name, "ok" if condition else "FAILED"))
    return 0 if condition else 1


# -- fakes, in the shape the real lookups return -----------------------------
BAD = "secure-billing-verify.com"


def fake_blocklist(domain, name, zone, test_name, refusals, meaning, timeout=12):
    if domain == BAD:
        return {"source": name, "ok": True, "known": True, "why": meaning + "."}
    return {"source": name, "ok": True, "known": False, "why": "%s does not list it." % name}


def fake_age(domain, timeout=12):
    if domain == BAD:
        return {"source": "How old it is", "ok": True, "known": True, "days": 4,
                "registered": "2026-08-14", "why": "Registered 4 days ago."}
    return {"source": "How old it is", "ok": True, "known": False, "benign": True,
            "days": 7000, "why": "Has existed for 19 years."}


def fake_age_only_new(domain, timeout=12):
    """A brand new domain no list has caught up with yet."""
    return {"source": "How old it is", "ok": True, "known": True, "days": 3,
            "registered": "2026-08-15", "why": "Registered 3 days ago."}


def fake_clean_blocklist(domain, name, zone, test_name, refusals, meaning, timeout=12):
    return {"source": name, "ok": True, "known": False, "why": "%s does not list it." % name}


def fake_vt_skipped(domain, key="", timeout=12):
    return {"source": "VirusTotal", "ok": False, "known": False, "skipped": True,
            "why": "VirusTotal was skipped: no key was given."}


def fake_dead(domain, *args, **kwargs):
    return {"source": "dead", "ok": False, "known": False, "why": "did not answer."}


MOCKS = {"blocklist": fake_blocklist, "age": fake_age, "virustotal": fake_vt_skipped}


def main():
    failures = 0

    # ---- which domains are worth asking about ----------------------------
    picked = links.domains_in([
        ("https://www.google.com/x", "google"),          # skipped, big provider
        ("http://secure-billing-verify.com/login", "PayPal"),
        ("http://192.168.1.1/x", "an address"),          # skipped, bare address
        ("mailto:someone@example.com", "mail"),          # skipped, not a link out
        ("https://secure-billing-verify.com/again", ""),  # same domain, once only
    ])
    failures += check("a well known provider is not looked up", "google.com" not in picked)
    failures += check("a bare numeric address is not looked up",
                      not any(p.startswith("192.168") for p in picked))
    failures += check("the suspicious domain is picked up", BAD in picked)
    failures += check("the same domain is only asked about once", picked.count(BAD) == 1)

    # ---- crossing the sources --------------------------------------------
    listed_and_new = links.check_domain(BAD, lookups=MOCKS)
    failures += check("blocklisted and days old reads as near certain",
                      listed_and_new["level"] == "certain")
    failures += check("that case carries the heaviest weight",
                      listed_and_new["weight"] == 3)
    failures += check("the verdict says it is not a judgement call",
                      "not a judgement call" in listed_and_new["verdict"][1])

    old_and_clean = links.check_domain("paypal.com", lookups=MOCKS)
    failures += check("an old domain on no list reads as the real thing",
                      old_and_clean["level"] == "established")
    failures += check("an established domain adds no weight", old_and_clean["weight"] == 0)

    # New, but no list has it yet. This is the case a blocklist alone misses.
    fresh_only = links.check_domain("brand-new-thing.com", lookups={
        "blocklist": fake_clean_blocklist, "age": fake_age_only_new,
        "virustotal": fake_vt_skipped})
    failures += check("a new domain no list knows is still flagged",
                      fresh_only["level"] == "new")
    failures += check("the new domain verdict says the lists have not caught up",
                      "caught up" in fresh_only["verdict"][1])

    # Everything down. Must not read as clean.
    silent = links.check_domain("whatever.com", lookups={
        "blocklist": fake_dead, "age": fake_dead, "virustotal": fake_dead})
    failures += check("nothing answering reads as could not check",
                      silent["level"] == "unknown")
    failures += check("a failed lookup adds no weight", silent["weight"] == 0)

    # ---- the trap these lists set -----------------------------------------
    # A blocklist that refuses this resolver answers exactly like one saying
    # "not listed". If that is believed, every link on earth reads as clean.
    links._usable_cache = {}
    refused = links.blocklist(
        "anything.example", "Spamhaus DBL", "dbl.spamhaus.org", "dbltest.com",
        links.SPAMHAUS_REFUSALS, "listed",
        resolver=lambda name, timeout=None: None)
    failures += check("a list failing its own test point is marked unusable",
                      refused.get("unusable") is True)
    failures += check("an unusable list is not counted as an answer",
                      refused.get("ok") is False)
    failures += check("an unusable list never says the domain is clean",
                      "does not list it" not in refused["why"])

    # And a refusal code must never be read as a hit, which would be worse:
    # it would accuse an innocent domain.
    links._usable_cache = {}

    def resolver_refuses(name, timeout=None):
        if name.startswith("dbltest.com."):
            return ["127.0.1.2"]                 # the list itself works
        return ["127.255.255.254"]               # but refuses this query
    hit = links.blocklist(
        "anything.example", "Spamhaus DBL", "dbl.spamhaus.org", "dbltest.com",
        links.SPAMHAUS_REFUSALS, "listed", resolver=resolver_refuses)
    failures += check("a refusal code is not read as a listing", not hit.get("known"))
    links._usable_cache = {}

    # ---- the link changes the whole message's verdict ---------------------
    original = links.check_all
    links.check_all = lambda l, vt_key="", timeout=12, limit=6, lookups=None: \
        original(l, vt_key, timeout, limit, MOCKS)
    try:
        body = (b"From: Accounts <accounts@example.com>\n"
                b"Subject: Invoice\n\nPlease see %s for the invoice.\n")
        bad = analyze.analyze_one(
            read.load(data=body % b"http://secure-billing-verify.com/login")[0],
            offline=False, check_domain=False)
        good = analyze.analyze_one(
            read.load(data=body % b"https://paypal.com/invoice")[0],
            offline=False, check_domain=False)

        failures += check("an ordinary message with a bad link is not called safe",
                          bad["level"] in ("high", "critical"))
        failures += check("that message is told plainly not to be opened",
                          "Do not open" in bad["verdict"][0])
        failures += check("the bad link is named in the verdict",
                          BAD in bad["verdict"][1])
        failures += check("the same message with a real link stays calm",
                          good["level"] == "normal")
        failures += check("the link reports are attached to the result",
                          len(bad.get("links", [])) == 1)

        # Offline must not reach for the network at all.
        offline = analyze.analyze_one(
            read.load(data=body % b"http://secure-billing-verify.com/login")[0],
            offline=True, check_domain=False)
        failures += check("offline does no link lookups", offline.get("links") == [])
    finally:
        links.check_all = original

    print()
    if failures:
        print("%d checks failed." % failures)
        return 1
    print("All link checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
