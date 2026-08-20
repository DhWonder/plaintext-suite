"""
Prove the domain reputation checks never report a clean bill of health they
did not earn.

No network. Every lookup is replaced with a fake.

The case worth reading is the blocklist one. These lists refuse queries that
arrive through a big public resolver, and a refused query comes back looking
exactly like "this domain is not listed". A tool that believes that answer
reports every domain as clean, for ever, and sounds confident doing it. That is
the single worst thing this module could do, so most of these checks are about
making sure it cannot.

    python3 tests/test_reputation.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import reputation


def check(name, condition):
    print("  %-64s %s" % (name, "ok" if condition else "FAILED"))
    return 0 if condition else 1


def fresh_module():
    """The usable-list answer is cached per run, so clear it between cases."""
    reputation._usable_cache = {}


# -- fake resolvers ----------------------------------------------------------
def resolver_working(listed_names=()):
    """A resolver that can reach the lists: the test points answer properly."""
    def resolve(name, timeout=None):
        if name.startswith("dbltest.com."):
            return ["127.0.1.2"]
        if name.startswith("test.multi.surbl.org"):
            return ["127.0.0.2"]
        for listed in listed_names:
            if name.startswith(listed + "."):
                return ["127.0.1.4"]
        return None                      # not listed
    return resolve


def resolver_blocked(name, timeout=None):
    """A public resolver: the lists refuse it, so nothing ever answers."""
    return None


def resolver_refusing(name, timeout=None):
    """A resolver the lists answer, but only to say they will not serve it."""
    if name.startswith("dbltest.com.") or name.startswith("test.multi.surbl.org"):
        return ["127.0.1.2"] if name.startswith("dbltest") else ["127.0.0.2"]
    return ["127.255.255.254"]           # Spamhaus: query via a public resolver


def age_old(domain, timeout=None):
    return {"source": "How old it is", "ok": True, "known": False, "benign": True,
            "days": 7000, "why": "Registered 19 years ago, which is what a real "
                                 "business looks like."}


def age_new(domain, timeout=None):
    return {"source": "How old it is", "ok": True, "known": True, "days": 4,
            "why": "Registered 4 days ago."}


def vt_skipped(domain, key="", timeout=None):
    return {"source": "VirusTotal", "ok": False, "known": False, "skipped": True,
            "why": "VirusTotal was skipped: no key was given."}


def lookups_with(resolve, age_fn=age_old):
    def bl(domain, name, zone, test_name, refusals, meaning, timeout=None):
        return reputation.blocklist(domain, name, zone, test_name, refusals, meaning,
                                    timeout, resolver=resolve)
    return {"blocklist": bl, "age": age_fn, "virustotal": vt_skipped}


def main():
    failures = 0

    # ---- the trap: a resolver the lists will not serve --------------------
    fresh_module()
    blocked = reputation.check("example.com", lookups=lookups_with(resolver_blocked))
    bl_results = [r for r in blocked["sources"] if r["source"] in ("Spamhaus DBL", "SURBL")]
    failures += check("a list that fails its own test point is marked unusable",
                      all(r.get("unusable") for r in bl_results))
    failures += check("an unusable list does not count as having answered",
                      all(not r.get("ok") for r in bl_results))
    failures += check("an unusable list never reports the domain as clean",
                      all(not r.get("known") for r in bl_results) and
                      all("does not list it" not in r["why"] for r in bl_results))
    failures += check("the verdict refuses to give a clean bill of health",
                      blocked["verdict"][0] == "Blocklists could not be checked")
    failures += check("the verdict names the lists that could not be reached",
                      "Spamhaus DBL" in blocked["verdict"][1])
    failures += check("the verdict says how to get a real answer",
                      "resolver" in blocked["verdict"][1])

    # ---- a refusal code must never be read as a listing -------------------
    fresh_module()
    refused = reputation.check("example.com", lookups=lookups_with(resolver_refusing))
    spamhaus = next(r for r in refused["sources"] if r["source"] == "Spamhaus DBL")
    failures += check("a refusal code is not treated as a hit", not spamhaus.get("known"))
    failures += check("a refusal code is reported as a refusal",
                      spamhaus.get("unusable") is True)
    failures += check("the refusal says it is not the same as being clean",
                      "not the same as saying the domain is clean" in spamhaus["why"])

    # ---- a resolver that works, on a domain nobody lists -------------------
    fresh_module()
    clean = reputation.check("example.com", lookups=lookups_with(resolver_working()))
    bl_results = [r for r in clean["sources"] if r["source"] in ("Spamhaus DBL", "SURBL")]
    failures += check("with a working resolver the lists do answer",
                      all(r.get("ok") for r in bl_results))
    failures += check("an unlisted domain reads as not listed",
                      all(not r.get("known") for r in bl_results))
    failures += check("an old unlisted domain reads as nothing against it",
                      clean["level"] == "established")

    # ---- a genuinely listed domain ----------------------------------------
    fresh_module()
    listed = reputation.check("bad.example",
                              lookups=lookups_with(resolver_working(["bad.example"])))
    failures += check("a listed domain is reported as listed", listed["level"] == "listed")
    failures += check("the listed verdict says mail is being rejected",
                      "rejected" in listed["verdict"][1])
    failures += check("the listed verdict names both lists",
                      len(listed["listed_by"]) == 2)

    # ---- listed and brand new is the worst combination --------------------
    fresh_module()
    throwaway = reputation.check(
        "bad.example",
        lookups=lookups_with(resolver_working(["bad.example"]), age_fn=age_new))
    failures += check("listed and days old reads as a throwaway domain",
                      throwaway["level"] == "throwaway")
    failures += check("the throwaway verdict says to treat it as hostile",
                      "hostile" in throwaway["verdict"][1])

    # ---- new but on no list -----------------------------------------------
    fresh_module()
    new = reputation.check("new.example",
                           lookups=lookups_with(resolver_working(), age_fn=age_new))
    failures += check("a new unlisted domain is still flagged as new",
                      new["level"] == "new")
    failures += check("the new verdict says the lists may not have caught up",
                      "caught up" in new["verdict"][1])

    # ---- the usable answer is worked out once, not per domain -------------
    fresh_module()
    calls = []

    def counting(name, timeout=None):
        calls.append(name)
        return resolver_working()(name, timeout)

    reputation.check("one.example", lookups=lookups_with(counting))
    first = len([c for c in calls if c.startswith("dbltest")])
    reputation.check("two.example", lookups=lookups_with(counting))
    second = len([c for c in calls if c.startswith("dbltest")])
    failures += check("the test point is asked once per run, not once per domain",
                      first == 1 and second == 1)

    print()
    if failures:
        print("%d checks failed." % failures)
        return 1
    print("All domain reputation checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
