"""
Asking several databases about an address that came to the honeypot.

A honeypot hit needs no interpretation. Nobody legitimate connects to a machine
that exists only to be connected to, so every session in the console is already
somebody doing something they should not. That part is settled before any
database is asked.

So what is reputation for here? One question, and it is the one that decides
whether this is a Tuesday or an incident:

    Were you swept up, or were you picked out?

An address GreyNoise knows as a mass scanner found your sensor the same way it
finds every address on the internet: by trying all of them. Annoying, worth
blocking if it is loud, not worth waking anybody. An address that no database
has ever heard of, that walked into a honeypot on your network, is a different
matter. Nobody stumbles onto a decoy by accident, and if the whole internet has
not seen this address then whoever it is may have come looking for you
specifically.

That is a distinction the session log alone cannot make, and it is the reason
this file exists.

WHO GETS ASKED

  GreyNoise (community)  free, no key at all. Knows the mass scanners by name.
                         The one that answers the question above.
  Spamhaus, DroneBL,     free, no key, over DNS. Each is asked its own test
  SpamCop                point first: these lists refuse queries from public
                         resolvers, and a refusal looks exactly like "not
                         listed" unless you check.
  VirusTotal             needs a free key. How many of about seventy vendors
                         call the address malicious.
  AbuseIPDB              needs a free key. How many people have reported it.

WHERE THIS RUNS

  The console only, never a sensor. A sensor is a machine you have deliberately
  decided to treat as untrusted and left where attackers can reach it, so no
  key of yours goes anywhere near one. The console holds the keys, does the
  asking, and the sensors never know any of it happened.

WHAT LEAVES YOUR MACHINE

  The attacker's address, and nothing else. Not what they typed, not which bait
  they took, not the name of your sensor or where it sits.
"""

import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 15
AGENT = "anglerfish"

# The free tiers, kept here so the pacing and the wording agree with each other.
FREE_PER_MINUTE = 4
FREE_PER_DAY = 500

# How long a cached answer is trusted. Reputation moves, but slowly, and asking
# again every day would spend the budget on addresses that have not changed.
DEFAULT_MAX_AGE = 7 * 24 * 3600

DOH_URL = "https://dns.google/resolve"

# Answers inside 127.0.0.0/8 that mean "I will not answer you" rather than
# "this is listed". Per list, not one shared set, because the same number means
# different things to different lists: 127.0.0.1 is a refusal to some and a
# perfectly valid listing type to DroneBL.
SPAMHAUS_REFUSALS = {
    "127.255.255.252",  # typing error in the query
    "127.255.255.253",  # query through an open resolver
    "127.255.255.254",  # query through a public resolver
    "127.255.255.255",  # volume limit exceeded
}

# The blocklists worth asking, with the test point each publishes and what a
# hit means. No key and no account: these are DNS lookups.
#
# The test point column exists because of a trap. These lists refuse queries
# that arrive through a big public resolver, and a refused query looks exactly
# like "this address is not listed". A tool that believes that answer reports
# every address as clean, for ever, and sounds confident doing it. So we ask
# each list its own published test point first: the universal convention is
# that 127.0.0.2 is always listed on a working list. If that does not come
# back listed, this machine cannot use the list and the honest answer is
# "could not check".
BLOCKLISTS = [
    ("Spamhaus", "zen.spamhaus.org", "2.0.0.127", SPAMHAUS_REFUSALS,
     "Spamhaus lists it, which usually means spam or a compromised machine"),
    ("DroneBL", "dnsbl.dronebl.org", "2.0.0.127", set(),
     "DroneBL lists it, which usually means a compromised machine or a proxy"),
    ("SpamCop", "bl.spamcop.net", "2.0.0.127", set(),
     "SpamCop lists it, which means it has been reported for sending spam"),
]


def _sources_asked(keys):
    """Who would actually be asked, given the keys available. For disclosure."""
    keys = keys or {}
    asked = [("GreyNoise", "free, no key needed")]
    for entry in BLOCKLISTS:
        asked.append((entry[0], "free, asked over DNS"))
    asked.append(("VirusTotal",
                  "asked" if keys.get("vt") else "skipped, no key"))
    asked.append(("AbuseIPDB",
                  "asked" if keys.get("abuseipdb") else "skipped, no key"))
    return asked


# ---------------------------------------------------------------------------
# One source at a time. Every one of these returns the same shape:
#
#   source   the name to show
#   ok       did it answer at all
#   known    does it consider this address bad
#   benign   does it positively consider it harmless (a known scanner, say)
#   why      one sentence, in words, for the report
#
# Nothing here raises. A source that is down must not take the run with it.
# ---------------------------------------------------------------------------
def greynoise(ip, key="", timeout=TIMEOUT):
    """The community endpoint: is this a known internet wide scanner?

    This is the source that prevents the most wrong conclusions, and it is free
    and needs no key. An address GreyNoise names as a scanner is knocking on
    every door on the internet, not picking yours.
    """
    request = urllib.request.Request(
        "https://api.greynoise.io/v3/community/" + urllib.parse.quote(ip),
        headers={"User-Agent": AGENT, "Accept": "application/json"})
    if key:
        request.add_header("key", key)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"source": "GreyNoise", "ok": True, "known": False, "benign": False,
                    "unseen": True, "why": "GreyNoise has never seen this address scanning."}
        if exc.code == 429:
            return {"source": "GreyNoise", "ok": False, "known": False, "benign": False,
                    "quota": True, "why": "GreyNoise asked us to slow down."}
        return {"source": "GreyNoise", "ok": False, "known": False, "benign": False,
                "why": "GreyNoise answered %s." % exc.code}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"source": "GreyNoise", "ok": False, "known": False, "benign": False,
                "why": "GreyNoise did not answer (%s)." % getattr(exc, "reason", exc)}

    classification = (data.get("classification") or "").lower()
    name = data.get("name") or ""
    noise = bool(data.get("noise"))
    riot = bool(data.get("riot"))

    result = {"source": "GreyNoise", "ok": True, "known": False, "benign": False,
              "classification": classification, "name": name, "noise": noise, "riot": riot}

    if classification == "malicious":
        result["known"] = True
        result["why"] = ("GreyNoise classes it as malicious%s, and sees it scanning the "
                         "internet broadly." % (" (%s)" % name if name else ""))
    elif classification == "benign" or riot:
        result["benign"] = True
        result["why"] = ("GreyNoise knows this one: %s. It scans the whole internet, so it "
                         "is not picking on you." % (name or "a known harmless service"))
    elif noise:
        result["why"] = ("GreyNoise sees it scanning the internet broadly%s, but does not "
                         "class it either way." % (" (%s)" % name if name else ""))
    else:
        result["unseen"] = True
        result["why"] = "GreyNoise has never seen this address scanning."
    return result



class _LookupFailed(object):
    """A timeout or a temporary resolver error. Not 'this name is not listed'."""

    def __repr__(self):
        return "LOOKUP_FAILED"


LOOKUP_FAILED = _LookupFailed()


def _name_is_missing(exc):
    """True only for a confirmed missing name.

    socket.gaierror is a subclass of OSError. A bare OSError handler would
    treat EAI_AGAIN and a timeout as 'not listed', which they are not.
    """
    code = getattr(exc, "errno", None)
    missing = []
    for name in ("EAI_NONAME", "EAI_NODATA"):
        value = getattr(socket, name, None)
        if value is not None:
            missing.append(value)
    return code in missing


def _resolve(name, timeout=TIMEOUT):
    """Ask this machine's own resolver, not a public one.

    The lists block the public resolvers, and at a client site the machine's
    own resolver is the path their mail and their firewall actually use, so
    the answer we get is the answer that matters to them.

    Returns a list of addresses, or None when the name does not exist.
    """
    previous = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname_ex(name)[2]
    except socket.gaierror as exc:
        if _name_is_missing(exc):
            return None                  # confirmed missing name: not listed
        return LOOKUP_FAILED             # EAI_AGAIN and the like are not "not listed"
    except OSError:
        return LOOKUP_FAILED             # timeout. gaierror is an OSError, so this is the rest
    finally:
        socket.setdefaulttimeout(previous)


# Whether a list answers us at all. Worked out once per run and remembered,
# because it is the same answer for every address we then ask about.
_usable_cache = {}


def _list_usable(zone, test_point, refusals, timeout=TIMEOUT, resolver=None):
    resolver = resolver or _resolve
    if zone in _usable_cache:
        return _usable_cache[zone]
    answers = resolver("%s.%s" % (test_point, zone), timeout)
    if answers is LOOKUP_FAILED:
        _usable_cache[zone] = LOOKUP_FAILED
        return LOOKUP_FAILED
    answers = answers or []
    good = [a for a in answers if a.startswith("127.") and a not in refusals]
    _usable_cache[zone] = bool(good)
    return _usable_cache[zone]


def blocklist(ip, name, zone, test_point, refusals, meaning, timeout=TIMEOUT,
              resolver=None):
    """A DNS blocklist, asked the way a mail server asks: reverse the address."""
    resolver = resolver or _resolve

    if ":" in ip:
        return {"source": name, "ok": False, "known": False, "benign": False,
                "why": "%s only lists IPv4 addresses." % name}
    parts = ip.split(".")
    if len(parts) != 4:
        return {"source": name, "ok": False, "known": False, "benign": False,
                "why": "That is not an address %s can be asked about." % name}

    usable = _list_usable(zone, test_point, refusals, timeout, resolver)
    if usable is LOOKUP_FAILED:
        return {"source": name, "ok": False, "known": False, "benign": False,
                "lookup_failed": True,
                "why": ("Could not check %s: the lookup failed (a timeout or a "
                        "temporary resolver error). That is not the same as the "
                        "address being clean." % name)}
    if not usable:
        return {"source": name, "ok": False, "known": False, "benign": False,
                "unusable": True,
                "why": ("%s would not answer its own test lookup from this machine. "
                        "These lists refuse queries that come through a big public "
                        "resolver, so this says nothing about the address." % name)}

    answers = resolver(".".join(reversed(parts)) + "." + zone, timeout)
    if answers is LOOKUP_FAILED:
        return {"source": name, "ok": False, "known": False, "benign": False,
                "lookup_failed": True,
                "why": ("Could not check %s: the lookup failed (a timeout or a "
                        "temporary resolver error). That is not the same as the "
                        "address being clean." % name)}
    if answers is None:
        return {"source": name, "ok": True, "known": False, "benign": False,
                "why": "%s does not list it." % name}

    refused = [a for a in answers if a in refusals]
    hits = [a for a in answers if a.startswith("127.") and a not in refusals]

    if refused and not hits:
        return {"source": name, "ok": False, "known": False, "benign": False,
                "unusable": True,
                "why": ("%s refused the query (%s), which is not the same as saying "
                        "the address is clean." % (name, ", ".join(refused)))}
    if not hits:
        return {"source": name, "ok": True, "known": False, "benign": False,
                "why": "%s does not list it." % name}
    return {"source": name, "ok": True, "known": True, "benign": False,
            "codes": hits, "why": meaning + "."}


def virustotal_ip(ip, key="", timeout=TIMEOUT):
    """How many of about seventy vendors call this address malicious."""
    if not key:
        return {"source": "VirusTotal", "ok": False, "known": False, "benign": False,
                "skipped": True, "why": "VirusTotal was skipped: no key was given."}

    request = urllib.request.Request(
        "https://www.virustotal.com/api/v3/ip_addresses/" + urllib.parse.quote(ip),
        headers={"User-Agent": AGENT, "x-apikey": key})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"source": "VirusTotal", "ok": True, "known": False, "benign": False,
                    "unseen": True,
                    "why": "Nobody has ever asked VirusTotal about this address."}
        if exc.code == 401:
            return {"source": "VirusTotal", "ok": False, "known": False, "benign": False,
                    "why": "The VirusTotal key was refused."}
        if exc.code == 429:
            return {"source": "VirusTotal", "ok": False, "known": False, "benign": False,
                    "quota": True, "why": "The VirusTotal key's limit was reached."}
        return {"source": "VirusTotal", "ok": False, "known": False, "benign": False,
                "why": "VirusTotal answered %s." % exc.code}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"source": "VirusTotal", "ok": False, "known": False, "benign": False,
                "why": "VirusTotal did not answer (%s)." % getattr(exc, "reason", exc)}

    attributes = (data.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    total = sum(int(v or 0) for v in stats.values())
    asn = attributes.get("asn")

    result = {
        "source": "VirusTotal", "ok": True, "known": malicious > 0, "benign": False,
        "malicious": malicious, "suspicious": suspicious, "total": total,
        "reputation": int(attributes.get("reputation", 0) or 0),
        "country": attributes.get("country", "") or "",
        "asn": str(asn) if asn is not None else "",
        "as_owner": attributes.get("as_owner", "") or "",
    }
    if malicious:
        result["why"] = ("%d of %d vendors on VirusTotal call this address malicious."
                         % (malicious, total))
    elif suspicious:
        result["why"] = ("No vendor calls it malicious, but %d flag it as suspicious."
                         % suspicious)
    else:
        result["why"] = "No vendor on VirusTotal currently flags this address."
    return result


def abuseipdb(ip, key="", timeout=TIMEOUT):
    """How many people have reported this address, and what for."""
    if not key:
        return {"source": "AbuseIPDB", "ok": False, "known": False, "benign": False,
                "skipped": True, "why": "AbuseIPDB was skipped: no key was given."}

    url = "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode(
        {"ipAddress": ip, "maxAgeInDays": 90})
    request = urllib.request.Request(
        url, headers={"User-Agent": AGENT, "Key": key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return {"source": "AbuseIPDB", "ok": False, "known": False, "benign": False,
                    "why": "The AbuseIPDB key was refused."}
        if exc.code == 429:
            return {"source": "AbuseIPDB", "ok": False, "known": False, "benign": False,
                    "quota": True, "why": "The AbuseIPDB key's daily limit was reached."}
        return {"source": "AbuseIPDB", "ok": False, "known": False, "benign": False,
                "why": "AbuseIPDB answered %s." % exc.code}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"source": "AbuseIPDB", "ok": False, "known": False, "benign": False,
                "why": "AbuseIPDB did not answer (%s)." % getattr(exc, "reason", exc)}

    payload = data.get("data") or {}
    score = int(payload.get("abuseConfidenceScore", 0) or 0)
    reports = int(payload.get("totalReports", 0) or 0)
    result = {
        "source": "AbuseIPDB", "ok": True, "benign": False,
        # Their own guidance: below about 25 is not worth acting on.
        "known": score >= 25,
        "score": score, "reports": reports,
        "country": payload.get("countryCode", "") or "",
        "isp": payload.get("isp", "") or "",
        "whitelisted": bool(payload.get("isWhitelisted")),
    }
    if payload.get("isWhitelisted"):
        result["benign"] = True
        result["known"] = False
        result["why"] = "AbuseIPDB has this address on its allow list of known good services."
    elif score >= 25:
        result["why"] = ("AbuseIPDB is %d%% confident this address is abusive, from %d "
                         "report%s in the last 90 days."
                         % (score, reports, "" if reports == 1 else "s"))
    elif reports:
        result["why"] = ("AbuseIPDB has %d report%s about it, but not enough to be confident."
                         % (reports, "" if reports == 1 else "s"))
    else:
        result["why"] = "Nobody has reported this address to AbuseIPDB."
    return result


# ---------------------------------------------------------------------------
# Asking everybody, then crossing what they said
# ---------------------------------------------------------------------------
def check(ip, keys=None, timeout=TIMEOUT, lookups=None):
    """Ask every source we can, and cross the answers into one verdict."""
    keys = keys or {}
    lookups = lookups or {}

    results = []
    results.append((lookups.get("greynoise") or greynoise)(ip, keys.get("greynoise", ""),
                                                           timeout))
    for name, zone, test_point, refusals, meaning in BLOCKLISTS:
        runner = lookups.get("blocklist") or blocklist
        results.append(runner(ip, name, zone, test_point, refusals, meaning, timeout))
    results.append((lookups.get("virustotal") or virustotal_ip)(ip, keys.get("vt", ""), timeout))
    results.append((lookups.get("abuseipdb") or abuseipdb)(ip, keys.get("abuseipdb", ""), timeout))

    combined = combine(results)
    combined["ip"] = ip
    combined["sources"] = results
    combined["checked_at"] = time.time()
    combined["ok"] = combined["answered"] > 0
    # Kept flat as well, because the cache and the older report code read these.
    combined["known"] = combined["level"] in ("known-bad", "single-report")
    return combined


def combine(results):
    """Cross the sources. Agreement is a finding; disagreement is usually the answer."""
    answered = [r for r in results if r.get("ok")]
    unusable = [r for r in results if r.get("unusable")]
    bad = [r for r in answered if r.get("known")]
    benign = [r for r in answered if r.get("benign")]
    quota = [r for r in results if r.get("quota")]
    skipped = [r for r in results if r.get("skipped")]

    scanner = _scanner_name(results)

    if not answered:
        level = "unknown"
    elif bad and benign:
        level = "disputed"
    elif len(bad) >= 2:
        level = "known-bad"
    elif len(bad) == 1:
        level = "single-report"
    elif benign:
        level = "benign"
    else:
        level = "clean"

    return {
        "level": level,
        "answered": len(answered),
        "asked": len(results),
        "bad_count": len(bad),
        "benign_count": len(benign),
        "bad_sources": [r["source"] for r in bad],
        "benign_sources": [r["source"] for r in benign],
        "quota_hit": bool(quota),
        "unusable": [r["source"] for r in unusable],
        "skipped": [r["source"] for r in skipped],
        "scanner": scanner,
        "verdict": _verdict(level, bad, benign, answered, results, scanner),
    }


def _scanner_name(results):
    for result in results:
        if result.get("source") == "GreyNoise" and result.get("name"):
            return result["name"]
    return ""


def _verdict(level, bad, benign, answered, results, scanner):
    """A headline and a paragraph. The paragraph is where the crossing pays off."""
    who_bad = ", ".join(r["source"] for r in bad)
    who_benign = ", ".join(r["source"] for r in benign)
    place = _place(results)
    tail = (" It is %s." % place) if place else ""

    if level == "unknown":
        return ("Could not check",
                "No reputation database answered, so this part tells you nothing either way. "
                "What the traffic itself showed, above, still stands on its own.")

    if level == "disputed":
        return ("Known scanner, also reported",
                "The databases disagree, and the disagreement is the useful part. %s %s it "
                "bad, while %s knows it as %s. That combination almost always means an "
                "internet wide scanner: it knocks on every door on the internet, including "
                "yours, so it is noise rather than an attack aimed at you. Worth blocking if "
                "it is loud, not worth an incident.%s"
                % (who_bad, "calls" if len(bad) == 1 else "call",
                   who_benign, scanner or "a known service", tail))

    if level == "known-bad":
        return ("Known bad",
                "%d of the %d databases that answered call this address bad: %s. Sources that "
                "agree independently are worth more than any one of them, so this is not just "
                "busy traffic. Somebody has already reported this address for attacks.%s"
                % (len(bad), len(answered), who_bad, tail))

    if level == "single-report":
        return ("Reported by one source",
                "%s calls this address bad, and the others that answered do not. One report is "
                "weaker than several agreeing, so weigh it with what the traffic showed rather "
                "than on its own.%s" % (who_bad, tail))

    if level == "benign":
        return ("Known harmless scanner",
                "%s knows this address as %s, and nobody reports it as bad. It scans the whole "
                "internet rather than picking on you. If it is loud enough to matter you can "
                "block it, but it is not an attack.%s"
                % (who_benign, scanner or "a known service", tail))

    return ("Not reported",
            "None of the %d databases that answered has anything against this address. That is "
            "worth less than it sounds for a source that is misbehaving right now: a fresh "
            "machine in a botnet is unknown to every database on its first day. Unknown is not "
            "the same as safe, so judge it on the traffic above.%s" % (len(answered), tail))


def _place(results):
    """Country and network, from whichever source knew them."""
    country = asn = owner = isp = ""
    for result in results:
        country = country or result.get("country", "")
        asn = asn or result.get("asn", "")
        owner = owner or result.get("as_owner", "")
        isp = isp or result.get("isp", "")
    bits = []
    if country:
        bits.append("in " + country)
    if asn:
        bits.append("on AS%s%s" % (asn, (" (%s)" % owner) if owner else ""))
    elif isp:
        bits.append("on " + isp)
    return ", ".join(bits)


def verdict(result):
    """The headline and paragraph for one crossed answer."""
    if not result:
        return ("Not checked", "This address was not looked up.")
    if result.get("skipped_all"):
        return ("Not checked", "No key was given and no free source answered.")
    if result.get("quota") and not result.get("sources"):
        return ("Not checked",
                "The lookup budget was reached before this address, so it was not checked. "
                "The traffic based judgement above still stands on its own.")
    found = result.get("verdict")
    if found:
        return tuple(found)
    return ("Could not check", "Nothing came back for this address.")


class Checker(object):
    """Enrich a set of addresses, using the cache first and the network sparingly.

    Give it the keys and (optionally) the Store to cache in. Call enrich() with
    the addresses you actually care about, which for this tool is the flagged
    sources, not the whole capture. It returns {ip: result} and keeps a tally of
    how the answers were obtained so the report can be honest about coverage.
    """

    def __init__(self, keys=None, store=None, pause=None, per_minute=FREE_PER_MINUTE,
                 daily_cap=FREE_PER_DAY, max_age=DEFAULT_MAX_AGE, lookup=None,
                 is_public=None, key=""):
        # `key` alone is still accepted, so an older call meaning "the VirusTotal
        # key" keeps working.
        self.keys = dict(keys or {})
        if key and not self.keys.get("vt"):
            self.keys["vt"] = key

        self.store = store
        self.per_minute = max(1, per_minute)
        self.pause = pause if pause is not None else (60.0 / self.per_minute)
        self.daily_cap = daily_cap
        self.max_age = max_age
        self._lookup = lookup or (lambda ip: check(ip, keys=self.keys))
        self._is_public = is_public or (lambda ip: True)

        self.from_cache = 0
        self.looked_up = 0
        self.skipped_private = 0
        self.skipped_quota = 0
        self.quota_hit = False

    def sources_asked(self):
        return _sources_asked(self.keys)

    def enrich(self, ips, progress=None):
        results = {}
        live_calls = 0
        seen = []
        for ip in ips:
            if ip not in seen:
                seen.append(ip)

        for ip in seen:
            if not self._is_public(ip):
                self.skipped_private += 1
                continue

            cached = self.store.get_reputation(ip, self.max_age) if self.store else None
            if cached:
                results[ip] = cached
                self.from_cache += 1
                continue

            if self.quota_hit or live_calls >= self.daily_cap:
                self.skipped_quota += 1
                results[ip] = {"ok": False, "known": False, "quota": True,
                               "level": "unknown", "sources": [],
                               "verdict": ("Not checked",
                                           "The lookup budget was reached before this "
                                           "address, so it was not checked.")}
                continue

            if live_calls and self.pause:
                time.sleep(self.pause)
            if progress:
                progress(ip, live_calls + 1)

            result = self._lookup(ip)
            live_calls += 1
            self.looked_up += 1

            # Only a source-wide quota stop should end the run. One database
            # rate limiting us is not a reason to stop asking the others.
            if result.get("quota_hit") and not result.get("answered"):
                self.quota_hit = True

            if result.get("ok") and self.store:
                self.store.save_reputation(ip, result)
            results[ip] = result

        return results

    def coverage(self):
        """A short, honest line about how the answers were obtained."""
        parts = []
        if self.looked_up:
            parts.append("%d looked up" % self.looked_up)
        if self.from_cache:
            parts.append("%d from earlier answers" % self.from_cache)
        if self.skipped_quota:
            parts.append("%d not checked because the lookup budget ran out" % self.skipped_quota)
        if self.skipped_private:
            parts.append("%d skipped as local addresses" % self.skipped_private)
        return ", ".join(parts)


# ---------------------------------------------------------------------------
# The honeypot reading of a crossed answer.
#
# traffic-analyzer asks "is this address a problem". Here that is already
# answered: it walked into a decoy. So the crossed result gets read for a
# different question, and the wording has to match, or somebody will read a
# "known bad" line and think it is the finding when the finding is the session
# underneath it.
# ---------------------------------------------------------------------------
def honeypot_verdict(result):
    """Were you swept up in a mass scan, or picked out?

    Returns (headline, sentence, attention) where attention is 0 to 2: 0 is
    background noise, 1 is worth a look, 2 is the one to read today.
    """
    if not result or not result.get("ok"):
        return ("Not checked",
                "Nothing was asked about this address, or nothing answered. The session "
                "itself is still the finding: somebody connected to a machine that exists "
                "only to be connected to.", 1)

    scanner = result.get("scanner") or ""
    level = result.get("level", "unknown")
    place = _place(result.get("sources", []))
    where = (" It is %s." % place) if place else ""

    if level == "disputed":
        return ("A known scanner that is also reported",
                "Databases disagree about this one, and for a honeypot the disagreement "
                "resolves the same way: %s knows it as a mass scanner, so it almost "
                "certainly found you by sweeping rather than by choosing you. Worth "
                "blocking, not worth an incident.%s" % (scanner or "GreyNoise", where), 1)

    if level == "benign" or (scanner and level != "known-bad"):
        return ("Swept up, not picked out",
                "GreyNoise knows this address as %s: it scans the whole internet, so it "
                "found your sensor by trying everything rather than by looking for you. "
                "Block it if it is noisy. It is not an incident.%s"
                % (scanner or "a known scanner", where), 0)

    if level == "known-bad":
        return ("A known attacker found you",
                "Several databases agree this address is already reported for attacks, and "
                "it has now been inside a decoy on your network. That does not by itself "
                "mean you were targeted, since known attackers sweep too, but it does mean "
                "this is a machine with a history rather than a curious stranger.%s"
                % where, 2)

    if level == "single-report":
        return ("Reported once, and now here",
                "One database has this address on record and the others do not. On its own "
                "that is weak, but combined with it walking into a decoy it is worth "
                "reading the session below properly.%s" % where, 2)

    # Nothing known, and it is in your honeypot. This is the interesting one.
    return ("Nobody has ever seen this address",
            "No database has a record of this address at all, and yet it found a machine "
            "on your network that exists only as bait. Mass scanners are known to the "
            "databases precisely because they scan everybody; an address nobody knows is "
            "one that has not been scanning everybody. Read this session first.%s" % where, 2)
