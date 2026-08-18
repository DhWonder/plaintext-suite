"""
Asking several databases about an address, and crossing their answers.

The analyser works out who is flooding you from the traffic alone: the rate, the
flags, the spread of ports, whether anyone answered back. That judgement stands
on its own and needs no internet. This adds one more thing on top of it, and only
when you ask: what does anybody else already know about this address.

WHY MORE THAN ONE DATABASE

Because one database is a rumour and three that agree are a finding. But the real
reason is the disagreements, which are where the useful answer usually hides:

  - VirusTotal says malicious, GreyNoise says "Shodan scanner". Both are right.
    It is an internet wide scanner that knocks on every door on the internet,
    including yours. It is noise, not an attack aimed at you, and the answer is
    "ignore it" rather than "we are under attack".
  - Nobody has heard of it, but it is flooding you at 40,000 packets a second.
    That is a fresh box in a botnet. Unknown is not the same as safe, and the
    tool says so rather than letting a clean lookup talk you out of what the
    traffic plainly shows.
  - Every source agrees it is a known attacker. Now the conversation is short.

So each source is asked separately, normalised into the same shape, and then
crossed. What comes out says who said what, whether they agreed, and what the
disagreement means, rather than one number that hides all of it.

WHO GETS ASKED

  GreyNoise (community)  free, no key at all. Tells you whether an address is a
                         known internet wide scanner and names it. This is the
                         one that stops the false alarms.
  Spamhaus, DroneBL      free, no key, answered over DNS the same way a mail
                         server asks. These are blocklists, so a hit means the
                         address is already known for abuse.
  VirusTotal             needs a free key. How many of about seventy vendors
                         call the address malicious.
  AbuseIPDB              needs a free key. How many people have reported it, and
                         what for.

WHAT LEAVES YOUR MACHINE

  The address, and nothing else, to the databases listed above. Sending an IP to
  a reputation service tells that service you are looking at it. For an address
  already attacking you that is a fair trade, but it is still a thing that
  leaves, so it is off until you ask, it only ever asks about the sources the
  analyser already flagged, and it never sends any of your traffic.
"""

import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 15
AGENT = "traffic-analyzer (plaintext IT)"

# The free tiers, kept here so the pacing and the wording agree with each other.
FREE_PER_MINUTE = 4
FREE_PER_DAY = 500

# How long a cached answer is trusted. Reputation moves, but slowly, and asking
# again every day would spend the budget on addresses that have not changed.
DEFAULT_MAX_AGE = 7 * 24 * 3600

DOH_URL = "https://dns.google/resolve"

# The blocklists worth asking, and what a hit from each one means. These are DNS
# lookups, so they need no key and no account.
BLOCKLISTS = [
    ("Spamhaus", "zen.spamhaus.org",
     "Spamhaus lists it, which usually means spam or a compromised machine"),
    ("DroneBL", "dnsbl.dronebl.org",
     "DroneBL lists it, which usually means a compromised machine or a proxy"),
]


def _sources_asked(keys):
    """Who would actually be asked, given the keys available. For disclosure."""
    keys = keys or {}
    asked = [("GreyNoise", "free, no key needed")]
    for name, _zone, _why in BLOCKLISTS:
        asked.append((name, "free, asked over DNS"))
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


def blocklist(ip, name, zone, meaning, timeout=TIMEOUT):
    """A DNS blocklist, asked the way a mail server asks: reverse the address."""
    if ":" in ip:
        return {"source": name, "ok": False, "known": False, "benign": False,
                "why": "%s only lists IPv4 addresses." % name}
    parts = ip.split(".")
    if len(parts) != 4:
        return {"source": name, "ok": False, "known": False, "benign": False,
                "why": "That is not an address %s can be asked about." % name}

    query = ".".join(reversed(parts)) + "." + zone
    url = "%s?%s" % (DOH_URL, urllib.parse.urlencode({"name": query, "type": "A"}))
    request = urllib.request.Request(url, headers={"User-Agent": AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as exc:
        return {"source": name, "ok": False, "known": False, "benign": False,
                "why": "%s did not answer (%s)." % (name, getattr(exc, "reason", exc))}

    # NXDOMAIN (status 3) is the normal answer and means "not listed".
    status = data.get("Status")
    answers = [a.get("data", "") for a in (data.get("Answer") or [])
               if a.get("type") == 1]
    if status == 3 or not answers:
        return {"source": name, "ok": True, "known": False, "benign": False,
                "why": "%s does not list it." % name}
    return {"source": name, "ok": True, "known": True, "benign": False,
            "codes": answers, "why": meaning + "."}


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
    for name, zone, meaning in BLOCKLISTS:
        runner = lookups.get("blocklist") or blocklist
        results.append(runner(ip, name, zone, meaning, timeout))
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
