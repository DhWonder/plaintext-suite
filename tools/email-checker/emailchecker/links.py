"""
Checking where a message's links actually go, across several databases.

The wording checks already notice when a link shows one address and leads to
another, and that alone catches most of what arrives at a small business. This
answers the next question: the link goes to `secure-billing-verify.com`, so is
that a real company or something somebody registered on Tuesday.

Four things get asked about each domain, and crossing them is the point:

  Spamhaus DBL   free, over DNS. A domain blocklist. A hit means it is already
                 known for phishing, malware or spam.
  SURBL          free, over DNS. The same idea, a different list, kept by
                 different people. Two independent lists agreeing is worth much
                 more than either alone.
  How old it is  free, over RDAP, which is the modern replacement for WHOIS.
                 This is the strongest single signal there is on a phishing
                 link. Real businesses have had their domain for years.
                 Campaigns register a fresh domain days before they send.
  VirusTotal     needs a free key. How many vendors flag the domain.

The crossing matters more here than anywhere else in the suite. A domain that is
four days old AND on a blocklist is not a judgement call. A domain that is
fifteen years old and on no list is almost certainly the real company, even if
the message around it looked odd. And a brand new domain that no list has caught
up with yet is exactly the case a single blocklist lookup would have called
clean, which is why age is asked about at all.

WHAT LEAVES YOUR MACHINE

  The domain name from the link, and nothing else. Not the message, not the
  address it was sent to, not the attachment. A domain name in an email is
  already public, and the lookups are the same ones a mail server does. Nothing
  here opens the link or fetches the page.
"""

import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 12
AGENT = "email-checker (plaintext IT)"
DOH_URL = "https://dns.google/resolve"

# Answers inside 127.0.0.0/8 that mean "I will not answer you" rather than
# "this is listed". Per list, because the same number means different things to
# different lists.
SPAMHAUS_REFUSALS = {
    "127.255.255.252", "127.255.255.253", "127.255.255.254", "127.255.255.255",
}
SURBL_REFUSALS = {"127.0.0.1", "127.0.0.254"}

# Domain blocklists, with the test point each publishes. No key, no account.
#
# The test point matters because these lists refuse queries that arrive through
# a big public resolver, and a refused query looks exactly like "not listed". A
# tool that believes it calls every link clean, for ever, while sounding sure.
# So each list is asked its own test point first, and if that does not come
# back listed the honest answer about the domain is "could not check".
BLOCKLISTS = [
    ("Spamhaus DBL", "dbl.spamhaus.org", "dbltest.com", SPAMHAUS_REFUSALS,
     "Spamhaus lists this domain, which means it is already known for phishing, "
     "malware or spam"),
    ("SURBL", "multi.surbl.org", "test", SURBL_REFUSALS,
     "SURBL lists this domain, which means it has been seen in spam or phishing "
     "messages"),
]

# Domains not worth spending a lookup on. These are the big providers a real
# message legitimately goes through, and asking about them wastes the budget.
SKIP = {
    "google.com", "www.google.com", "gmail.com", "googleapis.com", "gstatic.com",
    "microsoft.com", "outlook.com", "office.com", "office365.com", "live.com",
    "apple.com", "icloud.com", "amazon.com", "aws.amazon.com", "cloudfront.net",
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "youtube.com", "github.com", "dropbox.com", "zoom.us", "slack.com",
    "w3.org", "schema.org", "mailchimp.com", "sendgrid.net",
}

# How old counts as new. A domain younger than this in a message asking for money
# or a password is the single strongest signal there is.
VERY_NEW_DAYS = 30
NEW_DAYS = 180


def domains_in(links, limit=8):
    """The distinct domains a message's links point at, worth asking about.

    `links` is the (href, visible text) list the message reader already collects.
    """
    from .message import domain_of

    found = []
    for item in links:
        href = item[0] if isinstance(item, (list, tuple)) else item
        domain = domain_of(href)
        if not domain or "." not in domain:
            continue
        if domain in SKIP:
            continue
        # A bare address is handled by the wording checks, and no database takes
        # one for a domain lookup.
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
            continue
        if domain not in found:
            found.append(domain)
        if len(found) >= limit:
            break
    return found


# ---------------------------------------------------------------------------
# One source at a time. Each returns the same shape, and none of them raise.
# ---------------------------------------------------------------------------
def _resolve(name, timeout=TIMEOUT):
    """This machine's own resolver, not a public one: the lists block those."""
    previous = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname_ex(name)[2]
    except socket.gaierror:
        return None                      # no such name: not listed
    except OSError:
        return None
    finally:
        socket.setdefaulttimeout(previous)


_usable_cache = {}


def _list_usable(zone, test_name, refusals, timeout=TIMEOUT, resolver=None):
    resolver = resolver or _resolve
    if zone in _usable_cache:
        return _usable_cache[zone]
    answers = resolver("%s.%s" % (test_name, zone), timeout) or []
    good = [a for a in answers if a.startswith("127.") and a not in refusals]
    _usable_cache[zone] = bool(good)
    return _usable_cache[zone]


def blocklist(domain, name, zone, test_name, refusals, meaning, timeout=TIMEOUT,
              resolver=None):
    """A domain blocklist, asked the way a mail server asks."""
    resolver = resolver or _resolve

    if not _list_usable(zone, test_name, refusals, timeout, resolver):
        return {"source": name, "ok": False, "known": False, "unusable": True,
                "why": ("%s would not answer its own test lookup from this machine. "
                        "These lists refuse queries through a big public resolver, so "
                        "this says nothing about the domain." % name)}

    answers = resolver("%s.%s" % (domain, zone), timeout)
    if answers is None:
        return {"source": name, "ok": True, "known": False,
                "why": "%s does not list it." % name}

    refused = [a for a in answers if a in refusals]
    hits = [a for a in answers if a.startswith("127.") and a not in refusals]

    if refused and not hits:
        return {"source": name, "ok": False, "known": False, "unusable": True,
                "why": ("%s refused the query (%s), which is not the same as saying the "
                        "domain is clean." % (name, ", ".join(refused)))}
    if not hits:
        return {"source": name, "ok": True, "known": False,
                "why": "%s does not list it." % name}
    return {"source": name, "ok": True, "known": True, "codes": hits,
            "why": meaning + "."}


def age(domain, timeout=TIMEOUT):
    """How long this domain has existed, over RDAP. No key, no account.

    RDAP is what replaced WHOIS. The registration date is the useful part: a
    domain registered days ago, in a message asking for money or a password, is
    the strongest single signal there is.
    """
    url = "https://rdap.org/domain/" + urllib.parse.quote(domain)
    request = urllib.request.Request(url, headers={"User-Agent": AGENT,
                                                   "Accept": "application/rdap+json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"source": "How old it is", "ok": True, "known": False,
                    "registered": None,
                    "why": "No registration record exists for this domain at all, which is odd "
                           "for something being linked to in a message."}
        return {"source": "How old it is", "ok": False, "known": False,
                "why": "The registry answered %s." % exc.code}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"source": "How old it is", "ok": False, "known": False,
                "why": "The registry did not answer (%s)." % getattr(exc, "reason", exc)}

    when = ""
    for event in data.get("events") or []:
        if event.get("eventAction") in ("registration", "created"):
            when = event.get("eventDate", "")
            break
    if not when:
        return {"source": "How old it is", "ok": True, "known": False,
                "why": "The registry did not say when this domain was registered."}

    days = _days_since(when)
    if days is None:
        return {"source": "How old it is", "ok": True, "known": False,
                "why": "The registration date came back in a form we could not read."}

    result = {"source": "How old it is", "ok": True, "known": False,
              "registered": when[:10], "days": days}
    if days <= VERY_NEW_DAYS:
        result["known"] = True
        result["why"] = ("This domain was registered %d day%s ago. A business you already deal "
                         "with has had its domain for years; a phishing campaign registers one "
                         "the week it sends." % (days, "" if days == 1 else "s"))
    elif days <= NEW_DAYS:
        result["why"] = ("This domain is about %d months old, which is young enough to be worth "
                         "noticing but not damning on its own." % max(days // 30, 1))
    else:
        years = days / 365.0
        result["benign"] = True
        result["why"] = ("This domain has existed for %s, which is what a real business looks "
                         "like." % (("%.0f years" % years) if years >= 2 else "about a year"))
    return result


def _days_since(text):
    for shape in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S",
                  "%Y-%m-%d"):
        try:
            when = time.strptime(text[:26] if "." in text else text[:len(text)], shape)
            return max(int((time.time() - time.mktime(when)) / 86400), 0)
        except (ValueError, OverflowError):
            continue
    try:
        return max(int((time.time() - time.mktime(time.strptime(text[:10], "%Y-%m-%d"))) / 86400), 0)
    except (ValueError, OverflowError):
        return None


def virustotal_domain(domain, key="", timeout=TIMEOUT):
    """How many vendors flag this domain."""
    if not key:
        return {"source": "VirusTotal", "ok": False, "known": False, "skipped": True,
                "why": "VirusTotal was skipped: no key was given."}
    request = urllib.request.Request(
        "https://www.virustotal.com/api/v3/domains/" + urllib.parse.quote(domain),
        headers={"User-Agent": AGENT, "x-apikey": key})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"source": "VirusTotal", "ok": True, "known": False,
                    "why": "VirusTotal has no record of this domain."}
        if exc.code == 401:
            return {"source": "VirusTotal", "ok": False, "known": False,
                    "why": "The VirusTotal key was refused."}
        if exc.code == 429:
            return {"source": "VirusTotal", "ok": False, "known": False, "quota": True,
                    "why": "The VirusTotal key's limit was reached."}
        return {"source": "VirusTotal", "ok": False, "known": False,
                "why": "VirusTotal answered %s." % exc.code}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"source": "VirusTotal", "ok": False, "known": False,
                "why": "VirusTotal did not answer (%s)." % getattr(exc, "reason", exc)}

    stats = (((data.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {})
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    total = sum(int(v or 0) for v in stats.values())
    result = {"source": "VirusTotal", "ok": True, "known": malicious > 0,
              "malicious": malicious, "suspicious": suspicious, "total": total}
    if malicious:
        result["why"] = ("%d of %d vendors on VirusTotal flag this domain."
                         % (malicious, total))
    elif suspicious:
        result["why"] = "%d vendors call this domain suspicious." % suspicious
    else:
        result["why"] = "No vendor on VirusTotal flags this domain."
    return result


# ---------------------------------------------------------------------------
def check_domain(domain, vt_key="", timeout=TIMEOUT, lookups=None):
    """Ask every source about one domain, then cross what they said."""
    lookups = lookups or {}
    results = []
    runner = lookups.get("blocklist") or blocklist
    for name, zone, test_name, refusals, meaning in BLOCKLISTS:
        results.append(runner(domain, name, zone, test_name, refusals, meaning, timeout))
    results.append((lookups.get("age") or age)(domain, timeout))
    results.append((lookups.get("virustotal") or virustotal_domain)(domain, vt_key, timeout))

    crossed = combine(domain, results)
    crossed["domain"] = domain
    crossed["sources"] = results
    return crossed


def combine(domain, results):
    """Cross the sources into one level and one sentence."""
    answered = [r for r in results if r.get("ok")]
    unusable = [r for r in results if r.get("unusable")]
    bad = [r for r in answered if r.get("known")]
    listed = [r for r in bad if r.get("source") in ("Spamhaus DBL", "SURBL", "VirusTotal")]
    fresh = next((r for r in answered
                  if r.get("source") == "How old it is" and r.get("known")), None)
    old = next((r for r in answered
                if r.get("source") == "How old it is" and r.get("benign")), None)

    if not answered:
        level = "unknown"
    elif listed and fresh:
        level = "certain"
    elif len(listed) >= 2:
        level = "listed"
    elif listed:
        level = "listed-once"
    elif fresh:
        level = "new"
    elif old:
        level = "established"
    else:
        level = "clean"

    return {"level": level, "answered": len(answered), "asked": len(results),
            "unusable": [r["source"] for r in unusable],
            "bad_count": len(bad),
            "bad_sources": [r["source"] for r in bad],
            "verdict": _verdict(level, domain, listed, fresh, old, answered),
            "weight": _weight(level)}


def _weight(level):
    """How much this should push the whole message's verdict, 0 to 3."""
    return {"certain": 3, "listed": 3, "listed-once": 2, "new": 2,
            "established": 0, "clean": 0, "unknown": 0}.get(level, 0)


def _verdict(level, domain, listed, fresh, old, answered):
    who = ", ".join(r["source"] for r in listed)

    if level == "unknown":
        return ("Could not check",
                "Nothing answered about %s, so this part tells you nothing either way." % domain)

    if level == "certain":
        return ("Almost certainly a phishing link",
                "%s is on a blocklist (%s) and was registered %d days ago. Those two together "
                "are not a judgement call: a real business does not register its domain last "
                "week, and a clean domain does not end up on a blocklist. Do not open it."
                % (domain, who, fresh.get("days", 0)))

    if level == "listed":
        return ("Known bad link",
                "%s is listed by %s. Two lists kept by different people agreeing means this is "
                "already known for phishing or malware, not a guess. Do not open it."
                % (domain, who))

    if level == "listed-once":
        return ("Reported link",
                "%s is listed by %s, and the other sources have nothing on it. One list is "
                "weaker than two agreeing, but it is still a reason not to click."
                % (domain, who))

    if level == "new":
        return ("Brand new domain",
                "%s was registered %d days ago and no blocklist has it yet. That is the normal "
                "state of a phishing domain in its first week: the lists have not caught up. "
                "Treat a new domain asking for money or a password as false until somebody you "
                "trust confirms it." % (domain, fresh.get("days", 0)))

    if level == "established":
        return ("Looks like the real thing",
                "%s has existed for years and no list has anything against it. That is what a "
                "real company's domain looks like." % domain)

    return ("Nothing known",
            "No list has anything against %s. That is worth something, but new phishing domains "
            "are unknown to every list on the day they are used, so it is not proof." % domain)


def check_all(links, vt_key="", timeout=TIMEOUT, limit=6, lookups=None):
    """Every domain worth asking about in one message, crossed."""
    domains = domains_in(links, limit=limit)
    return [check_domain(d, vt_key=vt_key, timeout=timeout, lookups=lookups)
            for d in domains]


def findings_for(reports):
    """Turn the crossed link answers into the (weight, sentence) pairs the rest
    of the tool speaks, so a bad link raises the whole message's verdict."""
    findings = []
    for report in reports:
        weight = report.get("weight", 0)
        if not weight:
            continue
        findings.append((weight, report["verdict"][1]))
    return findings
