"""
What everybody else thinks of this domain, crossed.

domain_checker.py answers one question: can somebody send email pretending to
be this business. This answers the two next ones, which turn out to matter just
as much to somebody who runs on email:

  Is this domain on a blocklist right now?  If it is, the business is not
  being impersonated, it is being rejected. Their mail is silently going
  nowhere and they usually have no idea. That is a different emergency from a
  missing DMARC record and it needs saying differently.

  How old is it?  A domain registered last week, in a message asking for
  money, is the strongest single signal there is. Useful when you are checking
  a supplier's domain rather than a client's own.

WHY CROSS THEM

Because one blocklist is a rumour and two that agree are a finding. And because
the combinations say more than the parts: a domain that is both brand new and
already listed is not a business with a configuration problem. A domain that is
fifteen years old and on no list is almost certainly the real company, whatever
else looks odd about the message that mentioned it.

WHO GETS ASKED

  Spamhaus DBL   free, over DNS. The list most mail servers actually consult,
                 so a hit here is the one that is costing them delivery today.
  SURBL          free, over DNS. A second list, kept by different people.
  How old it is  free, over RDAP, which is what replaced WHOIS.
  VirusTotal     needs a free key. How many vendors flag the domain.

WHAT LEAVES YOUR MACHINE

  The domain name, and nothing else. It is already public, and these are the
  same lookups a mail server does when it decides whether to accept a message.
  Nothing here opens a website or fetches a page.
"""

import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 12
AGENT = "domain-checker (plaintext IT)"
DOH_URL = "https://dns.google/resolve"

# Answers inside 127.0.0.0/8 that mean "I will not answer you" rather than
# "this is listed". Reading one of these as a hit would accuse an innocent
# domain, which is the worse of the two mistakes.
#
# These are per list rather than one shared set, because the same number means
# different things to different lists: 127.0.0.1 is a refusal to SURBL and a
# perfectly valid listing type to DroneBL. A shared set would have quietly
# marked a working list as unusable.
SPAMHAUS_REFUSALS = {
    "127.255.255.252",  # typing error in the query
    "127.255.255.253",  # query through an open resolver
    "127.255.255.254",  # query through a public resolver
    "127.255.255.255",  # volume limit exceeded
}
SURBL_REFUSALS = {
    "127.0.0.1",        # blocked
    "127.0.0.254",      # blocked, usually a public resolver
}

# Each list, its published test point, its refusal codes, and what a hit means.
#
# The test point column is there because of a trap worth understanding. Every
# one of these lists refuses queries that arrive through a big public resolver,
# Google and Cloudflare among them, because they sell access to high volume
# users. A refused query comes back looking exactly like "this domain is not
# listed". So a tool that just asks and believes the answer reports every
# domain as clean, for ever, and sounds completely confident doing it.
#
# So before trusting a "not listed" we ask the list's own test point, which is
# published precisely so anybody can prove the lookup path works. If the test
# point does not come back listed, this machine cannot use this list, and the
# honest answer is "could not check" rather than a clean bill of health.
BLOCKLISTS = [
    ("Spamhaus DBL", "dbl.spamhaus.org", "dbltest.com", SPAMHAUS_REFUSALS,
     "Spamhaus lists this domain. Most mail servers consult Spamhaus, so mail "
     "from here is being rejected or filed as spam right now"),
    ("SURBL", "multi.surbl.org", "test", SURBL_REFUSALS,
     "SURBL lists this domain, which means it has been seen in spam or phishing "
     "messages"),
]

VERY_NEW_DAYS = 30
NEW_DAYS = 180


# ---------------------------------------------------------------------------
# One source at a time. Same shape from each, and none of them raise.
# ---------------------------------------------------------------------------
def _resolve(name, timeout=TIMEOUT):
    """Ask this machine's own resolver for a name's addresses.

    The machine's own resolver, not a public one, on purpose: the lists block
    the public ones. At a client site this is usually their router or their
    ISP, which is exactly the path their mail server uses, so the answer we get
    is the answer their mail is getting.

    Returns a list of addresses, or None when the name does not exist.
    """
    previous = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname_ex(name)[2]
    except socket.gaierror:
        return None                      # no such name: for a blocklist, not listed
    except OSError:
        return None
    finally:
        socket.setdefaulttimeout(previous)


# Whether a list answered its own test point. Worked out once per run and
# remembered, because it is the same answer for every domain we then ask about.
_usable_cache = {}


def _list_usable(zone, test_name, refusals, timeout=TIMEOUT, resolver=None):
    """Does this list actually answer us? Ask its published test point."""
    if zone in _usable_cache:
        return _usable_cache[zone]

    resolver = resolver or _resolve
    answers = resolver("%s.%s" % (test_name, zone), timeout) or []
    good = [a for a in answers if a.startswith("127.") and a not in refusals]
    _usable_cache[zone] = bool(good)
    return _usable_cache[zone]


def blocklist(domain, name, zone, test_name, refusals, meaning,
              timeout=TIMEOUT, resolver=None):
    """A domain blocklist, asked the way a mail server asks."""
    resolver = resolver or _resolve

    if not _list_usable(zone, test_name, refusals, timeout, resolver):
        return {"source": name, "ok": False, "known": False, "unusable": True,
                "why": ("%s would not answer its own test lookup from this machine. "
                        "These lists refuse queries that come through a big public "
                        "resolver, so this says nothing about the domain - point this "
                        "machine at your own or your ISP's resolver and ask again."
                        % name)}

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
    """How long this domain has existed, over RDAP. No key, no account."""
    url = "https://rdap.org/domain/" + urllib.parse.quote(domain)
    request = urllib.request.Request(url, headers={"User-Agent": AGENT,
                                                   "Accept": "application/rdap+json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"source": "How old it is", "ok": True, "known": False,
                    "why": "No registration record exists for this domain at all."}
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
        result["why"] = ("Registered %d day%s ago. A business you already deal with has had "
                         "its domain for years." % (days, "" if days == 1 else "s"))
    elif days <= NEW_DAYS:
        result["why"] = ("About %d months old. Young enough to notice, not damning on its own."
                         % max(days // 30, 1))
    else:
        years = days / 365.0
        result["benign"] = True
        result["why"] = ("Registered %s ago, which is what a real business looks like."
                         % (("%.0f years" % years) if years >= 2 else "about a year"))
    return result


def _days_since(text):
    for shape in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S",
                  "%Y-%m-%d"):
        try:
            parsed = time.strptime(text[:26] if "." in text else text, shape)
            return max(int((time.time() - time.mktime(parsed)) / 86400), 0)
        except (ValueError, OverflowError):
            continue
    try:
        return max(int((time.time() -
                        time.mktime(time.strptime(text[:10], "%Y-%m-%d"))) / 86400), 0)
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
            return {"source": "VirusTotal", "ok": False, "known": False,
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
        result["why"] = "%d of %d vendors on VirusTotal flag this domain." % (malicious, total)
    elif suspicious:
        result["why"] = "%d vendors call this domain suspicious." % suspicious
    else:
        result["why"] = "No vendor on VirusTotal flags this domain."
    return result


# ---------------------------------------------------------------------------
def check(domain, vt_key="", timeout=TIMEOUT, lookups=None):
    """Ask every source about the domain, then cross what they said."""
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
    """Cross the sources into one level and one thing to say about it."""
    answered = [r for r in results if r.get("ok")]
    unusable = [r for r in results if r.get("unusable")]
    listed = [r for r in answered
              if r.get("known") and r.get("source") != "How old it is"]
    fresh = next((r for r in answered
                  if r.get("source") == "How old it is" and r.get("known")), None)
    old = next((r for r in answered
                if r.get("source") == "How old it is" and r.get("benign")), None)

    if not answered:
        level = "unknown"
    elif listed and fresh:
        level = "throwaway"
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
            "listed_by": [r["source"] for r in listed],
            "verdict": _verdict(level, domain, listed, fresh, old, answered, unusable)}


def _verdict(level, domain, listed, fresh, old, answered, unusable=None):
    who = ", ".join(r["source"] for r in listed)
    unusable = unusable or []

    # A clean answer is only worth saying if somebody was actually able to
    # answer. With the blocklists refusing us, "nothing against it" would be a
    # claim resting on nothing, which is exactly the kind of confident wrong
    # answer this tool exists not to give.
    if level in ("established", "clean") and unusable:
        names = ", ".join(r["source"] for r in unusable)
        tail = ""
        if old:
            tail = (" What we could check: it was %s."
                    % old.get("why", "").lower().rstrip("."))
        return ("Blocklists could not be checked",
                "%s could not be asked from this machine, so nothing here says whether %s "
                "is listed.%s To get a real answer, run this where the machine uses its own "
                "or its ISP's resolver rather than a public one."
                % (names, domain, tail))

    if level == "unknown":
        return ("Could not check",
                "Nothing answered about %s, so this part tells you nothing either way. "
                "The SPF and DMARC findings above still stand on their own." % domain)

    if level == "throwaway":
        return ("A throwaway domain",
                "%s is on a blocklist (%s) and was registered %d days ago. That combination "
                "is not a business with a configuration problem, it is a domain set up to "
                "send something nobody wants. If a client is receiving mail from here, treat "
                "it as hostile." % (domain, who, fresh.get("days", 0)))

    if level == "listed":
        return ("Blocklisted, so mail is being rejected",
                "%s is listed by %s. Two lists kept by different people agree, so this is not "
                "a guess. If this is your client's own domain, their mail is being rejected or "
                "filed as spam right now and they probably do not know. That is a more urgent "
                "conversation than the records above: find out what was sent from here, get it "
                "stopped, then request delisting." % (domain, who))

    if level == "listed-once":
        return ("On one blocklist",
                "%s is listed by %s, and the other sources have nothing against it. One list "
                "is weaker than two agreeing, but if this is your client's own domain it is "
                "still worth finding out why before it spreads to the others."
                % (domain, who))

    if level == "new":
        return ("Registered very recently",
                "%s was registered %d days ago and no blocklist has it yet. For a domain you "
                "were asked to trust, that is the state a phishing domain is in during its "
                "first week: the lists have not caught up. For a client's brand new domain it "
                "is simply new, and the records above are what matter."
                % (domain, fresh.get("days", 0)))

    if level == "established":
        return ("Nothing against it",
                "%s has existed for years and no list has anything against it. Mail from here "
                "should be delivering normally, so the records above are the whole story."
                % domain)

    return ("Nothing known",
            "No list has anything against %s. That is worth something, but a new domain is "
            "unknown to every list on the day it is used, so it is not proof." % domain)
