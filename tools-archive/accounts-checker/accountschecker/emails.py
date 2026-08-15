"""
Has this email address turned up in a data breach?

Worth being straight about the difference between this and the password check.
A password can be checked without revealing it, because only five characters
of a fingerprint get sent. An email address cannot: to ask whether an address
appears in a breach, somebody has to be told the address.

So this tool never checks an address unless you have said yes to that, and it
names exactly which services it is about to ask. Checking your own address is
fine. Checking a client's address is something to have agreed with the client
first, and checking a stranger's is not your business.

Three sources, because no single one is complete:

  XposedOrNot   free, no account needed
  LeakCheck     free tier, no account needed, tells you which sites
  Have I Been Pwned   the best of them, but the address lookup needs a paid
                      key. Supply one with --hibp-key and it gets used.

None of them see anything except the address you asked about.
"""

import json
import re
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 12
AGENT = "accounts-checker (plaintext IT)"

SOURCES = [
    ("XposedOrNot", "free, no account needed"),
    ("LeakCheck", "free tier, names the sites"),
    ("Have I Been Pwned", "needs a paid key, skipped without one"),
]

VALID = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


def looks_like_email(text):
    return bool(VALID.match((text or "").strip()))


def _get(url, headers=None, timeout=TIMEOUT):
    request = urllib.request.Request(url, headers=dict({"User-Agent": AGENT}, **(headers or {})))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return exc.code, body
    except (urllib.error.URLError, OSError) as exc:
        return None, str(getattr(exc, "reason", exc))


# ---------------------------------------------------------------------------
def check_xposedornot(email, timeout=TIMEOUT):
    status, body = _get("https://api.xposedornot.com/v1/check-email/"
                        + urllib.parse.quote(email), timeout=timeout)
    if status is None:
        return {"source": "XposedOrNot", "ok": False, "error": body, "breaches": []}
    if status == 404:
        return {"source": "XposedOrNot", "ok": True, "breaches": []}
    if status != 200:
        return {"source": "XposedOrNot", "ok": False,
                "error": "answered %s" % status, "breaches": []}
    try:
        data = json.loads(body)
    except ValueError:
        return {"source": "XposedOrNot", "ok": False, "error": "unreadable answer", "breaches": []}

    found = []
    breaches = data.get("breaches") or []
    if breaches and isinstance(breaches[0], list):
        found = [str(name) for name in breaches[0]]
    elif breaches:
        found = [str(name) for name in breaches]
    return {"source": "XposedOrNot", "ok": True, "breaches": found}


def check_leakcheck(email, timeout=TIMEOUT):
    status, body = _get("https://leakcheck.io/api/public?check="
                        + urllib.parse.quote(email), timeout=timeout)
    if status is None:
        return {"source": "LeakCheck", "ok": False, "error": body, "breaches": []}
    if status == 429:
        return {"source": "LeakCheck", "ok": False,
                "error": "asked too often, try again in a minute", "breaches": []}
    if status != 200:
        return {"source": "LeakCheck", "ok": False, "error": "answered %s" % status, "breaches": []}
    try:
        data = json.loads(body)
    except ValueError:
        return {"source": "LeakCheck", "ok": False, "error": "unreadable answer", "breaches": []}

    if not data.get("success"):
        # A miss is reported as success:false with "Not found", which is an answer.
        message = str(data.get("error", "")).lower()
        if "not found" in message:
            return {"source": "LeakCheck", "ok": True, "breaches": []}
        return {"source": "LeakCheck", "ok": False,
                "error": data.get("error", "no answer"), "breaches": []}

    names = []
    for source in data.get("sources", []):
        if isinstance(source, dict):
            name = source.get("name", "")
            date = source.get("date", "")
            names.append("%s%s" % (name, " (%s)" % date if date else ""))
        else:
            names.append(str(source))
    return {"source": "LeakCheck", "ok": True, "breaches": names,
            "found": int(data.get("found", 0) or 0)}


def check_hibp(email, key, timeout=TIMEOUT):
    if not key:
        return {"source": "Have I Been Pwned", "ok": False, "skipped": True,
                "error": "no key supplied, so this one was skipped", "breaches": []}
    status, body = _get(
        "https://haveibeenpwned.com/api/v3/breachedaccount/"
        + urllib.parse.quote(email) + "?truncateResponse=false",
        headers={"hibp-api-key": key}, timeout=timeout)
    if status is None:
        return {"source": "Have I Been Pwned", "ok": False, "error": body, "breaches": []}
    if status == 404:
        return {"source": "Have I Been Pwned", "ok": True, "breaches": []}
    if status == 401:
        return {"source": "Have I Been Pwned", "ok": False,
                "error": "the key was refused", "breaches": []}
    if status == 429:
        return {"source": "Have I Been Pwned", "ok": False,
                "error": "rate limited, wait a moment", "breaches": []}
    if status != 200:
        return {"source": "Have I Been Pwned", "ok": False,
                "error": "answered %s" % status, "breaches": []}
    try:
        data = json.loads(body)
    except ValueError:
        return {"source": "Have I Been Pwned", "ok": False,
                "error": "unreadable answer", "breaches": []}

    names, detail = [], []
    for item in data:
        name = item.get("Name") or item.get("Title") or "unnamed"
        when = (item.get("BreachDate") or "")[:4]
        names.append("%s%s" % (name, " (%s)" % when if when else ""))
        detail.append({
            "name": name,
            "date": item.get("BreachDate", ""),
            "accounts": item.get("PwnCount", 0),
            "data": item.get("DataClasses", []),
        })
    return {"source": "Have I Been Pwned", "ok": True, "breaches": names, "detail": detail}


# ---------------------------------------------------------------------------
def check(email, hibp_key="", timeout=TIMEOUT):
    """Ask every source we can and gather the answers into one picture."""
    email = (email or "").strip().lower()
    results = [
        check_xposedornot(email, timeout),
        check_leakcheck(email, timeout),
        check_hibp(email, hibp_key, timeout),
    ]

    every = []
    for result in results:
        for name in result.get("breaches", []):
            if name not in every:
                every.append(name)

    answered = [r for r in results if r.get("ok")]
    exposed_types = []
    for result in results:
        for item in result.get("detail", []):
            for kind in item.get("data", []):
                if kind not in exposed_types:
                    exposed_types.append(kind)

    return {
        "email": email,
        "sources": results,
        "breaches": every,
        "answered": len(answered),
        "asked": len(results),
        "exposed_types": exposed_types,
        "verdict": verdict(every, answered, results),
    }


def verdict(breaches, answered, results):
    if not answered:
        return ("Could not check",
                "None of the breach databases answered. That is a problem with reaching them, not "
                "an all clear. Try again in a minute.")
    if not breaches:
        skipped = [r for r in results if r.get("skipped")]
        body = ("This address does not appear in the breach data the free sources hold. That is "
                "reassuring, but it is not proof: breaches are found and published years after "
                "they happen, and the most complete database charges for address lookups.")
        if skipped:
            body += (" Have I Been Pwned was skipped because no key was supplied, and it is the "
                     "one most likely to know.")
        return ("Nothing found", body)

    count = len(breaches)
    return ("Found in %d breach%s" % (count, "" if count == 1 else "es"),
            "This address is in published breach data. That does not mean an account is broken "
            "into. It means attackers have the address, and usually a password that went with it "
            "at the time. What matters now: any password reused from those sites should be "
            "changed, and two step login should be on for email, banking and anything that pays "
            "money.")
