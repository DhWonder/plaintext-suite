"""
Asking the malware databases whether anyone has seen this file before.

The important thing here is what gets sent, so it is worth stating plainly:
only the fingerprint leaves. A SHA-256 is a one way summary of the contents. It
cannot be turned back into the file, it reveals nothing about what is inside,
and it is the standard way these lookups are done.

The file itself is never uploaded. That matters because a client's attachment
may be a genuine invoice with their customers' details in it, and uploading
that to a public analysis service publishes it. Several well known tools do
exactly that by default. This one will not do it at all.

Two databases:

  MalwareBazaar (abuse.ch)   free. Run by researchers, holds samples that have
                             been seen in the wild and names the family.
  VirusTotal                 needs a free API key. Tells you how many of about
                             seventy scanners consider it malicious.

A miss means nobody has reported this exact file. It does not mean the file is
safe: malware is usually rebuilt for each campaign, so a fresh one is unknown
to everybody on its first day. That is why the offline structural check
matters more than this does.
"""

import json
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 15
AGENT = "file-checker (plaintext IT)"


def check(sha256, vt_key="", mb_key="", timeout=TIMEOUT):
    results = [malware_bazaar(sha256, mb_key, timeout)]
    results.append(virustotal(sha256, vt_key, timeout))

    known = [r for r in results if r.get("known")]
    answered = [r for r in results if r.get("ok")]
    return {
        "sha256": sha256,
        "sources": results,
        "known_bad": bool(known),
        "answered": len(answered),
        "verdict": _verdict(known, answered, results),
    }


def _verdict(known, answered, results):
    if known:
        names = []
        for result in known:
            if result.get("family"):
                names.append(result["family"])
        detail = (" It is known as %s." % ", ".join(sorted(set(names)))) if names else ""
        return ("Known malware",
                "This exact file is in a malware database.%s There is nothing to weigh up: do not "
                "open it, and if anybody already did, that machine needs looking at today."
                % detail)
    if not answered:
        return ("Could not check",
                "Neither database answered, so this part tells you nothing either way. The "
                "findings above were worked out here and still stand.")
    return ("Not known to the databases",
            "Nobody has reported this exact file. That is worth less than it sounds: malware is "
            "usually rebuilt for every campaign, so a new one is unknown to every database on the "
            "day it is sent. Judge it on what it is, above, not on this.")


# ---------------------------------------------------------------------------
def malware_bazaar(sha256, key="", timeout=TIMEOUT):
    payload = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode()
    headers = {"User-Agent": AGENT, "Content-Type": "application/x-www-form-urlencoded"}
    if key:
        headers["Auth-Key"] = key
    request = urllib.request.Request("https://mb-api.abuse.ch/api/v1/", data=payload,
                                     headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return {"source": "MalwareBazaar", "ok": False, "known": False,
                    "error": "needs a free account key now, pass it with --mb-key"}
        return {"source": "MalwareBazaar", "ok": False, "known": False,
                "error": "answered %s" % exc.code}
    except (urllib.error.URLError, OSError) as exc:
        return {"source": "MalwareBazaar", "ok": False, "known": False,
                "error": str(getattr(exc, "reason", exc))}

    try:
        data = json.loads(body)
    except ValueError:
        return {"source": "MalwareBazaar", "ok": False, "known": False,
                "error": "unreadable answer"}

    status = data.get("query_status", "")
    if status == "hash_not_found":
        return {"source": "MalwareBazaar", "ok": True, "known": False}
    if status in ("illegal_hash", "no_hash_provided"):
        return {"source": "MalwareBazaar", "ok": False, "known": False,
                "error": "the fingerprint was rejected"}
    if status == "unauthorized" or status == "unauthenticated":
        return {"source": "MalwareBazaar", "ok": False, "known": False,
                "error": "needs a free account key now, pass it with --mb-key"}
    if status != "ok":
        return {"source": "MalwareBazaar", "ok": False, "known": False,
                "error": status or "no answer"}

    items = data.get("data") or []
    first = items[0] if items else {}
    return {
        "source": "MalwareBazaar",
        "ok": True,
        "known": True,
        "family": first.get("signature") or "",
        "first_seen": first.get("first_seen", ""),
        "file_type": first.get("file_type", ""),
        "tags": first.get("tags") or [],
    }


def virustotal(sha256, key="", timeout=TIMEOUT):
    if not key:
        return {"source": "VirusTotal", "ok": False, "known": False, "skipped": True,
                "error": "no key supplied, so this one was skipped"}
    request = urllib.request.Request(
        "https://www.virustotal.com/api/v3/files/" + sha256,
        headers={"User-Agent": AGENT, "x-apikey": key})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"source": "VirusTotal", "ok": True, "known": False}
        if exc.code == 401:
            return {"source": "VirusTotal", "ok": False, "known": False,
                    "error": "the key was refused"}
        if exc.code == 429:
            return {"source": "VirusTotal", "ok": False, "known": False,
                    "error": "asked too often, the free key allows four a minute"}
        return {"source": "VirusTotal", "ok": False, "known": False,
                "error": "answered %s" % exc.code}
    except (urllib.error.URLError, OSError) as exc:
        return {"source": "VirusTotal", "ok": False, "known": False,
                "error": str(getattr(exc, "reason", exc))}

    try:
        data = json.loads(body)
    except ValueError:
        return {"source": "VirusTotal", "ok": False, "known": False, "error": "unreadable answer"}

    stats = (((data.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {})
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    total = sum(int(v or 0) for v in stats.values()) or 0
    attributes = ((data.get("data") or {}).get("attributes") or {})
    names = attributes.get("popular_threat_classification") or {}
    family = ""
    if isinstance(names, dict):
        family = names.get("suggested_threat_label", "") or ""

    return {
        "source": "VirusTotal",
        "ok": True,
        "known": malicious > 0,
        "malicious": malicious,
        "suspicious": suspicious,
        "total": total,
        "family": family,
    }
