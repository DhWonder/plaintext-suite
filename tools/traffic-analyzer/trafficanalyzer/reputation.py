"""
Asking VirusTotal whether a hostile address is already known to be bad.

The analyser works out who is flooding you from the traffic alone: the rate, the
flags, the spread of ports, whether anyone answered back. That judgement stands
on its own and needs no internet. This part adds one more thing on top of it, and
only when you ask for it: has anybody else already reported this address.

An address that is hammering you AND is flagged by forty vendors as a known
attacker is a different conversation from one that merely looks busy. That is all
this does. It does not change the score. It corroborates it, or it fails to, and
either way it says which.

WHAT LEAVES YOUR MACHINE

  The address, and nothing else. Sending an IP to VirusTotal tells VirusTotal you
  are looking at that IP. For an address that is already attacking you that is a
  fair trade, but it is still a thing that leaves, so it is off until you pass a
  key, and it only ever asks about the handful of sources the analyser already
  flagged, never every address in the capture.

THE FREE KEY IS SMALL

  Four lookups a minute, five hundred a day. You cannot check every source in a
  big capture and this tool will not try. It asks about the flagged ones, pauses
  between calls to stay inside the four-a-minute limit, remembers every answer in
  the database so a second run costs nothing, and stops and says so if the daily
  budget runs out. A tool that silently checked half the list would be worse than
  one that checked none.

Standard library only. The file is never involved here; this is addresses.
"""

import json
import time
import urllib.error
import urllib.request

TIMEOUT = 15
AGENT = "traffic-analyzer (plaintext IT)"

# The free tier. Kept here so the messaging and the pacing agree with each other.
FREE_PER_MINUTE = 4
FREE_PER_DAY = 500

# How long a cached answer is trusted before it is looked up again. Reputation
# moves, but slowly, and re-asking daily would burn the budget on addresses that
# have not changed. A week is a reasonable memory.
DEFAULT_MAX_AGE = 7 * 24 * 3600


def virustotal_ip(ip, key="", timeout=TIMEOUT):
    """Ask VirusTotal about one address. Returns a flat dict, never raises."""
    if not key:
        return {"source": "VirusTotal", "ok": False, "known": False, "skipped": True,
                "error": "no key supplied, so this was skipped"}

    request = urllib.request.Request(
        "https://www.virustotal.com/api/v3/ip_addresses/" + ip,
        headers={"User-Agent": AGENT, "x-apikey": key})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            # VirusTotal has never been asked about this address before.
            return {"source": "VirusTotal", "ok": True, "known": False, "unseen": True}
        if exc.code == 401:
            return {"source": "VirusTotal", "ok": False, "known": False,
                    "error": "the key was refused"}
        if exc.code == 429:
            # Either the four-a-minute pace or the daily budget. Either way, stop.
            return {"source": "VirusTotal", "ok": False, "known": False, "quota": True,
                    "error": "the free key's limit was reached"}
        return {"source": "VirusTotal", "ok": False, "known": False,
                "error": "answered %s" % exc.code}
    except (urllib.error.URLError, OSError) as exc:
        return {"source": "VirusTotal", "ok": False, "known": False,
                "error": str(getattr(exc, "reason", exc))}

    try:
        data = json.loads(body)
    except ValueError:
        return {"source": "VirusTotal", "ok": False, "known": False,
                "error": "unreadable answer"}

    attributes = (data.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    total = sum(int(v or 0) for v in stats.values())

    asn = attributes.get("asn")
    return {
        "source": "VirusTotal",
        "ok": True,
        "known": malicious > 0,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "total": total,
        "reputation": int(attributes.get("reputation", 0) or 0),
        "country": attributes.get("country", "") or "",
        "asn": str(asn) if asn is not None else "",
        "as_owner": attributes.get("as_owner", "") or "",
        "checked_at": time.time(),
    }


def verdict(result):
    """A short headline and one sentence, in the same plain voice as the rest."""
    if result.get("skipped"):
        return ("Not checked", "No key was given, so this address was not looked up.")
    if result.get("quota"):
        return ("Not checked",
                "The free key's limit was reached before this address, so it was not looked up. "
                "The traffic-based judgement above still stands on its own.")
    if not result.get("ok"):
        return ("Could not check",
                "VirusTotal did not answer for this one (%s). The traffic-based judgement above "
                "still stands." % result.get("error", "no answer"))

    where = _place(result)
    tail = (", " + where) if where else ""    # folds in before a full stop

    if result.get("known"):
        n = result["malicious"]
        total = result.get("total", 0)
        extra = (" and %d suspicious" % result["suspicious"]) if result.get("suspicious") else ""
        return ("Known bad",
                "%d of %d security vendors call this address malicious%s%s. This is not just busy "
                "traffic: somebody has already reported this address for attacks."
                % (n, total, extra, tail))
    if result.get("suspicious"):
        return ("Reported suspicious",
                "No vendor calls it outright malicious, but %d flag it as suspicious%s. Worth "
                "weighing with the traffic below." % (result["suspicious"], tail))
    if result.get("unseen"):
        return ("New to VirusTotal",
                "Nobody has ever asked VirusTotal about this address%s. That is common for a fresh "
                "attacker: it means unknown, not safe. Judge it on the traffic." % tail)
    return ("Not reported",
            "No vendor currently flags this address%s. That is worth less than it sounds for a "
            "source that is misbehaving right now, so judge it on the traffic above." % tail)


def _place(result):
    """A short 'in Country, on ASxxx (owner)' clause, if we have the pieces."""
    bits = []
    if result.get("country"):
        bits.append("in " + result["country"])
    if result.get("asn"):
        owner = result.get("as_owner")
        bits.append("on AS%s%s" % (result["asn"], (" (%s)" % owner) if owner else ""))
    return (", ".join(bits)) if bits else ""


class Checker(object):
    """Enrich a set of addresses, using the cache first and the network sparingly.

    Give it the key and (optionally) the Store to cache in. Call enrich() with the
    addresses you actually care about, which for this tool is the flagged sources,
    not the whole capture. It returns {ip: result} and keeps a tally of how the
    answers were obtained so the report can be honest about coverage.
    """

    def __init__(self, key="", store=None, pause=None, per_minute=FREE_PER_MINUTE,
                 daily_cap=FREE_PER_DAY, max_age=DEFAULT_MAX_AGE, lookup=None,
                 is_public=None):
        self.key = key
        self.store = store
        self.per_minute = max(1, per_minute)
        # Pace live calls to stay inside the per-minute limit. Overridable so the
        # tests do not sit and sleep.
        self.pause = pause if pause is not None else (60.0 / self.per_minute)
        self.daily_cap = daily_cap
        self.max_age = max_age
        self._lookup = lookup or (lambda ip: virustotal_ip(ip, self.key))
        self._is_public = is_public or (lambda ip: True)

        self.from_cache = 0
        self.looked_up = 0
        self.skipped_private = 0
        self.skipped_quota = 0
        self.quota_hit = False

    def enrich(self, ips, progress=None):
        results = {}
        live_calls = 0
        # De-duplicate while keeping order, so the same address in the list is one call.
        seen = []
        for ip in ips:
            if ip not in results and ip not in seen:
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
                results[ip] = {"source": "VirusTotal", "ok": False, "known": False,
                               "quota": True, "error": "the free key's daily budget was reached"}
                continue

            # Pace the live calls. The first goes straight through; each one after
            # it waits so four-a-minute is never exceeded.
            if live_calls and self.pause:
                time.sleep(self.pause)
            if progress:
                progress(ip, live_calls + 1)

            result = self._lookup(ip)
            live_calls += 1
            self.looked_up += 1

            if result.get("quota"):
                # The key is spent for now. Do not keep hammering it.
                self.quota_hit = True
                self.skipped_quota += 1
                results[ip] = result
                continue

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
            parts.append("%d not checked because the free key's limit was reached" % self.skipped_quota)
        if self.skipped_private:
            parts.append("%d skipped as local addresses" % self.skipped_private)
        return ", ".join(parts)
