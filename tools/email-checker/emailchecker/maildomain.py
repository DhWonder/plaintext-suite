"""
Can email be forged from the sender's own domain?

This is the other half of judging a message. The body checks ask "does this look
like a scam". This asks a flatter question about the domain the mail claims to
come from: is that domain even protected against being impersonated?

It matters both ways. If the claimed sender is a domain with no SPF and no
DMARC, anyone could have sent this and it would look real, so a suspicious
message is more likely to be a genuine forgery. If the domain is locked down
with DMARC reject, a perfect forgery is hard, which makes a suspicious message
more likely to be a lookalike domain instead - a different problem with a
different answer.

It reads three public DNS records over an encrypted DNS-over-HTTPS request, the
same public information any mail server reads. Nothing private is sent, and the
only thing that leaves is the domain name being asked about.

Adapted from the standalone mail-checker, which does the same for your own domain.
"""

import json
import urllib.parse
import urllib.request

DOH_URL = "https://dns.google/resolve"
TIMEOUT = 12
AGENT = "email-checker (plaintext IT)"


def dns_txt(name, timeout=TIMEOUT):
    query = urllib.parse.urlencode({"name": name, "type": "TXT"})
    request = urllib.request.Request("%s?%s" % (DOH_URL, query),
                                     headers={"User-Agent": AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.loads(response.read().decode("utf-8", "replace"))
    records = []
    for answer in data.get("Answer", []):
        text = answer.get("data", "").strip()
        if text.startswith('"') and text.endswith('"'):
            text = text[1:-1]
        records.append(text.replace('" "', ""))
    return records


def check_spf(domain, timeout=TIMEOUT):
    try:
        records = dns_txt(domain, timeout)
    except Exception:
        return ("error", "could not look up this domain (is it spelled right?)")
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf:
        return ("missing", "No SPF record. Nothing says which servers may send mail as this "
                           "domain, so anyone can try.")
    record = spf[0]
    if "-all" in record:
        return ("good", "SPF is present and strict (-all): unauthorised senders are told to fail.")
    if "~all" in record:
        return ("weak", "SPF is present but soft (~all): fakes are flagged, not rejected.")
    if "+all" in record.replace(" ", ""):
        return ("bad", "SPF ends in +all, which means 'anyone may send as us'. Worse than nothing.")
    return ("weak", "SPF is present but does not clearly reject fakes.")


def check_dmarc(domain, timeout=TIMEOUT):
    try:
        records = dns_txt("_dmarc." + domain, timeout)
    except Exception:
        return ("error", "could not look up the DMARC record.")
    dmarc = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not dmarc:
        return ("missing", "No DMARC record. Nothing tells receiving servers what to DO with "
                           "fakes, and the domain owner gets no report of impersonation.")
    record = dmarc[0].lower()
    if "p=reject" in record:
        return ("good", "DMARC is set to reject: forgeries are thrown away. This is the goal.")
    if "p=quarantine" in record:
        return ("weak", "DMARC is set to quarantine: forgeries go to spam. Good; reject is the last step.")
    if "p=none" in record:
        return ("weak", "DMARC is in 'none' mode: it only watches and reports, it does not block yet.")
    return ("weak", "DMARC exists but its policy is unclear.")


def check_dkim_hint():
    return ("info", "DKIM cannot be checked from outside without the mail provider's selector "
                    "name, so it is neither confirmed nor denied here.")


def check(domain, timeout=TIMEOUT):
    """The forgeability of one domain, gathered into one picture."""
    domain = (domain or "").strip().lower().lstrip("@")
    if not domain or "." not in domain:
        return {"domain": domain, "checked": False,
                "verdict": ("No domain to check", "The message had no usable sender domain.")}

    spf_status, spf_msg = check_spf(domain, timeout)
    dmarc_status, dmarc_msg = check_dmarc(domain, timeout)
    dkim_status, dkim_msg = check_dkim_hint()

    if spf_status == "error" and dmarc_status == "error":
        return {"domain": domain, "checked": False,
                "spf": {"status": spf_status, "message": spf_msg},
                "dmarc": {"status": dmarc_status, "message": dmarc_msg},
                "dkim": {"status": dkim_status, "message": dkim_msg},
                "verdict": ("Could not check the domain",
                            "The DNS lookup did not answer. That is a reachability problem, not "
                            "an all clear.")}

    forgeable = dmarc_status in ("missing", "weak", "bad") or spf_status in ("missing", "bad")
    return {
        "domain": domain,
        "checked": True,
        "spf": {"status": spf_status, "message": spf_msg},
        "dmarc": {"status": dmarc_status, "message": dmarc_msg},
        "dkim": {"status": dkim_status, "message": dkim_msg},
        "forgeable": forgeable,
        "verdict": verdict(domain, spf_status, dmarc_status),
    }


def verdict(domain, spf_status, dmarc_status):
    if spf_status == "good" and dmarc_status == "good":
        return ("Hard to forge",
                "%s is well protected: a perfect forgery of its address is genuinely hard, so a "
                "suspicious message claiming to be from it is more likely a lookalike domain than "
                "the real one impersonated. Check the sending address character by character."
                % domain)
    if dmarc_status == "missing" or spf_status in ("missing", "bad"):
        return ("Easy to forge",
                "%s is missing the records that stop impersonation, so anyone could send mail that "
                "appears to come from it and it would look real. If this message is a scam, it may "
                "well be a genuine forgery of the real address." % domain)
    return ("Partly protected",
            "%s has started but not finished its anti-forgery setup, so impersonation is harder "
            "than nothing but not blocked." % domain)
