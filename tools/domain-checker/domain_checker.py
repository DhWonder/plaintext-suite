#!/usr/bin/env python3
"""
domain-checker - can criminals send email pretending to be this business?

If a company's domain isn't set up correctly, a scammer can send email
that appears to come from them - "invoice from the boss", "new bank
details from accounts" - and it lands looking completely legitimate.
The protection is three DNS records with unfriendly names: SPF, DKIM and
DMARC. Most small businesses have never heard of them and don't have them.

This checks a domain for those records and explains, in plain English,
how exposed the business is - and what to do about it. I run it on every
new client's domain in the first ten minutes; it usually finds an easy,
high-value win.

Usage:
    python3 domain_checker.py example.com

It looks up public DNS records using an encrypted DNS-over-HTTPS request
to a public resolver, so it works on any machine with internet and needs
nothing installed. It only reads public records - nothing private.

DhWonder, Plaintext IT - MIT license.
"""

import json
import sys
import urllib.parse
import urllib.request

# A public DNS-over-HTTPS resolver. We ask it, over HTTPS, "what TXT
# records does this domain have?" - the same public info any mail server
# reads, just fetched in a way that works everywhere.
DOH_URL = "https://dns.google/resolve"
TIMEOUT = 15


def dns_txt(name):
    """Return the list of TXT record strings for a domain name."""
    query = urllib.parse.urlencode({"name": name, "type": "TXT"})
    url = "%s?%s" % (DOH_URL, query)
    req = urllib.request.Request(url, headers={"User-Agent": "mail-checker/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    records = []
    for answer in data.get("Answer", []):
        text = answer.get("data", "").strip()
        # DNS TXT values arrive wrapped in quotes; strip them.
        if text.startswith('"') and text.endswith('"'):
            text = text[1:-1]
        text = text.replace('" "', "")  # long records come in joined chunks
        records.append(text)
    return records


def check_spf(domain):
    """SPF says which servers are allowed to send mail for this domain."""
    try:
        records = dns_txt(domain)
    except Exception:
        return ("error", "couldn't look up records for this domain (is it spelled right?).")
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf:
        return ("missing",
                "No SPF record. Nothing tells the world which servers may send mail "
                "as this domain, so anyone can try. This is the first thing to fix.")
    record = spf[0]
    if "-all" in record:
        return ("good", "SPF is present and strict (-all) - unauthorised senders are told to fail. Good.")
    if "~all" in record:
        return ("weak", "SPF is present but soft (~all) - fakes are flagged, not rejected. "
                        "Fine as a step, stronger with -all once you're confident.")
    if "+all" in record.replace(" ", ""):
        return ("bad", "SPF exists but ends in +all, which literally means 'anyone may send as us'. "
                       "That's worse than nothing - fix immediately.")
    return ("weak", "SPF is present but doesn't clearly reject fakes. Worth tightening.")


def check_dmarc(domain):
    """DMARC ties SPF and DKIM together and says what to do with fakes -
    and can email the business a report of who's impersonating them."""
    try:
        records = dns_txt("_dmarc." + domain)
    except Exception:
        return ("error", "couldn't look up the DMARC record.")
    dmarc = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not dmarc:
        return ("missing",
                "No DMARC record. Even with SPF, nothing tells receiving mail servers "
                "what to DO with fakes, and the business gets no report of impersonation. "
                "This is the highest-value thing to add.")
    record = dmarc[0].lower()
    if "p=reject" in record:
        return ("good", "DMARC set to 'reject' - fakes are thrown away. This is the goal. Well done.")
    if "p=quarantine" in record:
        return ("weak", "DMARC set to 'quarantine' - fakes go to spam. Good; 'reject' is the final step.")
    if "p=none" in record:
        return ("weak", "DMARC is in 'none' mode - it only watches and reports, doesn't block yet. "
                        "A correct starting point; move to quarantine, then reject.")
    return ("weak", "DMARC exists but its policy is unclear. Worth a proper look.")


def check_dkim_hint(domain):
    """DKIM keys live at selector names we can't guess reliably, so we
    don't claim a false negative - we just note how to confirm it."""
    return ("info",
            "DKIM (which cryptographically signs your outgoing mail) can't be checked "
            "without knowing your mail provider's selector name. Confirm it inside your "
            "Google Workspace / Microsoft 365 admin panel - I do this during setup.")


def line(status, label, msg):
    tag = {"good": "GOOD", "weak": "OK-ish", "missing": "MISSING",
           "bad": "BAD", "error": "??", "info": "note"}[status]
    print("  [%-7s] %s: %s" % (tag, label, msg))


def main():
    if len(sys.argv) != 2:
        print(__doc__.strip())
        sys.exit(2)

    domain = sys.argv[1].strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0].lstrip("@")

    print("mail-checker - can someone forge email from %s ?" % domain)
    print("=" * 58)

    spf_status, spf_msg = check_spf(domain)
    dmarc_status, dmarc_msg = check_dmarc(domain)
    dkim_status, dkim_msg = check_dkim_hint(domain)

    line(spf_status, "SPF  ", spf_msg)
    line(dmarc_status, "DMARC", dmarc_msg)
    line(dkim_status, "DKIM ", dkim_msg)

    print("\n" + "-" * 58)
    # Verdict weighted mostly on DMARC, since it's what actually blocks fakes.
    if spf_status == "good" and dmarc_status == "good":
        print("Verdict: well protected. It's genuinely hard to forge mail from this domain.")
        sys.exit(0)
    elif dmarc_status == "missing" or spf_status in ("missing", "bad"):
        print("Verdict: EXPOSED. Someone could send email as this business today, and")
        print("the owner would never know. This is a fast, high-value fix - exactly the")
        print("kind of thing that makes a small business owner glad they called.")
        sys.exit(1)
    else:
        print("Verdict: partly protected. The pieces are started but not finished -")
        print("tightening them to reject fakes is a quick, worthwhile job.")
        sys.exit(1)


if __name__ == "__main__":
    main()
