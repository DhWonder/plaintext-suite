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
    python3 domain_checker.py example.com --reputation
    python3 domain_checker.py example.com --notify
    python3 domain_checker.py example.com --dkim-selector myselector

It probes a short list of common DKIM selectors (Google, Microsoft 365,
SendGrid, Mailchimp and the usual self-hosted names). A selector it does not
know can be added with --dkim-selector NAME (repeatable, or comma-separated);
a clean sweep is reported as "none of the common ones", never a false "no DKIM".

This tool only reads DNS and never sends mail. To safely DEMONSTRATE the
impact of a missing DMARC/DKIM record to a domain owner you are authorised to
test, see the companion red-team tool "spoof-proof" in this repo.

It looks up public DNS records using an encrypted DNS-over-HTTPS request
to a public resolver, so it works on any machine with internet and needs
nothing installed. It only reads public records - nothing private.

With --reputation it also asks what everybody else thinks of the domain, and
crosses the answers: is it on a blocklist right now (which means their mail is
being rejected, a different and more urgent problem than a missing record), and
how long has it existed. Spamhaus, SURBL and the registry need no key at all;
--vt-key KEY adds VirusTotal. Only the domain name is sent, and it is already
public.

With --notify it emails you when the answer is bad, which is the point of
running it from cron once a week: a domain that was protected can stop being
protected when somebody edits DNS, and nobody notices until the fake invoices
start. It stays quiet when the answer is good. Settings live in
~/.plaintext/notify.conf; write an example with:

    python3 domain_checker.py notify setup
    python3 domain_checker.py notify test

DhWonder, Plaintext IT - MIT license.
"""

import json
import os
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import notify
import reputation

# A public DNS-over-HTTPS resolver. We ask it, over HTTPS, "what TXT
# records does this domain have?" - the same public info any mail server
# reads, just fetched in a way that works everywhere.
DOH_URL = "https://dns.google/resolve"
TIMEOUT = 15

# DKIM public keys live at "<selector>._domainkey.<domain>", but the selector
# name is chosen by whoever set up the mail and cannot be derived from the
# domain. We cannot enumerate every selector, but the big mail providers and
# most small-business setups use a short, well-known set, so probing these
# turns "cannot check DKIM" into "found DKIM on selector1" most of the time.
# This list is not exhaustive: a miss means "none of these", not "no DKIM".
COMMON_DKIM_SELECTORS = [
    "google",                 # Google Workspace
    "selector1", "selector2", # Microsoft 365 / Outlook
    "default",                # generic / self-hosted, mail servers
    "k1",                     # Mailchimp / Mandrill
    "s1", "s2",               # SendGrid and others
    "mail",                   # common self-hosted
    "dkim",                   # common self-hosted
    "cm",                     # Campaign Monitor
]


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


def dkim_selectors(options):
    """The selectors to probe: the common set, plus any the operator names.

    --dkim-selector may be given more than once, or as a comma-separated list,
    so a known provider selector can be added without editing the code."""
    extra = options.get("dkim-selector") or options.get("dkim_selector")
    selectors = list(COMMON_DKIM_SELECTORS)
    if isinstance(extra, str):
        for name in extra.replace(",", " ").split():
            name = name.strip()
            if name and name not in selectors:
                selectors.append(name)
    return selectors


def probe_dkim_selector(domain, selector):
    """Look up one DKIM selector. Returns the record text, or '' if absent.

    A real DKIM record is a TXT at "<selector>._domainkey.<domain>" that names
    a key (v=DKIM1 and/or a p= public key). We keep only records that look
    like DKIM, so an unrelated TXT at that name is not mistaken for a key."""
    name = "%s._domainkey.%s" % (selector, domain)
    try:
        records = dns_txt(name)
    except Exception:
        return ""
    for record in records:
        low = record.lower()
        if "v=dkim1" not in low and "k=rsa" not in low and "p=" not in low:
            continue
        # The key itself lives in the p= tag. An empty p= means the key was
        # revoked (RFC 6376) - the selector exists but signs nothing - and
        # some domains publish a wildcard empty key to say exactly that, so we
        # must not count it as a working signature.
        key = ""
        for tag in record.replace(";", " ").split():
            if tag.lower().startswith("p="):
                key = tag[2:].strip()
        if key:
            return record
    return ""


def check_dkim(domain, options):
    """Probe the common DKIM selectors and report what signs this domain's mail.

    DKIM cryptographically signs outgoing mail; without it DMARC has only SPF
    to lean on, and SPF alone breaks the moment mail is forwarded. We cannot
    enumerate every selector, so a clean sweep is reported as a caveated
    'none of the common ones', never a false 'no DKIM'."""
    selectors = dkim_selectors(options)
    found = []
    for selector in selectors:
        record = probe_dkim_selector(domain, selector)
        if record:
            found.append(selector)
    if found:
        shown = ", ".join(found)
        return ("good",
                "DKIM key found on selector(s): %s. Outgoing mail from those "
                "systems is cryptographically signed, which is what lets DMARC "
                "tell a real message from a forgery." % shown, found)
    return ("missing",
            "No DKIM key on any of the %d common selectors probed (%s). That is "
            "not proof of none - a custom selector would be missed - but it means "
            "no mainstream provider signature was found, so DMARC has only SPF to "
            "rely on, and SPF alone fails the moment a message is forwarded."
            % (len(selectors), ", ".join(selectors)), found)


def line(status, label, msg):
    tag = {"good": "GOOD", "weak": "OK-ish", "missing": "MISSING",
           "bad": "BAD", "error": "??", "info": "note"}[status]
    print("  [%-7s] %s: %s" % (tag, label, msg))


def parse_options(args):
    """Pull the --flags out. Everything else is the domain."""
    options, positional = {}, []
    index = 0
    while index < len(args):
        item = args[index]
        if item in ("--notify-config", "--vt-key", "--dkim-selector"):
            options[item.lstrip("-")] = args[index + 1] if index + 1 < len(args) else ""
            index += 2
            continue
        if item.startswith("--"):
            options[item.lstrip("-")] = True
            index += 1
            continue
        positional.append(item)
        index += 1
    return options, positional


def wrap(text, width=70):
    """Fold a sentence to a width, so a long verdict is still readable."""
    words, lines, current = str(text).split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = (current + " " + word).strip()
    if current:
        lines.append(current)
    return lines


def show_reputation(domain, options):
    """Ask the blocklists and the registry, and print who said what.

    Naming every source and what it said is the point. A verdict somebody
    cannot check is a verdict they have to take on faith, and this tool is
    usually being read out loud to the person who owns the domain.
    """
    print()
    print("  What everybody else thinks of this domain")
    print("  " + "-" * 54)

    crossed = reputation.check(domain, vt_key=options.get("vt-key") or "")
    for source in crossed.get("sources", []):
        if source.get("skipped"):
            continue
        mark = "!" if source.get("known") else (" " if source.get("ok") else "?")
        print("  %s [%-13s] %s" % (mark, source.get("source", ""), source.get("why", "")))

    headline, body = crossed["verdict"]
    print()
    print("  %s" % headline)
    for text in wrap(body, 66):
        print("    " + text)
    return crossed


def tell_them(domain, verdict, lines, options):
    """Email the verdict, when it is a verdict worth an email.

    Keyed on the domain with a six hour quiet period, so a cron job running
    hourly on a broken domain sends you four emails a day rather than
    twenty-four, and a weekly one still always sends.
    """
    notifier, said = notify.from_options("domain-checker", options)
    if said:
        print()
        print(said)
    if not notifier.available:
        return
    result = notifier.send("%s can be forged: %s" % (domain, verdict), lines,
                           key="domain:%s" % domain, gap_seconds=6 * 3600,
                           context={"domain": domain})
    print("  %s" % result.detail)


def main():
    args = sys.argv[1:]
    if args and args[0] == "notify":
        # Setting up and testing the notification email, same as every tool here.
        sys.exit(notify.main(args[1:] or ["show"]))

    options, positional = parse_options(args)
    if len(positional) != 1:
        print(__doc__.strip())
        sys.exit(2)

    domain = positional[0].strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0].lstrip("@")

    print("mail-checker - can someone forge email from %s ?" % domain)
    print("=" * 58)

    spf_status, spf_msg = check_spf(domain)
    dmarc_status, dmarc_msg = check_dmarc(domain)
    dkim_status, dkim_msg, dkim_found = check_dkim(domain, options)

    line(spf_status, "SPF  ", spf_msg)
    line(dmarc_status, "DMARC", dmarc_msg)
    line(dkim_status, "DKIM ", dkim_msg)

    # What everybody else thinks of the domain, if asked. This can change the
    # whole conversation: a blocklisted domain is not being impersonated, it is
    # being rejected, and that is the more urgent problem of the two.
    crossed = None
    if options.get("reputation") or options.get("vt-key"):
        crossed = show_reputation(domain, options)

    print("\n" + "-" * 58)

    if crossed and crossed["level"] in ("listed", "throwaway"):
        headline, body = crossed["verdict"]
        print("Verdict: %s." % headline.upper())
        for text in wrap(body, 70):
            print(text)
        print()
        print("The SPF and DMARC findings above still stand, but this comes first.")
        if options.get("notify"):
            tell_them(domain, headline.lower(),
                      ["%s: %s" % (headline, body), ""] +
                      ["SPF:   %s" % spf_msg, "", "DMARC: %s" % dmarc_msg], options)
        sys.exit(1)
    # Verdict weighted mostly on DMARC, since it's what actually blocks fakes.
    if spf_status == "good" and dmarc_status == "good" and dkim_status == "good":
        print("Verdict: well protected. It's genuinely hard to forge mail from this domain.")
        # Nothing is emailed here. An all-clear that arrives every week is an
        # email you learn to delete unread, and then you delete the real one too.
        sys.exit(0)

    findings = ["SPF:   %s" % spf_msg, "", "DMARC: %s" % dmarc_msg, "",
                "DKIM:  %s" % dkim_msg, ""]
    if dmarc_status == "missing" or spf_status in ("missing", "bad"):
        print("Verdict: EXPOSED. Someone could send email as this business today, and")
        print("the owner would never know. This is a fast, high-value fix - exactly the")
        print("kind of thing that makes a small business owner glad they called.")
        findings.append("Someone could send email as this business today, and the owner")
        findings.append("would never know. This is a fast fix: it is three DNS records.")
        verdict = "exposed"
    else:
        print("Verdict: partly protected. The pieces are started but not finished -")
        print("tightening them to reject fakes is a quick, worthwhile job.")
        if dkim_status == "missing":
            print("No DKIM signature was found on the common selectors either, so a")
            print("confirmed selector (or adding DKIM) would strengthen this further.")
        findings.append("The pieces are started but not finished. Tightening them to")
        findings.append("reject fakes is a quick, worthwhile job.")
        verdict = "partly protected"

    if options.get("notify"):
        tell_them(domain, verdict, findings, options)
    sys.exit(1)


if __name__ == "__main__":
    main()
