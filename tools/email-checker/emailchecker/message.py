"""
Reading a suspicious message and pointing at what is wrong with it.

Somebody forwards you an email every week asking "is this real?". The signs
are almost always the same handful of things, and none of them need a security
degree to understand. They need someone to point at them.

That is all this does. It reads a saved message and explains, in order of how
much they matter, what looks wrong. It never opens a link, never downloads
anything, and never contacts the sender. It reads a file.

If the message has attachments, run file-checker on it next. That is the other
half of the question and it is a different job.
"""

import email
import email.policy
import email.utils
import html.parser
import re
import sys


# Words that show up when someone is trying to rush you. Pressure is the
# whole engine of phishing: a calm person checks, a panicked person clicks.
PRESSURE_PHRASES = [
    "urgent", "immediately", "right away", "within 24 hours", "final notice",
    "account will be closed", "account will be suspended", "suspended",
    "verify your account", "confirm your identity", "unusual activity",
    "unauthorized", "your payment failed", "invoice attached", "overdue",
    "gift card", "wire transfer", "change of bank", "new bank details",
]

# File types that are programs in disguise. A "document" ending in one of
# these is not a document.
DANGEROUS_ATTACHMENTS = [
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar", ".msi",
    ".ps1", ".hta", ".iso", ".img",
]


class LinkCollector(html.parser.HTMLParser):
    """Pulls every link out of the HTML part of the mail, remembering both
    where the link SAYS it goes (the visible text) and where it ACTUALLY
    goes (the href). The gap between those two is phishing's oldest trick."""

    def __init__(self):
        super().__init__()
        self.links = []          # list of (href, visible_text)
        self._current_href = None
        self._current_text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._current_href = dict(attrs).get("href")
            self._current_text = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._current_href is not None:
            text = "".join(self._current_text).strip()
            self.links.append((self._current_href, text))
            self._current_href = None


def domain_of(address_or_url):
    """Boil an email address or URL down to its core domain, e.g.
    'https://login.paypal.com.evil.io/x' -> 'evil.io'.
    The end of the hostname is the only part a sender can't fake."""
    s = (address_or_url or "").strip().lower()
    m = re.search(r"@([\w.-]+)", s)
    if m:
        host = m.group(1)
    else:
        m = re.match(r"[a-z][a-z0-9+.-]*://([^/:?#]+)", s)
        host = m.group(1) if m else s.split("/")[0]
    host = host.strip(".")
    # A bare IP address stays whole - trimming it to its last two numbers
    # would turn 185.22.11.9 into nonsense.
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return host
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def get_bodies(msg):
    """Return (plain_text, html_text) of the mail, decoded best-effort."""
    plain, html_body = "", ""
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace")
        except (LookupError, UnicodeDecodeError):
            text = str(part.get_payload())
        if ctype == "text/plain":
            plain += text
        else:
            html_body += text
    return plain, html_body

# ---------------------------------------------------------------------------
def examine(path):
    """Read a saved message and return the findings, worst first."""
    with open(path, "rb") as fh:
        message = email.message_from_binary_file(fh, policy=email.policy.default)
    return findings_for(message)


def attachment_summary(path):
    """What is attached, without opening any of it. Names and sizes only."""
    with open(path, "rb") as fh:
        message = email.message_from_binary_file(fh, policy=email.policy.default)

    items = []
    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename()
        disposition = (part.get("Content-Disposition") or "")
        if not filename and "attachment" not in disposition:
            continue
        try:
            body = part.get_payload(decode=True) or b""
        except Exception:
            body = b""
        items.append({
            "name": filename or "(unnamed)",
            "type": part.get_content_type(),
            "bytes": len(body),
        })
    return items


# ---------------------------------------------------------------------------
# Every sign worth pointing at, weighted by how much it means.
#   3 = a strong sign, hard to explain innocently
#   2 = a bad sign, common in scams and rare in real mail
#   1 = a small sign, worth noticing alongside others
# ---------------------------------------------------------------------------
def findings_for(message):
    findings = []      # (weight, explanation) - weight is how bad it is, 1..3

    # ------------------------------------------------------------------
    # 1. Who does this mail claim to be from, and does the claim hold up?
    # ------------------------------------------------------------------
    from_header = message.get("From", "")
    display_name, from_addr = email.utils.parseaddr(from_header)
    from_domain = domain_of(from_addr)

    reply_to = message.get("Reply-To", "")
    _, reply_addr = email.utils.parseaddr(reply_to)
    if reply_addr and domain_of(reply_addr) != from_domain:
        findings.append((3,
            "Replies to this mail would go to '%s' - a completely different "
            "address than the visible sender (%s). Legitimate companies "
            "don't do this; scammers do it so your reply reaches them."
            % (reply_addr, from_addr or "unknown")))

    return_path = message.get("Return-Path", "")
    rp_domain = domain_of(return_path)
    if rp_domain and from_domain and rp_domain != from_domain:
        findings.append((2,
            "Behind the scenes this mail was sent on behalf of '%s', not "
            "'%s' as the From line suggests. Sometimes legitimate (mailing "
            "services), but combined with other signs it matters." % (rp_domain, from_domain)))

    # A display name containing a DIFFERENT known-looking address is the
    # classic "Bank Support <random@gmail.com>" costume.
    name_addr = re.search(r"[\w.+-]+@[\w.-]+", display_name or "")
    if name_addr and domain_of(name_addr.group(0)) != from_domain:
        findings.append((3,
            "The sender's display name contains the address '%s', but the "
            "mail actually comes from '%s'. That's a costume, not a "
            "coincidence." % (name_addr.group(0), from_addr)))

    # ------------------------------------------------------------------
    # 2. Did the receiving server's own checks pass? (SPF/DKIM/DMARC)
    # ------------------------------------------------------------------
    auth = (message.get("Authentication-Results", "") or "").lower()
    for mech in ("spf", "dkim", "dmarc"):
        if ("%s=fail" % mech) in auth or ("%s=softfail" % mech) in auth:
            findings.append((2,
                "Your mail server's own authenticity check (%s) FAILED for "
                "this message - the sending server was not authorized to "
                "send mail for that domain." % mech.upper()))

    # ------------------------------------------------------------------
    # 3. Links: does the text say one thing and the destination another?
    # ------------------------------------------------------------------
    plain, html_body = get_bodies(message)

    # Kept so the caller can look the destinations up in the blocklists. The
    # wording checks below only compare what a link says against where it goes;
    # whether the destination is a known bad domain is a separate question, and
    # answering it needs the network.
    all_links = []

    if html_body:
        collector = LinkCollector()
        try:
            collector.feed(html_body)
        except Exception:
            pass
        all_links = list(collector.links)
        for href, text in collector.links:
            if not href or href.startswith(("mailto:", "tel:", "#")):
                continue
            href_dom = domain_of(href)
            text_dom = None
            m = re.search(r"[\w.-]+\.[a-z]{2,}", (text or "").lower())
            if m:
                text_dom = domain_of(m.group(0))
            if text_dom and href_dom and text_dom != href_dom:
                findings.append((3,
                    "A link in this mail SHOWS '%s' but actually LEADS to "
                    "'%s'. Showing one address and linking another is the "
                    "oldest trick in the book." % (text_dom, href_dom)))
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", href_dom or ""):
                findings.append((2,
                    "A link points to a bare numeric address (%s) instead of "
                    "a normal website name. Real companies don't do that." % href_dom))

    # ------------------------------------------------------------------
    # 4. Pressure language in the text.
    # ------------------------------------------------------------------
    # The subject counts as much as the body here. "URGENT: final notice" in the
    # subject line and a calm body is a normal shape for phishing, and scanning
    # the body alone misses it completely.
    subject_text = (message.get("Subject") or "")
    body_lower = (subject_text + " " + plain + " "
                  + re.sub(r"<[^>]+>", " ", html_body)).lower()
    pressure_hits = [p for p in PRESSURE_PHRASES if p in body_lower]
    if len(pressure_hits) >= 3:
        findings.append((2,
            "The message leans hard on pressure words (%s). Urgency is how "
            "phishing works: a rushed person doesn't stop to verify."
            % ", ".join("'%s'" % p for p in pressure_hits[:4])))
    elif len(pressure_hits) == 2:
        findings.append((1,
            "Some pressure language (%s). On its own, not proof of anything."
            % " and ".join("'%s'" % p for p in pressure_hits)))

    # ------------------------------------------------------------------
    # 5. Attachments that are secretly programs.
    # ------------------------------------------------------------------
    for part in message.walk():
        filename = part.get_filename()
        if not filename:
            continue
        lowered = filename.lower()
        for ext in DANGEROUS_ATTACHMENTS:
            if lowered.endswith(ext):
                findings.append((3,
                    "The attachment '%s' is an executable program, whatever "
                    "its icon claims to be. Do not open it." % filename))
        if re.search(r"\.(pdf|doc|docx|xls|xlsx)\.\w+$", lowered):
            findings.append((3,
                "The attachment '%s' has a fake double file-ending - it "
                "pretends to be a document but isn't one." % filename))

    # A message with no HTML part still carries links, just as bare text. The
    # comparison above cannot apply to them (there is no visible text saying
    # something different) but the destination is still worth looking up.
    for found in re.findall(r"https?://[^\s<>\"\')]+", plain or ""):
        if not any(found == href for href, _text in all_links):
            all_links.append((found, ""))

    findings.sort(reverse=True)
    score = sum(weight for weight, _ in findings)
    return {
        "from": message.get("From", "").strip(),
        "from_domain": from_domain,
        "subject": (message.get("Subject") or "").strip(),
        "reply_to": (message.get("Reply-To") or "").strip(),
        "date": (message.get("Date") or "").strip(),
        "findings": findings,
        "links": all_links,
        "score": score,
        "verdict": verdict_for(findings, score),
    }


def verdict_for(findings, score):
    if not findings:
        return ("None of the usual tricks",
                "The structure of this message shows none of the things scams normally get wrong. "
                "That is not a guarantee: a well made scam can look completely clean. The rule "
                "that always holds is that if a message asks for money, passwords or bank "
                "details, you verify it by phone on a number you already had, never one from "
                "the message.")
    if score >= 5:
        return ("This has the fingerprints of a phishing email",
                "Do not click its links, open its attachments or reply to it. If it claims to be "
                "from a company you deal with, go to that company through their app or a web "
                "address you type yourself, not through anything in this message.")
    return ("Suspicious, but not conclusive",
            "Some of this does not add up, though not enough to be certain. Treat it carefully: "
            "verify whatever it is asking for through a channel you already trust before acting "
            "on any of it.")
