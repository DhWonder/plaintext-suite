"""
The whole email, judged in one pass.

file-checker used to answer "is the attachment safe" and accounts-checker used to
answer "is the message a scam", and you had to run both and hold the two answers
in your head. This puts them together. One saved email in, one report out, in the
order that matters: is the message itself a scam, are the attachments safe to
open, and can the sender's own domain even be forged.

Each part is the same careful reader as before. What is new is that they run
together and produce a single verdict, because the question a person actually has
is "do I trust this email", not "does part three of five look alright".
"""

from . import attachments, maildomain, message, read, reputation

LEVELS = ["normal", "watch", "high", "critical"]
RANK = {name: i for i, name in enumerate(LEVELS)}


def analyze(path=None, data=None, text=None, offline=True,
            vt_key="", mb_key="", check_domain=None):
    """Read an email in any supported form and return one report per message
    (more than one only for a mailbox)."""
    loaded_list = read.load(path=path, data=data, text=text)
    return [analyze_one(loaded, offline=offline, vt_key=vt_key, mb_key=mb_key,
                        check_domain=check_domain) for loaded in loaded_list]


def analyze_one(loaded, offline=True, vt_key="", mb_key="", check_domain=None):
    # None means "follow offline". True or False is an explicit instruction.
    if check_domain is None:
        check_domain = not offline
    msg_report = message.findings_for(loaded.message)

    attach_reports = []
    for name, blob in loaded.attachments:
        report = attachments.examine(name, blob)
        if not offline:
            report["reputation"] = reputation.check(report["sha256"],
                                                    vt_key=vt_key, mb_key=mb_key)
        attach_reports.append(report)

    # check_domain is decided by the caller, not derived from `offline`. The
    # lookup is one DNS query for a public name, so somebody can reasonably want
    # it while still refusing every other network call.
    domain_report = None
    from_domain = msg_report.get("from_domain", "")
    if check_domain and from_domain and "." in from_domain:
        try:
            domain_report = maildomain.check(from_domain)
        except Exception:
            domain_report = None

    level, verdict = combine(msg_report, attach_reports, domain_report)
    return {
        "format": loaded.format,
        "message_index": loaded.index,
        "message_count": loaded.count,
        "from": msg_report.get("from", ""),
        "subject": msg_report.get("subject", ""),
        "reply_to": msg_report.get("reply_to", ""),
        "date": msg_report.get("date", ""),
        "from_domain": from_domain,
        "message": msg_report,
        "attachments": attach_reports,
        "domain": domain_report,
        "level": level,
        "verdict": verdict,
    }


def _worst_attachment_level(attach_reports):
    worst = "normal"
    for report in attach_reports:
        if report.get("reputation", {}).get("known_bad"):
            return "critical"
        if RANK.get(report.get("level", "normal"), 0) > RANK[worst]:
            worst = report["level"]
    return worst


def combine(msg_report, attach_reports, domain_report):
    """One level and one verdict for the whole email."""
    msg_score = msg_report.get("score", 0)
    attach_level = _worst_attachment_level(attach_reports)
    known_bad = any(r.get("reputation", {}).get("known_bad") for r in attach_reports)

    # The message's own contribution to the level.
    if msg_score >= 5:
        msg_level = "high"
    elif msg_score >= 3:
        msg_level = "watch"
    elif msg_score >= 1:
        msg_level = "watch"
    else:
        msg_level = "normal"

    level = LEVELS[max(RANK[msg_level], RANK[attach_level])]

    # Wording, strongest concern first.
    phishing = msg_score >= 5
    lines = []
    if known_bad:
        lines.append("an attachment is known malware")
    elif attach_level in ("critical", "high"):
        lines.append("an attachment should not be opened")
    if phishing:
        lines.append("the message itself has the shape of a phishing email")
    elif msg_score >= 1:
        lines.append("parts of the message do not add up")
    if domain_report and domain_report.get("forgeable") and msg_score >= 1:
        lines.append("and the sender's domain is easy to forge, so a real impersonation is possible")

    if not lines:
        headline = "Nothing here looks dangerous"
        body = ("Neither the message nor its attachments show the things scams and malware "
                "normally get wrong. That is not a guarantee. The rule that always holds: if it "
                "asks for money, a password or bank details, verify by phone on a number you "
                "already had.")
        return level, (headline, body)

    if known_bad or attach_level == "critical" or phishing:
        headline = "Do not open or act on this email"
    elif attach_level == "high":
        headline = "An attachment here should not be opened"
    else:
        headline = "Worth a closer look before trusting this"

    body = _sentence(lines) + ". "
    if known_bad or attach_level in ("critical", "high"):
        body += ("Do not open the attachment. ")
    if phishing:
        body += ("Do not click its links or reply to it; reach the sender on a number or address "
                 "you already had. ")
    body += ("The detail for each part is below.")
    return level, (headline, body.strip())


def _sentence(parts):
    parts = [p for p in parts if p]
    if not parts:
        return ""
    text = parts[0]
    for extra in parts[1:]:
        if extra.startswith("and "):
            text += ", " + extra
        else:
            text += ", and " + extra
    return text[0].upper() + text[1:]
