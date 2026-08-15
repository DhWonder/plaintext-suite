"""
Putting the findings on screen in the order a person actually reads them.

Every other module in here decides things. This one only says them. Keeping the
two apart matters more than it looks: the browser version needs the same answers
in a different shape, and a report that computed anything on its way to the
screen would have to be written twice and would eventually disagree with itself.

The order is fixed and deliberate. The verdict comes first, because somebody who
reads one line should still get the answer. Then the message, then attachments,
then the sender's domain, because that is the order of how much it matters to a
person holding a mail they are unsure about.
"""

LABELS = {3: "SERIOUS", 2: "BAD SIGN", 1: "WORTH NOTING"}

# How loudly to announce the overall level.
HEADLINE_MARK = {
    "critical": "!!",
    "high": "!!",
    "watch": "!",
    "normal": "",
}


# ---------------------------------------------------------------------------
def wrap(text, width=66):
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


def say(text, indent="  ", width=66):
    for line in wrap(text, width):
        print(indent + line)


def rule(title):
    print()
    print("=" * 70)
    print("  " + title)
    print("=" * 70)
    print()


def part(title):
    """A lighter divider for a section inside one report."""
    print("  " + title)
    print("  " + "-" * 66)


def field(label, value):
    if value:
        print("  %-10s %s" % (label + ":", value))


def findings_list(findings, indent="      "):
    """The (weight, sentence) pairs every module produces, worst first."""
    for weight, sentence in findings:
        print("%s[%s]" % (indent, LABELS.get(weight, "SIGN")))
        for line in wrap(sentence, 62):
            print(indent + "  " + line)
        print()


# ---------------------------------------------------------------------------
def render_email(result, origin):
    """One analysed message, start to finish."""
    title = origin
    if result.get("message_count", 1) > 1:
        title = "%s  (message %d of %d)" % (
            origin, result["message_index"] + 1, result["message_count"])
    rule(title)

    field("From", result.get("from"))
    reply_to = result.get("reply_to")
    if reply_to and reply_to != result.get("from"):
        field("Reply to", reply_to)
    field("Subject", result.get("subject"))
    field("Date", result.get("date"))
    field("Read as", result.get("format"))
    print()

    # The answer, before any of the detail behind it.
    headline, body = result["verdict"]
    mark = HEADLINE_MARK.get(result["level"], "")
    print("  " + (mark + " " if mark else "") + headline.upper())
    print()
    say(body, "  ")
    print()

    _render_message_part(result["message"])
    _render_attachments(result["attachments"])
    _render_domain(result.get("domain"))


def _render_message_part(msg_report):
    part("The message itself")
    findings = msg_report.get("findings") or []
    if not findings:
        say("Nothing in the headers or the wording matches the patterns scams "
            "normally leave behind.", "      ")
        print()
    else:
        print()
        findings_list(findings)
    headline, body = msg_report["verdict"]
    print("      %s" % headline)
    for line in wrap(body, 62):
        print("      " + line)
    print()


def _render_attachments(reports):
    part("Attachments")
    if not reports:
        say("None. There is nothing attached to open.", "      ")
        print()
        return
    print()
    for report in reports:
        print("      %s" % report["name"])
        print("      %s" % ("." * 60))
        print("          what it is:   %s" % report["real_type"])
        print("          size:         %s bytes" % "{:,}".format(report["bytes"]))
        print("          fingerprint:  %s" % report["sha256"])
        print()
        findings_list(report.get("findings") or [], "          ")
        if not report.get("findings"):
            say("Nothing structurally wrong with this one.", "          ")
            print()
        contents = report.get("contents") or []
        if contents:
            print("          inside it:")
            for entry in contents[:8]:
                print("            %s" % entry)
            if len(contents) > 8:
                print("            ... and %d more" % (len(contents) - 8))
            print()
        _render_reputation(report.get("reputation"))


def _render_reputation(rep):
    if not rep:
        return
    headline, body = rep["verdict"]
    print("          %s" % headline)
    for line in wrap(body, 58):
        print("          " + line)
    for source in rep.get("sources", []):
        if not source.get("ok"):
            print("            %-16s %s" % (source["source"],
                                            source.get("error", "no answer")))
        elif source.get("known"):
            extra = source.get("family") or "knows this file"
            print("            %-16s %s" % (source["source"], extra))
        else:
            print("            %-16s does not know it" % source["source"])
    print()


def _render_domain(domain):
    part("Can the sender's domain be forged?")
    if not domain:
        say("Not checked. This needs a DNS lookup, so it is skipped when the "
            "tool is offline or when there was no sender domain to check.",
            "      ")
        print()
        return
    print()
    for key, label in (("spf", "SPF"), ("dkim", "DKIM"), ("dmarc", "DMARC")):
        entry = domain.get(key) or {}
        print("      %-6s %-9s %s" % (label, entry.get("status", "?"),
                                      entry.get("message", "")))
    print()
    headline, body = domain["verdict"]
    print("      %s" % headline)
    for line in wrap(body, 62):
        print("      " + line)
    print()


# ---------------------------------------------------------------------------
def render_password(notes, good, guess_time, breach_count=None,
                    breach_note="", offline=False):
    """The password answer. The caller does the analysis and the lookup, so
    nothing secret is held here any longer than it takes to print."""
    rule("How strong is it?")
    print("  A determined attacker with ordinary equipment would need:")
    print("      %s" % guess_time)
    print()
    if good:
        print("  What is right about it")
        for item in good:
            say("- " + item, "    ")
        print()
    if notes:
        print("  What weakens it")
        for item in notes:
            say("- " + item, "    ")
        print()

    if offline:
        print("  Breach check skipped, because you asked for offline only.")
        print()
        return

    rule("Has it already been stolen?")
    say(breach_note)
    print()

    # A leaked password beats every other consideration, so it goes last.
    if breach_count:
        rule("What to do")
        say("Change this password anywhere it is used, starting with email, then "
            "banking, then anything that can spend money. Email first because "
            "whoever controls the mailbox can reset everything else.")
        print()


# ---------------------------------------------------------------------------
def render_breach(result):
    rule("Has %s been in a breach?" % result["email"])
    headline, body = result["verdict"]
    print("  %s" % headline)
    print()
    say(body)
    print()

    for source in result.get("sources", []):
        if source.get("skipped"):
            print("      %-20s skipped (%s)" % (source["source"],
                                                source.get("reason", "no key")))
        elif not source.get("ok"):
            print("      %-20s %s" % (source["source"],
                                      source.get("error", "no answer")))
        else:
            found = source.get("breaches") or []
            print("      %-20s %s" % (source["source"],
                                      "%d found" % len(found) if found else "nothing"))
    print()

    breaches = result.get("breaches") or []
    if breaches:
        print("  Where it turned up")
        for name in breaches[:20]:
            print("      - %s" % name)
        if len(breaches) > 20:
            print("      ... and %d more" % (len(breaches) - 20))
        print()

    exposed = result.get("exposed_types") or []
    if exposed:
        print("  What was exposed across those")
        say(", ".join(exposed), "      ")
        print()
