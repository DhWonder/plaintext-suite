#!/usr/bin/env python3
"""
file-checker: is this attachment safe to open?

Point it at a saved email and it pulls out the attachments, looks inside each
one without running it, and says in plain English what is wrong. Point it at a
file directly and it does the same for that.

USAGE

  python3 file_checker.py suspicious.eml
  python3 file_checker.py invoice.docm
  python3 file_checker.py --save-to ./quarantine suspicious.eml

OPTIONS

  --offline         do not contact the malware databases. Everything else works.
  --vt-key KEY      a VirusTotal key, for the reputation lookup
  --mb-key KEY      a MalwareBazaar key, if yours needs one
  --save-to DIR     write the attachments out, renamed so they cannot be run
                    by a double click, for handing to somebody else
  --json FILE       write the findings as JSON

WHAT LEAVES YOUR COMPUTER

  Nothing, unless the database lookup runs, and then only a SHA-256
  fingerprint: a one way summary that cannot be turned back into the file. The
  attachment itself is never uploaded, because a client's attachment may be a
  real invoice with real customer details in it, and uploading that to a public
  analysis service publishes it. Several well known tools do that by default.

WHAT THIS IS NOT

  It is not antivirus. It does not remove anything, and a clean result is not a
  guarantee. It is the reading somebody experienced would give an attachment
  before deciding whether to open it, done in a few seconds and written down.

Written by DhWonder for Plaintext IT. MIT licensed.
"""

import email
import email.policy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from filechecker import inspect as inspector
from filechecker import reputation

LABELS = {3: "SERIOUS", 2: "BAD SIGN", 1: "WORTH NOTING"}


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        print(__doc__.strip())
        return 0

    options, positional = parse_options(args)
    if not positional:
        print("Which file? Try: python3 file_checker.py suspicious.eml")
        return 2

    path = positional[0]
    if not os.path.exists(path):
        print("No such file: %s" % path)
        return 2

    items = pull_out(path)
    if not items:
        print()
        print("  Nothing to check. That message has no attachments.")
        print("  To look at the message itself, use accounts-checker:")
        print("      python3 accounts_checker.py message %s" % path)
        print()
        return 0

    print()
    print("=" * 70)
    print("  file-checker: %d item%s from %s"
          % (len(items), "" if len(items) == 1 else "s", os.path.basename(path)))
    print("=" * 70)

    reports, worst = [], 0
    for name, data in items:
        report = inspector.examine(name, data)

        if not options.get("offline"):
            report["reputation"] = reputation.check(
                report["sha256"],
                vt_key=options.get("vt-key", ""),
                mb_key=options.get("mb-key", ""))
        reports.append(report)
        worst = max(worst, report["score"] + (60 if report.get("reputation", {}).get("known_bad") else 0))
        show(report)

        if options.get("save-to"):
            saved = quarantine(options["save-to"], name, data)
            print("      Written to %s" % saved)
            print()

    print("=" * 70)
    print("  " + overall(reports))
    print("=" * 70)
    print()

    if options.get("json"):
        with open(options["json"], "w", encoding="utf-8") as fh:
            json.dump(reports, fh, indent=1)
        print("  Written to %s" % options["json"])
        print()
    return 1 if worst else 0


def parse_options(args):
    takes_value = {"--vt-key", "--mb-key", "--save-to", "--json"}
    options, positional = {}, []
    index = 0
    while index < len(args):
        item = args[index]
        if item in takes_value:
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


# ---------------------------------------------------------------------------
def pull_out(path):
    """Get the attachments out of a message, or treat the file as one itself."""
    with open(path, "rb") as fh:
        head = fh.read(4096)
        fh.seek(0)
        raw = fh.read()

    looks_like_mail = (b"\nFrom:" in head or head.startswith(b"From ")
                       or b"\nSubject:" in head or b"MIME-Version:" in head)
    if not looks_like_mail:
        return [(os.path.basename(path), raw)]

    message = email.message_from_bytes(raw, policy=email.policy.default)
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
        items.append((filename or "(unnamed)", body))
    return items


def quarantine(folder, name, data):
    """Write an attachment out so it cannot be run by accident.

    The extension is changed and the file is written without the execute bit.
    Somebody who really needs it can rename it back, deliberately, which is
    the point.
    """
    if not os.path.isdir(folder):
        os.makedirs(folder)
    safe = "".join(ch if (ch.isalnum() or ch in "._- ") else "_" for ch in name).strip() or "attachment"
    target = os.path.join(folder, safe + ".unsafe")
    with open(target, "wb") as fh:
        fh.write(data)
    os.chmod(target, 0o600)
    return target


# ---------------------------------------------------------------------------
def show(report):
    print()
    print("  %s" % report["name"])
    print("  " + "-" * 66)
    print("      what it is:   %s" % report["real_type"])
    print("      size:         %s bytes" % "{:,}".format(report["bytes"]))
    print("      fingerprint:  %s" % report["sha256"])
    print()

    if report["findings"]:
        for weight, sentence in report["findings"]:
            print("      [%s]" % LABELS.get(weight, "SIGN"))
            for line in wrap(sentence, 62):
                print("        " + line)
            print()
    else:
        for line in wrap("Nothing structurally wrong with it. It is what it says it is, and it "
                         "carries no code, no embedded files and no instructions to run "
                         "anything.", 62):
            print("      " + line)
        print()

    if report["contents"]:
        print("      inside it:")
        for entry in report["contents"][:8]:
            print("        %s" % entry)
        if len(report["contents"]) > 8:
            print("        ... and %d more" % (len(report["contents"]) - 8))
        print()

    rep = report.get("reputation")
    if rep:
        print("      %s" % rep["verdict"][0])
        for line in wrap(rep["verdict"][1], 62):
            print("        " + line)
        for source in rep["sources"]:
            if source.get("known"):
                extra = source.get("family") or ""
                if source["source"] == "VirusTotal" and source.get("total"):
                    extra = "%d of %d scanners call it malicious%s" % (
                        source.get("malicious", 0), source["total"],
                        (", %s" % extra) if extra else "")
                print("        %-16s %s" % (source["source"], extra or "knows this file"))
            elif source.get("ok"):
                print("        %-16s does not know it" % source["source"])
            else:
                print("        %-16s %s" % (source["source"], source.get("error", "no answer")))
        print()


def overall(reports):
    worst = ""
    for report in reports:
        if report.get("reputation", {}).get("known_bad"):
            return ("At least one attachment is known malware. Do not open any of it. If somebody "
                    "already did, that machine needs looking at today.")
        if report["level"] == "critical":
            worst = "critical"
        elif report["level"] == "high" and worst != "critical":
            worst = "high"
        elif report["level"] == "watch" and not worst:
            worst = "watch"

    if worst in ("critical", "high"):
        return ("This should not be opened. Reply to the sender on a number or address you "
                "already had, not this message, and ask whether they sent it.")
    if worst == "watch":
        return ("Nothing conclusive, but worth checking with the sender before opening it.")
    return ("Nothing here looks dangerous. That is not a guarantee, so the usual rule still "
            "applies: if it asks for money or a password, verify it by phone.")


def wrap(text, width=62):
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = (current + " " + word).strip()
    if current:
        lines.append(current)
    return lines


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
