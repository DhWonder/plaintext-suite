#!/usr/bin/env python3
"""
Does the reader really handle every format the tool says it handles?

The claim on the front of this tool is that it does not care which shape the
email arrived in. That claim is worth exactly as much as this file, so every
format gets a real fixture and the same assertions: the message parses, the
sender survives, and the attachments come out whole.

    python3 tests/test_read.py

Nothing here touches the network. Every check is offline.
"""

import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from emailchecker import analyze, read           # noqa: E402
import make_test_emails                          # noqa: E402

PASS, FAIL = [], []


def check(name, condition, detail=""):
    (PASS if condition else FAIL).append(name)
    print("  %s %s%s" % ("ok  " if condition else "FAIL", name,
                         "" if condition or not detail else "   (%s)" % detail))


def main():
    folder = tempfile.mkdtemp(prefix="emailchecker-tests-")
    try:
        files = make_test_emails.write_all(folder)
        print("\n  Fixtures in %s\n" % folder)

        # -- every format loads, and reports the format it actually was -----
        expected = {
            "clean.eml": ("eml", 1),
            "clean.eml.gz": ("eml.gz", 1),
            "apple.emlx": ("emlx", 1),
            "two.mbox": ("mbox", 2),
            "phish.msg": ("msg", 1),
            "bare.msg": ("msg", 1),
        }
        for name, (fmt, count) in sorted(expected.items()):
            loaded = read.load(path=files[name])
            check("%-14s reads as %-7s" % (name, fmt),
                  loaded[0].format == fmt, "got %s" % loaded[0].format)
            check("%-14s holds %d message(s)" % (name, count),
                  len(loaded) == count, "got %d" % len(loaded))

        # -- pasted text, with headers and without --------------------------
        with open(files["clean.eml"], "rb") as fh:
            raw = fh.read()
        pasted = read.load(text=raw)[0]
        check("pasted with headers keeps the sender",
              "dana@example.co.il" in (pasted.message.get("From") or ""))
        body_only = read.load(text=b"just some words somebody copied")[0]
        check("pasted body alone still parses", body_only.format == "text")

        # -- the Outlook reader, both branches ------------------------------
        phish = read.load(path=files["phish.msg"])[0]
        check("msg recovers the original From header",
              "paypa1-secure.com" in (phish.message.get("From") or ""))
        check("msg recovers Reply-To",
              "recover@mail.ru" in (phish.message.get("Reply-To") or ""))
        check("msg recovers the server's auth results",
              "spf=fail" in (phish.message.get("Authentication-Results") or ""))
        check("msg extracts the attachment",
              [n for n, _ in phish.attachments] == ["invoice.pdf.exe"],
              str([n for n, _ in phish.attachments]))
        check("msg attachment bytes are intact",
              phish.attachments and phish.attachments[0][1].startswith(b"MZ"))

        bare = read.load(path=files["bare.msg"])[0]
        check("msg with no headers still names the sender",
              "dana@example.co.il" in (bare.message.get("From") or ""),
              repr(bare.message.get("From")))
        check("msg with no headers keeps the subject",
              (bare.message.get("Subject") or "") == "Quick question")

        # -- the attachment survives a normal .eml too ----------------------
        clean = read.load(path=files["clean.eml"])[0]
        check("eml extracts the attachment",
              [n for n, _ in clean.attachments] == ["proof.pdf"],
              str([n for n, _ in clean.attachments]))

        # -- verdicts, end to end, offline ----------------------------------
        verdicts = {}
        for name in ("clean.eml", "phish.msg", "bare.msg"):
            loaded = read.load(path=files[name])[0]
            verdicts[name] = analyze.analyze_one(loaded, offline=True,
                                                 check_domain=False)
        check("a clean business email is not alarming",
              verdicts["clean.eml"]["level"] == "normal",
              verdicts["clean.eml"]["level"])
        check("a phish with a disguised program is critical",
              verdicts["phish.msg"]["level"] == "critical",
              verdicts["phish.msg"]["level"])
        check("a plain internal note is not alarming",
              verdicts["bare.msg"]["level"] == "normal",
              verdicts["bare.msg"]["level"])

        # -- pressure language in the subject alone must register -----------
        subject_only = read.load(text=(
            b"From: boss@example.com\r\n"
            b"Subject: URGENT: final notice, account will be suspended\r\n"
            b"\r\nPlease see the portal when you get a moment.\r\n"))[0]
        found = analyze.analyze_one(subject_only, offline=True, check_domain=False)
        check("urgency in the subject line is noticed",
              found["level"] != "normal", found["level"])

        # -- offline really is offline --------------------------------------
        clean_loaded = read.load(path=files["clean.eml"])[0]
        result = analyze.analyze_one(clean_loaded, offline=True)
        check("offline does no domain lookup", result["domain"] is None)
        check("offline does no reputation lookup",
              all("reputation" not in a for a in result["attachments"]))
    finally:
        shutil.rmtree(folder, ignore_errors=True)

    print("\n  %d passed, %d failed\n" % (len(PASS), len(FAIL)))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
