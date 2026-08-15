#!/usr/bin/env python3
"""
email-checker: everything about one email, in plain English.

Point it at an email somebody sent you -- in any format a mail program saves --
and it answers the whole question in one report: is the message a scam, are the
attachments safe to open, and can the domain it claims to come from even be
forged. The two old tools, file-checker and accounts-checker, are folded into
this, so it also checks a password and whether an address has been in a breach.

USAGE

  Check an email (any format below, or paste it on standard input):
      python3 email_checker.py suspicious.eml
      python3 email_checker.py message.msg
      python3 email_checker.py mailbox.mbox
      pbpaste | python3 email_checker.py -            read pasted text

  The account questions the old accounts-checker answered:
      python3 email_checker.py password
      python3 email_checker.py breach someone@example.com

  The browser version of the whole suite:
      python3 email_checker.py serve                  then open the address shown
      python3 email_checker.py serve --open           and open it for me

FORMATS IT READS

  .eml   .emlx (Apple Mail)   .mbox (a whole folder)   .msg (Outlook)
  .eml.gz (gzipped)   and raw text pasted on standard input.

OPTIONS

  --offline        do not touch the internet. The message and attachment
                   structure are still fully checked; only the lookups are off.
  --vt-key KEY     a VirusTotal key for the attachment reputation lookup
  --mb-key KEY     a MalwareBazaar key, if yours needs one
  --hibp-key KEY   a Have I Been Pwned key for the breach lookup
  --domain         also check the sender's domain even when otherwise offline
  --save-to DIR    write attachments out, renamed so they cannot be run, for
                   handing to somebody else
  --json FILE      also write the findings as JSON
  --yes            skip the confirmation before a breach lookup sends an address

OPTIONS FOR serve

  --port N         which port, default 8730
  --host H         what to listen on. Default 127.0.0.1, meaning this machine
                   only, which is what you want. Anything else prints a warning.
  --ui FILE        where email-checker.html is, if it is not found automatically
  --open           open the browser for me

WHAT LEAVES YOUR COMPUTER

  The message and its attachments are read here and never uploaded. The only
  things that ever leave are, and only if you let them: a fingerprint of an
  attachment (for the malware databases), the sender's domain name (for the DNS
  check), and an address you explicitly ask to look up in the breach data.

Written by DhWonder for Plaintext IT. MIT licensed.
"""

import getpass
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from emailchecker import analyze, breach, passwords, read, report


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        print(__doc__.strip())
        return 0

    options, positional = parse_options(args)
    command = positional[0] if positional else ""

    if command == "password":
        return do_password(options)
    if command == "breach":
        return do_breach(positional[1:], options)
    if command == "serve":
        return do_serve(options)

    # Otherwise it is an email: a file, or "-" for pasted text on stdin.
    return do_email(positional, options)


def parse_options(args):
    takes_value = {"--vt-key", "--mb-key", "--hibp-key", "--save-to", "--json",
                   "--port", "--host", "--ui"}
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
def do_email(positional, options):
    text = None
    path = positional[0] if positional else ""
    if path in ("", "-"):
        if sys.stdin.isatty():
            print("Paste the email, then press Ctrl-D. Or give a filename.")
            return 2
        text = sys.stdin.buffer.read()
        loaded_list = read.load(text=text)
        origin = "pasted text"
    else:
        if not os.path.exists(path):
            print("No such file: %s" % path)
            return 2
        try:
            loaded_list = read.load(path=path)
        except Exception as exc:
            print("Could not read that email: %s" % exc)
            print("Save it as .eml, .emlx, .mbox or .msg from your mail program and try again.")
            return 2
        origin = os.path.basename(path)

    offline = bool(options.get("offline"))
    # The domain check is one DNS lookup of a name that is already public, so it
    # runs by default when online. --domain says to do it even under --offline,
    # which is the one lookup people usually still want.
    check_domain = (not offline) or bool(options.get("domain"))
    worst = 0
    reports = []
    for loaded in loaded_list:
        result = analyze.analyze_one(
            loaded, offline=offline,
            vt_key=options.get("vt-key", ""), mb_key=options.get("mb-key", ""),
            check_domain=check_domain)
        reports.append(result)
        report.render_email(result, origin)
        worst = max(worst, analyze.RANK.get(result["level"], 0))
        if options.get("save-to"):
            for name, data in loaded.attachments:
                saved = quarantine(options["save-to"], name, data)
                print("      attachment written to %s" % saved)
            print()

    if options.get("json"):
        with open(options["json"], "w", encoding="utf-8") as fh:
            json.dump(reports if len(reports) > 1 else reports[0], fh, indent=1, default=str)
        print("  Written to %s" % options["json"])
        print()
    return 1 if worst >= 2 else 0


def quarantine(folder, name, data):
    if not os.path.isdir(folder):
        os.makedirs(folder)
    safe = "".join(ch if (ch.isalnum() or ch in "._- ") else "_" for ch in name).strip() or "attachment"
    target = os.path.join(folder, safe + ".unsafe")
    with open(target, "wb") as fh:
        fh.write(data)
    os.chmod(target, 0o600)
    return target


# ---------------------------------------------------------------------------
def do_password(options):
    print()
    print("  Type or paste the password. It will not be shown, saved or logged.")
    try:
        secret = getpass.getpass("  password: ")
    except (KeyboardInterrupt, EOFError):
        print()
        return 130
    if not secret:
        print("  Nothing entered.")
        return 0

    notes, good, penalty, guess_time = passwords.analyse(secret)

    offline = bool(options.get("offline"))
    count, note = None, ""
    if not offline:
        count, error = passwords.breach_count(secret)
        if error:
            note = error + ". The strength answer above still stands."
        else:
            _state, note = passwords.describe_breach(count)

    report.render_password(notes, good, guess_time,
                           breach_count=count, breach_note=note, offline=offline)
    del secret
    return 1 if (count or penalty >= 3) else 0


def do_breach(positional, options):
    if not positional:
        print("Which address? Try: python3 email_checker.py breach someone@example.com")
        return 2
    address = positional[0].strip()
    if not breach.looks_like_email(address):
        print("That does not look like an email address: %s" % address)
        return 2

    if not options.get("yes"):
        print()
        print("  Checking an address means telling a breach database the address. Who gets asked:")
        for name, note in breach.SOURCES:
            print("      %-20s %s" % (name, note))
        print()
        try:
            answer = input("  Ask about %s? [y/N] " % address).strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            return 130
        if answer not in ("y", "yes"):
            print("  Stopped, nothing was sent.")
            return 0

    print("\n  Asking...")
    result = breach.check(address, hibp_key=options.get("hibp-key", ""))
    report.render_breach(result)
    if options.get("json"):
        with open(options["json"], "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=1, default=str)
        print("  Written to %s\n" % options["json"])
    return 1 if result["breaches"] else 0


def do_serve(options):
    from emailchecker import server
    port = int(options.get("port") or 8730)
    # 127.0.0.1 unless somebody deliberately says otherwise. The server prints
    # its own warning in that case.
    host = options.get("host") or "127.0.0.1"
    server.serve(host=host, port=port,
                 ui_path=options.get("ui"),
                 allow_online=not options.get("offline"),
                 open_browser=bool(options.get("open")))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
