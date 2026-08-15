#!/usr/bin/env python3
"""
accounts-checker: can this account, or this message, be trusted?

Three questions that come up constantly in small businesses, answered in plain
English by one tool instead of three.

USAGE

  Is this password any good, and has it already been stolen?
      python3 accounts_checker.py password
      python3 accounts_checker.py password --offline

  Has this email address appeared in a breach?
      python3 accounts_checker.py email someone@example.com
      python3 accounts_checker.py email someone@example.com --hibp-key KEY

  Is this message a scam?
      python3 accounts_checker.py message suspicious.eml

OPTIONS

  --offline      do not contact anything. Password strength only.
  --hibp-key K   use a Have I Been Pwned key for the address lookup
  --yes          skip the "this sends the address out" confirmation
  --json FILE    also write the findings as JSON

WHAT LEAVES YOUR COMPUTER

  password    nothing. Five characters of a one way fingerprint are sent, and
              that matches hundreds of thousands of different passwords. The
              password itself never leaves, and the code showing that is in
              accountschecker/passwords.py.
  email       the address itself, to the breach databases. It cannot be done
              any other way, so the tool asks first and names them.
  message     nothing at all. The file is read here and no link is opened.

Written by DhWonder for Plaintext IT. MIT licensed.
"""

import getpass
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from accountschecker import emails, messages, passwords


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        print(__doc__.strip())
        return 0

    options, positional = parse_options(args)
    command = positional[0] if positional else ""

    if command == "password":
        return check_password(options)
    if command == "email":
        return check_email(positional[1:], options)
    if command == "message":
        return check_message(positional[1:], options)

    # Be forgiving: work out what they meant from what they typed.
    if command and emails.looks_like_email(command):
        return check_email(positional, options)
    if command and os.path.exists(command):
        return check_message(positional, options)

    print("I do not know what to do with that. Try one of:")
    print("  python3 accounts_checker.py password")
    print("  python3 accounts_checker.py email someone@example.com")
    print("  python3 accounts_checker.py message suspicious.eml")
    return 2


def parse_options(args):
    takes_value = {"--hibp-key", "--json"}
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


def rule(title):
    print()
    print("=" * 70)
    print("  " + title)
    print("=" * 70)
    print()


def wrap(text, width=66):
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


def say(text, indent="  "):
    for line in wrap(text):
        print(indent + line)


# ---------------------------------------------------------------------------
def check_password(options):
    print()
    print("  Type or paste the password. It will not be shown, saved or logged.")
    print("  Press enter on an empty line to cancel.")
    print()
    try:
        secret = getpass.getpass("  password: ")
    except (KeyboardInterrupt, EOFError):
        print()
        return 130
    if not secret:
        print("  Nothing entered.")
        return 0

    notes, good, penalty, guess_time = passwords.analyse(secret)

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

    count = None
    if options.get("offline"):
        print("  Breach check skipped, because you asked for offline only.")
    else:
        rule("Has it already been stolen?")
        count, error = passwords.breach_count(secret)
        if error:
            say(error + ". The strength answer above still stands.")
        else:
            state, explanation = passwords.describe_breach(count)
            say(explanation)
    print()

    # A leaked password beats every other consideration, so say so last, loudest.
    if count:
        rule("What to do")
        say("Change this password anywhere it is used, starting with email, then banking, "
            "then anything that can spend money. Email first because whoever controls the "
            "mailbox can reset everything else.")
        print()
    del secret
    return 1 if (count or penalty >= 3) else 0


# ---------------------------------------------------------------------------
def check_email(positional, options):
    if not positional:
        print("Which address? Try: python3 accounts_checker.py email someone@example.com")
        return 2
    address = positional[0].strip()
    if not emails.looks_like_email(address):
        print("That does not look like an email address: %s" % address)
        return 2

    if not options.get("yes"):
        print()
        say("Checking an address means telling somebody else the address. There is no way "
            "around that, so here is exactly who gets asked:")
        print()
        for name, note in emails.SOURCES:
            print("      %-20s %s" % (name, note))
        print()
        say("Check your own address freely. Check a client's only if they have agreed to it. "
            "Somebody else's is not your business.")
        print()
        try:
            answer = input("  Ask about %s? [y/N] " % address).strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            return 130
        if answer not in ("y", "yes"):
            print("  Stopped, nothing was sent.")
            return 0

    print()
    print("  Asking...")
    result = emails.check(address, hibp_key=options.get("hibp-key", ""))

    rule(result["verdict"][0])
    say(result["verdict"][1])
    print()

    print("  Who answered")
    for source in result["sources"]:
        if source.get("ok"):
            found = len(source["breaches"])
            state = "%d found" % found if found else "nothing found"
        else:
            state = source.get("error", "no answer")
        print("      %-20s %s" % (source["source"], state))
    print()

    if result["breaches"]:
        print("  Where it turned up")
        for name in result["breaches"][:25]:
            print("      - %s" % name)
        if len(result["breaches"]) > 25:
            print("      ... and %d more" % (len(result["breaches"]) - 25))
        print()

    if result["exposed_types"]:
        print("  What was exposed in those breaches")
        say(", ".join(result["exposed_types"][:14]), "      ")
        print()

    if result["breaches"]:
        rule("What to do")
        say("1. Change the password on any site in that list where you still have an account, "
            "and anywhere you used the same password.")
        print()
        say("2. Turn on two step login for email first, then banking, then anything that pays "
            "money. That single step defeats almost every use of a stolen password.")
        print()
        say("3. Expect more convincing scams to this address. Whoever bought the breach knows "
            "where you had accounts, which is what makes their emails believable.")
        print()

    if options.get("json"):
        with open(options["json"], "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=1)
        print("  Written to %s" % options["json"])
        print()
    return 1 if result["breaches"] else 0


# ---------------------------------------------------------------------------
def check_message(positional, options):
    if not positional:
        print("Which file? Try: python3 accounts_checker.py message suspicious.eml")
        return 2
    path = positional[0]
    if not os.path.exists(path):
        print("No such file: %s" % path)
        return 2

    try:
        result = messages.examine(path)
    except Exception as exc:
        print("Could not read that message: %s" % exc)
        print("Save it as .eml from your mail program, then try again.")
        return 2

    rule(result["verdict"][0])
    print("  From:    %s" % (result["from"] or "(missing)"))
    print("  Subject: %s" % (result["subject"] or "(missing)"))
    if result["reply_to"]:
        print("  Replies: %s" % result["reply_to"])
    print()
    say(result["verdict"][1])
    print()

    if result["findings"]:
        print("  What is wrong with it")
        print()
        labels = {3: "STRONG SIGN", 2: "BAD SIGN", 1: "SMALL SIGN"}
        for weight, explanation in result["findings"]:
            print("    [%s]" % labels.get(weight, "SIGN"))
            say(explanation, "      ")
            print()

    attachments = messages.attachment_summary(path)
    if attachments:
        print("  Attached to it")
        for item in attachments:
            print("      %-34s %-28s %s bytes"
                  % (item["name"][:34], item["type"], "{:,}".format(item["bytes"])))
        print()
        say("None of those were opened. To look inside them safely, run file-checker on this "
            "same message.")
        print()

    if options.get("json"):
        with open(options["json"], "w", encoding="utf-8") as fh:
            json.dump({k: v for k, v in result.items() if k != "findings"}, fh, indent=1)
        print("  Written to %s" % options["json"])
        print()
    return 1 if result["findings"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
