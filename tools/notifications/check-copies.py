#!/usr/bin/env python3
"""
Proving the copies of notify.py are still the same file, and that it works.

Every tool here is a folder you can copy to a server on its own, so each one
carries its own copy of notify.py rather than importing a shared one. That is
the right trade for the person running it and the wrong one for the person
maintaining it: five copies drift. This script is the thing that stops them.

    python3 check-copies.py            check the copies match, then self test
    python3 check-copies.py --sync     copy the master over every tool's copy

The master is notify.py next to this script. Edit that one, run --sync, commit
both. The self test sends nothing: it uses a fake sendmail that writes the
message to a file, so it proves the plumbing without needing a mail server.
"""

import hashlib
import importlib.util
import os
import shutil
import stat
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MASTER = os.path.join(HERE, "notify.py")

COPIES = [
    "../traffic-analyzer/trafficanalyzer/notify.py",
    "../decoy-house/decoyhouse/notify.py",
    "../email-checker/emailchecker/notify.py",
    "../domain-checker/notify.py",
    "../backup-checker/notify.py",
    "../system-checker/notify.py",
]


def digest(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def check_copies():
    master = digest(MASTER)
    problems = []
    print("  master  %s  %s" % (master[:12], os.path.relpath(MASTER, HERE)))
    for relative in COPIES:
        path = os.path.abspath(os.path.join(HERE, relative))
        if not os.path.exists(path):
            problems.append("missing: %s" % relative)
            print("  MISSING          %s" % relative)
            continue
        found = digest(path)
        same = found == master
        print("  %-7s %s  %s" % ("ok" if same else "DIFFERS", found[:12], relative))
        if not same:
            problems.append("out of date: %s" % relative)
    return problems


def sync_copies():
    for relative in COPIES:
        path = os.path.abspath(os.path.join(HERE, relative))
        folder = os.path.dirname(path)
        if not os.path.isdir(folder):
            print("  no such folder, skipped: %s" % folder)
            continue
        shutil.copyfile(MASTER, path)
        print("  wrote %s" % relative)
    return []


# ---------------------------------------------------------------------------
def load_master():
    spec = importlib.util.spec_from_file_location("plaintext_notify_master", MASTER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def self_test():
    notify = load_master()
    failures = []

    def check(name, condition, detail=""):
        print("  %-46s %s" % (name, "ok" if condition else "FAILED"))
        if not condition:
            failures.append("%s %s" % (name, detail))

    workspace = tempfile.mkdtemp(prefix="notify-test-")
    config_file = os.path.join(workspace, "notify.conf")
    state_file = os.path.join(workspace, "state.json")
    outbox = os.path.join(workspace, "outbox.txt")

    # A sendmail that is not sendmail: it writes what it was given to a file.
    fake_sendmail = os.path.join(workspace, "fake-sendmail")
    with open(fake_sendmail, "w", encoding="utf-8") as handle:
        handle.write("#!/bin/sh\ncat >> %s\n" % outbox)
    os.chmod(fake_sendmail, os.stat(fake_sendmail).st_mode | stat.S_IEXEC)

    with open(config_file, "w", encoding="utf-8") as handle:
        handle.write("to = someone@example.com\n"
                     "from = tools@example.com\n"
                     "sendmail = %s\n"
                     "gap_seconds = 60\n"
                     "max_per_hour = 2\n"
                     "subject_prefix = [test]\n"
                     "# a comment\n"
                     "nonsense line without an equals sign\n" % fake_sendmail)
    os.chmod(config_file, 0o600)

    settings, notes = notify.read_config(config_file)
    check("settings file is read", settings.get("to") == "someone@example.com", settings)
    check("a broken line is reported, not fatal",
          any("not a setting" in note for note in notes), notes)

    notifier = notify.Notifier("test-tool", enabled=True, config=config_file,
                               state_path=state_file)
    check("it knows it can send", notifier.available, notifier.reason)
    check("it says how", "someone@example.com" in notifier.describe(), notifier.describe())

    disabled = notify.Notifier("test-tool", enabled=False, config=config_file,
                               state_path=state_file)
    check("off unless asked for", not disabled.available, disabled.reason)

    message = notifier.build_message("something happened", ["a line", "another line"],
                                     context={"sensor": "web-01"})
    text = message.as_string()
    check("subject carries the prefix", "[test] something happened" in text)
    check("the body has what the tool said", "another line" in text)
    check("the body says what the email is", "plaintext-suite" in text)

    first = notifier.send("first alert", ["one"], key="thing")
    check("the first alert sends", first.ok and first.sent, first.detail)
    second = notifier.send("first alert again", ["one"], key="thing")
    check("the same alert does not send twice",
          second.ok and not second.sent and "held back" in second.detail, second.detail)
    other = notifier.send("a different alert", ["two"], key="other-thing")
    check("a different alert does send", other.ok and other.sent, other.detail)

    third = notifier.send("over the ceiling", ["three"], key="third-thing")
    check("the hourly ceiling stops the third",
          third.ok and not third.sent and "max_per_hour" in third.detail, third.detail)

    sent = ""
    if os.path.exists(outbox):
        with open(outbox, "r", encoding="utf-8") as handle:
            sent = handle.read()
    check("two messages actually reached sendmail", sent.count("Subject:") == 2,
          sent.count("Subject:"))

    # A failing transport must come back as an answer, not an exception, and
    # must not eat one of the hour's slots.
    broken = notify.Notifier("test-tool", enabled=True, config=config_file,
                             state_path=state_file)
    broken.settings["sendmail"] = os.path.join(workspace, "does-not-exist")
    broken.max_per_hour = 50
    result = broken.send("this cannot be sent", ["nothing"], key="broken")
    check("a broken sender reports instead of raising",
          (not result.ok) and "could not send" in result.detail, result.detail)

    loose = os.path.join(workspace, "loose.conf")
    with open(loose, "w", encoding="utf-8") as handle:
        handle.write("to = a@b.c\nsmtp_host = mail.example.com\nsmtp_password = hunter2\n")
    os.chmod(loose, 0o644)
    _settings, loose_notes = notify.read_config(loose)
    check("a world readable password is called out",
          any("chmod 600" in note for note in loose_notes), loose_notes)

    shutil.rmtree(workspace, ignore_errors=True)
    return failures


def main():
    if not os.path.exists(MASTER):
        print("No master notify.py next to this script.")
        return 2

    syncing = "--sync" in sys.argv[1:]
    print()
    print("  The copies" + (" (syncing from the master)" if syncing else ""))
    print("  " + "-" * 60)
    problems = sync_copies() if syncing else check_copies()
    print()

    print("  Does it work")
    print("  " + "-" * 60)
    failures = self_test()
    print()

    if problems:
        print("  %d copy problem(s). Fix with: python3 check-copies.py --sync"
              % len(problems))
    if failures:
        print("  %d self test failure(s)." % len(failures))
    if not problems and not failures:
        print("  All copies match the master, and it works.")
    print()
    return 1 if (problems or failures) else 0


if __name__ == "__main__":
    sys.exit(main())
