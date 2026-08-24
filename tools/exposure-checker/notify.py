"""
Sending you an email when something happens that you need to know about.

Every other file in this suite reads. This one sends, and that is why it is
worth reading before you switch it on. A notification is a piece of what a
tool found, leaving the machine, going to a mail server, and sitting in a
mailbox. That is a real change to the promise the rest of the suite makes, so
it is off until you configure it and ask for it, and it never sends anything
you were not told about.

What is in an email: the name of the tool, the machine it ran on, the time,
and the lines the tool would have printed on the screen. Nothing else. No
packet contents, no attacker payloads, no password you typed, no message body
from an email you were checking.

How it sends. If you give it an SMTP server it talks to that server directly.
If you do not, it hands the message to the machine's own `sendmail`, which is
how a normal server sends mail from cron. If neither is available it says so
loudly rather than quietly doing nothing, because a notification you believe
in and are not getting is worse than none at all.

The settings live in one file, `~/.plaintext/notify.conf`, shared by every
tool in the suite:

    to           = you@example.com
    from         = alerts@example.com
    smtp_host    = smtp.example.com
    smtp_port    = 587
    smtp_user    = alerts@example.com
    smtp_password= an app password, not your real one
    security     = starttls        starttls, ssl or none
    sendmail     = /usr/sbin/sendmail
    max_per_hour = 12
    gap_seconds  = 900
    subject_prefix = [plaintext]

That file holds a password, so it is created 0600 and this module complains if
anyone else on the machine can read it. `python3 notify.py setup` writes a
commented example, `python3 notify.py test` proves it works, and
`python3 notify.py show` prints what is configured without printing the
password.

Two things stop a bad night turning into a thousand emails. Each alert has a
key, and the same key does not send again until `gap_seconds` have passed. On
top of that no more than `max_per_hour` messages go out in an hour, and when
that cap swallows something the next email that does get through says how many
were suppressed. A tool that hides how much it dropped is lying to you.

Standard library only, Python 3.7 or newer, same as everything else here.
"""

import json
import os
import smtplib
import socket
import ssl
import subprocess
import sys
import threading
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

DEFAULT_CONFIG_PATH = "~/.plaintext/notify.conf"
DEFAULT_STATE_PATH = "~/.plaintext/notify-state.json"
CONFIG_ENV = "PLAINTEXT_NOTIFY_CONF"

DEFAULT_GAP_SECONDS = 900      # the same thing does not email you twice inside this
DEFAULT_MAX_PER_HOUR = 12      # a flood is a handful of emails, not a mailbox full
DEFAULT_TIMEOUT = 20

EXAMPLE_CONFIG = """\
# Settings for the notification emails the plaintext-suite tools can send.
# Every tool reads this one file. Nothing is sent unless you also pass the
# tool's --notify flag, so this file on its own is harmless.
#
# This file holds a mail password. Keep it readable only by you:
#     chmod 600 ~/.plaintext/notify.conf

# Where the notifications go. Required.
to = you@example.com

# Who they come from. Some providers insist this matches the account below.
from = you@example.com

# The mail server to send through. Leave the smtp_ lines out entirely to use
# the machine's own sendmail instead, which is what a normal server does.
smtp_host = smtp.example.com
smtp_port = 587
smtp_user = you@example.com
smtp_password =

# starttls (port 587, the usual), ssl (port 465), or none (a relay on your
# own network that does not want encryption).
security = starttls

# Where sendmail lives, used when there is no smtp_host above.
sendmail = /usr/sbin/sendmail

# How hard it is allowed to shout. gap_seconds is the quiet period before the
# same alert can email you again; max_per_hour is the ceiling on everything.
gap_seconds = 900
max_per_hour = 12

# Put this at the front of every subject line, so a mail rule can find them.
subject_prefix = [plaintext]
"""


class Result(object):
    """What happened when we tried to send. Never an exception, always an answer."""

    def __init__(self, ok, detail, sent=False):
        self.ok = ok
        self.detail = detail
        self.sent = sent

    def __bool__(self):
        return self.ok

    def __repr__(self):
        return "Result(ok=%r, sent=%r, detail=%r)" % (self.ok, self.sent, self.detail)


# ---------------------------------------------------------------------------
# The configuration file
# ---------------------------------------------------------------------------
def config_path(path=None):
    return os.path.expanduser(path or os.environ.get(CONFIG_ENV) or DEFAULT_CONFIG_PATH)


def read_config(path=None):
    """Read the settings file. Returns (settings, notes) and never raises.

    Notes are things worth telling the person running the tool: the file is
    missing, a line made no sense, the password is readable by other people.
    """
    full = config_path(path)
    notes = []
    settings = {}
    if not os.path.exists(full):
        return settings, ["there is no settings file at %s" % full]

    try:
        with open(full, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError as exc:
        return settings, ["could not read %s: %s" % (full, exc)]

    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if "=" not in line:
            notes.append("line %d of %s is not a setting: %s" % (number, full, line))
            continue
        key, value = line.split("=", 1)
        key = key.strip().lower().replace("-", "_")
        settings[key] = value.strip()

    try:
        mode = os.stat(full).st_mode
        if settings.get("smtp_password") and (mode & 0o077):
            notes.append("%s holds a mail password and other users on this machine "
                         "can read it. Fix with: chmod 600 %s" % (full, full))
    except OSError:
        pass

    return settings, notes


def write_example(path=None, overwrite=False):
    """Write the commented example settings file, readable only by its owner."""
    full = config_path(path)
    folder = os.path.dirname(full)
    if folder and not os.path.isdir(folder):
        os.makedirs(folder, 0o700)
    if os.path.exists(full) and not overwrite:
        return False, "%s already exists, so nothing was changed." % full
    with open(full, "w", encoding="utf-8") as handle:
        handle.write(EXAMPLE_CONFIG)
    os.chmod(full, 0o600)
    return True, "Wrote %s. Edit it, then run: python3 notify.py test" % full


def _number(settings, key, fallback):
    try:
        return int(str(settings.get(key, "")).strip())
    except (TypeError, ValueError):
        return fallback


# ---------------------------------------------------------------------------
# Not shouting the same thing over and over
# ---------------------------------------------------------------------------
class _State(object):
    """The small amount of memory needed to not send the same email twice.

    One JSON file. If it cannot be read or written the notifier still sends;
    losing the memory should cost you a duplicate email, not a missed alert.
    """

    def __init__(self, path=None):
        self.path = os.path.expanduser(path or DEFAULT_STATE_PATH)
        self.lock = threading.Lock()

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            data = {}
        data.setdefault("keys", {})
        data.setdefault("sent", [])
        data.setdefault("suppressed", 0)
        return data

    def _save(self, data):
        folder = os.path.dirname(self.path)
        try:
            if folder and not os.path.isdir(folder):
                os.makedirs(folder, 0o700)
            temporary = self.path + ".tmp"
            with open(temporary, "w", encoding="utf-8") as handle:
                json.dump(data, handle)
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def allow_key(self, key, gap_seconds):
        """True if this alert has not been sent recently. Records that it was."""
        if not key:
            return True
        now = time.time()
        with self.lock:
            data = self._load()
            last = data["keys"].get(key, 0)
            if now - last < gap_seconds:
                return False
            data["keys"][key] = now
            # Forget keys nobody has seen for a day, so the file stays small.
            data["keys"] = dict((k, v) for k, v in data["keys"].items()
                                if now - v < 86400)
            self._save(data)
        return True

    def take_slot(self, max_per_hour):
        """Claim one of this hour's sends. Returns (allowed, suppressed_so_far)."""
        now = time.time()
        with self.lock:
            data = self._load()
            recent = [t for t in data["sent"] if now - t < 3600]
            if len(recent) >= max_per_hour:
                data["sent"] = recent
                data["suppressed"] = int(data.get("suppressed", 0)) + 1
                self._save(data)
                return False, data["suppressed"]
            recent.append(now)
            suppressed = int(data.get("suppressed", 0))
            data["sent"] = recent
            data["suppressed"] = 0
            self._save(data)
        return True, suppressed

    def give_back_slot(self):
        """A send that failed should not count against the hourly ceiling."""
        with self.lock:
            data = self._load()
            if data["sent"]:
                data["sent"].pop()
            self._save(data)


# ---------------------------------------------------------------------------
# The notifier itself
# ---------------------------------------------------------------------------
class Notifier(object):
    """One tool's way of emailing you. Ask it to send; it tells you what happened.

    Nothing here raises. A tool that dies because its mail server was down
    would be a worse tool than one that never emailed at all, so every failure
    comes back as a Result you can print.
    """

    def __init__(self, tool, enabled=True, config=None, state_path=None, log=None):
        self.tool = tool
        self.enabled = bool(enabled)
        self.config_file = config_path(config)
        self.settings, self.notes = read_config(config)
        self.state = _State(state_path)
        self.log = log or (lambda message: None)
        self.hostname = socket.gethostname()

        self.gap_seconds = _number(self.settings, "gap_seconds", DEFAULT_GAP_SECONDS)
        self.max_per_hour = _number(self.settings, "max_per_hour", DEFAULT_MAX_PER_HOUR)
        self.timeout = _number(self.settings, "timeout", DEFAULT_TIMEOUT)
        self.available, self.reason = self._check()

    # -- is this thing going to work? -----------------------------------
    def _check(self):
        if not self.enabled:
            return False, "notifications were not asked for"
        if not self.settings:
            return False, ("no settings file at %s. Write an example with the "
                           "'notify setup' command of any tool in the suite"
                           % self.config_file)
        if not self.settings.get("to"):
            return False, "%s does not say who to email (the 'to' line)" % self.config_file
        if self.settings.get("smtp_host"):
            return True, ""
        sendmail = self._sendmail_path()
        if sendmail:
            return True, ""
        return False, ("%s has no smtp_host, and this machine has no sendmail to fall "
                       "back on, so there is no way to send mail from here"
                       % self.config_file)

    def _sendmail_path(self):
        candidates = [self.settings.get("sendmail"), "/usr/sbin/sendmail",
                      "/usr/lib/sendmail", "/usr/bin/sendmail"]
        for path in candidates:
            if path and os.path.exists(path) and os.access(path, os.X_OK):
                return path
        return ""

    def describe(self):
        """One line saying who gets told and how. Never prints the password."""
        if not self.available:
            return "notifications off: %s" % self.reason
        where = self.settings.get("to")
        if self.settings.get("smtp_host"):
            how = "%s:%s" % (self.settings["smtp_host"],
                             self.settings.get("smtp_port", "587"))
            if self.settings.get("smtp_user"):
                how += " as %s" % self.settings["smtp_user"]
        else:
            how = "this machine's %s" % self._sendmail_path()
        return "notifications on: email to %s through %s" % (where, how)

    # -- deciding whether to say anything -------------------------------
    def allow(self, key, gap_seconds=None):
        """Has this particular alert been quiet long enough to email about?

        Separate from send() on purpose: a tool that finds five new attackers
        in one go should check five keys and then send one email about all of
        them, rather than five emails.
        """
        if not self.available:
            return False
        gap = self.gap_seconds if gap_seconds is None else gap_seconds
        return self.state.allow_key(key, gap)

    # -- sending ---------------------------------------------------------
    def send(self, subject, lines, key=None, gap_seconds=None, context=None):
        """Send one notification. Returns a Result; never raises.

        `lines` is what the tool would have printed: a list of strings, or one
        string. `key` is what this alert is about, so the same thing does not
        email you repeatedly. `context` is a dict of short facts shown at the
        top, like the interface or the sensor name.
        """
        if not self.available:
            return Result(False, self.reason)

        if key is not None and not self.allow(key, gap_seconds):
            return Result(True, "held back: already emailed about %s recently" % key)

        allowed, suppressed = self.state.take_slot(self.max_per_hour)
        if not allowed:
            detail = ("held back: already sent %d emails this hour, which is the "
                      "max_per_hour limit" % self.max_per_hour)
            self.log(detail)
            return Result(True, detail)

        message = self.build_message(subject, lines, context=context,
                                     suppressed=suppressed)
        try:
            if self.settings.get("smtp_host"):
                self._send_smtp(message)
            else:
                self._send_sendmail(message)
        except Exception as exc:                      # any failure, one answer
            self.state.give_back_slot()
            detail = "could not send the notification: %s: %s" % (type(exc).__name__, exc)
            self.log(detail)
            return Result(False, detail)

        detail = "emailed %s: %s" % (self.settings.get("to"), subject)
        self.log(detail)
        return Result(True, detail, sent=True)

    def send_async(self, subject, lines, key=None, gap_seconds=None, context=None,
                   done=None):
        """Send on a thread of its own, for tools that cannot afford to wait.

        A live packet capture stops capturing while it talks to a mail server,
        which is exactly the wrong moment to go deaf. The decision about
        whether to send at all is made here, on the calling thread, so the
        duplicate check still holds.
        """
        if not self.available:
            return Result(False, self.reason)
        if key is not None and not self.allow(key, gap_seconds):
            return Result(True, "held back: already emailed about %s recently" % key)

        def worker():
            result = self.send(subject, lines, key=None, context=context)
            if done is not None:
                done(result)

        thread = threading.Thread(target=worker, name="plaintext-notify")
        thread.daemon = True
        thread.start()
        return Result(True, "sending in the background")

    # -- the message -----------------------------------------------------
    def build_message(self, subject, lines, context=None, suppressed=0):
        if isinstance(lines, str):
            lines = lines.splitlines()
        prefix = self.settings.get("subject_prefix", "[plaintext]")
        sender = self.settings.get("from") or ("plaintext-suite@%s" % self.hostname)

        body = []
        body.append("%s on %s" % (self.tool, self.hostname))
        body.append(time.strftime("%Y-%m-%d %H:%M:%S %z"))
        body.append("")
        for name, value in sorted((context or {}).items()):
            body.append("%-12s %s" % (name + ":", value))
        if context:
            body.append("")
        body.extend(list(lines))
        if suppressed:
            body.append("")
            body.append("%d other notification%s in the last hour were not sent, because "
                        "of the max_per_hour limit in %s."
                        % (suppressed, "" if suppressed == 1 else "s", self.config_file))
        body.append("")
        body.append("-- ")
        body.append("Sent by %s (plaintext-suite) on %s, because notifications are "
                    "switched on for it." % (self.tool, self.hostname))
        body.append("This email is the only thing that left the machine. To stop these, "
                    "drop the --notify flag or delete %s." % self.config_file)

        message = EmailMessage()
        message["From"] = sender
        message["To"] = self.settings["to"]
        message["Subject"] = ("%s %s" % (prefix, subject)).strip()
        message["Date"] = formatdate(localtime=True)
        try:
            message["Message-ID"] = make_msgid(domain=self.hostname)
        except Exception:
            message["Message-ID"] = make_msgid()
        message["Auto-Submitted"] = "auto-generated"
        message["X-Plaintext-Tool"] = self.tool
        message.set_content("\n".join(body) + "\n")
        return message

    # -- the two ways out of the machine ---------------------------------
    def _send_smtp(self, message):
        host = self.settings["smtp_host"]
        security = (self.settings.get("security") or "").strip().lower()
        port = _number(self.settings, "smtp_port", 465 if security == "ssl" else 587)
        if not security:
            security = "ssl" if port == 465 else ("none" if port == 25 else "starttls")

        if security == "ssl":
            server = smtplib.SMTP_SSL(host, port, timeout=self.timeout,
                                      context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(host, port, timeout=self.timeout)
        try:
            server.ehlo()
            if security == "starttls":
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
            user = self.settings.get("smtp_user")
            if user:
                server.login(user, self.settings.get("smtp_password", ""))
            server.send_message(message)
        finally:
            try:
                server.quit()
            except Exception:
                pass

    def _send_sendmail(self, message):
        path = self._sendmail_path()
        if not path:
            raise RuntimeError("no sendmail on this machine and no smtp_host configured")
        process = subprocess.Popen([path, "-t", "-oi"], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _out, err = process.communicate(message.as_bytes(), timeout=self.timeout)
        if process.returncode != 0:
            raise RuntimeError("%s exited %d: %s"
                               % (path, process.returncode,
                                  (err or b"").decode("utf-8", "replace").strip()))

    # -- proving it works before you rely on it ---------------------------
    def test(self):
        """Send a test message, ignoring both the duplicate check and the cap."""
        if not self.available:
            return Result(False, self.reason)
        lines = [
            "This is a test notification. Nothing is wrong.",
            "",
            "It was sent because somebody ran the test command, which is the",
            "right way to find out that the settings are wrong: now, rather",
            "than on the night something actually happens.",
        ]
        message = self.build_message("test notification from %s" % self.hostname, lines)
        try:
            if self.settings.get("smtp_host"):
                self._send_smtp(message)
            else:
                self._send_sendmail(message)
        except Exception as exc:
            return Result(False, "could not send: %s: %s" % (type(exc).__name__, exc))
        return Result(True, "test email sent to %s" % self.settings["to"], sent=True)


# ---------------------------------------------------------------------------
# A helper every tool's command line uses, so they all behave the same way
# ---------------------------------------------------------------------------
def from_options(tool, options, log=None):
    """Build a Notifier from a tool's parsed --notify / --notify-config options.

    Returns (notifier, message_to_print). The message is never empty when
    notifications were asked for: either it says where mail will go, or it says
    why it will not. Silence about a notification that will never arrive is the
    one behaviour worth ruling out.
    """
    wanted = bool(options.get("notify"))
    config = options.get("notify-config") or options.get("notify_config") or None
    if isinstance(config, bool):
        config = None
    notifier = Notifier(tool, enabled=wanted, config=config, log=log)
    if not wanted:
        return notifier, ""
    lines = list(notifier.notes) if notifier.available else []
    lines.append(notifier.describe())
    return notifier, "\n".join("  " + line for line in lines)


# ---------------------------------------------------------------------------
# Run this file directly to set it up, test it, or send one message
# ---------------------------------------------------------------------------
USAGE = """\
notify.py: the notification email settings shared by the plaintext-suite tools.

  python3 notify.py setup            write an example ~/.plaintext/notify.conf
  python3 notify.py show             what is configured (never the password)
  python3 notify.py test             send a test email and say what happened
  python3 notify.py send --tool NAME --subject TEXT [--key K] [--gap SECONDS]
                                     send one message, body read from stdin

Nothing is sent unless the settings file exists and a tool was asked to notify.
"""


def _cli_show(config):
    notifier = Notifier("notify.py", enabled=True, config=config)
    print()
    print("  Settings file: %s" % notifier.config_file)
    for note in notifier.notes:
        print("  Note:          %s" % note)
    print("  %s" % notifier.describe())
    if notifier.available:
        print("  Quiet period:  %d seconds before the same alert emails again"
              % notifier.gap_seconds)
        print("  Ceiling:       %d emails an hour" % notifier.max_per_hour)
        if notifier.settings.get("smtp_password"):
            print("  Password:      set (not shown)")
    print()
    return 0 if notifier.available else 1


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE.strip())
        return 0

    command = argv[0]
    options = {}
    index = 1
    while index < len(argv):
        item = argv[index]
        if item.startswith("--"):
            name = item[2:]
            value = argv[index + 1] if index + 1 < len(argv) else ""
            if value.startswith("--") or index + 1 >= len(argv):
                options[name] = True
                index += 1
            else:
                options[name] = value
                index += 2
            continue
        index += 1

    config = options.get("config")
    if isinstance(config, bool):
        config = None

    if command == "setup":
        ok, message = write_example(config, overwrite=bool(options.get("force")))
        print(message)
        return 0 if ok else 1

    if command == "show":
        return _cli_show(config)

    if command == "test":
        notifier = Notifier("notify.py", enabled=True, config=config)
        for note in notifier.notes:
            print("  %s" % note)
        result = notifier.test()
        print("  %s" % result.detail)
        return 0 if result.ok else 1

    if command == "send":
        tool = options.get("tool") or "plaintext-suite"
        subject = options.get("subject") or "notification"
        key = options.get("key")
        gap = options.get("gap")
        notifier = Notifier(tool if isinstance(tool, str) else "plaintext-suite",
                            enabled=True, config=config)
        body = sys.stdin.read() if not sys.stdin.isatty() else ""
        result = notifier.send(subject if isinstance(subject, str) else "notification",
                               body.splitlines() or ["(no detail)"],
                               key=key if isinstance(key, str) else None,
                               gap_seconds=int(gap) if isinstance(gap, str) and gap.isdigit() else None)
        print(result.detail)
        return 0 if result.ok else 1

    print(USAGE.strip())
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
