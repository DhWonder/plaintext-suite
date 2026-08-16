# Notifications

Getting an email when one of these tools finds something.

Everything else in this suite reads and reports. This is the one part that
sends, so it is off until you set it up and ask for it, and everything about it
is built to be checkable: one settings file you can read, one module you can
read, and an email that says at the bottom exactly why it arrived.

## What can tell you

| Tool | It emails you when |
|---|---|
| **traffic-analyzer** | a live capture sees a source turn hostile — a flood, a scan, a reflection attack — or a site check finds one of your sites down or its certificate dying |
| **decoy-house** | somebody connects to a honeypot sensor, and — the one that matters — when a canary token is used |
| **email-checker** | a breach lookup finds the address, or a password you checked is in the leaked set |
| **domain-checker** | a domain can be forged: SPF or DMARC missing, weak or broken |
| **backup-checker** | the backup has stopped running, has shrunk, or a restore drill failed |
| **system-checker** | the look-over of a machine found something worth attention, through the `plain-check-notify.sh` wrapper |

Each of them takes `--notify`. Without it nothing is sent, whatever is in the
settings file.

`system-checker` is the odd one out: it is C, and teaching a C program to speak
SMTP would mean a second copy of this logic in a second language, which is how
two tools end up disagreeing about what they sent. So the C program is left
alone — it reads, prints, and exits 0, 1 or 2 — and a small shell wrapper next
to it runs it and hands the output here.

That wrapper is worth reading if you want to do the same with something of your
own, because the general form is one line:

```
your-script | python3 notify.py send --tool your-script --subject "it went wrong"
```

Anything that prints can be notified about. `--key SOMETHING` gives it a quiet
period like everything else.

## Setting it up

Every tool shares one settings file, `~/.plaintext/notify.conf`, and every tool
can write, inspect and test it with the same three commands:

```
python3 traffic_analyzer.py notify setup     # writes a commented example
python3 traffic_analyzer.py notify show      # what is configured, minus the password
python3 traffic_analyzer.py notify test      # sends a test email and says what happened
```

`decoy_house.py notify`, `email_checker.py notify`, `domain_checker.py notify`
and `sh backup-witness.sh notify` all do the same thing. Use whichever tool you
have open.

Then edit the file:

```
to           = you@example.com
from         = alerts@example.com
smtp_host    = smtp.example.com
smtp_port    = 587
smtp_user    = alerts@example.com
smtp_password= an app password, not the real one
security     = starttls
```

**Use an app password, not your normal one.** Google, Microsoft and most
providers will issue one for a single program, and you can revoke it without
touching your account. It is going to sit in a file on a server; treat it as
something you expect to lose one day.

The file is created readable only by you, and the tools complain if it is not:

```
chmod 600 ~/.plaintext/notify.conf
```

**Or send nothing at all yourself.** Leave the `smtp_` lines out and the message
is handed to the machine's own `sendmail`, which is how a normal server sends
mail from cron. No password is stored anywhere in that case. It only works if
the machine has a working mail setup — a stock cloud instance usually does not,
which is what `notify test` is for.

## Then turn it on

```
sudo python3 traffic_analyzer.py live eth0 --notify
python3 traffic_analyzer.py sites clients.txt --notify
python3 decoy_house.py console --notify
python3 email_checker.py breach you@example.com --yes --notify
python3 domain_checker.py acme-bakery.com --notify
sh backup-witness.sh check /mnt/backup --notify
sh plain-check-notify.sh
```

Each one prints where mail will go before it starts working, or prints why it
cannot. It never starts silently believing it can email you.

## How it avoids becoming noise

A tool that emails you five hundred times in a night has taught you to filter it
out, which is worse than never having emailed at all.

- **Every alert has a key** — an address, a sensor, a token, a folder — and the
  same key does not email again until `gap_seconds` have passed (15 minutes by
  default). Twenty new hostile sources inside one flush are one email listing
  twenty, not twenty emails.
- **There is a ceiling**, `max_per_hour`, 12 by default. When it swallows
  something, the next email that does get through says how many were suppressed.
  A tool that quietly drops things is lying to you.
- **Good news is not emailed.** A domain that is protected, a backup that ran, a
  breach lookup that found nothing, a site answering with a healthy certificate:
  all silent. An all-clear that arrives every
  night is an email you stop opening, and then you stop opening the real one too.

Everything is still recorded in full where it always was — the database, the
log, the report on screen. The email is a nudge to go and look, not the record.

## What is in the email

The name of the tool, the machine it ran on, the time, and the lines the tool
would have printed on screen. Nothing else.

Not in it, ever: captured packet contents, anything an attacker typed being
executed, a password you typed into `email-checker`, or any part of an email
message you were checking. `decoy-house` does include what an attacker typed at
the honeypot and the fake credentials they tried, because that is the finding.

## Where the code is

`notify.py` here is the master copy, about three hundred readable lines of
standard library Python. Every tool carries its own identical copy, because each
tool is a folder you can copy to a server on its own and it would be a poor
trade to break that for one shared file.

Copies drift, so there is a script that stops them:

```
python3 check-copies.py          # are they all the same file, and does it work?
python3 check-copies.py --sync   # copy the master over all of them
```

Edit `notify.py` here, run `--sync`, commit both. The self test needs no mail
server: it uses a fake `sendmail` that writes the message to a file, and checks
the quiet period, the hourly ceiling, a failing transport, and the warning about
a world-readable password.

## Honest limitations

- **An email is not a guarantee.** The mail server can be down, the machine's
  network can be the thing under attack, the message can land in spam. If the
  send fails the tool says so on screen and in its log, and carries on doing its
  real job. Do not build a process that assumes silence means nothing happened.
- **It is one way.** Nothing reads a mailbox, nothing takes commands from email,
  no tool here can be driven by a message you receive.
- **The password is in a file.** SMTP has no better answer. Use an app password,
  keep the file at 0600, and on a machine you have decided to treat as
  untrusted — a honeypot sensor — do not put it there at all. That is why
  `decoy-house` only sends from the console.
