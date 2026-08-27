# The tools

Eight small programs I wrote and use. They are free, they are readable, and the
notes inside the code are in plain English too, which is the best proof I can
offer that the promise runs all the way down.

Everything here is Python 3, shell, or ANSI C with nothing to install, on
purpose: the machines that need this most are often the ones you are not
allowed to install things on. The three C tools need a compiler and nothing
else, which every Linux machine either has or can get in one command.

| Tool | Answers |
|---|---|
| **traffic-analyzer** | Is somebody attacking this network, and are my sites up with valid certificates? Reads captures, watches a card live, checks websites. |
| **email-checker** | Somebody forwards you a message and asks "is this real?". Is the wording a scam, is the attachment safe to open, can the sender's domain be forged, and separately, is this password weak or this address already in a breach? Everything `accounts-checker` and `file-checker` used to answer, in one verdict. Reads `.eml` through to Outlook `.msg`, and the message never leaves the machine. |
| **domain-checker** | Could somebody send email pretending to be this business? Checks SPF, DKIM and DMARC. |
| **decoy-house** | Who is poking around inside the network? Puts up a machine worth breaking into, then records everything they do to it and what bait they take. |
| **backup-checker** | Did the backup run, and would a restore actually work? Includes a drill that pulls a real file back. |
| **system-checker** | What is this machine - make, processor, memory, graphics, disks, real or virtual - and is anything wrong with it? Written in C for Linux and PowerShell for Windows, with a wrapper that emails you when it finds something. |
| **link-cleaner** | You copied a link to send to somebody - what does it say about you? Takes the campaign tags, click identifiers, affiliate tags and share tokens off, unwraps the redirectors, and can do it to your clipboard as you copy. C, with a shell script for the clipboard. |
| **exposure-checker** | What can reach this machine from the network, and which program is behind each open door? Reads `/proc` rather than scanning, so it also knows what runs behind each port and which of them can be used to attack somebody else. C, Linux. |

The two tools that became `email-checker` now live in
[`../tools-archive`](../tools-archive): `accounts-checker` for passwords, breaches
and scam wording, `file-checker` for attachments. Answering one question used to
mean running both and holding two answers in your head. The code is still worth
reading, but there is no reason to run them.

## The rule they all follow

Every one of them says what it sends and what it does not. Where something has
to leave the machine, it says so before it happens and names who receives it.
Where nothing leaves, the code showing that is short enough to read.

None of them scan anybody. They read files you already have, listen to a card
you own, or ask a public record the same question a browser asks.

## Being told about it

Every one of them can email you when it finds something: an attack in progress,
a website down or a certificate about to expire, somebody in the honeypot, a
canary token used, an address in a breach, a domain that can be forged, a backup
that has stopped, a machine with a problem on it. It is off until you configure
it and pass `--notify`, it goes through your own mail server to your own address,
and the email carries what the tool would have printed on screen and nothing
else. [`notifications/`](notifications) is the whole story: how to set it up,
what is in the email, and how it avoids becoming the noise you learn to ignore.

This is the one part of the suite that sends rather than reads, so it is worth
reading before you switch it on rather than after.

MIT licensed, all of them.
