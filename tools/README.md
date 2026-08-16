# The tools

Six small programs I wrote and use. They are free, they are readable, and the
notes inside the code are in plain English too, which is the best proof I can
offer that the promise runs all the way down.

Everything here is Python 3 or shell with nothing to install, on purpose: the
machines that need this most are often the ones you are not allowed to install
things on.

| Tool | Answers |
|---|---|
| **traffic-analyzer** | Is somebody attacking this network, and are my sites up with valid certificates? Reads captures, watches a card live, checks websites. |
| **email-checker** | Somebody forwards you a message and asks "is this real?". Is the wording a scam, is the attachment safe to open, can the sender's domain be forged, and separately, is this password weak or this address already in a breach? Everything `accounts-checker` and `file-checker` used to answer, in one verdict. Reads `.eml` through to Outlook `.msg`, and the message never leaves the machine. |
| **domain-checker** | Could somebody send email pretending to be this business? Checks SPF, DKIM and DMARC. |
| **decoy-house** | Who is poking around inside the network? Puts up a machine worth breaking into, then records everything they do to it and what bait they take. |
| **backup-checker** | Did the backup run, and would a restore actually work? Includes a drill that pulls a real file back. |
| **system-checker** | A read only look over a Linux machine: updates, accounts, what is listening. Written in C. |

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

MIT licensed, all of them.
