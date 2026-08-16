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
| **email-checker** | Somebody forwards you a message and asks "is this real?". One verdict covering the wording, the attachments, and whether the sender's domain can be forged. Reads `.eml` through to Outlook `.msg`, and never uploads the message. |
| **domain-checker** | Could somebody send email pretending to be this business? Checks SPF, DKIM and DMARC. |
| **decoy-house** | Who is poking around inside the network? Puts up a machine worth breaking into, then records everything they do to it and what bait they take. |
| **backup-checker** | Did the backup run, and would a restore actually work? Includes a drill that pulls a real file back. |
| **system-checker** | A read only look over a Linux machine: updates, accounts, what is listening. Written in C. |

Two earlier tools, `accounts-checker` and `file-checker`, now live in
[`../tools-archive`](../tools-archive). `email-checker` does both their jobs
better, but the code is still worth reading.

## The rule they all follow

Every one of them says what it sends and what it does not. Where something has
to leave the machine, it says so before it happens and names who receives it.
Where nothing leaves, the code showing that is short enough to read.

None of them scan anybody. They read files you already have, listen to a card
you own, or ask a public record the same question a browser asks.

MIT licensed, all of them.
