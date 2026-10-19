# The tools

Ten small programs I wrote and use. They are free, they are readable, and the
notes inside the code are in plain English too, which is the best proof I can
offer that the promise runs all the way down.

Everything here is Python 3, shell, or ANSI C with nothing to install, on
purpose: the machines that need this most are often the ones you are not
allowed to install things on. The C tools need a compiler; the VPN also needs OpenSSL
(`libssl-dev`), and the rest need nothing else. A compiler is something every
Linux machine either has or can get in one command.

| Tool | Answers |
|---|---|
| **traffic-analyzer** | Is somebody attacking this network, and are my sites up with valid certificates? Reads captures, watches a card live, checks websites. |
| **email-checker** | Somebody forwards you a message and asks "is this real?". Is the wording a scam, is the attachment safe to open, can the sender's domain be forged, and separately, is this password weak or this address already in a breach? Everything `accounts-checker` and `file-checker` used to answer, in one verdict. Reads `.eml` through to Outlook `.msg`, and the message never leaves the machine. |
| **domain-checker** | Could somebody send email pretending to be this business? Checks SPF and DMARC. It cannot check DKIM without the mail provider's selector, and it says so. |
| **anglerfish** | Who is poking around, and did they take the bait? A deception honeypot (NAS/SSH/FTP/mail persona) with off-host logs and a critical alert when planted bait is opened. |
| **backup-checker** | Did the backup run, and would a restore actually work? Includes a drill that pulls a real file back. |
| **system-checker** | What is this machine - make, processor, memory, graphics, disks, real or virtual - and is anything wrong with it? Written in C for Linux and PowerShell for Windows, with a wrapper that emails you when it finds something. |
| **link-cleaner** | You copied a link to send to somebody - what does it say about you? Takes the campaign tags, click identifiers, affiliate tags and share tokens off, unwraps the redirectors, and can do it to your clipboard as you copy. C, with a shell script for the clipboard. |
| **exposure-checker** | What can reach this machine from the network, and which program is behind each open door? Reads `/proc` rather than scanning, so it also knows what runs behind each port and which of them can be used to attack somebody else. C, Linux. |
| **iot-recon** | What IoT devices are on this network, what are they running, and how would each most likely get broken into? Recon, offline CVE matching and an attack-path verdict. Your targets only; intrusive steps are opt-in. Python. |
| **vpn** | How does a VPN actually work? A readable C89 build: a tun device, an authenticated-encryption UDP tunnel (ChaCha20-Poly1305), and the route takeover that pushes all traffic through the server. C. |

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

Eight of the eleven can email you when they find something. link-cleaner, iot-recon, vpn and anglerfish cannot (anglerfish uses SNS/CloudWatch instead).
exposure-checker can, through its notify wrapper, the same as the others: an attack
in progress, a website down or a certificate about to expire, somebody in the
honeypot, a canary token used, an address in a breach, a domain that can be forged,
a backup that has stopped, a machine with a problem, or a newly exposed door. It is off until you configure
it and pass `--notify`, it goes through your own mail server to your own address,
and the email carries what the tool would have printed on screen and nothing
else. [`notifications/`](notifications) is the whole story: how to set it up,
what is in the email, and how it avoids becoming the noise you learn to ignore.

This is the one part of the suite that sends rather than reads, so it is worth
reading before you switch it on rather than after.

MIT licensed, all of them.
