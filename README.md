# plaintext-suite

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)


Security tools that read, explain, and do not guess.

## Still a work in progress

Small tools for small businesses. Each one does a specific job, runs on its own without
a service behind it, and says what it found in plain English, including when the
honest answer is "I cannot tell you that." Every tool has its own README with its
limitations written down.

## The tools

| Tool | Language | What it does |
|------|----------|--------------|
| [traffic-analyzer](tools/traffic-analyzer) | Python | Reads a network capture and works out who is flooding you, how, and what to change. Includes a packet browser with Wireshark style filters, for when the question is "show me the actual packet". |
| [anglerfish](tools/anglerfish) | Python | A low-cost deception honeypot that looks like a real NAS/SSH/FTP/mail host, ships structured logs off-box, and alerts when bait is taken. Persona and secrets live in config, not the repo. |
| [email-checker](tools/email-checker) | Python | Is this email a scam, is the attachment safe to open, where do its links actually go, can the sender's domain be forged, and has this password or address been leaked? One verdict, and the message never leaves your machine. |
| [domain-checker](tools/domain-checker) | Python | Can a criminal send email pretending to be this business? Checks SPF, DMARC, and probes a list of common DKIM selectors. See also [spoof-proof](https://github.com/DhWonder/redline-suite/tree/main/tools/spoof-proof), the red-team demo companion. |
| [backup-checker](tools/backup-checker) | shell | Verifies backups actually ran, and that they can actually restore. |
| [system-checker](tools/system-checker) | C + PowerShell | What is this machine (make, OS, processor, memory, graphics, disks, network, real or virtual) and is anything wrong with it. C for Linux, PowerShell for Windows, same report from both. |
| [link-cleaner](tools/link-cleaner) | C + shell | Takes the tracking off a link before you send it. Campaign tags, click identifiers, affiliate tags, share tokens and highlighted-sentence fragments, plus the redirectors that wrap a link only to record the click. Watches the clipboard if you want it to. |
| [exposure-checker](tools/exposure-checker) | C | What can reach this machine, and what is behind each door. Names the program holding every open port, tells a loopback service apart from a genuinely open one, and says whether "every network" includes the internet. Reads `/proc`; scans nothing. |
| [iot-recon](tools/iot-recon) | Python | Authorized IoT assessment: finds a smart device's ports, services and UPnP details, matches known CVEs from an offline database, and names the most likely way each device gets owned. Acts only on targets you name; everything intrusive is opt-in. |
| [vpn](tools/vpn) | C | A working VPN in C89: a tun device, an encrypted UDP tunnel (ChaCha20-Poly1305) and the route takeover that sends every packet out through the server. A teaching build with the reasoning written down. |

Eight of the eleven can email you when they find something, which is the difference between
a tool that answers a question and one that watches for you. It is off
until you set it up and ask for it, it goes through your own mail server, and
[`tools/notifications`](tools/notifications) says exactly what ends up in the
message. That is the only part of the suite that sends anything anywhere.

Start with **traffic-analyzer**. It parses capture files by hand, tells a SYN flood
apart from a port scan, spots reflection attacks, and finishes with recommendations
you can act on.

## Two rules the newer work follows

**Ask more than one database, and cross the answers.** Where a tool asks something
outside itself, whether an address is a known attacker or a link goes somewhere real, it
asks several sources and says who said what. One database is a rumour; several that
agree are a finding. The disagreements matter most: an address VirusTotal calls
malicious that GreyNoise names as a known scanner is internet wide noise, not an attack
aimed at you, and a tool that only asked one of them would have told you the wrong
thing. The free sources are asked first, so these checks work with no account anywhere.

**Never a silent wrong answer.** A filter that will not parse is refused with the
reason, rather than quietly showing an empty list, because an empty list is how somebody
concludes there was no attack. "Nobody has heard of this address" is reported as
unknown, never as safe. When a limit is hit or a source is down, the tool says so
instead of presenting partial results as complete.

## Archive

[`tools-archive/`](tools-archive) holds the two tools `email-checker` was built out
of. `accounts-checker` did passwords and breach lookups, `file-checker` did
attachments, and both now live inside `email-checker` where one message gets one
answer instead of three. They are kept because the code is still worth reading, but
there is no reason to run them.

## Running them

The Python tools need no dependencies beyond the standard library. Each folder's
README has the exact command. `system-checker` builds with `make`.

## How this was built

Written with help from Claude and Grok. They drafted code and first drafts of
the docs. Every design decision, test run, and deployment was mine, and nothing
went in unread.

## License

MIT, all of it. Use it, change it, ship it. No strings.
