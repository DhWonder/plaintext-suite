# plaintext-suite

Security tools that read, explain, and do not guess.

## Still a work in progress 


Small tools for small businesses. Each one does a specific job, runs on its own without
a service behind it, and says what it found in plain English including when the
honest answer is "I cannot tell you that." Every tool has its own README with its
limitations written down.

## The tools

| Tool | Language | What it does |
|------|----------|--------------|
| [traffic-analyzer](tools/traffic-analyzer) | Python | Reads a network capture and works out who is flooding you, how, and what to change. |
| [decoy-house](tools/decoy-house) | Python | A machine that looks worth breaking into, and tells on whoever does. Honeypot plus a console. |
| [email-checker](tools/email-checker) | Python | Is this email a scam? One verdict on the wording, the attachments, and whether the sender's domain can be forged. The message is never uploaded. |
| [domain-checker](tools/domain-checker) | Python | Can a criminal send email pretending to be this business? (SPF/DMARC) |
| [backup-checker](tools/backup-checker) | shell | Verifies backups actually ran, and that they can actually restore. |
| [system-checker](tools/system-checker) | C | A read-only health and security look-over of a Linux machine. |

Start with **traffic-analyzer**. It parses capture files by hand, tells a SYN flood
apart from a port scan, spots reflection attacks, and finishes with recommendations
you can act on.

## Archive

[`tools-archive/`](tools-archive) holds two earlier tools — `accounts-checker` and
`file-checker` — kept because the code is still worth reading. Their jobs are now
done better by `email-checker`.

## Running them

The Python tools need no dependencies beyond the standard library. Each folder's
README has the exact command. `system-checker` builds with `make`.

## License

MIT, all of it. Use it, change it, ship it no strings.
