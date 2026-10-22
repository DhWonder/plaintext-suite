# domain-checker

Can a criminal send email pretending to be this business? For most small businesses
the answer is yes — and they have no idea. This checks a domain and explains, in
plain English, how exposed they are. **It only reads public DNS; it never sends mail.**

```
domain-checker - can someone forge email from example.com ?
  [MISSING] SPF  : No SPF record. Anyone can try to send mail as this domain.
  [MISSING] DMARC: No DMARC record. Nothing tells servers to block fakes...
  [MISSING] DKIM : No DKIM key on any of the 10 common selectors probed...

Verdict: EXPOSED. Someone could send email as this business today, and the
owner would never know.
```

## Why this exists

Invoice fraud and "email from the boss" scams work because most small-business
domains are missing three protective DNS records — SPF, DKIM and DMARC — with
names nobody outside IT has heard of. Setting them up is fast and cheap, and it
shuts down a whole category of fraud. This tool finds the gap in about ten seconds.

## What it checks

**SPF** — does the domain say which servers are allowed to send its mail?
**DMARC** — does it tell receiving servers to actually *block* fakes, and report
impersonation attempts?
**DKIM** — does the domain cryptographically sign its outgoing mail? The selector
name is chosen by whoever set up the mail and cannot be derived from the domain,
so the tool **probes a short list of common selectors** — `google` (Google
Workspace), `selector1`/`selector2` (Microsoft 365), `default`, `k1`, `s1`, `s2`,
`mail`, `dkim`, `cm` and others. A selector it does not know can be added with
`--dkim-selector NAME` (repeatable, or comma-separated). A clean sweep is reported
as "none of the common ones" — an honest caveat, never a false "no DKIM", because a
custom selector could still exist. An empty `p=` key (a revoked selector) is
correctly treated as *not signing*.

Each result is plain-English, with a verdict weighted on DMARC, because DMARC is
what actually stops the fakes.

## How to use it

```
python3 domain_checker.py example.com
python3 domain_checker.py example.com --dkim-selector mysel,another
python3 domain_checker.py example.com --reputation
```

It reads public DNS records over an encrypted DNS-over-HTTPS request, so it works
on any machine with internet and needs nothing installed. It only reads public
information — nothing private, and nothing about you goes anywhere, unless you
ask it to email you the answer with `--notify`.

## Checking it again, forever

A domain that is protected today can stop being protected the day somebody edits
DNS. Run it from cron and hear from it only when the answer is bad:

```
python3 domain_checker.py notify setup     write ~/.plaintext/notify.conf
python3 domain_checker.py notify test      prove it can actually send
0 7 * * 1 python3 /path/to/domain_checker.py example.com --notify
```

## See also

- **[`spoof-proof`](https://github.com/DhWonder/redline-suite/tree/main/tools/spoof-proof)** — the companion red-team tool. Where
  domain-checker *tells* you a domain is spoofable, spoof-proof lets you safely
  *demonstrate* it: it sends one clearly `[DEMO]`-marked message with a forged
  `From` to an address you choose, through your own SMTP server, so an owner can
  see the fake land in their inbox. Authorised demos only.

## Honest limitations

- DKIM can't be verified exhaustively from outside: the probe covers the common
  provider selectors, and reports a miss as "none of these", not "no DKIM".
- It reads the records; the fix is done in the domain's DNS or the mail provider's
  admin panel.
- A "well protected" result reflects these records only; email safety also depends
  on the people reading the mail.

---

Written by DhWonder · Plaintext IT — technology, translated. MIT license.
