# domain-checker

Can a criminal send email pretending to be this business? For most small businesses
the answer is yes — and they have no idea. This checks a domain and explains, in
plain English, how exposed they are.

```
domain-checker - can someone forge email from acme-bakery.com ?
  [MISSING] SPF  : No SPF record. Anyone can try to send mail as this domain.
  [MISSING] DMARC: No DMARC record. Nothing tells servers to block fakes...

Verdict: EXPOSED. Someone could send email as this business today, and the
owner would never know.
```

## Why this exists

Invoice fraud and "email from the boss" scams work because most small-business
domains are missing three protective DNS records — SPF, DKIM and DMARC — with
names nobody outside IT has heard of. Setting them up is fast and cheap, and it
shuts down a whole category of fraud. This tool finds the gap in about ten seconds,
which makes it one of the best conversation-openers I have: an easy, high-value win
a business owner immediately understands the value of.

## What it checks

**SPF** — does the domain say which servers are allowed to send its mail?
**DMARC** — does it tell receiving servers to actually *block* fakes, and report
impersonation attempts? **DKIM** — it explains why this one can't be auto-checked
(it needs your mail provider's private selector name) and where to confirm it.

Each result is plain-English, with a verdict weighted on DMARC, because DMARC is
what actually stops the fakes.

## How to use it

```
python3 domain_checker.py acme-bakery.com
```

It reads public DNS records over an encrypted DNS-over-HTTPS request, so it works
on any machine with internet and needs nothing installed. It only reads public
information — nothing private, nothing sent anywhere about you.

## Honest limitations

- DKIM genuinely can't be verified from outside without the provider's selector
  name — the tool says so rather than guessing, which is the honest thing to do.
- It reads the records; the fix is done in the domain's DNS settings or the mail
  provider's admin panel (that's the paid work — see the email-setup service).
- A "well protected" result reflects these records only; email safety also depends
  on the people reading the mail, which is what the phishing walkthrough covers.

---

Written by DhWonder · Plaintext IT — technology,
translated. MIT license.
