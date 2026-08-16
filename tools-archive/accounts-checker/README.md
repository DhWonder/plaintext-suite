# accounts-checker

> **Retired.** This tool is now part of [`email-checker`](../../tools/email-checker),
> along with `file-checker`. Everything below still works, but the password check,
> the breach lookup and the scam wording checks all live there now, next to the
> attachment and sender domain checks, so one message gets one answer. Use that
> instead. This is kept because the code is still worth reading.

Can this account, or this message, be trusted?

Three questions that come up constantly in small businesses, answered by one
tool instead of three, in words a person can act on.

```
python3 accounts_checker.py password
python3 accounts_checker.py email someone@example.com
python3 accounts_checker.py message suspicious.eml
```

## What it answers

**Is this password any good?** Length, whether it is a known common password,
whether it is a word with predictable decoration, and roughly how long a
determined attacker with ordinary equipment would need. Entirely offline.

**Has it already been stolen?** A password can be long, unusual and excellent
and still be worthless, because it appeared in a breach years ago and sits in
every attacker's list. Checked against the public breach data.

**Has this email address been in a breach?** Across three sources, because none
of them is complete on its own.

**Is this message a scam?** It reads a saved message and points at what is
wrong: replies going somewhere else, links that show one address and lead to
another, lookalike domains, pressure language, the usual repertoire.

## What leaves your computer

| | |
|---|---|
| password | **Nothing.** Five characters of a one way fingerprint are sent, which matches hundreds of thousands of different passwords. The password itself never leaves. The code that does this is in `accountschecker/passwords.py` and it is short enough to read. |
| email | **The address.** There is no way to ask whether an address is in a breach without saying the address. So the tool asks you first and names exactly which services get told. |
| message | **Nothing at all.** The file is read here. No link is opened, nothing is downloaded, the sender is never contacted. |

Check your own address freely. Check a client's only if they have agreed to it.
Somebody else's is not your business.

## The breach sources

| Source | |
|---|---|
| XposedOrNot | free, no account needed |
| LeakCheck | free tier, names the sites |
| Have I Been Pwned | the best of them, but address lookups need a paid key. Pass one with `--hibp-key` |

Nothing found is not the same as nothing there. Breaches surface years after
they happen, and the most complete database charges for this lookup. The tool
says so rather than implying an all clear.

## Honest limitations

- A clean message is not a safe message. A well made scam can look perfect.
  The rule that always holds: if it asks for money, passwords or bank details,
  verify by phone on a number you already had.
- The guessing time assumes ordinary equipment and an attacker who has the
  scrambled password to work on. Somebody who simply knows your password gets
  in immediately, however strong it is.
- Attachments are a separate job. Run `file-checker` on the same message.

Replaces the earlier `password-truth`, `leak-check` and `phish-explain`.

MIT licensed.
