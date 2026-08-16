# file-checker

> **Retired.** This tool is now part of [`email-checker`](../../tools/email-checker),
> along with `accounts-checker`. Everything below still works, but the attachment
> inspection lives there now, next to the scam wording and sender domain checks, so
> one message gets one answer. Use that instead. This is kept because the code is
> still worth reading.

Is this attachment safe to open?

Point it at a saved email and it pulls out the attachments, looks inside each
one without running it, and says in plain English what is wrong.

```
python3 file_checker.py suspicious.eml
python3 file_checker.py invoice.docm
python3 file_checker.py --save-to ./quarantine suspicious.eml
```

## What it looks for

Almost every malicious attachment gives itself away structurally, before anyone
needs to know which malware family it belongs to.

- **A program wearing a document's name.** The bytes say Windows program, the
  name says PDF. The clearest sign there is.
- **Double extensions.** `Invoice.pdf.exe`, which Windows displays as
  `Invoice.pdf` because it hides known extensions by default.
- **Macros.** Code inside a document that runs when somebody clicks Enable
  Content, which is what most office malware is waiting for.
- **PDFs that do things.** JavaScript, actions that fire on open, instructions
  to launch another program, files hidden inside.
- **Password protected archives.** In an email with the password in the message
  body, that exists for exactly one reason: a scanner cannot look inside a
  locked archive, and the person can.
- **Programs inside archives**, disk images attached to email, web pages sent as
  files, and contents that look encrypted rather than like a document.

Then, optionally, it asks two malware databases whether anyone has seen this
exact file before.

## What leaves your computer

**Nothing, unless the database lookup runs, and then only a SHA-256
fingerprint.** That is a one way summary that cannot be turned back into the
file and reveals nothing about what is inside.

The attachment itself is never uploaded. This matters: a client's attachment may
be a real invoice with real customer details in it, and uploading that to a
public analysis service publishes it, permanently, to anyone with an account.
Several well known tools do that by default. This one will not do it at all.

Use `--offline` and it contacts nothing.

| Database | |
|---|---|
| MalwareBazaar | free, run by researchers, names the malware family |
| VirusTotal | needs a free key (`--vt-key`), tells you how many of about seventy scanners flag it |

## What this is not

It is not antivirus. It does not remove anything, it does not sit in the
background, and a clean result is not a guarantee. Malware is usually rebuilt
for every campaign, so a fresh sample is unknown to every database on its first
day, which is exactly why the structural half matters more than the lookup.

What it is: the reading somebody experienced would give an attachment before
deciding whether to open it, done in a few seconds and written down.

`--save-to` writes the attachments out renamed so they cannot be run by a double
click, which is what you want when handing one to somebody else to look at.

MIT licensed.
