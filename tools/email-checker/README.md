# email-checker

Everything about one email, in plain English.

Somebody forwards you a message and asks "is this real?". Answering it properly
used to mean running three separate tools and holding three answers in your
head: one for the wording, one for the attachment, one for whether the sender's
domain can even be forged. This does all of it in one pass and gives one verdict.

```
python3 email_checker.py suspicious.eml
python3 email_checker.py message.msg
python3 email_checker.py mailbox.mbox
pbpaste | python3 email_checker.py -
```

It replaces `file-checker` and `accounts-checker`, which are folded into it.

## It reads whatever shape the email arrived in

People do not save email in one format, so the tool does not ask them to.

| Format | Where it comes from |
|---|---|
| `.eml` | forwarded or saved from almost any mail program |
| `.emlx` | a message dragged out of Apple Mail |
| `.mbox` | a whole exported folder, every message in it checked |
| `.msg` | Outlook, read directly with no Outlook and no dependency |
| `.eml.gz` | any of the above, gzipped |
| pasted text | the raw message pasted on standard input |

The Outlook reader is the interesting one. A `.msg` is not an email, it is a
Microsoft Compound File, the same little filesystem-inside-a-file that old `.doc`
used. Where Outlook kept the original internet headers, they are recovered and
every header check runs exactly as it would on a `.eml`. Where it did not, the
honest minimum is rebuilt from the fields Outlook did store.

## What it answers, in the order that matters

**1. Is the message itself a scam.** Replies routed to a different address than
the visible sender, the server's own SPF and DMARC results, lookalike sender
domains, links that show one address and lead to another, and pressure language
in the subject and the body, because urgency is the whole engine of phishing.

**2. Are the attachments safe to open.** Each one is examined by its bytes, not
its name: programs wearing a document's name, double extensions like
`Invoice.pdf.exe`, macros inside Office files, PDFs that carry JavaScript or
launch actions, password protected archives, programs inside archives, disk
images. Then, optionally, whether a malware database has seen that exact file.

**3. Can the sender's domain be forged.** SPF, DKIM and DMARC for the domain the
mail claims to come from. A domain with no DMARC can be impersonated by anyone,
which turns a suspicious message into a plausible one.

Each part prints its own findings, worst first, and the whole email gets one
verdict at the top so somebody who reads a single line still gets the answer.

## What leaves your computer

The message and its attachments are read here and **never uploaded**. This
matters: an attachment is often a real invoice with real customer details, and
uploading that to a public analysis service publishes it permanently to anyone
with an account. Several well known tools do that by default. This one will not
do it at all.

Only three things ever leave, and only if you allow them:

| | What is sent | To whom |
|---|---|---|
| attachment reputation | a SHA-256 fingerprint, which cannot be turned back into the file | MalwareBazaar, VirusTotal with `--vt-key` |
| domain check | the sender's domain name, which is already public | DNS over HTTPS |
| breach lookup | the address itself, because there is no other way | the databases the tool names before it asks |

`--offline` contacts nothing at all. The message and attachment structure are
still fully checked, because that half never needed the network.

## The account questions

```
python3 email_checker.py password
python3 email_checker.py breach someone@example.com
```

The password is never shown, saved or logged, and never sent. Five characters of
a one way fingerprint go to the breach service, and those match hundreds of
thousands of different passwords.

The breach lookup does send the address, so the tool names exactly who gets
asked and waits for a yes. Check your own address freely. Check a client's only
if they have agreed to it.

## Options

```
--offline        do not touch the internet
--domain         still do the domain check, even under --offline
--vt-key KEY     a VirusTotal key for attachment reputation
--mb-key KEY     a MalwareBazaar key, if yours needs one
--hibp-key KEY   a Have I Been Pwned key for the breach lookup
--save-to DIR    write attachments out, renamed so they cannot be run
--json FILE      also write the findings as JSON
--yes            skip the confirmation before a breach lookup sends an address
```

`--save-to` writes attachments renamed so a double click cannot run them, which
is what you want when handing one to somebody else to look at.

## What this is not

It is not antivirus, and a clean result is not a guarantee. Malware is usually
rebuilt for every campaign, so a fresh sample is unknown to every database on
its first day, which is exactly why the structural half matters more than the
lookup. A well made scam can pass every check here.

The rule that survives all of it: if a message asks for money, a password or
bank details, verify by phone on a number you already had, never one from the
message.

MIT licensed.

## The browser version

```
python3 email_checker.py serve --open
```

Drop an email onto the page and get the same report laid out instead of printed.
Three tabs: the email, a password, an address.

It works differently from the traffic analyzer's browser tool, and the
difference is worth knowing. That one parses captures in JavaScript, so it runs
from a `file://` URL with no server at all. This one cannot honestly do that.
The work here is a hand written Outlook Compound File reader, a structural
inspection of every attachment and a pile of careful wording checks, all of it
Python. Keeping a second copy of that judgement in JavaScript would mean two
answers that quietly drift apart, and the browser copy would be the one giving
a client an answer.

So the page is a face and the tool does the work. The email goes to 127.0.0.1,
Python does exactly what the command line does, and the answer comes back. The
promise that nothing is uploaded still holds, because the only thing listening
is this machine. Opening `email-checker.html` on its own will tell you so rather
than pretending to work.

The server binds to 127.0.0.1. Anything else needs an explicit `--host` and
prints a warning, because an email somebody is asking you about is usually the
most sensitive thing on the disk that day.

### Building the page

The page is one self contained file, kept as two readable pieces:

```
website/src/email-checker-shell.html   markup and styles
website/src/email-checker-ui.js        collecting input, drawing the answer
python3 website/build-checker-ui.py    puts them together
```

Edit the pieces, run the build, commit both. The build fails if the code reaches
for an id that is not in the markup, or uses a class with no style rule behind
it. Both of those break the page without throwing a single error, which is
exactly why they are checked at build time instead of being noticed later.

Everything the page draws is escaped on the way in. A subject line and a
filename are written by whoever sent the email, and on this tool that is often
somebody hostile. `website/tests/test-checker-ui.js` covers that, and runs under
`gjs` with no browser and nothing to install.
