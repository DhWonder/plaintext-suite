"""
Reading whatever shape the email arrived in, and handing back one thing.

People do not save email in one format. They forward a .eml, they drag a message
out of Apple Mail and get a .emlx, they export a whole folder as an .mbox, they
send an Outlook .msg, they gzip it to make it smaller, or they just paste the raw
text into a box. The rest of this tool should not have to care which of those
happened, so all of it is normalised here into a standard email.message together
with its attachments pulled out.

Everything is read. Nothing is opened in its application and nothing is sent.
"""

import email
import email.message
import email.policy
import gzip
import io
import re

from . import msg as msg_reader

POLICY = email.policy.default

# An mbox separator: a line that starts a new message. Real ones look like
# "From sender@host Wed Aug 12 ...". One of these at the very start is normal in
# a single .eml too, so more than one is what actually marks an mbox.
MBOX_SEP = re.compile(rb"^From \S+.*\d{4}", re.MULTILINE)


class Loaded(object):
    """One message, however it arrived, ready to analyse."""

    def __init__(self, message, attachments, fmt, index=0, count=1):
        self.message = message
        self.attachments = attachments        # [(name, bytes), ...]
        self.format = fmt                     # eml, emlx, mbox, msg, eml.gz, text
        self.index = index                    # which message, for an mbox
        self.count = count                    # how many were in the container


# ---------------------------------------------------------------------------
def load(path=None, data=None, text=None):
    """Return a list of Loaded messages from a file, raw bytes, or pasted text.

    Nearly always the list has one item. An mbox can hold many, so the caller
    gets all of them and decides what to show.
    """
    if text is not None:
        raw = text.encode("utf-8", "replace") if isinstance(text, str) else text
        return _from_pasted(raw)
    if data is None:
        with open(path, "rb") as fh:
            data = fh.read()

    lowered = (path or "").lower()

    if data[:2] == b"\x1f\x8b" or lowered.endswith(".gz"):
        try:
            data = gzip.decompress(data)
        except OSError:
            pass
        else:
            fmt_hint = "eml.gz"
            return _dispatch(data, lowered, forced_format=fmt_hint)

    return _dispatch(data, lowered)


def _dispatch(data, lowered, forced_format=None):
    if data.startswith(msg_reader.SIGNATURE) or lowered.endswith(".msg"):
        return [_from_msg(data)]
    if lowered.endswith(".emlx") or _looks_emlx(data):
        return [_from_emlx(data, forced_format)]
    if lowered.endswith((".mbox", ".mbx")) or len(MBOX_SEP.findall(data[:100000])) >= 2:
        return _from_mbox(data)
    return [_one(email.message_from_bytes(data, policy=POLICY), forced_format or "eml")]


# ---------------------------------------------------------------------------
def _one(message, fmt, index=0, count=1):
    return Loaded(message, attachments_of(message), fmt, index, count)


def _from_pasted(raw):
    """Pasted text. If it carries headers, treat it as a real message; if it is
    just the body somebody copied, wrap it so the wording checks still run."""
    head = raw[:4096]
    has_headers = re.search(rb"(?im)^(from|subject|to|received|reply-to)\s*:", head)
    if has_headers:
        return [_one(email.message_from_bytes(raw, policy=POLICY), "text")]
    built = email.message.EmailMessage()
    built.set_content(raw.decode("utf-8", "replace"))
    return [Loaded(built, [], "text")]


def _looks_emlx(data):
    # Apple Mail's .emlx begins with a plain byte count on its own line.
    first = data[:24].split(b"\n", 1)[0].strip()
    return first.isdigit() and len(first) <= 12


def _from_emlx(data, forced_format=None):
    """Apple Mail: a length line, then the RFC822 message, then a plist trailer.

    The length tells us exactly how many bytes of message follow, which also
    trims off the Apple metadata plist at the end."""
    newline = data.find(b"\n")
    body = data
    if newline != -1 and data[:newline].strip().isdigit():
        length = int(data[:newline].strip())
        start = newline + 1
        body = data[start:start + length]
    message = email.message_from_bytes(body, policy=POLICY)
    return _one(message, forced_format or "emlx")


def _from_mbox(data):
    """Split an mbox into its messages on the separator lines."""
    positions = [m.start() for m in MBOX_SEP.finditer(data)]
    if not positions:
        return [_one(email.message_from_bytes(data, policy=POLICY), "mbox")]
    positions.append(len(data))
    out = []
    count = len(positions) - 1
    for i in range(count):
        chunk = data[positions[i]:positions[i + 1]]
        # Drop the "From " separator line itself before parsing.
        nl = chunk.find(b"\n")
        if nl != -1:
            chunk = chunk[nl + 1:]
        message = email.message_from_bytes(chunk, policy=POLICY)
        out.append(_one(message, "mbox", index=i, count=count))
    return out


def _from_msg(data):
    """Outlook .msg, turned into a normal message plus its attachments."""
    parsed = msg_reader.parse(data)
    built = _message_from_msg(parsed)
    return Loaded(built, parsed["attachments"], "msg")


def _message_from_msg(parsed):
    """Rebuild a standard message from what Outlook kept.

    When the original internet headers survived we parse those, so From,
    Reply-To, Return-Path and the server's own authentication results are all
    present and every header check works unchanged. When they did not, we build
    the honest minimum from the fields Outlook did store."""
    out = email.message.EmailMessage()

    headers = parsed.get("headers") or ""
    if headers.strip():
        try:
            parsed_headers = email.message_from_string(headers, policy=POLICY)
            for key, value in parsed_headers.items():
                try:
                    out[key] = value
                except Exception:
                    pass
        except Exception:
            headers = ""

    if not headers.strip():
        name, addr = parsed.get("from_name", ""), parsed.get("from_email", "")
        if addr and name:
            out["From"] = "%s <%s>" % (name, addr)
        elif addr:
            out["From"] = addr
        elif name:
            out["From"] = name
        if parsed.get("to"):
            out["To"] = parsed["to"]
        if parsed.get("date"):
            out["Date"] = parsed["date"]

    if parsed.get("subject") and "Subject" not in out:
        out["Subject"] = parsed["subject"]

    try:
        out.set_content(parsed.get("body") or "")
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
def attachments_of(message):
    """Every attachment in a MIME message, as (name, bytes).

    An attachment is a part with a filename, or one explicitly marked as an
    attachment. Inline images that are part of the layout are left out, the same
    way a mail client hides them."""
    items = []
    if not message.is_multipart() and not message.get_filename():
        return items
    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename()
        disposition = (part.get("Content-Disposition") or "").lower()
        if not filename and "attachment" not in disposition:
            continue
        try:
            body = part.get_payload(decode=True) or b""
        except Exception:
            body = b""
        items.append((filename or "(unnamed)", body))
    return items


def summarise_attachments(attachments):
    """Names, types by extension, and sizes, without opening anything."""
    out = []
    for name, body in attachments:
        out.append({"name": name, "bytes": len(body)})
    return out
