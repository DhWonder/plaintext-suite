"""
Build one test email in every format the tool claims to read.

The interesting half is the .msg writer. Testing the Outlook reader needs a real
Compound File, and there is no way to make one from the standard library, so this
writes the container by hand: header, FAT, directory, mini FAT, mini stream. It
is the mirror image of the reader in emailchecker/msg.py, written separately and
deliberately, because a test that reuses the code it is testing proves nothing.

Run it directly to drop the fixtures somewhere:
    python3 tests/make_test_emails.py /tmp/fixtures
"""
import email.message
import gzip
import os
import struct

SIG = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
FREE, END, FATSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD
SEC, MINI = 512, 64


def uni(s):
    return s.encode("utf-16-le") + b"\x00\x00"


def build(streams, storages):
    """streams: list of (name, bytes) at top level.
       storages: list of (name, [(child_name, bytes), ...])"""
    # --- lay out every small stream into the mini stream ---
    mini_parts, mini_map = [], {}
    cursor = 0

    def place(key, blob):
        nonlocal cursor
        n = max(1, -(-len(blob) // MINI))
        mini_map[key] = (cursor, len(blob))
        padded = blob + b"\x00" * (n * MINI - len(blob))
        mini_parts.append(padded)
        cursor += n

    for name, blob in streams:
        place(("", name), blob)
    for sname, children in storages:
        for cname, blob in children:
            place((sname, cname), blob)

    mini_stream = b"".join(mini_parts)
    total_mini = cursor

    # --- minifat: each stream's sectors chained, then END ---
    minifat = [FREE] * total_mini
    for (start, size) in mini_map.values():
        n = max(1, -(-size // MINI))
        for i in range(n - 1):
            minifat[start + i] = start + i + 1
        minifat[start + n - 1] = END

    # --- directory entries ---
    # 0 = root, then top-level streams, then storages and their children.
    entries = []

    def entry(name, typ, left=-1, right=-1, child=-1, start=END, size=0):
        e = bytearray(128)
        nm = uni(name)
        e[0:len(nm)] = nm
        struct.pack_into("<H", e, 64, len(nm))
        e[66] = typ
        e[67] = 1  # black
        struct.pack_into("<i", e, 68, left)
        struct.pack_into("<i", e, 72, right)
        struct.pack_into("<i", e, 76, child)
        struct.pack_into("<I", e, 116, start)
        struct.pack_into("<Q", e, 120, size)
        return e

    entries.append(None)  # root placeholder, filled in below

    # Top level chained via `right`, in one flat list: streams then storages.
    top_indices = []
    for name, blob in streams:
        start, size = mini_map[("", name)]
        top_indices.append(len(entries))
        entries.append(entry(name, 2, start=start, size=size))

    storage_slots = []
    for sname, children in storages:
        top_indices.append(len(entries))
        storage_slots.append((len(entries), sname, children))
        entries.append(None)  # filled after children get indices

    for slot, sname, children in storage_slots:
        child_indices = []
        for cname, blob in children:
            start, size = mini_map[(sname, cname)]
            child_indices.append(len(entries))
            entries.append(entry(cname, 2, start=start, size=size))
        # chain children via right
        for i, idx in enumerate(child_indices):
            nxt = child_indices[i + 1] if i + 1 < len(child_indices) else -1
            struct.pack_into("<i", entries[idx], 72, nxt)
        entries[slot] = entry(sname, 1, child=child_indices[0] if child_indices else -1)

    # chain top level via right
    for i, idx in enumerate(top_indices):
        nxt = top_indices[i + 1] if i + 1 < len(top_indices) else -1
        struct.pack_into("<i", entries[idx], 72, nxt)

    # --- sector plan: 0=FAT, 1..d=directory, then minifat, then mini stream ---
    dir_bytes = b"".join(bytes(e) for e in entries[1:])
    n_dir = max(1, -(-(len(dir_bytes) + 128) // SEC))
    minifat_bytes = struct.pack("<%dI" % len(minifat), *minifat) if minifat else b""
    n_minifat = max(1, -(-len(minifat_bytes) // SEC))
    n_ministream = -(-len(mini_stream) // SEC)

    dir_start = 1
    minifat_start = dir_start + n_dir
    mini_start = minifat_start + n_minifat

    entries[0] = entry("Root Entry", 5,
                       child=top_indices[0] if top_indices else -1,
                       start=mini_start if n_ministream else END,
                       size=len(mini_stream))
    dir_bytes = b"".join(bytes(e) for e in entries)
    dir_bytes += b"\x00" * (n_dir * SEC - len(dir_bytes))

    # --- FAT ---
    total_sectors = 1 + n_dir + n_minifat + n_ministream
    fat = [FREE] * (SEC // 4)
    fat[0] = FATSECT
    for i in range(n_dir):
        fat[dir_start + i] = (dir_start + i + 1) if i + 1 < n_dir else END
    for i in range(n_minifat):
        fat[minifat_start + i] = (minifat_start + i + 1) if i + 1 < n_minifat else END
    for i in range(n_ministream):
        fat[mini_start + i] = (mini_start + i + 1) if i + 1 < n_ministream else END
    fat_bytes = struct.pack("<%dI" % len(fat), *fat)

    # --- header ---
    h = bytearray(512)
    h[0:8] = SIG
    struct.pack_into("<HH", h, 24, 0x3E, 3)
    struct.pack_into("<H", h, 28, 0xFFFE)
    struct.pack_into("<HH", h, 30, 9, 6)
    struct.pack_into("<I", h, 44, 1)              # one FAT sector
    struct.pack_into("<I", h, 48, dir_start)
    struct.pack_into("<I", h, 56, 4096)           # mini cutoff
    struct.pack_into("<I", h, 60, minifat_start)
    struct.pack_into("<I", h, 64, n_minifat)
    struct.pack_into("<I", h, 68, END)            # no DIFAT sectors
    struct.pack_into("<I", h, 72, 0)
    for i in range(109):
        struct.pack_into("<I", h, 76 + i * 4, 0 if i == 0 else FREE)

    out = bytes(h) + fat_bytes + dir_bytes
    out += minifat_bytes + b"\x00" * (n_minifat * SEC - len(minifat_bytes))
    out += mini_stream + b"\x00" * (n_ministream * SEC - len(mini_stream))
    return out


HEADERS = (
    "Return-Path: <billing@paypa1-secure.com>\r\n"
    "From: PayPal Billing <billing@paypa1-secure.com>\r\n"
    "Reply-To: recover@mail.ru\r\n"
    "To: recipient@example.com\r\n"
    "Subject: Your account will be suspended\r\n"
    "Date: Wed, 12 Aug 2026 10:00:00 +0300\r\n"
    "Authentication-Results: mx.google.com; spf=fail; dkim=none; dmarc=fail\r\n"
)
BODY = ("Dear customer,\r\n\r\nYour account will be suspended within 24 hours "
        "unless you verify your details immediately. Click here to confirm "
        "your password and card number.\r\n")

def clean_eml():
    """An ordinary business email with a real PDF attached. Nothing wrong."""
    m = email.message.EmailMessage()
    m["From"] = "Dana Levi <dana@example.co.il>"
    m["To"] = "someone@example.com"
    m["Subject"] = "Print job proof"
    m["Date"] = "Wed, 12 Aug 2026 09:00:00 +0300"
    m.set_content("Proof attached, please confirm the colours.\n")
    m.add_attachment(b"%PDF-1.4\n1 0 obj\n<</Type/Catalog>>\nendobj\ntrailer\n",
                     maintype="application", subtype="pdf", filename="proof.pdf")
    return m.as_bytes()


def phishing_msg():
    """Outlook .msg, original internet headers preserved, program attached."""
    return build(
        streams=[
            ("__substg1.0_007D001F", uni(HEADERS)[:-2]),
            ("__substg1.0_0037001F", uni("Your account will be suspended")[:-2]),
            ("__substg1.0_1000001F", uni(BODY)[:-2]),
            ("__substg1.0_0C1A001F", uni("PayPal Billing")[:-2]),
            ("__substg1.0_0C1F001F", uni("billing@paypa1-secure.com")[:-2]),
        ],
        storages=[
            ("__attach_version1.0_#00000000", [
                ("__substg1.0_3707001F", uni("invoice.pdf.exe")[:-2]),
                ("__substg1.0_37010102", b"MZ\x90\x00" + b"\x00" * 200),
            ]),
        ])


def bare_msg():
    """Outlook .msg with NO surviving headers, only Outlook's own fields.

    This is the branch that has to rebuild a message from scratch, and it is the
    one most likely to quietly lose the sender."""
    return build(
        streams=[
            ("__substg1.0_0037001F", uni("Quick question")[:-2]),
            ("__substg1.0_1000001F", uni("Are you at your desk?")[:-2]),
            ("__substg1.0_0C1A001F", uni("Dana Levi")[:-2]),
            ("__substg1.0_0C1F001F", uni("dana@example.co.il")[:-2]),
            ("__substg1.0_0E04001F", uni("someone@example.com")[:-2]),
        ],
        storages=[])


def write_all(folder):
    """Every fixture, one per format. Returns {name: path}."""
    if not os.path.isdir(folder):
        os.makedirs(folder)
    raw = clean_eml()
    files = {
        "clean.eml": raw,
        "clean.eml.gz": gzip.compress(raw),
        "apple.emlx": str(len(raw)).encode() + b"\n" + raw
                      + b'<?xml version="1.0"?><plist/>',
        "two.mbox": (b"From a@b.com Wed Aug 12 09:00:00 2026\n" + raw
                     + b"\nFrom c@d.com Wed Aug 13 09:00:00 2026\n" + raw),
        "phish.msg": phishing_msg(),
        "bare.msg": bare_msg(),
    }
    out = {}
    for name, blob in files.items():
        path = os.path.join(folder, name)
        with open(path, "wb") as fh:
            fh.write(blob)
        out[name] = path
    return out


if __name__ == "__main__":
    import sys
    where = sys.argv[1] if len(sys.argv) > 1 else "fixtures"
    for name, path in sorted(write_all(where).items()):
        print("wrote %s" % path)
