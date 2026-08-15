"""
Reading an Outlook .msg file, without Outlook and without any dependency.

A .msg is not an email in the normal sense. It is a Microsoft Compound File: the
same little filesystem-inside-a-file that old .doc and .xls used, a container of
named streams laid out with a FAT, a directory, and a separate "mini" area for
the small streams. Outlook writes each field of the mail into its own stream
with a coded name, so the subject lives in a stream called `__substg1.0_0037001F`
and the raw internet headers, when they survived, live in `__substg1.0_007D001F`.

This reads that container with nothing but the standard library, pulls out the
fields and the attachments, and hands back something the rest of the tool can
treat exactly like an ordinary .eml. Where Outlook kept the original transport
headers we rebuild a real message from them, so every header check that works on
a .eml works here too. Where it did not, we build the closest honest equivalent
from the fields Outlook did keep.

Nothing is executed and nothing is sent. It is bytes read carefully, the same
promise as the rest of the suite.

Reference: the Compound File Binary Format, MS-CFB, and MS-OXMSG for the stream
names. This implements the reading half of both, which is all that is needed.
"""

import struct

SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD

# The property stream names carry the field id and its type in hex. We only need
# a handful, and only the text (001F = Unicode) and binary (0102) variants.
PROP_SUBJECT = "0037"
PROP_BODY = "1000"
PROP_HEADERS = "007D"            # the original internet (RFC822) headers
PROP_SENDER_NAME = "0C1A"
PROP_SENDER_EMAIL = "0C1F"
PROP_SENDER_SMTP = "5D01"
PROP_SENT_REP_SMTP = "5D02"
PROP_DISPLAY_TO = "0E04"
PROP_DATE = "0039"               # client submit time (kept as text when present)
PROP_ATTACH_LONG = "3707"
PROP_ATTACH_SHORT = "3704"
PROP_ATTACH_DATA = "3701"


class MsgError(Exception):
    pass


class CompoundFile(object):
    """The minimum of MS-CFB needed to list and read streams by path."""

    def __init__(self, data):
        if not data.startswith(SIGNATURE):
            raise MsgError("not a compound file (wrong signature)")
        if len(data) < 512:
            raise MsgError("file is too small to be a compound file")
        self.data = data

        # Header. Everything is little-endian.
        self.minor, self.major = struct.unpack_from("<HH", data, 24)
        sector_shift, mini_shift = struct.unpack_from("<HH", data, 30)
        self.sector_size = 1 << sector_shift          # 512 (v3) or 4096 (v4)
        self.mini_size = 1 << mini_shift              # 64
        (self.num_fat_sectors,) = struct.unpack_from("<I", data, 44)
        (self.dir_start,) = struct.unpack_from("<I", data, 48)
        (self.mini_cutoff,) = struct.unpack_from("<I", data, 56)
        (self.minifat_start,) = struct.unpack_from("<I", data, 60)
        (self.num_minifat,) = struct.unpack_from("<I", data, 64)
        (self.difat_start,) = struct.unpack_from("<I", data, 68)
        (self.num_difat,) = struct.unpack_from("<I", data, 72)

        self._build_fat()
        self._read_directory()
        self._build_minifat()
        self._load_mini_stream()

    # -- sector maths ---------------------------------------------------
    def _sector(self, index):
        start = 512 + index * self.sector_size
        chunk = self.data[start:start + self.sector_size]
        if len(chunk) < self.sector_size:
            chunk = chunk + b"\x00" * (self.sector_size - len(chunk))
        return chunk

    def _build_fat(self):
        """The FAT is itself stored in sectors, listed by the DIFAT."""
        fat_sectors = []
        # The first 109 FAT sector locations sit in the header.
        for i in range(109):
            (loc,) = struct.unpack_from("<I", self.data, 76 + i * 4)
            if loc == FREESECT or loc == ENDOFCHAIN:
                continue
            fat_sectors.append(loc)
        # The rest, for very large files, are chained through DIFAT sectors.
        sector = self.difat_start
        guard = 0
        while sector != ENDOFCHAIN and sector != FREESECT and guard < 1 + self.num_difat:
            guard += 1
            block = self._sector(sector)
            entries = self.sector_size // 4
            for i in range(entries - 1):
                (loc,) = struct.unpack_from("<I", block, i * 4)
                if loc != FREESECT and loc != ENDOFCHAIN:
                    fat_sectors.append(loc)
            (sector,) = struct.unpack_from("<I", block, (entries - 1) * 4)

        fat = []
        for loc in fat_sectors:
            block = self._sector(loc)
            for i in range(self.sector_size // 4):
                (value,) = struct.unpack_from("<I", block, i * 4)
                fat.append(value)
        self.fat = fat

    def _chain(self, start):
        """Follow a FAT chain and return the ordered list of sector indices."""
        out = []
        sector = start
        seen = set()
        while sector != ENDOFCHAIN and sector != FREESECT:
            if sector in seen or sector >= len(self.fat):
                break                                 # a loop or a bad pointer
            seen.add(sector)
            out.append(sector)
            sector = self.fat[sector]
        return out

    def _read_chain(self, start, size=None):
        parts = [self._sector(i) for i in self._chain(start)]
        data = b"".join(parts)
        return data if size is None else data[:size]

    # -- directory ------------------------------------------------------
    def _read_directory(self):
        raw = self._read_chain(self.dir_start)
        self.entries = []
        for offset in range(0, len(raw), 128):
            entry = raw[offset:offset + 128]
            if len(entry) < 128:
                break
            name_len = struct.unpack_from("<H", entry, 64)[0]
            obj_type = entry[66]
            if obj_type == 0:                          # unused slot
                self.entries.append(None)
                continue
            name = entry[:max(name_len - 2, 0)].decode("utf-16-le", "replace")
            child = struct.unpack_from("<i", entry, 76)[0]
            start = struct.unpack_from("<I", entry, 116)[0]
            size = struct.unpack_from("<Q", entry, 120)[0]
            self.entries.append({
                "name": name, "type": obj_type, "child": child,
                "left": struct.unpack_from("<i", entry, 68)[0],
                "right": struct.unpack_from("<i", entry, 72)[0],
                "start": start, "size": size,
            })

        # Walk the red-black tree just enough to give every stream a path.
        self.paths = {}                                # tuple(path) -> entry
        if self.entries and self.entries[0]:
            self._walk(self.entries[0]["child"], ())

    def _walk(self, index, prefix, depth=0):
        if index < 0 or index >= len(self.entries) or depth > 64:
            return
        entry = self.entries[index]
        if entry is None:
            return
        self._walk(entry["left"], prefix, depth + 1)
        path = prefix + (entry["name"],)
        if entry["type"] == 2:                         # a stream
            self.paths[path] = entry
        elif entry["type"] == 1:                        # a storage (folder)
            self._walk(entry["child"], path, depth + 1)
        self._walk(entry["right"], prefix, depth + 1)

    # -- the mini area, where small streams live ------------------------
    def _build_minifat(self):
        raw = self._read_chain(self.minifat_start) if self.minifat_start != ENDOFCHAIN else b""
        self.minifat = list(struct.unpack("<%dI" % (len(raw) // 4), raw)) if raw else []

    def _load_mini_stream(self):
        root = self.entries[0] if self.entries else None
        self.mini_stream = self._read_chain(root["start"], root["size"]) if root else b""

    def _read_mini_chain(self, start, size):
        out = []
        sector = start
        seen = set()
        while sector != ENDOFCHAIN and sector != FREESECT:
            if sector in seen or sector >= len(self.minifat):
                break
            seen.add(sector)
            begin = sector * self.mini_size
            out.append(self.mini_stream[begin:begin + self.mini_size])
            sector = self.minifat[sector]
        return b"".join(out)[:size]

    def read(self, entry):
        if entry["size"] < self.mini_cutoff:
            return self._read_mini_chain(entry["start"], entry["size"])
        return self._read_chain(entry["start"], entry["size"])

    # -- convenience ----------------------------------------------------
    def stream(self, *path):
        entry = self.paths.get(tuple(path))
        return self.read(entry) if entry else None

    def top_level(self):
        """Names of the top-level entries, streams and storages alike."""
        names = []
        if self.entries and self.entries[0]:
            self._collect(self.entries[0]["child"], names)
        return names

    def _collect(self, index, names, depth=0):
        if index < 0 or index >= len(self.entries) or depth > 64:
            return
        entry = self.entries[index]
        if entry is None:
            return
        self._collect(entry["left"], names, depth + 1)
        names.append(entry)
        self._collect(entry["right"], names, depth + 1)


# ---------------------------------------------------------------------------
def _text(compound, path, prop):
    """A Unicode (001F) or ASCII (001E) property stream, decoded to str."""
    entry = compound.paths.get(tuple(path) + ("__substg1.0_%s001F" % prop,))
    if entry:
        return compound.read(entry).decode("utf-16-le", "replace").rstrip("\x00")
    entry = compound.paths.get(tuple(path) + ("__substg1.0_%s001E" % prop,))
    if entry:
        return compound.read(entry).decode("latin-1", "replace").rstrip("\x00")
    return ""


def _binary(compound, path, prop):
    for suffix in ("0102", "0100"):
        entry = compound.paths.get(tuple(path) + ("__substg1.0_%s%s" % (prop, suffix),))
        if entry:
            return compound.read(entry)
    return b""


def parse(data):
    """Read a .msg and return a dict the reader layer can normalise.

    {
      "headers": str,        the original RFC822 headers, or ""
      "from_name": str, "from_email": str,
      "subject": str, "date": str, "to": str,
      "body": str,
      "attachments": [(name, bytes), ...],
    }
    """
    compound = CompoundFile(data)

    result = {
        "headers": _text(compound, (), PROP_HEADERS),
        "subject": _text(compound, (), PROP_SUBJECT),
        "body": _text(compound, (), PROP_BODY),
        "from_name": _text(compound, (), PROP_SENDER_NAME),
        "from_email": (_text(compound, (), PROP_SENDER_SMTP)
                       or _text(compound, (), PROP_SENT_REP_SMTP)
                       or _text(compound, (), PROP_SENDER_EMAIL)),
        "to": _text(compound, (), PROP_DISPLAY_TO),
        "date": _text(compound, (), PROP_DATE),
        "attachments": [],
    }

    # Attachments live in storages named __attach_version1.0_#XXXXXXXX. Each has
    # its filename in 3707 (long) or 3704 (short) and its bytes in 3701.
    for entry in compound.top_level():
        if entry["type"] != 1 or not entry["name"].startswith("__attach_version1.0"):
            continue
        base = (entry["name"],)
        name = _text(compound, base, PROP_ATTACH_LONG) or _text(compound, base, PROP_ATTACH_SHORT)
        payload = _binary(compound, base, PROP_ATTACH_DATA)
        if payload or name:
            result["attachments"].append((name or "(unnamed)", payload))

    return result
