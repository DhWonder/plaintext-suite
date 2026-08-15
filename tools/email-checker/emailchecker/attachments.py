"""
Looking inside an attachment without running it.

Almost every malicious attachment gives itself away structurally, before
anybody needs to know what family of malware it belongs to. It is a program
wearing a document's name. It is a spreadsheet carrying macros. It is a PDF
that wants to run something when you open it. It is a zip with a password in
the email body, which exists for one reason: to get past the scanner.

None of that needs a virus database, an internet connection, or the file to be
run. It needs the first few hundred bytes read carefully. That is what this
does, and it is the half of the job that always works.

The file is never executed, never opened in its own application, and never
sent anywhere.
"""

import hashlib
import math
import os
import re
import struct
import zipfile

# What a file really is, read from its first bytes. A file's extension is a
# claim; this is closer to the truth.
SIGNATURES = [
    (b"MZ",                      "Windows program", "exe"),
    (b"\x7fELF",                 "Linux program", "elf"),
    (b"\xca\xfe\xba\xbe",        "Mac program", "macho"),
    (b"\xcf\xfa\xed\xfe",        "Mac program", "macho"),
    (b"%PDF",                    "PDF document", "pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "older Office document", "ole"),
    (b"PK\x03\x04",              "zip container", "zip"),
    (b"Rar!\x1a\x07",            "RAR archive", "rar"),
    (b"7z\xbc\xaf\x27\x1c",      "7-Zip archive", "7z"),
    (b"\x1f\x8b",                "gzip archive", "gz"),
    (b"{\\rtf",                  "RTF document", "rtf"),
    (b"\xed\xab\xee\xdb",        "RPM package", "rpm"),
    (b"ITSF",                    "Windows help file", "chm"),
    (b"L\x00\x00\x00\x01\x14\x02", "Windows shortcut", "lnk"),
    (b"\x00\x00\x01\x00",        "icon file", "ico"),
    (b"\x89PNG",                 "PNG image", "png"),
    (b"\xff\xd8\xff",            "JPEG image", "jpg"),
    (b"GIF8",                    "GIF image", "gif"),
]

# Extensions that are programs or scripts, whatever they are called.
RUNS_CODE = {
    "exe", "com", "scr", "pif", "cpl", "msi", "msp", "bat", "cmd", "ps1",
    "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "jar", "lnk",
    "reg", "dll", "sys", "app", "sh", "run", "apk", "iso", "img", "vhd",
    "vhdx", "chm", "inf", "scf",
}

# Documents that can carry code inside them.
CAN_CARRY_CODE = {
    "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "sldm",
    "doc", "xls", "ppt", "rtf", "pdf", "xll", "wll",
}

ARCHIVES = {"zip", "rar", "7z", "gz", "tar", "cab", "arj", "lzh", "ace", "iso", "img"}

# Extensions people trust on sight.
LOOKS_HARMLESS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg",
                  "jpeg", "png", "gif", "csv", "rtf", "odt", "ods"}


def sniff(data):
    """What the bytes say this file is, ignoring its name."""
    for magic, description, kind in SIGNATURES:
        if data.startswith(magic):
            return description, kind
    if data[:5].lower() == b"<html" or b"<!doctype html" in data[:200].lower():
        return "web page", "html"
    if data[:2] == b"#!":
        return "script", "sh"
    return "", ""


def entropy(data, sample=65536):
    """How random the bytes are, 0 to 8.

    Ordinary documents and programs have structure and repetition. Something
    near 8 is compressed or encrypted, which is normal for an archive and
    interesting in something claiming to be a document.
    """
    chunk = data[:sample]
    if not chunk:
        return 0.0
    counts = [0] * 256
    for byte in chunk:
        counts[byte] += 1
    total = float(len(chunk))
    result = 0.0
    for count in counts:
        if count:
            share = count / total
            result -= share * math.log(share, 2)
    return round(result, 2)


def extensions_of(name):
    parts = (name or "").lower().split(".")
    return [p for p in parts[1:] if p]


def examine(name, data):
    """Everything worth knowing about one attachment, from its bytes."""
    findings = []          # (weight 1..3, sentence)
    extensions = extensions_of(name)
    claimed = extensions[-1] if extensions else ""
    described, actually = sniff(data)

    report = {
        "name": name or "(unnamed)",
        "bytes": len(data),
        "claimed_type": claimed,
        "real_type": described or "unrecognised",
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "entropy": entropy(data),
        "findings": findings,
        "contents": [],
    }

    # 1. Is it a program pretending to be a document?
    if actually in ("exe", "elf", "macho"):
        if claimed in LOOKS_HARMLESS:
            findings.append((3, "This is a %s, but it is named like a %s. A file that runs code "
                                "should never be arriving with a document's name. This is the "
                                "single clearest sign there is."
                             % (described, claimed.upper())))
        else:
            findings.append((3, "This is a %s. Opening it runs whatever it was built to do, and "
                                "no ordinary business attachment needs to do that." % described))

    # 2. Two extensions, so the real one is hidden.
    if len(extensions) >= 2 and extensions[-1] in RUNS_CODE and extensions[-2] in LOOKS_HARMLESS:
        findings.append((3, "The name ends '.%s.%s'. Windows hides known extensions by default, "
                            "so the person sees a %s and gets a program. This is deliberate."
                         % (extensions[-2], extensions[-1], extensions[-2].upper())))

    # 3. Named as something that runs.
    if claimed in RUNS_CODE and not any(w == 3 for w, _ in findings):
        findings.append((3, "A .%s file runs code when it is opened. Whatever it claims to be, "
                            "treat it as a program somebody sent you." % claimed))

    # 4. The name says one thing, the bytes say another.
    if actually and claimed and claimed not in ARCHIVES:
        expected = {"pdf": "pdf", "zip": "zip", "docx": "zip", "xlsx": "zip", "pptx": "zip",
                    "docm": "zip", "xlsm": "zip", "doc": "ole", "xls": "ole", "ppt": "ole",
                    "rtf": "rtf", "jpg": "jpg", "jpeg": "jpg", "png": "png", "gif": "gif"}
        want = expected.get(claimed)
        if want and want != actually:
            findings.append((2, "It is named .%s but the contents are a %s. A mismatch like that "
                                "is either a broken file or a deliberate disguise."
                             % (claimed, described)))

    # 5. Office documents that can carry macros.
    if actually == "zip":
        findings.extend(_look_in_office(data, report))
    elif actually == "ole":
        findings.extend(_look_in_old_office(data, claimed))

    # 6. PDFs that want to do something on open.
    if actually == "pdf":
        findings.extend(_look_in_pdf(data))

    # 7. Archives, including the password trick.
    if actually in ("zip", "rar", "7z") and claimed in ARCHIVES:
        findings.extend(_look_in_archive(data, report))

    # 8. Disk images, which exist in email for one reason.
    if claimed in ("iso", "img", "vhd", "vhdx"):
        findings.append((3, "A disk image attached to an email is a way of smuggling a program "
                            "past the warning Windows shows for downloaded files. There is no "
                            "ordinary reason to send one."))

    # 9. A web page as an attachment.
    if actually == "html" or claimed in ("html", "htm", "shtml"):
        findings.append((2, "This is a web page sent as a file. Opened, it looks like a real "
                            "login page, and it is not on the internet where anyone could take "
                            "it down. This is a common way to collect passwords."))

    # 10. Nothing but noise.
    if report["entropy"] > 7.8 and actually not in ("zip", "rar", "7z", "gz", "jpg", "png", "gif"):
        findings.append((1, "The contents look compressed or encrypted rather than like a "
                            "document. That is normal in an archive and odd in anything else."))

    if len(data) < 32:
        findings.append((1, "The file is almost empty, which usually means it did not survive "
                            "being forwarded."))

    findings.sort(reverse=True)
    report["findings"] = findings
    report["score"] = sum(weight for weight, _ in findings)
    report["level"] = _level(report["score"], findings)
    return report


def _level(score, findings):
    if any(weight == 3 for weight, _ in findings):
        return "critical" if score >= 5 else "high"
    if score >= 3:
        return "watch"
    if score:
        return "watch"
    return "normal"


# ---------------------------------------------------------------------------
def _look_in_office(data, report):
    """Modern Office files are zip archives. Macros live in a known file."""
    findings = []
    try:
        import io
        with zipfile.ZipFile(io.BytesIO(data)) as bundle:
            names = bundle.namelist()
    except (zipfile.BadZipFile, OSError, ValueError):
        return findings

    report["contents"] = names[:40]

    if any(n.lower().endswith("vbaproject.bin") for n in names):
        findings.append((3, "This document carries macros: code that runs when the document is "
                            "opened, if the person clicks Enable Content. That button is what "
                            "most office malware is waiting for."))
    if any("externallink" in n.lower() for n in names):
        findings.append((2, "The document pulls content from somewhere else when opened, which "
                            "is how a document phones home or fetches the actual payload."))
    if any(n.lower().endswith(".bin") and "ole" in n.lower() for n in names):
        findings.append((2, "There is an embedded object inside the document. Sometimes that is "
                            "a chart. Sometimes it is a program with an icon on it."))
    if any(n.lower().endswith((".exe", ".dll", ".scr", ".js", ".vbs", ".ps1")) for n in names):
        findings.append((3, "There is a program file packed inside this document."))
    return findings


def _look_in_old_office(data, claimed):
    """The pre 2007 formats keep macros in a stream we can spot by name."""
    findings = []
    lowered = data.lower()
    if b"vba" in lowered or b"_vba_project" in lowered:
        findings.append((3, "This older Office file contains macro code. The older formats carry "
                            "macros with no warning in the file name, which is why attackers "
                            "still use them."))
    if b"equation.3" in lowered or b"equation native" in lowered:
        findings.append((3, "It uses the old equation editor, which has a long history of being "
                            "used to run code. Microsoft removed it years ago."))
    return findings


def _look_in_pdf(data):
    """PDFs are documents that can also be told to do things."""
    findings = []
    lowered = data.lower()
    if b"/javascript" in lowered or b"/js" in lowered:
        findings.append((3, "This PDF contains JavaScript. A document that needs to run code to "
                            "show you a page is not showing you a page."))
    if b"/openaction" in lowered or b"/aa" in lowered:
        findings.append((2, "It is set to do something the moment it opens, before you have "
                            "clicked anything."))
    if b"/launch" in lowered:
        findings.append((3, "It contains an instruction to launch another program."))
    if b"/embeddedfile" in lowered:
        findings.append((2, "There is another file hidden inside this PDF."))
    if b"/uri" in lowered and b"/openaction" in lowered:
        findings.append((2, "It opens a web address on its own when the document is opened."))
    return findings


def _look_in_archive(data, report):
    """What is in the archive, and whether it wants a password."""
    findings = []
    try:
        import io
        with zipfile.ZipFile(io.BytesIO(data)) as bundle:
            entries = bundle.infolist()
            report["contents"] = [item.filename for item in entries[:40]]
            encrypted = any(item.flag_bits & 0x1 for item in entries)
            inner = [item.filename.lower() for item in entries]
    except (zipfile.BadZipFile, OSError, ValueError):
        return findings

    if encrypted:
        findings.append((3, "The archive is password protected. In an email with the password "
                            "written in the message, that exists for one reason: a scanner "
                            "cannot look inside a locked archive, and the person can."))

    risky = [name for name in inner
             if name.rsplit(".", 1)[-1] in RUNS_CODE and "." in name]
    if risky:
        findings.append((3, "Inside the archive there %s a program: %s. Archives are used to get "
                            "programs past filters that would block them on their own."
                         % ("is" if len(risky) == 1 else "are", ", ".join(risky[:4]))))

    doubled = [name for name in inner if len(name.split(".")) >= 3
               and name.rsplit(".", 1)[-1] in RUNS_CODE]
    if doubled:
        findings.append((3, "A file inside the archive uses a double extension to hide what it "
                            "is: %s" % ", ".join(doubled[:3])))
    return findings
