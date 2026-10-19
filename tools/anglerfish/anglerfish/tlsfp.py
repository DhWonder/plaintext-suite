"""
TLS ClientHello / ServerHello fingerprinting for the HTTPS facade (stdlib only).

Why this exists: ``ssl.SSLContext.wrap_socket`` hides the raw handshake, so
JA3 / JA3S / SNI / ALPN could not be logged. Approach (no pip dependency):

1. ``peek_client_hello`` waits (bounded by time and size) for the first TLS
   handshake record(s) using ``MSG_PEEK`` -- nothing is consumed yet, so if the
   bytes are not a ClientHello the caller can still fall back to the plain
   ``wrap_socket`` path with the kernel buffer untouched.
2. ``parse_client_hello`` decodes the ClientHello in pure Python (never
   executes anything; every length is bounds-checked; malformed -> ``None``).
3. ``memory_bio_handshake`` consumes exactly the peeked bytes, feeds them into
   an incoming ``ssl.MemoryBIO`` and drives the real stdlib OpenSSL engine via
   ``ssl.SSLObject``. Further socket reads go into the same BIO, so the engine
   sees the complete, unmodified handshake. The engine's output (outgoing BIO)
   is sent to the peer *and* inspected: the plaintext ServerHello is parsed,
   so JA3S is computed from the ServerHello actually sent -- not guessed.
4. ``TLSConnection`` is a small socket-like shim (recv / sendall / settimeout /
   setsockopt / close / cipher / version / server_hostname) so the rest of the
   sensor is unchanged.

JA3  = md5("SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats")
JA3S = md5("SSLVersion,Cipher,Extensions")
Values are decimal, '-' joined, fields ',' joined; GREASE values (RFC 8701,
0x?a?a) are removed from every list. SSLVersion is the legacy
``client_version`` / ``server_version`` field (771 for TLS 1.2 *and* 1.3),
exactly as in the reference Salesforce implementation.
"""

import hashlib
import select
import socket
import ssl
import struct
import time

# RFC 8701 GREASE: 0x0a0a, 0x1a1a, ... 0xfafa
GREASE = frozenset(((b << 12) | (0xA << 8) | (b << 4) | 0xA) for b in range(16))

MAX_HELLO = 32 * 1024          # hard cap on ClientHello bytes we buffer
MAX_RECORD = 18432             # 2^14 + 2048 (RFC 8446 5.2 upper bound)
MAX_CAPTURE_OUT = 64 * 1024    # server-flight bytes kept for ServerHello parse
HANDSHAKE_TIMEOUT = 10.0       # seconds for the whole TLS handshake
PEEK_TIMEOUT = 5.0             # seconds to wait for a complete ClientHello

# HelloRetryRequest magic random (RFC 8446 4.1.3)
_HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

NEED_MORE, COMPLETE, INVALID = "need_more", "complete", "invalid"

EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10      # a.k.a. elliptic_curves
EXT_EC_POINT_FORMATS = 11
EXT_ALPN = 16
EXT_SUPPORTED_VERSIONS = 43


def is_grease(v):
    return v in GREASE


def _strip(values):
    return [v for v in values if v not in GREASE]


class _Reader(object):
    """Bounds-checked big-endian reader. Any overrun raises ValueError."""

    __slots__ = ("buf", "pos", "end")

    def __init__(self, buf, pos=0, end=None):
        self.buf = buf
        self.pos = pos
        self.end = len(buf) if end is None else end
        if self.end > len(buf) or pos > self.end:
            raise ValueError("bad bounds")

    def remaining(self):
        return self.end - self.pos

    def take(self, n):
        if n < 0 or self.pos + n > self.end:
            raise ValueError("overrun")
        out = self.buf[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack("!H", self.take(2))[0]

    def u24(self):
        b = self.take(3)
        return (b[0] << 16) | (b[1] << 8) | b[2]

    def sub(self, n):
        start = self.pos
        self.take(n)
        return _Reader(self.buf, start, start + n)


def _vec(r, len_bytes):
    n = r.u8() if len_bytes == 1 else r.u16() if len_bytes == 2 else r.u24()
    return r.sub(n)


def _u16_list(r):
    if r.remaining() % 2:
        raise ValueError("odd u16 list")
    out = []
    while r.remaining():
        out.append(r.u16())
    return out


# ---------------------------------------------------------------- records ---

def handshake_stream(buf, max_bytes=MAX_HELLO):
    """Reassemble handshake-layer bytes from leading TLS handshake records.

    Returns ``(status, handshake_bytes, consumed_record_bytes)``. ``status`` is
    COMPLETE once the first handshake message is fully present, NEED_MORE if
    more bytes are required, INVALID if this is not a TLS handshake."""
    if not buf:
        return NEED_MORE, b"", 0
    if buf[0] != 0x16:
        return INVALID, b"", 0
    out = bytearray()
    pos = 0
    while True:
        if len(buf) - pos < 5:
            return NEED_MORE, bytes(out), pos
        ctype, major, minor = buf[pos], buf[pos + 1], buf[pos + 2]
        length = struct.unpack("!H", buf[pos + 3:pos + 5])[0]
        if ctype != 0x16 or major != 3 or minor > 4 or length == 0 or length > MAX_RECORD:
            return INVALID, b"", 0
        if len(buf) - pos - 5 < length:
            return NEED_MORE, bytes(out), pos
        out.extend(buf[pos + 5:pos + 5 + length])
        pos += 5 + length
        if len(out) >= 4:
            msg_len = (out[1] << 16) | (out[2] << 8) | out[3]
            if 4 + msg_len > max_bytes:
                return INVALID, b"", 0
            if len(out) >= 4 + msg_len:
                return COMPLETE, bytes(out), pos
        if pos > max_bytes:
            return INVALID, b"", 0


def _parse_extensions(r):
    """Return list of (type, Reader-over-body) in wire order."""
    exts = []
    if not r.remaining():
        return exts
    block = _vec(r, 2)
    while block.remaining():
        etype = block.u16()
        exts.append((etype, _vec(block, 2)))
    return exts


def parse_client_hello(buf):
    """Parse raw bytes (starting at the TLS record header) as a ClientHello.

    Returns a dict or ``None`` if the bytes are not a well-formed ClientHello.
    Never raises."""
    try:
        status, hs, _consumed = handshake_stream(bytes(buf))
        if status != COMPLETE:
            return None
        return parse_client_hello_msg(hs)
    except Exception:
        return None


def parse_client_hello_msg(hs):
    """Parse a handshake-layer ClientHello message (type byte first)."""
    try:
        r = _Reader(hs)
        if r.u8() != 1:
            return None
        body = r.sub(r.u24())
        client_version = body.u16()
        body.take(32)                       # random
        _vec(body, 1)                       # legacy_session_id
        ciphers = _u16_list(_vec(body, 2))
        _vec(body, 1)                       # compression methods
        exts = _parse_extensions(body)
        info = {
            "client_version": client_version,
            "ciphers": ciphers,
            "extensions": [e for e, _ in exts],
            "groups": [],
            "point_formats": [],
            "sni": None,
            "alpn": [],
            "supported_versions": [],
        }
        for etype, er in exts:
            try:
                if etype == EXT_SERVER_NAME and er.remaining():
                    lst = _vec(er, 2)
                    while lst.remaining():
                        ntype = lst.u8()
                        name = _vec(lst, 2)
                        raw = name.take(name.remaining())
                        if ntype == 0 and info["sni"] is None:
                            info["sni"] = raw.decode("ascii", "replace")[:255]
                elif etype == EXT_SUPPORTED_GROUPS:
                    info["groups"] = _u16_list(_vec(er, 2))
                elif etype == EXT_EC_POINT_FORMATS:
                    pf = _vec(er, 1)
                    info["point_formats"] = list(pf.take(pf.remaining()))
                elif etype == EXT_ALPN:
                    lst = _vec(er, 2)
                    while lst.remaining():
                        p = _vec(lst, 1)
                        info["alpn"].append(
                            p.take(p.remaining()).decode("ascii", "replace")[:64])
                elif etype == EXT_SUPPORTED_VERSIONS:
                    sv = _vec(er, 1)
                    info["supported_versions"] = _u16_list(sv)
            except ValueError:
                # A malformed individual extension does not void the JA3.
                continue
        info["ja3_str"] = ja3_string(info)
        info["ja3"] = hashlib.md5(info["ja3_str"].encode("ascii")).hexdigest()
        return info
    except Exception:
        return None


def ja3_string(info):
    def j(vals):
        return "-".join(str(v) for v in _strip(vals))
    return ",".join([
        str(info["client_version"]),
        j(info["ciphers"]),
        j(info["extensions"]),
        j(info["groups"]),
        j(info["point_formats"]),
    ])


def parse_server_hello_msg(hs):
    """Parse a handshake-layer ServerHello. Returns dict or None."""
    try:
        r = _Reader(hs)
        if r.u8() != 2:
            return None
        body = r.sub(r.u24())
        server_version = body.u16()
        random = body.take(32)
        _vec(body, 1)
        cipher = body.u16()
        body.u8()                           # compression
        exts = _parse_extensions(body)
        info = {
            "server_version": server_version,
            "cipher": cipher,
            "extensions": [e for e, _ in exts],
            "hrr": random == _HRR_RANDOM,
        }
        info["ja3s_str"] = "%d,%d,%s" % (
            server_version, cipher,
            "-".join(str(e) for e in _strip(info["extensions"])))
        info["ja3s"] = hashlib.md5(info["ja3s_str"].encode("ascii")).hexdigest()
        return info
    except Exception:
        return None


def find_server_hello(flight):
    """Scan server output records for the first real (non-HRR) ServerHello."""
    try:
        pos = 0
        buf = bytes(flight)
        while len(buf) - pos >= 5:
            ctype = buf[pos]
            length = struct.unpack("!H", buf[pos + 3:pos + 5])[0]
            payload = buf[pos + 5:pos + 5 + length]
            pos += 5 + length
            if ctype == 0x16 and payload[:1] == b"\x02":
                sh = parse_server_hello_msg(payload)
                if sh and not sh["hrr"]:
                    return sh
        return None
    except Exception:
        return None


# ------------------------------------------------------------- live path ---

def peek_client_hello(sock, timeout=PEEK_TIMEOUT, max_bytes=MAX_HELLO):
    """Wait for a full ClientHello without consuming it.

    Returns ``(info_or_None, n_record_bytes)``. ``n_record_bytes`` is how many
    bytes form the ClientHello record(s) (0 when invalid / incomplete)."""
    deadline = time.monotonic() + timeout
    last_len = -1
    try:
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return None, 0
            readable, _, _ = select.select([sock], [], [], min(left, 0.5))
            if not readable:
                continue
            data = sock.recv(max_bytes + 5, socket.MSG_PEEK)
            if not data:
                return None, 0
            status, hs, consumed = handshake_stream(data, max_bytes)
            if status == INVALID:
                return None, 0
            if status == COMPLETE:
                return parse_client_hello_msg(hs), consumed
            if len(data) >= max_bytes:
                return None, 0
            if len(data) == last_len:
                # Data is pending but not growing: avoid a busy loop.
                time.sleep(0.02)
            last_len = len(data)
    except Exception:
        return None, 0


def _recv_exact(sock, n, deadline):
    out = bytearray()
    while len(out) < n:
        if time.monotonic() > deadline:
            raise socket.timeout("handshake deadline")
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise ConnectionError("eof during ClientHello consume")
        out.extend(chunk)
    return bytes(out)


def memory_bio_handshake(ctx, sock, hello_len, timeout=HANDSHAKE_TIMEOUT):
    """Run the server handshake through SSLObject + MemoryBIO.

    Consumes the ``hello_len`` peeked ClientHello bytes, feeds them to the
    engine, then keeps pumping socket <-> BIO until the handshake completes.
    Returns ``(TLSConnection, server_hello_info_or_None)``; raises
    ``ssl.SSLError`` / ``OSError`` on failure (caller logs + closes)."""
    deadline = time.monotonic() + timeout
    old_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_side=True)
    incoming.write(_recv_exact(sock, hello_len, deadline))
    captured = bytearray()
    while True:
        if time.monotonic() > deadline:
            raise socket.timeout("handshake deadline")
        try:
            obj.do_handshake()
            done = True
        except ssl.SSLWantReadError:
            done = False
        out = outgoing.read()
        if out:
            if len(captured) < MAX_CAPTURE_OUT:
                captured.extend(out[:MAX_CAPTURE_OUT - len(captured)])
            sock.sendall(out)
        if done:
            break
        data = sock.recv(MAX_RECORD + 5)
        if not data:
            incoming.write_eof()
            raise ConnectionError("eof during handshake")
        incoming.write(data)
    sock.settimeout(old_timeout)
    return TLSConnection(sock, obj, incoming, outgoing), find_server_hello(captured)


class TLSConnection(object):
    """Socket-like shim over an SSLObject driven by MemoryBIOs."""

    def __init__(self, sock, obj, incoming, outgoing, sni=None):
        self._sock = sock
        self._obj = obj
        self._in = incoming
        self._out = outgoing
        self.server_hostname = sni
        self._closed = False

    # -- passthrough ------------------------------------------------------
    def settimeout(self, t):
        return self._sock.settimeout(t)

    def gettimeout(self):
        return self._sock.gettimeout()

    def setsockopt(self, *a):
        return self._sock.setsockopt(*a)

    def fileno(self):
        return self._sock.fileno()

    def getpeername(self):
        return self._sock.getpeername()

    def getsockname(self):
        return self._sock.getsockname()

    def cipher(self):
        return self._obj.cipher()

    def version(self):
        return self._obj.version()

    def selected_alpn_protocol(self):
        return self._obj.selected_alpn_protocol()

    # -- I/O ----------------------------------------------------------------
    def _flush(self):
        out = self._out.read()
        if out:
            self._sock.sendall(out)

    def recv(self, n, flags=0):
        if flags:
            raise ValueError("flags not supported on TLS shim")
        while True:
            try:
                data = self._obj.read(n)
                self._flush()
                return data
            except ssl.SSLWantReadError:
                self._flush()
                raw = self._sock.recv(MAX_RECORD + 5)
                if not raw:
                    self._in.write_eof()
                    return b""
                self._in.write(raw)
            except ssl.SSLZeroReturnError:
                return b""
            except ssl.SSLEOFError:
                return b""

    def send(self, data):
        self.sendall(data)
        return len(data)

    def sendall(self, data):
        view = memoryview(bytes(data))
        while view:
            try:
                n = self._obj.write(view[:16384])
            except ssl.SSLWantReadError:
                self._flush()
                raw = self._sock.recv(MAX_RECORD + 5)
                if not raw:
                    raise ConnectionError("peer closed")
                self._in.write(raw)
                continue
            view = view[n:]
            self._flush()

    def shutdown(self, how=socket.SHUT_RDWR):
        try:
            self._sock.shutdown(how)
        except OSError:
            pass

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self._obj.unwrap()
        except Exception:
            pass
        try:
            self._flush()
        except Exception:
            pass
        try:
            self._sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
