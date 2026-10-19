"""
A small but genuine SSH-2 server for the honeypot.

Enough of the protocol that a modern OpenSSH or libssh/paramiko client finishes
key exchange, authenticates, and reaches a shell. After the password is accepted
the bytes the client sends are handed to a callback. This module runs nothing,
opens no sockets of its own, and forwards no ports: direct-tcpip and subsystems
are refused, so it can never be a relay or a pivot.

It speaks what a real OpenSSH client actually negotiates, so a scanner or
ssh-audit sees a real handshake instead of a one-algorithm-per-slot toy:

  key exchange:  curve25519-sha256 (+@libssh.org), diffie-hellman-group16-sha512,
                 diffie-hellman-group14-sha256, with kex-strict and ext-info
  host keys:     ssh-ed25519, rsa-sha2-512, rsa-sha2-256 (per-install, from the
                 persona; never hard-coded in this file)
  ciphers:       chacha20-poly1305@openssh.com, aes128-ctr, aes192-ctr, aes256-ctr
  macs:          hmac-sha2-256/512 and their -etm@openssh.com forms
  compression:   none

Known gap, stated honestly: the pure-Python crypto does not include the
post-quantum sntrup761x25519 kex or AES-GCM, so those are not advertised. A real
OpenSSH client falls through to curve25519-sha256 and aes/chacha, which are.
"""

import hashlib
import hmac as _hmac
import os
import socket
import struct
import sys
import time

from . import sshcrypto

# RFC 3526 2048-bit (group14) and 4096-bit (group16) MODP groups, g=2.
_GROUP14_HEX = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
"""
_GROUP16_HEX = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AACAA68 15D22618 98FA0510 15728E5A 8AACAA68
FFFFFFFF FFFFFFFF
"""
# (group16 constant defined precisely below)
GROUP14_P = int("".join(_GROUP14_HEX.split()), 16)

GROUP16_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
    16)

KEX_ADVERTISED = [
    "curve25519-sha256", "curve25519-sha256@libssh.org",
    "diffie-hellman-group16-sha512", "diffie-hellman-group14-sha256",
    "kex-strict-s-v00@openssh.com",
]
HOSTKEY_ADVERTISED = ["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"]
CIPHER_ADVERTISED = [
    "chacha20-poly1305@openssh.com",
    "aes128-ctr", "aes192-ctr", "aes256-ctr",
]
MAC_ADVERTISED = [
    "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256", "hmac-sha2-512",
]
COMP_ADVERTISED = ["none", "zlib@openssh.com"]

_PSEUDO = set([
    "ext-info-c", "ext-info-s",
    "kex-strict-c-v00@openssh.com", "kex-strict-s-v00@openssh.com",
])

SSH_MSG_DISCONNECT = 1
SSH_MSG_IGNORE = 2
SSH_MSG_UNIMPLEMENTED = 3
SSH_MSG_DEBUG = 4
SSH_MSG_SERVICE_REQUEST = 5
SSH_MSG_SERVICE_ACCEPT = 6
SSH_MSG_EXT_INFO = 7
SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21
SSH_MSG_KEXDH_INIT = 30
SSH_MSG_KEXDH_REPLY = 31
SSH_MSG_USERAUTH_REQUEST = 50
SSH_MSG_USERAUTH_FAILURE = 51
SSH_MSG_USERAUTH_SUCCESS = 52
SSH_MSG_USERAUTH_BANNER = 53
SSH_MSG_GLOBAL_REQUEST = 80
SSH_MSG_REQUEST_FAILURE = 82
SSH_MSG_CHANNEL_OPEN = 90
SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91
SSH_MSG_CHANNEL_OPEN_FAILURE = 92
SSH_MSG_CHANNEL_WINDOW_ADJUST = 93
SSH_MSG_CHANNEL_DATA = 94
SSH_MSG_CHANNEL_EOF = 96
SSH_MSG_CHANNEL_CLOSE = 97
SSH_MSG_CHANNEL_REQUEST = 98
SSH_MSG_CHANNEL_SUCCESS = 99
SSH_MSG_CHANNEL_FAILURE = 100

# OpenSSH disconnect reason codes.
DISC_PROTOCOL_ERROR = 2
DISC_KEY_EXCHANGE_FAILED = 3
DISC_MAC_ERROR = 5
DISC_SERVICE_NOT_AVAILABLE = 7
DISC_PROTOCOL_VERSION_NOT_SUPPORTED = 8
DISC_BY_APPLICATION = 11
DISC_TOO_MANY_CONNECTIONS = 12
DISC_AUTH_CANCELLED = 13
DISC_NO_MORE_AUTH_METHODS = 14

_MAX_PACKET = 262144
_DIGESTINFO = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


class ProtocolError(Exception):
    """The client sent something this server will not continue with."""


def _trace(text):
    if os.environ.get("ANGLERFISH_SSH_DEBUG"):
        sys.stderr.write("sshproto: %s\n" % text)
        sys.stderr.flush()


# ---------------------------------------------------------------------------
# SSH encoding helpers.
# ---------------------------------------------------------------------------
def _enc_string(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return struct.pack(">I", len(data)) + data


def _enc_mpint(number):
    if number < 0:
        raise ProtocolError("negative mpint")
    if number == 0:
        return struct.pack(">I", 0)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return struct.pack(">I", len(raw)) + raw


def _enc_namelist(names):
    return _enc_string(",".join(names).encode("ascii"))


def _take_string(buf, index):
    if index + 4 > len(buf):
        raise ProtocolError("short string")
    length = struct.unpack(">I", buf[index:index + 4])[0]
    index += 4
    if length > len(buf) - index or length > _MAX_PACKET:
        raise ProtocolError("string length")
    return buf[index:index + length], index + length


def _take_uint32(buf, index):
    if index + 4 > len(buf):
        raise ProtocolError("short uint")
    return struct.unpack(">I", buf[index:index + 4])[0], index + 4


def _take_string_raw(buf, index):
    if index + 4 > len(buf):
        raise ProtocolError("short field")
    length = struct.unpack(">I", buf[index:index + 4])[0]
    end = index + 4 + length
    if length > _MAX_PACKET or end > len(buf):
        raise ProtocolError("field length")
    return buf[index:end], end


def _mpint_value(encoded):
    length = struct.unpack(">I", encoded[:4])[0]
    raw = encoded[4:4 + length]
    if not raw:
        return 0
    return int.from_bytes(raw, "big")


def _choose(client_names, server_names):
    offered = set(server_names)
    for name in client_names:
        if name in _PSEUDO:
            continue
        if name in offered:
            return name
    return None


# ---------------------------------------------------------------------------
# Host keys, built from the persona (never hard-coded here).
# ---------------------------------------------------------------------------
class HostKeys(object):
    def __init__(self, rsa, ed25519_seed):
        self.rsa = rsa                      # {"n","e","d"}
        self.ed_seed = ed25519_seed
        self.ed_pub = sshcrypto.ed25519_public(ed25519_seed)

    def blob(self, algo):
        if algo == "ssh-ed25519":
            return _enc_string(b"ssh-ed25519") + _enc_string(self.ed_pub)
        # rsa-sha2-* use an "ssh-rsa" key blob
        return b"".join([_enc_string(b"ssh-rsa"),
                         _enc_mpint(self.rsa["e"]), _enc_mpint(self.rsa["n"])])

    def sign(self, algo, data):
        if algo == "ssh-ed25519":
            sig = sshcrypto.ed25519_sign(self.ed_seed, data)
            return _enc_string(b"ssh-ed25519") + _enc_string(sig)
        hashname = "sha512" if algo == "rsa-sha2-512" else "sha256"
        raw = _rsa_sign(self.rsa, data, hashname)
        return _enc_string(algo.encode()) + _enc_string(raw)

    def fingerprint_sha256(self, algo="ssh-ed25519"):
        import base64
        digest = hashlib.sha256(self.blob(algo)).digest()
        return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def _rsa_sign(rsa, data, hashname):
    h = hashlib.new(hashname, data).digest()
    info = _DIGESTINFO[hashname] + h
    k = (rsa["n"].bit_length() + 7) // 8
    if len(info) + 11 > k:
        raise ProtocolError("rsa block")
    em = b"\x00\x01" + (b"\xff" * (k - len(info) - 3)) + b"\x00" + info
    sig = pow(int.from_bytes(em, "big"), rsa["d"], rsa["n"])
    return sig.to_bytes(k, "big")


# ---------------------------------------------------------------------------
# Cipher / MAC state per direction.
# ---------------------------------------------------------------------------
_MAC_INFO = {
    "hmac-sha2-256": (hashlib.sha256, 32, False),
    "hmac-sha2-512": (hashlib.sha512, 64, False),
    "hmac-sha2-256-etm@openssh.com": (hashlib.sha256, 32, True),
    "hmac-sha2-512-etm@openssh.com": (hashlib.sha512, 64, True),
}
_CIPHER_KEYSIZE = {"aes128-ctr": 16, "aes192-ctr": 24, "aes256-ctr": 32}


class _Dir(object):
    """Encryption state for one direction (send or receive)."""

    def __init__(self):
        self.cipher = None          # AESCTR or ChaCha...
        self.aead = False
        self.block = 8
        self.mac_fn = None
        self.mac_len = 0
        self.mac_key = b""
        self.etm = False
        self.active = False


class PacketConn(object):
    def __init__(self, sock, preload=b""):
        self.sock = sock
        self.buf = bytearray(preload)
        self.send_seq = 0
        self.recv_seq = 0
        self.out = _Dir()
        self.inp = _Dir()
        self.strict = False

    def _read(self, size):
        while len(self.buf) < size:
            chunk = self.sock.recv(max(2048, size - len(self.buf)))
            if not chunk:
                raise EOFError("client closed")
            self.buf.extend(chunk)
        data = bytes(self.buf[:size])
        del self.buf[:size]
        return data

    # -- sending ------------------------------------------------------
    def send_packet(self, payload):
        d = self.out
        if not d.active:
            block = 8
            padlen = block - ((5 + len(payload)) % block)
            if padlen < 4:
                padlen += block
            padding = os.urandom(padlen)
            plen = 1 + len(payload) + padlen
            self.sock.sendall(struct.pack(">IB", plen, padlen) + payload + padding)
            self.send_seq = (self.send_seq + 1) & 0xFFFFFFFF
            return
        if d.aead:
            block = 8
            padlen = block - ((1 + len(payload)) % block)
            if padlen < 4:
                padlen += block
            padding = os.urandom(padlen)
            plen = 1 + len(payload) + padlen
            enc_len = d.cipher.encrypt_length(self.send_seq, struct.pack(">I", plen))
            body = bytes([padlen]) + payload + padding
            enc_body = d.cipher.encrypt_payload(self.send_seq, body)
            tag = d.cipher.tag(self.send_seq, enc_len + enc_body)
            self.sock.sendall(enc_len + enc_body + tag)
            self.send_seq = (self.send_seq + 1) & 0xFFFFFFFF
            return
        block = d.block
        if d.etm:
            padlen = block - ((1 + len(payload)) % block)
            if padlen < 4:
                padlen += block
            padding = os.urandom(padlen)
            plen = 1 + len(payload) + padlen
            length = struct.pack(">I", plen)
            enc = d.cipher.crypt(bytes([padlen]) + payload + padding)
            mac = _hmac.new(d.mac_key, struct.pack(">I", self.send_seq) + length + enc,
                            d.mac_fn).digest()
            self.sock.sendall(length + enc + mac)
        else:
            padlen = block - ((5 + len(payload)) % block)
            if padlen < 4:
                padlen += block
            padding = os.urandom(padlen)
            plen = 1 + len(payload) + padlen
            plain = struct.pack(">IB", plen, padlen) + payload + padding
            mac = _hmac.new(d.mac_key, struct.pack(">I", self.send_seq) + plain,
                            d.mac_fn).digest()
            enc = d.cipher.crypt(plain)
            self.sock.sendall(enc + mac)
        self.send_seq = (self.send_seq + 1) & 0xFFFFFFFF

    # -- receiving ----------------------------------------------------
    def recv_packet(self):
        d = self.inp
        if not d.active:
            head = self._read(4)
            plen = struct.unpack(">I", head)[0]
            if plen < 8 or plen > _MAX_PACKET or (4 + plen) % 8 != 0:
                raise ProtocolError("bad packet length")
            rest = self._read(plen)
            plain = head + rest
            padlen = plain[4]
            payload = plain[5:4 + plen - padlen]
            self.recv_seq = (self.recv_seq + 1) & 0xFFFFFFFF
            return payload
        if d.aead:
            enc_len = self._read(4)
            length = struct.unpack(">I", d.cipher.decrypt_length(self.recv_seq, enc_len))[0]
            if length < 8 or length > _MAX_PACKET:
                raise ProtocolError("bad packet length")
            enc_body = self._read(length)
            tag = self._read(16)
            expect = d.cipher.tag(self.recv_seq, enc_len + enc_body)
            if not _hmac.compare_digest(expect, tag):
                raise ProtocolError("bad poly1305 tag")
            body = d.cipher.decrypt_payload(self.recv_seq, enc_body)
            padlen = body[0]
            payload = body[1:length - padlen]
            self.recv_seq = (self.recv_seq + 1) & 0xFFFFFFFF
            return payload
        if d.etm:
            length_b = self._read(4)
            length = struct.unpack(">I", length_b)[0]
            if length < 8 or length > _MAX_PACKET or length % d.block != 0:
                raise ProtocolError("bad packet length")
            enc = self._read(length)
            mac = self._read(d.mac_len)
            expect = _hmac.new(d.mac_key, struct.pack(">I", self.recv_seq) + length_b + enc,
                               d.mac_fn).digest()
            if not _hmac.compare_digest(expect, mac):
                raise ProtocolError("bad mac")
            plain = d.cipher.crypt(enc)
            padlen = plain[0]
            payload = plain[1:length - padlen]
            self.recv_seq = (self.recv_seq + 1) & 0xFFFFFFFF
            return payload
        first = d.cipher.crypt(self._read(d.block))
        length = struct.unpack(">I", first[:4])[0]
        if length < 8 or length > _MAX_PACKET or (4 + length) % d.block != 0:
            raise ProtocolError("bad packet length")
        rest = d.cipher.crypt(self._read(4 + length - d.block))
        mac = self._read(d.mac_len)
        plain = first + rest
        expect = _hmac.new(d.mac_key, struct.pack(">I", self.recv_seq) + plain,
                           d.mac_fn).digest()
        if not _hmac.compare_digest(expect, mac):
            raise ProtocolError("bad mac")
        padlen = plain[4]
        payload = plain[5:4 + length - padlen]
        self.recv_seq = (self.recv_seq + 1) & 0xFFFFFFFF
        return payload

    def enable(self, d, cipher_name, mac_name, key, iv, mac_key):
        if cipher_name == "chacha20-poly1305@openssh.com":
            d.cipher = sshcrypto.ChaCha20Poly1305OpenSSH(key)
            d.aead = True
            d.block = 8
        else:
            d.cipher = sshcrypto.AESCTR(key[:_CIPHER_KEYSIZE[cipher_name]], iv)
            d.block = 16
            fn, mlen, etm = _MAC_INFO[mac_name]
            d.mac_fn = fn
            d.mac_len = mlen
            d.mac_key = mac_key[:mlen]
            d.etm = etm
        d.active = True

    def disconnect(self, code, message):
        try:
            self.send_packet(bytes([SSH_MSG_DISCONNECT]) + struct.pack(">I", code)
                             + _enc_string(message) + _enc_string(b""))
        except OSError:
            pass

    def unimplemented(self, seq):
        self.send_packet(bytes([SSH_MSG_UNIMPLEMENTED]) + struct.pack(">I", seq))


# ---------------------------------------------------------------------------
def _build_kexinit():
    parts = [bytes([SSH_MSG_KEXINIT]), os.urandom(16)]
    lists = [KEX_ADVERTISED, HOSTKEY_ADVERTISED, CIPHER_ADVERTISED, CIPHER_ADVERTISED,
             MAC_ADVERTISED, MAC_ADVERTISED, COMP_ADVERTISED, COMP_ADVERTISED, [], []]
    for names in lists:
        parts.append(_enc_namelist(names))
    parts.append(b"\x00")
    parts.append(struct.pack(">I", 0))
    return b"".join(parts)


def _parse_kexinit(payload):
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        raise ProtocolError("expected KEXINIT")
    index = 17
    lists = []
    for _ in range(10):
        raw, index = _take_string(payload, index)
        text = raw.decode("ascii", "replace")
        lists.append([item for item in text.split(",") if item])
    return lists


def hassh_client(lists):
    """HASSH of the client KEXINIT: md5(kex;ciphers_c2s;macs_c2s;comp_c2s)."""
    kex, _hk, c_cipher, _s_cipher, c_mac, _s_mac, c_comp = lists[0], lists[1], lists[2], lists[3], lists[4], lists[5], lists[6]
    raw = ";".join([",".join(kex), ",".join(c_cipher), ",".join(c_mac), ",".join(c_comp)])
    return hashlib.md5(raw.encode()).hexdigest()


def _kex_hash_name(kex):
    if kex in ("curve25519-sha256", "curve25519-sha256@libssh.org",
               "diffie-hellman-group14-sha256"):
        return "sha256"
    if kex == "diffie-hellman-group16-sha512":
        return "sha512"
    return "sha256"


def _derive(hashname, shared_mpint, exchange, session_id, letter, size):
    out = b""
    previous = b""
    h = lambda m: hashlib.new(hashname, m).digest()
    while len(out) < size:
        if not previous:
            material = shared_mpint + exchange + letter + session_id
        else:
            material = shared_mpint + exchange + previous
        previous = h(material)
        out += previous
    return out[:size]


# ---------------------------------------------------------------------------
def serve(sock, prelude, server_version, hooks, keys=None):
    """Run one SSH-2 session on an accepted socket. The banner is already sent.

    keys is a HostKeys. For backwards compatibility a transient key is minted
    if none is supplied (tests), but the sensor always passes the persona key.
    """
    if keys is None:
        keys = HostKeys(_transient_rsa(), os.urandom(32))
    conn = PacketConn(sock, b"")
    ident = _finish_ident(conn, prelude)
    _trace("client %s" % ident)
    if not (ident.startswith("SSH-2.0-") or ident.startswith("SSH-1.99-")):
        raise ProtocolError("not an SSH-2 banner")
    if hooks.get("banner"):
        hooks["banner"](ident)

    server_kexinit = _build_kexinit()
    conn.send_packet(server_kexinit)

    client_kexinit = conn.recv_packet()
    if not client_kexinit or client_kexinit[0] != SSH_MSG_KEXINIT:
        conn.disconnect(DISC_KEY_EXCHANGE_FAILED, "no matching key exchange method found")
        raise ProtocolError("no kexinit")
    lists = _parse_kexinit(client_kexinit)
    client_kex, client_host = lists[0], lists[1]
    c_cipher, s_cipher, c_mac, s_mac, c_comp, s_comp = lists[2:8]

    if hooks.get("kexinit"):
        try:
            hooks["kexinit"]({
                "hassh": hassh_client(lists),
                "kex": client_kex, "host_key": client_host,
                "ciphers_c2s": c_cipher, "macs_c2s": c_mac, "comp_c2s": c_comp,
            })
        except Exception:
            pass

    conn.strict = "kex-strict-c-v00@openssh.com" in client_kex
    want_ext_info = "ext-info-c" in client_kex

    kex = _choose(client_kex, [k for k in KEX_ADVERTISED if k not in _PSEUDO])
    host = _choose(client_host, HOSTKEY_ADVERTISED)
    cipher_cs = _choose(c_cipher, CIPHER_ADVERTISED)
    cipher_sc = _choose(s_cipher, CIPHER_ADVERTISED)
    mac_cs = _choose(c_mac, MAC_ADVERTISED)
    mac_sc = _choose(s_mac, MAC_ADVERTISED)
    comp_cs = _choose(c_comp, ["none"])
    comp_sc = _choose(s_comp, ["none"])
    if not (kex and host and cipher_cs and cipher_sc and comp_cs and comp_sc):
        conn.disconnect(DISC_KEY_EXCHANGE_FAILED, "no matching key exchange method found")
        raise ProtocolError("no shared algorithms")
    # AEAD ciphers carry their own MAC; only aes-ctr needs a negotiated hmac.
    if cipher_cs != "chacha20-poly1305@openssh.com" and not mac_cs:
        conn.disconnect(DISC_KEY_EXCHANGE_FAILED, "no matching mac found")
        raise ProtocolError("no shared mac")
    if cipher_sc != "chacha20-poly1305@openssh.com" and not mac_sc:
        conn.disconnect(DISC_KEY_EXCHANGE_FAILED, "no matching mac found")
        raise ProtocolError("no shared mac")

    hashname = _kex_hash_name(kex)
    is_ecdh = kex.startswith("curve25519")

    init = conn.recv_packet()
    if not init or init[0] != SSH_MSG_KEXDH_INIT:
        conn.disconnect(DISC_KEY_EXCHANGE_FAILED, "expected KEXDH_INIT")
        raise ProtocolError("no dh init")

    blob = keys.blob(host)
    if is_ecdh:
        client_pub, _end = _take_string(init, 1)
        if len(client_pub) != 32:
            conn.disconnect(DISC_KEY_EXCHANGE_FAILED, "bad curve25519 client value")
            raise ProtocolError("bad qc")
        priv = os.urandom(32)
        server_pub = sshcrypto.x25519_base(priv)
        shared_raw = sshcrypto.x25519(priv, client_pub)
        shared = int.from_bytes(shared_raw, "big")
        shared_mpint = _enc_mpint(shared)
        exchange = hashlib.new(hashname, b"".join([
            _enc_string(ident), _enc_string(server_version),
            _enc_string(client_kexinit), _enc_string(server_kexinit),
            _enc_string(blob),
            _enc_string(client_pub), _enc_string(server_pub),
            shared_mpint,
        ])).digest()
        signature = keys.sign(host, exchange)
        reply = b"".join([bytes([SSH_MSG_KEXDH_REPLY]), _enc_string(blob),
                          _enc_string(server_pub), _enc_string(signature)])
    else:
        p = GROUP16_P if kex == "diffie-hellman-group16-sha512" else GROUP14_P
        e_mpint, _end = _take_string_raw(init, 1)
        e = _mpint_value(e_mpint)
        if not (1 < e < p - 1):
            conn.disconnect(DISC_KEY_EXCHANGE_FAILED, "bad DH client value")
            raise ProtocolError("bad e")
        y = int.from_bytes(os.urandom(256), "big") % (p - 3) + 2
        f = pow(2, y, p)
        shared = pow(e, y, p)
        f_mpint = _enc_mpint(f)
        shared_mpint = _enc_mpint(shared)
        exchange = hashlib.new(hashname, b"".join([
            _enc_string(ident), _enc_string(server_version),
            _enc_string(client_kexinit), _enc_string(server_kexinit),
            _enc_string(blob), e_mpint, f_mpint, shared_mpint,
        ])).digest()
        signature = keys.sign(host, exchange)
        reply = b"".join([bytes([SSH_MSG_KEXDH_REPLY]), _enc_string(blob),
                          f_mpint, _enc_string(signature)])

    conn.send_packet(reply)
    conn.send_packet(bytes([SSH_MSG_NEWKEYS]))
    if conn.strict:
        conn.send_seq = 0

    session_id = exchange

    def mk(letter, size):
        return _derive(hashname, shared_mpint, exchange, session_id, letter, size)

    # IVs: 16 for aes-ctr; chacha uses none. Keys sized per cipher (chacha=64).
    def keysize(c):
        return 64 if c == "chacha20-poly1305@openssh.com" else _CIPHER_KEYSIZE[c]

    iv_cs = mk(b"A", 16)
    iv_sc = mk(b"B", 16)
    ek_cs = mk(b"C", keysize(cipher_cs))
    ek_sc = mk(b"D", keysize(cipher_sc))
    mlen_cs = _MAC_INFO[mac_cs][1] if mac_cs and cipher_cs != "chacha20-poly1305@openssh.com" else 0
    mlen_sc = _MAC_INFO[mac_sc][1] if mac_sc and cipher_sc != "chacha20-poly1305@openssh.com" else 0
    ik_cs = mk(b"E", mlen_cs) if mlen_cs else b""
    ik_sc = mk(b"F", mlen_sc) if mlen_sc else b""

    conn.enable(conn.out, cipher_sc, mac_sc, ek_sc, iv_sc, ik_sc)

    newkeys = conn.recv_packet()
    if newkeys != bytes([SSH_MSG_NEWKEYS]):
        conn.disconnect(DISC_PROTOCOL_ERROR, "expected SSH_MSG_NEWKEYS")
        raise ProtocolError("no newkeys")
    if conn.strict:
        conn.recv_seq = 0
    conn.enable(conn.inp, cipher_cs, mac_cs, ek_cs, iv_cs, ik_cs)
    _trace("encrypted: kex=%s host=%s cipher=%s mac=%s" % (kex, host, cipher_cs, mac_cs))

    if want_ext_info:
        ext = b"".join([bytes([SSH_MSG_EXT_INFO]), struct.pack(">I", 1),
                        _enc_string(b"server-sig-algs"),
                        _enc_string(b"rsa-sha2-512,rsa-sha2-256,ssh-ed25519")])
        conn.send_packet(ext)

    if not _accept_service(conn):
        return
    if not _authenticate(conn, hooks):
        return
    _connection(conn, hooks)


def _transient_rsa():
    from . import persona
    return persona.generate_rsa(2048)


def _finish_ident(conn, prelude):
    buf = bytearray(prelude)
    while b"\n" not in buf and len(buf) < 512:
        buf.extend(conn._read(1))
    raw = bytes(buf)
    line, sep, rest = raw.partition(b"\n")
    if not sep:
        raise ProtocolError("no client banner")
    if rest:
        conn.buf[:0] = rest
    return line.decode("ascii", "replace").rstrip("\r")


def _accept_service(conn):
    while True:
        payload = conn.recv_packet()
        kind = payload[0] if payload else 0
        if kind in (SSH_MSG_IGNORE, SSH_MSG_DEBUG, SSH_MSG_EXT_INFO):
            continue
        if kind == SSH_MSG_DISCONNECT:
            return False
        if kind != SSH_MSG_SERVICE_REQUEST:
            conn.disconnect(DISC_SERVICE_NOT_AVAILABLE, "expected a service request")
            return False
        name, _index = _take_string(payload, 1)
        if name != b"ssh-userauth":
            conn.disconnect(DISC_SERVICE_NOT_AVAILABLE, "Unsupported service.")
            return False
        conn.send_packet(bytes([SSH_MSG_SERVICE_ACCEPT]) + _enc_string(name))
        return True


def _auth_failure(conn, partial=False):
    conn.send_packet(bytes([SSH_MSG_USERAUTH_FAILURE])
                     + _enc_string(b"publickey,password")
                     + (b"\x01" if partial else b"\x00"))


def _parse_pubkey(payload, index):
    """Parse a publickey userauth request tail; return (algo, keyblob_fp)."""
    try:
        has_sig = payload[index]
        index += 1
        algo, index = _take_string(payload, index)
        keyblob, index = _take_string(payload, index)
        fp = "SHA256:" + __import__("base64").b64encode(
            hashlib.sha256(keyblob).digest()).decode().rstrip("=")
        return has_sig, algo.decode("ascii", "replace"), fp
    except Exception:
        return 0, "", ""


def _authenticate(conn, hooks):
    attempts = 0
    while True:
        payload = conn.recv_packet()
        kind = payload[0] if payload else 0
        if kind in (SSH_MSG_IGNORE, SSH_MSG_DEBUG, SSH_MSG_EXT_INFO):
            continue
        if kind == SSH_MSG_DISCONNECT:
            return False
        if kind != SSH_MSG_USERAUTH_REQUEST:
            conn.disconnect(DISC_PROTOCOL_ERROR, "expected SSH_MSG_USERAUTH_REQUEST")
            return False
        index = 1
        user, index = _take_string(payload, index)
        _service, index = _take_string(payload, index)
        method, index = _take_string(payload, index)
        user_text = user.decode("utf-8", "replace")

        if method == b"password" and index < len(payload) and payload[index] == 0:
            index += 1
            password, index = _take_string(payload, index)
            pass_text = password.decode("utf-8", "replace")
            if bool(hooks["password"](user_text, pass_text)):
                conn.send_packet(bytes([SSH_MSG_USERAUTH_SUCCESS]))
                return True
            attempts += 1
            if attempts >= 6:
                conn.disconnect(DISC_NO_MORE_AUTH_METHODS, "Too many authentication failures")
                return False
            _auth_failure(conn)
            continue

        if method == b"publickey":
            has_sig, algo, fp = _parse_pubkey(payload, index)
            if hooks.get("pubkey"):
                try:
                    hooks["pubkey"](user_text, algo, fp)
                except Exception:
                    pass
            # We never accept keys; a probe (no sig) and a real attempt both fail.
            _auth_failure(conn)
            continue

        # "none" and keyboard-interactive: advertise the real methods.
        _auth_failure(conn)


def _connection(conn, hooks):
    channel = None
    while True:
        payload = conn.recv_packet()
        kind = payload[0] if payload else 0
        if kind == SSH_MSG_DISCONNECT:
            return
        if kind in (SSH_MSG_IGNORE, SSH_MSG_DEBUG):
            continue
        if kind == SSH_MSG_KEXINIT:
            conn.disconnect(DISC_BY_APPLICATION, "rekeying not supported")
            return
        if kind == SSH_MSG_GLOBAL_REQUEST:
            _global_request(conn, payload)
            continue
        if kind == SSH_MSG_CHANNEL_OPEN:
            channel = _channel_open(conn, payload, channel)
            continue
        if channel is None:
            conn.disconnect(DISC_PROTOCOL_ERROR, "no channel")
            return
        if kind == SSH_MSG_CHANNEL_WINDOW_ADJUST:
            _window_adjust(channel, payload)
            continue
        if kind == SSH_MSG_CHANNEL_DATA:
            if _channel_data(conn, channel, payload, hooks):
                return
            continue
        if kind == SSH_MSG_CHANNEL_REQUEST:
            if _channel_request(conn, channel, payload, hooks):
                return
            continue
        if kind == SSH_MSG_CHANNEL_EOF:
            continue
        if kind == SSH_MSG_CHANNEL_CLOSE:
            # Mark closed but keep the connection up so a subsequent
            # session channel (another exec_command) can open.
            if channel is not None:
                channel["closed"] = True
            channel = None
            continue
        conn.unimplemented((conn.recv_seq - 1) & 0xFFFFFFFF)


def _global_request(conn, payload):
    index = 1
    _name, index = _take_string(payload, index)
    want = payload[index] if index < len(payload) else 0
    if want:
        conn.send_packet(bytes([SSH_MSG_REQUEST_FAILURE]))


def _channel_open(conn, payload, existing):
    index = 1
    ctype, index = _take_string(payload, index)
    sender, index = _take_uint32(payload, index)
    window, index = _take_uint32(payload, index)
    _max_packet, index = _take_uint32(payload, index)
    # Real OpenSSH allows multiple sequential session channels on one
    # connection (paramiko opens a new one per exec_command). Refuse only
    # non-session types and concurrent unclosed sessions.
    if ctype != b"session" or (existing is not None and not existing.get("closed")):
        conn.send_packet(bytes([SSH_MSG_CHANNEL_OPEN_FAILURE])
                         + struct.pack(">II", sender, 1)
                         + _enc_string(b"open failed") + _enc_string(b""))
        return existing
    channel = {"peer": sender, "send_window": window, "recv_left": 1024 * 1024,
               "pty": False, "shell": False, "buf": "", "closed": False}
    conn.send_packet(bytes([SSH_MSG_CHANNEL_OPEN_CONFIRMATION])
                     + struct.pack(">IIII", sender, 0, 1024 * 1024, 32768))
    return channel


def _window_adjust(channel, payload):
    _recipient, index = _take_uint32(payload, 1)
    extra, index = _take_uint32(payload, index)
    channel["send_window"] += extra


def _reply(conn, channel, want, ok):
    if not want:
        return
    kind = SSH_MSG_CHANNEL_SUCCESS if ok else SSH_MSG_CHANNEL_FAILURE
    conn.send_packet(bytes([kind]) + struct.pack(">I", channel["peer"]))


def _channel_request(conn, channel, payload, hooks):
    index = 1
    _recipient, index = _take_uint32(payload, index)
    name, index = _take_string(payload, index)
    want = payload[index] if index < len(payload) else 0
    index += 1
    if name == b"pty-req":
        channel["pty"] = True
        _reply(conn, channel, want, True)
        return False
    if name in (b"env", b"window-change", b"signal"):
        _reply(conn, channel, want, True)
        return False
    if name in (b"auth-agent-req@openssh.com", b"x11-req", b"subsystem"):
        _reply(conn, channel, want, False)
        return False
    if name == b"exec":
        command, _index = _take_string(payload, index)
        _reply(conn, channel, want, True)
        text = ""
        if hooks.get("exec"):
            text = hooks["exec"](command.decode("utf-8", "replace")) or ""
        _send_text(conn, channel, text, pty=False)
        _close_channel(conn, channel, 0)
        return False
    if name == b"shell":
        channel["shell"] = True
        _reply(conn, channel, want, True)
        greeting = ""
        if hooks.get("greeting"):
            greeting = hooks["greeting"]() or ""
        if greeting and not greeting.endswith("\n"):
            greeting += "\n"
        prompt = hooks["prompt"]() if hooks.get("prompt") else "$ "
        _send_text(conn, channel, greeting + prompt, pty=channel["pty"])
        return False
    _reply(conn, channel, want, False)
    return False


def _channel_data(conn, channel, payload, hooks):
    index = 1
    _recipient, index = _take_uint32(payload, index)
    data, index = _take_string(payload, index)
    channel["recv_left"] -= len(data)
    if channel["recv_left"] < 32768:
        extra = 1024 * 1024
        conn.send_packet(bytes([SSH_MSG_CHANNEL_WINDOW_ADJUST])
                         + struct.pack(">II", channel["peer"], extra))
        channel["recv_left"] += extra
    if channel.get("closed"):
        return False
    if channel["pty"]:
        return _feed_pty(conn, channel, data, hooks)
    channel["buf"] += data.decode("latin-1", "replace").replace("\r", "")
    while "\n" in channel["buf"]:
        line, channel["buf"] = channel["buf"].split("\n", 1)
        if _run_line(conn, channel, line, hooks):
            return False
    return False


def _feed_pty(conn, channel, data, hooks):
    echo = bytearray()
    for byte in data:
        if byte in (10, 13):
            echo.extend(b"\r\n")
            line = channel["buf"]
            channel["buf"] = ""
            _send_bytes(conn, channel, bytes(echo))
            echo = bytearray()
            if _run_line(conn, channel, line, hooks):
                return False
        elif byte in (8, 127):
            if channel["buf"]:
                channel["buf"] = channel["buf"][:-1]
                echo.extend(b"\b \b")
        elif byte == 3:
            channel["buf"] = ""
            echo.extend(b"^C\r\n")
            prompt = hooks["prompt"]() if hooks.get("prompt") else "$ "
            echo.extend(_as_pty(prompt))
        elif byte == 4 and not channel["buf"]:
            _send_bytes(conn, channel, bytes(echo))
            _close_channel(conn, channel, 0)
            return False
        elif byte == 21:
            channel["buf"] = ""
            echo.extend(b"\r")
            prompt = hooks["prompt"]() if hooks.get("prompt") else "$ "
            echo.extend(_as_pty(prompt))
        elif byte >= 32:
            if len(channel["buf"]) < 4096:
                channel["buf"] += chr(byte)
                echo.append(byte)
    if echo:
        _send_bytes(conn, channel, bytes(echo))
    return False


def _run_line(conn, channel, line, hooks):
    reply, done = "", False
    if hooks.get("line"):
        result = hooks["line"](line)
        if result:
            reply, done = result
    text = ""
    if reply:
        text = reply if str(reply).endswith("\n") else str(reply) + "\n"
    if done:
        if text:
            _send_text(conn, channel, text, pty=channel["pty"])
        _close_channel(conn, channel, 0)
        return True
    prompt = hooks["prompt"]() if hooks.get("prompt") else "$ "
    _send_text(conn, channel, text + prompt, pty=channel["pty"])
    return False


def _as_pty(text):
    return text.replace("\r\n", "\n").replace("\n", "\r\n").encode("latin-1", "replace")


def _send_text(conn, channel, text, pty):
    if not text:
        return
    if isinstance(text, bytes):
        data = text
    elif pty:
        data = _as_pty(text)
    else:
        data = text.encode("latin-1", "replace")
    _send_bytes(conn, channel, data)


def _send_bytes(conn, channel, data):
    while data:
        space = channel["send_window"]
        if space <= 0:
            conn.sock.settimeout(2.0)
            try:
                extra = conn.recv_packet()
            except (socket.timeout, OSError, ProtocolError, EOFError):
                return
            if extra and extra[0] == SSH_MSG_CHANNEL_WINDOW_ADJUST:
                _window_adjust(channel, extra)
            continue
        take = min(len(data), space, 16384)
        chunk = data[:take]
        data = data[take:]
        conn.send_packet(bytes([SSH_MSG_CHANNEL_DATA])
                         + struct.pack(">I", channel["peer"]) + _enc_string(chunk))
        channel["send_window"] -= len(chunk)


def _close_channel(conn, channel, status):
    if channel.get("closed"):
        return
    channel["closed"] = True
    conn.send_packet(bytes([SSH_MSG_CHANNEL_REQUEST]) + struct.pack(">I", channel["peer"])
                     + _enc_string(b"exit-status") + b"\x00"
                     + struct.pack(">I", status & 0xFFFFFFFF))
    conn.send_packet(bytes([SSH_MSG_CHANNEL_EOF]) + struct.pack(">I", channel["peer"]))
    conn.send_packet(bytes([SSH_MSG_CHANNEL_CLOSE]) + struct.pack(">I", channel["peer"]))


# ---------------------------------------------------------------------------
def crypto_self_test():
    """Run the primitive self-tests plus a group-prime sanity check."""
    sshcrypto.self_test()
    if GROUP14_P.bit_length() != 2048:
        raise AssertionError("group14 prime size")
    if GROUP16_P.bit_length() != 4096:
        raise AssertionError("group16 prime size")
    if _enc_mpint(0) != b"\x00\x00\x00\x00":
        raise AssertionError("mpint 0")
    if _enc_mpint(0x80) != b"\x00\x00\x00\x02\x00\x80":
        raise AssertionError("mpint high bit")
    return True
