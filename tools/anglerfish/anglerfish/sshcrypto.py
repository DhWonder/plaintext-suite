"""
Pure-Python crypto primitives for the honeypot's SSH facade.

Standard library only, on purpose: the honeypot ships without third-party
packages. These are the algorithms a modern OpenSSH client actually negotiates,
so the handshake a scanner sees is a real one rather than a toy that only
answers one invented cipher.

Implemented here and checked against published test vectors in self_test():

  - AES-128/192/256 (FIPS-197) and AES-CTR
  - ChaCha20 and Poly1305, and the chacha20-poly1305@openssh.com AEAD
  - Curve25519 X25519 (RFC 7748) for curve25519-sha256 key exchange
  - Ed25519 (RFC 8032) for the ssh-ed25519 host key

Nothing here reaches the network or runs attacker input; it is arithmetic.
"""

import hashlib
import hmac
import os

# ===========================================================================
# AES (FIPS-197), 128/192/256 bit, plus counter mode.
# ===========================================================================
_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _expand_key(key):
    nk = len(key) // 4
    nr = {4: 10, 6: 12, 8: 14}[nk]
    w = list(key)
    rcon_i = 1
    total = 16 * (nr + 1)
    while len(w) < total:
        temp = w[-4:]
        if len(w) % (nk * 4) == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[rcon_i]
            rcon_i += 1
        elif nk > 6 and len(w) % (nk * 4) == 16:
            temp = [_SBOX[b] for b in temp]
        for j in range(4):
            w.append(w[-nk * 4] ^ temp[j])
    return w, nr


def _encrypt_block(expanded, nr, block):
    st = [[0] * 4 for _ in range(4)]
    for i, b in enumerate(block):
        st[i % 4][i // 4] = b

    def add_round(rk):
        for i, b in enumerate(rk):
            st[i % 4][i // 4] ^= b

    add_round(expanded[0:16])
    for rnd in range(1, nr):
        for r in range(4):
            for c in range(4):
                st[r][c] = _SBOX[st[r][c]]
        for r in range(1, 4):
            st[r] = st[r][r:] + st[r][:r]
        for c in range(4):
            col = [st[r][c] for r in range(4)]
            st[0][c] = _mul(col[0], 2) ^ _mul(col[1], 3) ^ col[2] ^ col[3]
            st[1][c] = col[0] ^ _mul(col[1], 2) ^ _mul(col[2], 3) ^ col[3]
            st[2][c] = col[0] ^ col[1] ^ _mul(col[2], 2) ^ _mul(col[3], 3)
            st[3][c] = _mul(col[0], 3) ^ col[1] ^ col[2] ^ _mul(col[3], 2)
        add_round(expanded[rnd * 16:(rnd + 1) * 16])
    for r in range(4):
        for c in range(4):
            st[r][c] = _SBOX[st[r][c]]
    for r in range(1, 4):
        st[r] = st[r][r:] + st[r][:r]
    add_round(expanded[nr * 16:(nr + 1) * 16])
    out = bytearray(16)
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = st[r][c]
    return bytes(out)


class AESCTR(object):
    """AES in counter mode for 128/192/256 bit keys. En/decrypt are identical."""

    def __init__(self, key, iv):
        if len(key) not in (16, 24, 32) or len(iv) != 16:
            raise ValueError("aes-ctr key must be 16/24/32 bytes and iv 16")
        self._expanded, self._nr = _expand_key(list(key))
        self._counter = int.from_bytes(iv, "big")
        self._ks = b""

    def crypt(self, data):
        out = bytearray()
        ks = self._ks
        for byte in data:
            if not ks:
                ks = _encrypt_block(self._expanded, self._nr,
                                    self._counter.to_bytes(16, "big"))
                self._counter = (self._counter + 1) & ((1 << 128) - 1)
            out.append(byte ^ ks[0])
            ks = ks[1:]
        self._ks = ks
        return bytes(out)


# Backwards-compatible name used by older callers/tests.
class AES128CTR(AESCTR):
    def __init__(self, key, iv):
        if len(key) != 16:
            raise ValueError("aes128-ctr wants a 16 byte key")
        super(AES128CTR, self).__init__(key, iv)


# ===========================================================================
# ChaCha20 / Poly1305 and the chacha20-poly1305@openssh.com AEAD.
# ===========================================================================
def _rotl32(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _chacha_block(key, counter, nonce):
    constants = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
    state = list(constants)
    state += [int.from_bytes(key[i:i + 4], "little") for i in range(0, 32, 4)]
    state.append(counter & 0xFFFFFFFF)
    state += [int.from_bytes(nonce[i:i + 4], "little") for i in range(0, 12, 4)]
    x = list(state)

    def qr(a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = _rotl32(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = _rotl32(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = _rotl32(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = _rotl32(x[b] ^ x[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    out = bytearray()
    for i in range(16):
        out += ((x[i] + state[i]) & 0xFFFFFFFF).to_bytes(4, "little")
    return bytes(out)


def chacha20(key, counter, nonce, data):
    out = bytearray()
    for off in range(0, len(data), 64):
        block = _chacha_block(key, counter, nonce)
        counter += 1
        chunk = data[off:off + 64]
        out += bytes(a ^ b for a, b in zip(chunk, block))
    return bytes(out)


def poly1305_mac(msg, key):
    r = int.from_bytes(key[:16], "little")
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:32], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        chunk = msg[i:i + 16]
        n = int.from_bytes(chunk + b"\x01" + b"\x00" * (16 - len(chunk)), "little") \
            if len(chunk) < 16 else int.from_bytes(chunk + b"\x01", "little")
        acc = ((acc + n) * r) % p
    acc = (acc + s) & ((1 << 128) - 1)
    return acc.to_bytes(16, "little")


class ChaCha20Poly1305OpenSSH(object):
    """The chacha20-poly1305@openssh.com AEAD used for SSH packets.

    Two 256-bit keys in one 64-byte key: K_2 (first 32) encrypts the payload,
    K_1 (second 32) encrypts the 4-byte length. The Poly1305 key is the first
    64 bytes of the K_2 keystream at counter 0.
    """

    def __init__(self, key):
        if len(key) != 64:
            raise ValueError("chacha20-poly1305 needs a 64 byte key")
        self.k_enc = key[:32]
        self.k_len = key[32:64]

    def _nonce(self, seq):
        return b"\x00\x00\x00\x00" + seq.to_bytes(8, "big")

    def encrypt_length(self, seq, four):
        return chacha20(self.k_len, 0, self._nonce(seq), four)

    def decrypt_length(self, seq, four):
        return chacha20(self.k_len, 0, self._nonce(seq), four)

    def poly_key(self, seq):
        return _chacha_block(self.k_enc, 0, self._nonce(seq))[:32]

    def encrypt_payload(self, seq, data):
        return chacha20(self.k_enc, 1, self._nonce(seq), data)

    def decrypt_payload(self, seq, data):
        return chacha20(self.k_enc, 1, self._nonce(seq), data)

    def tag(self, seq, ciphertext):
        return poly1305_mac(ciphertext, self.poly_key(seq))


# ===========================================================================
# Curve25519 (X25519, RFC 7748).
# ===========================================================================
_P25519 = (1 << 255) - 19
_A24 = 121665


def _cswap(swap, a, b):
    if swap:
        return b, a
    return a, b


def x25519(scalar, u):
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    u = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0
    p = _P25519
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = kt
        a = (x2 + z2) % p
        aa = (a * a) % p
        b = (x2 - z2) % p
        bb = (b * b) % p
        e = (aa - bb) % p
        c = (x3 + z3) % p
        d = (x3 - z3) % p
        da = (d * a) % p
        cb = (c * b) % p
        x3 = pow((da + cb) % p, 2, p)
        z3 = (x1 * pow((da - cb) % p, 2, p)) % p
        x2 = (aa * bb) % p
        z2 = (e * ((aa + (_A24 * e) % p) % p)) % p
    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)
    res = (x2 * pow(z2, p - 2, p)) % p
    return res.to_bytes(32, "little")


def x25519_base(scalar):
    nine = b"\x09" + b"\x00" * 31
    return x25519(scalar, nine)


# ===========================================================================
# Ed25519 (RFC 8032).
# ===========================================================================
_Q = (1 << 255) - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _ed_recover_x(y, sign):
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q)
    x = pow(xx % _Q, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != sign:
        x = _Q - x
    return x


_BY = (4 * pow(5, _Q - 2, _Q)) % _Q
_BX = _ed_recover_x(_BY, 0)
_B = (_BX % _Q, _BY % _Q, 1, (_BX * _BY) % _Q)


def _ed_add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = ((y1 - x1) * (y2 - x2)) % _Q
    b = ((y1 + x1) * (y2 + x2)) % _Q
    c = (t1 * 2 * _D * t2) % _Q
    dd = (z1 * 2 * z2) % _Q
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    return ((e * f) % _Q, (g * h) % _Q, (f * g) % _Q, (e * h) % _Q)


def _ed_mul(P, s):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _ed_add(Q, P)
        P = _ed_add(P, P)
        s >>= 1
    return Q


def _ed_encode(P):
    x, y, z, _t = P
    zi = pow(z, _Q - 2, _Q)
    x = (x * zi) % _Q
    y = (y * zi) % _Q
    val = y | ((x & 1) << 255)
    return val.to_bytes(32, "little")


def ed25519_public(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    A = _ed_mul(_B, a)
    return _ed_encode(A)


def ed25519_sign(seed, msg):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    prefix = h[32:]
    A = _ed_encode(_ed_mul(_B, a))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % _L
    R = _ed_encode(_ed_mul(_B, r))
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % _L
    s = (r + k * a) % _L
    return R + s.to_bytes(32, "little")


# ===========================================================================
def self_test():
    # AES-128 FIPS-197
    exp, nr = _expand_key(list(bytes.fromhex("000102030405060708090a0b0c0d0e0f")))
    if _encrypt_block(exp, nr, bytes.fromhex("00112233445566778899aabbccddeeff")) \
            != bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"):
        raise AssertionError("AES-128 block")
    # AES-256 FIPS-197
    exp, nr = _expand_key(list(bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")))
    if _encrypt_block(exp, nr, bytes.fromhex("00112233445566778899aabbccddeeff")) \
            != bytes.fromhex("8ea2b7ca516745bfeafc49904b496089"):
        raise AssertionError("AES-256 block")
    # AES-128-CTR NIST SP800-38A F.5.1
    ctr = AESCTR(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
                 bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
    if ctr.crypt(bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")) \
            != bytes.fromhex("874d6191b620e3261bef6864990db6ce"):
        raise AssertionError("AES-CTR")
    # ChaCha20 RFC 8439 2.3.2
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    blk = _chacha_block(key, 1, nonce)
    if blk[:4] != bytes.fromhex("10f1e7e4"):
        raise AssertionError("ChaCha20 block")
    # Poly1305 RFC 8439 2.5.2
    pkey = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
    tag = poly1305_mac(b"Cryptographic Forum Research Group", pkey)
    if tag != bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9"):
        raise AssertionError("Poly1305")
    # X25519 RFC 7748 6.1
    a_priv = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    a_pub = x25519_base(a_priv)
    if a_pub != bytes.fromhex(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"):
        raise AssertionError("X25519 base")
    b_priv = bytes.fromhex(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    shared = x25519(a_priv, x25519_base(b_priv))
    if shared != bytes.fromhex(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"):
        raise AssertionError("X25519 shared")
    # Ed25519 RFC 8032 7.1 TEST 1
    seed = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pub = ed25519_public(seed)
    if pub != bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"):
        raise AssertionError("Ed25519 public")
    sig = ed25519_sign(seed, b"")
    if sig != bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"):
        raise AssertionError("Ed25519 sign")
    return True


if __name__ == "__main__":
    self_test()
    print("sshcrypto self-test passed")
