"""
Per-deployment identity for a anglerfish sensor.

Two installs of this honeypot should not be twins. If every copy shipped the
same SSH host key, the same self-signed TLS certificate, the same hostname and
the same uptime, one Shodan search for that fingerprint would find every
anglerfish on the internet at once. So the first time a sensor runs it mints
an identity and saves it; every run after that reuses it, the way a real server
keeps the host keys and the machine-id it was installed with.

Identity strings (hostname, company, domain, NAS model, banners, bait names)
come from the operator's persona YAML (config.py), never from source.

What is minted and persisted (under ~/.anglerfish/persona.json plus key files):

  - FQDN, internal IP, MAC, and the planted login passwords (random per install)
  - an uptime seed (a believable boot time in the past) so `uptime`/`w` are
    stable across restarts instead of resetting to "47 days" every launch
  - an Ed25519 host key and a 3072-bit RSA host key, generated here, never shipped in
    source (that was the old tell: one hard-coded key shared by every copy)
  - a self-signed TLS certificate + key for the HTTPS/SMTPS ports
  - a shared token the sensor presents to its console, so /api/report and
    /api/register cannot be forged by anyone who finds the console
  - a stable canary seed so planted tokens persist across restarts instead of
    regenerating (a token that changes every boot is useless for attribution)

Nothing here reaches the network. Key generation is local arithmetic; the TLS
cert is produced with the system `openssl` when present, and skipped (ports
fall back to plaintext, with a note) when it is not.
"""

import json
import os
import random
import socket
import subprocess
import time

from . import sshcrypto

DEFAULT_DIR = os.path.expanduser("~/.anglerfish")

# Fallback identity when no persona file is configured. Deliberately fictional
# (example.net is reserved by RFC 2606) and loudly warned about at start-up:
# never run a public sensor on the example persona, everyone can read it here.
EXAMPLE_PERSONA = {
    "hostname": "files01",
    "company": "Example Clinic",
    "domain": "example.net",
    "nas_model": "DS220+",
    "nas_firmware": "7.2.1-69057",
}

# Word pool for minted planted passwords: careless-admin style, but random per
# install so the repo never contains a password that opens any sensor.
_PW_WORDS = (
    "Winter", "Summer", "Autumn", "Spring", "Harbor", "Falcon", "Copper", "Maple",
    "Orchid", "Granite", "Velvet", "Cobalt", "Juniper", "Saffron", "Willow", "Ember",
    "Summit", "Lantern", "Beacon", "Meadow", "Cedar", "Quartz", "Thistle", "Raven",
    "Admin", "Welcome", "Office", "Backup", "Storage", "Staging", "Nas", "Files",
)


def mint_password(brand="", rng=None):
    """A believable weak-but-not-wordlist password, random per install."""
    import secrets
    choice = (rng.choice if rng else secrets.choice)
    pick = (lambda n: rng.randrange(n)) if rng else secrets.randbelow
    word = choice(_PW_WORDS)
    digits = "%02d" % (10 + pick(90))
    sym = choice("!#$@*")
    base = brand or choice(_PW_WORDS)
    pattern = pick(4)
    if pattern == 0:
        return "%s%s%s%s" % (base, word, digits, sym)
    if pattern == 1:
        return "%s%s%s" % (word, digits, sym) + base[:3].lower()
    if pattern == 2:
        return "%s@%s%s" % (base, word.lower(), digits)
    return "%s%s%s%s" % (word, sym, base, digits)


def mint_logins(spec, brand=""):
    """Resolve planted_logins_spec (password 'auto' -> minted) into [[user, pw], ...]."""
    spec = spec or [{"user": "deploy", "password": "auto"},
                    {"user": "admin", "password": "auto"}]
    out = []
    for row in spec:
        pw = row.get("password") or "auto"
        if pw == "auto":
            pw = mint_password(brand)
        out.append([row["user"], pw])
    return out


def _rand_mac():
    # Locally-administered, unicast; AWS-style 06:xx is believable for EC2 ENIs.
    return "06:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))


# ---------------------------------------------------------------------------
# RSA keygen, pure Python. Done once per install, then persisted.
# ---------------------------------------------------------------------------
def _is_probable_prime(n, rounds=24):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits):
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def generate_rsa(bits=2048):
    e = 65537
    half = bits // 2
    while True:
        p = _gen_prime(half)
        q = _gen_prime(bits - half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        d = pow(e, -1, phi)
        if n.bit_length() == bits:
            return {"n": n, "e": e, "d": d, "p": p, "q": q}


# ---------------------------------------------------------------------------
def _seed_random(path_salt):
    # Seed the persona RNG from real entropy; persona is saved so this only
    # matters for the one-time mint.
    random.seed(os.urandom(32) + path_salt.encode("utf-8", "replace"))


def load_or_create(directory=DEFAULT_DIR, console_host="", note=None, config_path=""):
    """Return the persona dict, creating and saving it on first run.

    Identity (company, hostname, domain, NAS model, banners, bait names) comes
    from the operator's persona YAML (see config.py). Secrets are minted here
    once and persisted: host keys, TLS cert, planted passwords, console token,
    canary seed. Delete the state directory to re-mint.
    """
    from . import config as config_module
    if not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "persona.json")
    cfg_path = config_module.find(config_path, state_dir=directory)
    cfg = config_module.flatten(config_module.load(cfg_path)) if cfg_path else {}
    if not cfg_path and note:
        note("WARNING: no persona file found - running the public EXAMPLE persona. "
             "Copy config/persona.example.yaml to config/persona.yaml and edit it "
             "before exposing this sensor.")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if data.get("version") == 3 and data.get("rsa") and data.get("ed25519_seed"):
                data["_dir"] = directory
                data["_config"] = cfg_path
                return data
        except (OSError, ValueError):
            pass

    _seed_random(directory)
    base = dict(EXAMPLE_PERSONA)
    base.update({k: v for k, v in cfg.items() if k != "planted_logins_spec"})
    octet = random.randint(10, 240)
    now = time.time()
    # A believable boot time: 8-420 days ago.
    boot = now - random.randint(8, 420) * 86400 - random.randint(0, 86400)
    if note:
        note("minting a new persona (first run) - generating host keys, this takes a moment")
    rsa = generate_rsa(3072)
    ed_seed = os.urandom(32)
    hostname = base["hostname"]
    domain = base["domain"]
    brand = "".join(ch for ch in (base["company"].split() or ["Files"])[0] if ch.isalnum())
    data = dict(base)
    data.update({
        "version": 3,
        "fqdn": "%s.%s" % (hostname, domain),
        "internal_ip": base.get("internal_ip") or "10.0.%d.%d" % (random.randint(0, 40), octet),
        "public_ip_hint": "",
        "mac": _rand_mac(),
        "boot_time": boot,
        "planted_logins": mint_logins(cfg.get("planted_logins_spec"), brand),
        "console_token": sshcrypto.ed25519_public(os.urandom(32)).hex()[:40],
        "canary_seed": os.urandom(16).hex(),
        "ed25519_seed": ed_seed.hex(),
        "rsa": {"n": hex(rsa["n"]), "e": rsa["e"], "d": hex(rsa["d"])},
    })
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    _ensure_tls(directory, data, note=note)
    data["_dir"] = directory
    data["_config"] = cfg_path
    return data


def _ensure_tls(directory, data, note=None):
    """Generate a self-signed TLS cert+key with the system openssl, if present."""
    cert = os.path.join(directory, "tls-cert.pem")
    key = os.path.join(directory, "tls-key.pem")
    if os.path.exists(cert) and os.path.exists(key):
        return cert, key
    subj = "/O=%s/CN=%s" % (data["company"], data["fqdn"])
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", cert, "-days", "825", "-subj", subj,
             "-addext", "subjectAltName=DNS:%s,DNS:%s" % (data["fqdn"], data["hostname"])],
            check=True, capture_output=True, timeout=60)
        os.chmod(key, 0o600)
        if note:
            note("generated self-signed TLS cert for %s" % data["fqdn"])
        return cert, key
    except (OSError, subprocess.SubprocessError):
        if note:
            note("openssl not available; TLS ports will fall back to plaintext")
        return "", ""


def tls_paths(directory=DEFAULT_DIR):
    cert = os.path.join(directory, "tls-cert.pem")
    key = os.path.join(directory, "tls-key.pem")
    if os.path.exists(cert) and os.path.exists(key):
        return cert, key
    return "", ""


def rsa_tuple(data):
    r = data["rsa"]
    return {"n": int(r["n"], 16), "e": int(r["e"]) if isinstance(r["e"], int) else int(r["e"], 10),
            "d": int(r["d"], 16)}


def ed25519_seed(data):
    return bytes.fromhex(data["ed25519_seed"])


def uptime_fields(data, now=None):
    """Return (days, pretty) for `uptime`, derived from the persisted boot time."""
    now = now or time.time()
    secs = max(60, now - data.get("boot_time", now - 86400))
    days = int(secs // 86400)
    rem = int(secs % 86400)
    hours = rem // 3600
    mins = (rem % 3600) // 60
    if days:
        pretty = "%d days, %d:%02d" % (days, hours, mins)
    else:
        pretty = "%d:%02d" % (hours, mins)
    return days, pretty
