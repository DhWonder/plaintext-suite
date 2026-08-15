"""
Canary tokens: bait that tells on whoever takes it.

A canary token is a secret that has no real use except to be stolen. You plant
it somewhere a legitimate person would never look, wrapped up to look valuable,
and you wait. The day it is used, it calls home, and now you know somebody who
should not have it does.

This is the honest, legal way to follow an attacker. You never reach into their
machine. You leave something they choose to take, and it is the token that
phones you, not you that phones them. That distinction is the whole thing.

Each token is:

  - an id, unique to one bait item on one sensor
  - a beacon: a web address, a hostname, or a fake key that carries the id, so
    that when the attacker's own tooling touches it the id comes back to your
    console and you know which piece of bait was triggered, and from where

Nothing here needs anything installed.
"""

import hashlib
import os
import struct
import time

# The alphabet for token ids: lowercase and digits, no vowels, so a token can
# never accidentally spell something and can be read aloud over the phone.
ALPHABET = "bcdfghjkmnpqrstvwxz23456789"


def _random_bytes(n):
    """Real randomness. os.urandom is right for anything a token depends on."""
    return os.urandom(n)


def new_id(length=10):
    """A short, unguessable id for one token."""
    raw = _random_bytes(length)
    return "".join(ALPHABET[b % len(ALPHABET)] for b in raw)


def make(kind, label, console_host="", sensor=""):
    """Mint one token.

    `kind` is what shape the bait takes, so the beacon looks native to the file
    it will live in. `console_host` is where triggers should report; leave it
    empty and the token still works as a tripwire you match against your own
    logs, it just cannot phone home on its own.
    """
    token_id = new_id()
    beacon_host = _beacon_host(token_id, console_host)
    token = {
        "id": token_id,
        "kind": kind,
        "label": label,
        "sensor": sensor,
        "created": time.time(),
        "beacon_host": beacon_host,
        "beacon_url": ("http://%s/t/%s" % (console_host, token_id)) if console_host else "",
    }
    token["value"] = _shape(kind, token_id, token)
    return token


def _beacon_host(token_id, console_host):
    """A hostname carrying the token id.

    If a document or a config carrying this ends up somewhere that resolves
    hostnames, the lookup itself is the beacon. When there is a console its own
    name is used so the lookup reaches you; without one, a placeholder that is
    still unique per token so you can grep for it.
    """
    if console_host:
        base = console_host.split(":", 1)[0]
        return "%s.%s" % (token_id, base)
    return "%s.canary.invalid" % token_id


def _shape(kind, token_id, token):
    """Dress the token id up as the kind of secret it is pretending to be.

    The id is always recoverable from the value, because that is what lets the
    console say which token fired. The rest is camouflage.
    """
    if kind == "aws":
        # Looks like an AWS access key pair. The access key id starts AKIA the
        # way real ones do; the secret carries the token id so a trigger names
        # this exact key. A real AWS canary needs registering with a service
        # that watches for its use, which the README explains; on its own this
        # is a tripwire you match against CloudTrail.
        suffix = _upper36(token_id, 12)
        access = "AKIA" + _upper36(token_id + "a", 16)
        secret = _mixed(token_id + "s", 40)
        return {"access_key_id": access, "secret_access_key": secret, "marker": suffix}

    if kind == "url":
        return token.get("beacon_url") or ("http://%s/" % token["beacon_host"])

    if kind == "password":
        # A believable strong password with the id woven in.
        return "Wtr#%s!29" % token_id[:6].capitalize()

    if kind == "hostname":
        return token["beacon_host"]

    if kind == "connstring":
        # A database connection string, the sort found in a config file.
        return "postgres://svc_reports:%s@db-prod-01.internal:5432/customers" % token_id[:12]

    return token_id


def _upper36(seed, length):
    digest = hashlib.sha256(seed.encode()).hexdigest().upper()
    table = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    out = []
    for i in range(length):
        out.append(table[int(digest[i * 2:i * 2 + 2], 16) % len(table)])
    return "".join(out)


def _mixed(seed, length):
    digest = hashlib.sha256(seed.encode()).digest()
    table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    out = []
    for i in range(length):
        out.append(table[digest[i % len(digest)] % len(table)])
    return "".join(out)


def find_ids(text, known_ids):
    """Which known token ids appear in a piece of text.

    Used by the console when a beacon or a report comes in, to work out which
    planted token was involved.
    """
    hits = []
    for token_id in known_ids:
        if token_id and token_id in text:
            hits.append(token_id)
    return hits
