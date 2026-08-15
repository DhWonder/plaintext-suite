"""
How strong a password is, and whether it has already been stolen.

Two questions that sound the same and are not. A password can be long,
unusual and excellent, and still be worthless because it appeared in a breach
five years ago and sits in every attacker's list. So this answers both:

  - how long would guessing it take, and why
  - has it already been published

The strength half runs entirely offline. The breach half uses a method that
means your password never leaves this computer, explained where it happens.
"""

import hashlib
import re
import urllib.error
import urllib.request

PWNED_API = "https://api.pwnedpasswords.com/range/"
TIMEOUT = 10

COMMON = {
    "password", "123456", "123456789", "qwerty", "abc123", "111111",
    "12345678", "password1", "123123", "admin", "letmein", "welcome",
    "monkey", "dragon", "iloveyou", "sunshine", "princess", "football",
    "qwerty123", "1q2w3e4r", "000000", "aa123456", "password123",
    "qwertyuiop", "superman", "trustno1", "changeme",
}

KEYBOARD_RUNS = ["qwerty", "asdf", "zxcv", "1234", "12345", "qazwsx", "0987"]


def char_pool(password):
    """How many different characters an attacker must consider per position.
    Using more kinds of character (lower, UPPER, digits, symbols) enlarges
    this pool and makes guessing dramatically slower."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 33  # rough count of common keyboard symbols
    return pool


def human_time(seconds):
    """Turn a raw number of seconds into a phrase a person feels."""
    if seconds < 1:
        return "less than a second"
    units = [
        ("years", 365 * 24 * 3600),
        ("days", 24 * 3600),
        ("hours", 3600),
        ("minutes", 60),
        ("seconds", 1),
    ]
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            if name == "years" and value > 1000:
                if value > 1e9:
                    return "longer than the age of the universe"
                return "thousands of years or more"
            return "about %s %s" % (_round_nice(value), name)
    return "less than a second"


def _round_nice(value):
    if value >= 100:
        return str(int(round(value, -1)))
    if value >= 10:
        return str(int(value))
    return "%.1f" % value


def analyse(password):
    notes = []          # things worth telling the user
    good = []           # things they did right
    verdict_penalty = 0 # higher = weaker

    length = len(password)

    # 1. The single biggest factor: length.
    if length < 8:
        notes.append("It's very short (%d characters). Length matters more than "
                     "anything else - short passwords fall in seconds no matter "
                     "how clever they look." % length)
        verdict_penalty += 3
    elif length < 12:
        notes.append("It's on the short side (%d characters). Aim for at least "
                     "12, ideally more." % length)
        verdict_penalty += 1
    else:
        good.append("It's a good length (%d characters) - the most important thing." % length)

    # 2. Is it simply a known password?
    lowered = password.lower()
    if lowered in COMMON:
        notes.append("This is one of the most common passwords in the world. "
                     "It would be tried in the first breath of any attack.")
        verdict_penalty += 5

    # 3. Is it a word with predictable decorations? (Word + digits + !)
    stripped = re.sub(r"[0-9!@#$%^&*.]+$", "", lowered)
    stripped = re.sub(r"^[0-9]+", "", stripped)
    word_based = bool(stripped and stripped.isalpha() and stripped in COMMON)
    if word_based:
        notes.append("Underneath the numbers and symbols it's still a common word. "
                     "Attackers try 'word + 123 + !' automatically - the decorations "
                     "barely slow them down.")
        verdict_penalty += 3

    # 4. Keyboard runs and pure repetition.
    for run in KEYBOARD_RUNS:
        if run in lowered:
            notes.append("It contains the keyboard pattern '%s', which guessing "
                         "tools know by heart." % run)
            verdict_penalty += 2
            break
    if length > 0 and len(set(password)) <= max(2, length // 4):
        notes.append("It repeats the same few characters, which adds far less "
                     "strength than it appears to.")
        verdict_penalty += 2

    # 5. Variety of character types.
    pool = char_pool(password)
    kinds = sum(bool(re.search(p, password)) for p in
                (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^a-zA-Z0-9]"))
    if kinds >= 3:
        good.append("It mixes several kinds of character (upper, lower, digits, symbols).")
    elif kinds <= 1 and lowered not in COMMON:
        notes.append("It uses only one kind of character. Mixing in capitals, "
                     "digits or symbols would help - though length helps more.")
        verdict_penalty += 1

    # 6. A rough, honest crack-time estimate.
    # We assume an attacker who has stolen the scrambled passwords and can try
    # around 10 billion guesses per second on ordinary graphics hardware -
    # a realistic figure for a fast, common hashing setup.
    guesses_per_second = 1e10
    if pool > 0 and length > 0:
        combinations = pool ** length
        # On average an attacker finds it halfway through the space.
        seconds = (combinations / 2) / guesses_per_second
    else:
        seconds = 0
    # A known-common password is found immediately regardless of the maths.
    if lowered in COMMON:
        seconds = 0
    elif word_based:
        # The character-pool maths assumes randomness. A common word dressed
        # up with digits and a symbol isn't random - a dictionary attack tries
        # exactly these combinations, so the honest estimate is minutes, not
        # the millions of years the raw maths would suggest.
        seconds = min(seconds, 600)

    return notes, good, verdict_penalty, human_time(seconds)

# ---------------------------------------------------------------------------
# Has it already been stolen?
# ---------------------------------------------------------------------------
def breach_count(password, timeout=TIMEOUT):
    """How many times this password appears in known breaches.

    Your password never leaves this machine, and that is not a promise you
    have to take on trust. Here is the whole trick:

      1. The password is hashed here, locally. A hash is a one way fingerprint.
      2. Only the FIRST FIVE characters of that fingerprint are sent.
      3. The service sends back every leaked fingerprint starting with those
         five, usually several hundred of them.
      4. This computer looks through that list for the rest of the fingerprint.

    So the service learns five characters of a fingerprint, which matches
    hundreds of thousands of different passwords. It cannot tell which one is
    yours, and it never sees the password itself.

    Returns (count, error). A count of 0 means it was not found.
    """
    fingerprint = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, rest = fingerprint[:5], fingerprint[5:]

    request = urllib.request.Request(
        PWNED_API + prefix,
        headers={"User-Agent": "accounts-checker (plaintext IT)",
                 "Add-Padding": "true"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except urllib.error.URLError as exc:
        return None, "could not reach the breach database (%s)" % getattr(exc, "reason", exc)
    except OSError as exc:
        return None, "could not reach the breach database (%s)" % exc

    for line in body.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate == rest:
            try:
                return int(count), ""
            except ValueError:
                return None, "the breach database answered in a form I do not read"
    return 0, ""


def describe_breach(count):
    """Say what a breach count actually means for the person holding it."""
    if count is None:
        return ("unknown", "Could not check whether this password has been leaked.")
    if count == 0:
        return ("clear", "This password does not appear in the public breach data. That is good, "
                         "but it is not the same as strong: an unleaked bad password is still a "
                         "bad password.")
    if count < 10:
        return ("leaked", "This password appears %d times in public breach data. Attackers work "
                          "from those lists first. Change it wherever it is used." % count)
    if count < 1000:
        return ("leaked", "This password appears %s times in public breach data. It is on the "
                          "lists attackers try before anything else, so its real strength is "
                          "close to zero however clever it looks." % "{:,}".format(count))
    return ("leaked", "This password appears %s times in public breach data. It is one of the "
                      "first things any attacker tries. Treat anything using it as already open."
            % "{:,}".format(count))
