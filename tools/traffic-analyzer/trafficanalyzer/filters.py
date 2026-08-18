"""
The filter box: saying which packets you want to see.

Anybody who has used Wireshark already knows this language, so this uses the same
one rather than inventing a worse one:

    ip.addr == 45.9.0.1
    tcp.port == 443 && tcp.flags.syn == 1
    ip.src == 10.0.0.5 and not icmp
    tcp.stream == 7
    frame.len > 1400
    payload contains "GET /admin"

It is a small language on purpose. It has the fields this tool actually records,
and no others, because a filter box that accepts a field it cannot evaluate and
then quietly matches nothing is worse than one that says "I do not know that
field" and lists the ones it does.

Two rules the whole thing is built on:

  - A filter that will not parse never runs. It returns the reason, pointing at
    the character it gave up on, and the packet list stays exactly as it was.
    Silently showing zero packets is how somebody concludes there was no attack.
  - Nothing here evaluates arbitrary text. It is a parser and a small tree
    walker, not eval(), because the filter box on a security tool is the last
    place to hand a string to the interpreter.
"""

import re

# Every field the language knows, what it reads off a packet record, and the
# sentence shown in the help. Adding a field means adding it here and nowhere
# else, which is the point of the table.
FIELDS = {
    "ip.src":        ("address", "src", "the address the packet came from"),
    "ip.dst":        ("address", "dst", "the address it was sent to"),
    "ip.addr":       ("address", None, "either end, source or destination"),
    "ip.ttl":        ("number", "ttl", "time to live, roughly how many hops it has left"),
    "ip.version":    ("number", "family", "4 or 6"),
    "frame.number":  ("number", "n", "position in the capture, the number in the first column"),
    "frame.len":     ("number", "size", "length of the packet in bytes"),
    "frame.time":    ("number", "ts", "the timestamp, in seconds"),
    "tcp.srcport":   ("number", "sport", "TCP source port"),
    "tcp.dstport":   ("number", "dport", "TCP destination port"),
    "tcp.port":      ("number", None, "either TCP port"),
    "tcp.stream":    ("number", "stream", "which conversation, so you can follow one"),
    "tcp.window":    ("number", "window", "the receive window"),
    "udp.srcport":   ("number", "sport", "UDP source port"),
    "udp.dstport":   ("number", "dport", "UDP destination port"),
    "udp.port":      ("number", None, "either UDP port"),
    "icmp.type":     ("number", "icmp_type", "the ICMP message type number"),
    "tcp.flags":     ("number", "flags", "all the TCP flag bits as one number"),
    "tcp.flags.syn": ("flag", 0x02, "set on a packet asking to open a connection"),
    "tcp.flags.ack": ("flag", 0x10, "set when confirming received data"),
    "tcp.flags.fin": ("flag", 0x01, "set when one side has finished sending"),
    "tcp.flags.rst": ("flag", 0x04, "set when a connection is refused or torn down"),
    "tcp.flags.psh": ("flag", 0x08, "set to hand data straight to the program"),
    "tcp.flags.urg": ("flag", 0x20, "the rarely used urgent bit"),
    "stream":        ("number", "stream", "same as tcp.stream, for any protocol"),
    "payload":       ("bytes", None, "the packet's own bytes, for `contains`"),
}

# Bare words that mean "this protocol", the way `tcp` does in Wireshark.
PROTOCOLS = {
    "tcp": ("proto", 6), "udp": ("proto", 17), "icmp": ("proto", 1),
    "icmpv6": ("proto", 58), "igmp": ("proto", 2), "gre": ("proto", 47),
    "sctp": ("proto", 132), "esp": ("proto", 50),
    "ip": ("family", 4), "ipv4": ("family", 4), "ipv6": ("family", 6),
}

COMPARISONS = ["==", "!=", ">=", "<=", ">", "<", "eq", "ne", "ge", "le", "gt", "lt"]
COMPARE_ALIAS = {"eq": "==", "ne": "!=", "ge": ">=", "le": "<=", "gt": ">", "lt": "<"}


class FilterError(Exception):
    """A filter that will not parse. Carries where it gave up."""

    def __init__(self, message, position=None, hint=""):
        Exception.__init__(self, message)
        self.message = message
        self.position = position
        self.hint = hint


# ---------------------------------------------------------------------------
# Turning the text into tokens
# ---------------------------------------------------------------------------
TOKEN_PATTERN = re.compile(r"""
    (?P<space>\s+)
  | (?P<string>"[^"]*"|'[^']*')
  | (?P<op>==|!=|>=|<=|&&|\|\||[<>()!])
  | (?P<word>[A-Za-z0-9_.:/-]+)
""", re.VERBOSE)


def tokenize(text):
    tokens = []
    position = 0
    while position < len(text):
        match = TOKEN_PATTERN.match(text, position)
        if not match:
            raise FilterError("I do not understand the character %r here." % text[position],
                              position,
                              "Filters look like:  ip.addr == 10.0.0.5 && tcp.port == 443")
        kind = match.lastgroup
        value = match.group()
        if kind != "space":
            tokens.append({"kind": kind, "value": value, "at": position})
        position = match.end()
    return tokens


# ---------------------------------------------------------------------------
# Turning the tokens into a tree
# ---------------------------------------------------------------------------
class Parser(object):
    def __init__(self, tokens, text=""):
        self.tokens = tokens
        self.text = text
        self.index = 0

    def peek(self):
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def take(self):
        token = self.peek()
        if token is not None:
            self.index += 1
        return token

    def expect_end(self):
        token = self.peek()
        if token is not None:
            raise FilterError("There is something extra after the filter: %r" % token["value"],
                              token["at"],
                              "If you meant two conditions, join them with && or ||.")

    # or > and > not > comparison > group
    def parse(self):
        if not self.tokens:
            return None
        node = self.parse_or()
        self.expect_end()
        return node

    def parse_or(self):
        left = self.parse_and()
        while True:
            token = self.peek()
            if token and (token["value"] == "||" or token["value"].lower() == "or"):
                self.take()
                right = self.parse_and()
                left = ("or", left, right)
                continue
            return left

    def parse_and(self):
        left = self.parse_not()
        while True:
            token = self.peek()
            if token and (token["value"] == "&&" or token["value"].lower() == "and"):
                self.take()
                right = self.parse_not()
                left = ("and", left, right)
                continue
            return left

    def parse_not(self):
        token = self.peek()
        if token and (token["value"] == "!" or token["value"].lower() == "not"):
            self.take()
            return ("not", self.parse_not())
        return self.parse_atom()

    def parse_atom(self):
        token = self.take()
        if token is None:
            raise FilterError("The filter stops before it says anything.",
                              len(self.text),
                              "Try:  ip.addr == 10.0.0.5")

        if token["value"] == "(":
            node = self.parse_or()
            closing = self.take()
            if closing is None or closing["value"] != ")":
                raise FilterError("This bracket was never closed.", token["at"],
                                  "Every ( needs a matching ).")
            return node

        if token["kind"] == "string":
            raise FilterError("A piece of text on its own is not a condition: %s" % token["value"],
                              token["at"],
                              'Text goes on the right of `contains`, like:  payload contains "GET"')

        word = token["value"]
        lowered = word.lower()

        # A bare protocol name, like `tcp`.
        if lowered in PROTOCOLS and not self._next_is_comparison():
            attribute, value = PROTOCOLS[lowered]
            return ("equals", attribute, value)

        if lowered not in FIELDS:
            raise FilterError("I do not know a field called %r." % word, token["at"],
                              _closest_hint(lowered))

        operator_token = self.take()
        if operator_token is None:
            raise FilterError("%s needs something to compare against." % word,
                              token["at"] + len(word),
                              "For example:  %s == %s" % (word, _example_for(lowered)))

        operator = operator_token["value"].lower()
        if operator == "contains":
            value_token = self.take()
            if value_token is None:
                raise FilterError("`contains` needs some text after it.",
                                  operator_token["at"] + len(operator),
                                  'For example:  payload contains "password"')
            return ("contains", lowered, _unquote(value_token["value"]))

        if operator not in COMPARISONS:
            raise FilterError("I do not understand %r as a comparison." % operator_token["value"],
                              operator_token["at"],
                              "The comparisons are ==, !=, >, <, >= and <=.")
        operator = COMPARE_ALIAS.get(operator, operator)

        value_token = self.take()
        if value_token is None:
            raise FilterError("%s %s needs a value after it." % (word, operator),
                              operator_token["at"] + len(operator),
                              "For example:  %s %s %s" % (word, operator, _example_for(lowered)))

        return ("compare", lowered, operator, _unquote(value_token["value"]),
                value_token["at"])

    def _next_is_comparison(self):
        token = self.peek()
        return bool(token and token["value"].lower() in COMPARISONS + ["contains"])


def _unquote(value):
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _example_for(field):
    kind = FIELDS.get(field, ("number",))[0]
    if kind == "address":
        return "10.0.0.5"
    if kind == "flag":
        return "1"
    return "443"


def _closest_hint(word):
    """Point at the nearest real field rather than just refusing."""
    stem = word.split(".")[0]
    near = [name for name in FIELDS if name.startswith(stem)]
    if not near:
        near = [name for name in FIELDS if stem in name]
    if near:
        return "Did you mean %s?" % ", ".join(sorted(near)[:5])
    return ("The fields are: %s" % ", ".join(sorted(FIELDS)[:8])) + ", and a few more."


# ---------------------------------------------------------------------------
# Turning the tree into something that answers yes or no about a packet
# ---------------------------------------------------------------------------
def compile_filter(text):
    """Return a function(record, payload_getter) -> bool. Raises FilterError."""
    text = (text or "").strip()
    if not text:
        return lambda record, payload=None: True

    node = Parser(tokenize(text), text).parse()
    if node is None:
        return lambda record, payload=None: True
    _check(node)
    return lambda record, payload=None: _evaluate(node, record, payload)


def _check(node):
    """Validate values up front, so a bad number is reported before it runs."""
    kind = node[0]
    if kind in ("and", "or"):
        _check(node[1])
        _check(node[2])
        return
    if kind == "not":
        _check(node[1])
        return
    if kind == "compare":
        _, field, operator, value, at = node
        spec = FIELDS[field]
        if spec[0] == "address":
            return
        if spec[0] in ("number", "flag"):
            if not _looks_numeric(value):
                raise FilterError("%s expects a number, but I got %r." % (field, value), at,
                                  "For example:  %s %s %s" % (field, operator, _example_for(field)))
        return


def _looks_numeric(value):
    try:
        _number(value)
        return True
    except ValueError:
        return False


def _number(value):
    text = str(value).strip()
    if text.lower().startswith("0x"):
        return int(text, 16)
    if "." in text:
        return float(text)
    return int(text)


def _evaluate(node, record, payload_getter):
    kind = node[0]
    if kind == "and":
        return _evaluate(node[1], record, payload_getter) and \
               _evaluate(node[2], record, payload_getter)
    if kind == "or":
        return _evaluate(node[1], record, payload_getter) or \
               _evaluate(node[2], record, payload_getter)
    if kind == "not":
        return not _evaluate(node[1], record, payload_getter)
    if kind == "equals":
        return record.get(node[1]) == node[2]
    if kind == "contains":
        return _contains(node[1], node[2], record, payload_getter)
    if kind == "compare":
        return _compare(node[1], node[2], node[3], record)
    return False


def _compare(field, operator, wanted, record):
    kind, source, _note = FIELDS[field]

    if kind == "address":
        if field == "ip.addr":
            values = [record.get("src", ""), record.get("dst", "")]
        else:
            values = [record.get(source, "")]
        hit = any(_address_matches(value, wanted) for value in values)
        return hit if operator == "==" else (not hit)

    if kind == "flag":
        bit = source
        have = 1 if (record.get("flags", 0) or 0) & bit else 0
        return _numeric_compare(have, operator, _number(wanted))

    # Either-end port fields.
    if field in ("tcp.port", "udp.port"):
        proto = 6 if field.startswith("tcp") else 17
        if record.get("proto") != proto:
            return operator == "!="
        target = _number(wanted)
        values = [record.get("sport"), record.get("dport")]
        hit = any(v is not None and _numeric_compare(v, operator, target) for v in values)
        return hit

    # Port fields only mean something on the right protocol.
    if field.startswith("tcp.") and record.get("proto") != 6 and field != "tcp.stream":
        return operator == "!="
    if field.startswith("udp.") and record.get("proto") != 17:
        return operator == "!="
    if field.startswith("icmp.") and record.get("proto") not in (1, 58):
        return operator == "!="

    value = record.get(source)
    if value is None:
        return operator == "!="
    return _numeric_compare(value, operator, _number(wanted))


def _numeric_compare(value, operator, wanted):
    try:
        if operator == "==":
            return value == wanted
        if operator == "!=":
            return value != wanted
        if operator == ">":
            return value > wanted
        if operator == "<":
            return value < wanted
        if operator == ">=":
            return value >= wanted
        if operator == "<=":
            return value <= wanted
    except TypeError:
        return False
    return False


def _address_matches(value, wanted):
    """Exact match, or a prefix when the filter ends in a dot or gives a /24."""
    if not value:
        return False
    if wanted.endswith("/24") and "." in value:
        return value.startswith(wanted[:-3].rsplit(".", 1)[0] + ".")
    if wanted.endswith("."):
        return value.startswith(wanted)
    return value == wanted


def _contains(field, needle, record, payload_getter):
    """`contains` only makes sense against bytes, and only if we have them."""
    if payload_getter is None:
        return False
    data = payload_getter(record)
    if not data:
        return False
    if isinstance(needle, str):
        needle_bytes = needle.encode("utf-8", "replace")
    else:
        needle_bytes = needle
    return needle_bytes in data


# ---------------------------------------------------------------------------
def help_text():
    """What the filter box offers, for the UI and for `--help`."""
    lines = []
    for name in sorted(FIELDS):
        kind, _source, note = FIELDS[name]
        lines.append((name, note))
    return lines


def describe(text):
    """Say a filter back in words, so somebody can check it means what they meant."""
    text = (text or "").strip()
    if not text:
        return "every packet"
    try:
        node = Parser(tokenize(text), text).parse()
    except FilterError:
        return ""
    return _describe(node) if node else "every packet"


def _describe(node):
    kind = node[0]
    if kind == "and":
        return "%s and %s" % (_describe(node[1]), _describe(node[2]))
    if kind == "or":
        return "%s or %s" % (_describe(node[1]), _describe(node[2]))
    if kind == "not":
        return "not (%s)" % _describe(node[1])
    if kind == "equals":
        attribute, value = node[1], node[2]
        if attribute == "proto":
            from . import packets
            return "the protocol is %s" % packets.proto_name(value)
        return "IPv%d" % value
    if kind == "contains":
        return 'the bytes contain "%s"' % node[2]
    if kind == "compare":
        _, field, operator, value, _at = node
        spec = FIELDS[field]

        # A flag is on or off, so "the SYN flag is set" reads better than
        # "set on a packet asking to open a connection is 1".
        if spec[0] == "flag":
            name = field.rsplit(".", 1)[-1].upper()
            on = str(value).strip() not in ("0", "false", "no")
            if operator == "!=":
                on = not on
            return "the %s flag is %s" % (name, "set" if on else "not set")

        words = {"==": "is", "!=": "is not", ">": "is more than", "<": "is less than",
                 ">=": "is at least", "<=": "is at most"}
        return "%s %s %s" % (spec[2], words.get(operator, operator), value)
    return ""
