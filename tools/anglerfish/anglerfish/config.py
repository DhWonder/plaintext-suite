"""
Operator configuration: the persona file.

Everything that makes one Anglerfish install look like one specific fake
company lives in a YAML file the operator owns, not in source. The repository
ships only ``config/persona.example.yaml`` (an obviously fictional clinic on
example.net). Copy it to ``config/persona.yaml`` (gitignored) or point
``ANGLERFISH_PERSONA`` / ``--persona`` at your own file, and change every value.

Why: a public repo whose defaults match a live sensor lets anyone fingerprint
that sensor with one search. Hostname, company, NAS model, banners, planted
logins and bait names are therefore configuration; host keys, the TLS cert,
planted passwords and canary values are minted at install time.

PyYAML is used when installed. Without it a small built-in reader handles the
subset the example uses (nested mappings, scalar lists, lists of mappings,
comments, quoted strings). The sensor stays stdlib-only.
"""

import os

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
SEARCH = (
    os.path.join(REPO_ROOT, "config", "persona.yaml"),
    "/etc/anglerfish/persona.yaml",
)
EXAMPLE = os.path.join(REPO_ROOT, "config", "persona.example.yaml")


def find(explicit="", state_dir=""):
    """Path of the persona file to use, or '' when none exists."""
    candidates = [explicit, os.environ.get("ANGLERFISH_PERSONA", "")]
    if state_dir:
        candidates.append(os.path.join(state_dir, "persona.yaml"))
    candidates.extend(SEARCH)
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return ""


def load(path):
    """Parse a persona YAML file into a dict ({} when path is empty)."""
    if not path:
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(text)
    except ImportError:
        data = parse_mini_yaml(text)
    return data or {}


# ---------------------------------------------------------------------------
# Minimal YAML subset reader (no anchors, no flow style, no multi-line scalars).
# ---------------------------------------------------------------------------
def _scalar(raw):
    raw = raw.strip()
    if not raw:
        return ""
    if raw[0] in "\"'":
        quote = raw[0]
        end = raw.rfind(quote)
        body = raw[1:end] if end > 0 else raw[1:]
        if quote == '"':
            body = body.replace('\\"', '"').replace("\\\\", "\\")
        return body
    # strip trailing comment
    if " #" in raw:
        raw = raw.split(" #", 1)[0].rstrip()
    low = raw.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~"):
        return None
    if raw == "[]":
        return []
    if raw == "{}":
        return {}
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        if "." in raw and raw.replace(".", "", 1).isdigit():
            return float(raw)
    except ValueError:
        pass
    return raw


def _lines(text):
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped == "---":
            continue
        indent = len(line) - len(line.lstrip(" "))
        out.append((indent, line.strip()))
    return out


def _split_kv(item):
    # key: value  (value may contain ':' e.g. URLs, so split on first ': ')
    if item.endswith(":"):
        return item[:-1].strip(), None
    key, _, value = item.partition(": ")
    return key.strip(), value


def _parse_block(lines, i, indent):
    """Parse lines starting at i with exactly `indent`; return (obj, next_i)."""
    if i < len(lines) and lines[i][1].startswith("- "):
        result = []
        while i < len(lines) and lines[i][0] == indent and lines[i][1].startswith("- "):
            item = lines[i][1][2:].strip()
            if ":" in item and not item[0] in "\"'" and (": " in item or item.endswith(":")):
                # list of mappings; first key on the dash line
                child_indent = indent + 2
                synthetic = [(child_indent, item)]
                j = i + 1
                while j < len(lines) and lines[j][0] > indent:
                    synthetic.append(lines[j])
                    j += 1
                obj, _ = _parse_block(synthetic, 0, child_indent)
                result.append(obj)
                i = j
            else:
                result.append(_scalar(item))
                i += 1
        return result, i
    result = {}
    while i < len(lines) and lines[i][0] == indent:
        key, value = _split_kv(lines[i][1])
        i += 1
        if value is None:
            if i < len(lines) and lines[i][0] > indent:
                child, i = _parse_block(lines, i, lines[i][0])
                result[key] = child
            else:
                result[key] = None
        else:
            result[key] = _scalar(value)
    return result, i


def parse_mini_yaml(text):
    lines = _lines(text)
    if not lines:
        return {}
    obj, _ = _parse_block(lines, 0, lines[0][0])
    return obj


def flatten(cfg):
    """Turn the nested YAML layout into the flat persona keys the sensor uses."""
    cfg = cfg or {}
    ident = cfg.get("identity") or {}
    nas = cfg.get("nas") or {}
    banners = cfg.get("banners") or {}
    bait_cfg = cfg.get("bait") or {}
    out = {}

    def put(key, value):
        if value not in (None, "", "auto"):
            out[key] = value

    put("company", ident.get("company"))
    put("hostname", ident.get("hostname"))
    put("domain", ident.get("domain"))
    put("internal_ip", ident.get("internal_ip"))
    put("aws_region", ident.get("aws_region"))
    put("staff_name", ident.get("staff_name"))
    put("nas_model", nas.get("model"))
    put("nas_firmware", nas.get("firmware"))
    put("ssh_banner", banners.get("ssh"))
    put("http_server", banners.get("http_server"))
    put("ftp_banner", banners.get("ftp"))
    put("smtp_banner", banners.get("smtp"))
    put("lure_path", bait_cfg.get("lure_path"))
    put("vault_image", bait_cfg.get("vault_image"))
    put("creds_image", bait_cfg.get("creds_image"))
    put("assets_dir", bait_cfg.get("assets_dir"))
    logins = []
    for row in cfg.get("planted_logins") or []:
        if isinstance(row, dict) and row.get("user"):
            logins.append({"user": str(row["user"]),
                           "password": str(row.get("password") or "auto"),
                           "planted_in": str(row.get("planted_in") or "")})
    if logins:
        out["planted_logins_spec"] = logins
    return out
