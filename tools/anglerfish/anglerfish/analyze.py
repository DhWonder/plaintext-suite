"""
Attack analysis and tagging for anglerfish.

The sensor writes down *what* happened: every probe, login, command, file read,
prize-bait reveal (GOTCHA), download attempt, and "I was here" guestbook note.
This module answers *what it means*. It reads a recorded session (the same dict
the sensor and console already store) and, without ever touching the attacker or
re-running anything, turns the raw event stream into:

  - a tag on every event: a MITRE ATT&CK-style tactic + technique, a plain-words
    label, and a severity (info / low / medium / high / critical);
  - a per-session verdict: who this looks like (automated scanner, credential
    bot, or hands-on-keyboard human), how far up the kill chain they got, a
    0-100 threat score, and the handful of moments that matter;
  - an aggregate audit across many sessions: ATT&CK coverage, a merged timeline,
    the bait that was taken, and every piece of graffiti left behind.

Everything here is read-only analysis of data already captured. It runs on the
console (where analysis belongs), never on the sensor, and it reaches nothing.
"""

import re
import time

# Severity ladder, lowest to highest. Used for ordering and for the score.
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SEVERITY_WEIGHT = {"info": 1, "low": 4, "medium": 12, "high": 30, "critical": 60}


def _sev_max(a, b):
    return a if SEVERITY_ORDER.index(a) >= SEVERITY_ORDER.index(b) else b


# ---------------------------------------------------------------------------
# Command classification: map a typed shell command to ATT&CK.
# Each rule is (compiled regex, tactic, technique_id, technique, severity, label).
# First match wins; order matters (specific before general).
# ---------------------------------------------------------------------------
def _c(pattern):
    return re.compile(pattern, re.IGNORECASE)

COMMAND_RULES = [
    # Credential access -- reading the credential stores themselves.
    (_c(r"\b(cat|less|more|head|tail|strings|xxd|od)\b.*/etc/shadow"),
     "Credential Access", "T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow",
     "critical", "read the shadow password file"),
    (_c(r"\b(cat|less|more|head|tail)\b.*/etc/passwd"),
     "Credential Access", "T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow",
     "high", "enumerated local accounts via /etc/passwd"),
    (_c(r"\b(cat|less|more|head|tail|grep)\b.*(\.env|credentials|\.aws|id_rsa|\.ssh/|authorized_keys|\.pem|\.ovpn|vault|password|secret|backup\.sh|mysql_history|bash_history)"),
     "Credential Access", "T1552", "Unsecured Credentials: files and history",
     "high", "hunted for stored credentials"),
    # Discovery
    (_c(r"^\s*(whoami|id|groups)\b"),
     "Discovery", "T1033", "System Owner/User Discovery",
     "low", "checked who they are on the box"),
    (_c(r"^\s*(uname|hostnamectl|hostname|lsb_release|cat\s+/etc/os-release|cat\s+/etc/issue)\b"),
     "Discovery", "T1082", "System Information Discovery",
     "low", "fingerprinted the host"),
    (_c(r"^\s*(ps|top|htop)\b"),
     "Discovery", "T1057", "Process Discovery",
     "low", "listed running processes"),
    (_c(r"^\s*(ss|netstat|lsof)\b"),
     "Discovery", "T1049", "System Network Connections Discovery",
     "low", "listed network connections"),
    (_c(r"^\s*(ip|ifconfig|route|arp|ip\s+a|ip\s+addr)\b"),
     "Discovery", "T1016", "System Network Configuration Discovery",
     "low", "read the network configuration"),
    (_c(r"^\s*(last|lastlog|w|who)\b"),
     "Discovery", "T1033", "System Owner/User Discovery",
     "low", "checked who else logs in"),
    (_c(r"^\s*(crontab|systemctl|service)\b"),
     "Discovery", "T1007", "System Service Discovery",
     "low", "looked at services and scheduled tasks"),
    (_c(r"^\s*(find|locate)\b"),
     "Discovery", "T1083", "File and Directory Discovery",
     "medium", "searched the filesystem"),
    (_c(r"^\s*(ls|dir|ll|pwd|cd|tree|stat)\b"),
     "Discovery", "T1083", "File and Directory Discovery",
     "info", "browsed the filesystem"),
    (_c(r"^\s*(env|printenv|set)\b"),
     "Discovery", "T1082", "System Information Discovery",
     "low", "dumped the environment"),
    (_c(r"^\s*history\b"),
     "Discovery", "T1552.003", "Unsecured Credentials: Bash History",
     "medium", "read shell history for secrets"),
    # Collection -- reading content off the box.
    (_c(r"^\s*(cat|less|more|head|tail|cp|tar|zip|gzip|scp)\b"),
     "Collection", "T1005", "Data from Local System",
     "medium", "read or staged files off the box"),
    # Exfiltration / C2 -- pulling tools in or pushing data out.
    (_c(r"^\s*(wget|curl|tftp|ftp|nc|ncat|netcat)\b"),
     "Command and Control", "T1105", "Ingress Tool Transfer",
     "high", "tried to pull a tool onto the box"),
    (_c(r"(>|>>|\|)\s*(/dev/tcp|nc\b|curl\b|wget\b)"),
     "Exfiltration", "T1041", "Exfiltration Over C2 Channel",
     "high", "tried to push data off the box"),
    # Persistence / defense evasion
    (_c(r"\b(authorized_keys|ssh-keygen|useradd|adduser|passwd\s+\w)"),
     "Persistence", "T1098", "Account Manipulation",
     "high", "tried to plant persistent access"),
    (_c(r"\b(history\s+-c|rm\s+.*bash_history|unset\s+HISTFILE|shred\b)"),
     "Defense Evasion", "T1070.003", "Indicator Removal: Clear Command History",
     "high", "tried to cover their tracks"),
    (_c(r"\b(chmod|chown)\b"),
     "Defense Evasion", "T1222", "File and Directory Permissions Modification",
     "low", "changed file permissions"),
]

# Bait files whose content is itself a credential/secret: reading one is
# Credential Access, not just Collection.
CREDENTIAL_BAIT = re.compile(
    r"(\.env|app\.env|docker-compose|\.ovpn|backup\.sh|customers_export|"
    r"it-handover|re-nas-access|\.ssh/config|authorized_keys|vault|\.vault-key|"
    r"bash_history|mysql_history|passwd|shadow)", re.IGNORECASE)


def tag_command(line):
    text = (line or "").strip()
    for rx, tactic, tid, tech, sev, label in COMMAND_RULES:
        if rx.search(text):
            return {"tactic": tactic, "technique_id": tid, "technique": tech,
                    "severity": sev, "label": label}
    return {"tactic": "Execution", "technique_id": "T1059",
            "technique": "Command and Scripting Interpreter",
            "severity": "info", "label": "typed a command"}


def tag_event(ev):
    """Return a tag dict for one recorded event, or None for noise.

    tag = {tactic, technique_id, technique, severity, label}
    """
    kind = ev.get("kind", "")
    detail = ev.get("detail", "") or ""

    if kind in ("probe", "first-bytes"):
        return {"tactic": "Reconnaissance", "technique_id": "T1595",
                "technique": "Active Scanning", "severity": "info",
                "label": "probed the service"}
    if kind == "ssh-client":
        return {"tactic": "Reconnaissance", "technique_id": "T1592",
                "technique": "Gather Victim Host Information", "severity": "info",
                "label": "announced an SSH client (%s)" % detail[:60]}
    if kind in ("login-user", "login-pass"):
        return None  # folded into the login-result tag below
    if kind == "login-result":
        if detail == "ok":
            return {"tactic": "Initial Access", "technique_id": "T1078",
                    "technique": "Valid Accounts", "severity": "high",
                    "label": "signed in with a planted credential"}
        return {"tactic": "Credential Access", "technique_id": "T1110",
                "technique": "Brute Force", "severity": "medium",
                "label": "failed a login (guessed credentials)"}
    if kind == "auth-slowdown":
        return {"tactic": "Credential Access", "technique_id": "T1110.001",
                "technique": "Brute Force: Password Guessing", "severity": "medium",
                "label": "hit the login rate limit (repeated guessing)"}
    if kind == "command":
        return tag_command(detail)
    if kind in ("smtp", "ftp"):
        return {"tactic": "Reconnaissance", "technique_id": "T1595.002",
                "technique": "Active Scanning: Vulnerability Scanning",
                "severity": "info", "label": "probed the %s service" % kind}
    if kind == "smtp-mail":
        return {"tactic": "Reconnaissance", "technique_id": "T1595.002",
                "technique": "Active Scanning", "severity": "low",
                "label": "tested the mail relay"}
    if kind == "http":
        return {"tactic": "Reconnaissance", "technique_id": "T1595.003",
                "technique": "Active Scanning: Wordlist Scanning", "severity": "info",
                "label": "requested a web page"}
    if kind == "http-post":
        return {"tactic": "Credential Access", "technique_id": "T1110",
                "technique": "Brute Force", "severity": "low",
                "label": "posted credentials to the web login"}
    if kind == "read-file":
        if CREDENTIAL_BAIT.search(detail):
            return {"tactic": "Credential Access", "technique_id": "T1552.001",
                    "technique": "Unsecured Credentials: Credentials In Files",
                    "severity": "high", "label": "read a credential file (%s)"
                    % detail.rsplit("/", 1)[-1]}
        return {"tactic": "Collection", "technique_id": "T1005",
                "technique": "Data from Local System", "severity": "medium",
                "label": "read a file (%s)" % detail.rsplit("/", 1)[-1]}
    if kind == "download-attempt":
        return {"tactic": "Command and Control", "technique_id": "T1105",
                "technique": "Ingress Tool Transfer", "severity": "high",
                "label": "tried to pull a tool onto the box (%s)" % detail[:60]}
    if kind == "http-exploit":
        return {"tactic": "Initial Access", "technique_id": "T1190",
                "technique": "Exploit Public-Facing Application", "severity": "high",
                "label": "exploitation probe: %s" % detail[:80]}
    if kind == "ssh-hassh":
        return {"tactic": "Reconnaissance", "technique_id": "T1592.002",
                "technique": "Gather Victim Host Information: Software",
                "severity": "info", "label": "SSH client fingerprint (HASSH %s)" % detail[:16]}
    if kind == "ssh-pubkey":
        return {"tactic": "Credential Access", "technique_id": "T1110.001",
                "technique": "Brute Force: Password Guessing", "severity": "low",
                "label": "offered an SSH public key (%s)" % detail[:60]}
    if kind == "ssh-reject":
        return {"tactic": "Reconnaissance", "technique_id": "T1595",
                "technique": "Active Scanning", "severity": "info",
                "label": "non-SSH probe on the SSH port"}
    if kind == "gotcha":
        return {"tactic": "Collection", "technique_id": "T1005",
                "technique": "Data from Local System", "severity": "critical",
                "label": "opened prize bait -- GOTCHA (%s)"
                % detail.split(" via ")[0].rsplit("/", 1)[-1]}
    if kind == "guestbook":
        return {"tactic": "Impact", "technique_id": "T1491.001",
                "technique": "Defacement: Internal Defacement", "severity": "high",
                "label": 'left an "I was here" note'}
    return None


# ---------------------------------------------------------------------------
def analyze_session(session):
    """Turn one recorded session into a tagged, scored verdict."""
    events = session.get("events", []) or []
    tagged = []
    tactics = {}            # tactic -> count
    techniques = {}         # technique_id -> {technique, tactic, count, severity}
    score = 0
    worst = "info"

    for ev in events:
        tag = tag_event(ev)
        if not tag:
            continue
        item = dict(ev)
        item["tag"] = tag
        tagged.append(item)
        tactics[tag["tactic"]] = tactics.get(tag["tactic"], 0) + 1
        tid = tag["technique_id"]
        slot = techniques.setdefault(tid, {
            "technique_id": tid, "technique": tag["technique"],
            "tactic": tag["tactic"], "count": 0, "severity": "info"})
        slot["count"] += 1
        slot["severity"] = _sev_max(slot["severity"], tag["severity"])
        score += SEVERITY_WEIGHT[tag["severity"]]
        worst = _sev_max(worst, tag["severity"])

    # Signals used for the verdict.
    auth_ok = bool(session.get("auth_ok")) or any(
        e.get("kind") == "login-result" and e.get("detail") == "ok" for e in events)
    n_commands = len(session.get("commands", []) or [])
    n_reads = len(session.get("read_files", []) or [])
    n_creds = len(session.get("credentials", []) or [])
    n_fail = sum(1 for e in events
                 if e.get("kind") == "login-result" and e.get("detail") == "fail")
    gotchas = session.get("gotchas", []) or [
        e for e in events if e.get("kind") == "gotcha"]
    guestbook = session.get("guestbook", []) or []
    graffiti_notes = [g.get("note") if isinstance(g, dict) else str(g)
                      for g in guestbook]
    if not graffiti_notes:
        graffiti_notes = [e.get("detail") for e in events
                          if e.get("kind") == "guestbook"]
    duration = session.get("duration", 0) or 0

    # Actor classification.
    if auth_ok and n_commands >= 3:
        actor = "hands-on-keyboard"
        actor_why = ("signed in and typed %d commands by hand -- a person, not a "
                     "script" % n_commands)
    elif auth_ok:
        actor = "hands-on-keyboard"
        actor_why = "signed in with valid credentials and looked around"
    elif n_fail >= 3 or (n_creds >= 3 and not auth_ok):
        actor = "credential bot"
        actor_why = "hammered the login with %d credential guesses" % max(n_fail, n_creds)
    elif n_commands == 0 and n_reads == 0:
        actor = "automated scanner"
        actor_why = "connected, fingerprinted the service, and left -- no login"
    else:
        actor = "opportunistic probe"
        actor_why = "poked at the service without getting in"

    # Kill-chain stages reached, in attack order.
    chain_order = ["Reconnaissance", "Initial Access", "Execution",
                   "Persistence", "Defense Evasion", "Credential Access",
                   "Discovery", "Lateral Movement", "Collection",
                   "Command and Control", "Exfiltration", "Impact"]
    stages = [t for t in chain_order if t in tactics]

    # Highlights: the handful of things a human should read first.
    highlights = []
    if auth_ok:
        user = session.get("username", "")
        highlights.append("Signed in%s with a planted credential (Valid Accounts)."
                          % ((" as %s" % user) if user else ""))
    if gotchas:
        names = ", ".join(sorted({(g.get("path") if isinstance(g, dict) else str(g)).rsplit("/", 1)[-1]
                                  for g in gotchas}))
        highlights.append("GOTCHA: opened prize bait (%s)." % names)
    if any(t["severity"] == "critical" for t in techniques.values()):
        highlights.append("Reached credential stores or prize bait (critical).")
    if n_reads:
        highlights.append("Read %d file(s) off the decoy." % n_reads)
    dl = [e for e in events if e.get("kind") == "download-attempt"]
    if dl:
        highlights.append("Attempted %d inbound tool-transfer(s)." % len(dl))
    if graffiti_notes:
        highlights.append('Left graffiti: "%s"' % (graffiti_notes[0] or "")[:120])
    if n_fail and not auth_ok:
        highlights.append("Failed %d login attempt(s) -- brute force." % n_fail)
    if not highlights:
        highlights.append("Connected and probed; no login, no files taken.")

    # Score: weight by how far up the kill chain they got, not by raw event
    # count. Nine failed logins must not equal 100 — that used to make a
    # credential bot look as dangerous as someone who took the vault.
    stage_bonus = {
        "Reconnaissance": 2, "Credential Access": 8, "Initial Access": 18,
        "Discovery": 6, "Collection": 14, "Persistence": 16,
        "Defense Evasion": 12, "Command and Control": 16, "Exfiltration": 18,
        "Execution": 4, "Impact": 20,
    }
    unique_stage_score = sum(stage_bonus.get(s, 0) for s in stages)
    # Diminishing returns on repetitive events (brute force).
    event_score = min(40, int(round(score * 0.25)))
    gotcha_bonus = 25 if gotchas else 0
    graffiti_bonus = 10 if graffiti_notes else 0
    auth_bonus = 15 if auth_ok else 0
    score = min(100, unique_stage_score + event_score + gotcha_bonus
                + graffiti_bonus + auth_bonus)

    # Timing-based bot-vs-human refinement: a human pauses between commands.
    if actor == "hands-on-keyboard" and n_commands >= 3:
        cmd_times = [e.get("at", 0) for e in events if e.get("kind") == "command"]
        if len(cmd_times) >= 3:
            gaps = [cmd_times[i+1] - cmd_times[i] for i in range(len(cmd_times)-1)]
            median_gap = sorted(gaps)[len(gaps)//2]
            if median_gap < 0.15:
                actor = "scripted post-auth"
                actor_why = ("signed in then fired %d commands with <150ms gaps "
                             "— scripted, not typed" % n_commands)
                verdict_override = True
            else:
                verdict_override = False
        else:
            verdict_override = False
    else:
        verdict_override = False

    # One-line verdict.
    sev_word = {"info": "noise", "low": "minor", "medium": "notable",
                "high": "serious", "critical": "critical"}[worst]
    verdict = "%s %s -- %s" % (sev_word.capitalize(), actor, actor_why)

    return {
        "verdict": verdict,
        "actor": actor,
        "actor_why": actor_why,
        "severity": worst,
        "score": score,
        "auth_ok": auth_ok,
        "kill_chain": stages,
        "tactics": [{"tactic": t, "count": c} for t, c in
                    sorted(tactics.items(), key=lambda kv: -kv[1])],
        "techniques": sorted(techniques.values(),
                             key=lambda d: (-SEVERITY_WEIGHT[d["severity"]], -d["count"])),
        "highlights": highlights,
        "graffiti": [g for g in graffiti_notes if g],
        "tagged_events": tagged,
        "counts": {"commands": n_commands, "reads": n_reads, "creds": n_creds,
                   "failed_logins": n_fail, "gotchas": len(gotchas),
                   "duration": duration},
    }


# ---------------------------------------------------------------------------
def audit(sessions):
    """Aggregate analysis across many full session dicts.

    `sessions` is a list of the stored session detail dicts.
    """
    techniques = {}   # tid -> {.., count, sessions:set, severity}
    tactics = {}
    timeline = []
    graffiti = []
    bait_taken = {}
    per_session = []
    actors = {}
    severities = {s: 0 for s in SEVERITY_ORDER}
    attackers = set()
    total_score = 0

    for s in sessions:
        a = analyze_session(s)
        sid = s.get("id", "")
        ip = s.get("peer_ip", "")
        attackers.add(ip)
        actors[a["actor"]] = actors.get(a["actor"], 0) + 1
        severities[a["severity"]] += 1
        total_score += a["score"]
        per_session.append({
            "id": sid, "peer_ip": ip, "sensor": s.get("sensor", ""),
            "protocol": s.get("protocol", ""), "started": s.get("started", 0),
            "verdict": a["verdict"], "actor": a["actor"], "severity": a["severity"],
            "score": a["score"], "kill_chain": a["kill_chain"],
            "highlights": a["highlights"],
        })
        for t in a["techniques"]:
            tid = t["technique_id"]
            slot = techniques.setdefault(tid, {
                "technique_id": tid, "technique": t["technique"],
                "tactic": t["tactic"], "count": 0, "sessions": set(),
                "severity": "info"})
            slot["count"] += t["count"]
            slot["sessions"].add(sid)
            slot["severity"] = _sev_max(slot["severity"], t["severity"])
        for t in a["tactics"]:
            tactics[t["tactic"]] = tactics.get(t["tactic"], 0) + t["count"]
        for ev in a["tagged_events"]:
            timeline.append({
                "at": ev.get("at", 0), "peer_ip": ip, "sensor": s.get("sensor", ""),
                "session": sid, "kind": ev.get("kind"), "detail": ev.get("detail"),
                "tag": ev.get("tag"),
            })
        for note in a["graffiti"]:
            graffiti.append({"note": note, "peer_ip": ip, "sensor": s.get("sensor", ""),
                             "session": sid, "at": s.get("ended") or s.get("started", 0)})
        for f in (s.get("read_files", []) or []):
            bait_taken[f] = bait_taken.get(f, 0) + 1

    timeline.sort(key=lambda e: e.get("at", 0))

    coverage = sorted(techniques.values(),
                      key=lambda d: (d["tactic"], d["technique_id"]))
    for c in coverage:
        c["sessions"] = len(c["sessions"])

    return {
        "generated_at": time.time(),
        "totals": {
            "sessions": len(sessions),
            "attackers": len(attackers),
            "techniques": len(techniques),
            "tactics": len(tactics),
            "graffiti": len(graffiti),
            "avg_score": int(round(total_score / len(sessions))) if sessions else 0,
        },
        "by_actor": actors,
        "by_severity": severities,
        "tactics": [{"tactic": t, "count": c} for t, c in
                    sorted(tactics.items(), key=lambda kv: -kv[1])],
        "attack_coverage": coverage,
        "top_bait": sorted(({"path": p, "count": c} for p, c in bait_taken.items()),
                           key=lambda d: -d["count"])[:15],
        "graffiti_wall": sorted(graffiti, key=lambda g: -g.get("at", 0)),
        "timeline": timeline,
        "sessions": sorted(per_session, key=lambda d: -d.get("score", 0)),
        "stolen_cred_links": link_stolen_creds(sessions),
        "by_ip": correlate_by_ip(sessions),
        "iocs": sorted({ioc for s in sessions
                        for e in (s.get("events") or [])
                        if e.get("kind") == "download-attempt"
                        for ioc in extract_iocs(e.get("detail") or "")}),
    }


# ---------------------------------------------------------------------------
# IOC extraction and cross-session correlation
# ---------------------------------------------------------------------------
_URL_RE = re.compile(r"https?://[^\s\"\'<>]+|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/\S*)?",
                     re.IGNORECASE)
_CRED_RE = re.compile(r"(?i)(password|passwd|pwd|secret|token|key)\s*[=:]\s*(\S+)")


def extract_iocs(command):
    """Pull URLs/IPs/ports out of a wget/curl/nc line. Never fetches them."""
    found = []
    for m in _URL_RE.finditer(command or ""):
        found.append(m.group(0).rstrip(");,\"\'"))
    return found


def link_stolen_creds(sessions):
    """Connect 'read a bait password' to 'later logged in with it'.

    Returns a list of {credential, stolen_from, stolen_at, used_at, peer_ip,
    steal_session, use_session} for the attack-path slide.
    """
    # Map password -> list of (when, session_id, path, peer)
    stolen = {}
    for s in sessions:
        for f in (s.get("read_files") or []):
            leaf = f.rsplit("/", 1)[-1]
            # We do not re-parse bait here; the credential list on later sessions
            # is enough to match. Record the read as a candidate source.
            stolen.setdefault(s.get("peer_ip", ""), []).append({
                "at": s.get("started", 0), "session": s.get("id", ""),
                "path": f, "peer_ip": s.get("peer_ip", ""),
            })
    links = []
    for s in sessions:
        if not s.get("auth_ok"):
            continue
        for cred in (s.get("credentials") or []):
            pw = cred.get("password") or ""
            if not pw or cred.get("service") == "sudo":
                continue
            # Look for an earlier session from same IP that read credential bait
            # before this login.
            prior = [r for r in stolen.get(s.get("peer_ip", ""), [])
                     if r["at"] <= (s.get("started") or 0)
                     and r["session"] != s.get("id")
                     and any(k in (r["path"] or "").lower()
                             for k in ("handover", "compose", "draft", ".env",
                                       "vault", "ovpn", "backup"))]
            if prior:
                src = prior[-1]
                links.append({
                    "credential": "%s / %s" % (cred.get("username", ""), pw[:3] + "***"),
                    "password_prefix": pw[:3],
                    "stolen_from": src["path"],
                    "stolen_at": src["at"],
                    "used_at": s.get("started", 0),
                    "peer_ip": s.get("peer_ip", ""),
                    "steal_session": src["session"],
                    "use_session": s.get("id", ""),
                    "lag_seconds": round((s.get("started") or 0) - src["at"], 1),
                })
    return links


def correlate_by_ip(sessions):
    """Group sessions by source IP across protocols for the attack path."""
    by_ip = {}
    for s in sessions:
        ip = s.get("peer_ip") or "?"
        by_ip.setdefault(ip, []).append({
            "id": s.get("id"), "protocol": s.get("protocol"),
            "started": s.get("started", 0), "auth_ok": bool(s.get("auth_ok")),
            "commands": len(s.get("commands") or []),
            "reads": len(s.get("read_files") or []),
        })
    out = []
    for ip, rows in by_ip.items():
        rows.sort(key=lambda r: r["started"])
        protocols = sorted({r["protocol"] for r in rows if r["protocol"]})
        out.append({
            "peer_ip": ip, "sessions": len(rows), "protocols": protocols,
            "path": rows, "crossed_protocols": len(protocols) > 1,
        })
    out.sort(key=lambda d: (-d["sessions"], d["peer_ip"]))
    return out
