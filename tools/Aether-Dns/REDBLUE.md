# Aether-Dns Red-Team / Blue-Team Review — DNS-tunnel C2 PoC

**Target of review:** `/home/user1/plaintext-suite/tools/Aether-Dns/` (`aether_server.py` ~164 LOC, `aether_agent.py` ~140 LOC, `README.md`).
**Engagement:** authorized white-box source review only, 18 Oct 2026 (Asia/Jerusalem).
**Scope honored:** read-only analysis of the user's own files. **Did not** run the agent against any host, bind UDP/53, stop systemd-resolved, or improve/extend the C2. No third-party targeting.

---

## 1. Verdict — what a peer reviewer would conclude

**What it is:** A **DNS-tunneling Command-and-Control (C2) framework** — not a DNS scanner, not a resolver abuse checker, not a defensive DNS tool. The README labels it explicitly as an "Operational DNS-Tunneling C2 Framework." The agent beacons over crafted UDP/53 queries to a zone (default `aether.internal`), receives short commands in forged Type-A answers, and can list directories, run shell commands, and exfiltrate files (zlib + AES-256-GCM + base32 in subdomain labels). The server reassembles chunks (`str-` / `chk-` / `end-`), decrypts, prints output or writes `loot_*` files, and stops/starts `systemd-resolved` to free port 53.

**Useful (as purple-team / academic artifact):** Conditionally. It demonstrates real C2 primitives (AEAD payloads in DNS labels, selective-repeat chunking, beacon jitter, direct-to-IP DNS queries that skip recursive resolvers). For a **closed, consented lab** that already teaches DNS C2 detection, the *shape* is educational.

**Safe:** **No — not for casual portfolio packaging or unattended use.** This is malware-class software: an implant with `subprocess.run(..., shell=True)`, file fetch, and encrypted covert-channel egress. The legal disclaimer exists, but the code has no consent gate, no kill-switch beyond operator exit, a **hardcoded shared AES key in both files**, and root-required server behavior that disables the host DNS stub. Publishing it under `plaintext-suite/tools/` next to benign checkers risks misinterpretation (and misuse) by anyone who clones the suite.

**Would a skilled reviewer ship this as a "productized service"?** No. Keep it (if at all) in a clearly labeled `lab-c2-demos/` with ROE docs, or rewrite as a **detection lab** that emits synthetic DNS C2 traffic without a live shell agent. Do not present the working implant as a portfolio deliverable for recruiters/freelance clients.

---

## 2. Surface / capabilities found

| Component | Role | Behavior (from source) |
|-----------|------|------------------------|
| `aether_server.py` | C2 listener | Binds `0.0.0.0:53/udp` as root; `systemctl stop systemd-resolved` on start, start on exit; interactive menu: List Dir / Run Command / Fetch File / Terminate; decrypts base32+AES-GCM+zlib streams; writes `loot_<name>` |
| `aether_agent.py` | Implant | `--server` (required), `--domain` (default `aether.internal`); infinite beacon loop (~4s ±30% jitter); dispatches on decoded 4-byte A-RDATA; `os.listdir`, `subprocess.run(arg, shell=True)`, file read + chunked exfil |
| Crypto | Shared | `SHARED_CRYPTO_KEY = b"AetherFrameworkSecureKey2026!!!!"` identical in both files; AES-256-GCM (IV 12 + tag 16 + ciphertext), then base32 for DNS labels |
| Transport | DNS labels | Upstream: `str-<n>-<name>`, `chk-<seq>-<24char>`, `end-<name>`, `beacon`; Downstream: 4 ASCII bytes stuffed into A-record RDATA (`ACK`/`DONE`/`Rnnn`/command) |

**Not present:** recursive-resolver abuse (queries go **direct** to `--server:53`), DoH/DoT, domain fronting, multi-agent session IDs, auth beyond the shared key, or any assessment/reporting features of the plaintext-suite checkers.

---

## 3. What worked (red-team wins + blue-team strengths)

**Red-team / abuse potential (high level — no procedures):**
- **Covert C2 channel:** DNS is often poorly monitored and allowed outbound; label-chunked encrypted blobs evade naïve payload inspection.
- **Direct IP queries** bypass corporate recursive resolvers and some DNS-logging pipelines that only see stub→resolver traffic (depends on network path).
- **Full remote capabilities once running:** directory listing, arbitrary shell via `shell=True`, file exfiltration to `loot_*` on the controller.
- **OpSec-ish features already in tree:** AES-GCM + zlib, randomized IV, beacon jitter, no hardcoded C2 IP in the agent (passed at runtime), stdlib + pycryptodome only.
- **Server clears port 53** by stopping systemd-resolved — works on typical Ubuntu attacker boxes but is noisy and fragile.

**Blue-team strengths / detection surface (what defenders get for free):**
- **Hardcoded key in plaintext** — anyone with the repo decrypts historical captures; also a static IOC string (`AetherFrameworkSecureKey2026!!!!`, zone `aether.internal`).
- **Predictable label grammar:** `str-`, `chk-`, `end-`, `beacon` prefixes under a single zone — trivial Suricata/Zeek signatures.
- **Base32-looking long labels** + high query volume to one authority IP (esp. direct to non-DNS infrastructure IPs).
- **Unsolicited / weird A answers** carrying ASCII command nibbles; selective-repeat `R###` replies.
- **Host artifacts:** Python process with raw UDP/53, `systemctl stop systemd-resolved`, files named `loot_*`, agent args `--server` / `--domain`.
- **Beacon cadence** ~3–5s with ±30% jitter — still periodic; detectable with inter-arrival stats.

---

## 4. What is correctly blocked / gated (and what is not)

**Present:**
- Legal disclaimer in README (authorization language only — honor system).
- Agent requires explicit `--server` at runtime (no baked-in IP).
- Crypto integrity check (`decrypt_and_verify`) rejects tampered ciphertext.

**Absent / unsafe:**
- **No authorization gate, scope lock, or operator attestation** before shell/file ops.
- **`shell=True`** on the agent — classic RCE primitive; argument comes from the C2 path.
- **Shared static key** committed in source — not operator-provisioned, not rotated.
- **Server always binds all interfaces** and stops system DNS without confirmation beyond needing root.
- **Command channel is only 4 bytes** in the A-record (`opt` + up to 3 chars of argument after strip). That severely constrains usable remote args and makes several menu paths fragile/broken for non-trivial paths/commands — i.e. this is a **lab PoC**, not a polished framework. (Review does not include a patch.)
- No multi-tenant session isolation; single global `SessionState`.

---

## 5. Remaining tells & recommendations (prioritized)

**Portfolio / safety (do these first):**
1. **Do not ship the live implant as a public "tool" next to benign checkers.** Move to a private lab folder or strip the agent down to a **simulator** that only emits DNS frames for blue-team detection labs — no `shell=True`, no file read.
2. **Remove or rotate the hardcoded key out of git history** if this ever left the box; treat the current key string as burned.
3. **Add unmistakable labeling** in README title and file headers: `LAB-ONLY DNS C2 DEMO — AUTHORIZED USE ONLY — NOT A PRODUCT`, and keep it out of recruiter-facing one-pagers unless framed as "I built a detector for X" not "I built X."

**Blue-team / lab hygiene:**
4. Prefer teaching detection: Zeek `dns` logs for base32 entropy + label length, alerts on `chk-`/`str-` patterns, block direct UDP/53 to non-approved resolvers, alert on systemd-resolved stop + python binding :53.
5. If kept for purple team: require an explicit ROE file, lab-only networks, and never point `--server` at anything you do not own.

**Quality notes (not hardening advice for attackers):**
6. README claims "production-ready" — source quality does not match (4-byte command encoding, single global session, silent `except` on agent errors).
7. Dependency on stopping `systemd-resolved` is host-disruptive; document blast radius for any lab host used as controller.

---

## 6. Key judgement

Aether-Dns is a **compact, readable DNS C2 PoC** with modern-looking crypto wrapping and classic implant features. That makes it valuable as a **specimen for detection engineering** and dangerous as a **portable remote-control kit**. For this user's portfolio mix (recruiters + freelance clients), the right move is: **do not productize the agent**; if DNS C2 is a talking point, lead with **how you detect and contain it**, using this code only as an offline reference or synthetic traffic generator under written authorization. Same policy line as prior ICMP C2 refusals: theory and detection yes; build/run/improve the live channel no.

---

## 7. Timeline (Asia/Jerusalem)

- 18:04 — Confirmed paths under `plaintext-suite/tools/Aether-Dns/` (iot-recon already moved; no `mv` needed).
- 18:05 — Read README + both Python sources end-to-end; mapped beacon/stream/crypto/menu surfaces.
- 18:10 — Wrote this report (source review only; C2 not executed).

---
*No Aether-Dns source was modified. No agent or server process was started. No third-party host was contacted.*
