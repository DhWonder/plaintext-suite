# iotscan — IoT device security assessment tool

A reusable, modular **authorized-pentest** tool for IoT devices (smart TVs,
cameras, media players, routers, hubs). It chains **recon → CVE matching →
confirmed footholds** into a per-device assessment. Written in Python 3,
standard-library first. `nmap` is used if present; otherwise a pure-Python TCP
connect scanner is the fallback.

> **AUTHORIZED USE ONLY.** Run this only against devices you own or have
> explicit, documented permission to test. It enumerates passively by default.
> Everything intrusive is **opt-in** behind explicit flags. No destructive
> payloads, no persistence, no data exfiltration, and no attacks on third
> parties. See the ethics notice at the bottom.

---

## Two-tier safety model

The tool separates *looking* from *touching*:

| Tier | Flag | Covers |
|------|------|--------|
| **Authorization** | `--i-have-authorization` | Required for **any** active scanning (or answer `yes` to the interactive prompt). With no TTY and no flag, the tool aborts. |
| **Foothold confirmation** | `--confirm-footholds` | Required **in addition** for the intrusive confirmation modules (`adb`, `webvuln`). Refuses to run unless `--i-have-authorization` is also set. |

`--try-creds` (default-credential check) is also intrusive and opt-in.

---

## Install / requirements

- **Python 3.7+** (tested on 3.13). No required pip packages — stdlib only.
- **Optional:** `nmap` for richer service/version detection (`sudo apt install nmap`).
  Without it the tool falls back to a built-in Python port scanner automatically.
- **Optional:** `adb` (Android platform-tools) for the `adb` foothold module
  (`sudo apt install android-tools-adb`). If missing, the module reports that
  it's required instead of confirming.

No virtualenv needed.

---

## Quick start

```bash
# See options
python3 iotscan.py --help

# Dry run — validate target parsing + config, send no packets
python3 iotscan.py 192.168.1.50 --dry-run

# Default scan: ports,http,upnp,media,cve (prompts for authorization)
python3 iotscan.py 192.168.1.50

# Skip the prompt (you assert authorization)
python3 iotscan.py 192.168.1.50 --i-have-authorization

# Recon + offline CVE matching only (passive, safe)
python3 iotscan.py 192.168.1.50 --modules ports,http,upnp,media,cve --i-have-authorization

# Full assessment incl. intrusive foothold confirmation (YOUR devices only)
python3 iotscan.py 192.168.1.50 \
    --modules ports,http,upnp,media,cve,adb,webvuln \
    --confirm-footholds --i-have-authorization -o report.json

# Opt-in default-credential check
python3 iotscan.py 192.168.1.50 --try-creds --i-have-authorization

# Add online NVD enrichment on top of the offline DB
python3 iotscan.py 192.168.1.50 --modules cve --nvd-online --i-have-authorization

# Scan a subnet / range, be polite (0.3s between probes)
python3 iotscan.py 192.168.1.0/24 --rate 0.3 --i-have-authorization
python3 iotscan.py 192.168.1.10-40 --rate 0.3 --i-have-authorization
```

Targets accepted: single IP, CIDR (`192.168.1.0/24`), or last-octet range
(`192.168.1.10-40`).

---

## Modules

Selected with `--modules a,b,c` (default: `ports,http,upnp,media,cve`).

| Module | Tier | What it does |
|--------|------|--------------|
| `ports` | auth | `nmap -sV -T4 -Pn` on a curated IoT port set (or `-p-` with `--full`); falls back to a threaded pure-Python TCP connect scan with best-effort banner grab. |
| `http`  | auth | GETs root + common admin/config/descriptor paths (read-only). Captures `Server`, title, `WWW-Authenticate`, content-type. Flags reachable admin panels and no-auth admin pages. |
| `upnp`  | auth | SSDP `M-SEARCH` multicast; collects responders and fetches/parses the UPnP device-descriptor XML (friendlyName, manufacturer, model, serial). |
| `media` | auth | DIAL/Chromecast (8008), Roku ECP (8060), RTSP (554 `OPTIONS`), Android-TV ADB note (5555). Read-only. |
| `cve`   | auth | **Offline CVE matching.** Builds a fingerprint from banners/versions + UPnP manufacturer/model/firmware and matches it against `cve_db.json`. Reports CVE id, severity, description, references. Optional online NVD enrichment with `--nvd-online`. No internet needed by default. |
| `adb`   | **confirm** | **ADB foothold confirmation.** If 5555 is open and `--confirm-footholds` is set, runs `adb connect`, then a few **harmless read-only** commands (`getprop ro.product.model`, `getprop ro.build.version.release`, `getprop ro.product.manufacturer`, `id`) to CONFIRM shell access, then disconnects. Reports a confirmed critical foothold with device info. No persistence, no file drops, nothing destructive. Requires the `adb` binary. |
| `webvuln` | **confirm** | **Web-UI probes against the device's own HTTP admin interface only**, read-only / detection-only, rate-limited and hard-capped (no fuzzing storms): <br>• **auth-bypass** — direct GET of known protected paths; 200-with-content-and-no-login flagged as suspected.<br>• **path traversal** — read-only `../etc/passwd`-style requests, matched only on the `root:...:0:0:` signature (contents never stored).<br>• **command injection** — DETECTION-ONLY: injects a benign `;echo <nonce>` / `$(echo <nonce>)` / backtick marker with a unique nonce into common params and confirms injection **only** if the bare nonce is reflected (no real command beyond `echo`).<br>• **CVE endpoints** — read-only reachability check of endpoints named by matched CVEs (exploit payloads are **never** fired). |

Opt-in extra:

| Flag | What it does |
|------|--------------|
| `--try-creds` | Intrusive, opt-in. Tests a tiny list of *documented* default creds against HTTP Basic-auth challenges only. Hard-capped at 4 attempts/endpoint, stops at first success. Not a brute-forcer. |

---

## The offline CVE database (`cve_db.json`)

An **offline, extensible** knowledge base of well-known IoT CVEs, loaded at
runtime (no internet by default). Each entry:

```json
{
  "cve": "CVE-2021-36260",
  "match": {"any": "Hikvision|App-webs|DNVRS-Webs"},
  "severity": "critical",
  "description": "Hikvision ... unauthenticated command injection ...",
  "endpoints": ["/SDK/webLanguage"],
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-36260"]
}
```

- `match` fields are **case-insensitive regexes**. Supported keys: `server`,
  `banner`, `manufacturer`, `model`, `version`, `service`, and `any` (matches
  any detected string). **All** keys in an entry must match (AND).
- `endpoints` are optional read-only paths the `webvuln` module probes to
  corroborate a match.
- **To extend:** just add entries to the `entries` array. Use `--cve-db
  /path/to/custom.json` to point at your own DB. Ships with ~17 illustrative
  entries (routers, cameras, Chromecast/DIAL, Roku, Samsung, Android-TV ADB,
  plus Mirai-class default-telnet and GPON/Netgear router RCE botnet entries).
  Botnet-recruited device classes carry an optional `"botnet": true` flag and a
  short `"attack_vector"` string used by the botnet-exposure audit.
- `--nvd-online` additionally queries the public NVD 2.0 API for extra context
  (read-only, best-effort, off by default).

Matches are **advisory** — always verify against the actual model/firmware
before treating them as exploitable.

---

## Output: the assessment chain

- **Console**: live per-device progress, severity-tagged findings, and a final
  per-device **assessment** block.
- **JSON report** (`-o`, default `iotscan_report.json`): full structured results.
  Each device carries `ports`, `http`, `upnp`, media info, `cve_matches`,
  `foothold_findings`, a merged `findings` list, and an `assessment`:

```json
"assessment": {
  "worst_severity": "critical",
  "exposed_ports": [80, 5555, 9000],
  "cve_matches": ["CVE-2018-10088"],
  "confirmed_footholds": ["command_injection"],
  "suspected_issues": ["auth_bypass_suspected"],
  "next_manual_step": "Confirmed command injection - identify the vulnerable binary/firmware version and patch or isolate the device.",
  "likely_attack_vector": "web command injection",
  "attack_path_summary": "How this device would most likely be compromised: web command injection - a benign nonce echo executed via the web UI (confirmed foothold).",
  "botnet_recruitable": true,
  "botnet_exposure_severity": "critical",
  "botnet_vectors": ["adb_remote_shell", "known_botnet_cve"]
}
```

So each device reads as **what's exposed → what might be vulnerable (CVEs) →
what's confirmed exploitable → the suggested next manual step.** Confirmed
footholds are tagged `(CONFIRMED)` in the console.

---

## Botnet-exposure / recruitability audit (reporting only)

Every device scan now runs a **botnet-exposure audit** (`botnet_exposure_audit`)
that answers *"could this device be recruited into a botnet or persisted on, and
how?"* — as **findings with severity and evidence**, derived **only** from what
recon already detected. It installs nothing, uploads nothing, and persists
nothing. It is pure risk reporting so the owner can understand and close the gap.

Vectors it flags (detection/evidence only):

| Vector | Severity | Evidence used |
|--------|----------|---------------|
| `telnet_remote_shell` | high | Telnet (23) open — the classic Mirai ingress (default/weak telnet creds → loader → bot binary). |
| `ssh_remote_shell` | medium | SSH (22) open — remote-shell vector if weak/default creds. |
| `adb_remote_shell` | critical | ADB (5555) open — unauthenticated full shell / persistence foothold (ADB.Miner-class). |
| `default_credentials` | critical | A default/weak login was actually accepted (`--try-creds`). |
| `unauth_control_api` | medium | Open Cast/DIAL (8008) control API — LAN abuse surface. |
| `unauth_upnp` | medium | Exposed UPnP SOAP control ports — NAT-injection / proxy-botnet abuse. |
| `firmware_upload_persistence` | high | An upload/firmware/upgrade endpoint was discovered — a persistence vector (**report only; nothing is uploaded**). |
| `known_botnet_cve` | (CVE sev) | A matched `cve_db.json` entry flagged `"botnet": true` or describing a Mirai/Satori/ADB.Miner-class target. |

Each device's JSON gets a `botnet_exposure` block (`recruitable`, `severity`,
`vectors[]` each with `vector`/`severity`/`detail`/`evidence`, and a `summary`),
and the assessment rolls it up into `botnet_recruitable`,
`botnet_exposure_severity`, and `botnet_vectors`.

> **Scope:** this audits *exposure and suitability* only. The tool contains **no
> implant, persistence payload, C2, worm/spreading, or botnet-client code** and
> never will. "How it could be persisted on" is reported as a finding to fix,
> not performed.

---

## "Likely attack path" verdict

Each device's `assessment` now carries the single most-probable route in:

- `likely_attack_vector` — a short label, e.g. `default credentials over Telnet`,
  `ADB shell on 5555`, `unauthenticated Cast/DIAL control API`,
  `web admin file-upload / firmware endpoint`, `BLE pairing (Just Works)`,
  `web command injection`, or `no obvious remote vector found`.
- `attack_path_summary` — a human sentence:
  *"How this device would most likely be compromised: &lt;vector&gt; — &lt;one-line why&gt;."*

It is derived from a clear **priority ordering** (`determine_attack_vector`):
confirmed footholds first (command injection → path traversal → ADB shell), then
default credentials, weak BLE pairing, Telnet, exposed ADB, writable firmware
endpoint, unauthenticated web admin, open Cast/DIAL API, SSH, UPnP, RTSP, and
finally a matched-CVE fallback. It is printed prominently (`>>>`) in the console
assessment and included in the JSON.

---

## BLE pairing-security assessment (reporting only)

The Bluetooth side now characterises **pairing/bonding posture** for discovered
BLE devices (`assess_ble_pairing`), as descriptive risk reporting:

- Flags **"Just Works"** pairing (no PIN/passkey) — the device accepts
  unauthenticated bonds, so a host it then *trusts* may reach control
  characteristics post-pairing.
- Where posture can't be inferred from advertisements, it says so and points at
  `--gatt` (read-only connect test) rather than guessing.
- `--gatt` additionally reports `unauthenticated_connect_allowed`: whether a
  read-only connect/enumerate succeeded **without** pairing — a `pairing_finding`
  describing the exposure.

> This is **descriptive only**. There is **no pair-then-manipulate / bonding-then-write**
> logic. `--gatt` performs a read-only connect/enumerate (already gated behind
> `--confirm-footholds`); GATT writes are never auto-performed.

---

## Safety & ethics

- **Authorization is mandatory.** A banner prints every run; confirm `yes` or
  pass `--i-have-authorization`. No TTY + no flag = abort.
- **Intrusive confirmation is double-gated.** `--confirm-footholds` is required
  for `adb`/`webvuln` and refuses to run without `--i-have-authorization`.
- **Non-destructive by design.** No exploit payloads are fired, no files are
  written/dropped on targets, **no implant / persistence / C2 / worm / botnet-client
  code exists anywhere in the tool**, no credential dumping, no data exfiltration.
  Botnet-recruitability and persistence vectors are **reported as findings to fix**,
  never performed. Command-injection is proven with a benign `echo <nonce>` and
  nothing more; path traversal is matched on a signature and contents are not
  stored.
- **Bounded.** `webvuln` is rate-limited and hard-capped (e.g. ≤40 injection
  probes/host); `--rate` adds a global minimum interval.
- **Your targets only.** The tool acts solely on the IP(s) you specify.
- **Legal:** testing devices you don't own or lack written permission to test
  may be illegal. You are solely responsible for having authorization. Use this
  for your own equipment, learning, and authorized engagements only.

---

## Extending

Each capability is a self-contained function orchestrated by `scan_device`:

- Recon: `nmap_scan`/`python_scan`, `enum_http`, `ssdp_discover`,
  `fetch_upnp_descriptor`, `enum_dial`, `enum_roku`, `enum_rtsp`.
- CVE: `load_cve_db`, `collect_fingerprints`, `match_cves`, `nvd_online_lookup`.
- Footholds: `confirm_adb_foothold`, `run_webvuln` (`probe_auth_bypass`,
  `probe_path_traversal`, `probe_command_injection`, `probe_cve_endpoints`).
- Chaining: `synthesize_findings` + `build_assessment`.

Add a module by writing an `enum_*`/`probe_*` function and wiring it into
`scan_device`. Add ports to `IOT_PORTS`, paths to `HTTP_PATHS`, CVEs to
`cve_db.json`.

### Out of scope (needs a local radio/link)
- **Packet capture / Wireshark** and **Bluetooth/BLE** enumeration need a local
  interface and must run on a machine on the same link — this is an IP-network
  tool.
- **mDNS**: use `avahi-browse -a` / `dns-sd` on the local segment for deep
  service discovery.

---

## Bluetooth / BLE modules

These run off the **local host's Bluetooth adapter** (bluez), not a remote IP, so
they take no IP target. They degrade gracefully (report "tool/adapter required")
when bluez or a radio is missing.

| Flag | Tier | What it does |
|------|------|--------------|
| `--bt-scan` | auth | Classic Bluetooth discovery via `hcitool scan` (MAC, name, OUI vendor, discoverable flag). |
| `--ble-scan` | auth | BLE advertisement scan via `bluetoothctl` (or `hcitool lescan`); MAC, name, vendor. |
| `--gatt <MAC>` | **confirm** | Read-only GATT service/characteristic enumeration of a BLE device (connects, so gated behind `--confirm-footholds`). |
| `--gatt-write` | — | Acknowledges GATT writes are intrusive; writes are still never auto-performed. |
| `--bt-duration N` | — | Seconds to scan (default 10). |

**Deps:** bluez (`sudo apt install bluez`) for `bluetoothctl`/`hcitool`/`gatttool`.
`hcitool lescan` and some scans may need `sudo` / `CAP_NET_ADMIN`. Requires a local
Bluetooth adapter.

**Examples:**
```bash
python3 iotscan.py --bt-scan --i-have-authorization -o bt.json
python3 iotscan.py --ble-scan --bt-duration 20 --i-have-authorization
sudo python3 iotscan.py --gatt AA:BB:CC:DD:EE:FF --confirm-footholds --i-have-authorization
```

Results are written to the same JSON report under a `bluetooth` section, with a
severity-tagged console summary. Read-only by default; no pairing disruption, no
characteristic writes.
