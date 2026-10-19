# Anglerfish detection-rule spec

Rules over the structured events in `log-schema.md`. Each rule: name, trigger,
severity, CloudWatch Logs metric-filter pattern (where cheap), and a SIEM note.

Metric filters are free; two roll-up custom metrics (`AnglerfishCritical`,
`AnglerfishHighSignal`) keep you inside the always-free CloudWatch tier.

## Severity guide

| Sev | Meaning | Alarm |
|---|---|---|
| CRITICAL | Planted/org-themed credential used, or clear proof of a thinking adversary against the deception | Fire immediately (5-min window, threshold 1) |
| HIGH | High-signal indicator that separates a thinking adversary from bot noise | Fire when ≥5 hits in 1 hour |
| MEDIUM | Interesting but common (or needs correlation) | Log / dashboard; no SNS by default |
| LOW | Context for later analysis | Log only |

## Rules

### R1 — Planted / canary credential accepted (`auth_ok`)
- **Severity:** CRITICAL
- **Trigger:** `event == "auth" AND auth_ok == true`
- **Why:** With the rework, the fake NAS *grants a sandboxed File Station session* on planted/canary creds. `auth_ok=true` means the adversary got a real (contained) session — still fabricated bait, never a path to real data — and is the first half of the top-severity "bait taken" signal. Pair with R1b.
- **CW filter:** `{ $.event = "auth" && $.auth_ok IS TRUE }` → metric `AnglerfishCritical`
- **Legacy (until Red Team ships v2):** `{ $.auth_ok IS TRUE && $.peer_ip = "*" }` (session-end records)
- **SIEM:** `event:auth auth_ok:true`

### R1b — Bait / canary file taken (`path_read` / gotcha)
- **Severity:** CRITICAL (top alarm — higher priority than R1 alone)
- **Trigger:** `(event IN ("read-file","gotcha") AND path_read is set)` OR `(event == "gotcha")` OR (`auth_ok == true` on the same `session_id` as a subsequent `path_read` of bait/fake docs/AWS-key canaries)
- **Why:** Red Team's rework exposes sandboxed File Station (fake docs / planted AWS keys / bait). A sandboxed login *plus* reading bait is the cleanest "thinking adversary took the honey" signal — distinct from a mere cred-harvest attempt that fails.
- **CW filter (path_read present):** `{ ($.event = "read-file" || $.event = "gotcha") && $.path_read = "*" }` → `AnglerfishCritical`
- **CW filter (gotcha id):** *omitted in the shipped template* — the sensor emits `read-file` with `path_read`, not a standalone `event=gotcha`. Keep the `path_read` filter; add a gotcha filter only if you enable classroom reveal mode.
- **SIEM:** correlate `auth_ok:true` → `path_read:*` / `gotcha_id:*` on same `session_id` within 15 minutes; alert as **BAIT_TAKEN**.
- **Note:** Do not treat failed `auth_ok=false` harvest attempts the same way — those stay under R2 / R7.

### R2 — Org-themed credential guess
- **Severity:** CRITICAL
- **Trigger:** `event == "auth" AND (username OR password matches the operator's persona brand / company / domain tokens)`
- **Why:** An attacker guessing credentials themed to the fake company (not Mirai/hydra lists) is the cleanest "thinking adversary" signal.
- **CW filter:** build from your persona at deploy time, e.g. `{ $.event = "auth" && ($.username = %Example% || $.password = %Example% || $.password = %Clinic%) }` → `AnglerfishCritical`. Never commit the live brand into the shared template.
- **SIEM:** Extend the pattern with the persona company/domain tokens when the persona rotates.


### R3 — Synology DSM webapi / CGI hit
- **Severity:** HIGH
- **Trigger:** `event == "http" AND http_path matches /(webapi|webman)/`
- **Why:** Real Synology paths (`/webapi/query.cgi`, `auth.cgi`, `entry.cgi`, `/webman/login.cgi`) are what a targeted pass used. Generic scanners rarely hit these.
- **CW filter:** `{ $.event = "http" && $.http_path = %\/webapi\/|\/webman\/% }` → `AnglerfishHighSignal`
- **Legacy:** `{ $.first_bytes = %\/webapi\/|\/webman\/% && $.peer_ip = "*" }`
- **Bonus field:** when `syno_api` is present, alert on any non-empty value the same way.

### R4 — FTP protocol dialogue (beyond USER/PASS)
- **Severity:** HIGH
- **Trigger:** `event == "ftp" AND ftp_cmd IN (SYST, FEAT, STAT, SITE, HELP, AUTH, PASV, EPSV, LIST, RETR, STOR)`
- **Why:** Bots usually stop at USER/PASS. `SYST`/`FEAT`/`STAT` (and data-channel verbs) are the targeted-pass fingerprint.
- **CW filter:** `{ $.event = "ftp" && ($.ftp_cmd = "SYST" || $.ftp_cmd = "FEAT" || $.ftp_cmd = "STAT" || $.ftp_cmd = "SITE" || $.ftp_cmd = "HELP" || $.ftp_cmd = "AUTH" || $.ftp_cmd = "PASV" || $.ftp_cmd = "EPSV" || $.ftp_cmd = "LIST" || $.ftp_cmd = "RETR" || $.ftp_cmd = "STOR") }` → `AnglerfishHighSignal`

### R5 — Forged session material (sid / X-SYNO-TOKEN)
- **Severity:** HIGH
- **Trigger:** `event == "http" AND session_material_presented == true AND session_material_valid == false`
- **Why:** a targeted pass forged `sid` cookies and `X-SYNO-TOKEN` against `/files/*`. Needs the new schema fields.
- **CW filter:** `{ $.event = "http" && $.session_material_presented IS TRUE && $.session_material_valid IS FALSE }` → `AnglerfishHighSignal`
- **Fallback (pre-schema):** inspect `headers_of_interest.cookie` / `headers_of_interest.x-syno-token` in a SIEM; CW filters can't do nested-key regex cleanly.

### R6 — Path traversal
- **Severity:** MEDIUM (bump to HIGH if paired with a Synology path or a successful file read)
- **Trigger:** `event == "http" AND (http_path contains ".." OR uri_len-decoded path contains "etc/passwd" OR "%2e%2e")`
- **CW filter (partial — CW regex can't do char classes):** `{ $.event = "http" && $.http_path = %\.\.% }`
- **SIEM (preferred):** `http_path:(*..* OR *%2e%2e* OR *etc/passwd*)`
- **Correlate with:** `event == "read-file"` / `gotcha` on the same `session_id`.

### R7 — SQLi-as-credential
- **Severity:** MEDIUM
- **Trigger:** `event == "auth" AND (username OR password) matches /(OR.*=|--|UNION|sleep\(|benchmark\()/i`
- **CW filter:** `{ $.event = "auth" && ($.username = %OR.*=|--|UNION% || $.password = %OR.*=|--|UNION%) }` → can feed `AnglerfishHighSignal` if you want; default is log-only because SQLi-creds are common scanner noise.
- **Note:** A common scanner pass used `' OR '1'='1` in the web login — worth a dashboard tile, not a page.

### R8 — Long URI (≥ 2048 / 9000-char test)
- **Severity:** MEDIUM
- **Trigger:** `event == "http" AND uri_len >= 2048`
- **CW filter:** `{ $.event = "http" && $.uri_len >= 2048 }`
- **Why:** a targeted pass's 9000-char URI was lost to the 200-char capture cap. With `uri_len` we catch it even when `request_line` is truncated. Pair with nginx-accurate 414 responses Red Team is adding.

### R9 — Bad Host header
- **Severity:** LOW–MEDIUM
- **Trigger:** `event == "http" AND host_header is set AND host_header does NOT start with the public IP or the persona hostname`
- **CW filter (validated):** `{ $.event = "http" && $.host_header != "203.0.113.10*" && $.host_header != "<persona-hostname>*" && $.host_header = "*" }`
- **Caveat:** hard-codes today's IP/hostname. Prefer a SIEM rule that reads them from a lookup, or accept the drift when the instance is rebuilt.
- **Why:** a targeted pass's bad-Host test. Red Team is making nginx return the default-server page for these.

### R10a — TLS plaintext / non-TLS on 443 (`tls_fp_path=fallback`)
- **Severity:** HIGH
- **Trigger:** `event == "tls" AND tls_fp_path == "fallback"`
- **Why:** Red Team's sensor sets `tls_fp_path=fallback` when the ClientHello could not be parsed via the memory BIO path — typically plaintext-or-garbage on 443/8443 (scanners, misconfigured clients, or intentional non-TLS probes). Distinct from a clean `memory_bio` fingerprint.
- **CW filter:** `{ $.event = "tls" && $.tls_fp_path = "fallback" }` → `AnglerfishHighSignal`
- **Correlate:** often pairs with failed `tls_handshake_ok=false` and a populated `tls_error`.

### R10b — Missing or IP-literal SNI
- **Severity:** MEDIUM (bump HIGH if correlated with Synology paths or org-themed creds on the same session)
- **Trigger:** `event == "tls" AND (tls_sni is absent/empty OR tls_sni looks like an IPv4/IPv6 literal)`
- **Why:** Browsers and most legit clients send the persona hostname; scanners and scripted tools often omit SNI or put the raw IP. targeted-pass-style adaptive probes may still send IP SNI when hitting by address.
- **CW filter (absent):** `{ $.event = "tls" && $.tls_sni NOT EXISTS }` → log / dashboard (CW can't easily match "empty string" + IP regex in one cheap filter)
- **CW filter (IP-ish substring, partial):** `{ $.event = "tls" && $.tls_sni = %203.0.113.10% }` → useful as "connected by public IP SNI" tile, not SNS by default
- **SIEM (preferred):** `event:tls AND (NOT tls_sni:* OR tls_sni:/^\d+\.\d+\.\d+\.\d+$/)`

### R10c — JA3 / JA3S clustering (baseline then anomaly)
- **Severity:** LOW → MEDIUM once a 7-day baseline exists
- **Trigger:** `event == "tls" AND tls_ja3 is set AND tls_ja3 NOT IN <known-benign-or-known-scanner set>`
- **Fields (Red Team afbd1d4):** `tls_ja3` (MD5), `tls_ja3_str` (raw), `tls_ja3s` (exact), `tls_ja3s_str` (raw; TLS1.3 often `771,4866,43-51`), `tls_alpn` (client offered), `tls_alpn_selected` (negotiated), `tls_client_versions`, `tls_fp_path`, `tls_error`. Failed handshakes still carry JA3/SNI when ClientHello parsed.
- **CW:** no cheap anomaly filter — ship to SIEM / Athena / periodic Insights query. Example Insights:
  `fields tls_ja3, tls_sni, src_ip | filter event = "tls" and ispresent(tls_ja3) | stats count() as n by tls_ja3 | sort n desc`
- **Operator note:** first week = collect dominant JA3s (nmap, curl, browsers, RT tools). After that, alert on novel JA3s that also hit R3/R2/R1b.

### R11 — DNS version.bind / AXFR — future
- **Severity:** HIGH (once a DNS listener exists)
- **Trigger:** `event == "dns" AND (dns_qtype IN (AXFR, IXFR) OR dns_qname == "version.bind")`
- **CW (when live):** `{ $.event = "dns" && ($.dns_qtype = "AXFR" || $.dns_qtype = "IXFR" || $.dns_qname = "version.bind") }` → `AnglerfishHighSignal`
- **Today:** no DNS listener, so Pass 1's `version.bind`/AXFR probes left no evidence. Tracked as a redesign item.

## Alarm wiring (in the template diff)

| Alarm | Metric | Period | Threshold | SNS |
|---|---|---|---|---|
| `anglerfish-detect-critical` | `anglerfish/detections` / `AnglerfishCritical` | 300 s | ≥ 1 | `anglerfish-alerts` |
| `anglerfish-detect-high-signal` | `anglerfish/detections` / `AnglerfishHighSignal` | 3600 s | ≥ 5 | `anglerfish-alerts` |

`TreatMissingData: notBreaching` on both. `EnableLogAlarms=false` disables them without removing the filters (filters stay free and keep publishing metrics for dashboards).

## What stays out of scope (cost)

- No GuardDuty, no Security Hub, no OpenSearch/ELK, no Kinesis/Firehose, no Lambda subscribers, no third-party SIEM subscription.
- No per-rule alarms (that would burn the free-tier alarm budget). Two roll-up alarms are enough for a single honeypot.
- Metric filters on `STANDARD` log class only — `INFREQUENT_ACCESS` is cheaper to store but **does not support metric filters**, so we stay on STANDARD and keep retention at 30 days.

## Operator cheatsheet (after deploy)

```bash
# Live tail
aws logs tail /anglerfish/sessions --follow --region us-east-1

# Last critical hits
aws logs filter-log-events --region us-east-1 \
  --log-group-name /anglerfish/sessions \
  --filter-pattern '{ $.event = "auth" && $.auth_ok IS TRUE }' \
  --start-time $(( ($(date +%s) - 86400) * 1000 ))
```
