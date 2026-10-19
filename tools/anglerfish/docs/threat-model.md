# Anglerfish threat model

## What it is

Anglerfish is a **multi-service deception sensor**. It listens on common
Internet-facing ports (SSH, HTTP/HTTPS, FTP, SMTP, telnet) and answers with
believable banners and a coherent fake machine (small-business NAS + deploy
host). Attackers who dig in find planted credentials and canary files; taking
them is itself the detection signal.

It is **not** a SIEM, WAF, or IDS. Cheap CloudWatch Logs metric filters and two
roll-up alarms sit on top of the structured event stream so an operator gets
paged when bait is taken — nothing more.

## Assets

| Asset | Sensitivity | Notes |
|---|---|---|
| Operator's real AWS account / VPC | High | Instance role must not reach anything outside `/anglerfish/*` |
| Admin SSH on a non-default port | High | Locked to `AdminCidr` (/32) |
| Planted credentials & canary tokens | Low (bait) | Intended to be stolen; never reused on real systems |
| Structured session logs | Medium | Off-host in CloudWatch Logs; may contain attacker payloads |
| Persona file | Medium | Identifies *this* install; keep out of git |

## Adversaries considered

1. **Mass scanners / botnets** (Mirai-class telnet sprays, credential lists).
   Expected volume; mostly noise. Logged, rarely alerted.
2. **Opportunistic humans** following a Shodan / Censys hit.
   Should see a coherent persona, a login that works, and bait worth taking.
3. **Careful humans / red teamers** probing for honeypot tells
   (thin TLS fingerprint, missing DSM surface, shared host keys across
   installs). Persona-per-install and install-time key minting are the main
   counters; some tells remain (see `red-blue-evaluation.md`).

## Hard line (containment)

> Bait and fabricated data may be reachable. There must be **no path to
> anything real**.

- Instance role: Deny outside `/anglerfish/*` (SSM params, S3, etc.).
- IMDSv2 required, hop limit 1 (blocks SSRF-to-IMDS via containers).
- No real credentials on the box. Planted passwords are random per install.
- Host egress guard (optional script) blocks the sensor UID from IMDS,
  admin SSH, and the rest of the VPC.
- Sandboxed File Station / fake shell never exec attacker input and never
  touch the real filesystem.

## Trust boundaries

```
Internet  --open-->  honeypot ports (22/80/443/21/25/23/…)
Admin /32 --only--->  real sshd (non-22)
Sensor UID -/deny/->  IMDS, VPC, admin port
Instance role -/deny/->  anything outside /anglerfish/*
```

## Out of scope

- Building C2, implants, or attack tooling.
- Putting Anglerfish in front of real services.
- Managed WAF/CDN in front (would hide the fingerprints the sensor is built to collect).
