# Red vs Blue evaluation (sanitized)

Independent ratings of a live Anglerfish deployment after the deception
rework. Numbers are aggregate and scrubbed — no live IPs, account IDs, or
persona strings.

## Scores

| Team | Overall | Notes |
|---|---|---|
| Red Team | **8/10** (was ~6.5) | containment 9 · cover/deception 7.5 · detection-feed 8.5 |
| Blue Team | **8/10** (was ~5.5 on detection/logging) | detection 8 · logging 8 · containment 9 · resilience 7.5 · cost 9.5 |

## What improved

- **Containment.** Winning the honeypot only harvests canaries. IMDSv2 hop=1,
  instance role Deny outside `/anglerfish/*`, bait is sandboxed.
- **Cover.** Coherent persona + host keys + TLS cert per install; Synology DSM
  webapi/login SPA; nginx/OpenSSH banners; planted-cred → FileStation →
  `path_read` bait chain (R1b BAIT_TAKEN).
- **Detection feed.** JA3/JA3S/SNI/ALPN + HASSH + `events.jsonl`; failed-hello
  still fingerprinted; plaintext-on-443 → `tls_fp_path=fallback`. Off-host
  CloudWatch shipping with two roll-up alarms.

## Remaining tells (honest)

1. TLS↔HTTP session join is weak (pair by `src_ip+src_port` until `session_id`
   is bound across both).
2. Stdlib Python HTTPS / ALPN http/1.1-only / no HTTP2 — fine for an
   "nginx without http2" story, but JA3S diversity on TLS1.3 is low.
3. SSH algorithm/timing profile is thinner than a real OpenSSH for the
   claimed banner (no tarpit / alternate KEX in this release).
4. DSM surface is webapi + login SPA + sandboxed File Station; deeper
   FileBrowser behaviour beyond the bait path thins out.
5. Some CDN/egress paths drop hostname-SNI before arrival — operator network
   issue, not a honeypot tell, but it means some clients never exercise the
   SNI path you log.

## Priority improvements

1. Bind TLS ↔ HTTP under one `session_id`.
2. Thicken post-login DSM bait (more files/shares/canary docs) without real exec.
3. SSH algorithm/timing closer to the claimed OpenSSH version.
4. Optional JA4 (pure-Python, carefully reviewed) — low priority vs 1–3.
5. Keep cost flat — no managed WAF/CDN in front.

## Early wild traffic (first ~33h, aggregate)

- **~21,000** sessions from **~320** source IPs
- **~96%** telnet (Mirai-class credential sprays)
- SSH quiet relative to telnet; web traffic includes secrets/AI-config hunting
  and Synology/ProxyShell/HNAP/GPON-shaped probes
- **Zero** wild compromises of anything real (by design: nothing real to reach)

Exact attacker IPs, the live persona, and account identifiers are intentionally
omitted from this public write-up.
