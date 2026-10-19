# anglerfish log field schema (Blue Team → Red Team)

**Machine-readable companion:** `log-schema.json` (JSON Schema draft 2020-12).
**Target file on the box:** `/opt/anglerfish/log/events.jsonl` (one JSON object per line, written immediately).
**Legacy file kept:** `/opt/anglerfish/log/sessions.log` (one session object per line at close) — still shipped, but detection prefers the new stream.
**Schema version:** `"2"` (include as `schema_version`).

This extends the fields already visible in tonight's `/opt/anglerfish/log/sessions.log` (id, sensor, peer_ip, peer_port, local_port, started, protocol, service, events[{at,kind,detail}], credentials[{username,password,service}], first_bytes, auth_ok, ssh_client, hassh, pubkeys, ended, duration, credential_count). We rename a few for SIEM clarity and add the fields the joint log review showed were missing.

## Non-negotiable rules for Red Team

1. **Write each event immediately** as its own JSON line. Do not buffer until session end. Detection + shipping depend on this.
2. **`ts` is the first key** and is ISO8601 UTC with millisecond precision and a trailing `Z` (e.g. `2026-10-18T18:45:01.123Z`). The CloudWatch agent parses it.
3. **Raise the capture cap from 200 chars to ≥ 2048.** Keep a separate true-length counter so long-URI tests are never lost.
4. **Never execute or interpret captured attacker input.** Log it, escape it, ship it.
5. **Unknown keys are allowed** (forward-compatible). Keep any single line under 200 KB.
6. Attacker bytes that aren't valid UTF-8: either escape as `\xNN` in a UTF-8 string, or hex-encode and set the matching `*_encoding` to `"hex"`.

## Envelope (every event)

| Key | Type | Notes |
|---|---|---|
| `ts` | string | ISO8601 UTC ms, `Z`. **First key.** |
| `schema_version` | string | `"2"` |
| `sensor` | string | Existing sensor name |
| `host` | string | Persona hostname (`files01`) |
| `event` | string | See enum below |
| `service` | string | `ssh` \| `http` \| `https` \| `ftp` \| `telnet` \| `smtp` \| `dns` \| `sandbox` |
| `transport` | string | `tcp` (default) \| `udp` |
| `src_ip` | string | = legacy `peer_ip` |
| `src_port` | int | = legacy `peer_port` |
| `dst_port` | int | **Public** facade port the attacker hit (22/80/443/21/23/25/53), pre-REDIRECT |
| `listen_port` | int | Local sensor port (2222/8080/…) = legacy `local_port` |
| `session_id` | string | = legacy session `id` |
| `seq` | int | 0-based event index within the session |
| `tls` | bool | Connection was TLS-wrapped |
| `tags` | string[] | Optional sensor hints; detection does **not** rely on them |

### `event` enum

`session-start` `session-end` `probe` `first-bytes` `http` `http-body` `ftp` `smtp` `telnet` `ssh-client` `ssh-kex` `ssh-hassh` `ssh-reject` `ssh-pubkey` `ssh-command` `auth` `read-file` `tls` `dns` `gotcha` `guestbook` `auth-slowdown` `tarpit`

## Per-event detail keys (flat — no nesting)

### first-bytes (raise the 200-char cap)

| Key | Type | Notes |
|---|---|---|
| `first_bytes` | string | Up to **2048** chars (was ~120 bytes / 200 chars) |
| `first_bytes_encoding` | string | `utf8` \| `hex` |
| `first_bytes_len` | int | **True** length before truncation |
| `first_bytes_truncated` | bool | |

### http / http-body

| Key | Type | Notes |
|---|---|---|
| `http_method` | string | |
| `http_path` | string | Path only, no query |
| `http_query` | string | Raw query (no leading `?`) |
| `http_version` | string | |
| `host_header` | string | |
| `user_agent` | string | |
| `referer` | string | |
| `content_type` | string | |
| `content_length` | int | |
| `uri_len` | int | **True** length of request-target (path+?+query) before truncation — so 9000-char URI tests aren't lost |
| `request_line` | string | First request line, capped at 2048 |
| `request_line_truncated` | bool | |
| `headers_of_interest` | object | Subset: `cookie`, `x-syno-token`, `authorization`, `x-forwarded-for`, `origin`, `accept` |
| `body_len` | int | |
| `body_first_bytes` | string | First 512 bytes of body |
| `body_encoding` | string | `utf8` \| `hex` |
| `http_status` | int | Status we returned |
| `response_bytes` | int | |
| `session_material_presented` | bool | Any of: Cookie `sid=`, `X-SYNO-TOKEN`, `Authorization SynoToken` |
| `session_material_valid` | bool | `false` when forged / unknown |
| `session_cookie` | string | |
| `syno_token` | string | |
| `syno_api` | string | Parsed `api=` query value (e.g. `SYNO.API.Info`) |
| `syno_method` | string | Parsed `method=` |
| `syno_version` | string | |

### ftp / smtp / telnet

| Key | Type | Notes |
|---|---|---|
| `ftp_cmd` | string | Verb only: `USER` `PASS` `SYST` `FEAT` `STAT` `SITE` `HELP` `QUIT` `PWD` `CWD` `LIST` `RETR` `STOR` `PASV` `EPSV` `PORT` `AUTH` `TYPE` … |
| `ftp_arg` | string | Arg after verb, capped at 512 |
| `ftp_reply_code` | int | |
| `smtp_cmd` / `smtp_arg` / `smtp_reply_code` | | Same pattern |
| `telnet_line` | string | |

### ssh-*

| Key | Type | Notes |
|---|---|---|
| `ssh_client_version` | string | `SSH-2.0-…` banner |
| `ssh_kex_algs` | string[] | |
| `ssh_host_key_algs` | string[] | |
| `ssh_enc_algs_ctos` | string[] | |
| `ssh_mac_algs_ctos` | string[] | |
| `ssh_comp_algs_ctos` | string[] | |
| `hassh` | string | HASSH MD5 |
| `ssh_pubkey_type` / `ssh_pubkey_fp` | string | |
| `ssh_command` | string | Requested exec/shell (never run) |

### auth (replaces login-user / login-pass / login-result)

| Key | Type | Notes |
|---|---|---|
| `username` | string | |
| `password` | string | |
| `auth_ok` | bool | `true` **only** when a planted credential matched |
| `cred_source` | string | `ssh-password` \| `ssh-pubkey` \| `http-form` \| `http-basic` \| `http-syno-api` \| `ftp-userpass` \| `telnet-userpass` \| `smtp-auth` \| `other` |
| `auth_method` | string | Optional finer grain |

### tls (structured — Red Team afbd1d4+)

| Key | Type | Notes |
|---|---|---|
| `tls_version` | string | `TLSv1.2` / `TLSv1.3` |
| `tls_cipher` | string | |
| `tls_sni` | string | Server Name Indication; may be absent, hostname, or IP literal |
| `tls_alpn` | array/string | Client-offered ALPN list |
| `tls_alpn_selected` | string | Negotiated ALPN |
| `tls_ja3` | string | JA3 MD5 |
| `tls_ja3_str` | string | Raw JA3 string before hash |
| `tls_ja3s` | string | JA3S (exact); TLS1.3 often looks like `771,4866,43-51` |
| `tls_ja3s_str` | string | Raw JA3S string |
| `tls_client_versions` | array/string | Client-advertised versions from ClientHello |
| `tls_fp_path` | string | `memory_bio` (full parse) \| `fallback` (plaintext/garbage on 443 — high signal) |
| `tls_error` | string | Handshake / parse error if any; failed handshakes may still carry JA3/SNI |
| `tls_cert_fp_sha256` | string | SHA-256 of the leaf we presented |
| `tls_handshake_ok` | bool | |

### dns (new — for a future DNS listener)

| Key | Type | Notes |
|---|---|---|
| `dns_qname` | string | |
| `dns_qtype` | string | `A` `AAAA` `TXT` `MX` `SOA` `NS` `ANY` `AXFR` `version.bind` |
| `dns_opcode` | string | |
| `dns_rcode` | string | |
| `dns_id` | int | |

### session-end / gotcha / guestbook / tarpit

| Key | Type | Notes |
|---|---|---|
| `duration_s` `bytes_in` `bytes_out` `event_count` `credential_count` | | session-end |
| `close_reason` | string | `client-close` \| `idle-timeout` \| `tarpit` \| `protocol-error` \| `limit` \| `server-close` |
| `path_read` `gotcha_id` `guestbook_note` | | |
| `tarpit_ms` `tarpit_reason` | | |

## Key list (paste to Red Team)

```
ts schema_version sensor host event service transport
src_ip src_port dst_port listen_port session_id seq tls tags
duration_s bytes_in bytes_out event_count credential_count close_reason
first_bytes first_bytes_encoding first_bytes_len first_bytes_truncated
http_method http_path http_query http_version host_header user_agent referer
content_type content_length uri_len request_line request_line_truncated
headers_of_interest body_len body_first_bytes body_encoding
http_status response_bytes
session_material_presented session_material_valid session_cookie syno_token
syno_api syno_method syno_version
ftp_cmd ftp_arg ftp_reply_code smtp_cmd smtp_arg smtp_reply_code telnet_line
ssh_client_version ssh_kex_algs ssh_host_key_algs ssh_enc_algs_ctos
ssh_mac_algs_ctos ssh_comp_algs_ctos hassh ssh_pubkey_type ssh_pubkey_fp ssh_command
username password auth_ok cred_source auth_method
tls_version tls_cipher tls_sni tls_alpn tls_alpn_selected tls_ja3 tls_ja3_str tls_ja3s tls_ja3s_str tls_client_versions tls_fp_path tls_error tls_cert_fp_sha256 tls_handshake_ok
dns_qname dns_qtype dns_opcode dns_rcode dns_id
path_read gotcha_id guestbook_note tarpit_ms tarpit_reason
```

## Mapping from tonight's legacy session record

| Legacy | New |
|---|---|
| `id` | `session_id` |
| `peer_ip` / `peer_port` / `local_port` | `src_ip` / `src_port` / `listen_port` (+ new `dst_port` = public facade) |
| `started` (unix float) | `ts` (ISO8601) on every event; `session-start` / `session-end` bookends |
| `events[].{at,kind,detail}` | One line per event; `kind` → `event`; `detail` split into typed keys |
| `credentials[]` | One `auth` event per try, with `username` `password` `auth_ok` `cred_source` |
| `first_bytes` (≤200 chars) | `first_bytes` (≤2048) + `first_bytes_len` + `first_bytes_truncated` |
| `auth_ok` (session bool) | Per-try `auth_ok` on each `auth` event; session-end still can roll up |
| `ssh_client` / `hassh` | `ssh_client_version` / `hassh` on `ssh-client` / `ssh-hassh` events |
| (missing) | `tls_*`, `dns_*`, `uri_len`, `session_material_*`, `syno_*`, `host_header`, `headers_of_interest` |

## Example lines

```json
{"ts":"2026-10-18T18:42:11.204Z","schema_version":"2","sensor":"sensor","host":"files01","event":"http","service":"https","transport":"tcp","src_ip":"203.0.113.50","src_port":53122,"dst_port":443,"listen_port":8443,"session_id":"sensor-1760823731-12","seq":3,"tls":true,"http_method":"GET","http_path":"/webapi/query.cgi","http_query":"api=SYNO.API.Info&version=1&method=query","uri_len":58,"host_header":"203.0.113.10","syno_api":"SYNO.API.Info","syno_method":"query","http_status":200,"session_material_presented":false}
{"ts":"2026-10-18T18:43:02.010Z","schema_version":"2","sensor":"sensor","host":"files01","event":"auth","service":"ssh","src_ip":"198.51.100.50","src_port":44112,"dst_port":22,"listen_port":2222,"session_id":"sensor-1760823782-44","seq":5,"username":"example.admin","password":"Clinic2026!","auth_ok":false,"cred_source":"ssh-password"}
{"ts":"2026-10-18T18:43:15.500Z","schema_version":"2","sensor":"sensor","host":"files01","event":"ftp","service":"ftp","src_ip":"192.0.2.50","src_port":50210,"dst_port":21,"listen_port":2121,"session_id":"sensor-1760823795-7","seq":2,"ftp_cmd":"SYST","ftp_reply_code":215}
{"ts":"2026-10-18T18:44:01.000Z","schema_version":"2","sensor":"sensor","host":"files01","event":"tls","service":"https","src_ip":"203.0.113.50","src_port":53122,"dst_port":443,"listen_port":8443,"session_id":"sensor-1760823731-12","seq":1,"tls":true,"tls_version":"TLSv1.3","tls_cipher":"TLS_AES_256_GCM_SHA384","tls_sni":"203.0.113.10","tls_alpn":["http/1.1"],"tls_alpn_selected":"http/1.1","tls_ja3":"…","tls_ja3_str":"771,…","tls_ja3s":"771,4866,43-51","tls_fp_path":"memory_bio","tls_handshake_ok":true,"tls_cert_fp_sha256":"ab…"}
```
