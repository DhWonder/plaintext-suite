"""
The valuable-looking content that makes an attacker stay.

A honeypot that answers a knock and nothing else tells you somebody scanned
you. A honeypot that looks like a real machine with real secrets on it tells
you far more: what they go for first, what tools they use, what they try to
steal, and, through the tokens planted in that content, where they turn up
next.

This builds one coherent machine: a small organisation's internal file-share
and deploy host. The identity (company, hostname, domain, NAS model, banners,
bait names) comes from the operator's persona file (config/persona.yaml); the
built-in default is the public, fictional "Example Clinic" on example.net and
must not be exposed to the internet. Every company-flavoured string (bucket,
image, SSID, vault key) is derived from that one identity so two names never
share a box. Same hostname, banners, NAS title, process list, mail, and configs
everywhere. The web File Station and the fake shell read the same lived-in tree.

Planted logins are split across bait the way a careless admin would leave them
— never all in one file:

  - planted_logins[0] (deploy-style)  →  docker-compose under the NAS web root
  - planted_logins[1] (admin-style)   →  a mail draft in admin's mailbox
  - admin / <canary>                  →  the IT handover note only

Planted passwords are minted at random per install (persona.py); the repo
contains none. Every other secret is either a canary token from tokens.py or
derived from the per-install seed, so no two installs share a bait string.
"""

import base64
import codecs
import os
import re
import time
from urllib.parse import quote

from . import tokens

import hashlib
import hmac
import random
import struct
import zlib

# One identity, used by banners, web title, shell, mail, and configs.
# Defaults are the public EXAMPLE persona; real installs override them from
# the operator's persona file via apply_persona().
HOSTNAME = "files01"
COMPANY = "Example Clinic"
DOMAIN = "example.net"
FQDN = "%s.%s" % (HOSTNAME, DOMAIN)
NAS_MODEL = "DS220+"
NAS_FIRMWARE = "7.2.1-69057"
INTERNAL_IP = "10.0.0.21"
# Region the bait claims the box lives in. Should match where it is deployed.
AWS_REGION = "us-east-1"
STAFF = "Sam"
# Service banners (generic, widely-deployed versions; configurable).
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
HTTP_SERVER = "nginx/1.18.0 (Ubuntu)"
FTP_BANNER = "220 {fqdn} FTP server (vsftpd 3.0.5) ready."
SMTP_BANNER = "220 {fqdn} ESMTP Postfix (Ubuntu)"
LURE_PATH = "/finance/{year}/payroll-master.xlsx"
DEFAULT_VAULT_IMG = "password-vault-export.png"
DEFAULT_CREDS_IMG = "domainadmin-creds-backup.png"
VAULT_IMG = DEFAULT_VAULT_IMG
CREDS_IMG = DEFAULT_CREDS_IMG
ASSETS_DIR = ""
# Per-install seed for derived bait strings (process-random without a persona).
SEED = os.urandom(16).hex()


def _derived(label, length=16, alphabet="0123456789abcdef"):
    """Deterministic per-install filler secret (not a canary, just not shared)."""
    out = []
    counter = 0
    while len(out) < length:
        digest = hmac.new(SEED.encode(), ("%s:%d" % (label, counter)).encode(),
                          hashlib.sha256).digest()
        out.extend(alphabet[b % len(alphabet)] for b in digest)
        counter += 1
    return "".join(out[:length])


def _rng(label):
    return random.Random("%s:%s" % (SEED, label))


def _brand(company=None):
    """First word of the company name: 'Example Clinic' -> 'Example'."""
    words = (company or COMPANY or "Files").split()
    return re.sub(r"[^A-Za-z0-9]", "", words[0]) or "Files"


def _domain_label(domain=None):
    """'example.net' -> 'example' (used for bucket / image names)."""
    return ((domain or DOMAIN or "files").split(".")[0]).lower()


def _initials(company=None):
    words = [w for w in (company or COMPANY or "F").split() if w[:1].isalpha()]
    return ("".join(w[0] for w in words[:2]) or "F").capitalize()


def backup_bucket(domain=None):
    return "%s-nas-backups" % _domain_label(domain)


def vault_key(company=None):
    return "%s-Vault-2025-Staging!\n" % _initials(company)

# Post-auth only. Never put this on MOTD, login pages, or public /api.
# Plaintext form is for tests/docs; bait files carry obfuscated encodings of it.
# Resolves to a dead internal-looking file-server link; the real "gotcha" is
# the download being logged, not where it points.
LURE_URL = "https://files.%s%s" % (DOMAIN, LURE_PATH.replace("{year}", time.strftime("%Y")))


def _mint_default_logins():
    from .persona import mint_password
    return (("deploy", mint_password(_brand(COMPANY))), ("admin", mint_password()))


# The only logins that open the fake shell / NAS (plus the canary from bait).
# Minted at random: per process here, per install (persisted) with a persona.
PLANTED_LOGINS = _mint_default_logins()

# Where each planted password lives in the bait tree (for docs and tests).
PLANT_LOCATIONS = {
    "deploy": "/var/www/nas/docker-compose.yml",
    "admin": "/home/admin/Mail/Drafts/re-nas-access.txt",
    "canary_admin": "/home/deploy/notes/it-handover.txt",
}


def planted_password_map():
    """username -> password for every fixed planted login."""
    return dict(PLANTED_LOGINS)


_IDENTITY_KEYS = {
    "HOSTNAME": "hostname", "COMPANY": "company", "DOMAIN": "domain",
    "NAS_MODEL": "nas_model", "NAS_FIRMWARE": "nas_firmware",
    "INTERNAL_IP": "internal_ip", "AWS_REGION": "aws_region", "STAFF": "staff_name",
    "SSH_BANNER": "ssh_banner", "HTTP_SERVER": "http_server",
    "FTP_BANNER": "ftp_banner", "SMTP_BANNER": "smtp_banner",
    "LURE_PATH": "lure_path", "VAULT_IMG": "vault_image",
    "CREDS_IMG": "creds_image", "ASSETS_DIR": "assets_dir",
}
# Frozen at import so apply_persona can restore after a persona-driven build.
_DEFAULTS = dict((k, globals()[k]) for k in _IDENTITY_KEYS)
_DEFAULTS.update({"PLANTED_LOGINS": PLANTED_LOGINS, "SEED": SEED})


def apply_persona(persona):
    """Override the module-level identity from a persona dict, or restore defaults."""
    g = globals()
    persona = persona or {}
    for name, key in _IDENTITY_KEYS.items():
        g[name] = persona.get(key) or _DEFAULTS[name]
    g["FQDN"] = persona.get("fqdn") or ("%s.%s" % (g["HOSTNAME"], g["DOMAIN"]))
    g["LURE_URL"] = "https://files.%s%s" % (
        g["DOMAIN"], g["LURE_PATH"].replace("{year}", time.strftime("%Y")))
    g["SEED"] = persona.get("canary_seed") or _DEFAULTS["SEED"]
    logins = persona.get("planted_logins")
    if logins and len(logins) >= 2:
        g["PLANTED_LOGINS"] = tuple((str(u), str(p)) for u, p in logins)
    else:
        g["PLANTED_LOGINS"] = _DEFAULTS["PLANTED_LOGINS"]


def ftp_banner():
    return FTP_BANNER.replace("{fqdn}", FQDN)


def smtp_banner():
    return SMTP_BANNER.replace("{fqdn}", FQDN)


def _rename_images(fs):
    """Apply configured bait image names to paths and text that mention them."""
    pairs = [(DEFAULT_VAULT_IMG, VAULT_IMG), (DEFAULT_CREDS_IMG, CREDS_IMG)]
    pairs = [(a[:-4], b[:-4] if b.endswith(".png") else b) for a, b in pairs if a != b]
    if not pairs:
        return fs
    out = {}
    for path, content in fs.items():
        for old, new in pairs:
            path = path.replace(old, new)
            if isinstance(content, str):
                content = content.replace(old, new)
        out[path] = content
    return out


def build(console_host="", sensor_name="", persona=None, classroom=False):
    """Assemble a full fake machine, and the list of tokens planted in it.

    Returns (filesystem, planted_tokens). The filesystem is a flat map of path
    to file, which the sensor serves. planted_tokens is what the console needs
    to recognise a trigger later.

    persona: optional dict from persona.load_or_create(); when omitted the
    built-in public example persona is used (tests / classroom demos only).
    classroom: when True, leave the playful GOTCHA prompts in bait comments;
    when False (default for production), scrub them.
    """
    apply_persona(persona)
    planted = []

    def token(kind, label):
        t = tokens.make(kind, label, console_host=console_host, sensor=sensor_name)
        planted.append(t)
        return t

    aws = token("aws", "AWS keys in deploy .env")
    db = token("connstring", "database connection string")
    vpn_pass = token("password", "VPN profile password")
    admin_pass = token("password", "admin password in IT note")
    backup_key = token("aws", "backup bucket keys")
    portal = token("url", "internal portal link")
    # The console usually sits on loopback (127.0.0.1:8770). A raw loopback
    # monitoring port in an admin's notes is a tell, so dress the displayed
    # link as the company intranet SSO. The token id (and /t/<id>) is kept so
    # the console still matches it in recorded sessions.
    _host = (console_host or "").split(":", 1)[0]
    if _host in ("127.0.0.1", "localhost", "::1", ""):
        portal["value"] = "https://intranet.%s/sso/t/%s" % (DOMAIN, portal["id"])

    deploy_user, deploy_pass = PLANTED_LOGINS[0]
    admin_user, admin_pass_fixed = PLANTED_LOGINS[1]

    # Canary from the handover note also opens shell/NAS. Fixed plants do too.
    logins = list(PLANTED_LOGINS) + [("admin", admin_pass["value"])]

    fs = {}

    # --- system identity --------------------------------------------------
    fs["/etc/passwd"] = _passwd()
    fs["/etc/group"] = _group()
    fs["/etc/hostname"] = HOSTNAME + "\n"
    fs["/etc/hosts"] = _hosts()
    fs["/etc/os-release"] = _os_release()
    fs["/etc/motd"] = _motd()
    fs["/etc/issue"] = "Ubuntu 22.04.4 LTS \\n \\l\n"
    fs["/etc/resolv.conf"] = "nameserver 10.0.0.2\nnameserver 1.1.1.1\n"
    fs["/etc/ssh/sshd_config"] = _sshd_config()
    fs["/etc/postfix/main.cf"] = _postfix_main()
    fs["/etc/nas/device.conf"] = _nas_device_conf()
    fs["/etc/nas/shares.conf"] = _nas_shares_conf()

    # --- logs that look lived-in ------------------------------------------
    fs["/var/log/auth.log"] = _auth_log()
    fs["/var/log/syslog"] = _syslog()
    fs["/var/log/nginx/access.log"] = _nginx_access()
    fs["/var/log/mail.log"] = _mail_log()

    # --- app + NAS web root (the hosted service) --------------------------
    fs["/var/www/app/.env"] = _env_file(aws, db)
    fs["/var/www/app/config/database.yml"] = _database_yml(db)
    fs["/var/www/app/README.md"] = _app_readme()

    fs["/var/www/nas/README.txt"] = _nas_readme()
    fs["/var/www/nas/docker-compose.yml"] = _docker_compose(deploy_user, deploy_pass)
    fs["/var/www/nas/.env.example"] = _nas_env_example()
    fs["/var/www/nas/www/index.html"] = _nas_static_hint()

    # --- deploy home ------------------------------------------------------
    fs["/home/deploy/.bash_history"] = _bash_history(portal)
    fs["/home/deploy/.bashrc"] = _bashrc()
    fs["/home/deploy/.profile"] = "# ~/.profile\n. ~/.bashrc\n"
    fs["/home/deploy/.ssh/config"] = _ssh_config()
    fs["/home/deploy/backup.sh"] = _backup_script(backup_key)
    fs["/home/deploy/notes/it-handover.txt"] = _handover_note(
        admin_pass, portal, deploy_user)
    fs["/home/deploy/notes/todo.txt"] = _todo_note()
    # Post-auth vault + obfuscated loot pointers (local copies and link forms).
    fs["/home/deploy/notes/vault-staging.b64"] = _vault_staging()
    fs["/home/deploy/notes/.vault-key"] = _vault_key()
    fs["/home/deploy/notes/vault-cleartext.txt"] = _vault_cleartext()
    # Recoverable local images (File Station + shell).
    fs["/home/deploy/notes/password-vault-export.png"] = _asset_bytes("password-vault-export.png")
    fs["/home/deploy/notes/domainadmin-creds-backup.png"] = _asset_bytes("domainadmin-creds-backup.png")
    # Obfuscated / split / remote-only forms of the same lure + credential-screenshot crumbs.
    for path, content in _obfuscated_plants(
            fs["/home/deploy/notes/password-vault-export.png"],
            fs["/home/deploy/notes/domainadmin-creds-backup.png"]).items():
        fs[path] = content
    fs["/home/deploy/customers_export.csv"] = _customers_csv()
    fs["/home/deploy/office-vpn.ovpn"] = _vpn_profile(vpn_pass)
    fs["/home/deploy/shares/README.txt"] = (
        "%s shared folders are exported by the NAS UI on :80.\n"
        "Local mirrors live under /srv/shares/.\n" % COMPANY
    )

    # --- admin home (mail draft plants the fixed admin password) ---------------------
    fs["/home/admin/.bashrc"] = _bashrc()
    fs["/home/admin/.profile"] = "# ~/.profile\n. ~/.bashrc\n"
    fs["/home/admin/Mail/Drafts/re-nas-access.txt"] = _mail_draft_admin(
        admin_user, admin_pass_fixed)
    fs["/home/admin/Mail/Inbox/welcome-to-nas.txt"] = _mail_inbox()

    # --- shared folders the NAS "hosts" -----------------------------------
    fs["/srv/shares/IT/it-handover.txt"] = fs["/home/deploy/notes/it-handover.txt"]
    fs["/srv/shares/IT/runbook.md"] = _runbook()
    fs["/srv/shares/IT/vault-staging.b64"] = fs["/home/deploy/notes/vault-staging.b64"]
    fs["/srv/shares/IT/password-vault-export.png"] = fs["/home/deploy/notes/password-vault-export.png"]
    fs["/srv/shares/IT/domainadmin-creds-backup.png"] = fs["/home/deploy/notes/domainadmin-creds-backup.png"]
    fs["/srv/shares/IT/verify.b64.txt"] = fs["/home/deploy/notes/verify.b64.txt"]
    fs["/srv/shares/IT/drop-channel.hex"] = fs["/home/deploy/notes/drop-channel.hex"]
    fs["/srv/shares/IT/domainadmin-creds-backup.recovery.txt"] = fs["/home/deploy/notes/domainadmin-creds-backup.recovery.txt"]
    fs["/srv/shares/Customers/customers_export.csv"] = fs["/home/deploy/customers_export.csv"]
    fs["/srv/shares/Customers/README.txt"] = (
        "Customer exports. Confidential. Do not email outside %s.\n" % COMPANY
    )
    fs["/srv/shares/Deploy/docker-compose.yml"] = fs["/var/www/nas/docker-compose.yml"]
    fs["/srv/shares/Deploy/app.env"] = fs["/var/www/app/.env"]
    fs["/srv/shares/Deploy/backup.sh"] = fs["/home/deploy/backup.sh"]
    fs["/srv/shares/Office/office-vpn.ovpn"] = fs["/home/deploy/office-vpn.ovpn"]
    fs["/srv/shares/Office/wifi-guest.txt"] = (
        "Guest Wi-Fi (office lobby)\n"
        "SSID: %s-Guest\n"
        "Key:  ask reception — rotated Mondays\n" % _brand()
    )

    # --- root crumbs ------------------------------------------------------
    fs["/root/.ssh/authorized_keys"] = _authorized_keys()
    fs["/root/.bash_history"] = _root_history()
    fs["/root/.mysql_history"] = _mysql_history()

    fs = _rename_images(fs)
    directories = _directories_for(fs)
    shares = _share_index(fs)

    return {
        "hostname": HOSTNAME,
        "fqdn": FQDN,
        "company": COMPANY,
        "domain": DOMAIN,
        "nas_model": NAS_MODEL,
        "nas_firmware": NAS_FIRMWARE,
        "internal_ip": INTERNAL_IP,
        "files": fs,
        "dirs": directories,
        "shares": shares,
        "tokens": planted,
        "logins": logins,
        "plant_locations": dict(PLANT_LOCATIONS),
        "canary_admin_password": admin_pass["value"],
        "classroom": bool(classroom),
        "built": time.time(),
    }, planted


# ---------------------------------------------------------------------------
# Share index for the NAS File Station (same tree the shell can cat).
# ---------------------------------------------------------------------------
def _share_index(files):
    """Map share name -> list of {name, path, size} for files under /srv/shares."""
    shares = {}
    prefix = "/srv/shares/"
    for path, content in files.items():
        if not path.startswith(prefix):
            continue
        rest = path[len(prefix):]
        if "/" not in rest:
            continue
        share, name = rest.split("/", 1)
        if "/" in name:
            # keep nested as flat name with slashes for simplicity
            pass
        shares.setdefault(share, []).append({
            "name": name,
            "path": path,
            "size": len(content if isinstance(content, (bytes, bytearray)) else content.encode("utf-8")),
        })
    for share in shares:
        shares[share].sort(key=lambda row: row["name"])
    return shares


# ---------------------------------------------------------------------------
# The files.
# ---------------------------------------------------------------------------
def _passwd():
    return (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "sync:x:4:65534:sync:/bin:/bin/sync\n"
        "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
        "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
        "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
        "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
        "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n"
        "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n"
        "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
        "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n"
        "irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n"
        "gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n"
        "systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\n"
        "systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\n"
        "messagebus:x:103:106::/nonexistent:/usr/sbin/nologin\n"
        "syslog:x:104:110::/home/syslog:/usr/sbin/nologin\n"
        "_apt:x:105:65534::/nonexistent:/usr/sbin/nologin\n"
        "tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false\n"
        "uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin\n"
        "tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin\n"
        "sshd:x:109:65534::/run/sshd:/usr/sbin/nologin\n"
        "pollinate:x:110:1::/var/cache/pollinate:/bin/false\n"
        "landscape:x:111:115::/var/lib/landscape:/usr/sbin/nologin\n"
        "fwupd-refresh:x:112:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin\n"
        "postfix:x:113:117::/var/spool/postfix:/usr/sbin/nologin\n"
        "postgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
        "deploy:x:1001:1001:deploy,,,:/home/deploy:/bin/bash\n"
        "admin:x:1002:1002:%s admin,,,:/home/admin:/bin/bash\n"
        "ftp:x:115:65534::/srv:/usr/sbin/nologin\n"
    ) % COMPANY


def _group():
    return (
        "root:x:0:\n"
        "daemon:x:1:\n"
        "sudo:x:27:ubuntu,deploy,admin\n"
        "adm:x:4:ubuntu,syslog\n"
        "www-data:x:33:\n"
        "postfix:x:117:\n"
        "postgres:x:120:\n"
        "ubuntu:x:1000:\n"
        "deploy:x:1001:\n"
        "admin:x:1002:\n"
        "nogroup:x:65534:\n"
    )


def _hosts():
    return (
        "127.0.0.1 localhost\n"
        "%s %s %s\n"
        "::1 localhost ip6-localhost ip6-loopback\n"
        % (INTERNAL_IP, FQDN, HOSTNAME)
    )


def _os_release():
    return (
        'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
        'NAME="Ubuntu"\nVERSION_ID="22.04"\nVERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
        "ID=ubuntu\nID_LIKE=debian\n"
    )


def _motd():
    return (
        "Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)\n\n"
        " * Support:        https://ubuntu.com/advantage\n\n"
        "  System load:  0.08              Processes:             128\n"
        "  Usage of /:   61.2%% of 78.4GB  Users logged in:       0\n"
        "  IP address:   %s               Hostname:              %s\n\n"
        "  %s file share — NAS UI on http://%s/\n\n"
        "Last login: %s from 10.0.0.14\n"
        % (INTERNAL_IP, HOSTNAME, COMPANY, FQDN,
           time.strftime("%a %b %d %H:%M:%S %Y"))
    )


def _sshd_config():
    return (
        "# OpenSSH for %s\n"
        "Port 22\nProtocol 2\n"
        "PermitRootLogin prohibit-password\n"
        "PasswordAuthentication yes\n"
        "PubkeyAuthentication yes\n"
        "X11Forwarding no\n"
        "AllowUsers deploy admin\n"
        "# deploy password is NOT here — see /var/www/nas/docker-compose.yml\n"
        % HOSTNAME
    )


def _postfix_main():
    return (
        "smtpd_banner = $myhostname ESMTP $mail_name\n"
        "biff = no\n"
        "myhostname = %s\n"
        "mydomain = %s\n"
        "myorigin = $mydomain\n"
        "inet_interfaces = all\n"
        "mydestination = $myhostname, localhost.$mydomain, $mydomain\n"
        % (FQDN, DOMAIN)
    )


def _nas_device_conf():
    return (
        "# %s NAS appliance config — generated by first-boot\n"
        "model=%s\n"
        "firmware=%s\n"
        "hostname=%s\n"
        "fqdn=%s\n"
        "mgmt_ip=%s\n"
        "shares_root=/srv/shares\n"
        "web_root=/var/www/nas/www\n"
        "# last rotated by first-boot; see IT handover for operators\n"
        % (COMPANY, NAS_MODEL, NAS_FIRMWARE, HOSTNAME, FQDN, INTERNAL_IP)
    )


def _nas_shares_conf():
    return (
        "[IT]\npath=/srv/shares/IT\nbrowseable=yes\nread only=no\n"
        "comment=IT runbooks and handover\n\n"
        "[Customers]\npath=/srv/shares/Customers\nbrowseable=yes\nread only=yes\n"
        "comment=CRM exports\n\n"
        "[Deploy]\npath=/srv/shares/Deploy\nbrowseable=yes\nread only=no\n"
        "comment=Staging compose and app env\n\n"
        "[Office]\npath=/srv/shares/Office\nbrowseable=yes\nread only=yes\n"
        "comment=VPN and office odds and ends\n"
    )


def _auth_log():
    day = time.strftime("%b %e")
    return (
        "%s 06:12:01 %s sshd[1042]: Accepted publickey for deploy from 10.0.0.14 port 51122\n"
        "%s 06:14:33 %s sshd[1042]: Received disconnect from 10.0.0.14\n"
        "%s 08:01:09 %s sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; "
        "COMMAND=/bin/systemctl restart nginx\n"
        "%s 09:22:41 %s sshd[1882]: Accepted password for admin from 10.0.0.18 port 49801\n"
        % (day, HOSTNAME, day, HOSTNAME, day, HOSTNAME, day, HOSTNAME)
    )


def _syslog():
    day = time.strftime("%b %e")
    return (
        "%s 00:00:01 %s systemd[1]: Started Daily apt download activities.\n"
        "%s 02:30:01 %s CRON[8821]: (deploy) CMD (/home/deploy/backup.sh)\n"
        "%s 02:31:14 %s backup.sh: uploaded db dump to s3://%s/db/\n"
        "%s 03:00:02 %s nginx[1042]: shares OK: IT Customers Deploy Office\n"
        % (day, HOSTNAME, day, HOSTNAME, day, HOSTNAME, backup_bucket(), day, HOSTNAME)
    )


def _nginx_access():
    stamp = time.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return (
        "10.0.0.14 - - [%s] \"GET /health HTTP/1.1\" 200 15\n"
        "10.0.0.14 - - [%s] \"GET / HTTP/1.1\" 200 4120\n"
        "10.0.0.18 - - [%s] \"GET /api/status HTTP/1.1\" 200 188\n"
        "10.0.0.18 - - [%s] \"POST /login HTTP/1.1\" 302 0\n"
        % (stamp, stamp, stamp, stamp)
    )


def _mail_log():
    day = time.strftime("%b %e")
    return (
        "%s 07:15:22 %s postfix/smtpd[2201]: connect from mail.office.example[10.0.0.9]\n"
        "%s 07:15:23 %s postfix/smtpd[2201]: disconnect from mail.office.example[10.0.0.9]\n"
        % (day, HOSTNAME, day, HOSTNAME)
    )


def _env_file(aws, db):
    return (
        "# %s production. do not commit.\n"
        "APP_ENV=production\n"
        "APP_KEY=base64:%s=\n"
        "DB_CONNECTION=pgsql\n"
        "DATABASE_URL=%s\n"
        "AWS_ACCESS_KEY_ID=%s\n"
        "AWS_SECRET_ACCESS_KEY=%s\n"
        "AWS_DEFAULT_REGION=%s\n"
        "MAIL_HOST=smtp.mailgun.org\n"
        "MAIL_PASSWORD=%s\n"
        "NAS_URL=http://%s/\n"
        % (COMPANY, _derived("app_key", 43, _B64), db["value"], aws["value"]["access_key_id"],
           aws["value"]["secret_access_key"], AWS_REGION, _derived("mail_password", 16), FQDN)
    )


_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _database_yml(db):
    return (
        "production:\n"
        "  adapter: postgresql\n"
        "  encoding: unicode\n"
        "  url: %s\n"
        "  pool: 10\n"
        % db["value"]
    )


def _app_readme():
    return (
        "# %s internal application\n\n"
        "Staging lives on %s next to the NAS File Station.\n"
        "Deploy with docker compose from /var/www/nas/.\n"
        "Secrets live in /var/www/app/.env, never in git.\n"
        "Nightly backup runs from /home/deploy/backup.sh at 02:30.\n"
        % (COMPANY, HOSTNAME)
    )


def _nas_readme():
    return (
        "%s — NAS / File Station on %s\n"
        "=====================================\n\n"
        "Model %s  firmware %s\n"
        "Shares: /srv/shares/{IT,Customers,Deploy,Office}\n"
        "Web UI: http://%s/  (sign in, then File Station)\n"
        "Status: http://%s/api/status\n\n"
        "Compose stack for the staging app sits beside this README.\n"
        "Do not commit real passwords into git; they stay in compose locally.\n"
        % (COMPANY, HOSTNAME, NAS_MODEL, NAS_FIRMWARE, FQDN, FQDN)
    )


def _docker_compose(deploy_user, deploy_pass):
    """Plant deploy credentials here — not in the handover note."""
    return (
        "# %s staging stack on %s\n"
        "# Brought up by deploy after reboot. Keep this file mode 600.\n"
        "version: \"3.8\"\n"
        "services:\n"
        "  web:\n"
        "    image: %s/crm-staging:1.4.2\n"
        "    restart: unless-stopped\n"
        "    ports:\n"
        "      - \"8081:8080\"\n"
        "    env_file:\n"
        "      - /var/www/app/.env\n"
        "    volumes:\n"
        "      - /srv/shares/Customers:/data/exports:ro\n"
        "  # host maintenance login used by the deploy user over SSH\n"
        "  # (compose does not use these; %s left them here so the night\n"
        "  #  crew can find the box password without paging him)\n"
        "  # HOST_SSH_USER=%s\n"
        "  # HOST_SSH_PASSWORD=%s\n"
        "  redis:\n"
        "    image: redis:7-alpine\n"
        "    restart: unless-stopped\n"
        % (COMPANY, HOSTNAME, _domain_label(), STAFF, deploy_user, deploy_pass)
    )


def _nas_env_example():
    return (
        "# copy to .env on first boot — example only\n"
        "NAS_HOSTNAME=%s\n"
        "NAS_COMPANY=%s\n"
        "SHARES_ROOT=/srv/shares\n"
        % (HOSTNAME, COMPANY)
    )


def _nas_static_hint():
    return (
        "<!doctype html><html><head><title>%s</title></head>"
        "<body><p>%s File Station is served by the appliance on /.</p></body></html>\n"
        % (COMPANY, COMPANY)
    )


def _bash_history(portal):
    return (
        "ls -la\n"
        "cd /var/www/nas\n"
        "docker compose ps\n"
        "cd /var/www/app\n"
        "git pull\n"
        "sudo systemctl restart nginx\n"
        "sudo systemctl restart postfix\n"
        "psql $DATABASE_URL -c 'select count(*) from customers;'\n"
        "curl -s %s\n"
        "curl -s http://127.0.0.1/api/status\n"
        "vim /var/www/nas/docker-compose.yml\n"
        "df -h\n"
        "free -m\n"
        "uptime\n"
        "ss -tlnp\n"
        "ls /srv/shares\n"
        "sudo tail -f /var/log/nginx/access.log\n"
        "cat ~/notes/it-handover.txt\n"
        "head -n 20 ~/notes/vault-staging.b64\n"
        "ls -la ~/notes/*.png ~/notes/verify.* ~/notes/session-verify.frag.*\n"
        "base64 -d ~/notes/verify.b64.txt\n"
        "cd ~/notes && openssl enc -d -aes-256-cbc -a -in vault-staging.b64 -out vault-cleartext.txt -pass file:.vault-key\n"
        % portal["value"]
    )


def _bashrc():
    return (
        "# ~/.bashrc\n"
        "export HISTSIZE=1000\n"
        "export HISTFILESIZE=2000\n"
        "alias ll='ls -alF'\n"
        "alias la='ls -A'\n"
    )


def _ssh_config():
    return (
        "# ~/.ssh/config — %s\n"
        "Host *\n"
        "    ServerAliveInterval 60\n"
        "Host bastion\n"
        "    HostName bastion.%s\n"
        "    User deploy\n"
        "    # password is in /var/www/nas/docker-compose.yml (HOST_SSH_*)\n"
        "    IdentityFile ~/.ssh/id_ed25519\n"
        % (HOSTNAME, DOMAIN)
    )


def _backup_script(backup_key):
    return (
        "#!/bin/bash\n"
        "# nightly off-site backup. runs from cron at 02:30.\n"
        "set -e\n"
        "export AWS_ACCESS_KEY_ID=%s\n"
        "export AWS_SECRET_ACCESS_KEY=%s\n"
        "export AWS_DEFAULT_REGION=%s\n"
        "pg_dump \"$DATABASE_URL\" | gzip > /tmp/db-$(date +%%F).sql.gz\n"
        "aws s3 cp /tmp/db-*.sql.gz s3://%s/db/\n"
        "tar czf /tmp/shares-$(date +%%F).tgz /srv/shares/IT /srv/shares/Office\n"
        "aws s3 cp /tmp/shares-*.tgz s3://%s/shares/\n"
        "rm -f /tmp/db-*.sql.gz /tmp/shares-*.tgz\n"
        % (backup_key["value"]["access_key_id"], backup_key["value"]["secret_access_key"],
           AWS_REGION, backup_bucket(), backup_bucket())
    )


def _handover_note(admin_pass, portal, deploy_user):
    """Canary portal password only. Deploy password is pointed at compose."""
    return (
        "IT handover notes - keep off the shared drive\n"
        "=============================================\n\n"
        "Server:   %s (%s) — Ubuntu 22.04, AWS %s\n"
        "Role:     internal NAS / file share + CRM staging\n"
        "SSH:      user `%s` (sudo). Password is in\n"
        "          /var/www/nas/docker-compose.yml  (HOST_SSH_PASSWORD).\n"
        "          root login is by key only.\n"
        "Portal:   %s\n"
        "          login admin / %s\n"
        "NAS UI:   http://%s/  — use the admin account %s mailed you\n"
        "          (see his draft in /home/admin/Mail/Drafts/ if you\n"
        "          still have local mail on this box).\n\n"
        "Shares:   /srv/shares/{IT,Customers,Deploy,Office}\n"
        "Services: nginx :80 (File Station), sshd :22, postfix :25, vsftpd :21.\n"
        "If the app is down, check disk on / first — logs fill it.\n"
        "Backups go to the %s S3 bucket every night.\n"
        "Old VPN profile is under Office share / home/deploy.\n"
        % (HOSTNAME, FQDN, AWS_REGION, deploy_user, portal["value"], admin_pass["value"], FQDN,
           STAFF, backup_bucket())
    )



def _asset_bytes(name):
    """Post-auth bait image: operator-supplied, else generated per install.

    Set bait.assets_dir in the persona file to serve your own images (keep
    them out of git). Otherwise a screenshot-ish PNG (pale window, dark
    "text" bars) is drawn from the install seed, so no two installs serve
    byte-identical files and nothing third-party is shipped.
    """
    if ASSETS_DIR:
        path = os.path.join(os.path.expanduser(ASSETS_DIR), name)
        if os.path.isfile(path):
            with open(path, "rb") as fh:
                return fh.read()
    return _generated_png(name)


def _png_chunk(tag, data):
    raw = tag + data
    return struct.pack(">I", len(data)) + raw + struct.pack(">I", zlib.crc32(raw) & 0xffffffff)


def _generated_png(label, width=640, height=400):
    rng = _rng("img:" + label)
    bg = (rng.randint(236, 250),) * 3
    ink = (rng.randint(30, 70), rng.randint(30, 70), rng.randint(40, 90))
    title = (rng.randint(40, 90), rng.randint(70, 120), rng.randint(140, 190))
    rows = []
    for y in range(height):
        row = bytearray()
        for x in range(width):
            if y < 36:
                c = title
            elif 60 < y < height - 40 and 40 < x < width - 40 and (y // 14) % 2 == 0 and (x // 8) % 7 != 0:
                c = ink
            else:
                c = bg
            row.extend(c)
        rows.append(b"\x00" + bytes(row))
    raw = zlib.compress(b"".join(rows), 9)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"IDAT", raw) + _png_chunk(b"IEND", b"")


def _url_b64():
    return base64.b64encode(LURE_URL.encode("ascii")).decode("ascii")


def _url_rot13():
    return codecs.encode(LURE_URL, "rot_13")


def _url_hex():
    return LURE_URL.encode("ascii").hex()


def _url_quoted():
    return quote(LURE_URL, safe="")


def _vault_blob_lines():
    # Looks like an openssl Salted__ dump; content is per-install filler.
    salt = _derived("vault_salt", 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
    seed = "U2FsdGVkX1" + salt + _brand().lower() + "VaultChunk" + _derived("vault_body", 80)
    return ["%s%02d==" % ((seed + str(i) * 8)[:76], i) for i in range(1, 12)]


def _vault_staging():
    """Easy vault chain: obfuscated lure (base64) + local screenshot pointer + unwrap hop.

    Plaintext https://… is intentionally absent here — decode verify.b64 / the
    embedded marker, or unwrap to cleartext for other encodings.
    """
    blob = "\n".join(_vault_blob_lines())
    marker = _url_b64()
    return (
        "# CONFIDENTIAL — %s credential staging (DO NOT SHARE)\n"
        "# AES-256-CBC dump of last password-vault export before S3 offload.\n"
        "# Session-verify endpoint (base64 — decode before use):\n"
        "#   %s\n"
        "# Local screenshot copy (recoverable PNG): password-vault-export.png\n"
        "# Also split: session-verify.frag.a + session-verify.frag.b\n"
        "#\n"
        "# Full unwrap (writes vault-cleartext.txt — percent-encoded verify link):\n"
        "#   openssl enc -d -aes-256-cbc -a -in vault-staging.b64 "
        "-out vault-cleartext.txt -pass file:.vault-key\n"
        "#\n"
        "# stego: EOF marker repeats b64 verify (ignore Salted__ lines above)\n"
        "%s\n"
        "#EOF:%s\n"
        % (COMPANY, marker, blob, marker)
    )


def _vault_key():
    return vault_key()


def _vault_cleartext():
    """Deeper hop: same lure URL as percent-encoding + rot13 pointer (not plaintext)."""
    return (
        "# %s password-vault export (decrypted staging copy)\n"
        "# Generated on %s — delete after S3 offload.\n\n"
        "entry,username,secret,notes\n"
        "crm-db,svc_reports,pg-rotating-see-env,prod replica\n"
        "aws-deploy,AKIA-see-app-env,(secret in .env),%s\n"
        "nas-admin,admin,(see Mail/Drafts),File Station\n"
        "session-verify,—,—,urlencode then open (local screenshot: password-vault-export.png):\n"
        "  %s\n"
        "session-verify-alt,—,—,rot13 file verify.rot13 or:\n"
        "  %s\n\n"
        "# end of export\n"
        % (COMPANY, HOSTNAME, AWS_REGION, _url_quoted(), _url_rot13())
    )


def _obfuscated_plants(vault_png_bytes, creds_png_bytes):
    """Extra post-auth crumbs: mix of local recoverables and remote-only link forms."""
    url = LURE_URL
    mid = len(url) // 2
    plants = {}

    # Remote-link forms (no image payload — only resolve to the remote lure).
    plants["/home/deploy/notes/verify.b64.txt"] = (
        "# decode: base64 -d verify.b64.txt\n%s\n" % _url_b64()
    )
    plants["/home/deploy/notes/verify.rot13"] = (
        "# tr A-Za-z N-ZA-Mn-za-m < verify.rot13\n%s\n" % _url_rot13()
    )
    plants["/home/deploy/notes/drop-channel.hex"] = (
        "# remote drop only — xxd -r -p drop-channel.hex\n"
        "# (no local mirror; do not commit)\n"
        "%s\n" % _url_hex()
    )
    plants["/home/deploy/notes/session-verify.frag.a"] = url[:mid] + "\n"
    plants["/home/deploy/notes/session-verify.frag.b"] = url[mid:] + "\n"
    plants["/home/deploy/notes/session-verify.frag.README"] = (
        "# concat frag.a + frag.b for the live verify URL (remote).\n"
        "# Local screenshot for the same plant: password-vault-export.png\n"
    )

    # Fake .enc: base64 of a short note that only contains the remote URL (not the png).
    enc_note = (
        "%s SESSION VERIFY\n"
        "open: %s\n"
        "(no binary attached — use remote)\n" % (_brand().upper(), url)
    )
    plants["/home/deploy/notes/session-verify.enc"] = (
        "# openssl-looking wrapper; payload is base64 of a plaintext note:\n"
        "#   base64 -d session-verify.enc | sed '1,2d'\n"
        "U2FsdGVkX19ub3RyZWFs\n"
        "%s\n" % base64.b64encode(enc_note.encode("utf-8")).decode("ascii")
    )

    # Local recoverable: base64 of the real screenshot PNG (reassemble with base64 -d).
    plants["/home/deploy/notes/password-vault-export.png.b64"] = (
        "# recoverable local copy of password-vault-export.png — base64 -d > password-vault-export.png\n"
        + base64.b64encode(vault_png_bytes).decode("ascii")
        + "\n"
    )

    # Credential-screenshot recovery note (path hint + real PNG header hex + pointer).
    plants["/home/deploy/notes/domainadmin-creds-backup.recovery.txt"] = (
        "# credential screenshot recovery notes — full image: domainadmin-creds-backup.png\n"
        "# PNG header hex: %s\n"
        "# if the image is truncated, grab the copy on the IT share\n"
        % creds_png_bytes[:8].hex()
    )

    # Chunked image: first 64 bytes as hex "preview" (not enough alone — soft pressure to open png).
    preview = creds_png_bytes[:64].hex()
    plants["/home/deploy/notes/domainadmin-creds-backup.header.hex"] = (
        "# first 64 bytes of domainadmin-creds-backup.png (PNG signature should show). Full file: domainadmin-creds-backup.png\n"
        "%s\n" % preview
    )

    return plants


def _todo_note():
    return ((
        "- rotate guest wifi Monday\n"
        "- remind %s to remove HOST_SSH_PASSWORD from compose\n"
        "- export customers before month-end\n"
        "- check /api/status after nginx upgrades\n"
        "- finish vault-staging.b64 handoff (notes/) before leave — do not email\n"
        "- verify crumbs: verify.b64.txt / verify.rot13 / session-verify.frag.*\n"
        "- domainadmin-creds-backup.png — move that creds screenshot off the NAS before leave (+ domainadmin-creds-backup.recovery.txt)\n"
    ) % STAFF)


def _mail_draft_admin(admin_user, admin_pass):
    """Plant the fixed admin password here — not next to the deploy password."""
    return (
        "From: %s@%s\n"
        "To: it-handover@%s\n"
        "Subject: Re: NAS access for the new box\n"
        "Date: %s\n"
        "X-Status: draft\n\n"
        "Quick note before I disappear on leave —\n\n"
        "The File Station on %s is up. Factory admin login is still on it:\n\n"
        "    username: %s\n"
        "    password: %s\n\n"
        "Change it when you first sign in. I did not put this in the shared\n"
        "IT folder on purpose. Deploy/SSH is separate; ask whoever has the\n"
        "compose file on the box.\n\n"
        "%s\n"
        % (STAFF.lower(), DOMAIN, DOMAIN, time.strftime("%a, %d %b %Y %H:%M:%S +0000"),
           FQDN, admin_user, admin_pass, STAFF)
    )


def _mail_inbox():
    return (
        "From: noreply@%s\n"
        "To: admin@%s\n"
        "Subject: Your %s NAS (%s) is online\n\n"
        "Device %s firmware %s reported healthy.\n"
        "Shares mounted: IT, Customers, Deploy, Office.\n"
        % (DOMAIN, DOMAIN, COMPANY, HOSTNAME, NAS_MODEL, NAS_FIRMWARE)
    )


def _runbook():
    return (
        "# %s — %s runbook\n\n"
        "## Services\n"
        "- File Station (nginx) on :80\n"
        "- SSH on :22 (users: deploy, admin)\n"
        "- Postfix on :25 (outbound office mail)\n"
        "- vsftpd on :21 (legacy; prefer File Station)\n\n"
        "## Health\n"
        "`curl -s http://127.0.0.1/api/status` should show shares_ok true.\n\n"
        "## If disk fills\n"
        "Truncate `/var/log/nginx/access.log`, then restart nginx.\n"
        % (COMPANY, HOSTNAME)
    )


def _customers_csv():
    first = [
        "id,company,contact,email,phone,plan,mrr",
        "1,Harbourside Cafe,J. Mercer,accounts@harbourside.cafe,+1 555 010 0142,standard,290",
        "2,Delacroix Dental,S. Delacroix,admin@delacroixdental.co.uk,+1 555 010 0287,priority,490",
        "3,Peak Fitness,R. Owens,billing@peakfitness.gym,+1 555 010 0331,essentials,140",
        "4,Ravel Interiors,M. Ravel,hello@ravelinteriors.co.uk,+1 555 010 0419,standard,290",
        "5,Kestrel Legal,A. Kestrel,finance@kestrellegal.co.uk,+1 555 010 0558,priority,490",
    ]
    # Pad to a believable export size without inventing thousands of named people.
    names = ["Ashford","Bellamy","Cortez","Dunne","Ellis","Frost","Grant","Huang",
             "Ibrahim","Jensen","Kaur","Lambert","Morales","Nguyen","Owens","Patel",
             "Quinn","Rossi","Singh","Turner","Underwood","Vargas","Walsh","Xu","Young"]
    cities = ["Reading","Bristol","Leeds","Cardiff","Brighton","York","Bath","Exeter"]
    plans = [("standard",290),("priority",490),("essentials",140),("enterprise",890)]
    rows = list(first)
    for i in range(6, 41):
        nm = names[(i * 3) % len(names)]
        city = cities[i % len(cities)]
        plan, mrr = plans[i % len(plans)]
        rows.append("%d,%s %s,%s. %s,accounts@%s-%s.co.uk,+1 555 010 %04d,%s,%d"
                    % (i, nm, city, nm[0], nm, nm.lower(), city.lower(), 1000 + i * 7, plan, mrr))
    rows.append("# exported %s — %d rows" % (time.strftime("%Y-%m-%d"), len(rows) - 1))
    return "\n".join(rows) + "\n"


def _vpn_profile(vpn_pass):
    return (
        "client\ndev tun\nproto udp\nremote vpn.%s 1194\n"
        "resolv-retry infinite\nnobind\npersist-key\npersist-tun\n"
        "auth-user-pass\n# saved credentials: office / %s\n"
        "cipher AES-256-GCM\nverb 3\n"
        "<ca>\n-----BEGIN CERTIFICATE-----\nMIIB (truncated for this note)\n"
        "-----END CERTIFICATE-----\n</ca>\n"
        % (DOMAIN, vpn_pass["value"])
    )


def _authorized_keys():
    # Fake ed25519 public key (32-byte payload, base64). Not a real key.
    payload = bytes(int(_derived("sshkey", 64, "0123456789abcdef")[i:i+2], 16)
                    for i in range(0, 64, 2))
    body = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 " + payload).decode("ascii")
    return "ssh-ed25519 %s deploy@%s\n" % (body, HOSTNAME)


def _root_history():
    return (
        "apt update && apt upgrade -y\n"
        "systemctl status nginx postfix ssh nasd\n"
        "ufw status\n"
        "journalctl -u ssh -n 50\n"
        "ls /srv/shares\n"
        "cat /etc/nas/device.conf\n"
        "cat /var/log/auth.log | tail\n"
    )


def _mysql_history():
    return (
        "show databases;\n"
        "use customers;\n"
        "select count(*) from orders;\n"
        "select * from users where role='admin';\n"
    )


def _directories_for(files):
    """Every directory implied by the file paths, so `ls` and `cd` work."""
    dirs = set(["/"])
    for path in files:
        parts = path.strip("/").split("/")
        for depth in range(1, len(parts)):
            dirs.add("/" + "/".join(parts[:depth]))
    return sorted(dirs)
