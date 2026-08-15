"""
The valuable-looking content that makes an attacker stay.

A honeypot that answers a knock and nothing else tells you somebody scanned
you. A honeypot that looks like a real machine with real secrets on it tells
you far more: what they go for first, what tools they use, what they try to
steal, and, through the tokens planted in that content, where they turn up
next.

So this builds a believable small business server. Not a maze, just the handful
of things that are genuinely on machines like this and that a threat actor
recognises instantly as worth taking:

  - credentials in the places people really leave them (an .env, a backup
    script, a saved database connection)
  - a customer database export, because that is what gets sold
  - a VPN profile, because that is a way further in
  - a note from IT with a password in it, because there is always one

Every secret in here is a canary token from tokens.py. None of it is real. The
whole point is that it looks real enough to take, and tells you when it is.

Everything is generated fresh per sensor, so two honeypots never share bait and
a triggered token names exactly which machine it came from.
"""

import time

from . import tokens

# A believable hostname and a believable business. Generic on purpose: it
# should look like ten thousand other small company servers, not like a trap
# dressed up for one.
HOSTNAME = "srv-app01"
COMPANY = "Northwind Trading"


def build(console_host="", sensor_name=""):
    """Assemble a full fake machine, and the list of tokens planted in it.

    Returns (filesystem, planted_tokens). The filesystem is a flat map of path
    to file, which the sensor serves. planted_tokens is what the console needs
    to recognise a trigger later.
    """
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

    fs = {}

    # The shape of a real Linux box. Directories the attacker expects to find.
    fs["/etc/passwd"] = _passwd()
    fs["/etc/hostname"] = HOSTNAME + "\n"
    fs["/etc/os-release"] = _os_release()
    fs["/etc/motd"] = _motd()

    # A deploy directory with the secret people always forget to remove.
    fs["/var/www/app/.env"] = _env_file(aws, db)
    fs["/var/www/app/config/database.yml"] = _database_yml(db)
    fs["/var/www/app/README.md"] = _app_readme()

    # The home directory of whoever runs this box.
    fs["/home/deploy/.bash_history"] = _bash_history(portal)
    fs["/home/deploy/backup.sh"] = _backup_script(backup_key)
    fs["/home/deploy/notes/it-handover.txt"] = _handover_note(admin_pass, portal)
    fs["/home/deploy/customers_export.csv"] = _customers_csv(db)
    fs["/home/deploy/office-vpn.ovpn"] = _vpn_profile(vpn_pass)

    # Root's crumbs, for the attacker who gets that far.
    fs["/root/.ssh/authorized_keys"] = _authorized_keys()
    fs["/root/.mysql_history"] = _mysql_history()

    directories = _directories_for(fs)

    return {
        "hostname": HOSTNAME,
        "company": COMPANY,
        "files": fs,
        "dirs": directories,
        "tokens": planted,
        "built": time.time(),
    }, planted


# ---------------------------------------------------------------------------
# The files. Each reads like the real thing because the real things are boring
# and consistent, and that is exactly what makes bait convincing.
# ---------------------------------------------------------------------------
def _passwd():
    return (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "postgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\n"
        "deploy:x:1000:1000:deploy,,,:/home/deploy:/bin/bash\n"
        "backup:x:1001:1001::/home/backup:/usr/sbin/nologin\n"
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
        "  Usage of /:   61.2%% of 78.4GB  Users logged in:       0\n\n"
        "Last login: %s from 10.0.0.14\n"
        % time.strftime("%a %b %d %H:%M:%S %Y")
    )


def _env_file(aws, db):
    return (
        "# %s production. do not commit.\n"
        "APP_ENV=production\n"
        "APP_KEY=base64:9Qm2sVwq1hR8nZpKcYxA7bLdEfGhJkMn0pQrStUvWxY=\n"
        "DB_CONNECTION=pgsql\n"
        "DATABASE_URL=%s\n"
        "AWS_ACCESS_KEY_ID=%s\n"
        "AWS_SECRET_ACCESS_KEY=%s\n"
        "AWS_DEFAULT_REGION=eu-west-1\n"
        "MAIL_HOST=smtp.mailgun.org\n"
        "MAIL_PASSWORD=8f2c1d9a4b7e6058\n"
        % (COMPANY, db["value"], aws["value"]["access_key_id"],
           aws["value"]["secret_access_key"])
    )


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
        "Deploy with ./deploy.sh. Secrets live in .env, never in git.\n"
        "Nightly backup runs from /home/deploy/backup.sh at 02:30.\n"
        % COMPANY
    )


def _bash_history(portal):
    return (
        "ls -la\n"
        "cd /var/www/app\n"
        "git pull\n"
        "sudo systemctl restart app\n"
        "psql $DATABASE_URL -c 'select count(*) from customers;'\n"
        "curl -s %s/health\n"
        "vim .env\n"
        "df -h\n"
        "sudo tail -f /var/log/app/production.log\n"
        % portal["value"]
    )


def _backup_script(backup_key):
    return (
        "#!/bin/bash\n"
        "# nightly off-site backup. runs from cron at 02:30.\n"
        "set -e\n"
        "export AWS_ACCESS_KEY_ID=%s\n"
        "export AWS_SECRET_ACCESS_KEY=%s\n"
        "pg_dump \"$DATABASE_URL\" | gzip > /tmp/db-$(date +%%F).sql.gz\n"
        "aws s3 cp /tmp/db-*.sql.gz s3://northwind-backups/db/\n"
        "rm -f /tmp/db-*.sql.gz\n"
        % (backup_key["value"]["access_key_id"], backup_key["value"]["secret_access_key"])
    )


def _handover_note(admin_pass, portal):
    return (
        "IT handover notes - keep off the shared drive\n"
        "=============================================\n\n"
        "Server:   %s (Ubuntu 22.04, in the AWS eu-west-1 account)\n"
        "Admin:    the deploy user has sudo. root login is by key only.\n"
        "Portal:   %s  (admin / %s)\n\n"
        "If the app is down, first thing is check disk on /, it fills from logs.\n"
        "Backups go to the northwind-backups S3 bucket every night.\n"
        "The old VPN profile is in this folder if you need in from home.\n"
        % (HOSTNAME, portal["value"], admin_pass["value"])
    )


def _customers_csv(db):
    # A small, believable export. The names are invented, the shape is real,
    # and the point is that a data thief grabs this on sight.
    rows = [
        "id,company,contact,email,phone,plan,mrr",
        "1,Harbourside Cafe,J. Mercer,accounts@harboursidecafe.example,+44 20 7946 0011,standard,290",
        "2,Delacroix Dental,S. Delacroix,admin@delacroixdental.example,+44 161 496 0022,priority,490",
        "3,Peak Fitness,R. Owens,billing@peakfitness.example,+44 113 496 0033,essentials,140",
        "4,Ravel Interiors,M. Ravel,hello@ravelinteriors.example,+44 20 7946 0044,standard,290",
        "5,Kestrel Legal,A. Kestrel,finance@kestrellegal.example,+44 131 496 0055,priority,490",
        "# ... 4,118 more rows, exported %s" % time.strftime("%Y-%m-%d"),
    ]
    return "\n".join(rows) + "\n"


def _vpn_profile(vpn_pass):
    return (
        "client\ndev tun\nproto udp\nremote vpn.northwind-trading.example 1194\n"
        "resolv-retry infinite\nnobind\npersist-key\npersist-tun\n"
        "auth-user-pass\n# saved credentials: office / %s\n"
        "cipher AES-256-GCM\nverb 3\n"
        "<ca>\n-----BEGIN CERTIFICATE-----\nMIIB (truncated for this note)\n"
        "-----END CERTIFICATE-----\n</ca>\n"
        % vpn_pass["value"]
    )


def _authorized_keys():
    return ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK9Xr2tPqL3mN8vBcZfWqYhJ0dRsTuVwXyZ "
            "deploy@srv-app01\n")


def _mysql_history():
    return (
        "show databases;\n"
        "use customers;\n"
        "select count(*) from orders;\n"
        "select * from users where role='admin';\n"
    )


# ---------------------------------------------------------------------------
def _directories_for(files):
    """Every directory implied by the file paths, so `ls` and `cd` work."""
    dirs = set(["/"])
    for path in files:
        parts = path.strip("/").split("/")
        for depth in range(1, len(parts)):
            dirs.add("/" + "/".join(parts[:depth]))
    return sorted(dirs)
