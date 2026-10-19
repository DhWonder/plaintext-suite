#!/bin/bash
# anglerfish EC2 bootstrap (Amazon Linux 2023 / Ubuntu)
# Runs as root from cloud-init. Installs the honeypot, mints a persona,
# redirects well-known ports to high ports, and starts an unprivileged
# systemd service. Never exposes the console to the network.
set -euo pipefail
exec > /var/log/anglerfish-bootstrap.log 2>&1
echo "=== anglerfish bootstrap $(date -u) ==="

PACKAGE_S3_URI="${PackageS3Uri}"
CONSOLE_TOKEN_PARAM="${ConsoleToken}"
ADMIN_PORT="${AdminSshPort}"

# --- packages -----------------------------------------------------------
if command -v dnf >/dev/null 2>&1; then
  dnf -y update --security || true
  dnf -y install python3 python3-pip iptables iptables-nft openssl tar gzip shadow-utils
  IPTABLES=iptables
elif command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq python3 python3-pip iptables openssl tar gzip
  IPTABLES=iptables
else
  echo "unsupported distro"; exit 1
fi

# --- decoy user (never run the sensor as root) --------------------------
id decoy >/dev/null 2>&1 || useradd --system --create-home --home-dir /opt/anglerfish --shell /sbin/nologin decoy
mkdir -p /opt/anglerfish /opt/anglerfish/state /opt/anglerfish/log
chown -R decoy:decoy /opt/anglerfish

# --- fetch package ------------------------------------------------------
cd /tmp
if [[ -n "$PACKAGE_S3_URI" ]]; then
  if command -v aws >/dev/null 2>&1; then
    aws s3 cp "$PACKAGE_S3_URI" /tmp/anglerfish.tgz
  else
    # IMDSv2 + awscli via pip as fallback
    pip3 install --quiet awscli || true
    aws s3 cp "$PACKAGE_S3_URI" /tmp/anglerfish.tgz
  fi
else
  echo "PackageS3Uri empty - expecting /tmp/anglerfish.tgz already present"
fi
tar xzf /tmp/anglerfish.tgz -C /opt/anglerfish
# tarball extracts to anglerfish-upgraded/
APP=/opt/anglerfish/anglerfish-upgraded
if [[ ! -d "$APP" ]]; then
  # tolerate a tarball whose top-level dir name differs
  APP=$(find /opt/anglerfish -maxdepth 1 -type d -name 'anglerfish*' | head -1)
fi
chown -R decoy:decoy /opt/anglerfish

# --- mint persona (as decoy user) ---------------------------------------
sudo -u decoy mkdir -p /opt/anglerfish/state
# First run generates host keys + TLS cert + console token.
sudo -u decoy python3 - <<PY
import sys
sys.path.insert(0, "$APP")
from decoyhouse import persona
p = persona.load_or_create("/opt/anglerfish/state", note=print)
print("persona:", p["fqdn"], p["company"])
print("console_token:", p["console_token"])
open("/opt/anglerfish/state/console.token","w").write(p["console_token"])
PY
TOKEN=$(cat /opt/anglerfish/state/console.token)
# Allow operator override from CFN parameter (keeps sensor+console matched)
if [[ -n "$CONSOLE_TOKEN_PARAM" && "$CONSOLE_TOKEN_PARAM" != "auto" ]]; then
  TOKEN="$CONSOLE_TOKEN_PARAM"
  python3 - <<PY
import json
p=json.load(open("/opt/anglerfish/state/persona.json"))
p["console_token"]="$TOKEN"
json.dump(p, open("/opt/anglerfish/state/persona.json","w"), indent=2)
open("/opt/anglerfish/state/console.token","w").write("$TOKEN")
PY
fi
chmod 600 /opt/anglerfish/state/console.token /opt/anglerfish/state/persona.json
chown -R decoy:decoy /opt/anglerfish/state

# --- iptables: well-known -> high ports (sensor stays unprivileged) ----
# Flush any prior decoy redirects then install ours.
$IPTABLES -t nat -D PREROUTING -p tcp --dport 22  -j REDIRECT --to-ports 2222 2>/dev/null || true
$IPTABLES -t nat -D PREROUTING -p tcp --dport 80  -j REDIRECT --to-ports 8080 2>/dev/null || true
$IPTABLES -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443 2>/dev/null || true
$IPTABLES -t nat -D PREROUTING -p tcp --dport 25  -j REDIRECT --to-ports 2525 2>/dev/null || true
$IPTABLES -t nat -D PREROUTING -p tcp --dport 21  -j REDIRECT --to-ports 2121 2>/dev/null || true
$IPTABLES -t nat -D PREROUTING -p tcp --dport 23  -j REDIRECT --to-ports 2323 2>/dev/null || true
$IPTABLES -t nat -A PREROUTING -p tcp --dport 22  -j REDIRECT --to-ports 2222
$IPTABLES -t nat -A PREROUTING -p tcp --dport 80  -j REDIRECT --to-ports 8080
$IPTABLES -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443
$IPTABLES -t nat -A PREROUTING -p tcp --dport 25  -j REDIRECT --to-ports 2525
$IPTABLES -t nat -A PREROUTING -p tcp --dport 21  -j REDIRECT --to-ports 2121
$IPTABLES -t nat -A PREROUTING -p tcp --dport 23  -j REDIRECT --to-ports 2323
# Persist rules across reboot when possible
if command -v iptables-save >/dev/null; then
  mkdir -p /etc/sysconfig
  iptables-save > /etc/sysconfig/iptables || true
fi

# Move real sshd off 22 if it is holding it, onto the admin port.
if [[ -f /etc/ssh/sshd_config ]]; then
  if ! grep -qE "^Port ${ADMIN_PORT}$" /etc/ssh/sshd_config; then
    sed -i 's/^#\\?Port .*/Port '"${ADMIN_PORT}"'/' /etc/ssh/sshd_config || true
    if ! grep -qE "^Port " /etc/ssh/sshd_config; then
      echo "Port ${ADMIN_PORT}" >> /etc/ssh/sshd_config
    fi
    systemctl restart sshd || systemctl restart ssh || true
  fi
fi

# --- systemd units ------------------------------------------------------
cat > /etc/systemd/system/anglerfish-sensor.service <<EOF
[Unit]
Description=anglerfish honeypot sensor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=decoy
Group=decoy
WorkingDirectory=$APP
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 $APP/anglerfish.py sensor \\
  --bind 0.0.0.0 \\
  --ports 2222 8080 8443 2525 2121 2323 \\
  --state-dir /opt/anglerfish/state \\
  --log /opt/anglerfish/log/sessions.log \\
  --console http://127.0.0.1:8770 \\
  --token $TOKEN
Restart=always
RestartSec=5
# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/anglerfish/state /opt/anglerfish/log
CapabilityBoundingSet=
AmbientCapabilities=
MemoryMax=256M
TasksMax=128

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/anglerfish-console.service <<EOF
[Unit]
Description=anglerfish console (localhost only)
After=network-online.target

[Service]
Type=simple
User=decoy
Group=decoy
WorkingDirectory=$APP
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 $APP/anglerfish.py console \\
  --host 127.0.0.1 --port 8770 \\
  --db /opt/anglerfish/state/console.db \\
  --token $TOKEN
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/anglerfish/state /opt/anglerfish/log
MemoryMax=128M
TasksMax=64

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now anglerfish-console.service
systemctl enable --now anglerfish-sensor.service

# --- banner for the operator -------------------------------------------
PUBLIC_IP=$(curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/public-ipv4 || echo unknown)
cat > /opt/anglerfish/READY.txt <<EOF
anglerfish is up.

Public IP:      $PUBLIC_IP
Honeypot ports: 22/tcp (ssh), 80/tcp (http), 443/tcp (https),
                21/tcp (ftp), 23/tcp (telnet), 25/tcp (smtp)
                (iptables-redirected to high ports; sensor is unprivileged)
Admin SSH:      port ${ADMIN_PORT} (security group: your IP only)
Console:        http://127.0.0.1:8770 on the instance (SSH tunnel to reach it)
Console token:  $TOKEN

Shodan will see OpenSSH 8.9p1 + nginx 1.18.0 (Ubuntu) + Postfix + vsftpd.

Tear down: aws cloudformation delete-stack --stack-name <name>
EOF
chown decoy:decoy /opt/anglerfish/READY.txt
echo "=== bootstrap done $(date -u) ==="
cat /opt/anglerfish/READY.txt
