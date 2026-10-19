#!/bin/bash
# anglerfish Blue Team: install + configure amazon-cloudwatch-agent to ship honeypot logs off-host.
# Run ON THE INSTANCE as root (via SSM Run Command) ONLY AFTER the stack update that creates
# the /anglerfish/sessions log group, the /anglerfish/cwagent-config SSM parameter and the IAM grants.
# Idempotent. Read-only toward the sensor: it never touches sensor code, its unit, or its log files.
set -euo pipefail
PARAM="${1:-/anglerfish/cwagent-config}"
CTL=/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl

rpm -q amazon-cloudwatch-agent >/dev/null 2>&1 || dnf -y install amazon-cloudwatch-agent
# The sensor dir is 0700 decoy:decoy, so the agent runs as root (config: agent.run_as_user=root).
# It only opens the files listed in collect_list, read-only.
$CTL -a fetch-config -m ec2 -s -c "ssm:${PARAM}"
systemctl enable amazon-cloudwatch-agent
sleep 5
$CTL -a status
# Memory guard for t3.micro (1 GiB): cap the agent so it can never starve the sensor.
mkdir -p /etc/systemd/system/amazon-cloudwatch-agent.service.d
cat > /etc/systemd/system/amazon-cloudwatch-agent.service.d/10-decoy-limits.conf <<'UNIT'
[Service]
MemoryMax=128M
CPUQuota=25%
UNIT
systemctl daemon-reload
systemctl restart amazon-cloudwatch-agent
$CTL -a status
