#!/bin/bash
# anglerfish Blue Team (OPTIONAL, step 2): host-level containment for the unprivileged sensor user
# and any future sandbox service user. Security groups do NOT govern loopback or the instance's own
# IMDS traffic, so this is the layer that keeps a popped sensor away from the role credentials,
# the real admin sshd and the localhost console internals.
# Run ON THE INSTANCE as root via SSM. Idempotent. Rules match by uid, so root/ssm-agent/cw-agent are unaffected.
set -euo pipefail
ADMIN_PORT="${ADMIN_PORT:-22222}"
USERS="${GUARD_USERS:-decoy}"   # e.g. GUARD_USERS="decoy sandbox"
CHAIN=DECOY_EGRESS
iptables -N $CHAIN 2>/dev/null || iptables -F $CHAIN
# 1) never let sensor/sandbox users reach IMDS (instance-role creds live there)
iptables -A $CHAIN -d 169.254.169.254/32 -j REJECT
# 2) never let them reach the real admin sshd, even over loopback
iptables -A $CHAIN -p tcp --dport "$ADMIN_PORT" -j REJECT
# 3) no lateral movement into the VPC (but keep the VPC DNS resolver for name lookups)
iptables -A $CHAIN -d 172.31.0.2/32 -p udp --dport 53 -j RETURN
iptables -A $CHAIN -d 172.31.0.2/32 -p tcp --dport 53 -j RETURN
iptables -A $CHAIN -d 172.31.0.0/16 -j REJECT
iptables -A $CHAIN -j RETURN
for u in $USERS; do
  id "$u" >/dev/null 2>&1 || continue
  iptables -C OUTPUT -m owner --uid-owner "$u" -j $CHAIN 2>/dev/null || iptables -I OUTPUT 1 -m owner --uid-owner "$u" -j $CHAIN
done
iptables-save > /etc/sysconfig/iptables
iptables -S $CHAIN
