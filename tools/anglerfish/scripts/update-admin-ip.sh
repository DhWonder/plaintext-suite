#!/usr/bin/env bash
# Update the admin-SSH allowlist on the live anglerfish security group.
# Usage:
#   ./update-admin-ip.sh                 # uses your current public IP
#   ./update-admin-ip.sh 203.0.113.10    # set a specific IP
#   ./update-admin-ip.sh 203.0.113.10/32 # set a CIDR
set -euo pipefail
REGION="${AWS_REGION:-us-east-1}"
STACK="${STACK_NAME:-anglerfish}"
PORT="${ADMIN_SSH_PORT:-22222}"

IPARG="${1:-}"
if [[ -z "$IPARG" ]]; then
  IPARG="$(curl -4 -fsS --max-time 8 https://checkip.amazonaws.com | tr -d '[:space:]')"
  echo "Detected public IP: $IPARG"
fi
if [[ "$IPARG" != */* ]]; then
  CIDR="${IPARG}/32"
else
  CIDR="$IPARG"
fi

SG=$(aws cloudformation describe-stack-resources \
  --stack-name "$STACK" --region "$REGION" \
  --logical-resource-id HoneypotSecurityGroup \
  --query 'StackResources[0].PhysicalResourceId' --output text)

if [[ -z "$SG" || "$SG" == "None" ]]; then
  echo "Could not find security group for stack $STACK" >&2
  exit 1
fi

echo "Security group: $SG"
echo "Setting admin SSH (:$PORT) allowlist to $CIDR"

# Drop every existing ingress rule on the admin port (any CIDR).
mapfile -t OLD < <(aws ec2 describe-security-groups --region "$REGION" --group-ids "$SG" \
  --query "SecurityGroups[0].IpPermissions[?FromPort==\`${PORT}\` && ToPort==\`${PORT}\`].IpRanges[].CidrIp" \
  --output text | tr '\t' '\n' | grep -v '^$' || true)

for old in "${OLD[@]:-}"; do
  [[ -z "$old" ]] && continue
  echo "  revoke $old"
  aws ec2 revoke-security-group-ingress --region "$REGION" --group-id "$SG" \
    --protocol tcp --port "$PORT" --cidr "$old" >/dev/null || true
done

aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG" \
  --ip-permissions "IpProtocol=tcp,FromPort=${PORT},ToPort=${PORT},IpRanges=[{CidrIp=${CIDR},Description=real sshd (admin only)}]" \
  >/dev/null

echo "Done. Admin SSH on :$PORT now allows $CIDR only."
echo "Connect: ssh -i anglerfish.pem -p $PORT ec2-user@\$(aws cloudformation describe-stacks --stack-name $STACK --region $REGION --query 'Stacks[0].Outputs[?OutputKey==\`PublicIp\`].OutputValue' --output text)"
