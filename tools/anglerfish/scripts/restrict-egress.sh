#!/usr/bin/env bash
# anglerfish Blue Team (OPTIONAL, NOT RUN): tighten the honeypot SG egress IN PLACE to tcp/443 only.
# Done out-of-band (like update-admin-ip.sh) because declaring egress in CloudFormation would
# replace the SG and therefore the instance (new public IP). Creates CFN drift on the SG; harmless.
# Honeypot replies are unaffected (SGs are stateful). VPC DNS (172.31.0.2), NTP (169.254.169.123)
# and IMDS are not filtered by SGs. Revert: ./restrict-egress.sh --revert
set -euo pipefail
REGION="${AWS_REGION:-us-east-1}"; STACK="${STACK_NAME:-anglerfish}"
SG=$(aws cloudformation describe-stack-resources --stack-name "$STACK" --region "$REGION" \
  --logical-resource-id HoneypotSecurityGroup --query 'StackResources[0].PhysicalResourceId' --output text)
ALL='IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]'
HTTPS='IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=0.0.0.0/0,Description=HTTPS only - SSM CWLogs S3 dnf DoH}]'
if [[ "${1:-}" == "--revert" ]]; then
  aws ec2 authorize-security-group-egress --region "$REGION" --group-id "$SG" --ip-permissions "$ALL" || true
  aws ec2 revoke-security-group-egress    --region "$REGION" --group-id "$SG" --ip-permissions "$HTTPS" || true
  echo "egress on $SG restored to allow-all"; exit 0
fi
aws ec2 authorize-security-group-egress --region "$REGION" --group-id "$SG" --ip-permissions "$HTTPS"
aws ec2 revoke-security-group-egress    --region "$REGION" --group-id "$SG" --ip-permissions "$ALL"
# If you ever enable console --notify (SMTP submission), also allow tcp/587:
# aws ec2 authorize-security-group-egress --region "$REGION" --group-id "$SG" --ip-permissions 'IpProtocol=tcp,FromPort=587,ToPort=587,IpRanges=[{CidrIp=0.0.0.0/0}]'
echo "egress on $SG is now tcp/443 only. Verify: aws ssm describe-instance-information (PingStatus Online)"
