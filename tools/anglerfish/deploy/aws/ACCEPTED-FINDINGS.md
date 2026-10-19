# Accepted compliance findings

A honeypot that is not reachable from the internet is useless for Shodan /
attacker telemetry. The following findings from `cfn-lint`, `cfn-guard`,
`checkov`, or `check_cloudformation_template_compliance` are **accepted**:

| Rule (typical) | Why accepted |
|----------------|--------------|
| SG ingress 0.0.0.0/0 on 22/80/443/21/23/25 | Intentional honeypot facades. Real admin SSH is on a non-standard port locked to `AdminCidr`. |
| EC2 has a public IP | Required for Shodan visibility. Auto-assigned (no Elastic IP). |
| Instance role allows `cloudwatch:PutMetricData` on `*` | CloudWatch metrics API requires `*`; constrained by `cloudwatch:namespace` condition. |
| No IMDSv1 | We require IMDSv2 (`HttpTokens: required`). |
| Budgets / billing alarm email | Operator must confirm the SNS subscription; documented in README. |

Rejected / fixed if seen:

- World-open admin SSH
- NAT Gateway / ELB / unattached EIP
- Root volume > 30 GB
- Instance types other than t3.micro / t2.micro
- Sensor running as root without iptables redirect

## checkov results (this tree)

| Check | Result | Notes |
|-------|--------|-------|
| CKV_AWS_24 (SG 0.0.0.0/0 port 22) | FAIL — accepted | Honeypot SSH facade |
| CKV_AWS_260 (SG 0.0.0.0/0 port 80) | FAIL — accepted | Honeypot HTTP |
| CKV_AWS_88 (EC2 public IP) | FAIL — accepted | Required for Shodan |
| CKV_AWS_26 (SNS encryption) | PASS | Uses `alias/aws/sns` |
| Remaining CKV_* in this template | PASS | |

`cfn-lint deploy/aws/anglerfish.yaml` → exit 0 (no errors).

## cfn-guard / check_cloudformation_template_compliance

| Rule | Verdict |
|------|---------|
| EC2_INSTANCE_NO_PUBLIC_IP | Accepted — required for Shodan |
| EC2_SECURITY_GROUP_INGRESS_OPEN_TO_WORLD / RESTRICTED_INCOMING_TRAFFIC | Accepted — honeypot facades (22/80/443/21/23/25) |
| SECURITY_GROUP_INGRESS_CIDR_NON_32_RULE | Accepted for honeypot ports (0.0.0.0/0); AdminCidr is operator-supplied and should be /32 |
| SECURITY_GROUP_MISSING_EGRESS_RULE | Accepted — default allow-all egress so yum/S3 work without a NAT Gateway (NAT ≈ $32/mo) |
| EC2_INSTANCES_IN_VPC | Accepted — uses default VPC via auto public IP NI; no custom VPC (avoids NAT cost) |
| EBS_OPTIMIZED_INSTANCE / EC2_INSTANCE_DETAILED_MONITORING_ENABLED | Accepted — not free-tier-relevant; detailed monitoring costs extra |
| IAM_NO_INLINE_POLICY_CHECK / IAM_POLICYDOCUMENT_NO_WILDCARD_RESOURCE | Accepted — tiny instance role with s3:GetObject on one object + cloudwatch:PutMetricData constrained by namespace condition |
