# Anglerfish on AWS

CloudFormation template: `anglerfish.yaml`.

## Parameters you must set

| Parameter | Purpose |
|---|---|
| `AlertEmail` | SNS subscription for Critical / HighSignal alarms |
| `AdminCidr` | Your public `/32` for real sshd (never `0.0.0.0/0`) |
| `AmiId` | **Pin** an AMI id so stack updates cannot replace the instance |
| `PackageS3Bucket` / `PackageS3Key` | Where the release tarball lives (or pre-stage on the box) |

## What the stack creates

- EC2 host with world-open honeypot ports + admin SSH from `AdminCidr`
- Instance role with Deny outside `/anglerfish/*` SSM/S3
- IMDSv2 required, hop limit 1
- Log group `/anglerfish/sessions` + CloudWatch agent config (SSM param)
- Metric filters → `AnglerfishCritical` / `AnglerfishHighSignal`
- Two alarms → SNS topic

The dead `crit-r1b-gotcha` filter from earlier drafts is **not** included; the
sensor emits `read-file` + `path_read`, which `crit-r1b-bait-taken` matches.

## Helper scripts

See `../../scripts/`: `cwagent-rollout.sh`, `host-egress-guard.sh`,
`restrict-egress.sh`, `update-admin-ip.sh`. Read before running; none are
invoked by the template automatically.
