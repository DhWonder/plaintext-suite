# Deploying Anglerfish

For the AWS path see [`deploy/aws/README.md`](deploy/aws/README.md).

## Local / lab

1. `cp config/persona.example.yaml config/persona.yaml` and edit.
2. High ports: `python3 anglerfish_cli.py sensor --bind 127.0.0.1 --ports 2222 8080 8443 --persona config/persona.yaml`
3. Privileged (real 22/80/443): run under systemd as the `anglerfish` user; see the CloudFormation user-data for a working unit file.
4. Optional console: `python3 anglerfish_cli.py console --port 8770 --token <same as sensor>`

## Non-negotiables

- Persona file is **not** the example before any public bind.
- Admin SSH (non-22) locked to your `/32`.
- Instance role Deny outside `/anglerfish/*`; IMDSv2 hop limit 1.
- No real credentials anywhere on the box.
