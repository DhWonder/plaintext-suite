# Short demo

```bash
cp config/persona.example.yaml config/persona.yaml
python3 anglerfish_cli.py sensor --bind 127.0.0.1 --ports 2222 8080 8443 \
  --persona config/persona.yaml --state-dir /tmp/anglerfish-demo
```

Then:

```bash
# SSH banner + HASSH-able KEXINIT
nc 127.0.0.1 2222

# DSM-looking login
curl -s http://127.0.0.1:8080/ | head

# Synology API catalog
curl -s 'http://127.0.0.1:8080/webapi/query.cgi?api=SYNO.API.Info&query=ALL' | head
```

Planted passwords were printed when the sensor minted its state. Log in on
the web UI, open File Station, read a bait file — that is R1b.
