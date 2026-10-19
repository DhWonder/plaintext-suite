# Example output

These are **synthetic** sample reports showing the JSON shape `iotscan.py`
produces. They are not real scans. All addresses are from the
[RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) documentation ranges
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), all MACs are fabricated
(`00:11:22:...`), and device names/vendors are generic placeholders.

| File | Shows |
|---|---|
| `host-example.json` | A single-host IP scan: ports, HTTP, UPnP descriptor, findings, botnet-exposure audit, and the rolled-up assessment. |
| `ble-example.json` | A Bluetooth/BLE advertisement scan with a Just Works pairing finding. |

Run the tool against **your own** devices to generate real reports. Live scan
output is git-ignored on purpose (see `.gitignore`) so a real assessment of a
real network is never committed.
