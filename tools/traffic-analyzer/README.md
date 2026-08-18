# traffic-analyzer

Work out who is flooding your network, and say so in plain English.

Point it at a packet capture, or let it listen to a network card, and it tells you
which addresses are a problem, why it thinks so, and what to change. Every finding
comes with the sentence that explains it, because a score nobody understands is a
score nobody acts on.

Nothing needs installing. It is Python 3 and the standard library, on purpose: the
machines that need this most are often the ones you are not allowed to install
things on.

```
python3 traffic_analyzer.py attack.pcap
python3 traffic_analyzer.py attack.pcapng.gz --html report.html
sudo python3 traffic_analyzer.py live eth0 --save
python3 traffic_analyzer.py watch
```

---

## What it reads

This is the part that decides whether the tool works on the file somebody actually
hands you, so it is deliberately forgiving.

| | |
|---|---|
| Formats | classic pcap, both byte orders, microsecond and nanosecond stamps; **pcapng**, which is what Wireshark saves by default |
| Compression | gzip, transparently (`.pcap.gz`, `.pcapng.gz`) |
| Addresses | IPv4 and IPv6, including fragments and extension headers |
| Link types | Ethernet (with VLAN and MPLS), raw IP, Linux cooked capture v1 and v2, BSD and OpenBSD loopback, PPP |
| Damaged files | reads what is there, notices the file was cut short, and says so |

When it cannot use a frame it does not quietly drop it. It counts why, so instead of
"no packets found" you get "read 17,000 frames, used none, the capture is 802.11 with
radiotap headers, which this tool does not decode". A tool that tells you why it
failed is worth more than one that just fails.

Big captures stream rather than load. A 132 MB, two million packet capture reads in
about 14 seconds using 51 MB of memory, and the same file in the browser takes about
two and a half seconds while the page stays usable.

---

## The five things it does

**Read a capture.**

```
python3 traffic_analyzer.py attack.pcap                  print the report
python3 traffic_analyzer.py attack.pcap --html out.html  also write a dashboard to send on
python3 traffic_analyzer.py attack.pcap --json out.json  also write the raw findings
python3 traffic_analyzer.py attack.pcap --save           record it so you can look again later
```

**Watch a network card.** Linux, and it needs root, because reading other people's
packets is a privileged thing to be able to do.

```
sudo python3 traffic_analyzer.py live eth0
sudo python3 traffic_analyzer.py live any --seconds 300 --save --log /var/log/traffic-analyzer.log
```

**Open the browser view**, which shows the past and the present in the same page.

```
python3 traffic_analyzer.py watch                  saved captures, in the browser
sudo python3 traffic_analyzer.py watch --live eth0 start listening straight away
python3 traffic_analyzer.py watch --open           and open the browser for me
```

**Look at what you recorded before.**

```
python3 traffic_analyzer.py sessions      list everything in the database
python3 traffic_analyzer.py show 3        print that session's report again
```

**Be told, rather than watching.** Both the live capture and the site check can
email you, which is the point of leaving either one running.

```
python3 traffic_analyzer.py notify setup           write ~/.plaintext/notify.conf
python3 traffic_analyzer.py notify test            prove it can actually send
sudo python3 traffic_analyzer.py live eth0 --notify
sudo python3 traffic_analyzer.py watch --live eth0 --notify
python3 traffic_analyzer.py sites clients.txt --notify
```

From the capture: one email listing everything that turned hostile in the same
moment, then quiet about those addresses for fifteen minutes. Twenty machines
in a botnet arriving together are one email, not twenty.

From the site check: one email for every site that is down or whose certificate
has expired or is about to. A site that is merely slow does not email — that is
worth knowing at nine in the morning, not at three. A site that is down repeats
every six hours; a certificate quietly running out repeats once a day, so a
`sites` check in cron is a thing you can leave alone for a year:

```
*/15 * * * * python3 /path/to/traffic_analyzer.py sites /etc/clients.txt --notify --save
```

The full picture stays where it always was, in the report and the database.
[`../notifications`](../notifications) has the settings, the limits, and what
ends up in the message.

---

## What it looks for

Each source address is scored, and every point added comes with a reason in words.

- **Volume** far above what a person browsing produces
- **Half open connections**, and the difference between a SYN flood (hammering one
  service) and a port scan (walking across many looking for something open), because
  they need different answers
- **Reflection and amplification** off DNS, NTP, SSDP, memcached, CLDAP, SNMP,
  chargen, portmapper, NetBIOS and game servers
- **Machine generated traffic**, where every packet is identical
- **Traffic aimed at things that matter**: SSH, Remote Desktop, file sharing, mail,
  databases
- **Floods spread across the port range**, where blocking one port will not help
- **ICMP floods**

Sources are then grouped by behaviour. Two addresses sending the same protocol, to
the same port, at the same speed, with the same packet size and the same starting
TTL are doing the same thing, which in a flood usually means one botnet or one tool.
The report names those groups. On the sample attack it correctly splits the botnet
into its Linux half and its Windows half.

---

## Asking VirusTotal about the flagged sources

The scoring above needs no internet: it decides who is a problem from the traffic
alone. If you pass a VirusTotal key, it will add one thing on top of that, and only
for the sources it already flagged: has anybody else reported this address before.

```
python3 traffic_analyzer.py attack.pcap --vt-key YOUR_KEY
```

An address that is hammering you AND is flagged by forty vendors as a known attacker
is a different conversation from one that merely looks busy. So the report gains a
short section that leads with the known-bad ones, naming how many vendors call each
address malicious and what country and network it sits in.

The rules it follows are the same ones the rest of the suite follows:

- **Only the flagged sources are looked up, never the whole capture,** and only the
  address is ever sent. Sending an IP to VirusTotal tells VirusTotal you are looking
  at it, which is a fair trade for an address already attacking you but is still a
  thing that leaves, so it is off until you pass a key.
- **The free key is small:** four lookups a minute, five hundred a day. The tool
  paces itself to stay inside that, checks the busiest ten flagged sources and says
  plainly when more were flagged than were looked up, and stops if the daily budget
  runs out rather than failing halfway through in silence.
- **Every answer is cached** in the same database, so running the same capture again,
  or seeing the same address in a later one, costs no lookup.

The key can also come from the `VT_API_KEY` environment variable, to keep it out of
your shell history. A free key is enough; get one from virustotal.com.

---

## The browser version

`website/traffic-analyzer-ui.html` is the same analysis running in a browser. Open it
from disk and it works with no server at all: your capture is read by your own
machine and is never uploaded anywhere.

Four views:

- **Report** — the plain version, with the verdict and what to change
- **Sources** — every address, searchable, sortable, filterable
- **World map** — scroll to zoom, drag to pan, click a dot
- **Console** — the same findings laid out the way a monitoring wall shows them

Click any address anywhere and a panel opens with everything known about it: what it
did, why it was flagged, when it was active, what the host looks like, which ports it
aimed at, which machines it talked to, its connection behaviour, a sample of its
actual packets, and three kinds of neighbour — addresses behaving identically,
addresses in the same network block, and addresses aiming at the same target.

Served by `traffic_analyzer.py watch` the same page also lists your saved captures and can
start and stop a live capture.

It agrees with the Python version packet for packet. That is tested, not claimed:

```
python3 tests/make_test_captures.py     build captures in every supported shape
python3 tests/test_capture.py           check the reader handles all of them
python3 tests/test_parity.py            check both engines produce the same numbers
```

The page is built from readable pieces in `website/src/` by `website/build-ui.py`,
because a single 580 KB file with a 440 KB base64 line in it is not something anybody
can edit. Change the pieces, run the build, commit both.

---

## Where it keeps things

One SQLite file, `~/.traffic-analyzer/history.db` unless you pass `--db`. Every run
becomes a session in it. No server to install, and the client can email you the whole
history as one attachment.

**The raw packets are never stored.** Only counts and per source summaries. Storing
traffic contents would turn this tool into a privacy problem and a legal one.

The web server binds to `127.0.0.1` on purpose. This can show every address talking
to a machine, which is not something that should be reachable from the network by
accident. Binding it anywhere else takes an explicit `--host` and prints a warning.

---

## Honest limitations

- **The region is not geolocation.** Positions come from which registry the address
  block was handed out in. That is roughly right at the continent level and no more.
  It is enough to answer "is this coming from places our customers actually live".
- **The operating system guess is a hint.** It comes from the starting TTL, which is
  64 on Linux and Unix, 128 on Windows, 255 on network equipment. A firewall in the
  middle can change it.
- **Source addresses in a flood are often forged.** When one address shows several
  different TTLs the panel says so, because that usually means the traffic is really
  coming from several machines.
- **Very large captures are capped.** Past 150,000 distinct source addresses it stops
  tracking them individually and groups the rest by network. The totals stay exact and
  the report says the cap was hit. A number that quietly stopped being exact is worse
  than no number.
- **It reads. It does not scan, block or change anything.** It contacts nobody
  about what it found unless you switch it on yourself, and there are only two
  ways to: `--notify` emails you, through your own mail server, at your own
  address; and `--vt-key` sends the flagged addresses, and only those, to
  VirusTotal to ask whether they are already known. Both are off by default.
  Nothing is ever sent to me, and your traffic is never sent anywhere.

---

## Layout

```
traffic_analyzer.py              the command line tool
trafficanalyzer/
  capture.py                reading capture files and network cards
  analyse.py                scoring, grouping, recommendations
  store.py                  the SQLite history, and the reputation cache
  live.py                   live capture, rolling state, the alert log
  server.py                 the local web server and JSON API
  services.py               website reachability and certificate checks
  reputation.py             the VirusTotal address lookups, paced and cached
  report.py                 the terminal report and the HTML dashboard
  notify.py                 the notification email, shared with the other tools
tests/
  make_test_captures.py     builds a capture in every supported shape
  test_capture.py           proves the reader handles all of them
  test_parity.py            proves both engines agree
  test_reputation.py        proves the VirusTotal lookups behave, offline
make_sample_attack.py       builds the synthetic attack used in the demo
samples/attack.pcap         that attack, ready to run
```

---

Written by DhWonder for [Plaintext IT](https://github.com/DhWonder/plaintext-suite). MIT licensed.
Use it on your own network, or on one you have written permission to look at. Nothing
in here is a substitute for that permission.
