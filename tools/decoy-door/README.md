# decoy-door

A fake door for your network that writes down who rattles the handle.

```
2026-08-12 08:47:50  KNOCK  port 2222 from 203.0.113.7
2026-08-12 08:47:50  SAID   port 2222 from 203.0.113.7: "SSH-2.0-libssh_0.9"
```

## The idea, in one paragraph

Open a door on your network that nothing legitimate ever uses. Real users have no
reason to touch it — so anyone who knocks is scanning or probing. The door leads
nowhere; it just logs who knocked, when, and what they said. Security people call
this a honeypot. I call it a doorbell camera for your network.

## Why a small business would run one

Watch it for a day on any internet-facing machine and the abstract idea of
"attackers" becomes a log file of real addresses trying your doors around the
clock. Nothing I can say in a meeting makes the point as well as that log does.

Used inside an office network it's a tripwire: nothing should ever touch it, so
the day something does — some machine on your own network scanning its neighbors —
you find out immediately instead of months later.

## How to use it

```
python3 decoy_door.py listen 2222 2323 8080     # open fake doors, log visits
python3 decoy_door.py report                    # plain-English summary of who knocked
```

Run it on a spare machine, a Raspberry Pi in the office, or a $5 cloud server.
Ports under 1024 (like the real SSH port 22) need administrator rights; the high
ports above are fine to start — scanners try them anyway.

## Safety, honestly addressed

A honeypot only makes sense if it can't be turned against you, so this one is
deliberately boring: it never answers with anything, never executes anything it
receives, reads at most 256 bytes per visitor before closing the connection, and
sanitizes everything before printing it (visitor input is hostile input, even in
a log). It's ~200 lines — read them, that's the point.

Run it on a machine you own or have permission to run it on, and remember it's a
listening post, not protection: it doesn't block anyone, it informs you.

## Honest limitations

- It records TCP connection attempts. Sophisticated attackers scan quietly;
  a silent day proves less than a noisy day does.
- On a home connection your router probably blocks these knocks before they
  reach you (good!). You'll see the most action on cloud servers.
- `report` is a summary, not an alert system. Piping the log into something
  that emails you is a natural next step — ask me and I'll show you.

---

Written by DhWonder · Plaintext IT — technology,
translated. MIT license: use it, share it, no strings.
