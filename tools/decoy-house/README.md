# decoy-house

A machine that looks worth breaking into, and tells on whoever does.

A honeypot. You open what looks like an ordinary, slightly careless small
business server: a login that lets anyone in, an admin panel somebody forgot
about, and files on it a thief wants. Nobody legitimate has a reason to touch
it, so anyone who does is either scanning you or up to something, and now you
are watching them do it in detail rather than guessing.

```
sudo python3 decoy_house.py sensor --ports 22 80 2222
python3 decoy_house.py console --open
python3 decoy_house.py report
```

## Before you use port 22

Ports below 1024 need sudo, which is why that first line has it. The catch is
that most machines already have something on 22 and 80. If sshd is on 22, the
sensor cannot have it: you get `could not open port 22: Address already in use`,
that port is skipped, and the sensor carries on with the others. It does not
stop, so read the startup lines and check every port you asked for actually
opened.

If you are logged into the machine over SSH, think before you free up 22. Moving
sshd to another port to make room is how people lock themselves out of a remote
box. Get the new port working in a second terminal, and confirm the firewall
allows it, before you close the session you are already in.

The easy version is a machine with nothing else on it, where the honeypot can
have the real ports. Failing that, high ports work fine:

```
python3 decoy_house.py sensor --ports 2222 8080
```

You catch fewer bored internet scanners that way, since they mostly try 22 and
80. Inside an office network it makes little difference: anything touching the
sensor at all is the thing you wanted to know about.

## Two parts

**The sensor** is the honeypot itself, run on a machine you want to watch. It
presents a believable machine: a real-looking SSH banner, a login that accepts
anything, a fake shell over the top of a fake filesystem, and a web admin panel.
It records every keystroke, every credential tried, every file read, every
attempt to pull down a payload.

**The console** is where your sensors report. Run it once, point every sensor at
it, and watch every attacker across every machine from one screen in the
browser. It stores everything in one SQLite file and it only ever receives.

## The valuable content

A honeypot with nothing on it tells you somebody scanned you. A honeypot that
looks lived-in tells you what they are really after. So the sensor builds a
believable small business server: credentials in an `.env`, a customer database
export, a VPN profile, a backup script with cloud keys in it, an IT handover
note with the admin password. The things that are genuinely on machines like
this, and that a threat actor recognises instantly as worth taking.

Every secret in it is fake, unique to that sensor, and is a **canary token**.

## Canary tokens: how you follow an attacker honestly

A canary token is bait that tells on whoever takes it. Each fake credential is
wired so that if it is ever used, it calls your console and tells you which
piece of bait fired and roughly from where.

This is the honest, legal way to follow an attacker after they have gone. You
never touch their machine. You leave something they choose to take, and it is
the token that phones you, not you that phones them. That distinction is the
whole thing, and it is why this is a tool a security business can put its name
on rather than a thing that gets you arrested.

## Safe by design

- **The sensor never runs anything an attacker sends.** Every command gets a
  scripted answer from the fake filesystem. Whatever they type, the real
  machine does nothing but write it down. It is a puppet show with a notebook.
  Tested: an attacker running `touch`, `echo >` and chained commands creates
  nothing on the real disk.
- **The console only ever receives.** Sensors report to it; it never sends a
  command back to anything. Reports flow one way, inward. It binds to localhost
  unless you force it otherwise, and warns you if you do.

## What this will not do

It will not touch an attacker's machine. Following someone by breaking into
their computer is illegal wherever you are, and it is not what this is for. If
that is what you were hoping for, this is the wrong tool, on purpose.

## Where it fits

Inside an office network a sensor is a tripwire: nothing should ever touch it,
so the day something does, you know a machine on your network has been taken
over and is looking around. On an internet-facing box it shows you, with data
instead of guesses, that the internet starts trying your doors within minutes.

MIT licensed. Run it on machines you own, on a network you control.
