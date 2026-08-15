# plain-check

A small program that looks over a Linux machine and reports what it finds in
plain English — the way I'd explain it to a client across the table, not the way
a scanner dumps it into a log.

```
Disk space
  [LOOK]  the main disk is 88% full. Not urgent, but plan a cleanup
          before it becomes urgent.

User accounts
  [RISK]  account 'user1' has NO password. Anyone at the keyboard can
          become them. Set a password or lock the account today.
```

## Why this exists

Security tools mostly talk to security people. When a small business asks "is this
machine okay?", the honest answer usually involves five boring things — a disk
about to fill up, a machine that hasn't rebooted (so hasn't really updated) in
months, a forgotten open port, an account with no password, a system file anyone
can edit. plain-check walks exactly that list and explains each finding, calmly.

It's also deliberately written in plain ANSI C with no dependencies: it compiles
on more or less anything with a C compiler, and the source is meant to be read.
If you're curious what your machine is being checked for, open the .c file —
every check has a comment explaining, in normal words, why it matters.

## What it checks

Disk fullness on the main drive, days since the last restart, listening network
ports (with plain-English notes on famous trouble ports like Telnet and exposed
Remote Desktop), accounts with no password or with hidden administrator power,
and world-writable files under /etc.

## What it does NOT do

It never changes anything — it only reads. It's a ten-second look-over, not a
professional audit: passing plain-check means "nothing obviously wrong," not
"secure." For the real thing, that's literally my day job — see the link below.

## Build and run

```
cc -ansi -pedantic -Wall -Wextra -o plain-check plain-check.c
./plain-check          # sudo ./plain-check to include the password checks
```

The exit code is 0 (healthy), 1 (worth a look) or 2 (real risk found), so you can
run it from a script and only get emailed when something needs attention.

## Honest limitations

- Linux only (it reads /proc and /etc directly). The port and account checks
  have no meaning on other systems.
- The known-trouble port list is short and opinionated on purpose — it flags the
  doors that hurt small businesses in practice, not every theoretical one.
- Without sudo, the no-password check politely skips instead of guessing.

---

Written by DhWonder · Plaintext IT — technology,
translated. MIT license: use it, share it, no strings.
