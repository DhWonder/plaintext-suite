# system-checker

What is this machine, and is anything wrong with it? Answered in plain English.

Two jobs in one run, in the order you actually need them when somebody hands you
a machine you have never seen:

**1. What am I looking at.** Make and model, operating system, processor, memory,
graphics, disks, network, and whether this is real hardware or a virtual machine.
The things you want to know before you touch anything, and the things that go on
a quote.

**2. Is anything wrong.** Full disks, forgotten open ports, accounts with no
password, system files anyone can edit, and on Windows the firewall, antivirus,
disk encryption and how long since it was patched.

It only ever **reads**. It changes nothing, installs nothing, starts nothing, and
sends nothing anywhere.

The open ports part of that second job is deliberately shallow - it lists port
numbers, so you know to ask. When the answer to "what is on port 6379" matters,
[exposure-checker](../exposure-checker) names the program behind each one, says
whether anything outside can actually reach it, and tells a loopback service
apart from a genuinely open one.

---

## Two machines, two collectors

There are two of these because there are two kinds of machine, and the honest way
to read a Windows box is to ask Windows rather than to guess.

| | | |
|---|---|---|
| **plain-check.c** | Linux | ANSI C, no dependencies, compiles anywhere |
| **windows-check.ps1** | Windows | PowerShell, nothing to install |

Both print the same report in the same order, so you can put two machines side by
side and read them the same way.

If you are not sure which you want, ask:

```
sh system-check.sh
```

```
  Which machine are you looking at?

    1) this Linux machine
    2) a Windows machine

  Choose [1 or 2, default 1]:
```

It defaults to whatever it is running on, builds the Linux one if it has not been
built yet, and for Windows hands you the command to take to that machine. It takes
an answer on the command line too (`sh system-check.sh linux`), so it never sits
waiting at a prompt in a script or in cron.

---

## Running them directly

**Linux**

```
make                    build it
./plain-check           both halves
./plain-check --what    just what the machine is
./plain-check --check   just the health and security checks
sudo ./plain-check      include the password check and the serial number
```

**Windows**

```
powershell -ExecutionPolicy Bypass -File windows-check.ps1
powershell -ExecutionPolicy Bypass -File windows-check.ps1 -What
powershell -ExecutionPolicy Bypass -File windows-check.ps1 -Check
```

Run PowerShell as Administrator to include the account, firewall and BitLocker
checks. Without it the tool says which parts it could not see, rather than quietly
leaving them out.

---

## What it tells you

Facts first, with no judgement attached, because the inventory is describing the
machine rather than grading it:

```
Operating system
  distribution   Ubuntu 24.04.4 LTS
  kernel         Linux 6.8.0-51-generic
  architecture   x86_64
  hostname       reception-pc

Real or virtual
  running on     a virtual machine on VMware

Processor
  model          Intel(R) Core(TM) i5-8500 CPU @ 3.00GHz
  count          6 logical processors
  virtualisation supported by the processor

Memory
  fitted         15.6 GB
  free right now 9.1 GB (58% of the total)
  swap           2.0 GB
```

Then the checks, in three kinds of line: `[ OK ]` is fine, `[LOOK]` is worth ten
minutes sometime soon, `[RISK]` is worth acting on this week.

```
User accounts
  [RISK]  account 'test' has NO password. Anyone at the keyboard can become them.
  [ OK ]  only 'root' has administrator-level user id. As it should be.
```

The exit code says the same thing for a script: **0** healthy, **1** something worth
a look, **2** a real risk.

---

## Where the numbers come from

Everything on Linux is read from files the kernel already publishes: `/proc`,
`/sys` and `/etc`. No commands are run and nothing is parsed out of another tool's
output, so there is nothing to install and nothing to go wrong when a distribution
changes its formatting.

On Windows it uses the CIM classes that ship with the operating system, which is
why it works on a machine you are not allowed to put software on. That is usually
the machine that most needs looking at.

**If a file or a class is not there, the tool says it could not tell.** It never
fills a gap with a guess. This matters more than it sounds on the Windows side,
where "there is no antivirus on this machine" and "I could not ask about
antivirus" lead somewhere completely different, and only one of them is a reason
to relax.

---

## Honest limitations

- **It reads. It does not fix anything.** Every finding is something for a person
  to decide about.
- **It looks at this machine only.** There is no network scanning here and no
  reaching into anything else. If you want to look at a client's machine, you run
  it on that machine, with their agreement.
- **The security checks are a short list, not an audit.** They cover the handful
  of things that actually bite small businesses. A clean run means those things
  are fine, not that the machine is secure.
- **Some things need root or Administrator**: the password check and the hardware
  serial on Linux, the accounts, firewall and BitLocker on Windows. Without it the
  report says so on the line where the answer should have been.
- **A container reports its host's disks, memory and ports** as if they were its
  own, because from inside a container they are. plain-check notices it is in a
  container and says to read those numbers with that in mind.
- **macOS is not covered.** `system-check.sh` says so rather than pretending.

---

## Layout

```
plain-check.c        the Linux collector, ANSI C
windows-check.ps1    the Windows collector, PowerShell
system-check.sh      asks which machine, then runs the right one
plain-check-notify.sh  runs plain-check and emails the report if it finds something
notify.py            the shared notification code, same as the other tools
Makefile             build, and `make check` to prove it still works
```

`plain-check` is C and stays C: teaching a C program to speak SMTP would mean a
second copy of the notification logic in a second language, which is how two tools
end up disagreeing about what they sent. So the C program reads, prints, and exits
0, 1 or 2, and the shell wrapper next to it hands that output to the shared
notifier. [`../notifications`](../notifications) is the whole story.

---

Written by DhWonder for [Plaintext IT](https://github.com/DhWonder/plaintext-suite). MIT licensed.
Run it on your own machines, or on ones you have permission to look at.
