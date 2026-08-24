# exposure-checker

What can reach this machine, and what is behind each door?

Every listening port is a door. `netstat` will happily tell you there are
seventeen of them, which is not an answer to anything. This tells you which of
those doors another machine can actually knock on, which program is standing
behind each one, and which of them matter.

    $ sudo ./plain-expose

    Doors other machines can reach

      TCP port 6379 (Redis) - reachable from every network this machine is on,
          and one of those is the internet
              held open by redis-server (process 700), running as redis
      [RISK]  Redis should never be reachable from another machine, and this one
              historically ships with no password at all - reaching it may be the
              whole attack. Bind it to 127.0.0.1.

      TCP port 22 (SSH) - reachable from every network this machine is on, and
          one of those is the internet
              held open by sshd (process 702), running as root
              listening on IPv4 and IPv6
      [ OK ]  SSH, which is meant to be reachable. Worth confirming password
              logins are off and only keys are accepted.

## The three questions it answers

**Can anything outside actually get here?** A service bound to `127.0.0.1` is
two programs on this machine talking to each other. Nothing outside can reach
it, so it is not exposure, and a report that lists it next to a genuinely open
port is training you to ignore the list. Loopback services are put in their own
section and no verdict is attached to them.

**What is behind it?** "Port 5432 is open" is trivia. "PostgreSQL, running as
postgres, held open by process 701, accepting connections from every network
this machine is on" is something you can act on. The kernel does not hand you
that join - it says inode 41207 is listening, and separately lists the inodes
each process holds - so the tool does the join. That is also why it wants root:
you can only look inside your own processes.

**Does it matter?** Some doors are meant to be open; a web server on 443 is
doing its job. Some are catastrophic; Redis, Memcached, MongoDB, Elasticsearch
and the Docker API all shipped for years with no authentication at all, on the
assumption that nothing outside could reach them. For those, the port being
open *is* the breach - there is nothing else to get past.

## The distinction the tool exists for

`0.0.0.0` does not mean "the internet". It means every network card this
machine has, and whether that includes the internet depends on whether one of
them holds a public address. So the tool reads the machine's own addresses
first, and the same open database reads differently on a rented server than on
a laptop behind a router:

    reachable from every network this machine is on, and one of those is the internet
    reachable from every network this machine is on

Both are worth fixing. Only one of them has probably already happened.

## The other direction: what this machine can be used to do

A handful of UDP services answer a small question with a large reply - DNS,
NTP, SNMP, SSDP, chargen. Point one of those at a forged return address and
your machine posts the large reply at somebody else. That is a reflection
attack, and the machine doing it is not the victim.

[traffic-analyzer](../traffic-analyzer) in this suite tells you when one is
being thrown at you. This tells you whether you are the one throwing it.

## What it will tell you that other tools will not

- **A program still running code that no longer exists on disk.** The package
  was updated, the service was never restarted, so the machine has the fix
  installed and is not using it. This is one of the most common ways a
  "patched" machine stays vulnerable, and it is invisible to a version check.
- **The IPv6 trap.** On most machines a socket bound to `::` accepts IPv4
  connections through the same socket. People close a port in the IPv4
  firewall, watch it disappear from `netstat -4`, and leave it open. The tool
  reads `bindv6only` and says so.
- **Something reading raw traffic.** A packet socket means a program is reading
  traffic that was not addressed to it. If you are running `tcpdump`, that is
  it. If you are not, that is a question.
- **Ports with no owner at all**, distinguished from ports whose owner you were
  not allowed to see. Those are two very different findings and saying the
  wrong one sends you chasing the wrong thing.

## What it does not do

It does not scan anything. It reads files the kernel already publishes under
`/proc`, on the machine it is running on. That is deliberate twice over: port
scanning a machine you do not own is a criminal offence in most places,
including here, and reading the answer from the inside is more accurate than
guessing at it from the outside anyway.

It runs no commands, opens no sockets of its own, and sends nothing anywhere.
The one exception is the notify wrapper below, which is off until you set it up.

It only covers Linux, because it reads Linux's `/proc`.
[system-checker](../system-checker) covers Windows as well and has a much
shallower version of this check built in - it lists port numbers and nothing
else. This is the tool for when that list raised a question.

## Running it

    make
    sudo ./plain-expose

Without `sudo` it still lists every door, because the socket tables are
readable by anyone - but it cannot name the program behind most of them, and it
says how many it could not name rather than leaving you to read the blanks as
nothing.

    ./plain-expose            the report
    ./plain-expose --what     also list the loopback services and the machine's addresses
    ./plain-expose --check    only the things worth acting on
    ./plain-expose --list     one plain line per door, for scripts
    ./plain-expose --root DIR read DIR/proc instead of /proc

Exit code is `0` nothing to do, `1` worth a look, `2` a real risk.

## Being told when a door opens

    sh plain-expose-notify.sh notify test     set the email up
    sh plain-expose-notify.sh                 run it

This one does not email you the report. On a machine nobody has touched, the
report says the same thing every week, and an email that always says the same
thing is one you stop opening - including the week it changed.

Instead it remembers which doors were open last time and emails you when the
list is **different**: a port that was not there yesterday, or one that has
gone. A new listening port on a server nobody logged into is worth knowing
about that morning. The same twelve ports as last Tuesday is not.

It also emails on a real risk even when nothing changed, because a Redis that
has been wide open for a month has not stopped being wide open.

    0 7 * * * sh /path/to/plain-expose-notify.sh

Everything about what the email contains and where it goes is in
[tools/notifications](../notifications).

## Testing it

    make check

The tests build small fake `/proc` trees on disk and point the tool at them
with `--root`. That is what `--root` is for: the cases worth testing are a
Redis wide open on the internet and a telnet server on the office network, and
you cannot wait around for a machine to have those. It also means the tests
need no particular machine and change nothing on this one.

`--root` works on a copied tree too, though the `/proc/<pid>/fd` symlinks have
to survive the copy for the program names to come out, and most ways of copying
a directory do not preserve them.

## Limitations, written down

- **Linux only.** It reads `/proc`. There is no BSD or macOS version.
- **It sees what this machine can see.** On a host running containers, ports
  belonging to a container in its own network namespace show up with no owner.
  The tool says that is what happened rather than calling them unowned and
  leaving it there, but it cannot look inside the container from outside.
- **The port table is opinionated and short.** It covers what actually turns up
  on small business machines. An unrecognised port is reported as unrecognised
  and handed back to you - never as fine.
- **A firewall is not consulted.** A port can be listening and still be
  unreachable because something in front of the machine drops the traffic. The
  tool reports what the machine has open, which is the thing that is true
  regardless of whether the firewall rule survives the next reboot.
- **A snapshot, not a watch.** It reads the socket tables once. A service that
  listens for thirty seconds a day will only be caught if you happen to look
  during those thirty seconds. The notify wrapper narrows that gap; it does not
  close it.

## License

MIT.
