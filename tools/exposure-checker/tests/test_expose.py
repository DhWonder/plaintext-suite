"""
Prove plain-expose reads a machine the way it claims to.

Nothing here touches a real machine. Every test builds a small fake /proc
tree on disk - the same handful of files the kernel publishes - points the
tool at it with --root, and reads what came out. That is the whole reason
--root exists: the interesting cases are a Redis wide open on the internet
and a telnet server on the office network, and you cannot wait around for a
machine to have those.

The cases worth having are the ones where the port number alone is
misleading:

  * the same database is a disaster on 0.0.0.0 and completely fine on
    127.0.0.1, and the tool has to say so in both directions;
  * "0.0.0.0" only means the internet if the machine actually has a public
    address, so the same line has to read differently on a laptop behind a
    router;
  * a service listening on both IPv4 and IPv6 is one service, not two
    problems.

    python3 tests/test_expose.py
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL_DIR = os.path.dirname(HERE)
BINARY = os.path.join(TOOL_DIR, "plain-expose")

LE = sys.byteorder == "little"

TCP_LISTEN = 0x0A
TCP_ESTABLISHED = 0x01


def squash(text):
    """
    Collapse the report's line breaks so a test can look for a sentence.

    The tool wraps its output at 78 columns for somebody reading it in a
    terminal, which means any sentence long enough to matter is split across
    lines. Testing the exact layout would mean rewriting the tests every time
    a word changes width; testing the words means the tests are about what the
    tool says, which is the part that matters.
    """
    return re.sub(r"\s+", " ", text)


def check(name, condition):
    print("  %-70s %s" % (name, "ok" if condition else "FAILED"))
    return 0 if condition else 1


# ---------------------------------------------------------------------------
# Writing the hex the kernel writes.
#
# /proc/net/tcp prints raw 32 bit words in the machine's own byte order, so
# the fixtures have to be built the same way round as the machine running
# the test. The tool works this out at runtime rather than assuming; so does
# this.
# ---------------------------------------------------------------------------

def hex_v4(dotted):
    a, b, c, d = [int(x) for x in dotted.split(".")]
    if LE:
        value = a | (b << 8) | (c << 16) | (d << 24)
    else:
        value = (a << 24) | (b << 16) | (c << 8) | d
    return "%08X" % value


def hex_v6(packed):
    """packed is 16 raw bytes."""
    out = ""
    for i in range(4):
        word = packed[i * 4:i * 4 + 4]
        if LE:
            word = word[::-1]
        out += "".join("%02X" % byte for byte in word)
    return out


def v6(text):
    import socket
    return socket.inet_pton(socket.AF_INET6, text)


class Fake(object):
    """A fake machine, built one file at a time."""

    def __init__(self):
        self.root = tempfile.mkdtemp()
        self.rows = {"tcp": [], "tcp6": [], "udp": [], "udp6": []}
        self.next_inode = 1000
        os.makedirs(os.path.join(self.root, "proc", "net"))
        os.makedirs(os.path.join(self.root, "proc", "sys", "net", "ipv6"))
        os.makedirs(os.path.join(self.root, "etc"))
        self.write("etc/passwd",
                   "root:x:0:0:root:/root:/bin/bash\n"
                   "postgres:x:114:120::/var/lib/postgresql:/bin/bash\n"
                   "redis:x:115:121::/var/lib/redis:/usr/sbin/nologin\n"
                   "www-data:x:33:33::/var/www:/usr/sbin/nologin\n")
        self.write("proc/sys/net/ipv6/bindv6only", "0\n")

    def path(self, tail):
        return os.path.join(self.root, tail)

    def write(self, tail, text):
        full = self.path(tail)
        directory = os.path.dirname(full)
        if not os.path.isdir(directory):
            os.makedirs(directory)
        handle = open(full, "w")
        handle.write(text)
        handle.close()

    # -- sockets ------------------------------------------------------------

    def listen(self, proto, addr, port, uid=0, family=4):
        return self._sock(proto, addr, port, "0.0.0.0" if family == 4 else "::",
                          0, TCP_LISTEN if proto == "tcp" else 0x07, uid, family)

    def connection(self, addr, port, peer, peer_port, uid=0):
        return self._sock("tcp", addr, port, peer, peer_port,
                          TCP_ESTABLISHED, uid, 4)

    def _sock(self, proto, addr, port, peer, peer_port, state, uid, family):
        key = proto if family == 4 else proto + "6"
        if family == 4:
            local, remote = hex_v4(addr), hex_v4(peer)
        else:
            local, remote = hex_v6(v6(addr)), hex_v6(v6(peer))
        inode = self.next_inode
        self.next_inode += 1
        self.rows[key].append(
            "%4d: %s:%04X %s:%04X %02X 00000000:00000000 00:00000000"
            " 00000000 %5d        0 %d 1 0000000000000000 100 0 0 10 0"
            % (len(self.rows[key]), local, port, remote, peer_port,
               state, uid, inode))
        return inode

    # -- processes ----------------------------------------------------------

    def process(self, pid, name, exe, inodes, deleted=False):
        base = "proc/%d" % pid
        self.write(base + "/comm", name + "\n")
        fd_dir = self.path(base + "/fd")
        os.makedirs(fd_dir)
        target = exe + " (deleted)" if deleted else exe
        os.symlink(target, self.path(base + "/exe"))
        for number, inode in enumerate(inodes):
            os.symlink("socket:[%d]" % inode,
                       os.path.join(fd_dir, str(number)))

    # -- the machine's own addresses ---------------------------------------

    def addresses(self, v4_list, v6_list=()):
        lines = ["Main:"]
        for addr in v4_list:
            lines.append("           |-- %s" % addr)
            lines.append("              /32 host LOCAL")
        lines.append("        |-- 10.255.255.255")
        lines.append("           /32 link BROADCAST")
        self.write("proc/net/fib_trie", "\n".join(lines) + "\n")

        rows = []
        for addr, scope in v6_list:
            raw = "".join("%02x" % byte for byte in v6(addr))
            rows.append("%s 02 40 %02x 80       eth0" % (raw, scope))
        self.write("proc/net/if_inet6", "\n".join(rows) + "\n")

    # -- run ----------------------------------------------------------------

    def finish(self):
        header = ("  sl  local_address rem_address   st tx_queue rx_queue tr"
                  " tm->when retrnsmt   uid  timeout inode\n")
        for name, rows in self.rows.items():
            self.write("proc/net/" + name, header + "\n".join(rows) + "\n")

    def run(self, *args):
        self.finish()
        proc = subprocess.Popen(
            [BINARY, "--root", self.root] + list(args),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, _ = proc.communicate()
        return out.decode("utf-8", "replace"), proc.returncode

    def clean(self):
        shutil.rmtree(self.root, ignore_errors=True)


def main():
    if not os.path.exists(BINARY):
        print("Build it first: make")
        return 1

    failures = 0

    # =====================================================================
    # A rented server with a public address, and several bad decisions on it.
    # =====================================================================
    print("\nA server facing the internet")
    m = Fake()
    m.addresses(["127.0.0.1", "203.0.113.9"],
                [("::1", 0x10), ("2001:db8::9", 0x00)])

    redis = m.listen("tcp", "0.0.0.0", 6379, uid=115)
    pg = m.listen("tcp", "127.0.0.1", 5432, uid=114)
    ssh4 = m.listen("tcp", "0.0.0.0", 22, uid=0)
    ssh6 = m.listen("tcp", "::", 22, uid=0, family=6)
    telnet = m.listen("tcp", "203.0.113.9", 23, uid=0)
    ntp = m.listen("udp", "0.0.0.0", 123, uid=0)
    odd = m.listen("tcp", "0.0.0.0", 48123, uid=33)
    web = m.listen("tcp", "0.0.0.0", 443, uid=33)
    m.connection("203.0.113.9", 443, "198.51.100.4", 51234, uid=33)
    m.connection("203.0.113.9", 443, "198.51.100.9", 51235, uid=33)

    m.process(700, "redis-server", "/usr/bin/redis-server", [redis])
    m.process(701, "postgres", "/usr/lib/postgresql/16/bin/postgres", [pg])
    m.process(702, "sshd", "/usr/sbin/sshd", [ssh4, ssh6])
    m.process(703, "inetd", "/usr/sbin/inetd", [telnet])
    m.process(704, "ntpd", "/usr/sbin/ntpd", [ntp])
    m.process(705, "python3", "/usr/bin/python3", [odd])
    m.process(706, "nginx", "/usr/sbin/nginx", [web], deleted=True)

    out, code = m.run("--what")
    out = squash(out)

    failures += check("a wide open Redis is a risk, not a note",
                      "[RISK]" in out and "Redis" in out)
    failures += check("it says why Redis in particular is so bad",
                      "no password at all" in out)
    failures += check("the same database on loopback is not in the exposed list",
                      "PostgreSQL" in out.split("Doors only this machine")[1]
                      and "PostgreSQL" not in out.split("Doors only this machine")[0])
    failures += check("SSH on a public address is expected, not a finding",
                      "[ OK ] SSH, which is meant to be reachable" in out)
    failures += check("telnet is a risk because the password is readable",
                      "telnet" in out and "readable text" in out)
    failures += check("a public NTP server is called out as a weapon",
                      "throw traffic at somebody else in your name" in out)
    failures += check("an unrecognised port is a question, not a verdict",
                      "I do not recognise this port" in out and "python3" in out)
    failures += check("it names the program behind each door",
                      "redis-server" in out and "sshd" in out)
    failures += check("it names the user each program runs as",
                      "running as redis" in out)
    failures += check("v4 and v6 for one service are shown once",
                      out.count("TCP port 22") == 1
                      and "listening on IPv4 and IPv6" in out)
    failures += check("live connections on a port are counted",
                      "2 connections are live on it right now" in out)
    failures += check("an upgraded but unrestarted program is reported",
                      "no longer exists on disk" in out and "nginx" in out)
    failures += check("the IPv6 wildcard trap is explained",
                      "will not close them" in out)
    failures += check("a public address is recognised as public",
                      "203.0.113.9" in out and "reachable from the internet" in out)
    failures += check("an IPv6 address is decoded and shortened",
                      "2001:db8::9" in out)
    failures += check("loopback is not called an exposure",
                      "127.0.0.1" in out)
    failures += check("a machine with real risks exits 2", code == 2)
    m.clean()

    # =====================================================================
    # The same Redis, on a laptop behind a router. Same port, different
    # sentence - this is the case the tool exists for.
    # =====================================================================
    print("\nThe same machine behind a router")
    m = Fake()
    m.addresses(["127.0.0.1", "192.168.1.40"])
    redis = m.listen("tcp", "0.0.0.0", 6379, uid=115)
    m.process(700, "redis-server", "/usr/bin/redis-server", [redis])
    out, code = m.run()
    out = squash(out)

    failures += check("with no public address it does not claim the internet",
                      "one of those is the internet" not in out)
    failures += check("but the wide open database is still a risk", code == 2)
    failures += check("the private address is named as private",
                      "192.168.1.40" in out and "a private network" in out)
    m.clean()

    # =====================================================================
    # A machine with nothing open at all.
    # =====================================================================
    print("\nA machine with nothing listening outward")
    m = Fake()
    m.addresses(["127.0.0.1", "10.0.0.5"])
    pg = m.listen("tcp", "127.0.0.1", 5432, uid=114)
    m.process(701, "postgres", "/usr/lib/postgresql/16/bin/postgres", [pg])
    m.write("proc/sys/net/ipv6/bindv6only", "1\n")
    out, code = m.run()
    out = squash(out)

    failures += check("it says so plainly rather than printing an empty list",
                      "nothing on this machine is accepting connections" in out)
    failures += check("a clean machine exits 0", code == 0)
    m.clean()

    # =====================================================================
    # What it does when it cannot see. The rule for the whole suite is that
    # a gap is reported as a gap, never as good news.
    # =====================================================================
    print("\nWhen it cannot see who owns a port")
    m = Fake()
    m.addresses(["127.0.0.1", "203.0.113.9"])
    m.listen("tcp", "0.0.0.0", 6379, uid=115)     # no process claims it
    out, code = m.run()
    out = squash(out)

    failures += check("an unowned port is still reported as a risk",
                      "[RISK]" in out and "Redis" in out)
    failures += check("and the missing owner is spelled out, not left blank",
                      "could not be traced to a program" in out)
    m.clean()

    # =====================================================================
    # Address formatting, which is fiddly enough to be worth its own set.
    #
    # /proc writes IPv6 as 32 hex characters. Every one of these has to come
    # back out in the form somebody would actually type into a firewall
    # rule, because an address written wrong is a different address.
    # =====================================================================
    print("\nWriting addresses back the way people write them")
    cases = [
        ("::1", "loopback"),
        ("2001:db8::9", "one gap in the middle"),
        ("2001:db8:0:1:2:3:4:5", "no gap at all"),
        ("fe80::1", "link local"),
        ("2001:db8::", "a gap at the end"),
        ("::ffff:192.0.2.7", "an IPv4 address in IPv6 clothing"),
    ]
    m = Fake()
    m.addresses(["127.0.0.1"], [(text, 0x00) for text, _ in cases])
    sock = m.listen("tcp", "127.0.0.1", 5432, uid=114)
    m.process(701, "postgres", "/usr/lib/postgresql/16/bin/postgres", [sock])
    out, _ = m.run()
    out = squash(out)
    for text, what in cases:
        failures += check("%s comes back as %s" % (what, text),
                          text in out)
    m.clean()

    # =====================================================================
    # --check has to stay actionable: fewer words, same facts.
    # =====================================================================
    print("\nThe short list")
    m = Fake()
    m.addresses(["127.0.0.1", "203.0.113.9"])
    redis = m.listen("tcp", "0.0.0.0", 6379, uid=115)
    ssh = m.listen("tcp", "0.0.0.0", 22, uid=0)
    m.process(700, "redis-server", "/usr/bin/redis-server", [redis])
    m.process(702, "sshd", "/usr/sbin/sshd", [ssh])
    out, code = m.run("--check")
    out = squash(out)

    failures += check("--check drops the lines that need no action",
                      "[ OK ]" not in out)
    failures += check("--check still names the port to act on",
                      "port 6379" in out)
    failures += check("--check still counts the good news in the summary",
                      "1 fine" in out)
    m.clean()

    # =====================================================================
    # Refusing rather than guessing.
    # =====================================================================
    print("\nRefusing to guess")
    empty = tempfile.mkdtemp()
    proc = subprocess.Popen([BINARY, "--root", empty],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = proc.communicate()
    out = squash(out.decode())
    failures += check("with no socket tables it says so instead of 'all clear'",
                      "Could not read the socket tables" in out
                      and proc.returncode == 3)
    shutil.rmtree(empty, ignore_errors=True)

    proc = subprocess.Popen([BINARY, "--nonsense"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = proc.communicate()
    failures += check("an option it does not understand is refused, not ignored",
                      proc.returncode == 3)

    print()
    if failures:
        print("%d checks failed." % failures)
        return 1
    print("All exposure checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
