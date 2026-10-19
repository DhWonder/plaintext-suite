# vpn walkthrough

What every file contains, what every function does, and how a packet actually
travels. Each function gets a **technical** explanation and a **like you're
five** one; the trickier ones also get a diagram or a worked example with real
numbers taken from the live machine.

**Build:**

```
make
```

The `Makefile` builds both binaries; it tracks the headers, so touching
`vpn_crypto.h` rebuilds everything that needs it. Needs `libssl-dev`.

`-ansi` means C89: no `//` comments, every variable declared at the top of its
block.

Every function heading carries a tag: `[both]` means the client and the server
both call it, `[client]` and `[server]` mean only that side's path reaches it.
It describes *use*, not location — `route_cmd`, `nat_rules` and `ip_forward` all
live in the shared `vpn_net.c` but each is only ever called by one side.

---

## Contents

| | |
|---|---|
| [The big picture](#the-big-picture) | what the whole thing does |
| [Follow one packet](#follow-one-packet) | a single ping, hop by hop |
| [The files](#the-files) | what lives where |
| [`vpn_net.h`](#vpn_neth--the-shared-contract) | constants, state, prototypes |
| [`vpn_net.c`](#vpn_netc--the-shared-implementation) | 17 functions in 6 groups |
| [`client.c`](#clientc) · [`server.c`](#serverc) | the two mains |
| [`vpn_crypto.c`](#vpn_cryptoc--encryption) | chacha20, and why the nonce matters |
| [The bug that was found](#the-bug-that-was-found) | side by side, wrong vs right |
| [What is tested](#what-is-tested) | all green, plus the slirp story |
| [Running it](#running-it) | plus a troubleshooting tree |
| [Glossary](#glossary) | every term used above |

---

## The big picture

```
         CLIENT machine                                SERVER machine
 ┌──────────────────────────────┐            ┌──────────────────────────────┐
 │  browser / ping / curl       │            │                              │
 │            │                 │            │                              │
 │            ▼                 │            │                              │
 │  ┌────────────────────┐      │            │   ┌────────────────────┐     │
 │  │ tun0    10.8.0.2   │      │            │   │ tun0    10.8.0.1   │     │
 │  └────────┬───────────┘      │            │   └────────▲─┬─────────┘     │
 │           │ read()           │            │    write() │ │ read()        │
 │  ┌────────▼───────────┐      │            │   ┌────────┴─▼─────────┐     │
 │  │    vpn_client      │      │            │   │    vpn_server      │     │
 │  └────────┬───────────┘      │            │   └────────▲─┬─────────┘     │
 │           │ sendto()         │            │  recvfrom()│ │               │
 │  ┌────────▼───────────┐      │  udp/51820 │   ┌────────┴─▼─────────┐     │
 │  │  real network card ├──────┼───────────►┼───┤  real network card │     │
 │  └────────────────────┘      │            │   └────────┬───────────┘     │
 └──────────────────────────────┘            │            │ forwarding+nat  │
                                             │            ▼                 │
                                             │      the internet            │
                                             └──────────────────────────────┘
```

`tun0` is a **fake network card**. The machine treats it like any other, but
whatever it sends into `tun0` pops out inside our program, which puts it in an
ordinary UDP message and posts it to the other side.

---

## Follow one packet

You type `ping 1.1.1.1` on the client. Here is what happens to that one packet.

```
 ①  ping builds an IP packet         from 10.8.0.2  to 1.1.1.1
                │
 ②  kernel picks a route            "default goes via tun0" → into tun0
                │
 ③  vpn_client's read(tun_fd)       gets those exact bytes
                │
 ④  vpn_encrypt, then sendto()      wrapped: from CLIENT:xxxxx to SERVER:51820
                │                   ┌──────────────────────────────┐
                │                   │ outer: real addrs, udp 51820 │
                │                   │ nonce + ENCRYPTED inner pkt  │
                │                   └──────────────────────────────┘
       ~~~~~~~~ the real network ~~~~~~~~
                │
 ⑤  recvfrom(), then vpn_decrypt   unwraps; remembers who sent it
                │
 ⑥  write(tun_fd)                   inner packet handed to the server's kernel
                │
 ⑦  forwarding + masquerade         from 10.8.0.2 → rewritten to SERVER's addr
                │
 ⑧  out to 1.1.1.1                  which sees only the server, never the client
                │
 ⑨  reply comes back                masquerade reverses it → back to 10.8.0.2
                │
 ⑩  routed into tun0, read by vpn_server, sendto() the remembered client addr
                │
 ⑪  vpn_client recvfrom() → write(tun_fd) → the kernel hands it to ping
```

Steps ③–④ and ⑤–⑥ are `forward_loop`. Steps ⑦ and ⑨ are done entirely by the
kernel, because `setup_server` turned on forwarding and installed the NAT rules.

**Like you're five.** You put your letter inside a bigger envelope addressed to a
friend. They open it, put their own return address on your letter, and post it
properly. Replies come back to them, and they wrap them up again for you.

---

## The files

```
         vpn_net.h + vpn_crypto.h ─── the contracts everyone agrees on
                  │
      ┌───────────┼───────────┬──────────────┐
      │           │           │              │
  client.c      server.c      vpn_net.c   +   vpn_crypto.c
   (main)      (main)       (main)      (everything)
      └───────────┴───────────┴──────────────┘
                     all link against
```

| File | Lines | What it is |
|---|---|---|
| `vpn_net.h` | 135 | The shared contract: constants, the state struct, prototypes |
| `vpn_net.c` | 826 | Everything both sides do: tunnel, system changes, packet loop |
| `vpn_crypto.h` | 75 | The crypto contract: key size, nonce size, the three calls |
| `vpn_crypto.c` | 217 | OpenSSL ChaCha20-Poly1305, and the per-packet wrapper |
| `client.c` | 107 | Just a `main` — takes over routing, runs the loop, restores |
| `server.c` | 119 | Just a `main` — enables forwarding and NAT, runs the loop, restores |

**Reading it for the first time?** `vpn_net.h` → `client.c` → `forward_loop` →
the rest of `vpn_net.c`.

---

## `vpn_net.h` — the shared contract

### The addressing, as a map

```
   CLIENT                                              SERVER
   ┌────────────────────────┐                ┌────────────────────────┐
   │ tun0  10.8.0.2         │◄══ tunnel ════►│ tun0  10.8.0.1         │
   │       mtu 1400         │                │       mtu 1400         │
   │                        │                │                        │
   │ real  192.168.57.254   │───── udp ─────►│ real  192.168.57.1     │
   │       (vboxnet0)       │      51820     │       (eth0)           │
   └────────────────────────┘                └────────────────────────┘
                       tunnel subnet: 10.8.0.0/24
```

**Why MTU 1400 and not 1500?** Because the inner packet has to fit inside the
outer one:

```
   a normal packet on the wire ....................... 1500 bytes max
   ┌──────────────┬─────────────────────────────────────────────────┐
   │ outer ip+udp │  the whole inner packet, up to 1400             │
   │   28 bytes   │                                                 │
   └──────────────┴─────────────────────────────────────────────────┘
                                              ↑ 72 bytes of slack
```

Set the inner size to 1500 and every packet would have to be split in two.

### `struct vpn_net`, as a notebook

```
   ┌─ what we're using ─────────────────────────────────────────┐
   │  tun_fd        the open handle — close it, interface gone  │
   │  tun_name      the name the kernel actually gave us        │
   │  server_ip     kept so teardown removes the RIGHT route    │
   ├─ how we found the machine ─────────────────────────────────┤
   │  old_gateway   where the default route pointed             │
   │  egress_dev    which interface it left through             │
   │  old_ip_forward  the forwarding setting's old value        │
   ├─ what we changed (tick boxes) ─────────────────────────────┤
   │  applied_tun             the interface exists              │
   │  applied_host_route      the pinned route exists           │
   │  applied_default_route   the ORIGINAL default is gone      │
   │  applied_ip_forward      the setting was changed           │
   │  applied_nat             the firewall rules were added     │
   └────────────────────────────────────────────────────────────┘
```

**Like you're five.** It's a notebook. On the left you write down how you found
things; on the right you tick off each change you made. When you leave you undo
only the ticked boxes — so if you got interrupted half way, you put back exactly
what you moved and nothing else.

---

## `vpn_net.c` — the shared implementation

Seventeen functions, in six groups:

```
                                                          used by
  1. talking to an interface   set_ifr_name               both
                               set_iface_addr             both
  2. running commands          run_cmd                    both
                               route_cmd                  client
                               nat_rules                  server
  3. reading machine state     route_lookup               both
                               ip_forward                 server
  4. building the tunnel       vpn_net_init               both
                               tun_alloc                  both
                               iface_config               both
  5. setup and teardown        setup_client               client
                               teardown_client            client
                               setup_server               server
                               teardown_server            server
  6. stopping and forwarding   on_signal                  both
                               vpn_install_handlers       both
                               forward_loop               both
```

---

### Group 1: talking to a network interface

#### `set_ifr_name(ifr, name)` — prepares a blank request with an interface's name filled in   `[both]`

**Technical.** Zeroes the `struct ifreq` and copies the name in with guaranteed
nul termination. Exists because the same three lines start six other functions.

**Like you're five.** Before posting a letter you need a clean envelope with the
name on it. This fetches the envelope and writes the name.

#### `set_iface_addr(sock, name, request, ip)` — writes one address onto an interface, chosen by `request`   `[both]`

**Technical.** Three settings share one union field; only the request number
differs. A malformed address is rejected before the kernel sees it.

```
   struct ifreq
   ┌─────────────┬──────────────────────────┐
   │ ifr_name    │ ifr_addr  ◄──────────────┼── SIOCSIFADDR    (my address)
   │  "tun0"     │           ◄──────────────┼── SIOCSIFDSTADDR (far end)
   │             │           ◄──────────────┼── SIOCSIFNETMASK (netmask)
   └─────────────┴──────────────────────────┘
```

So one function covers all three. A malformed address is rejected before the
kernel sees it.

**Like you're five.** Three questions answered on the same blank line of the same
form. One helper fills it in and changes only which question it's answering.

---

### Group 2: running system commands

#### `run_cmd(argv)` — runs another program and reports whether it succeeded   `[both]`

**Technical.** `fork` → `execvp` in the child → `waitpid` in the parent; success
only on exit status 0.

**Why not `system()`** — this is the whole reason:

```
   system("ip route add 1.2.3.4 ...")        execvp with a list
   ┌──────────────────────────────┐          ┌──────────────────────────┐
   │ one string → handed to SHELL │          │ ["ip","route","add",...] │
   │ shell splits it, and honours │          │ no shell, no splitting,  │
   │ ; | && $() as COMMANDS       │          │ nothing to smuggle in    │
   └──────────────────────────────┘          └──────────────────────────┘
        server ip comes from argv                    safe
```

**Like you're five.** Shout an errand across the room and a troublemaker can add
words to it. Hand over a list of exactly the words you mean, and they can't.

#### `route_cmd(op, dest, gw, dev)` — adds or removes one route   `[client]`

**Technical.** Builds `ip route <op> <dest> [via <gw>] [dev <dev>]`. Both tails
are optional:

| Situation | Command produced | Why |
|---|---|---|
| Add, via a router | `ip route add 8.8.8.8 via 172.20.10.1 dev wlp8s0` | full form |
| Add, directly reachable | `ip route add 192.168.57.1 dev vboxnet0` | no router in between, so no `via` |
| Any delete | `ip route del 192.168.57.1` | the destination alone identifies it |

That last row matters: the host's default route carries `metric 600`, and
over-describing a route on delete can fail to match it.

**Like you're five.** A tiny form: *add or remove*, *where to*, and only if you
need them, *through whom* and *out of which door*. To throw something away you
only have to say what it is, not describe it completely.

#### `nat_rules(op, tun, egress)` — adds (`-A`) or removes (`-D`) the three firewall rules   `[server]`

```
   ①  MASQUERADE     10.8.0.2 ──► rewritten to the server's own address
                     so the internet's reply comes back to the server

   ②  FORWARD out    tun0 ──────► eth0     allowed
   ③  FORWARD in     eth0 ──────► tun0     allowed, but ONLY replies to
                                            conversations the client started
```

Rule ③ is what stops the outside world reaching into the tunnel. The three
belong together, which is why one `applied_nat` flag covers all of them.

**Like you're five.** A grown-up posts letters for a kid with no address, putting
their own on the envelope so replies come home. Letters go out and answers come
back — but strangers starting a new conversation are turned away.

---

### Group 3: reading what the machine is doing

#### `route_lookup(dest, gw, dev)` — answers "how does this machine reach that address right now?"   `[both]`

**Technical.** Keeps the most specific route covering `dest` — the same choice the
kernel makes. Gateway comes back `0.0.0.0` when the address is on-link. Passing
`dest = 0` asks for the default route.

**Worked example — the real table on this machine.** Looking up `192.168.57.1`:

```
 the address, as the table stores it:   192.168.57.1  →  0139A8C0

 Iface       Destination   Gateway    Flags   Mask
 ─────────────────────────────────────────────────────
 wlp8s0      00000000      010A14AC   0003    00000000    ← the default route
 wlp8s0      000A14AC      00000000   0001    F0FFFFFF
 vboxnet0    0039A8C0      00000000   0001    00FFFFFF

 test each row:  (address AND mask) == destination ?

   wlp8s0 default   0139A8C0 & 00000000 = 00000000 == 00000000   ✓ matches
   wlp8s0 subnet    0139A8C0 & F0FFFFFF = 0039A8C0 != 000A14AC   ✗
   vboxnet0         0139A8C0 & 00FFFFFF = 0039A8C0 == 0039A8C0   ✓ matches

 two matches — keep the narrower mask:
   00FFFFFF  is narrower than  00000000        → vboxnet0 wins

 result:  dev vboxnet0,  gateway 0.0.0.0  (directly reachable, no router)
```

That last line is the whole point. Compare with `ip route get 192.168.57.1`,
which says `192.168.57.1 dev vboxnet0` — same answer.

**Like you're five.** We look up how to reach *this* place instead of assuming.
Sometimes it's down the road; sometimes it's next door and you just walk over.
Getting this wrong is exactly [the bug that was found](#the-bug-that-was-found).

#### `ip_forward(value, write_it)` — reads or writes the forwarding sysctl   `[server]`

**Technical.** One function for both directions; `write_it` chooses. The server
reads the current value before changing it, so the original can be restored.

```
   off (0)                          on (1)
   ┌─────────┐                      ┌─────────┐
   │ tun0 ─╳ │  packets stop here   │ tun0 ───┼──► eth0   packets pass through
   │ eth0    │                      │         │
   └─────────┘                      └─────────┘
```

**Like you're five.** A switch on the wall marked "let things pass through". Note
which way it was before you flip it, and put it back when you leave.

---

### Group 4: building the tunnel

#### `vpn_net_init(state)` — clears the struct and marks the tunnel handle as unused   `[both]`

**Technical.** Zeroes everything, then sets `tun_fd = -1`.

**Why `-1` and not just zero:**

```
   handle 0 = the program's own input (stdin)
   handle 1 = its output
   handle 2 = its errors

   a struct cleared to all-zeros claims to own handle 0
   → teardown would close the program's own input
```

**Like you're five.** Empty means empty. If we left the box saying "0", someone
would go looking for a toy called 0.

#### `tun_alloc(state, name)` — creates the fake network card and stores its handle   `[both]`

**Technical.** Asks `/dev/net/tun` for a plain IP interface with no per-packet
header. The name is **read back** afterwards — the kernel picks another if `tun0`
is taken. The interface lives only while the descriptor is open.

```
   open("/dev/net/tun")  ──►  ioctl(TUNSETIFF, "tun0")  ──►  interface exists
                                                                    │
                       close(fd)  ◄─────────────────────────────────┘
                            └──► interface disappears immediately
```

**Like you're five.** This asks the computer for a magic pipe. What you push in
one end comes out the other as if it arrived from the network. Hold onto the
handle — let go and the pipe vanishes.

#### `iface_config(name, local_ip, peer_ip, netmask, mtu)` — gives the interface its addresses and size, then switches it on   `[both]`

**Technical.** Five steps in order:

```
   1. SIOCSIFADDR      my address        10.8.0.2
   2. SIOCSIFDSTADDR   the far end       10.8.0.1
   3. SIOCSIFNETMASK   netmask           255.255.255.0
   4. SIOCSIFMTU       biggest packet    1400
   5. SIOCGIFFLAGS  ─┐  read what's already on
      SIOCSIFFLAGS  ─┘  add UP and RUNNING, write back
```

Step 5 is a **read-modify-write**, not a plain write:

```
   wrong:  write(UP)            → wipes flags the kernel already set
   right:  read → flags|UP      → keeps them, adds ours
```

The socket opened here is never used to send anything; these requests simply
have to be made through some socket.

**Like you're five.** The pipe exists but has no address and isn't switched on.
This writes the address on it, says who's at the other end, and flips the switch
— after *looking* at which switches are already up, so it doesn't turn off
something the computer had already turned on.

> **Note.** Setting the far-end address marks the interface point-to-point, so
> the kernel adds a route to that one address rather than a `10.8.0.0/24` route.
> Don't be surprised when `ip route` shows no `/24`.

---

### Group 5: setup and teardown

#### `setup_client(state, server_ip)` — takes over the machine's routing so everything travels through the tunnel   `[client]`

**The routing table, before → during → after:**

```
 BEFORE                              AFTER setup                    AFTER teardown
 ───────────────────────             ───────────────────────        ──────────────
 default via 172.20.10.1             192.168.57.1 dev vboxnet0  ①   back to BEFORE
   dev wlp8s0                        default via 10.8.0.1
 192.168.57.0/24 dev vboxnet0          dev tun0                 ②
 172.20.10.0/28 dev wlp8s0           192.168.57.0/24 dev vboxnet0
                                     172.20.10.0/28 dev wlp8s0

                                     ① the pin — keeps the server reachable
                                     ② everything else goes down the tunnel
```

**Technical.** In order:

| # | Step | Flag set |
|---|---|---|
| 1 | Check and store the server address | |
| 2 | Create the tunnel and switch it on | `applied_tun` |
| 3 | Look up **both** routes, before anything changes | |
| 4 | Pin the server to the path it uses right now | `applied_host_route` |
| 5 | Remove the old default route | `applied_default_route` |
| 6 | Point the default at the far end of the tunnel | |

Note the flag on row 5, not row 6 — the old route is *already gone* at that
point, so teardown must restore it even if step 6 fails.

**What happens if you skip step 4** — the counterexample:

```
   packet for the server ──► "default says use tun0" ──► into the tunnel
                                       │
                          but the tunnel's own packets ARE
                          what we were trying to send...
                                       │
                                  ┌────▼────┐
                                  │ deadlock │  nothing ever leaves
                                  └─────────┘
```

**Like you're five.** You reroute the post through a new courier — but the courier
must stay reachable the *old* way, or they'd deliver their own mail to themselves.

#### `teardown_client(state)` — puts the routing back and removes the tunnel   `[client]`

**Technical.** Walks the flags backwards, skipping anything not applied:

```
   applied_default_route ?  ──► delete tunnel default, restore the old one
   applied_host_route    ?  ──► delete the pin
   applied_tun           ?  ──► close the handle, interface vanishes
```

A failure does not stop the remaining steps.

**Like you're five.** Undo your changes backwards, and only the ones you
actually made. If one undo goes wrong, keep going anyway — a half-tidied room
beats one where the door is still blocked.

#### `setup_server(state)` — gets the machine ready to carry traffic for a client   `[server]`

**Technical.**

```
   1. tunnel up            10.8.0.1, far end 10.8.0.2
   2. route_lookup(0)      NOT to change routing — only to learn which
                           interface reaches the internet, for the NAT rule
   3. save + enable forwarding
   4. add the three NAT rules
```

`applied_nat` is raised *before* the rules are added, because a partial failure
can leave some in place and teardown must try to remove all three.

**Like you're five.** The server doesn't change how its own post works. It turns
on the "pass things along" switch and puts its own name on outgoing envelopes.

#### `teardown_server(state)` — removes the rules, restores forwarding, removes the tunnel   `[server]`

**Like you're five.** Take your name back off the envelopes, put the switch how
it was, and let the pipe go.

---

### Group 6: stopping cleanly, and the packet loop

#### `on_signal(sig)` and `vpn_install_handlers()` — makes ctrl-c stop the program cleanly instead of killing it outright   `[both]`

**Technical.** The handler does exactly one thing: set a flag.

```
   ctrl-c ──► on_signal()      sets g_running = 0     ← does NOTHING else
                  │
                  ▼
   select() returns EINTR ──► loop sees the flag ──► returns
                                                       │
                                                       ▼
                                        main() runs teardown  ← safe here
```

The flag is `volatile sig_atomic_t` — the only type guaranteed to be written in
one uninterruptible go, since a signal can land between any two machine
instructions. Interrupted waits are deliberately left to fail rather than
resume: the loop spends nearly all its time waiting, and a wait that resumed by
itself would mean ctrl-c did nothing until the next packet happened to arrive.

**Like you're five.** Ctrl-c only flips a "time to stop" switch. The main program
checks it and tidies up when it's safe. Cleaning up in a panic breaks things.

#### `forward_loop(state, sock, peer, learn_peer, crypto)` — carries packets both ways until the program is asked to stop   `[both]`

```
              ┌──────────────────────────────┐
              │  select() — wait on BOTH     │◄────────────┐
              └───────┬──────────────┬───────┘             │
                      │              │                     │
          socket ready│              │tun ready            │
                      ▼              ▼                     │
            recvfrom(sock)      read(tun_fd)               │
                      │              │                     │
                      ▼              ▼                     │
             write(tun_fd)      sendto(sock)               │
                      │              │                     │
                      └──────┬───────┘                     │
                             └───────────────────────────► │
                                        loop while g_running
```

**Technical.** Two buffers, and encryption on the two seams. A datagram too short
to hold a nonce is dropped — anyone can send to an open port.

**The order matters.** `have_peer` is set only **after** the Poly1305 tag
verifies. It used to be set on arrival, which meant a single junk datagram from
anyone would redirect the tunnel at them — they could not read the traffic, but
they could black-hole it. Checking first is only possible because the crypto is
authenticated; with the earlier unauthenticated cipher there was no way to tell
a real peer from a stranger.

Nothing has to be cut up or reassembled — one read from the
tunnel is exactly one packet, and one message on the socket is exactly one
packet, so they map one-for-one.

`learn_peer` is the **only** difference between the two sides:

| | client | server |
|---|---|---|
| `learn_peer` | `0` | `1` |
| Knows the far address? | yes, up front | no — takes it from each message |
| Before the first message | n/a | packets from the tunnel are dropped |

Taking the address from *every* message means a client that moves is still
answered at its new address. A message that fails to send is reported and
skipped rather than treated as fatal — losing the occasional packet is normal.

**Like you're five.** Two letterboxes, one person watching both, carrying whatever
drops into one across to the other.

---
## `vpn_crypto.c` — encryption

Five functions, wrapping OpenSSL's **ChaCha20-Poly1305**.

This file used to contain a hand-written ChaCha20 — about 200 lines that
matched the RFC test vector exactly. It was replaced on the teacher's
instruction, and that was the right call: hand-rolled crypto is something you
write once to prove you understand it, then hand to a library that is audited,
constant-time on every platform, and maintained by people who do nothing else.

The swap also bought authentication almost for free:

```
   ChaCha20          hides the packet                   confidentiality
   + Poly1305        proves nobody altered it           integrity
   ─────────────────────────────────────────────────
   = an AEAD, and decryption now FAILS on a tampered packet
     instead of quietly handing the kernel a corrupted one
```

```
   the wire format

   [ 12-byte nonce ][ ciphertext ][ 16-byte tag ]

   1400 inner + 12 + 16 + 28 outer ip/udp = 1456  <  1500
   the MTU stays at 1400 — the 60 bytes of slack were left for exactly this
```

#### `load32(p)` and `store32(p, v)` — 4 bytes ↔ one 32-bit word   `[both]`

```
   bytes                     one word
   +----+----+----+----+
   | 01 | 02 | 03 | 04 | <-> 0x04030201    least significant byte first
   +----+----+----+----+
```

**Technical.** Only used to assemble the nonce now — OpenSSL takes the key as
raw bytes, so the eight-word unpacking the old version needed is gone.

**Like you're five.** Packs and unpacks four bytes at a time, the same way on
every machine.

#### `read_exactly(path, buf, n)` — read n bytes or fail   `[both]`

**Technical.** `fopen`, `fread`, `fclose`, succeed only on exactly `n` bytes.
Used twice — the 32-byte key file and the 4 random salt bytes.

**Like you're five.** "Give me exactly this many bytes, or admit you couldn't."

#### `vpn_crypto_init(crypto, key_path)` — load the key, open the contexts   `[both]`

```
        head -c 32 /dev/urandom > vpn.key
                    │
        ┌───────────┴───────────┐          the SAME 32 bytes on both
        ▼                       ▼          machines — the shared secret
   ┌─────────┐             ┌─────────┐
   │ client  │             │ server  │
   │ key     │             │ key     │   identical
   │ salt ●  │             │ salt ○  │   different — drawn from /dev/urandom
   │ ctr  0  │             │ ctr  0  │     once per process
   └─────────┘             └─────────┘
        two independent nonce spaces, so neither can collide with the other
```

**Technical.** Reads the key, draws the salt, then creates one encrypt and one
decrypt `EVP_CIPHER_CTX` and binds the algorithm and key to each **once**. Per
packet only the nonce is rebound, which is OpenSSL's documented cheap path —
creating a context per packet would mean a malloc on every packet.

Called **before** setup in both `main`s, so a missing key fails while the
machine is still untouched — verified: with no key, the client exits without
ever creating `tun0`.

**Like you're five.** Fetch the shared secret both machines were given, roll a
die this program keeps for life so its numbering never clashes with the other
side's, and get two work benches from OpenSSL to do the actual work on.

#### `vpn_crypto_cleanup(crypto)` — hand the contexts back   `[both]`

**Technical.** Frees both contexts and nulls them. Safe on a half-built struct,
which is why `vpn_crypto_init` can call it on its own failure path. Both `main`s
call it on every exit path.

**Like you're five.** Give the work benches back when you're done with them.

#### `vpn_encrypt` and `vpn_decrypt` — the per-packet wrapper   `[both]`

**Technical.** `vpn_encrypt` builds the nonce into the front of the outgoing
buffer, bumps the counter, encrypts, and asks OpenSSL for the tag to put on the
end. `vpn_decrypt` takes the nonce off the front, hands OpenSSL the tag that
arrived, and calls `EVP_DecryptFinal_ex` — **that call is the check**. A runt
datagram is rejected before any of this, since anyone can send to an open port.

```
   what the tag changed

   before (hand-written)                  after (Poly1305)
   ─────────────────────                  ────────────────
   flip a bit in transit → the same       flip any bit → decryption FAILS,
   bit flips in the decrypted packet,     packet dropped, nothing reaches
   silently                               the kernel

   wrong key → silent garbage handed      wrong key → rejected, with a
   to the kernel ("write tun: Invalid     warning printed once naming
   argument", if you were lucky)          vpn.key as the likely cause
```

That second row is a real usability win, not just a security one — a key
mismatch used to be silent and cost an hour to find.

**Like you're five.** Every envelope gets a number nobody has used before,
written where anyone can read it, plus a wax seal. The number stops two
envelopes being scrambled the same way. The seal means if anyone opened or
changed it on the way, you can tell, and you throw it away unread.

---


## `client.c`

#### `main(argc, argv)` — the client's whole life, in order   `[client]`

```
   read server address from argv (or use the built-in default)
        │
   install signal handlers
        │
   open the UDP socket
        │
   setup_client()  ────────── failed? ──► teardown_client(), exit 1
        │                                  (undoes only what succeeded)
   forward_loop(..., learn_peer = 0)
        │  ← ctrl-c or error lands here
   teardown_client(), close socket, exit 0
```

The cleanup runs here, on the ordinary path, whether the loop ended on ctrl-c or
on an error — never inside the interrupt itself.

**Like you're five.** "I'm the kid." Everything else lives in the shared file.

---

## `server.c`

#### `udp_listen(port)` — opens the socket clients connect to   `[server]`

**Technical.** Claims the port on every interface of the machine, and marks it
reusable so restarting straight away works instead of failing on a port the
previous run still holds.

**Like you're five.** Puts up the sign saying which door to knock on, and makes
sure the door isn't still stuck from last time.

#### `main(void)` — the server's whole life, in order   `[server]`
Same shape as the client:

```
   install handlers → udp_listen() → setup_server()
        → forward_loop(..., learn_peer = 1) → teardown_server()
```

**Like you're five.** "I'm the grown-up."

---

## The bug that was found

The most instructive thing here, so it gets its own section.

**The old code assumed the server is reached through the default gateway.**
Here is that assumption against reality on this machine:

```
   WHAT THE OLD CODE DID                    WHAT IS ACTUALLY TRUE
   ─────────────────────────                ─────────────────────
   "server? use the default gateway"        192.168.57.1 is next door,
                                            directly on vboxnet0

   ip route add 192.168.57.1                ip route get 192.168.57.1
     via 172.20.10.1 dev wlp8s0               → dev vboxnet0

        client                                    client
          │                                         │
          ▼                                         ▼
     [wifi router] ──► ✗ nowhere                [vboxnet0] ──► ✓ the VM
```

**Why it's nasty:** that command *succeeds*. It installs a route for that one
address which beats the `192.168.57.0/24` route, so every tunnel packet goes to
the wifi router and dies. It looks like "no response from server", not like a
routing mistake.

**Why it happened:** the original pseudocode was written for the normal case — a
server out on the internet, genuinely reached *through* the default gateway.
When the server is directly connected, the pin is both unnecessary and harmful.

**The fix:** `read_default_route` became `route_lookup`, which answers "how do I
reach *this* address" for any destination. `setup_client` now pins the server's
real path, leaving out `via` when it's directly reachable. This fixes the VM case
*and* keeps a cloud server working — which the old version only half-did.

**Like you're five.** We assumed every journey starts down the road. But the VM is
next door — you just walk over. So we look up the real way there first.

---

## What is tested

**It works end to end.** Verified on the real setup: host client, kali VM
server, VM bridged onto the LAN.

| | Status | How |
|---|---|---|
| Compiles clean | ✅ | zero warnings, `-ansi -pedantic -Wall -Wextra` |
| `route_lookup` correctness | ✅ | 5 destinations vs `ip route get`, all match |
| Rollback after failed setup | ✅ | ran as non-root: fails at tun, restores, no `tun0` |
| Comment rewrite changed nothing | ✅ | object files byte-identical before/after |
| Interface comes up | ✅ | `ping 10.8.0.1` — ttl 64, 0.8 ms |
| Forwarding and NAT | ✅ | `ping 1.1.1.1` — seq 1,2,3, ttl 52, real latency |
| Traffic uses the tunnel | ✅ | `traceroute` hop 1 = `10.8.0.1`, hop 2 = the LAN router |
| Full stack | ✅ | `curl ifconfig.me` → matches hop 6 of the traceroute |
| No packet duplication | ✅ | `tcpdump -ni eth1 icmp` — clean 1:1, seq 37–42 |
| Client teardown | ✅ | internet returns after every exit; a broken restore would be obvious |
| Server teardown | ✅ | `iptables -S \| grep -c 10.8.0.0/24` → `0` with nothing running: no leftover rules, forwarding restored |
| Crypto is OpenSSL, not hand-rolled | ✅ | `EVP_chacha20_poly1305()`, links against `libcrypto` |
| Packet round trip | ✅ | 64 in → 92 on the wire → 64 recovered, same key |
| Plaintext is gone | ✅ | no readable fragment found in the encrypted datagram |
| Wrong key fails | ✅ | **rejected outright** now, not silent garbage |
| Tampered ciphertext | ✅ | one flipped bit → rejected |
| Tampered tag | ✅ | rejected |
| Tampered nonce | ✅ | rejected |
| Untampered still works | ✅ | after all the above, a clean packet still decrypts |
| No leaks | ✅ | valgrind: 0 errors, contexts freed |
| Works over a real internet path | ✅ | AWS `eu-central-1`, `t3.micro`: tunnel, forwarding, NAT all fine |
| Traffic really exits elsewhere | ✅ | `curl ifconfig.me` → `203.0.113.10`, the instance — the lab could not show this |
| `route_lookup` is portable | ✅ | found `ens5` on Nitro unaided, after `eth1` on the VM; no code change |
| The pin takes the gateway branch | ✅ | `203.0.113.10 via 172.20.10.1 dev wlp8s0` — the branch the lab never exercised |
| Nonce never repeats | ✅ | counter advances per packet; two processes draw different salts |
| Runt datagram | ✅ | rejected, no read past the end of the buffer |
| Missing key is safe | ✅ | client exits without creating `tun0` — key is loaded before setup |
| Encrypted traffic end to end | ⚠️ | proven for the hand-rolled version (40 hits inside `tun0`, 0 on the wire). Needs re-running against the OpenSSL build |

### The one real bug the live test found

Not in this code — in the environment. With the VM on VirtualBox's **NAT**
adapter, forwarding and masquerade worked perfectly (packets left `eth1`
correctly rewritten), but slirp, VirtualBox's userspace network stack, faked the
replies:

```
   request sent:   10.0.3.15 > 1.1.1.1   echo request, seq 37
   "reply" back:   1.1.1.1 > 10.0.3.15   echo reply,   seq 0     ← always 0
```

A real host echoes the sequence number back. Every reply arriving as `seq 0`,
with `ttl 62` and corrupted payloads, was slirp answering pings itself instead
of forwarding them — while its gateway `10.0.3.2` returned `net unreachable` for
every TCP destination. Switching the adapter to **bridged** fixed it outright,
with no code change: `route_lookup` picked up the new egress interface at
runtime, which is exactly why it isn't hardcoded.

**Worth knowing:** the tunnel is IPv4 only. On a network with working IPv6,
that traffic bypasses the tunnel entirely.

---

## Running it

First, on the host, make a key and copy the SAME file to the VM — both ends must
have identical bytes:

```
head -c 32 /dev/urandom > vpn.key
scp vpn.key kali@192.168.57.1:~/vpn/
```

Then, on the kali VM:

```
sudo ./vpn_server
```

On the host — **with `wg0-mullvad` down and the VM running**:

```
sudo ./vpn_client 192.168.57.1
```

Then `ping 10.8.0.1`, then `curl ifconfig.me` — it should report the VM's public
address, not yours. Ctrl-C on either side restores the machine.

### If it doesn't work

```
   does `ping 10.8.0.1` reply?
     │
     ├─ no ──► `ip route get 192.168.57.1` on the host
     │            │
     │            ├─ says wlp8s0 ──► the pin is wrong (see the bug section)
     │            └─ says vboxnet0 ──► `tcpdump -i vboxnet0 udp port 51820`
     │                                    │
     │                                    ├─ nothing leaving ──► client side
     │                                    └─ leaving, no reply ──► VM side:
     │                                         `iptables -L INPUT -n`
     │                                         is udp 51820 accepted?
     │
     └─ yes ──► tunnel works. does `curl ifconfig.me` show the VM's address?
                  │
                  ├─ no ──► forwarding or NAT: on the VM check
                  │           `cat /proc/sys/net/ipv4/ip_forward` (want 1)
                  │           `iptables -t nat -L POSTROUTING -n`
                  └─ yes ──► it all works
```

**Note:** we add `FORWARD` rules but nothing for `INPUT`, so a restrictive input
policy on the VM drops the client's packets before the server ever sees them.
Also: the "client is X:Y" print was removed when the two loops were merged — add
it back inside `forward_loop` if you need to see whether the server heard anything.

---

## Glossary

| Term | Plain meaning |
|---|---|
| **tun interface** | A fake network card. What the machine sends into it arrives in our program instead of on a wire. |
| **fd / handle** | A number the kernel gives you to refer to something you opened. Close it and the thing goes away. |
| **route** | A rule saying "to reach *these* addresses, send packets *this* way". |
| **default route** | The catch-all route, used when no more specific one matches. |
| **gateway** | The router a packet is handed to on its way somewhere else. |
| **on-link / directly reachable** | The destination is on the same network — no gateway needed, just shout down the wire. |
| **netmask** | Says how much of an address is "the network" and how much is "the machine". Narrower mask = more specific route. |
| **MTU** | The biggest packet an interface will carry. |
| **forwarding** | A machine being willing to pass packets between its interfaces, instead of only handling its own. |
| **NAT / masquerade** | Rewriting a packet's sender address to your own, so replies come back to you, then passing them on. |
| **ioctl** | "Do this odd thing to this open handle" — how interfaces are configured from C. |
| **EINTR** | "Your wait was cut short by a signal." Not an error, just a nudge to check whether you should stop. |
| **stream cipher** | Turns a key into an endless run of pseudo-random bytes; encrypting is XOR-ing your data against them. Adds no length. |
| **keystream** | Those pseudo-random bytes. Both ends generate the same ones from the same key and nonce. |
| **AEAD** | Encryption that also proves the message was not altered. ChaCha20-Poly1305 is one. |
| **tag** | The 16 bytes Poly1305 appends. Decryption fails if it does not match. |
| **nonce** | A number used once. Public, but must never repeat with the same key — reuse lets two ciphertexts cancel the key out. |
| **salt** | Here, the random half of the nonce, drawn once per process so two machines never number their packets the same way. |

---

## Open decisions

1. **Mullvad must be down.** `route_lookup` reads the main routing table, which
   is what decides routing with Mullvad off. Leave it up and its own policy
   table decides instead, and nothing here will match what the kernel does.
2. **Shelling out to `ip` and `iptables`** rather than doing it all with ioctls.
   Routes could use ioctls; the masquerade rule cannot, so both go through the
   tools for one consistent style. `execvp`, never `system`.
3. **The key is pre-shared, not negotiated.** The same `vpn.key` must be copied
   to both machines by hand, and never committed. A real VPN does a key exchange
   so each session gets a fresh key. THIS IS THE REMAINING CRYPTO GAP.
4. **Nothing on the server’s `INPUT` chain.** Deliberate — the exercise assumes a
   permissive default policy. Worth adding if kali turns out to be locked down.
