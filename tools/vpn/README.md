# vpn

A working VPN in C89: a tun device, a UDP tunnel, and authenticated encryption.
Written for the Infinity Labs networking track.

Run the client and every packet your machine sends leaves through the server
instead — encrypted on the way, and with the server's address on it by the time
it reaches the internet.

```
        YOUR MACHINE                                THE SERVER
   ┌──────────────────────┐                   ┌──────────────────────┐
   │  browser / ping      │                   │                      │
   │        │             │                   │                      │
   │   tun0 10.8.0.2      │                   │   tun0 10.8.0.1      │
   │        │             │   encrypted udp   │        │             │
   │   vpn_client ────────┼──────────────────►│   vpn_server         │
   └──────────────────────┘      port 51820   │        │             │
                                              │   nat + forwarding   │
                                              │        ▼             │
                                              │   the internet       │
                                              └──────────────────────┘
```

## The files

| File | Lines | What it is |
|---|---|---|
| `vpn_net.h` / `.c` | 965 | The tunnel, the system changes, the packet loop |
| `vpn_crypto.h` / `.c` | 292 | OpenSSL ChaCha20-Poly1305, per-packet |
| `client.c` | 107 | A `main` that takes over routing |
| `server.c` | 119 | A `main` that forwards and masquerades |
| `Makefile` | 21 | Builds both |

Two companion documents:

- **`psuedocode.md`** — the structure. Call trees, step order, wire format, one
  diagram per function.
- **`walkthrough.md`** — the reasoning. Every function explained technically and
  then in plain words, plus the bugs found and how.

## Building

Needs `libssl-dev` (`openssl-devel` on RHEL-family):

```
make
```

Produces `vpn_client` and `vpn_server`. Warning-free under
`-ansi -pedantic -Wall -Wextra`.

## Running

Both machines need the **same** key file:

```
head -c 32 /dev/urandom > vpn.key
scp vpn.key user@<server>:~/vpn/
```

Then, as root on each side:

```
# on the server
sudo ./vpn_server

# on the client
sudo ./vpn_client <server-ip>
```

Ctrl-C on either side puts the machine back exactly as it was.

## How it works, briefly

`tun0` is a network interface with no hardware behind it. Packets the kernel
sends into it arrive in our program, which encrypts them and forwards them over
an ordinary UDP socket. The server does the reverse, then lets the kernel
forward and masquerade them out to the internet.

The client's setup is the delicate part. It has to move the default route onto
the tunnel *without* trapping the tunnel's own packets inside it, so it first
pins one route to the server along whatever path that server currently uses.
Every change is recorded in a flag, and teardown undoes only the flags that were
set — which is what makes it safe to fail halfway.

## What has been verified

On a VirtualBox VM over a host-only link, and again on an AWS `t3.micro` in
`eu-central-1` over the real internet:

| | |
|---|---|
| Tunnel, forwarding, NAT | ✅ |
| Traffic really uses the tunnel | ✅ `traceroute` hop 1 = `10.8.0.1` |
| Traffic really exits at the server | ✅ `curl ifconfig.me` returns the instance |
| Both teardowns restore the machine | ✅ routing back, no leftover firewall rules |
| Rollback after a failed setup | ✅ leaves no `tun0`, no route changes |
| Crypto is OpenSSL, not hand-rolled | ✅ `EVP_chacha20_poly1305()` |
| Tampering is detected | ✅ ciphertext, tag and nonce flips all rejected |
| Wrong key is rejected | ✅ with a warning, not silent corruption |
| No memory errors | ✅ valgrind clean |
| Portable across topologies | ✅ found `eth1`, `ens5`, `vboxnet0` unaided |

One item outstanding: the plaintext-on-the-wire check (`ping -p cafebabe…`,
captured either side of the encryption) passed against an earlier build and has
not been re-run since the switch to OpenSSL.

## What it deliberately does not do

- **No key exchange.** The key is pre-shared by hand. A real VPN negotiates a
  fresh one per session.
- **No killswitch.** Connections opened *before* the VPN starts keep their
  original source address and stay outside the tunnel until they close.
- **No keepalive.** Behind NAT, an idle tunnel can lose its mapping and the
  server cannot reach back until the client speaks again.
- **IPv4 only.** IPv6 traffic bypasses the tunnel entirely.
- **One client per server.** The server tracks a single peer.
- **No `INPUT` firewall rules** on the server; a restrictive default policy will
  drop the client's packets before they arrive.

## Two bugs worth knowing about

**The route to the server was assumed, not looked up.** The original design
pinned it via the default gateway. That is right for a server out on the
internet and wrong for one on a directly connected network — and the wrong
version *succeeds*, installing a route that quietly sends every tunnel packet to
the wrong interface. Fixed by asking the routing table how that specific address
is actually reached.

**The peer's address was trusted before the packet was authenticated.** Anyone
who sent a single junk datagram to the open port could redirect the tunnel at
themselves. Fixed by moving the trust to after the Poly1305 tag verifies — which
is only possible *because* the crypto is now authenticated.
