# vpn pseudocode

The skeleton of the code as diagrams — one section per function, named as it is
in the source. Each step pairs the plain-English intent on the left with the
actual call, flag or constant on the right, so it reads as an explanation and
still maps line for line onto the C.

For the longer *why*, see `walkthrough.md`. For what it is and how to run it,
see `README.md`.

Each heading is tagged with who actually uses it:

| tag | meaning |
|---|---|
| `[both]` | the client and the server both call it |
| `[client]` | only the client path reaches it |
| `[server]` | only the server path reaches it |

Note this is about *use*, not location — everything except the two `main`s,
`udp_listen`, and the `vpn_crypto.c` functions lives in `vpn_net.c`. `route_cmd`
sits in the shared file but only the client ever calls it; `nat_rules` and `ip_forward` likewise are server-only.

---

## the map

```
 the program starts
     |
     +-- clear the state ............................ vpn_net_init
     +-- catch ctrl-c ............................... vpn_install_handlers
     +-- load the shared key ......................... vpn_crypto_init
     |
     +-- open the udp socket
     |      client: socket(AF_INET, SOCK_DGRAM)
     |      server: same, plus bind to :51820 ....... udp_listen
     |
     +-- change the machine
     |      client: take the routing over ........... setup_client
     |      server: forwarding + nat ................ setup_server
     |
     +-- carry packets until ctrl-c ................. forward_loop
     |
     +-- restore the machine
            client: ................................. teardown_client
            server: ................................. teardown_server


 inside the two setup calls:

   setup_client                            setup_server
       |                                       |
       +-- tun_alloc                           +-- tun_alloc
       +-- iface_config                        +-- iface_config
       +-- route_lookup   x2                   +-- route_lookup   x1
       +-- route_cmd      x3                   +-- ip_forward     x2
                                               +-- nat_rules

 static helpers underneath:
       set_ifr_name, set_iface_addr    the interface ioctls
       run_cmd                         under route_cmd and nat_rules
```

---

## struct vpn_net — what we changed, and what it was before   `[both]`

```
 struct vpn_net
     |
     +-- what we opened
     |     +-- tun_fd ......... the descriptor; close() deletes the interface
     |     +-- tun_name ....... IFNAMSIZ buffer, the name the kernel gave us
     |     +-- server_ip ...... the udp endpoint the client pinned a route to,
     |                          kept so teardown deletes that exact route
     |
     +-- the machine as we found it
     |     +-- old_gateway .... the default route's gateway
     |     +-- egress_dev ..... the interface the default route left through
     |     +-- old_ip_forward   the sysctl's value before we touched it
     |
     +-- which changes are in effect     teardown undoes ONLY these
           +-- applied_tun ............. the interface exists
           +-- applied_host_route ...... the pin to the server exists
           +-- applied_default_route ... the ORIGINAL default route is gone
           +-- applied_ip_forward ...... the sysctl was changed
           +-- applied_nat ............. the iptables rules were added
```

---

## set_ifr_name — fill in a blank interface request   `[both]`

```
 set_ifr_name(ifr, name)
     |
     +-- wipe the request ...................... memset(ifr, 0, sizeof(*ifr))
     +-- copy the interface name in ............ strncpy(ifr->ifr_name, name,
     |                                                   IFNAMSIZ - 1)
     +-- terminate it by hand .................. ifr->ifr_name[IFNAMSIZ-1] = 0
            strncpy does not terminate when the source fills the buffer

 exists because every interface ioctl below starts with these three lines
```

---

## set_iface_addr — write one address onto an interface   `[both]`

```
 set_iface_addr(sock, name, request, ip)
     |
     +-- set_ifr_name(&ifr, name)
     +-- point at the address field ............ addr = (struct sockaddr_in *)
     |                                                    &ifr.ifr_addr
     +-- text to binary, reject nonsense ....... inet_pton(AF_INET, ip, ...)
     +-- hand it to the kernel ................. ioctl(sock, request, &ifr)


 the trick: three settings, ONE union field. only the request changes.

     struct ifreq
     +-------------+--------------------------+
     | ifr_name    | ifr_addr  <--------------+-- SIOCSIFADDR     my address
     |  "tun0"     |           <--------------+-- SIOCSIFDSTADDR  the far end
     |             |           <--------------+-- SIOCSIFNETMASK  the netmask
     +-------------+--------------------------+
```

---

## run_cmd — run another program safely   `[both]`

```
 run_cmd(argv)
     |
     +-- split the process ..................... pid = fork()
     |
     +-- in the child: become that program ..... execvp(argv[0], argv)
     |      +-- only returns if exec failed .... perror(); _exit(127)
     |
     +-- in the parent: wait for it ............ waitpid(pid, &status, 0)
     |
     +-- success only on a clean exit .......... WIFEXITED(status) &&
                                                 WEXITSTATUS(status) == 0


 why execvp and not system():

     system("ip route add ...")            execvp with an argv[] list
     +-----------------------------+       +---------------------------+
     | one string, given to a SHELL |       | ["ip","route","add",...]  |
     | the shell honours ; | && $() |       | no shell, no re-splitting |
     | as commands                  |       | nothing to smuggle in     |
     +-----------------------------+       +---------------------------+
          server_ip comes from argv                   safe
```

---

## route_cmd — add or remove one route   `[client]`

```
 route_cmd(op, dest, gw, dev)                     op is "add" or "del"
     |
     +-- argv = ["ip", "route", op, dest]
     |
     +-- append "via <gw>"  ......... unless gw is NULL or NO_GATEWAY
     |      skipped when the destination is on-link: there is no router
     |
     +-- append "dev <dev>" ......... unless dev is NULL
     |      skipped on delete: naming the destination is enough, and
     |      over-describing can fail to match (the host's default route
     |      carries metric 600)
     |
     +-- run_cmd(argv)


 the four calls this project makes:

   add, via a router     ip route add 8.8.8.8 via 172.20.10.1 dev wlp8s0
   add, on-link          ip route add 192.168.57.1 dev vboxnet0
   add the tunnel        ip route add default via 10.8.0.1 dev tun0
   any delete            ip route del default
```

---

## nat_rules — the three firewall rules   `[server]`

```
 nat_rules(op, tun, egress)                       op is "-A" or "-D"
     |
     +-- 1. rewrite the sender ................. -t nat POSTROUTING
     |         -s 10.8.0.0/24 -o <egress> -j MASQUERADE
     |         the tunnel's private address becomes the server's own,
     |         so replies from the internet come back to the server
     |
     +-- 2. let the tunnel out ................. FORWARD
     |         -i <tun> -o <egress> -j ACCEPT
     |
     +-- 3. let replies back in ................ FORWARD
     |         -i <egress> -o <tun>
     |         -m state --state RELATED,ESTABLISHED -j ACCEPT
     |         only for conversations the client started - nothing
     |         outside can open a new one into the tunnel
     |
     +-- each goes through run_cmd; the three are one unit, so a single
         applied_nat flag covers all of them
```

---

## ip_forward — read or flip the forwarding sysctl   `[server]`

```
 ip_forward(value, write_it)
     |
     +-- open /proc/sys/net/ipv4/ip_forward ..... fopen(..., write_it?"w":"r")
     +-- write_it ?  fprintf(fp, "%d", *value)
     |            :  fscanf(fp, "%d", value)
     +-- fclose, and treat a failed close as a failed write


 what the sysctl does:

     0                                   1
     +-----------+                       +-----------+
     | tun0 --X  |  packets stop at the  | tun0 -----+---> eth1
     | eth1      |  interface they       |           |
     +-----------+  arrived on           +-----------+  the machine routes
                                                        between interfaces
```

---

## route_lookup — how does this machine reach an address?   `[both]`

```
 route_lookup(dest, out_gw, out_dev)      dest = 0 asks for the default route
     |
     +-- open /proc/net/route
     |
     +-- for each line: sscanf iface, destination, gateway, flags, mask
     |      |
     |      +-- fewer than 5 fields?            skip   (the header lands here)
     |      +-- !(flags & ROUTE_UP)?            skip   route is down
     |      +-- (dest & mask) != destination?   skip   does not cover dest
     |      +-- ntohl(mask) >= ntohl(best)?     KEEP   longest prefix wins,
     |                                                 the kernel's own rule
     |
     +-- nothing matched -> VPN_ERROR
     |
     +-- out_gw  = inet_ntop(best gateway) ..... "0.0.0.0" means on-link
     +-- out_dev = best iface


 worked example - reaching 192.168.57.1, as the table stores it: 0139A8C0

   Iface      Destination  Gateway   Flags  Mask
   -------------------------------------------------
   wlp8s0     00000000     010A14AC  0003   00000000     the default route
   wlp8s0     000A14AC     00000000  0001   F0FFFFFF
   vboxnet0   0039A8C0     00000000  0001   00FFFFFF

   0139A8C0 & 00000000 = 00000000 == 00000000   match (the default)
   0139A8C0 & F0FFFFFF = 0039A8C0 != 000A14AC   no
   0139A8C0 & 00FFFFFF = 0039A8C0 == 0039A8C0   match (vboxnet0)

   two matches -> keep the longer prefix -> vboxnet0, gateway 0.0.0.0
```

---

## vpn_net_init — clear the state   `[both]`

```
 vpn_net_init(state)
     |
     +-- zero everything ....................... memset(state, 0, sizeof(*state))
     +-- mark the descriptor unused ............ state->tun_fd = -1


 why -1 and not the zero memset already wrote:

     fd 0 = stdin, fd 1 = stdout, fd 2 = stderr

     a struct cleared to all-zeros claims to own fd 0,
     so teardown would close the program's own input
```

---

## tun_alloc — create the tun interface   `[both]`

```
 tun_alloc(state, name)
     |
     +-- open the clone device ................. open("/dev/net/tun", O_RDWR)
     |
     +-- ask for a layer-3 interface ........... ifr.ifr_flags =
     |                                             IFF_TUN | IFF_NO_PI
     |      IFF_TUN     raw IP packets, not ethernet frames
     |      IFF_NO_PI   no 4-byte info header before each packet
     |
     +-- request a name ........................ ifr.ifr_name = "tun0"
     |      an empty name lets the kernel pick the first free tunN
     |
     +-- create it ............................. ioctl(fd, TUNSETIFF, &ifr)
     |
     +-- read the name BACK .................... state->tun_name = ifr.ifr_name
     |      the kernel may have assigned a different one if tun0 was taken
     |
     +-- keep the descriptor ................... state->tun_fd = fd
                                                 state->applied_tun = 1


 lifetime:   ioctl ──► the interface exists ──► close(fd) ──► it is gone
             it is not persistent, which is why teardown is just close()
```

---

## iface_config — address the interface and bring it up   `[both]`

```
 iface_config(name, local_ip, peer_ip, netmask, mtu)
     |
     +-- open a throwaway socket ............... socket(AF_INET, SOCK_DGRAM, 0)
     |      never sends anything; the ioctls just need some socket
     |
     +-- my address ............................ SIOCSIFADDR      10.8.0.2
     +-- the far end ........................... SIOCSIFDSTADDR   10.8.0.1
     +-- the netmask ........................... SIOCSIFNETMASK   255.255.255.0
     +-- the biggest packet .................... SIOCSIFMTU       1400
     |
     +-- read the current flags ................ SIOCGIFFLAGS
     +-- write them back plus ours ............. SIOCSIFFLAGS
     |                                             flags |= IFF_UP|IFF_RUNNING
     +-- close(sock)   on every path, including every error path


 why read-then-write, not a bare write:

     wrong:  write(IFF_UP)          wipes flags the kernel already set
     right:  read, then flags|UP    keeps them, adds ours

 why mtu 1400 and not 1500:

     +--------------+------------------------------------------+
     | outer ip+udp |  the whole inner packet, up to 1400       |
     |   28 bytes   |                                          |
     +--------------+------------------------------------------+
     .................. 1500 on the wire ........................

 note: setting the peer address marks the interface POINTOPOINT, so the
 kernel installs a host route to 10.8.0.1 rather than a 10.8.0.0/24 route
```

---

## setup_client — take the routing over   `[client]`

```
 setup_client(state, server_ip)
     |
  1  +-- validate and store the address ........ inet_pton, strcpy into
     |                                             state->server_ip
     |      teardown must delete the exact route we are about to add
     |
  2  +-- tun_alloc("tun0") ..................... [applied_tun]
     +-- iface_config(10.8.0.2, peer 10.8.0.1, /24, 1400)
     |
  3  +-- route_lookup(0)  -> old_gateway, egress_dev      to restore later
     +-- route_lookup(server) -> server_gw, server_dev    to pin
     |      BOTH before any change, while the answers are still true
     |
  4  +-- route_cmd("add", server_ip, server_gw, server_dev)
     |                                           [applied_host_route]
     |      the pin - see "four things you must not reorder"
     |
  5  +-- route_cmd("del", "default", NULL, NULL)
     |                                           [applied_default_route]
     |      the flag is set HERE, not after step 6
     |
  6  +-- route_cmd("add", "default", 10.8.0.1, tun_name)


 the routing table across those steps:

   BEFORE                        AFTER SETUP                 AFTER TEARDOWN
   ------------------------      ------------------------    --------------
   default via 172.20.10.1       192.168.57.1 dev vboxnet0   back to BEFORE
     dev wlp8s0                  default via 10.8.0.1
   192.168.57.0/24 vboxnet0        dev tun0
   172.20.10.0/28 wlp8s0         192.168.57.0/24 vboxnet0
                                 172.20.10.0/28 wlp8s0
```

---

## teardown_client — put the routing back   `[client]`

```
 teardown_client(state)                 reverse order, skip what was not applied
     |
     +-- applied_default_route ?
     |      +-- route_cmd("del", "default", NULL, NULL)
     |      +-- route_cmd("add", "default", old_gateway, egress_dev)
     |
     +-- applied_host_route ?
     |      +-- route_cmd("del", server_ip, NULL, NULL)
     |
     +-- applied_tun ?
            +-- close(tun_fd) ................. the interface goes with it
                tun_fd = -1

 a failure does NOT stop the remaining steps: a partly restored machine
 still beats one stranded on a tunnel that no longer works
```

---

## setup_server — forwarding and nat   `[server]`

```
 setup_server(state)
     |
     +-- tun_alloc("tun0") ..................... [applied_tun]
     +-- iface_config(10.8.0.1, peer 10.8.0.2, /24, 1400)
     |
     +-- route_lookup(0) -> egress_dev
     |      the server does NOT change its own routing. this is read only
     |      to learn which interface reaches the internet, for rule 1
     |
     +-- ip_forward(&old_ip_forward, read)      save it
     +-- ip_forward(&on, write)  ............... [applied_ip_forward]
     |
     +-- set applied_nat FIRST ................. [applied_nat]
     +-- nat_rules("-A", tun_name, egress_dev)
            three rules go in one at a time; failing on the second leaves
            the first behind, so the flag must already be set
```

---

## teardown_server — undo it   `[server]`

```
 teardown_server(state)
     |
     +-- applied_nat ?          nat_rules("-D", tun_name, egress_dev)
     +-- applied_ip_forward ?   ip_forward(&old_ip_forward, write)
     +-- applied_tun ?          close(tun_fd); tun_fd = -1
```

---

## on_signal and vpn_install_handlers — stop cleanly   `[both]`

```
 on_signal(sig)
     +-- g_running = 0                          and nothing else


 vpn_install_handlers()
     +-- sa.sa_handler = on_signal
     +-- sigaction(SIGINT,  &sa, NULL)
     +-- sigaction(SIGTERM, &sa, NULL)
     +-- sa.sa_flags = 0 ....................... deliberately NOT SA_RESTART


 the path from ctrl-c to a restored machine:

     ctrl-c
       |
       +-- on_signal .......................... g_running = 0
       |
       +-- select() returns ................... errno == EINTR
       |
       +-- forward_loop sees the flag, returns
       |
       +-- main() runs teardown ............... on the ordinary path


 g_running is volatile sig_atomic_t: a signal can land between any two
 machine instructions, and that is the only type guaranteed to be written
 in one uninterruptible go.

 no SA_RESTART because the loop is almost always blocked in select(). if
 the wait resumed by itself, ctrl-c would do nothing until the next packet.
```

---
## the wire format

```
 before encryption            after
 -----------------            -----
 [ inner IP packet ]          [ 12-byte nonce ][ ciphertext ][ 16-byte tag ]

 sizes:  1400 inner + 12 nonce + 16 tag + 28 outer ip/udp = 1456  <  1500
         the mtu stays at 1400 - the slack was left for exactly this

 the nonce travels in the clear. it is not a secret, it only has to be unique.
 the tag is poly1305's proof that nobody altered the packet on the way.
```

---

## read_exactly — read n bytes from a file, or fail   `[both]`

```
 read_exactly(path, buf, n)
     +-- fopen(path, "rb")
     +-- fread(buf, 1, n, fp)
     +-- fclose
     +-- succeed only if we got exactly n bytes

 used twice: for the 32-byte key file, and for the 4 random salt bytes
```

---

## load32 and store32 — 4 bytes <-> one 32-bit word   `[both]`

```
   bytes                     one word
   +----+----+----+----+
   | 01 | 02 | 03 | 04 | <-> 0x04030201    least significant byte first
   +----+----+----+----+
     p   p+1  p+2  p+3

 only used to build the nonce now - openssl takes the key as raw bytes
```

---

## vpn_crypto_init — load the key, draw a salt, open the contexts   `[both]`

```
 vpn_crypto_init(crypto, key_path)
     |
     +-- read 32 bytes from the key file ....... read_exactly(key_path, ...)
     |      on failure, print how to make one:
     |        head -c 32 /dev/urandom > vpn.key
     |      the SAME file must exist on both machines
     |
     +-- read 4 random bytes as the salt ....... read_exactly("/dev/urandom")
     +-- counter = 0
     |
     +-- crypto->enc = EVP_CIPHER_CTX_new()
     +-- crypto->dec = EVP_CIPHER_CTX_new()
     |
     +-- bind algorithm + key ONCE ............. EVP_EncryptInit_ex(enc,
     |      EVP_chacha20_poly1305(), NULL, key, NULL)      and DecryptInit
     |      from here only the nonce is rebound per packet - openssl's
     |      documented cheap path

 both mains call this BEFORE setup, so a missing key fails while the
 machine is still untouched
```

---

## vpn_crypto_cleanup — hand the contexts back   `[both]`

```
 vpn_crypto_cleanup(crypto)
     +-- enc ?  EVP_CIPHER_CTX_free(enc);  enc = NULL
     +-- dec ?  EVP_CIPHER_CTX_free(dec);  dec = NULL

 safe on a half-built struct, so init can call it on its own failure path
```

---

## vpn_encrypt and vpn_decrypt — the per-packet wrapper   `[both]`

```
 vpn_encrypt(crypto, in, len, out)
     |
     +-- build the nonce into the front of out
     |      +-- bytes 0..3   the salt      random, fixed for this process
     |      +-- bytes 4..7   zero
     |      +-- bytes 8..11  the counter   goes up every packet
     +-- counter++
     |
     +-- EVP_EncryptInit_ex(enc, NULL, NULL, NULL, out)    rebind the nonce
     +-- EVP_EncryptUpdate(enc, out+12, &body, in, len)    the ciphertext
     +-- EVP_EncryptFinal_ex(enc, out+12+body, &rest)
     +-- EVP_CIPHER_CTX_ctrl(enc, GET_TAG, 16, end)        poly1305's tag
     |
     +-- return 12 + body + rest + 16


 vpn_decrypt(crypto, in, len, out)
     |
     +-- payload = len - 28
     +-- payload < 0 ?  reject ........ too short to hold a nonce and a tag
     |
     +-- EVP_DecryptInit_ex(dec, NULL, NULL, NULL, in)     nonce off the front
     +-- EVP_DecryptUpdate(dec, out, &body, in+12, payload)
     +-- EVP_CIPHER_CTX_ctrl(dec, SET_TAG, 16, in+12+payload)
     |
     +-- EVP_DecryptFinal_ex(dec, out+body, &rest)
     |      THE CHECK. fails if any byte was altered in transit, or if the
     |      sender used a different key. out is discarded, not handed on.
     |
     +-- return body + rest


 what the tag buys us:

     without it (the old hand-written version)   with it
     -----------------------------------------   -------
     flip a bit in transit -> the same bit       flip any bit -> decrypt
     flips in the decrypted packet, silently     FAILS and the packet is
                                                 dropped
     wrong key -> silent garbage handed to       wrong key -> rejected, with
     the kernel                                  a warning printed once
```

---


## forward_loop — carry packets both ways   `[both]`

```
 forward_loop(state, sock, peer, learn_peer, crypto)

     two buffers now:
        plain[BUF_SIZE]                the real packet
        wire[BUF_SIZE + 28]            nonce + ciphertext + tag

     have_peer = !learn_peer         client knows the peer; server must learn it

          +----------------------------------------------------------+
          |                                                          |
          v                                                          |
     select(maxfd+1, &readfds, ...)                                  |
          |                                                          |
          +-- EINTR? ------------------------------------------------+
          |      continue; g_running decides whether to stop
          |
          +-- FD_ISSET(sock) ?                     the other machine -> us
          |      +-- recvfrom(sock, wire, ...,
          |      |            learn_peer ? &peer : NULL)
          |      +-- vpn_decrypt(crypto, wire, n, plain)
          |      |      +-- returned < 0 ?  drop it and carry on
          |      |             too short, altered in transit, or a different key -
          |      |             a warning is printed once, then they are dropped
          |      +-- have_peer = 1        ONLY after the tag verified.
          |             before the check, one junk datagram from anyone
          |             would redirect the tunnel at them
          |      +-- write(tun_fd, plain, crypt_len)
          |
          +-- FD_ISSET(tun_fd) ?                   us -> the other machine
                 +-- read(tun_fd, plain)
                 +-- have_peer ?
                 |      +-- vpn_encrypt(crypto, plain, n, wire)   <-- NEW
                 |      +-- sendto(sock, wire, crypt_len, peer)
                 |             a failed sendto is reported, not fatal
                 +-- else drop: nowhere to send yet
                                                                     |
          while (g_running) --------------------------------------- +

 no framing needed: one read from tun_fd is exactly one IP packet, one udp
 datagram is exactly one packet, and encryption keeps that one-to-one - a
 stream cipher does not change the length, it only adds the 12-byte nonce


                      client                  server
   learn_peer         0                       1
   peer address       known up front          taken from every datagram,
                                              so a client that moves is
                                              still answered
   before the first   n/a                     tun packets are dropped
   datagram
```

---

## client.c main — the client's whole life   `[client]`

```
 main(argc, argv)
     |
     +-- server_ip = argv[1], or SERVER_UDP_IP
     +-- vpn_net_init(&state)
     +-- build the sockaddr we send to ......... inet_pton, htons(51820)
     +-- vpn_install_handlers()
     +-- vpn_crypto_init(&crypto, VPN_KEY_FILE)
     |      a missing key fails HERE, before the machine is touched
     +-- sock = socket(AF_INET, SOCK_DGRAM, 0)
     |
     +-- setup_client() ---- failed? ---> teardown_client(); close; exit 1
     |                                    safe: undoes only what succeeded
     +-- forward_loop(&state, sock, &server, 0, &crypto)
     |
     +-- teardown_client() ..................... the ordinary path, reached
     +-- close(sock)                             whether the loop ended on
                                                 ctrl-c or on an error
```

---

## server.c main and udp_listen — the server's whole life   `[server]`

```
 udp_listen(port)
     +-- sock = socket(AF_INET, SOCK_DGRAM, 0)
     +-- setsockopt(SO_REUSEADDR) .............. retake the port after a restart
     +-- bind(INADDR_ANY, htons(51820)) ........ every interface on the machine


 main(void)
     |
     +-- vpn_net_init(&state)
     +-- memset(&client, 0, ...) ............... filled in by the loop
     +-- vpn_install_handlers()
     +-- vpn_crypto_init(&crypto, VPN_KEY_FILE)
     |      a missing key fails HERE, before the machine is touched
     +-- sock = udp_listen(SERVER_UDP_PORT)
     |
     +-- setup_server() ---- failed? ---> teardown_server(); close; exit 1
     |
     +-- forward_loop(&state, sock, &client, 1, &crypto)
     |
     +-- teardown_server()
     +-- vpn_crypto_cleanup(&crypto)
     +-- close(sock)
```

---

## five things you must not reorder

```
 1   pin the server BEFORE moving the default route
     |
     |   skip it and:  a packet addressed to the server
     |                    ──► the default route says "use tun0"
     |                    ──► into the tunnel
     |                    ──► but that IS the packet we were trying to send
     |                    ──► deadlock; nothing ever leaves the machine


 2   both route_lookup calls BEFORE any route change
     |
     |   afterwards /proc/net/route describes the state we just created,
     |   not the one we need to restore


 3   applied_default_route is set BETWEEN the delete and the add
     |
     |      route_cmd("del", "default", ...)   <-- the old route is gone
     |      state->applied_default_route = 1   <-- so teardown MUST restore it
     |      route_cmd("add", "default", ...)       even if this line fails


 4   applied_nat is set BEFORE nat_rules runs
     |
     |   three rules added one at a time. a failure on the second leaves
     |   the first in place, so teardown has to try to remove all three


 5   load the key BEFORE setup_client / setup_server
     |
     |   a missing or wrong-sized key file is the most likely startup
     |   failure. checking it first means it cannot leave a half
     |   configured machine behind - verified: with no key, the client
     |   exits without ever creating tun0
```

---

## what changed from the first draft

```
 old:  route add <server_ip> via <the DEFAULT GATEWAY> dev <the default dev>
                                  ^^^^^^^^^^^^^^^^^^^
                                  assumes the server is out on the internet

 now:  route_lookup(server_ip) -> pin whatever path it actually uses


 why it mattered here:

     assumed                          actual
     -------                          ------
     reached through the router       192.168.57.1 is on-link on vboxnet0

     ip route add 192.168.57.1        ip route get 192.168.57.1
       via 172.20.10.1 dev wlp8s0       -> 192.168.57.1 dev vboxnet0

          client                            client
            |                                 |
            v                                 v
       [wifi router] --> X nowhere       [vboxnet0] --> the VM

 the old command SUCCEEDS, which is what made it nasty: it installs a /32
 that beats the on-link /24, so every tunnel packet goes to the wifi router
 and dies. it looks like "no response from server", not a routing mistake.
```

`read_default_route` became `route_lookup(dest)`, which answers the question for
any address — the default route is simply `dest = 0`.
