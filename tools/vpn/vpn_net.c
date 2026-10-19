/* Author: Dvash */
/* Reviewer: */

/*
 * vpn_net.c
 *
 * the shared half of the vpn: creating the tun interface, changing and
 * restoring the machine's networking, and the loop that moves packets between
 * the tunnel and the socket.
 */

#include <fcntl.h>          /* open, O_RDWR */
#include <string.h>         /* memset, strncpy, strcmp */
#include <unistd.h>         /* read, write, close, _exit */
#include <stdio.h>          /* perror, fprintf */
#include <errno.h>          /* errno, EINTR */
#include <signal.h>         /* sigaction, sig_atomic_t */
#include <sys/ioctl.h>      /* ioctl, SIOCSIFADDR and friends */
#include <sys/socket.h>     /* socket, sendto, recvfrom */
#include <sys/select.h>     /* select, fd_set */
#include <sys/types.h>      /* pid_t, ssize_t */
#include <sys/wait.h>       /* waitpid, WIFEXITED, WEXITSTATUS */
#include <arpa/inet.h>      /* inet_pton, inet_ntop, ntohl */
#include <linux/if_tun.h>   /* IFF_TUN, IFF_NO_PI, TUNSETIFF */

#include "vpn_net.h"

#define TUN_CLONE_DEV   "/dev/net/tun"
#define PROC_ROUTE      "/proc/net/route"
#define PROC_IP_FORWARD "/proc/sys/net/ipv4/ip_forward"

#define ROUTE_UP    0x0001UL    /* the "this route is usable" flag in the route table */
#define NO_GATEWAY  "0.0.0.0"   /* what route_lookup reports when nothing is in between */
#define BUF_SIZE    2048        /* one packet at a time, comfortably above TUN_MTU */

/* raised when the program is asked to stop; the packet loop watches it */
static volatile sig_atomic_t g_running = 1;

/*
 * runs when ctrl-c or kill arrives. it only records that the program should
 * stop - doing real work here would interrupt whatever main was in the middle
 * of, so the cleanup is left to main once the loop returns.
 */
static void on_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

/*
 * prepares a blank interface request with the interface's name filled in.
 * every interface ioctl below starts this way, and the name has to be
 * terminated inside a fixed size buffer.
 */
static void set_ifr_name(struct ifreq *ifr, const char *name)
{
    memset(ifr, 0, sizeof(*ifr));
    strncpy(ifr->ifr_name, name, IFNAMSIZ - 1);
    ifr->ifr_name[IFNAMSIZ - 1] = '\0';
}

/*
 * writes one address onto an interface - which address depends on the request
 * passed in: the interface's own, the one at the far end, or the netmask. all
 * three are written to the same place in the request, so only the request
 * number changes. a malformed address is rejected before the kernel sees it.
 */
static int set_iface_addr(int sock, const char *name, unsigned long request,
                          const char *ip)
{
    struct ifreq ifr;
    struct sockaddr_in *addr = NULL;

    set_ifr_name(&ifr, name);

    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;

    if (1 != inet_pton(AF_INET, ip, &addr->sin_addr))
    {
        fprintf(stderr, "iface_config: %s is not a valid address\n", ip);
        return VPN_ERROR;
    }

    if (0 > ioctl(sock, request, &ifr))
    {
        perror("iface_config: ioctl set address");
        return VPN_ERROR;
    }

    return VPN_OK;
}

/*
 * runs another program, waits for it to finish, and reports whether it
 * succeeded. used for the ip and iptables commands further down.
 *
 * the arguments are passed as a list rather than as one string, so there is no
 * shell involved. that matters because the server address can come from the
 * command line, and a string handed to a shell could carry extra commands.
 */
static int run_cmd(char *const argv[])
{
    pid_t pid = -1;
    int status = 0;

    pid = fork();
    if (0 > pid)
    {
        perror("run_cmd: fork");
        return VPN_ERROR;
    }

    if (0 == pid)
    {
        execvp(argv[0], argv);
        perror("run_cmd: execvp");  /* only reached if the program never started */
        _exit(127);
    }

    if (0 > waitpid(pid, &status, 0))
    {
        perror("run_cmd: waitpid");
        return VPN_ERROR;
    }

    if (!WIFEXITED(status) || 0 != WEXITSTATUS(status))
    {
        fprintf(stderr, "run_cmd: %s %s %s failed\n", argv[0], argv[2],
                argv[3]);
        return VPN_ERROR;
    }

    return VPN_OK;
}

/*
 * adds or removes one route, by building and running an "ip route" command.
 *
 * the gateway is left out when the destination is directly reachable, since
 * there is no router to go through. both the gateway and the interface are left
 * out when removing a route, because naming the destination is enough to
 * identify it - and describing it too precisely can fail to match.
 */
static int route_cmd(const char *op, const char *dest, const char *gw,
                     const char *dev)
{
    char *argv[9];
    int i = 0;

    argv[i++] = "ip";
    argv[i++] = "route";
    argv[i++] = (char *)op;
    argv[i++] = (char *)dest;

    if (NULL != gw && 0 != strcmp(gw, NO_GATEWAY))
    {
        argv[i++] = "via";
        argv[i++] = (char *)gw;
    }

    if (NULL != dev)
    {
        argv[i++] = "dev";
        argv[i++] = (char *)dev;
    }

    argv[i] = NULL;

    return run_cmd(argv);
}

/*
 * answers "how does this machine currently reach that address": which
 * interface the packets leave through, and which gateway they are handed to.
 * the gateway comes back as NO_GATEWAY when the address is on the local
 * network and no gateway is involved. asking about address 0 returns the
 * default route, the one used for everything with no better match.
 *
 * it reads the kernel's route table and keeps the most specific route that
 * covers the address, which is the same choice the kernel itself makes.
 *
 * this is a real lookup rather than "assume the default gateway" because a
 * server sitting on a directly connected network is not reached through the
 * default gateway at all, and assuming otherwise sends the tunnel's traffic
 * out of the wrong interface.
 */
static int route_lookup(in_addr_t dest, char *gw, char *dev)
{
    FILE *fp = NULL;
    char line[256];
    char iface[IFNAMSIZ];
    unsigned long d = 0;
    unsigned long g = 0;
    unsigned long flags = 0;
    unsigned long mask = 0;
    unsigned long best = 0;
    struct in_addr addr;
    int found = 0;

    fp = fopen(PROC_ROUTE, "r");
    if (NULL == fp)
    {
        perror("route_lookup: fopen " PROC_ROUTE);
        return VPN_ERROR;
    }

    memset(&addr, 0, sizeof(addr));

    /* the table's heading line simply fails to parse, and is skipped along
       with anything else that does not look like a route */
    while (NULL != fgets(line, sizeof(line), fp))
    {
        if (5 != sscanf(line, "%15s %lx %lx %lx %*d %*d %*d %lx",
                        iface, &d, &g, &flags, &mask))
        {
            continue;
        }

        /* skip routes that are switched off, and routes that do not cover
           the address we are asking about */
        if (!(flags & ROUTE_UP) || (dest & (in_addr_t)mask) != (in_addr_t)d)
        {
            continue;
        }

        /* of the routes that do cover it, keep the narrowest one. the byte
           order is flipped first so that a narrower range really does compare
           as the larger number */
        if (!found || ntohl((in_addr_t)mask) >= ntohl((in_addr_t)best))
        {
            best = mask;
            addr.s_addr = (in_addr_t)g;
            strncpy(dev, iface, IFNAMSIZ - 1);
            dev[IFNAMSIZ - 1] = '\0';
            found = 1;
        }
    }

    fclose(fp);

    if (!found)
    {
        fprintf(stderr, "route_lookup: no route to destination\n");
        return VPN_ERROR;
    }

    /* the table stores the gateway as raw bytes; turn it back into text */
    if (NULL == inet_ntop(AF_INET, &addr, gw, INET_ADDRSTRLEN))
    {
        perror("route_lookup: inet_ntop");
        return VPN_ERROR;
    }

    return VPN_OK;
}

/*
 * adds ("-A") or removes ("-D") the three firewall rules that let the client
 * reach the internet through the server:
 *
 *   1. replaces the tunnel's private sender address with the server's own, so
 *      that replies from the internet find their way back to the server.
 *   2. allows packets to travel from the tunnel out to the internet.
 *   3. allows replies to travel back in - but only replies to conversations
 *      the client started, so nothing outside can reach into the tunnel.
 *
 * the three belong together, which is why a single applied_nat flag covers
 * all of them.
 */
static int nat_rules(const char *op, const char *tun, const char *egress)
{
    char *masq[12];
    char *fwd_out[10];
    char *fwd_in[14];

    masq[0] = "iptables";   masq[1] = "-t";     masq[2] = "nat";
    masq[3] = (char *)op;   masq[4] = "POSTROUTING";
    masq[5] = "-s";         masq[6] = TUN_SUBNET;
    masq[7] = "-o";         masq[8] = (char *)egress;
    masq[9] = "-j";         masq[10] = "MASQUERADE";
    masq[11] = NULL;

    fwd_out[0] = "iptables";        fwd_out[1] = (char *)op;
    fwd_out[2] = "FORWARD";
    fwd_out[3] = "-i";              fwd_out[4] = (char *)tun;
    fwd_out[5] = "-o";              fwd_out[6] = (char *)egress;
    fwd_out[7] = "-j";              fwd_out[8] = "ACCEPT";
    fwd_out[9] = NULL;

    fwd_in[0] = "iptables";         fwd_in[1] = (char *)op;
    fwd_in[2] = "FORWARD";
    fwd_in[3] = "-i";               fwd_in[4] = (char *)egress;
    fwd_in[5] = "-o";               fwd_in[6] = (char *)tun;
    fwd_in[7] = "-m";               fwd_in[8] = "state";
    fwd_in[9] = "--state";          fwd_in[10] = "RELATED,ESTABLISHED";
    fwd_in[11] = "-j";              fwd_in[12] = "ACCEPT";
    fwd_in[13] = NULL;

    if (VPN_OK != run_cmd(masq) ||
        VPN_OK != run_cmd(fwd_out) ||
        VPN_OK != run_cmd(fwd_in))
    {
        return VPN_ERROR;
    }

    return VPN_OK;
}

/*
 * reads or writes the kernel setting that decides whether this machine is
 * willing to pass packets between its interfaces. write_it chooses which:
 * reading stores the current setting in *value, writing applies *value.
 *
 * the server reads it before changing it so the original setting can be put
 * back on the way out.
 */
static int ip_forward(int *value, int write_it)
{
    FILE *fp = fopen(PROC_IP_FORWARD, write_it ? "w" : "r");
    int ok = 0;

    if (NULL == fp)
    {
        perror("ip_forward: fopen " PROC_IP_FORWARD);
        return VPN_ERROR;
    }

    ok = write_it ? (0 < fprintf(fp, "%d\n", *value))
                  : (1 == fscanf(fp, "%d", value));

    if (0 != fclose(fp) || !ok)
    {
        fprintf(stderr, "ip_forward: cannot %s " PROC_IP_FORWARD "\n",
                write_it ? "write" : "read");
        return VPN_ERROR;
    }

    return VPN_OK;
}

/*
 * clears the struct and marks the tun handle as unused.
 *
 * the handle is set to -1 rather than left at zero, because zero is a
 * perfectly valid handle - a cleared struct would otherwise look like it owns
 * the program's own input, and teardown would close it.
 */
void vpn_net_init(struct vpn_net *state)
{
    if (NULL == state)
    {
        return;
    }

    memset(state, 0, sizeof(*state));
    state->tun_fd = -1;
}

/*
 * creates a tun interface and stores its handle in the struct.
 *
 * a tun interface is a fake network card: packets the machine sends into it
 * arrive here to be read, and packets written here look to the machine as
 * though they arrived from the network. it is asked for as a plain ip
 * interface with no extra header in front of each packet.
 *
 * the name is read back afterwards, because if the requested name is already
 * taken the kernel picks a different one. the interface exists only while the
 * handle is open, which is why teardown just closes it.
 */
int tun_alloc(struct vpn_net *state, const char *name)
{
    struct ifreq ifr;
    int fd = -1;

    if (NULL == state)
    {
        return VPN_ERROR;
    }

    fd = open(TUN_CLONE_DEV, O_RDWR);
    if (0 > fd)
    {
        perror("tun_alloc: open " TUN_CLONE_DEV);
        return VPN_ERROR;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    /* an empty name means "any free one will do" */
    if (NULL != name && '\0' != name[0])
    {
        strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    }

    if (0 > ioctl(fd, TUNSETIFF, &ifr))
    {
        perror("tun_alloc: ioctl TUNSETIFF");
        close(fd);
        return VPN_ERROR;
    }

    strncpy(state->tun_name, ifr.ifr_name, IFNAMSIZ - 1);
    state->tun_name[IFNAMSIZ - 1] = '\0';

    state->tun_fd = fd;
    state->applied_tun = 1;

    return VPN_OK;
}

/*
 * sets up an interface and switches it on: its own address, the address of
 * the machine at the far end, the netmask, and the largest packet it will
 * carry. the size is kept under the usual 1500 so that a tunnelled packet
 * still fits inside a normal one once the outer headers are added.
 *
 * the switch-on step reads the interface's current settings first and adds to
 * them, rather than overwriting - the kernel has already set some of them, and
 * replacing the lot would undo its work.
 *
 * the socket opened here is never used to send anything. it exists only
 * because these requests have to be made through some socket.
 */
int iface_config(const char *name, const char *local_ip, const char *peer_ip,
                 const char *netmask, int mtu)
{
    struct ifreq ifr;
    int sock = -1;

    if (NULL == name || NULL == local_ip || NULL == peer_ip ||
        NULL == netmask)
    {
        return VPN_ERROR;
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (0 > sock)
    {
        perror("iface_config: socket");
        return VPN_ERROR;
    }

    /* own address, then the far end's, then the netmask */
    if (VPN_OK != set_iface_addr(sock, name, SIOCSIFADDR, local_ip) ||
        VPN_OK != set_iface_addr(sock, name, SIOCSIFDSTADDR, peer_ip) ||
        VPN_OK != set_iface_addr(sock, name, SIOCSIFNETMASK, netmask))
    {
        close(sock);
        return VPN_ERROR;
    }

    set_ifr_name(&ifr, name);
    ifr.ifr_mtu = mtu;
    if (0 > ioctl(sock, SIOCSIFMTU, &ifr))
    {
        perror("iface_config: ioctl SIOCSIFMTU");
        close(sock);
        return VPN_ERROR;
    }

    set_ifr_name(&ifr, name);
    if (0 > ioctl(sock, SIOCGIFFLAGS, &ifr))
    {
        perror("iface_config: ioctl SIOCGIFFLAGS");
        close(sock);
        return VPN_ERROR;
    }

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (0 > ioctl(sock, SIOCSIFFLAGS, &ifr))
    {
        perror("iface_config: ioctl SIOCSIFFLAGS");
        close(sock);
        return VPN_ERROR;
    }

    close(sock);

    return VPN_OK;
}

/*
 * gets the client machine ready to send everything through the tunnel, in
 * this order:
 *
 *   1. check the server address and keep it, so teardown can undo the right
 *      route later.
 *   2. create the tunnel interface and switch it on.
 *   3. look up how the machine routes today - both the default route, so it
 *      can be restored, and the route to the server. both lookups happen
 *      before anything is changed, while the answers are still true.
 *   4. pin the server to the path it uses right now. this has to come before
 *      the next step: once everything goes through the tunnel, the tunnel's
 *      own packets would be sent into the tunnel as well, and nothing would
 *      ever leave the machine.
 *   5. remove the old default route.
 *   6. point the default route at the far end of the tunnel.
 *
 * if any step fails it stops and returns an error. the caller then calls
 * teardown_client, which undoes whatever had already succeeded.
 */
int setup_client(struct vpn_net *state, const char *server_ip)
{
    struct in_addr server;
    char server_gw[INET_ADDRSTRLEN];
    char server_dev[IFNAMSIZ];

    if (NULL == state || NULL == server_ip)
    {
        return VPN_ERROR;
    }

    if (INET_ADDRSTRLEN <= strlen(server_ip) ||
        1 != inet_pton(AF_INET, server_ip, &server))
    {
        fprintf(stderr, "setup_client: %s is not a valid address\n",
                server_ip);
        return VPN_ERROR;
    }
    strcpy(state->server_ip, server_ip);

    if (VPN_OK != tun_alloc(state, TUN_DEV_NAME) ||
        VPN_OK != iface_config(state->tun_name, CLIENT_TUN_IP, SERVER_TUN_IP,
                               TUN_NETMASK, TUN_MTU))
    {
        return VPN_ERROR;
    }

    if (VPN_OK != route_lookup(0, state->old_gateway, state->egress_dev) ||
        VPN_OK != route_lookup(server.s_addr, server_gw, server_dev))
    {
        return VPN_ERROR;
    }

    if (VPN_OK != route_cmd("add", state->server_ip, server_gw, server_dev))
    {
        return VPN_ERROR;
    }
    state->applied_host_route = 1;

    if (VPN_OK != route_cmd("del", "default", NULL, NULL))
    {
        return VPN_ERROR;
    }

    /* marked here rather than after the next line: the old route is already
       gone, so it has to be restored even if what follows fails */
    state->applied_default_route = 1;

    return route_cmd("add", "default", SERVER_TUN_IP, state->tun_name);
}

/*
 * puts the client machine back the way it was: the default route returns to
 * the original gateway, the pinned route to the server is removed, and the
 * tunnel interface disappears when its handle is closed.
 *
 * each step is skipped unless it was actually applied, so this is safe to call
 * after a setup that only got part way. a failure does not stop the remaining
 * steps - a partly restored machine is still better than one left pointing at
 * a tunnel that no longer works.
 */
void teardown_client(struct vpn_net *state)
{
    if (NULL == state)
    {
        return;
    }

    if (state->applied_default_route)
    {
        route_cmd("del", "default", NULL, NULL);
        route_cmd("add", "default", state->old_gateway, state->egress_dev);
        state->applied_default_route = 0;
    }

    if (state->applied_host_route)
    {
        route_cmd("del", state->server_ip, NULL, NULL);
        state->applied_host_route = 0;
    }

    if (state->applied_tun)
    {
        close(state->tun_fd);
        state->tun_fd = -1;
        state->applied_tun = 0;
    }
}

/*
 * gets the server machine ready to carry traffic for a client:
 *
 *   1. create the tunnel interface and switch it on.
 *   2. look up the default route. the server keeps its own routing exactly as
 *      it is - this is read only to learn which interface reaches the
 *      internet, which the firewall rules need to know.
 *   3. remember the current forwarding setting, then turn forwarding on so
 *      the machine is willing to pass packets between the tunnel and the
 *      internet.
 *   4. add the firewall rules.
 *
 * the nat flag is raised before the rules are added, not after, because a
 * failure part way can still leave some of them in place and teardown has to
 * try to remove all three.
 */
int setup_server(struct vpn_net *state)
{
    int on = 1;

    if (NULL == state)
    {
        return VPN_ERROR;
    }

    if (VPN_OK != tun_alloc(state, TUN_DEV_NAME) ||
        VPN_OK != iface_config(state->tun_name, SERVER_TUN_IP, CLIENT_TUN_IP,
                               TUN_NETMASK, TUN_MTU))
    {
        return VPN_ERROR;
    }

    if (VPN_OK != route_lookup(0, state->old_gateway, state->egress_dev) ||
        VPN_OK != ip_forward(&state->old_ip_forward, 0))
    {
        return VPN_ERROR;
    }

    if (VPN_OK != ip_forward(&on, 1))
    {
        return VPN_ERROR;
    }
    state->applied_ip_forward = 1;

    state->applied_nat = 1;

    return nat_rules("-A", state->tun_name, state->egress_dev);
}

/*
 * puts the server machine back the way it was: the firewall rules are removed,
 * the forwarding setting is restored to whatever it was before, and the tunnel
 * interface disappears when its handle is closed.
 *
 * as on the client side, each step is skipped unless it was applied, and a
 * failure does not stop the rest.
 */
void teardown_server(struct vpn_net *state)
{
    if (NULL == state)
    {
        return;
    }

    if (state->applied_nat)
    {
        nat_rules("-D", state->tun_name, state->egress_dev);
        state->applied_nat = 0;
    }

    if (state->applied_ip_forward)
    {
        ip_forward(&state->old_ip_forward, 1);
        state->applied_ip_forward = 0;
    }

    if (state->applied_tun)
    {
        close(state->tun_fd);
        state->tun_fd = -1;
        state->applied_tun = 0;
    }
}

/*
 * arranges for ctrl-c and kill to be caught rather than killing the program
 * outright, so that it gets the chance to undo its changes on the way out.
 *
 * interrupted operations are deliberately left to fail rather than resume. the
 * packet loop spends nearly all its time waiting, and if that wait resumed by
 * itself the program would not notice the request to stop until the next
 * packet happened to arrive.
 */
int vpn_install_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (0 > sigaction(SIGINT, &sa, NULL) ||
        0 > sigaction(SIGTERM, &sa, NULL))
    {
        perror("vpn: sigaction");
        return VPN_ERROR;
    }

    return VPN_OK;
}

/*
 * carries packets in both directions until the program is asked to stop.
 *
 * it waits until either side has something ready, then moves it across:
 * whatever arrives from the other machine is handed to the tunnel, and
 * whatever the tunnel produces is sent to the other machine.
 *
 * nothing has to be cut up or joined back together: one read from the tunnel
 * is exactly one packet, and one message on the socket is exactly one packet,
 * so they map onto each other one for one.
 *
 * learn_peer says whether the other machine's address is already known. the
 * server does not know it until a client speaks, so it takes the address from
 * each message that arrives - which also means a client that moves is still
 * answered at its new address. until the first message arrives the server has
 * nowhere to send, and packets from the tunnel are dropped.
 *
 * a message that fails to send is reported and skipped rather than treated as
 * fatal, since losing the occasional packet is normal here.
 */
void forward_loop(struct vpn_net *state, int sock, struct sockaddr_in *peer,
                  int learn_peer, struct vpn_crypto *crypto)
{
    unsigned char plain[BUF_SIZE];                      /* the real packet */
    unsigned char wire[BUF_SIZE + VPN_OVERHEAD];        /* nonce + ciphertext + tag */
    fd_set readfds;
    socklen_t len = 0;
    ssize_t nbytes = 0;
    long crypt_len = 0;   /* length after encrypting or decrypting */
    int have_peer = !learn_peer;
    int auth_warned = 0;
    int maxfd = (state->tun_fd > sock) ? state->tun_fd : sock;

    while (g_running)
    {
        FD_ZERO(&readfds);
        FD_SET(state->tun_fd, &readfds);
        FD_SET(sock, &readfds);

        if (0 > select(maxfd + 1, &readfds, NULL, NULL, NULL))
        {
            /* the wait was cut short by a signal; the flag decides whether
               that means stop or carry on */
            if (EINTR == errno)
            {
                continue;
            }
            perror("vpn: select");
            break;
        }

        /* something arrived from the other machine - decrypt it, then give
           the packet inside to the tunnel */
        if (FD_ISSET(sock, &readfds))
        {
            len = sizeof(*peer);
            nbytes = recvfrom(sock, wire, sizeof(wire), 0,
                              learn_peer ? (struct sockaddr *)peer : NULL,
                              learn_peer ? &len : NULL);
            if (0 > nbytes)
            {
                if (EINTR == errno)
                {
                    continue;
                }
                perror("vpn: recvfrom");
                break;
            }

            crypt_len = vpn_decrypt(crypto, wire, (long)nbytes, plain);
            if (0 > crypt_len)
            {
                /* either too short, or the tag did not verify: altered in
                   transit, or the sender used a different key. dropped
                   without being handed to the kernel */
                if (!auth_warned)
                {
                    fprintf(stderr, "vpn: dropping packets that "
                            "fail to decrypt - do both sides "
                            "share the same vpn.key?\n");
                    auth_warned = 1;
                }
                continue;
            }

            /* the tag verified, so this really is our peer talking.
               only now is the return address worth believing - before
               the check, anyone could send one junk datagram and
               redirect the tunnel at themselves */
            have_peer = 1;

            if (0 > write(state->tun_fd, plain, (size_t)crypt_len))
            {
                perror("vpn: write tun");
            }
        }

        /* the machine put something into the tunnel - encrypt it and send */
        if (FD_ISSET(state->tun_fd, &readfds))
        {
            nbytes = read(state->tun_fd, plain, sizeof(plain));
            if (0 >= nbytes)
            {
                if (EINTR == errno)
                {
                    continue;
                }
                perror("vpn: read tun");
                break;
            }

            if (have_peer)
            {
                crypt_len = vpn_encrypt(crypto, plain, (long)nbytes, wire);

                if (0 > sendto(sock, wire, (size_t)crypt_len, 0,
                               (const struct sockaddr *)peer, sizeof(*peer)))
                {
                    perror("vpn: sendto");
                }
            }
        }
    }
}
