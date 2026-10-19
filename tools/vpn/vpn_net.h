/* Author: Dvash */
/* Reviewer: */

/*
 * vpn_net.h
 *
 * the parts both sides of the vpn share: the tun device, the changes each
 * side makes to the machine's networking, and the loop that moves packets.
 * client.c and server.c are only a main() each on top of this.
 */

#ifndef VPN_NET_H
#define VPN_NET_H

#include <net/if.h>         /* IFNAMSIZ */
#include <netinet/in.h>     /* INET_ADDRSTRLEN */

#include "vpn_crypto.h"     /* struct vpn_crypto, carried through the loop */

/* addresses inside the tunnel, the same on both sides */
#define TUN_DEV_NAME    "tun0"
#define TUN_NETMASK     "255.255.255.0"
#define TUN_MTU         1400

#define SERVER_TUN_IP   "10.8.0.1"
#define CLIENT_TUN_IP   "10.8.0.2"
#define TUN_SUBNET      "10.8.0.0/24"

/* where the client sends its tunnelled packets, on the real network */
#define SERVER_UDP_IP   "192.168.57.1"
#define SERVER_UDP_PORT 51820

#define VPN_OK          0
#define VPN_ERROR       (-1)

/*
 * everything the program changed on the machine, plus what it was before.
 *
 * each "applied" field records that one specific change went through. teardown
 * checks them one by one and undoes only what actually happened, which is what
 * makes it safe to call teardown after a setup that failed half way.
 */
struct vpn_net
{
    int  tun_fd;                        /* open handle; closing it removes the interface */
    char tun_name[IFNAMSIZ];            /* name the kernel gave the interface */

    /* the server's address on the real network. the client pins a route to it
       before moving the default route, and has to delete that same route later,
       so the address it used is kept here rather than assumed */
    char server_ip[INET_ADDRSTRLEN];

    /* what the machine looked like before we touched it */
    char old_gateway[INET_ADDRSTRLEN];  /* gateway the default route pointed at */
    char egress_dev[IFNAMSIZ];          /* interface the default route left through */
    int  old_ip_forward;                /* the sysctl's previous value, server only */

    /* which of our changes are in effect right now */
    int applied_tun;                    /* the tun interface exists */
    int applied_host_route;             /* the pinned route to the server exists */
    int applied_default_route;          /* the original default route is gone */
    int applied_ip_forward;             /* the sysctl was changed */
    int applied_nat;                    /* the iptables rules were added */
};

/*
 * clears the struct and marks the tun handle as unused. call this first, before
 * anything else touches the struct.
 */
void vpn_net_init(struct vpn_net *state);

/*
 * asks the kernel for a tun interface with the given name and stores its handle
 * and its actual name in the struct. pass an empty name to let the kernel pick
 * one. the interface exists for exactly as long as the handle stays open.
 */
int tun_alloc(struct vpn_net *state, const char *name);

/*
 * gives an existing interface its address, the address of the machine at the
 * other end, its netmask and its mtu, then switches the interface on.
 */
int iface_config(const char *name, const char *local_ip, const char *peer_ip,
                 const char *netmask, int mtu);

/*
 * client side: creates and configures the tunnel, remembers how the machine
 * currently routes, pins a route to the server so the tunnel's own packets
 * keep their old path, and then sends everything else through the tunnel.
 */
int setup_client(struct vpn_net *state, const char *server_ip);

/*
 * client side: puts the routing back the way it was and removes the tunnel.
 * safe to call at any point, including after a setup that failed part way.
 */
void teardown_client(struct vpn_net *state);

/*
 * server side: creates and configures the tunnel, turns on packet forwarding,
 * and adds the firewall rules that let the client reach the internet through
 * this machine's own connection.
 */
int setup_server(struct vpn_net *state);

/*
 * server side: removes the firewall rules, restores the forwarding setting and
 * removes the tunnel. safe to call after a setup that failed part way.
 */
void teardown_server(struct vpn_net *state);

/*
 * arranges for ctrl-c and kill to stop the program cleanly. they only raise a
 * flag that the packet loop checks; the actual cleanup happens afterwards in
 * main, never inside the interrupt itself.
 */
int vpn_install_handlers(void);

/*
 * carries packets in both directions until one of those signals arrives:
 * anything the machine writes into the tunnel is sent to the other side, and
 * anything arriving from the other side is handed back to the machine.
 *
 * learn_peer says where the other side is. the client already knows the
 * server's address and passes 0. the server cannot know where a client is until
 * it hears from one, so it passes an empty address and 1, and the address is
 * taken from whatever arrives.
 *
 * every packet is encrypted on the way out and decrypted on the way back in,
 * so nothing readable ever reaches the wire.
 */
void forward_loop(struct vpn_net *state, int sock, struct sockaddr_in *peer,
                  int learn_peer, struct vpn_crypto *crypto);

#endif /* VPN_NET_H */
