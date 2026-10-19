/* Author: Dvash */
/* Reviewer: */

/*
 * server.c
 *
 * the vpn server. it lets a client borrow this machine's internet connection:
 * traffic arriving through the tunnel is passed out to the internet under this
 * machine's own address, and the replies are sent back down the tunnel. on the
 * way out it removes everything it added.
 */

#include <stdio.h>          /* printf, fprintf, perror */
#include <stdlib.h>         /* EXIT_SUCCESS, EXIT_FAILURE */
#include <string.h>         /* memset */
#include <unistd.h>         /* close */
#include <sys/socket.h>     /* socket, bind, setsockopt */
#include <arpa/inet.h>      /* htons, htonl */

#include "vpn_net.h"
#include "vpn_crypto.h"

/*
 * opens the socket clients connect to and claims the given port on every
 * interface of this machine. the port is also marked reusable, so restarting
 * the server straight away works instead of failing on a port still held by
 * the previous run.
 */
static int udp_listen(int port)
{
    struct sockaddr_in addr;
    int sock = -1;
    int opt = 1;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (0 > sock)
    {
        perror("server: socket");
        return VPN_ERROR;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((unsigned short)port);

    if (0 > setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) ||
        0 > bind(sock, (struct sockaddr *)&addr, sizeof(addr)))
    {
        perror("server: bind");
        close(sock);
        return VPN_ERROR;
    }

    return sock;
}

/*
 * works through the server's whole life in order: arrange to be interrupted
 * cleanly, start listening for clients, set up forwarding and the firewall
 * rules, carry packets until asked to stop, and then remove everything again.
 *
 * if the setup fails part way it still calls teardown, which undoes whichever
 * steps had already succeeded.
 */
int main(void)
{
    struct vpn_net state;
    struct vpn_crypto crypto;
    struct sockaddr_in client;
    int sock = -1;

    vpn_net_init(&state);

    /* filled in by the loop once a client is heard from */
    memset(&client, 0, sizeof(client));

    if (VPN_OK != vpn_install_handlers())
    {
        return EXIT_FAILURE;
    }

    /* load the key first: a missing key must fail before we touch anything */
    if (VPN_CRYPTO_OK != vpn_crypto_init(&crypto, VPN_KEY_FILE))
    {
        return EXIT_FAILURE;
    }

    sock = udp_listen(SERVER_UDP_PORT);
    if (0 > sock)
    {
        return EXIT_FAILURE;
    }

    if (VPN_OK != setup_server(&state))
    {
        fprintf(stderr, "server: setup failed, rolling back\n");
        teardown_server(&state);
        vpn_crypto_cleanup(&crypto);
        close(sock);
        return EXIT_FAILURE;
    }

    printf("server up: %s on %s, listening on udp %d\n"
           "masquerading %s out through %s\n"
           "ctrl-c to remove the rules again\n",
           SERVER_TUN_IP, state.tun_name, SERVER_UDP_PORT,
           TUN_SUBNET, state.egress_dev);

    /* the server has no idea where the client is, so it learns the address */
    forward_loop(&state, sock, &client, 1, &crypto);

    printf("\nserver: removing the rules\n");
    teardown_server(&state);
    vpn_crypto_cleanup(&crypto);
    close(sock);

    return EXIT_SUCCESS;
}
