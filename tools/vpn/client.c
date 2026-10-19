/* Author: Dvash */
/* Reviewer: */

/*
 * client.c
 *
 * the vpn client. it takes over this machine's routing so that everything it
 * sends travels to the server first, and then spends the rest of its life
 * carrying packets back and forth. on the way out it puts the routing back.
 *
 * usage: vpn_client [server ip]   - the built-in address is used if none given
 */

#include <stdio.h>          /* printf, fprintf, perror */
#include <stdlib.h>         /* EXIT_SUCCESS, EXIT_FAILURE */
#include <string.h>         /* memset */
#include <unistd.h>         /* close */
#include <sys/socket.h>     /* socket */
#include <arpa/inet.h>      /* inet_pton, htons */

#include "vpn_net.h"
#include "vpn_crypto.h"

/*
 * works through the client's whole life in order: read the server address off
 * the command line, arrange to be interrupted cleanly, open the socket that
 * talks to the server, take over the routing, carry packets until asked to
 * stop, and then restore the machine.
 *
 * if the takeover fails part way it still calls teardown, which undoes
 * whichever steps had already succeeded and leaves the rest alone.
 */
int main(int argc, char *argv[])
{
    struct vpn_net state;
    struct vpn_crypto crypto;
    struct sockaddr_in server;
    const char *server_ip = SERVER_UDP_IP;
    int sock = -1;

    if (2 == argc)
    {
        server_ip = argv[1];
    }
    else if (1 != argc)
    {
        fprintf(stderr, "usage: %s [server ip]\n", argv[0]);
        return EXIT_FAILURE;
    }

    vpn_net_init(&state);

    /* where the tunnelled packets get sent on the real network */
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons((unsigned short)SERVER_UDP_PORT);
    if (1 != inet_pton(AF_INET, server_ip, &server.sin_addr))
    {
        fprintf(stderr, "client: %s is not a valid address\n", server_ip);
        return EXIT_FAILURE;
    }

    if (VPN_OK != vpn_install_handlers())
    {
        return EXIT_FAILURE;
    }

    /* load the key first: a missing key must fail before we touch routing */
    if (VPN_CRYPTO_OK != vpn_crypto_init(&crypto, VPN_KEY_FILE))
    {
        return EXIT_FAILURE;
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (0 > sock)
    {
        perror("client: socket");
        return EXIT_FAILURE;
    }

    /* setup keeps the server reachable by its original path before it moves
       everything else onto the tunnel, so this socket keeps working */
    if (VPN_OK != setup_client(&state, server_ip))
    {
        fprintf(stderr, "client: setup failed, rolling back\n");
        teardown_client(&state);
        vpn_crypto_cleanup(&crypto);
        close(sock);
        return EXIT_FAILURE;
    }

    printf("client up: %s on %s, everything leaves through %s:%d\n"
           "ctrl-c to put the old routing back\n",
           CLIENT_TUN_IP, state.tun_name, server_ip, SERVER_UDP_PORT);

    /* the client knows where the server is, so the address is not learned */
    forward_loop(&state, sock, &server, 0, &crypto);

    /* reached whether the loop ended on ctrl-c or on an error. the cleanup
       runs here, on the ordinary path, and never inside the interrupt */
    printf("\nclient: restoring the old routing\n");
    teardown_client(&state);
    vpn_crypto_cleanup(&crypto);
    close(sock);

    return EXIT_SUCCESS;
}
