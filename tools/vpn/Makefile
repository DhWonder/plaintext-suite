# Author: Dvash

CC     = gcc
CFLAGS = -ansi -pedantic -Wall -Wextra -D_DEFAULT_SOURCE
LDLIBS = -lcrypto

COMMON  = vpn_net.c vpn_crypto.c
HEADERS = vpn_net.h vpn_crypto.h

all: vpn_client vpn_server

vpn_client: client.c $(COMMON) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ client.c $(COMMON) $(LDLIBS)

vpn_server: server.c $(COMMON) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ server.c $(COMMON) $(LDLIBS)

clean:
	rm -f vpn_client vpn_server

.PHONY: all clean
