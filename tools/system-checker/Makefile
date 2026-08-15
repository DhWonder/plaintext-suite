# Build with strict ANSI C flags - the code is written to pass them.
CC     ?= cc
CFLAGS  = -ansi -pedantic -Wall -Wextra

plain-check: plain-check.c
	$(CC) $(CFLAGS) -o plain-check plain-check.c

clean:
	rm -f plain-check

.PHONY: clean
