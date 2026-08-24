# Build with strict ANSI C flags - the code is written to pass them.
CC     ?= cc
CFLAGS  = -ansi -pedantic -Wall -Wextra

plain-expose: plain-expose.c
	$(CC) $(CFLAGS) -o plain-expose plain-expose.c

# Prove it still builds clean, still runs, and still says the right thing
# about a machine with known problems on it. The test suite builds fake
# /proc trees and reads them back with --root, so `make check` needs no
# particular machine and changes nothing on this one.
#
# The exit codes are meaningful rather than pass/fail: 0 nothing to do,
# 1 worth a look, 2 a real risk. All three are a successful run.
check: plain-expose
	@./plain-expose --check >/dev/null; s=$$?; [ $$s -le 2 ] || { echo "--check exited $$s"; exit 1; }
	@./plain-expose --list  >/dev/null
	@./plain-expose --help  >/dev/null
	@sh -n plain-expose-notify.sh
	@python3 tests/test_expose.py

clean:
	rm -f plain-expose

.PHONY: check clean
