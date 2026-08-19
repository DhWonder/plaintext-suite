# Build with strict ANSI C flags - the code is written to pass them.
CC     ?= cc
CFLAGS  = -ansi -pedantic -Wall -Wextra

plain-check: plain-check.c
	$(CC) $(CFLAGS) -o plain-check plain-check.c

# Prove it still builds clean and still runs. Nothing here changes the
# machine, so it is safe to run as part of a build.
#
# The exit codes are meaningful rather than pass/fail: 0 is a healthy
# machine, 1 means something is worth a look, 2 means a real risk. All
# three are a successful run, so only something worse counts as broken.
check: plain-check
	@./plain-check --what >/dev/null; s=$$?; [ $$s -le 2 ] || { echo "--what exited $$s"; exit 1; }
	@./plain-check --check >/dev/null; s=$$?; [ $$s -le 2 ] || { echo "--check exited $$s"; exit 1; }
	@./plain-check --help  >/dev/null
	@sh -n system-check.sh
	@echo "plain-check builds, runs, and system-check.sh parses."

clean:
	rm -f plain-check

.PHONY: check clean
