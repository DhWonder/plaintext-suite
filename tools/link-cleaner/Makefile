# Build with strict ANSI C flags - the code is written to pass them.
CC     ?= cc
CFLAGS  = -ansi -pedantic -Wall -Wextra

plain-link: plain-link.c
	$(CC) $(CFLAGS) -o plain-link plain-link.c

# Prove it still builds, still refuses what it should refuse, and above all
# still leaves alone the things that must survive. Nothing here touches the
# network or writes to disk outside this folder.
#
# The exit codes are meaningful rather than pass/fail: 0 the link was already
# clean, 1 something was removed, 2 that was not a link. All three are a
# successful run.
check: plain-link
	@./plain-link "https://e.com/a?utm_source=x" >/dev/null; s=$$?; [ $$s -eq 1 ] || { echo "expected 1, got $$s"; exit 1; }
	@./plain-link "https://e.com/a" >/dev/null; s=$$?; [ $$s -eq 0 ] || { echo "expected 0, got $$s"; exit 1; }
	@./plain-link "not a link" >/dev/null 2>&1; s=$$?; [ $$s -eq 2 ] || { echo "expected 2, got $$s"; exit 1; }
	@./plain-link --list >/dev/null
	@./plain-link --help >/dev/null
	@sh -n plain-link-watch.sh
	@python3 tests/test_link.py

clean:
	rm -f plain-link

.PHONY: check clean
