#!/bin/sh
#
# plain-link-watch - watch the clipboard, and take the tracking off any link
#                    you copy, as you copy it.
#
# plain-link does the thinking. This does the one thing plain-link cannot do
# without dragging in X11, Wayland and macOS all at once: reach the
# clipboard. Keeping them apart means the C stays dependency-free and this
# stays short enough to read before you trust it - which matters more here
# than anywhere else in this suite, because this is the only tool that reads
# your clipboard.
#
# ABOUT THAT. Your clipboard holds passwords. It holds whatever you last
# copied out of a password manager, a client's bank details, half a private
# message. This script reads all of it, every second, for as long as it runs.
# So, in full:
#
#   * It writes nothing to disk. No log, no history, no cache. The only
#     copies of your clipboard it makes live in shell variables and die with
#     the process.
#   * It prints nothing except links. If what you copied is not a link, this
#     script has nothing to say and says nothing.
#   * It sends nothing anywhere. There is no network call in this file, and
#     plain-link has none either.
#   * It only writes to the clipboard when a link came in and something was
#     actually removed. Copy a clean link and the clipboard is untouched.
#
# That is a promise you can check: this file is about a hundred lines and
# every clipboard read is on one of them.
#
# Usage:
#   sh plain-link-watch.sh              watch until you stop it
#   sh plain-link-watch.sh --once       clean what is in there now, then stop
#   sh plain-link-watch.sh --text       also clean links inside copied text
#   sh plain-link-watch.sh --quiet      do it without saying anything
#   sh plain-link-watch.sh --every 2    seconds between looks (default 1)
#
# Stop it with ctrl-C.
#
# DhWonder, Plaintext IT - MIT license.

HERE=$(dirname "$0")
TOOL="$HERE/plain-link"
EVERY=1
ONCE=0
QUIET=0
TEXT_MODE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --once)  ONCE=1 ;;
        --quiet) QUIET=1 ;;
        --text)  TEXT_MODE="--text" ;;
        --every) shift; EVERY="$1" ;;
        --help|-h)
            sed -n '2,40p' "$0" | sed 's/^#//; s/^ //'
            exit 0 ;;
        *)
            printf '%s\n' "Do not understand \"$1\". Try --help."
            exit 3 ;;
    esac
    shift
done

if [ ! -x "$TOOL" ]; then
    printf '%s\n' "plain-link is not built yet. Build it first:"
    printf '%s\n' "    make -C $HERE"
    exit 2
fi

# Work out how to talk to this machine's clipboard. Wayland, X11 and macOS
# each have their own, and there is no common one - which is exactly why
# this is a shell script and not part of the C.
if command -v wl-paste >/dev/null 2>&1 && command -v wl-copy >/dev/null 2>&1; then
    READ_CLIP="wl-paste --no-newline"
    WRITE_CLIP="wl-copy"
    WHICH="Wayland"
elif command -v xclip >/dev/null 2>&1; then
    READ_CLIP="xclip -selection clipboard -o"
    WRITE_CLIP="xclip -selection clipboard -in"
    WHICH="X11 (xclip)"
elif command -v xsel >/dev/null 2>&1; then
    READ_CLIP="xsel --clipboard --output"
    WRITE_CLIP="xsel --clipboard --input"
    WHICH="X11 (xsel)"
elif command -v pbpaste >/dev/null 2>&1; then
    READ_CLIP="pbpaste"
    WRITE_CLIP="pbcopy"
    WHICH="macOS"
else
    printf '%s\n' "No way to reach the clipboard on this machine."
    printf '%s\n' ""
    printf '%s\n' "Install one of these, whichever suits your desktop:"
    printf '%s\n' "    wl-clipboard   Wayland"
    printf '%s\n' "    xclip          X11"
    printf '%s\n' "    xsel           X11"
    printf '%s\n' ""
    printf '%s\n' "Or use plain-link on its own, which needs nothing:"
    printf '%s\n' "    $TOOL \"https://...\""
    exit 2
fi

say() {
    [ "$QUIET" -eq 1 ] || printf '%s\n' "$1"
}

# One pass: read, clean, write back only if something came off.
#
# plain-link's exit code carries the answer, which is why this does not
# have to compare strings: 0 means it was already clean, 1 means something
# was removed, anything else means it was not a link. Nothing is written to
# the clipboard except in the middle case.
#
# That test on the exit code is doing more work than it looks like. Reading
# from a pipe, plain-link passes a line that is not a link straight through
# unchanged - which is right for a pipe, and would be a disaster here: it
# means "cleaned" holds a copy of whatever you copied, password included.
# Checking that something was actually removed is what keeps that copy from
# being written back and printed. Loosen this to "did we get anything back"
# and the script starts announcing your clipboard. There is a test for that
# exact mistake in tests/test_link.py.
sweep() {
    current=$($READ_CLIP 2>/dev/null) || return 0
    [ -n "$current" ] || return 0
    [ "$current" = "$LAST" ] && return 0
    LAST="$current"

    cleaned=$(printf '%s' "$current" | "$TOOL" $TEXT_MODE 2>/dev/null)
    status=$?

    if [ "$status" -eq 1 ] && [ -n "$cleaned" ]; then
        printf '%s' "$cleaned" | $WRITE_CLIP
        # Remember what we put there, so the next look does not treat our
        # own write as something new the user copied.
        LAST="$cleaned"
        say "  cleaned: $cleaned"
    fi
    return 0
}

LAST=""

if [ "$ONCE" -eq 1 ]; then
    sweep
    say "Done."
    exit 0
fi

say "Watching the clipboard through $WHICH, every ${EVERY}s."
say "Copy a link and the tracking comes off it. ctrl-C to stop."
say "Nothing is written to disk and nothing leaves this machine."
say ""

while true; do
    sweep
    sleep "$EVERY"
done
