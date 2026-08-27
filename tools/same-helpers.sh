#!/bin/sh
#
# same-helpers - prove the handful of functions the C tools share are still
#                the same in both, and shout if they are not.
#
# The C tools deliberately do not share a header. The reasons are written up
# in the comment block at the top of each shared region, and the short
# version is that ANSI C has no `inline`, so a header full of `static`
# helpers costs the warning-clean build, and a real .c/.h pair costs the
# promise every README makes that one file compiles with one command.
#
# The price of that decision is thirty duplicated lines. That price is only
# worth paying while the copies stay identical - the moment one tool fixes a
# bug the other still has, the duplication has become the thing it always
# threatens to become. So this checks. It is run by `make check` in each
# tool, which means the day they drift is the day a build says so, rather
# than some later day when the two disagree in front of a client.
#
# If this fails, the fix is to make them the same again, not to edit this.
# If they genuinely need to differ, that is the signal that the shared
# region should stop being shared - move that function out of the marked
# block in both files and give each its own name.
#
#   sh tools/same-helpers.sh
#
# DhWonder, Plaintext IT - MIT license.

HERE=$(dirname "$0")
START='SHARED HELPERS - keep identical'
END='END OF SHARED HELPERS'

FILES="$HERE/system-checker/plain-check.c $HERE/exposure-checker/plain-expose.c"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/same-helpers.XXXXXX") || exit 2
trap 'rm -rf "$WORK"' EXIT INT TERM

COUNT=0
for f in $FILES; do
    if [ ! -f "$f" ]; then
        printf '%s\n' "same-helpers: cannot find $f"
        exit 2
    fi
    COUNT=$((COUNT + 1))
    sed -n "/$START/,/$END/p" "$f" > "$WORK/$COUNT"
    if [ ! -s "$WORK/$COUNT" ]; then
        printf '%s\n' "same-helpers: $f has no shared block."
        printf '%s\n' "Either the markers were removed, or the block was."
        exit 1
    fi
done

FIRST="$WORK/1"
N=2
while [ "$N" -le "$COUNT" ]; do
    if ! cmp -s "$FIRST" "$WORK/$N"; then
        printf '%s\n' "The shared helpers have drifted apart:"
        printf '%s\n' ""
        diff "$FIRST" "$WORK/$N"
        printf '%s\n' ""
        printf '%s\n' "Make them the same again, or move the one that had to"
        printf '%s\n' "change out of the shared block in both files."
        exit 1
    fi
    N=$((N + 1))
done

printf '%s\n' "The shared C helpers are identical in all $COUNT files."
