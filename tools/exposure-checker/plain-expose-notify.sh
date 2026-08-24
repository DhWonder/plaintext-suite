#!/bin/sh
#
# plain-expose-notify - watch for doors opening, and say so when one does.
#
# The report plain-expose prints is worth reading the first time. It is not
# worth emailing every week, because on a machine nobody has touched it says
# exactly the same thing every week, and an email that always says the same
# thing is one you stop opening - including the week it changed.
#
# So this wrapper does not email you the report. It remembers which doors
# were open last time and emails you when the list is different: a port that
# was not there yesterday, or one that used to be there and has gone. That
# is the event. A new listening port on a server nobody logged into is worth
# waking up for; the same twelve ports as last Tuesday is not.
#
# It also emails on a real risk even when nothing changed, because a Redis
# that has been wide open for a month has not stopped being wide open just
# because it was also wide open yesterday.
#
# Usage:
#   sh plain-expose-notify.sh                run it, email if anything changed
#   sh plain-expose-notify.sh --always       email whatever it finds
#   sh plain-expose-notify.sh --reset        forget what it knew, start again
#   sh plain-expose-notify.sh notify test    set up and test the email settings
#
# From cron, on a server, daily:
#   0 7 * * * sh /path/to/plain-expose-notify.sh
#
# Run it as root or the emails will be full of doors with no owner.
#
# Exit code is plain-expose's own: 0 nothing to do, 1 worth a look, 2 risk.
#
# DhWonder, Plaintext IT - MIT license.

HERE=$(dirname "$0")
TOOL="$HERE/plain-expose"
ALWAYS=0

# Where the last known list of doors lives. /var/lib if we can write there,
# which is where state belongs on a server; the user's own directory if not,
# so this still works without root.
if [ -w /var/lib ] 2>/dev/null; then
    STATE_DIR=/var/lib/plaintext-it
else
    STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/plaintext-it"
fi
STATE="$STATE_DIR/exposure.doors"

if [ "$1" = "notify" ]; then
    shift
    if [ ! -f "$HERE/notify.py" ] || ! command -v python3 >/dev/null 2>&1; then
        printf '%s\n' "That needs python3 and notify.py next to this script."
        exit 2
    fi
    if [ $# -eq 0 ]; then set -- show; fi
    python3 "$HERE/notify.py" "$@"
    exit $?
fi

if [ "$1" = "--reset" ]; then
    rm -f "$STATE"
    printf '%s\n' "Forgotten. The next run will treat every open door as new."
    exit 0
fi

[ "$1" = "--always" ] && ALWAYS=1

if [ ! -x "$TOOL" ]; then
    printf '%s\n' "plain-expose is not built yet. Build it first:"
    printf '%s\n' "    make -C $HERE"
    exit 2
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/plain-expose.XXXXXX") || exit 2
trap 'rm -rf "$WORK"' EXIT INT TERM

NOW="$WORK/now"
REPORT="$WORK/report"

# The two runs answer different questions: --list is the set of doors, for
# comparing, and --check is the readable part, for the email body.
"$TOOL" --list | sort > "$NOW"
"$TOOL" --check > "$REPORT" 2>&1
STATUS=$?

cat "$REPORT"

# Keep a copy of what we knew before overwriting it, because the whole
# email is the difference between the two and the state file is about to
# stop being the old one.
PREV="$WORK/prev"
CHANGED=0
FIRST_RUN=0
if [ -f "$STATE" ]; then
    # Sorted, not copied: comm refuses to work on unsorted input, and a
    # state file from an older version of this script may not be in the
    # same order. Sorting both sides costs nothing and removes a way for
    # this to fail noisily on somebody else's machine.
    sort "$STATE" > "$PREV"
    if ! cmp -s "$PREV" "$NOW"; then
        CHANGED=1
    fi
else
    : > "$PREV"
    FIRST_RUN=1
fi

mkdir -p "$STATE_DIR" 2>/dev/null
cp "$NOW" "$STATE" 2>/dev/null || {
    printf '%s\n' ""
    printf '%s\n' "Could not remember today's doors ($STATE is not writable),"
    printf '%s\n' "so the next run cannot tell you what changed. The report"
    printf '%s\n' "above is unaffected."
}

# The first run has nothing to compare against. Saying "12 new doors!" on a
# machine that has had those twelve doors open for two years would be a lie
# by omission, so it says what it is instead.
if [ "$FIRST_RUN" -eq 1 ] && [ "$ALWAYS" -eq 0 ] && [ "$STATUS" -lt 2 ]; then
    printf '%s\n' ""
    printf '%s\n' "First run: nothing to compare against yet. From now on this"
    printf '%s\n' "will tell you when the list changes."
    exit "$STATUS"
fi

if [ "$CHANGED" -eq 0 ] && [ "$ALWAYS" -eq 0 ] && [ "$STATUS" -lt 2 ]; then
    exit "$STATUS"
fi

if [ ! -f "$HERE/notify.py" ] || ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' ""
    printf '%s\n' "Could not send the notification: it needs python3 and notify.py"
    printf '%s\n' "next to this script. The report above is unaffected."
    exit "$STATUS"
fi

WHO=$(hostname 2>/dev/null || printf '%s' "this machine")

BODY="$WORK/body"
if [ "$CHANGED" -eq 1 ]; then
    {
        printf '%s\n' "The list of doors on $WHO is not what it was."
        printf '%s\n' ""
        # Both sides are sorted, which is what comm needs. Its second
        # column is what is only in the new list, the first what is only
        # in the old.
        comm -13 "$PREV" "$NOW" | sed 's/^/  now open:   /'
        comm -23 "$PREV" "$NOW" | sed 's/^/  now closed: /'
        printf '%s\n' ""
    } > "$WORK/changes"
    # Shown as well as sent. Run by hand, the change is the thing you came
    # to see, and it should not only exist inside an email.
    printf '%s\n' ""
    cat "$WORK/changes"
    cat "$WORK/changes" > "$BODY"
    cat "$REPORT" >> "$BODY"
    SUBJECT="$WHO: the open ports have changed"
else
    cp "$REPORT" "$BODY"
    if [ "$STATUS" -eq 2 ]; then
        SUBJECT="$WHO: something is reachable that should not be"
    elif [ "$STATUS" -eq 1 ]; then
        SUBJECT="$WHO: a couple of open ports worth a look"
    else
        SUBJECT="$WHO: nothing reachable that should not be"
    fi
fi

python3 "$HERE/notify.py" send --tool exposure-checker \
    --subject "$SUBJECT" --key "exposure:$WHO:$STATUS:$CHANGED" < "$BODY"

exit "$STATUS"
