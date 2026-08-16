#!/bin/sh
#
# plain-check-notify - run plain-check, and email the report if it found
#                      something worth your attention.
#
# plain-check itself is C, and teaching a C program to speak SMTP would mean
# a second copy of that logic written in a second language, which is how two
# tools end up disagreeing about what they sent. So the C stays as it is: it
# reads the machine, it prints, it exits 0, 1 or 2. This wrapper runs it and
# hands the output to notify.py, the same module every other tool here uses.
#
# Usage:
#   sh plain-check-notify.sh                 run it, email if anything is wrong
#   sh plain-check-notify.sh --always        email even when the machine is fine
#   sh plain-check-notify.sh notify test     set up and test the email settings
#
# From cron, weekly, on a machine you do not log into often:
#   0 8 * * 1 sh /path/to/plain-check-notify.sh
#
# Exit code is plain-check's own: 0 healthy, 1 worth a look, 2 real risk.
#
# DhWonder, Plaintext IT - MIT license.

HERE=$(dirname "$0")
CHECKER="$HERE/plain-check"
ALWAYS=0

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

[ "$1" = "--always" ] && ALWAYS=1

if [ ! -x "$CHECKER" ]; then
    printf '%s\n' "plain-check is not built yet. Build it first:"
    printf '%s\n' "    make -C $HERE"
    exit 2
fi

REPORT=$(mktemp "${TMPDIR:-/tmp}/plain-check.XXXXXX") || exit 2
trap 'rm -f "$REPORT"' EXIT INT TERM

"$CHECKER" > "$REPORT" 2>&1
STATUS=$?
cat "$REPORT"

# 0 means nothing to say. An all-clear that arrives every week is an email
# you stop opening, and then you stop opening the one that matters too.
if [ "$STATUS" -eq 0 ] && [ "$ALWAYS" -eq 0 ]; then
    exit 0
fi

if [ ! -f "$HERE/notify.py" ] || ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' ""
    printf '%s\n' "Could not send the notification: it needs python3 and notify.py"
    printf '%s\n' "next to this script. The report above is unaffected."
    exit "$STATUS"
fi

WHO=$(hostname 2>/dev/null || printf '%s' "this machine")
if [ "$STATUS" -eq 2 ]; then
    SUBJECT="$WHO: something on this machine needs attention"
elif [ "$STATUS" -eq 1 ]; then
    SUBJECT="$WHO: a couple of things worth a look"
else
    SUBJECT="$WHO: nothing wrong with this machine"
fi

python3 "$HERE/notify.py" send --tool system-checker \
    --subject "$SUBJECT" --key "system:$WHO:$STATUS" < "$REPORT"

exit "$STATUS"
