#!/bin/sh
#
# backup-witness - checks that your backups are actually happening,
#                  and that you could actually restore from them.
#
# I wrote this after seeing the same story too many times: a business
# has a backup job, the job died quietly months ago, and everyone finds
# out on the day they need it. A backup nobody has tested is a guess.
#
# Usage:
#   backup-witness.sh check  /path/to/backup/folder
#   backup-witness.sh drill  /path/to/backup/folder /path/to/original/folder
#   backup-witness.sh check  /path/to/backup/folder --notify
#   backup-witness.sh notify setup | test | show
#
# "check" answers: did a backup happen recently, and does it look sane?
# "drill" answers: can I take a random file out of the backup and does
#         it match the original? (a tiny restore test, do it monthly)
#
# Exit codes: 0 = all good, 1 = warning, 2 = something is wrong.
# That makes it easy to run from cron and get emailed only on trouble.
#
# --notify is for when cron is not set up to mail you, which on a modern
# machine it usually is not. It sends this report to the address in
# ~/.plaintext/notify.conf, and only when something is wrong: a run that
# finds nothing to say sends nothing, because an all-clear that arrives
# every night is an email you stop reading. It needs notify.py, which
# lives next to this script, and python3.
#
# DhWonder, Plaintext IT - MIT license.

MAX_AGE_HOURS=30      # newest file in the backup should be younger than this
SHRINK_ALERT=10       # complain if the backup shrank more than this percent
STATE_DIR="${HOME}/.backup-witness"

HERE=$(dirname "$0")
NOTIFY=0
NOTIFY_CONFIG=""
TRANSCRIPT=""
SUBJECT_OF="backup"

# Everything printed is also kept, so that if there turns out to be
# something worth emailing, the email is the same words you would have
# read on the screen rather than a summary of them.
say() {
    printf '%s\n' "$*"
    if [ -n "$TRANSCRIPT" ]; then
        printf '%s\n' "$*" >> "$TRANSCRIPT"
    fi
    return 0
}

notify_send() {
    # notify_send <subject> <key>. Body is everything said so far.
    [ "$NOTIFY" -eq 1 ] || return 0
    [ -n "$TRANSCRIPT" ] || return 0
    if [ ! -f "$HERE/notify.py" ] || ! command -v python3 >/dev/null 2>&1; then
        printf '%s\n' "Could not send the notification: it needs python3 and notify.py"
        printf '%s\n' "next to this script. The report above is unaffected."
        return 1
    fi
    if [ -n "$NOTIFY_CONFIG" ]; then
        python3 "$HERE/notify.py" send --tool backup-checker \
            --subject "$1" --key "$2" --config "$NOTIFY_CONFIG" < "$TRANSCRIPT"
    else
        python3 "$HERE/notify.py" send --tool backup-checker \
            --subject "$1" --key "$2" < "$TRANSCRIPT"
    fi
}

fail() {
    say "PROBLEM: $*"
    notify_send "backup problem: $SUBJECT_OF" "backup:$SUBJECT_OF"
    exit 2
}
warn_count=0
warn() { say "WARNING: $*"; warn_count=$((warn_count + 1)); }

usage() {
    say "usage: $0 check  <backup-folder> [--notify]"
    say "       $0 drill  <backup-folder> <original-folder> [--notify]"
    say "       $0 notify setup|test|show"
    exit 2
}

# ---------------------------------------------------------------
# check mode
# ---------------------------------------------------------------
do_check() {
    backup="$1"
    SUBJECT_OF="$backup"

    [ -d "$backup" ] || fail "the backup folder '$backup' does not exist. If it lives on an external disk or network drive, it may not be connected."

    say "Checking backup folder: $backup"
    say ""

    # 1. Is there anything in it at all?
    file_count=$(find "$backup" -type f | wc -l)
    [ "$file_count" -gt 0 ] || fail "the backup folder is empty. The backup job is probably not running at all."
    say "  Files found:            $file_count"

    # 2. When did the newest file arrive?
    #    If nothing new appeared recently, the backup job has stopped.
    newest=$(find "$backup" -type f -mmin -$((MAX_AGE_HOURS * 60)) | head -1)
    if [ -n "$newest" ]; then
        say "  Freshness:              OK (something was written in the last ${MAX_AGE_HOURS}h)"
    else
        warn "nothing new in the last ${MAX_AGE_HOURS} hours. If your backup runs daily, it has likely stopped. Check the backup software's own logs."
    fi

    # 3. Compare total size with the last time we looked.
    #    A backup that suddenly shrinks is a classic sign of trouble.
    mkdir -p "$STATE_DIR"
    state_file="$STATE_DIR/$(printf '%s' "$backup" | tr '/ ' '__').size"
    size_now=$(du -sk "$backup" | cut -f1)
    say "  Total size:             $((size_now / 1024)) MB"

    if [ -f "$state_file" ]; then
        size_before=$(cat "$state_file")
        if [ "$size_before" -gt 0 ]; then
            # percent change, done in integer math to stay POSIX-friendly
            diff=$((size_now - size_before))
            pct=$((diff * 100 / size_before))
            if [ "$pct" -lt "-$SHRINK_ALERT" ]; then
                warn "the backup shrank by ${pct#-}% since last check. That can be normal (cleanup) but is worth a look."
            else
                say "  Size vs last check:     OK (${pct}% change)"
            fi
        fi
    else
        say "  Size vs last check:     first run, nothing to compare yet"
    fi
    printf '%s\n' "$size_now" > "$state_file"

    say ""
    if [ "$warn_count" -eq 0 ]; then
        say "Verdict: your backup looks alive. Run a 'drill' once a month to be sure it restores."
        exit 0
    else
        say "Verdict: $warn_count warning(s) above. A warning today is cheaper than a disaster later."
        notify_send "backup warning: $backup" "backup:$backup"
        exit 1
    fi
}

# ---------------------------------------------------------------
# drill mode - the part almost nobody does
# ---------------------------------------------------------------
do_drill() {
    backup="$1"
    original="$2"
    SUBJECT_OF="$backup"

    [ -d "$backup" ]   || fail "backup folder '$backup' not found."
    [ -d "$original" ] || fail "original folder '$original' not found."

    say "Restore drill: picking a random file from the backup and comparing it to the original."
    say ""

    # Pick a file that exists in both places. We try a handful of
    # random candidates because some files legitimately exist only
    # in the backup (old versions, deleted files kept on purpose).
    tries=0
    picked=""
    while [ "$tries" -lt 25 ]; do
        tries=$((tries + 1))
        # shuf isn't POSIX, so fall back to awk-based sampling if needed
        if command -v shuf >/dev/null 2>&1; then
            candidate=$(find "$backup" -type f | shuf -n 1)
        else
            candidate=$(find "$backup" -type f | awk 'BEGIN{srand()} {a[NR]=$0} END{if (NR>0) print a[int(rand()*NR)+1]}')
        fi
        [ -n "$candidate" ] || fail "could not find any file in the backup to test."
        rel="${candidate#"$backup"/}"
        if [ -f "$original/$rel" ]; then
            picked="$rel"
            break
        fi
    done

    [ -n "$picked" ] || fail "tried $tries random files and none of them exist in the original folder. Either the folder layout differs, or the backup is of something else entirely."

    say "  Testing file:  $picked"

    sum_backup=$(cksum < "$backup/$picked")
    sum_orig=$(cksum < "$original/$picked")

    if [ "$sum_backup" = "$sum_orig" ]; then
        say "  Result:        MATCH - the backed-up copy is byte-for-byte identical."
        say ""
        say "Verdict: this backup can actually restore files. Do this drill again next month."
        exit 0
    else
        say "  Result:        MISMATCH - the backup copy differs from the original."
        say ""
        say "Verdict: this may just mean the file changed since the last backup ran."
        say "Run the drill again on a file that hasn't changed lately. If mismatches"
        say "keep happening, treat the backup as broken until proven otherwise."
        notify_send "restore drill mismatch: $backup" "drill:$backup"
        exit 1
    fi
}

# ---------------------------------------------------------------
# Arguments. The flags are pulled out first so the folder paths can be
# anywhere on the line, and so a path with a space in it still survives.
# ---------------------------------------------------------------
mode="${1:-}"
[ $# -gt 0 ] && shift

remaining=$#
while [ "$remaining" -gt 0 ]; do
    arg="$1"
    shift
    remaining=$((remaining - 1))
    case "$arg" in
        --notify)
            NOTIFY=1 ;;
        --notify-config)
            NOTIFY_CONFIG="$1"
            shift
            remaining=$((remaining - 1)) ;;
        --*)
            printf '%s\n' "I do not know the option $arg"
            usage ;;
        *)
            set -- "$@" "$arg" ;;
    esac
done

if [ "$NOTIFY" -eq 1 ]; then
    TRANSCRIPT=$(mktemp "${TMPDIR:-/tmp}/backup-witness.XXXXXX" 2>/dev/null) || TRANSCRIPT=""
    [ -n "$TRANSCRIPT" ] && trap 'rm -f "$TRANSCRIPT"' EXIT INT TERM
fi

case "$mode" in
    check)  [ $# -eq 1 ] || usage; do_check "$1" ;;
    drill)  [ $# -eq 2 ] || usage; do_drill "$1" "$2" ;;
    notify)
        # Setting up and testing the notification email, the same settings
        # and the same commands as every other tool in the suite.
        if [ ! -f "$HERE/notify.py" ] || ! command -v python3 >/dev/null 2>&1; then
            say "That needs python3 and notify.py next to this script."
            exit 2
        fi
        if [ $# -eq 0 ]; then set -- show; fi
        python3 "$HERE/notify.py" "$@"
        exit $? ;;
    *) usage ;;
esac
