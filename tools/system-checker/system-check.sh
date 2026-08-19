#!/bin/sh
#
# system-check - ask which machine you are looking at, then run the right one.
#
# There are two collectors in this folder because there are two kinds of
# machine, and the honest way to read a Windows box is to ask Windows:
#
#   plain-check.c        Linux, written in C, no dependencies
#   windows-check.ps1    Windows, written in PowerShell, nothing to install
#
# Both print the same report in the same order, so you can put two machines
# side by side and read them the same way.
#
# This just asks which one you want and gets out of the way. If you already
# know, skip it:
#
#     ./plain-check                                          on Linux
#     powershell -ExecutionPolicy Bypass -File windows-check.ps1   on Windows
#
# Everything here only reads. Nothing is changed on any machine.
#
# DhWonder, Plaintext IT - MIT license.

set -e

HERE=$(cd "$(dirname "$0")" && pwd)
CHOICE=""

# Work out what we are running on, so the obvious answer is the default and
# somebody who just presses enter gets the right thing.
GUESS="linux"
case "$(uname -s 2>/dev/null || echo unknown)" in
    Linux*)                      GUESS="linux" ;;
    MINGW*|MSYS*|CYGWIN*)        GUESS="windows" ;;
    Darwin*)                     GUESS="mac" ;;
esac

# An answer can come from the command line, for cron and for scripts, which
# should never sit waiting at a prompt nobody is there to answer.
if [ $# -gt 0 ]; then
    case "$1" in
        linux|--linux|1)     CHOICE="linux" ;;
        windows|--windows|2) CHOICE="windows" ;;
        -h|--help|help)
            sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *)
            echo "I do not know '$1'. Say 'linux' or 'windows', or pass nothing to be asked."
            exit 2 ;;
    esac
fi

if [ -z "$CHOICE" ]; then
    echo
    echo "  Which machine are you looking at?"
    echo
    echo "    1) this Linux machine"
    echo "    2) a Windows machine"
    echo
    if [ "$GUESS" = "mac" ]; then
        echo "  (this looks like a Mac. Neither collector covers macOS yet, so"
        echo "   both choices below will tell you what to run elsewhere.)"
        echo
    fi
    printf "  Choose [1 or 2, default %s]: " "$([ "$GUESS" = "windows" ] && echo 2 || echo 1)"
    read -r ANSWER || ANSWER=""
    case "$ANSWER" in
        2|windows|w|W) CHOICE="windows" ;;
        1|linux|l|L)   CHOICE="linux" ;;
        "")            CHOICE="$GUESS" ;;
        *)
            echo "  I did not understand '$ANSWER'. Nothing was run."
            exit 2 ;;
    esac
    echo
fi

# ---------------------------------------------------------------------------
if [ "$CHOICE" = "linux" ]; then
    if [ "$GUESS" != "linux" ]; then
        echo "  This is not a Linux machine, so plain-check cannot run here."
        echo "  Copy this folder onto the Linux machine and run:"
        echo
        echo "      make && ./plain-check"
        echo
        exit 1
    fi

    if [ ! -x "$HERE/plain-check" ]; then
        echo "  Building plain-check first."
        if ! ( cd "$HERE" && make >/dev/null ); then
            echo "  The build failed. You need a C compiler: on Debian or Ubuntu"
            echo "  that is 'sudo apt install build-essential'."
            exit 1
        fi
        echo
    fi

    if [ "$(id -u)" != "0" ]; then
        echo "  Not running as root, so the password check and the serial number"
        echo "  will say they were skipped. Run with sudo to include them."
        echo
    fi

    exec "$HERE/plain-check"
fi

# ---------------------------------------------------------------------------
if [ "$CHOICE" = "windows" ]; then
    # A Windows machine is almost never the one you are sitting at when you
    # run a shell script, so the useful thing here is usually the command to
    # take with you rather than an attempt to run it.
    if command -v pwsh >/dev/null 2>&1 && [ "$GUESS" != "windows" ]; then
        echo "  PowerShell is installed here, but this is not Windows, so the"
        echo "  report would be a page of 'could not tell'. Run this on the"
        echo "  Windows machine itself:"
    elif [ "$GUESS" = "windows" ]; then
        echo "  Run this in PowerShell:"
    else
        echo "  Run this on the Windows machine, in PowerShell:"
    fi
    echo
    echo "      powershell -ExecutionPolicy Bypass -File windows-check.ps1"
    echo
    echo "  Copy windows-check.ps1 across on a memory stick or paste it into"
    echo "  a file there. It needs nothing installed. Run PowerShell as"
    echo "  Administrator to include the account, firewall and BitLocker checks."
    echo
    exit 0
fi
