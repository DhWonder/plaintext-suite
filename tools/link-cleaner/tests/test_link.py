"""
Prove plain-link takes the tracking off and nothing else.

There are two ways this tool can be wrong and they are not equally bad.

Missing a tracker is a disappointment: the link still works, it just still
carries something you would rather it did not. Removing something that was
not a tracker is a broken link, sent to somebody who will not tell you it
was broken until much later, if at all.

So the tests are weighted accordingly. Roughly half of them are about things
that must survive - a "t" that is a timestamp, an "s" that is not on X, a
fragment that is a heading rather than a highlight, a plus sign that means a
plus sign. Those are the ones worth having.

One warning about running this. The clipboard checks start xclip, and xclip
does not exit - on X, the process that set a selection is the one that serves
it, so it has to stay alive holding it. That is normal and it is how every
clipboard tool on X behaves. It does mean that if you capture this script's
output through a pipe, the pipe may not appear to close when the script ends,
because xclip is still holding its end. Redirect to a file if you need the
output. Run plainly in a terminal, or through `make check`, it is fine.

    python3 tests/test_link.py
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "plain-link")


def check(name, condition):
    print("  %-72s %s" % (name, "ok" if condition else "FAILED"))
    return 0 if condition else 1


def run(*args, **kwargs):
    """Returns (stdout, stderr, exit code)."""
    stdin = kwargs.get("stdin")
    proc = subprocess.Popen(
        [TOOL] + list(args),
        stdin=subprocess.PIPE if stdin is not None else None,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(
        stdin.encode() if stdin is not None else None)
    return out.decode().strip(), err.decode().strip(), proc.returncode


def cleaned(url):
    return run(url)[0]


def main():
    if not os.path.exists(TOOL):
        print("Build it first: make")
        return 1

    failures = 0

    # ------------------------------------------------------------------
    print("\nTaking the obvious things off")
    failures += check(
        "campaign tags go, and what the page needs stays",
        cleaned("https://shop.example.com/kettle?utm_source=news&"
                "utm_campaign=spring&fbclid=IwAR3&colour=black")
        == "https://shop.example.com/kettle?colour=black")
    failures += check(
        "anything starting utm_ goes, including ones not on the list",
        cleaned("https://e.com/a?utm_pubreferrer=x&utm_whatever=y&keep=1")
        == "https://e.com/a?keep=1")
    failures += check(
        "the whole query going leaves no dangling question mark",
        cleaned("https://e.com/page?utm_source=x&gclid=y")
        == "https://e.com/page")
    failures += check(
        "a link with nothing on it comes back untouched",
        cleaned("https://e.com/page?id=7&sort=name")
        == "https://e.com/page?id=7&sort=name")

    # ------------------------------------------------------------------
    # The half of the tests that matter more.
    # ------------------------------------------------------------------
    print("\nLeaving alone everything it is not sure about")
    failures += check(
        "an unrecognised parameter survives, whatever it looks like",
        cleaned("https://e.com/a?trackingthing=abc&sessionid=99")
        == "https://e.com/a?trackingthing=abc&sessionid=99")
    failures += check(
        "\"t\" on youtube is a timestamp and must survive",
        cleaned("https://www.youtube.com/watch?v=abc&si=xyz&t=42")
        == "https://www.youtube.com/watch?v=abc&t=42")
    failures += check(
        "\"t\" on x.com is a tracking token and must not",
        cleaned("https://x.com/who/status/1?s=20&t=xyz")
        == "https://x.com/who/status/1")
    failures += check(
        "\"t\" on a site with no rule survives",
        cleaned("https://example.com/a?t=42") == "https://example.com/a?t=42")
    failures += check(
        "\"s\" on a site with no rule survives",
        cleaned("https://example.com/a?s=20") == "https://example.com/a?s=20")
    failures += check(
        "\"si\" on a site with no rule survives",
        cleaned("https://example.com/a?si=x") == "https://example.com/a?si=x")
    failures += check(
        "a host that merely ends in the same letters is not matched",
        cleaned("https://notx.com/a?t=42") == "https://notx.com/a?t=42")
    failures += check(
        "but a subdomain of a matched host is",
        cleaned("https://mobile.x.com/a?t=42") == "https://mobile.x.com/a")
    failures += check(
        "the host match ignores capitals, because hostnames do",
        cleaned("https://X.COM/a?t=42") == "https://X.COM/a")

    # ------------------------------------------------------------------
    print("\nUnwrapping links that are only wrappers")
    failures += check(
        "a Google result link becomes the link it points at",
        cleaned("https://www.google.com/url?q=https%3A%2F%2Fexample.com"
                "%2Fpage&sa=U&ved=2ahUKEwi") == "https://example.com/page")
    failures += check(
        "the link inside gets cleaned too",
        cleaned("https://l.facebook.com/l.php?u=https%3A%2F%2Fnews.example"
                ".com%2Fs%3Futm_medium%3Dsocial%26id%3D7&h=AT1")
        == "https://news.example.com/s?id=7")
    failures += check(
        "an Outlook safelink becomes the real link",
        cleaned("https://eu01.safelinks.protection.outlook.com/?url=https%3A"
                "%2F%2Fexample.com%2Fdoc&data=05%7C01")
        == "https://example.com/doc")
    failures += check(
        "a wrapper whose parameter is not a link is left alone",
        cleaned("https://www.google.com/url?q=notalink&sa=U")
        == "https://www.google.com/url?q=notalink")
    # Refused for the right reason: exit 2 also covers "that is not a link",
    # so the code alone would pass this test even if the hop limit were
    # broken. The message is what proves which refusal happened.
    _out, _err, _code = run("https://www.google.com/url?q=" +
                            "https%3A%2F%2Fwww.google.com%2Furl%3Fq%3D" * 8 +
                            "https%253A%252F%252Fe.com")
    failures += check(
        "a wrapper nested past what a real link does is refused, not half done",
        _code == 2 and "wraps another link more than" in _err)

    # ------------------------------------------------------------------
    print("\nThe part of the address after the hash")
    failures += check(
        "a highlighted-sentence fragment is removed",
        cleaned("https://en.wikipedia.org/wiki/Kettle#:~:text=A%20kettle")
        == "https://en.wikipedia.org/wiki/Kettle")
    failures += check(
        "an ordinary fragment is not - it is where the page opens",
        cleaned("https://docs.example.com/guide#installation")
        == "https://docs.example.com/guide#installation")
    failures += check(
        "a fragment is kept when the highlight is only part of it",
        cleaned("https://e.com/g#section:~:text=hello")
        == "https://e.com/g#section")
    failures += check(
        "a question mark inside a fragment is not mistaken for a query",
        cleaned("https://e.com/app#/route?utm_source=x")
        == "https://e.com/app#/route?utm_source=x")
    failures += check(
        "the query is cleaned and the fragment kept, together",
        cleaned("https://e.com/g?utm_source=x&id=2#part3")
        == "https://e.com/g?id=2#part3")

    # ------------------------------------------------------------------
    print("\nThings that are not links")
    for text, why in [
            ("not a link at all", "plain words"),
            ("mailto:someone@example.com", "an email address"),
            ("ftp://files.example.com/x", "a protocol it does not handle"),
            ("https://localhost/a", "a host with no dot in it"),
            ("/just/a/path", "a path")]:
        failures += check("refuses %s, and says so" % why, run(text)[2] == 2)

    failures += check(
        "a plus sign stays a plus sign rather than becoming a space",
        cleaned("https://e.com/s?q=a+b&utm_source=x") == "https://e.com/s?q=a+b")

    # ------------------------------------------------------------------
    print("\nLinks inside ordinary text")
    out = run("--text", "look at https://e.com/a?utm_source=x and tell me")[0]
    failures += check("the link is cleaned where it sits",
                      out == "look at https://e.com/a and tell me")

    out = run("--text", "see https://e.com/page?gclid=1.")[0]
    failures += check("a full stop after a link is the sentence's, not the link's",
                      out == "see https://e.com/page.")

    out = run("--text", "(https://e.com/a?fbclid=2)")[0]
    failures += check("a link in brackets keeps the brackets outside it",
                      out == "(https://e.com/a)")

    out = run("--text", "https://e.com/wiki/Foo_(bar)?utm_source=x")[0]
    failures += check("a bracket that belongs to the link stays in it",
                      out == "https://e.com/wiki/Foo_(bar)")

    out = run("--text", "two: https://a.com/x?utm_source=1 https://b.com/y?gclid=2")[0]
    failures += check("more than one link in a line is handled",
                      out == "two: https://a.com/x https://b.com/y")

    out = run("--text", "nothing to do here")[0]
    failures += check("text with no link comes back exactly as it went in",
                      out == "nothing to do here")

    # ------------------------------------------------------------------
    print("\nReading from a pipe, which is how the clipboard watcher uses it")
    out, _, code = run(stdin="https://e.com/a?utm_source=x\n")
    failures += check("a link on stdin is cleaned", out == "https://e.com/a")
    failures += check("and the exit code says something was removed", code == 1)

    out, _, code = run(stdin="https://e.com/a?keep=1\n")
    failures += check("an already clean link exits 0, so nothing gets rewritten",
                      code == 0)

    out, _, _ = run(stdin="not a link\n")
    failures += check("a line that is not a link is passed through untouched",
                      out == "not a link")

    out, _, _ = run(stdin="https://a.com/1?gclid=x\nplain text\nhttps://b.com/2\n")
    failures += check("several lines each get their own answer",
                      out.splitlines() ==
                      ["https://a.com/1", "plain text", "https://b.com/2"])

    # ------------------------------------------------------------------
    print("\nSaying what it did")
    out, err, _ = run("--explain",
                      "https://e.com/a?utm_source=news&fbclid=1&id=2")
    failures += check("the link goes to stdout on its own",
                      out == "https://e.com/a?id=2")
    failures += check("and the reasons go to stderr, so a pipe copies the link",
                      "utm_source" in err and "fbclid" in err)
    failures += check("each removal says why in words, not jargon",
                      "which advert or email sent you" in err)

    _, err, _ = run("--explain", "https://e.com/a?id=2")
    failures += check("a clean link is told it was already clean",
                      "already clean" in err)

    out, _, code = run("--list")
    failures += check("--list shows both lists and explains why there are two",
                      "Removed from any site" in out
                      and "Removed only on the site named" in out
                      and "would have to pick one" in out)
    failures += check("--list is honest that it will miss things",
                      "will always miss some tracking" in out)
    failures += check("an option it does not understand is refused",
                      run("--nonsense")[2] == 3)

    # ------------------------------------------------------------------
    # The clipboard half, if this machine has a clipboard to test against.
    #
    # Most machines running this test will not - a build server has no
    # desktop. Skipping is said out loud rather than passing quietly,
    # because "0 failures" on a suite that silently skipped its riskiest
    # part is the kind of green tick that hides things.
    # ------------------------------------------------------------------
    print("\nThe clipboard, if there is one")
    watcher = os.path.join(os.path.dirname(HERE), "plain-link-watch.sh")
    have_clip = (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")) \
        and any(os.access(os.path.join(d, "xclip"), os.X_OK)
                for d in os.environ.get("PATH", "").split(os.pathsep))

    rc = subprocess.call(["sh", "-n", watcher])
    failures += check("plain-link-watch.sh parses as a shell script", rc == 0)

    skip_reason = "no clipboard on this machine"

    # Having DISPLAY set and xclip installed is not the same as having a
    # working clipboard - the display can point at a server that is not
    # there, which is what a stale DISPLAY left in a shell profile looks
    # like. Exit codes do not separate the cases cleanly enough to trust
    # (xclip returns 1 both for "no display" and for an empty clipboard),
    # so the probe is the only thing that settles it: write a sentinel,
    # read it back, see if it survived. Skipping loudly beats four
    # failures that blame the tool for the environment.
    if have_clip:
        probe_file = os.path.join(HERE, ".probe")
        probe_sh = os.path.join(HERE, ".probe.sh")
        handle = open(probe_sh, "w")
        handle.write("#!/bin/sh\n"
                     'printf clipboard-alive | xclip -selection clipboard -in '
                     ">/dev/null 2>&1\n"
                     'xclip -selection clipboard -o </dev/null >"$1" 2>/dev/null\n')
        handle.close()
        subprocess.call(["sh", probe_sh, probe_file],
                        stdin=open(os.devnull),
                        stdout=open(os.devnull, "wb"),
                        stderr=subprocess.STDOUT)
        alive = (os.path.exists(probe_file) and
                 open(probe_file, "rb").read() == b"clipboard-alive")
        for leftover in (probe_file, probe_sh):
            if os.path.exists(leftover):
                os.remove(leftover)
        if not alive:
            skip_reason = "a clipboard was expected here but nothing answered"
            have_clip = False

    if not have_clip:
        print("  %-72s %s" % (skip_reason + " - round trip not run", "skipped"))
    else:
        # Every clipboard command writes to a file, never to a pipe. On X,
        # a selection is served by the process that set it, so xclip stays
        # alive in the background holding whatever descriptors it
        # inherited - and a pipe it holds is a pipe nothing ever sees the
        # end of. Reading its output through subprocess.check_output
        # deadlocks for exactly that reason.
        #
        # Note what is deliberately NOT redirected: xclip's standard input
        # on the line that sets the clipboard. That has to stay the pipe,
        # because the pipe is where the text comes from. Writing the
        # obvious "</dev/null" there - which this file did at first -
        # stores an empty clipboard instead, and then every check below
        # passes or fails for reasons that have nothing to do with the
        # tool being tested.
        script = os.path.join(HERE, ".clip.sh")
        result = os.path.join(HERE, ".clip.out")
        handle = open(script, "w")
        handle.write(
            "#!/bin/sh\n"
            "# $1 the text to copy, $2 the watcher, $3 an extra flag,\n"
            "# $4 where to write what came back out.\n"
            'printf "%s" "$1" | xclip -selection clipboard -in >/dev/null 2>&1\n'
            'sh "$2" --once $3 </dev/null >"$4.said" 2>&1\n'
            'xclip -selection clipboard -o </dev/null >"$4" 2>/dev/null\n')
        handle.close()

        def round_trip(text, extra="--quiet"):
            subprocess.call(["sh", script, text, watcher, extra, result],
                            stdin=open(os.devnull),
                            stdout=open(os.devnull, "wb"),
                            stderr=subprocess.STDOUT)
            after = open(result, "rb").read().decode()
            said = open(result + ".said", "rb").read().decode()
            return after, said

        # Before anything else, prove the harness works. A string that is
        # not a link has to come back exactly as it went in. If this fails,
        # the clipboard is not being set at all and nothing after it means
        # anything - which is a state this file has already been in once.
        probe, _ = round_trip("clipboard-harness-probe")
        failures += check("the clipboard round trip itself works",
                          probe == "clipboard-harness-probe")

        after, _ = round_trip(
            "https://shop.example.com/x?utm_source=news&colour=black")
        failures += check("a dirty link copied is a clean link pasted",
                          after == "https://shop.example.com/x?colour=black")

        after, _ = round_trip("https://example.com/plain")
        failures += check("a clean link is left exactly as it was",
                          after == "https://example.com/plain")

        # The one that matters most. This tool reads everything you copy.
        secret = "correct-horse-battery-staple"
        after, said = round_trip(secret, "")
        failures += check("something that is not a link is not touched",
                          after == secret)
        failures += check("and is never printed, because it might be a password",
                          secret not in said)

        for leftover in (script, result, result + ".said"):
            if os.path.exists(leftover):
                os.remove(leftover)

    print()
    if failures:
        print("%d checks failed." % failures)
        return 1
    print("All link checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
