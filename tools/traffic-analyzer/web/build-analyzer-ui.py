#!/usr/bin/env python3
"""
Glue the browser tool back together into one file.

traffic-analyzer.html has to be a single self contained page: it gets opened
straight from disk, emailed, and served from a machine with no internet, so
it cannot go asking for separate script files. But a 580KB file with a 440KB
base64 line in the middle is not something anybody can edit.

So the page is kept as five readable pieces in src/, and this puts them
together. Edit the pieces, run this, commit both.

    python3 web/build-analyzer-ui.py

  src/traffic-analyzer-shell.html    the page itself, markup and styles
  src/traffic-analyzer-worker.js     the parser and the analysis, runs on its own thread
  src/traffic-analyzer-ui.js         drawing and wiring, runs on the page thread
  src/traffic-analyzer-data.js       the world map dots
  src/traffic-analyzer-examples.js   the example captures, gzipped and base64

The built page is committed alongside the sources on purpose. This is a tool
somebody clones and runs, and a tool that needs a build step before it will show
you anything is a tool that looks broken the first time you try it.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "src")
OUT = os.path.join(HERE, "traffic-analyzer.html")


def read(name):
    path = os.path.join(SRC, name)
    if not os.path.exists(path):
        print("Missing source file: %s" % path)
        sys.exit(1)
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def main():
    shell = read("traffic-analyzer-shell.html")
    worker = read("traffic-analyzer-worker.js")
    ui = read("traffic-analyzer-ui.js")
    data = read("traffic-analyzer-data.js")
    examples = read("traffic-analyzer-examples.js")

    # A closing script tag inside the worker source would end the block early
    # and break the page in a way that is miserable to debug. Catch it here.
    for name, blob in (("worker", worker), ("ui", ui), ("data", data), ("examples", examples)):
        if "</script" in blob.lower():
            print("The %s source contains a closing script tag, which would break "
                  "the built page. Split the string." % name)
            sys.exit(1)

    if "<!--SCRIPTS-->" not in shell:
        print("The shell has no <!--SCRIPTS--> marker to put the code into.")
        sys.exit(1)

    block = "\n".join([
        "<!-- The analysis engine. Parked in a script block the browser does not run,",
        "     then handed to a Web Worker so a big capture is read on its own thread",
        "     and the page stays usable while it happens. -->",
        '<script type="text/js-worker" id="workerSrc">',
        worker,
        "</script>",
        "",
        "<script>",
        data,
        examples,
        "",
        'const WORKER_SOURCE = document.getElementById("workerSrc").textContent;',
        "",
        ui,
        "</script>",
    ])

    page = shell.replace("<!--SCRIPTS-->", block)
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(page)

    print("Built %s" % OUT)
    print("  %s bytes from %d source files" % ("{:,}".format(len(page)), 5))

    problems = check(page, ui)
    if problems:
        print()
        print("  Built, but something looks wrong:")
        for line in problems:
            print("    " + line)
        return 1
    return 0


# Elements the code creates itself at run time, so they are not in the markup.
MADE_AT_RUNTIME = {"clearFilter", "pSpark"}


def check(page, ui):
    """Catch the two mistakes that break this page silently.

    Both have bitten me. An id the code reaches for that is not in the markup
    gives you a null and a dead page. A class in the markup with no rule behind
    it gives you an element that is supposed to be hidden sitting there in plain
    view. Neither shows up as an error anywhere, so they get checked here.
    """
    import re
    problems = []

    ids = set(re.findall(r'id="([^"]+)"', page))
    wanted = set(re.findall(r'el\("([^"]+)"\)', ui))
    wanted |= set(re.findall(r'getElementById\("([^"]+)"\)', ui))
    for name in sorted(wanted - ids - MADE_AT_RUNTIME):
        problems.append('the code looks for id "%s", which is not in the page' % name)

    styles = page[page.index("<style>"):page.index("</style>")]
    used = set()
    for group in re.findall(r'class="([^"]+)"', page):
        used.update(group.split())
    for name in sorted(used):
        if ("." + name) not in styles:
            problems.append('class "%s" is used but has no style rule' % name)

    return problems


if __name__ == "__main__":
    import sys
    sys.exit(main() or 0)
