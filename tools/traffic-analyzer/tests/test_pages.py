"""
Prove every browser page a tool looks for is actually there.

This test exists because the failure it catches has now happened twice, and both
times it looked the same from outside: you run the tool, open the address it
prints, and get a JSON error saying the page was not found. The tool is fine.
The code is fine. The page simply is not in the repository, or is not where the
code looks for it.

Nothing else catches this. The page is loaded at run time by path, so no import
fails, no test that exercises the API notices, and the tool starts up perfectly
happily and tells you about it only when somebody opens a browser.

So this walks the candidate lists in the server code, resolves them the same way
the server does, and fails if nothing is found. It also checks the page is a real
page rather than an empty file, because a zero byte html file would satisfy
"exists" and still be broken.

    python3 tests/test_pages.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)
TOOLS = os.path.dirname(TOOL)

sys.path.insert(0, TOOL)


def check(name, condition, detail=""):
    print("  %-58s %s" % (name, "ok" if condition else "FAILED"))
    if not condition and detail:
        print("      %s" % detail)
    return 0 if condition else 1


def looks_like_a_page(path):
    """A real page, not an empty file or a stub."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    lowered = head.lower()
    return "<html" in lowered and len(head) > 500


def main():
    failures = 0

    # ---- traffic-analyzer: the two pages its own server resolves ----------
    from trafficanalyzer import server

    found = server.find_ui()
    failures += check("traffic-analyzer finds its main page", bool(found),
                      "none of these exist: " + ", ".join(
                          os.path.abspath(p) for p in server.UI_CANDIDATES))
    if found:
        failures += check("the main page is a real page", looks_like_a_page(found), found)

    packets = server.find_packet_ui()
    failures += check("traffic-analyzer finds its packet browser", bool(packets),
                      "none of these exist: " + ", ".join(
                          os.path.abspath(p) for p in server.PACKET_UI_CANDIDATES))
    if packets:
        failures += check("the packet browser is a real page", looks_like_a_page(packets),
                          packets)

    # ---- the other tools in the suite, if they are sitting beside us ------
    # Each entry: folder, the module that resolves the page, how to call it.
    others = [
        ("email-checker", "emailchecker.server", "find_ui",
         "email-checker finds its page"),
        ("decoy-house", None, None, "decoy-house finds its console"),
    ]

    for folder, module_name, function_name, label in others:
        tool_path = os.path.join(TOOLS, folder)
        if not os.path.isdir(tool_path):
            print("  %-58s %s" % (label, "skipped, not next to this tool"))
            continue

        saved = list(sys.path)
        sys.path.insert(0, tool_path)
        try:
            if folder == "decoy-house":
                # Its resolver lives on the CLI rather than in the package.
                import importlib
                cli = importlib.import_module("decoy_house")
                importlib.reload(cli)
                page = cli.find_ui()
            else:
                import importlib
                module = importlib.import_module(module_name)
                importlib.reload(module)
                page = getattr(module, function_name)()
        except Exception as exc:
            page = None
            print("      could not ask %s: %s" % (folder, exc))
        finally:
            sys.path[:] = saved

        failures += check(label, bool(page))
        if page:
            failures += check("  and it is a real page", looks_like_a_page(page), page)

    # ---- the pages must be committed, not just present locally -----------
    # A page that exists only in a working copy is exactly how this broke: it
    # was there while it was being built and missing for everybody who cloned.
    import subprocess
    try:
        tracked = subprocess.check_output(
            ["git", "ls-files", "*.html"], cwd=TOOLS,
            stderr=subprocess.DEVNULL).decode("utf-8", "replace").split()
    except Exception:
        tracked = None

    if tracked is None:
        print("  %-58s %s" % ("pages are committed", "skipped, no git here"))
    else:
        names = [os.path.basename(p) for p in tracked]
        for wanted in ("traffic-analyzer.html", "traffic-analyzer-packets.html",
                       "email-checker.html", "console.html"):
            failures += check("%s is committed, not just on disk" % wanted,
                              wanted in names,
                              "git does not track any file called that")

    print()
    if failures:
        print("%d checks failed." % failures)
        return 1
    print("All browser pages are present.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
