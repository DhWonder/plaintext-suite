"""
traffic-analyzer: work out who is flooding you, and say so in plain English.

The pieces, in the order they run:

    capture.py   reading capture files and network cards
    analyse.py   scoring each source, grouping them, deciding what to recommend
    store.py     the SQLite history, so a run is not thrown away when it ends
    live.py      listening to a card, the rolling window, the alert log
    server.py    the local web server and the JSON API behind the browser view
    report.py    the terminal report and the HTML dashboard

traffic_analyzer.py in the folder above is the command line tool that ties them
together. Everything here is Python 3 and the standard library, on purpose:
the machines that need this most are often the ones you are not allowed to
install anything on.

Written by DhWonder for Plaintext IT. MIT licensed.
"""

__version__ = "2.0"
