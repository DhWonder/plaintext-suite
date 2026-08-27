# link-cleaner

Take the tracking off a link before you send it to somebody.

You copy a link to send to a colleague. What you actually copied, on most of
the web, is a link plus a short report on you: which email you clicked it from,
which campaign brought you there, an identifier tying this click to everything
else you have done on that site, and sometimes the exact sentence you had
highlighted when you hit copy. Then you paste it into a group chat and forty
people open it, and now the site knows they all came from you.

None of that is needed to open the page.

    $ plain-link "https://shop.example.com/kettle?utm_source=newsletter&utm_campaign=spring&fbclid=IwAR3x9&colour=black"
    https://shop.example.com/kettle?colour=black

And with the clipboard watcher running, that happens as you copy, with nothing
to remember.

## The one rule

**A cleaned link must open the same page as the dirty one.** A tool that
quietly breaks one link in fifty is worse than no tool, because you find out
weeks later when somebody mentions the link you sent was dead. Everything below
follows from that:

**Only names on a known list are removed.** Anything unrecognised survives.
This will always miss some tracking. It will not break your links, and given
the choice those are not close.

**Where a name means different things on different sites, the rule is tied to
the site.** `t` on x.com is a share token unique to your copy of the link. `t`
on youtube.com is where to start playing. A single global list has to pick one,
and picking wrong either leaks or breaks:

    https://www.youtube.com/watch?v=abc&si=xyz&t=42   ->  ...?v=abc&t=42
    https://x.com/who/status/1?s=20&t=xyz             ->  .../status/1

**Where a link is only a wrapper around another link, the answer is the link
inside.** The redirectors that mail and social apps wrap everything in exist to
record the click; cleaning the wrapper's parameters would leave the wrapper.

    https://www.google.com/url?q=https%3A%2F%2Fexample.com%2Fpage&sa=U&ved=2ah
    ->  https://example.com/page

## What it removes

`plain-link --list` prints the whole thing. In summary:

- **Campaign tagging** — every `utm_*`, plus Mailchimp's `mc_cid`/`mc_eid`,
  HubSpot's `_hsenc`/`__hstc`, Listrak, MailerLite, Vero and the rest. These
  say which newsletter you clicked and, often, which subscriber you are.
- **Ad click identifiers** — `fbclid`, `gclid`, `gbraid`, `wbraid`, `msclkid`,
  `ttclid`, `twclid`, `yclid`, `dclid`.
- **Share identifiers** — `igshid`, YouTube's and Spotify's `si`, Reddit's
  `share_id`. These say *who shared it*, which is the part people miss.
- **Affiliate tags** — Amazon's `tag`, eBay's `campid`, AliExpress's `aff_*`.
  Somebody earns from that click.
- **Redirect wrappers** — `l.facebook.com`, Google result links, Outlook
  safelinks, Slack redirects, Steam's link filter, and others. Unwrapped, then
  the link inside is cleaned too.
- **`#:~:text=`** — Chrome's text fragment. Harmless to the site, but it tells
  whoever you send it to exactly which sentence caught your eye. That is rarely
  what you meant to send.

## Running it

    make
    ./plain-link "https://..."             clean one link
    ./plain-link --explain "https://..."   say what came off and why
    ./plain-link --text "a sentence ..."   clean the links inside some text
    ./plain-link --list                    everything it knows how to remove
    echo "..." | ./plain-link              clean each line that arrives

`--explain` writes the link to standard output and the reasons to standard
error, so `plain-link --explain "$URL" | pbcopy` copies the link and not the
essay:

    $ ./plain-link --explain "https://e.com/a?utm_source=news&fbclid=1&id=2"
    https://e.com/a?id=2
    Removed 2 things:

      utm_source             campaign tagging - which advert or email sent you
      fbclid                 Facebook's click identifier, ties the visit to your account

    The link goes to the same page without them.

Exit code is `0` already clean, `1` something was removed, `2` not a link. The
clipboard watcher uses that rather than comparing strings.

## The clipboard watcher

    sh plain-link-watch.sh

Copy a link, and the tracking is off it by the time you paste. Stop it with
ctrl-C.

    sh plain-link-watch.sh --once     clean what is in there now, then stop
    sh plain-link-watch.sh --text     also clean links inside copied text
    sh plain-link-watch.sh --every 2  seconds between looks (default 1)
    sh plain-link-watch.sh --quiet    do it without saying anything

It finds `wl-copy`, `xclip`, `xsel` or `pbcopy`, whichever this machine has,
and says what to install if it has none.

### About it reading your clipboard

This is the only tool in the suite that does, and your clipboard holds
passwords. Whatever you last copied out of a password manager, a client's bank
details, half a private message. So, in full:

- **It writes nothing to disk.** No log, no history, no cache. The only copies
  it makes live in shell variables and die with the process.
- **It prints nothing except links.** If what you copied is not a link, it has
  nothing to say and says nothing. There is a test for exactly this.
- **It sends nothing anywhere.** No network call in the script, and none in
  `plain-link` either.
- **It writes to the clipboard only when a link came in and something was
  actually removed.** Copy a clean link and the clipboard is untouched.

That is checkable rather than a promise: the script is about a hundred lines
and every clipboard read is on one of them.

## Why C and shell rather than one thing

The interesting part is string surgery, which is what C is for and which needs
nothing installed. Reaching the clipboard means X11 *and* Wayland *and* macOS -
three platform dependencies bolted onto a program whose actual job is picking
apart a query string.

So they are separate. `plain-link` compiles with one command anywhere and reads
text from wherever you point it. `plain-link-watch.sh` knows about clipboards
and nothing else. Either is useful without the other, and the half that touches
your clipboard is the half you can read in a minute.

## Testing it

    make check

Roughly half the checks are about things that must **survive**: a `t` that is a
timestamp, an `s` that is not on X, a fragment that is a heading rather than a
highlight, a plus sign that means a plus sign, a host that merely ends in the
same letters as one with a rule. Those are the tests worth having, because
missing a tracker is a disappointment and breaking a link is a real problem.

If the machine has a clipboard, the round trip is tested too - including that
copying a password neither changes it nor prints it. If it has no clipboard,
that is said out loud and skipped rather than passing quietly.

## Limitations, written down

- **It will miss things.** Deliberately. A tool that stripped every parameter
  it did not recognise would clean more and break links, and there is no
  version of that trade worth taking.
- **The list needs upkeep.** Trackers are renamed; new ones appear. This is a
  list in a C file, not a feed - which also means it does not phone anywhere to
  update itself, and never will.
- **It does not shorten links.** Nothing is fetched, so a `bit.ly` stays a
  `bit.ly`. Resolving one means asking the shortener, which is a click, which
  is the thing being avoided.
- **Only http and https.** A `mailto:` or a file path is not something this has
  any business editing.
- **It cannot know what a site needs.** If some site uses `utm_source` as a
  real parameter, this will break that link. No such site is known, but the
  risk is real and belongs written down rather than assumed away.

## License

MIT.
