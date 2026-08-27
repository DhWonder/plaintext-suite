/*
 * plain-link - take the tracking off a link before you send it to somebody.
 *
 * You copy a link to send to a colleague. What you actually copied, on most
 * of the web, is a link plus a short report on you: which email you clicked
 * it from, which campaign brought you there, an identifier that ties this
 * click to every other thing you have done on that site, and sometimes the
 * exact sentence you had highlighted when you hit copy. Then you paste it
 * into a group chat and forty people load it, and now the site knows they
 * all came from you.
 *
 * None of that is needed to open the page. Strip it and the link goes to
 * exactly the same place.
 *
 *   in:  https://shop.example.com/kettle?utm_source=newsletter&utm_campaign=
 *        spring&fbclid=IwAR3x9&colour=black
 *   out: https://shop.example.com/kettle?colour=black
 *
 * The one rule this tool cannot break is that the cleaned link must open the
 * same page as the dirty one. A shortener that quietly breaks one link in
 * fifty is worse than useless, because you will not find out until somebody
 * tells you the link you sent them was dead. So:
 *
 *   * Only parameters on a known list are removed. Anything unrecognised is
 *     left alone. This tool will always miss some tracking; it will not
 *     break your links.
 *
 *   * Where a name means different things on different sites, the rule is
 *     tied to the site. "t" on x.com is a tracking token. "t" on youtube.com
 *     is where to start playing. Removing the wrong one either leaks or
 *     breaks, and a single global list would have to pick one.
 *
 *   * Where a link is nothing but a wrapper around another link - the
 *     redirectors mail and social apps wrap everything in - the answer is
 *     the link inside, not the wrapper with its parameters tidied.
 *
 * It reads text and writes text. No network, no files, nothing stored. The
 * clipboard half lives in plain-link-watch.sh next door, because talking to
 * a clipboard means talking to X11 or Wayland or macOS, and that is three
 * platform dependencies to bolt onto a program whose actual job is string
 * surgery. The shell handles the clipboard, this handles the link, and
 * either one can be used without the other.
 *
 * Build:  make    (or: cc -ansi -pedantic -Wall -Wextra -o plain-link plain-link.c)
 *
 * Run:    ./plain-link "https://..."     clean one link, print it
 *         echo "..." | ./plain-link      clean whatever comes in, line by line
 *         ./plain-link --explain "..."   say what was taken off and why
 *         ./plain-link --text "..."      find and clean links inside a sentence
 *         ./plain-link --list            everything it knows how to remove
 *
 * Exit code: 0 the link was already clean, 1 something was removed,
 *            2 that was not a link.
 *
 * DhWonder, Plaintext IT - MIT license.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_URL   8192
#define MAX_PARAM 1024
#define MAX_NOTES 64

/* Every removal, kept so --explain can say what happened and why. */
struct note {
    char name[128];
    const char *why;
};
static struct note notes[MAX_NOTES];
static int n_notes = 0;

static void noted(const char *name, const char *why)
{
    if (n_notes >= MAX_NOTES)
        return;
    sprintf(notes[n_notes].name, "%.120s", name);
    notes[n_notes].why = why;
    n_notes++;
}

/* ================================================================
 * What gets removed, and why.
 *
 * Two lists. The first applies everywhere, because these names mean the
 * same thing on every site that uses them and none of them is ever load
 * bearing. The second is tied to a host, because the same short name is a
 * tracker on one site and part of the address on another - and guessing
 * wrong in that direction breaks the link, which is the one thing this is
 * not allowed to do.
 * ================================================================ */

struct tracker {
    const char *name;
    const char *why;
};

/* Anywhere. A trailing '*' means "and anything starting with this". */
static const struct tracker GLOBAL[] = {
    { "utm_*",          "campaign tagging - which advert or email sent you" },
    { "fbclid",         "Facebook's click identifier, ties the visit to your account" },
    { "fb_action_ids",  "Facebook click tracking" },
    { "fb_action_types","Facebook click tracking" },
    { "fb_source",      "Facebook click tracking" },
    { "fb_ref",         "Facebook click tracking" },
    { "gclid",          "Google Ads click identifier" },
    { "gclsrc",         "Google Ads click source" },
    { "dclid",          "Google display advert identifier" },
    { "gbraid",         "Google Ads identifier used across apps" },
    { "wbraid",         "Google Ads identifier used across the web" },
    { "gad_source",     "Google Ads source tagging" },
    { "srsltid",        "Google Shopping result identifier" },
    { "msclkid",        "Microsoft Ads click identifier" },
    { "twclid",         "X/Twitter click identifier" },
    { "ttclid",         "TikTok click identifier" },
    { "igshid",         "Instagram share identifier - says who shared it" },
    { "igsh",           "Instagram share identifier - says who shared it" },
    { "yclid",          "Yandex click identifier" },
    { "_openstat",      "Russian advert click tracking" },
    { "mc_cid",         "Mailchimp campaign - which newsletter you clicked" },
    { "mc_eid",         "Mailchimp subscriber - identifies you personally" },
    { "_hsenc",         "HubSpot email tracking token" },
    { "_hsmi",          "HubSpot email identifier" },
    { "__hssc",         "HubSpot session cookie in the address" },
    { "__hstc",         "HubSpot visitor cookie in the address" },
    { "hsCtaTracking",  "HubSpot call-to-action tracking" },
    { "vero_conv",      "Vero email conversion tracking" },
    { "vero_id",        "Vero subscriber identifier" },
    { "oly_anon_id",    "Omeda anonymous visitor identifier" },
    { "oly_enc_id",     "Omeda known visitor identifier" },
    { "wickedid",       "WickedReports click identifier" },
    { "cmpid",          "campaign identifier" },
    { "trk_contact",    "Listrak contact identifier" },
    { "trk_msg",        "Listrak message identifier" },
    { "trk_module",     "Listrak module tracking" },
    { "trk_sid",        "Listrak session identifier" },
    { "ml_subscriber",  "MailerLite subscriber identifier" },
    { "ml_subscriber_hash", "MailerLite subscriber hash" }
};

/* Only on the hosts named. The host match is a suffix, so "x.com" also
 * covers "mobile.x.com", and never matches "notx.com" because the
 * character before the match has to be a dot or the start. */
struct host_tracker {
    const char *host;
    const char *name;
    const char *why;
};

static const struct host_tracker BY_HOST[] = {
    { "x.com",        "s",  "X/Twitter share source - which app you shared from" },
    { "x.com",        "t",  "X/Twitter share token, unique to your copy of the link" },
    { "twitter.com",  "s",  "Twitter share source" },
    { "twitter.com",  "t",  "Twitter share token, unique to your copy of the link" },
    { "twitter.com",  "ref_src", "Twitter referrer tagging" },
    { "twitter.com",  "ref_url", "Twitter referrer tagging" },
    { "x.com",        "ref_src", "X referrer tagging" },
    { "x.com",        "ref_url", "X referrer tagging" },

    { "youtube.com",  "si", "YouTube share identifier - says who shared it" },
    { "youtu.be",     "si", "YouTube share identifier - says who shared it" },
    { "youtube.com",  "pp", "YouTube share parameters" },
    { "youtu.be",     "pp", "YouTube share parameters" },
    { "youtube.com",  "feature", "how you arrived at the video" },

    { "open.spotify.com", "si", "Spotify share identifier - says who shared it" },
    { "spotify.com",  "si", "Spotify share identifier - says who shared it" },

    { "amazon.com",   "psc", "Amazon listing tracking" },
    { "amazon.com",   "tag", "Amazon affiliate tag - somebody earns from this click" },
    { "amazon.com",   "linkCode", "Amazon affiliate link type" },
    { "amazon.com",   "ascsubtag", "Amazon affiliate sub-tag" },
    { "amazon.com",   "ref_", "Amazon internal referrer" },
    { "amazon.com",   "pd_rd_*", "Amazon page placement tracking" },
    { "amazon.com",   "pf_rd_*", "Amazon page placement tracking" },
    { "amazon.com",   "_encoding", "Amazon request tagging" },
    { "amazon.co.uk", "psc", "Amazon listing tracking" },
    { "amazon.co.uk", "tag", "Amazon affiliate tag" },
    { "amazon.co.uk", "pd_rd_*", "Amazon page placement tracking" },
    { "amazon.co.uk", "pf_rd_*", "Amazon page placement tracking" },
    { "amazon.co.uk", "ref_", "Amazon internal referrer" },
    { "amazon.de",    "psc", "Amazon listing tracking" },
    { "amazon.de",    "tag", "Amazon affiliate tag" },
    { "amazon.de",    "pd_rd_*", "Amazon page placement tracking" },
    { "amazon.de",    "pf_rd_*", "Amazon page placement tracking" },
    { "amazon.de",    "ref_", "Amazon internal referrer" },

    { "linkedin.com", "trackingId", "LinkedIn tracking identifier" },
    { "linkedin.com", "refId", "LinkedIn referrer identifier" },
    { "linkedin.com", "lipi", "LinkedIn page instance - ties the click to your session" },
    { "linkedin.com", "licu", "LinkedIn control urn" },
    { "linkedin.com", "midToken", "LinkedIn email token - identifies you" },
    { "linkedin.com", "midSig", "LinkedIn email signature" },
    { "linkedin.com", "trkEmail", "LinkedIn email tracking" },
    { "linkedin.com", "eBP", "LinkedIn billing tracking" },
    { "linkedin.com", "originalSubdomain", "LinkedIn origin tagging" },

    { "reddit.com",   "share_id", "Reddit share identifier - says who shared it" },
    { "reddit.com",   "correlation_id", "Reddit session correlation" },
    { "reddit.com",   "ref_source", "Reddit referrer tagging" },
    { "reddit.com",   "ref_campaign", "Reddit campaign tagging" },
    { "reddit.com",   "rdt", "Reddit click tracking" },

    { "ebay.com",     "_trkparms", "eBay tracking parameters" },
    { "ebay.com",     "mkcid", "eBay marketing channel" },
    { "ebay.com",     "mkrid", "eBay marketing rotation" },
    { "ebay.com",     "campid", "eBay affiliate campaign" },
    { "ebay.com",     "toolid", "eBay affiliate tool" },
    { "ebay.com",     "customid", "eBay affiliate custom identifier" },
    { "ebay.co.uk",   "_trkparms", "eBay tracking parameters" },
    { "ebay.co.uk",   "campid", "eBay affiliate campaign" },

    { "aliexpress.com", "spm", "AliExpress page placement tracking" },
    { "aliexpress.com", "scm", "AliExpress recommendation tracking" },
    { "aliexpress.com", "aff_*", "AliExpress affiliate tagging" },

    { "bilibili.com", "spm_id_from", "Bilibili page placement tracking" },
    { "bilibili.com", "vd_source", "Bilibili visitor source" },

    { "instagram.com", "img_index", "Instagram share position" },

    { "tiktok.com",   "is_from_webapp", "TikTok referrer tagging" },
    { "tiktok.com",   "sender_device", "TikTok device tagging" },
    { "tiktok.com",   "web_id", "TikTok visitor identifier" },

    { "google.com",   "ved", "Google result position tracking" },
    { "google.com",   "ei",  "Google search session identifier" },
    { "google.com",   "sa",  "Google click type" },
    { "google.com",   "source", "Google referrer tagging" },

    { "medium.com",   "source", "Medium referrer tagging" },
    { "stackoverflow.com", "r", "Stack Overflow referrer tagging" },
    { "substack.com", "r", "Substack referrer identifier" },
    { "substack.com", "showWelcome", "Substack signup prompt" }
};

/* Links that are only a wrapper around another link. The parameter named
 * holds the real address; everything else on the wrapper is tracking by
 * definition, because the wrapper exists to record the click. */
struct redirector {
    const char *host;
    const char *param;
};

static const struct redirector REDIRECTORS[] = {
    { "l.facebook.com",     "u" },
    { "lm.facebook.com",    "u" },
    { "l.messenger.com",    "u" },
    { "l.instagram.com",    "u" },
    { "away.vk.com",        "to" },
    { "out.reddit.com",     "url" },
    { "t.umblr.com",        "z" },
    { "steamcommunity.com", "url" },
    { "href.li",            "" },
    { "www.google.com",     "q" },
    { "google.com",         "q" },
    { "news.url.google.com","url" },
    { "linkedin.com",       "url" },
    { "slack-redir.net",    "url" },
    { "safelinks.protection.outlook.com", "url" },
    { "vk.com",             "to" }
};

#define N_GLOBAL      ((int)(sizeof(GLOBAL) / sizeof(GLOBAL[0])))
#define N_BY_HOST     ((int)(sizeof(BY_HOST) / sizeof(BY_HOST[0])))
#define N_REDIRECTORS ((int)(sizeof(REDIRECTORS) / sizeof(REDIRECTORS[0])))

/* ================================================================
 * Taking a link apart.
 *
 * Deliberately not a full URL parser. It needs four things - the scheme,
 * the host, the query, and the fragment - and each of them is found by
 * looking for one character. A real parser would handle userinfo, ports,
 * IPv6 literals in brackets and a dozen other things that make no
 * difference to whether utm_source is present.
 * ================================================================ */

struct url {
    char before[MAX_URL];   /* scheme, host and path, untouched */
    char host[512];
    char query[MAX_URL];
    char fragment[MAX_URL];
    int  has_query;
    int  has_fragment;
};

static int split(const char *text, struct url *u)
{
    const char *scheme, *host_start, *host_end, *q, *hash;
    size_t len;

    memset(u, 0, sizeof *u);
    if (strlen(text) >= MAX_URL)
        return 0;

    /* Only http and https. A mailto: or a file path is not something this
     * tool has any business editing. */
    if (strncmp(text, "http://", 7) == 0)
        scheme = text + 7;
    else if (strncmp(text, "https://", 8) == 0)
        scheme = text + 8;
    else
        return 0;

    host_start = scheme;
    host_end = host_start;
    while (*host_end != '\0' && *host_end != '/' && *host_end != '?' &&
           *host_end != '#')
        host_end++;
    if (host_end == host_start)
        return 0;

    len = (size_t)(host_end - host_start);
    if (len >= sizeof u->host)
        return 0;
    memcpy(u->host, host_start, len);
    u->host[len] = '\0';

    /* A host with no dot in it is not a host anybody is sending links to. */
    if (strchr(u->host, '.') == NULL)
        return 0;

    hash = strchr(text, '#');
    q = strchr(text, '?');
    if (hash != NULL && q != NULL && q > hash)
        q = NULL;   /* the "?" was inside the fragment, so there is no query */

    if (q != NULL) {
        len = (size_t)(q - text);
        memcpy(u->before, text, len);
        u->before[len] = '\0';
        u->has_query = 1;
        if (hash != NULL) {
            len = (size_t)(hash - q - 1);
            memcpy(u->query, q + 1, len);
            u->query[len] = '\0';
        } else {
            sprintf(u->query, "%.8000s", q + 1);
        }
    } else if (hash != NULL) {
        len = (size_t)(hash - text);
        memcpy(u->before, text, len);
        u->before[len] = '\0';
    } else {
        sprintf(u->before, "%.8000s", text);
    }

    if (hash != NULL) {
        u->has_fragment = 1;
        sprintf(u->fragment, "%.8000s", hash + 1);
    }
    return 1;
}

/* Does this host end in that one, on a dot boundary?
 * "x.com" matches "x.com" and "mobile.x.com" and never "notx.com". */
static int host_is(const char *host, const char *suffix)
{
    size_t h = strlen(host), s = strlen(suffix);

    if (s > h)
        return 0;
    /* Compare case-insensitively; hostnames are not case sensitive and
     * people paste them in whatever case the site used. */
    {
        size_t i;
        for (i = 0; i < s; i++)
            if (tolower((unsigned char)host[h - s + i]) !=
                tolower((unsigned char)suffix[i]))
                return 0;
    }
    if (h == s)
        return 1;
    return host[h - s - 1] == '.';
}

/* A name matches an entry, where an entry ending in '*' is a prefix. */
static int name_matches(const char *name, const char *entry)
{
    size_t len = strlen(entry);

    if (len > 0 && entry[len - 1] == '*')
        return strncmp(name, entry, len - 1) == 0;
    return strcmp(name, entry) == 0;
}

/* Should this parameter go? Returns the reason if so, NULL to keep it. */
static const char *tracker_reason(const char *host, const char *name)
{
    int i;

    for (i = 0; i < N_GLOBAL; i++)
        if (name_matches(name, GLOBAL[i].name))
            return GLOBAL[i].why;

    for (i = 0; i < N_BY_HOST; i++)
        if (host_is(host, BY_HOST[i].host) &&
            name_matches(name, BY_HOST[i].name))
            return BY_HOST[i].why;

    return NULL;
}

/* Turn %3A back into ':'. Needed because a wrapped link arrives encoded
 * as a parameter value, and the thing inside is the answer.
 *
 * '+' is left alone on purpose. In an HTML form '+' means a space, but in
 * a wrapped address it is far more often a literal plus that belongs to
 * the link, and turning those into spaces would break it. This tool is
 * allowed to miss tracking; it is not allowed to break links. */
static void percent_decode(const char *in, char *out, size_t max)
{
    size_t o = 0;

    while (*in != '\0' && o + 1 < max) {
        if (in[0] == '%' && isxdigit((unsigned char)in[1]) &&
            isxdigit((unsigned char)in[2])) {
            char pair[3];
            pair[0] = in[1];
            pair[1] = in[2];
            pair[2] = '\0';
            out[o++] = (char)strtol(pair, NULL, 16);
            in += 3;
        } else {
            out[o++] = *in++;
        }
    }
    out[o] = '\0';
}

/* Pull one parameter's value out of a query string. */
static int query_value(const char *query, const char *want, char *out, size_t max)
{
    const char *p = query;

    while (*p != '\0') {
        const char *amp = strchr(p, '&');
        const char *eq = strchr(p, '=');
        size_t pair_len = amp ? (size_t)(amp - p) : strlen(p);

        if (eq != NULL && (amp == NULL || eq < amp)) {
            size_t name_len = (size_t)(eq - p);
            if (name_len == strlen(want) &&
                strncmp(p, want, name_len) == 0) {
                size_t value_len = pair_len - name_len - 1;
                if (value_len >= max)
                    return 0;
                memcpy(out, eq + 1, value_len);
                out[value_len] = '\0';
                return 1;
            }
        }
        if (amp == NULL)
            break;
        p = amp + 1;
    }
    return 0;
}

/* Is this link nothing but a wrapper around another one? If so, hand back
 * the link inside. */
static int unwrap(const struct url *u, char *out, size_t max)
{
    char raw[MAX_URL];
    char decoded[MAX_URL];
    int i;

    if (!u->has_query)
        return 0;

    for (i = 0; i < N_REDIRECTORS; i++) {
        if (!host_is(u->host, REDIRECTORS[i].host))
            continue;
        if (REDIRECTORS[i].param[0] == '\0')
            continue;
        if (!query_value(u->query, REDIRECTORS[i].param, raw, sizeof raw))
            continue;

        percent_decode(raw, decoded, sizeof decoded);
        if (strncmp(decoded, "http://", 7) != 0 &&
            strncmp(decoded, "https://", 8) != 0)
            continue;   /* not a link inside after all - leave it alone */
        if (strlen(decoded) >= max)
            return 0;
        strcpy(out, decoded);
        return 1;
    }
    return 0;
}

/* A fragment of the form #:~:text=... is a Chrome text fragment: it is the
 * sentence you had highlighted when you copied. Harmless to the site, but
 * it tells whoever you send it to exactly what caught your eye, which is
 * not usually what you meant to send. */
static int strip_text_fragment(struct url *u)
{
    char *mark;

    if (!u->has_fragment)
        return 0;

    mark = strstr(u->fragment, ":~:text=");
    if (mark == NULL)
        return 0;

    noted("#:~:text", "the sentence you had highlighted when you copied");
    if (mark == u->fragment) {
        u->has_fragment = 0;
        u->fragment[0] = '\0';
    } else {
        /* Something else was in the fragment too - keep that part. */
        if (mark > u->fragment && mark[-1] == ':')
            mark--;
        *mark = '\0';
        if (u->fragment[0] == '\0')
            u->has_fragment = 0;
    }
    return 1;
}

/* ================================================================
 * The clean itself.
 *
 * Walk the query one parameter at a time, keep the ones that are not on a
 * list, and put the survivors back together. Anything not recognised
 * survives - that is the rule the whole tool rests on.
 * ================================================================ */

static int clean_once(const char *text, char *out, size_t max)
{
    struct url u;
    char kept[MAX_URL];
    const char *p;
    size_t k = 0;
    int removed = 0;

    if (!split(text, &u))
        return -1;

    kept[0] = '\0';
    p = u.query;
    while (u.has_query && *p != '\0') {
        const char *amp = strchr(p, '&');
        const char *eq = strchr(p, '=');
        size_t pair_len = amp ? (size_t)(amp - p) : strlen(p);
        size_t name_len = (eq != NULL && (amp == NULL || eq < amp))
                          ? (size_t)(eq - p) : pair_len;
        char name[MAX_PARAM];
        const char *why;

        if (pair_len == 0) {
            /* An empty pair, from "a=1&&b=2". Dropping it changes nothing
             * about where the link goes. */
            if (amp == NULL)
                break;
            p = amp + 1;
            continue;
        }

        if (name_len >= sizeof name)
            name_len = sizeof name - 1;
        memcpy(name, p, name_len);
        name[name_len] = '\0';

        why = tracker_reason(u.host, name);
        if (why != NULL) {
            noted(name, why);
            removed++;
        } else {
            if (k + pair_len + 2 >= sizeof kept)
                return -1;
            if (k > 0)
                kept[k++] = '&';
            memcpy(kept + k, p, pair_len);
            k += pair_len;
            kept[k] = '\0';
        }

        if (amp == NULL)
            break;
        p = amp + 1;
    }

    if (strip_text_fragment(&u))
        removed++;

    if (strlen(u.before) + k + strlen(u.fragment) + 3 >= max)
        return -1;

    strcpy(out, u.before);
    if (k > 0) {
        strcat(out, "?");
        strcat(out, kept);
    }
    if (u.has_fragment && u.fragment[0] != '\0') {
        strcat(out, "#");
        strcat(out, u.fragment);
    }
    return removed;
}

/* Clean, and keep cleaning while the answer is a wrapper around another
 * link. Bounded, because a redirector that points at itself would
 * otherwise spin forever and there is no reason to trust the input. */
#define MAX_HOPS 5

static int clean(const char *text, char *out, size_t max)
{
    char current[MAX_URL];
    char inside[MAX_URL];
    struct url u;
    int total = 0;
    int hop;

    if (strlen(text) >= sizeof current)
        return -1;
    strcpy(current, text);

    for (hop = 0; hop < MAX_HOPS; hop++) {
        int removed;

        if (!split(current, &u))
            return -1;
        if (unwrap(&u, inside, sizeof inside)) {
            noted(u.host, "a redirector that exists to record the click - "
                          "the link inside goes to the same place");
            strcpy(current, inside);
            total++;
            continue;
        }

        removed = clean_once(current, out, max);
        if (removed < 0)
            return -1;
        return total + removed;
    }

    /* Ran out of hops. Say so rather than handing back a half-unwrapped
     * link as though it were finished. */
    return -2;
}

/* ================================================================
 * Finding links inside ordinary text.
 *
 * People do not only copy bare links. They copy a line out of a chat, or a
 * paragraph with a link in the middle. --text handles that: everything
 * that is not a link is passed through exactly as it arrived, and each
 * link found is replaced by its cleaned version.
 * ================================================================ */

/* Where does a link end, given that it started here? Trailing punctuation
 * is the awkward part: in "see https://example.com/page." the full stop is
 * the sentence's, not the link's, but in "https://example.com/a_(b)" the
 * bracket belongs to the link. The rule below is the one most chat clients
 * use, and it is right far more often than it is wrong. */
static size_t link_length(const char *s)
{
    size_t len = 0;
    int depth = 0;

    while (s[len] != '\0' && !isspace((unsigned char)s[len]) &&
           s[len] != '<' && s[len] != '>' && s[len] != '"') {
        if (s[len] == '(')
            depth++;
        else if (s[len] == ')') {
            if (depth == 0)
                break;      /* a closing bracket that was never opened */
            depth--;
        }
        len++;
    }

    /* Walk back over punctuation that is almost certainly the sentence's. */
    while (len > 0 && strchr(".,;:!?'", s[len - 1]) != NULL)
        len--;

    return len;
}

static int clean_text(const char *text, int explain)
{
    const char *p = text;
    int total = 0;

    while (*p != '\0') {
        const char *http = strstr(p, "http://");
        const char *https = strstr(p, "https://");
        const char *found;
        size_t len;
        char link[MAX_URL];
        char cleaned[MAX_URL];
        int removed;

        if (http == NULL && https == NULL)
            found = NULL;
        else if (http == NULL)
            found = https;
        else if (https == NULL)
            found = http;
        else
            found = http < https ? http : https;

        if (found == NULL) {
            fputs(p, stdout);
            break;
        }

        fwrite(p, 1, (size_t)(found - p), stdout);

        len = link_length(found);
        if (len == 0 || len >= sizeof link) {
            fputc(*found, stdout);
            p = found + 1;
            continue;
        }
        memcpy(link, found, len);
        link[len] = '\0';

        removed = clean(link, cleaned, sizeof cleaned);
        if (removed >= 0) {
            fputs(cleaned, stdout);
            total += removed;
        } else {
            fputs(link, stdout);    /* could not clean it: leave it exactly */
        }
        p = found + len;
    }

    if (explain && total == 0)
        fprintf(stderr, "\nNothing to remove.\n");
    return total;
}

/* ================================================================
 * Saying what happened.
 * ================================================================ */

static void explain_notes(void)
{
    int i;

    /* The link goes to stdout and the explanation to stderr, so that
     * `plain-link ... | pbcopy` copies the link and not the essay. They
     * are separate streams with separate buffers, so without this the
     * explanation arrives first and reads as though it were about
     * something else. */
    fflush(stdout);

    if (n_notes == 0) {
        fprintf(stderr, "Nothing was removed. That link was already clean.\n");
        return;
    }

    fprintf(stderr, "Removed %d thing%s:\n\n", n_notes,
            n_notes == 1 ? "" : "s");
    for (i = 0; i < n_notes; i++)
        fprintf(stderr, "  %-22.22s %s\n", notes[i].name, notes[i].why);
    fprintf(stderr, "\nThe link goes to the same page without them.\n");
}

static void list_all(void)
{
    int i;

    printf("Removed from any site\n");
    printf("---------------------\n");
    for (i = 0; i < N_GLOBAL; i++)
        printf("  %-22.22s %s\n", GLOBAL[i].name, GLOBAL[i].why);

    printf("\nRemoved only on the site named\n");
    printf("------------------------------\n");
    printf("Because the same short name means different things in different\n");
    printf("places. \"t\" on x.com is a tracking token; \"t\" on youtube.com is\n");
    printf("where to start playing. A single list would have to pick one, and\n");
    printf("picking wrong either leaks or breaks the link.\n\n");
    for (i = 0; i < N_BY_HOST; i++)
        printf("  %-20.20s %-18.18s %s\n",
               BY_HOST[i].host, BY_HOST[i].name, BY_HOST[i].why);

    printf("\nUnwrapped rather than cleaned\n");
    printf("-----------------------------\n");
    printf("These hosts exist to record a click and pass you along. The\n");
    printf("answer is the link inside, not the wrapper tidied up.\n\n");
    for (i = 0; i < N_REDIRECTORS; i++)
        if (REDIRECTORS[i].param[0] != '\0')
            printf("  %-36.36s the \"%s\" parameter\n",
                   REDIRECTORS[i].host, REDIRECTORS[i].param);

    printf("\nAlso removed\n");
    printf("------------\n");
    printf("  %-22.22s %s\n", "#:~:text",
           "the sentence you had highlighted when you copied");
    printf("\nAnything not on these lists is left exactly as it was. This\n");
    printf("will always miss some tracking. It will not break your links.\n");
}

static void usage(const char *me)
{
    printf("%s - take the tracking off a link.\n\n", me);
    printf("  %s \"https://...\"        clean one link\n", me);
    printf("  echo \"...\" | %s         clean each line that comes in\n", me);
    printf("  %s --explain \"...\"      say what was removed and why\n", me);
    printf("  %s --text \"...\"         clean the links inside a sentence\n", me);
    printf("  %s --list               everything it knows how to remove\n", me);
    printf("  %s --help               this text\n\n", me);
    printf("Reads text, writes text. No network, no files, nothing stored.\n");
    printf("For the clipboard, see plain-link-watch.sh next to this.\n\n");
    printf("Exit: 0 already clean, 1 something was removed, 2 not a link.\n");
}

int main(int argc, char **argv)
{
    char out[MAX_URL];
    char line[MAX_URL];
    int explain = 0, as_text = 0;
    const char *input = NULL;
    int i, removed;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--list") == 0) {
            list_all();
            return 0;
        } else if (strcmp(argv[i], "--explain") == 0) {
            explain = 1;
        } else if (strcmp(argv[i], "--text") == 0) {
            as_text = 1;
        } else if (argv[i][0] == '-' && argv[i][1] != '\0') {
            fprintf(stderr, "%s: do not understand \"%s\". Try --help.\n",
                    argv[0], argv[i]);
            return 3;
        } else {
            input = argv[i];
        }
    }

    /* Given something on the command line, answer about that. */
    if (input != NULL) {
        if (as_text) {
            removed = clean_text(input, 0);
            printf("\n");
            if (explain)
                explain_notes();
            return removed > 0 ? 1 : 0;
        }
        removed = clean(input, out, sizeof out);
        if (removed == -2) {
            fprintf(stderr, "That link wraps another link more than %d times "
                            "deep, which is not something a real link does. "
                            "Left it alone.\n", MAX_HOPS);
            return 2;
        }
        if (removed < 0) {
            fprintf(stderr, "That is not a link I can clean. It has to start "
                            "with http:// or https:// and have a host with a "
                            "dot in it. Left it alone.\n");
            return 2;
        }
        printf("%s\n", out);
        if (explain)
            explain_notes();
        return removed > 0 ? 1 : 0;
    }

    /* Nothing on the command line: read what arrives, a line at a time.
     * That is what makes it useful in a pipe and from the clipboard
     * watcher, which pipes the clipboard through it. */
    {
        int any_removed = 0;
        int saw_input = 0;

        while (fgets(line, sizeof line, stdin) != NULL) {
            size_t len = strlen(line);
            int had_newline = 0;

            saw_input = 1;
            while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
                line[--len] = '\0';
                had_newline = 1;
            }

            if (as_text) {
                any_removed += clean_text(line, 0);
            } else {
                removed = clean(line, out, sizeof out);
                if (removed < 0) {
                    fputs(line, stdout);   /* not a link: pass it through */
                } else {
                    fputs(out, stdout);
                    any_removed += removed;
                }
            }
            if (had_newline)
                fputc('\n', stdout);
        }

        if (!saw_input) {
            usage(argv[0]);
            return 0;
        }
        if (explain)
            explain_notes();
        return any_removed > 0 ? 1 : 0;
    }
}
