"""
Checking that the things a business depends on are actually working.

Traffic analysis answers "is somebody attacking us". This answers the quieter
question that costs small businesses more money: "is our website up, and is the
padlock about to expire". Both belong in one tool because both are the same
job, which is noticing before the customer does.

Two small disasters happen over and over:

  - the site goes down and the owner finds out from a customer rather than
    from their hosting company
  - the certificate expires and every visitor gets a full page warning telling
    them the site is dangerous

Neither is visible until it is embarrassing. Both take seconds to check.

Nothing here is a scan. It asks a public website for its front page and reads
the certificate it presents, which is what any browser does when you visit.
That distinction matters legally as well as ethically.
"""

import datetime
import http.client
import socket
import ssl
import time

TIMEOUT = 10
CERT_WARNING_DAYS = 21          # start nagging this far ahead of expiry
CERT_URGENT_DAYS = 7


def check(host, timeout=TIMEOUT):
    """Look at one site and report what a visitor would experience.

    Returns a dictionary rather than printing, so the same check can feed the
    terminal, the HTML report, and the history database without doing the work
    three times.
    """
    host = tidy(host)
    started = time.time()
    result = {
        "host": host,
        "checked_at": time.time(),
        "reachable": None,
        "status": None,
        "response_ms": None,
        "certificate_ok": None,
        "certificate_days": None,
        "certificate_expires": "",
        "issuer": "",
        "level": "unknown",
        "notes": [],
    }

    reachable, status, note, elapsed = _reach(host, timeout)
    result["reachable"] = reachable
    result["status"] = status
    result["response_ms"] = elapsed
    result["notes"].append(note)

    ok, days, expires, issuer, cert_note = _certificate(host, timeout)
    result["certificate_ok"] = ok
    result["certificate_days"] = days
    result["certificate_expires"] = expires
    result["issuer"] = issuer
    result["notes"].append(cert_note)

    result["level"] = _level(result)
    result["headline"] = _headline(result)
    result["seconds"] = round(time.time() - started, 2)
    return result


def check_all(hosts, timeout=TIMEOUT):
    return [check(host, timeout) for host in hosts]


# ---------------------------------------------------------------------------
def tidy(host):
    """Accept whatever somebody pasted in and turn it into a hostname."""
    host = (host or "").strip()
    for prefix in ("https://", "http://"):
        if host.lower().startswith(prefix):
            host = host[len(prefix):]
    host = host.split("/", 1)[0].split("?", 1)[0].strip().strip(".")
    if "@" in host:
        host = host.split("@", 1)[1]
    return host.lower()


def _reach(host, timeout):
    """Ask for the front page the way a browser would."""
    started = time.time()
    try:
        connection = http.client.HTTPSConnection(host, timeout=timeout)
        connection.request("GET", "/", headers={
            "User-Agent": "traffic-analyzer (site check; plaintext IT)",
            "Accept": "text/html",
        })
        response = connection.getresponse()
        status = response.status
        response.read(1)
        connection.close()
    except socket.gaierror:
        return False, None, ("the domain name does not resolve. It may be misspelled, or the "
                             "registration may have lapsed."), None
    except (socket.timeout, TimeoutError):
        return False, None, ("no answer within %d seconds, so the site is either down or very "
                             "slow." % timeout), None
    except ssl.SSLCertVerificationError:
        return False, None, ("the connection was refused because the certificate does not check "
                             "out. Visitors are being warned away right now."), None
    except ssl.SSLError as exc:
        return False, None, "the secure connection failed (%s)." % (getattr(exc, "reason", "") or exc), None
    except (ConnectionError, OSError) as exc:
        return False, None, "could not connect (%s)." % exc, None
    except http.client.HTTPException:
        return False, None, "the site answered, but not in a way a browser understands.", None

    elapsed = int((time.time() - started) * 1000)

    if status < 400:
        note = "answering normally, in %d milliseconds." % elapsed
        if elapsed > 3000:
            note = ("answering, but slowly: %d milliseconds. Visitors notice anything over about "
                    "three seconds." % elapsed)
        return True, status, note, elapsed
    if status < 500:
        return False, status, ("the site answered %d, which means that page, or the whole site, is "
                               "missing." % status), elapsed
    return False, status, ("the site answered %d, which means the server itself is failing. This "
                           "is usually visible to customers right now." % status), elapsed


def _certificate(host, timeout):
    """Read the certificate the site presents and work out its expiry."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as secure:
                cert = secure.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return False, None, "", "", ("the certificate is not valid (%s). Browsers show a full page "
                                     "warning for this." % (getattr(exc, "verify_message", "") or "rejected"))
    except (socket.gaierror, socket.timeout, TimeoutError, ConnectionError, OSError):
        return None, None, "", "", "could not read the certificate, for the reason above."

    if not cert:
        return None, None, "", "", "no certificate details came back."

    issuer = ""
    for part in cert.get("issuer", ()):
        for key, value in part:
            if key == "organizationName":
                issuer = value

    raw_expiry = cert.get("notAfter")
    if not raw_expiry:
        return None, None, "", issuer, "the certificate carried no readable expiry date."
    try:
        expires = datetime.datetime.strptime(raw_expiry, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None, None, raw_expiry, issuer, "the certificate expiry date was in a format I do not read."

    days = (expires - datetime.datetime.utcnow()).days
    stamp = expires.strftime("%d %b %Y")

    if days < 0:
        return False, days, stamp, issuer, ("the certificate EXPIRED %d days ago. Every visitor is "
                                            "seeing a warning telling them the site is unsafe."
                                            % abs(days))
    if days <= CERT_URGENT_DAYS:
        return False, days, stamp, issuer, ("the certificate expires in %d days, on %s. Renew it "
                                            "today." % (days, stamp))
    if days <= CERT_WARNING_DAYS:
        return False, days, stamp, issuer, ("the certificate expires in %d days, on %s. Worth "
                                            "sorting this week." % (days, stamp))
    return True, days, stamp, issuer, "certificate is healthy, %d days left (expires %s)." % (days, stamp)


def _level(result):
    if result["reachable"] is False:
        return "critical"
    if result["certificate_ok"] is False:
        days = result["certificate_days"]
        if days is not None and days < 0:
            return "critical"
        return "high"
    if result["response_ms"] and result["response_ms"] > 3000:
        return "watch"
    if result["reachable"] and result["certificate_ok"]:
        return "normal"
    return "watch"


def _headline(result):
    if result["reachable"] is False:
        return "Down, or unreachable"
    if result["certificate_ok"] is False:
        days = result["certificate_days"]
        if days is not None and days < 0:
            return "Certificate expired"
        return "Certificate expiring"
    if result["level"] == "watch":
        return "Up, but worth a look"
    return "Healthy"


def load_hosts(items):
    """Take a mix of hostnames and files containing hostnames."""
    hosts = []
    for item in items:
        try:
            with open(item, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.split("#", 1)[0].strip()
                    if line:
                        hosts.append(line)
            continue
        except (OSError, UnicodeDecodeError):
            pass
        hosts.append(item)

    seen, unique = set(), []
    for host in (tidy(h) for h in hosts):
        if host and host not in seen:
            seen.add(host)
            unique.append(host)
    return unique
