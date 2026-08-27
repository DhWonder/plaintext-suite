/*
 * plain-expose - what can reach this machine from the network, and which
 *                program is on the other side of each open door?
 *
 * Every listening socket is a door into the machine. The useful question is
 * never "how many are open" - it is:
 *
 *   1. Which of them can be reached from another machine at all?  A door
 *      bound to 127.0.0.1 is not a door to the outside world, it is two
 *      programs on this machine talking to each other. Confusing the two is
 *      the single most common mistake people make reading `netstat`, in both
 *      directions: panicking about a loopback database, and shrugging at one
 *      that is genuinely wide open.
 *
 *   2. What is behind it?  A port number is not an answer. "5432 is open"
 *      is trivia. "PostgreSQL, running as postgres, accepting connections
 *      from every network this machine is on" is a finding.
 *
 *   3. Does it matter?  Some doors are meant to be open. A web server on
 *      443 is doing its job. A Redis on 0.0.0.0 is a disaster, because
 *      Redis historically shipped with no password at all and assumed
 *      nobody could reach it.
 *
 * It also answers the question the other direction: which services on this
 * machine can be abused to attack somebody else. A handful of UDP services
 * answer a small question with a big answer, which is exactly what a
 * reflection attack needs. traffic-analyzer in this same suite tells you
 * when you are being hit by one of those. This tells you whether you are
 * the one being used to throw it.
 *
 * It only ever READS. It runs no commands, opens no sockets of its own,
 * scans nothing and nobody, and sends nothing anywhere. Everything below
 * comes out of files the kernel already publishes under /proc.
 *
 * That last point is not modesty, it is the design. Port scanning somebody
 * else's machine is a criminal offence in most places, including here.
 * Asking the kernel of the machine you are sitting at what it has open is
 * not scanning at all, and it is also more accurate: a scanner guesses from
 * the outside, this reads the answer from the inside.
 *
 * Build:  make    (or: cc -ansi -pedantic -Wall -Wextra -o plain-expose plain-expose.c)
 *
 * Run:    ./plain-expose               the full report
 *         ./plain-expose --what        every open door, including local ones
 *         ./plain-expose --check       only the things worth acting on
 *         ./plain-expose --root DIR    read DIR/proc instead of /proc
 *
 * Run it with sudo. Without it the kernel will only show you the programs
 * belonging to your own user, so most doors will be listed with no owner.
 * The tool says how many it could not name rather than leaving you to
 * assume the blanks are nothing.
 *
 * Exit code: 0 nothing to do, 1 something worth a look, 2 a real risk.
 *
 * This one is Linux, because it reads Linux's /proc. system-checker in this
 * same suite covers Windows as well and has a much shallower version of
 * this check built in - it lists port numbers. This is the tool for when
 * that list raised a question.
 *
 * DhWonder, Plaintext IT - MIT license.
 */

#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>

/* Plenty for any real machine. If a machine somehow has more sockets than
 * this we say so rather than silently reporting the first few thousand. */
#define MAX_SOCKS  4096
#define MAX_PROCS  2048
#define MAX_USERS  512

/* Room for a full uncompressed IPv6 address and then some. */
#define IPLEN      64
#define PATHLEN    512
#define LINELEN    1024

/* The two protocols we care about. Raw and packet sockets are handled
 * separately because they are not doors - they are ears. */
#define P_TCP 0
#define P_UDP 1

/* What kind of service sits on a well known port. The kind decides what
 * the tool says about it, because the same port number means something
 * completely different depending on which of these it is. */
#define C_EXPECTED 0   /* normal to find open: web, ssh, mail */
#define C_ADMIN    1   /* remote control of the machine itself */
#define C_DATA     2   /* databases and caches, never meant to face outward */
#define C_SHARE    3   /* file and printer sharing */
#define C_AMPLIFY  4   /* UDP services abused to attack other people */
#define C_LEGACY   5   /* sends passwords in the clear */
#define C_UNKNOWN  6

/* How reachable a listening socket actually is. */
#define R_LOCAL   0    /* loopback only - other machines cannot get here */
#define R_ANY     1    /* every network this machine is on */
#define R_ONE     2    /* one specific address, so one network */

/* Terminal width to wrap at. Fixed rather than asked for, because asking
 * means an ioctl, and a report that reflows depending on how wide the
 * window happened to be is a report you cannot diff against last week's. */
#define WRAP 78

/* Counters for the summary at the end. */
static int n_ok = 0;
static int n_look = 0;
static int n_risk = 0;

/* With --check the good news is counted but not printed: the point of
 * that mode is a short list of things to do, and a clean line is not one.
 * It still goes into the summary, so the counts always add up. */
static int only_problems = 0;

/* Print a long sentence broken at spaces, with every line after the first
 * indented to sit under the first. Written by hand rather than left to the
 * terminal, because a terminal breaks mid-word at whatever column the
 * window happens to be, and these lines are meant to be read. */
static void wrapped(const char *first, const char *rest, const char *text)
{
    int used;
    const char *p = text;

    printf("%s", first);
    used = (int)strlen(first);

    while (*p != '\0') {
        const char *space;
        int word;

        while (*p == ' ')
            p++;
        if (*p == '\0')
            break;

        space = strchr(p, ' ');
        word = space ? (int)(space - p) : (int)strlen(p);

        if (used > (int)strlen(rest) && used + 1 + word > WRAP) {
            printf("\n%s", rest);
            used = (int)strlen(rest);
        } else if (used > (int)strlen(first)) {
            printf(" ");
            used++;
        }
        printf("%.*s", word, p);
        used += word;
        p += word;
    }
    printf("\n");
}

static void ok(const char *msg)
{
    if (!only_problems)
        wrapped("  [ OK ]  ", "          ", msg);
    n_ok++;
}
static void look(const char *msg) { wrapped("  [LOOK]  ", "          ", msg); n_look++; }
static void risk(const char *msg) { wrapped("  [RISK]  ", "          ", msg); n_risk++; }

/* A line that is neither good nor bad, just a fact about the machine. */
static void note(const char *msg)
{
    if (!only_problems)
        wrapped("          ", "          ", msg);
}

/* ================================================================
 * Where we read from.
 *
 * Normally /proc. The --root option points everything at a copy of it
 * instead, which is how the tests drive this without needing a machine
 * that happens to have Redis wide open. It also means you can copy the
 * relevant files off a machine and read them somewhere else, though the
 * /proc/<pid>/fd symlinks have to survive the copy for the program names
 * to come out, and most ways of copying a directory do not preserve them.
 * ================================================================ */

static const char *root_dir = "";

static void proc_path(char *out, const char *tail)
{
    sprintf(out, "%.200s/proc%.250s", root_dir, tail);
}

/* ================================================================
 * Small helpers. Each one fails quietly and lets the caller say
 * "could not tell", because a made up value is worse than a gap.
 * ================================================================ */


/* ================================================================
 * SHARED HELPERS - keep identical across the C tools
 *
 * The few lines between this marker and its closing one are duplicated,
 * on purpose, in every C tool in this suite. There is no shared header,
 * and that is a decision rather than an oversight:
 *
 *   ANSI C has no `inline`. A header full of `static` helpers means every
 *   tool that does not use all of them builds with warnings, and these
 *   build warning-clean under -Wall -Wextra, which is worth more than
 *   thirty saved lines.
 *
 *   A real .c and .h pair would work, but it costs the promise each
 *   README makes: one file, one command, no dependencies. Being able to
 *   drop a single .c on a machine you have never seen and compile it is
 *   most of why these are written in C at all.
 *
 * The price is that a fix applied here has to be applied in the other
 * tools too. `tools/same-helpers.sh`, which `make check` runs, fails the
 * build the day the copies stop matching - so the duplication cannot
 * quietly rot into two versions that disagree.
 *
 * If one tool genuinely needs a different version of one of these, that
 * is the signal to move it out of this block in both files and give each
 * its own name, not to let the block drift.
 * ================================================================ */

/* Strip whitespace and newlines from both ends, in place. */
static void trim(char *s)
{
    size_t len;
    char *start = s;

    while (*start != '\0' && isspace((unsigned char)*start))
        start++;
    if (start != s)
        memmove(s, start, strlen(start) + 1);

    len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1]))
        s[--len] = '\0';
}

/* Read the first line of a file. Returns 1 on success. */
static int read_line(const char *path, char *out, size_t max)
{
    FILE *fp;

    out[0] = '\0';
    fp = fopen(path, "r");
    if (fp == NULL)
        return 0;
    if (fgets(out, (int)max, fp) == NULL) {
        fclose(fp);
        return 0;
    }
    fclose(fp);
    trim(out);
    return out[0] != '\0';
}

/* ================================================================
 * END OF SHARED HELPERS
 * ================================================================ */

static int all_digits(const char *s)
{
    if (*s == '\0')
        return 0;
    while (*s != '\0') {
        if (!isdigit((unsigned char)*s))
            return 0;
        s++;
    }
    return 1;
}

/* ================================================================
 * Turning the kernel's hex into an address you can read.
 *
 * /proc/net/tcp does not print addresses, it prints the raw 32 bit words
 * as the machine holds them. On the little endian processors almost
 * everything runs on, that comes out byte reversed: 127.0.0.1 is written
 * "0100007F". On a big endian machine the same kernel code prints
 * "7F000001" instead, so we work out which way round this machine is
 * rather than assuming, and get the right answer on both.
 * ================================================================ */

static int little_endian(void)
{
    unsigned long probe = 1;
    return *(const unsigned char *)&probe == 1;
}

/* Pull one 8 character hex word out and hand back its four bytes in the
 * order they belong in an address. */
static void word_bytes(const char *hex, unsigned char *out)
{
    unsigned long v = strtoul(hex, NULL, 16);

    if (little_endian()) {
        out[0] = (unsigned char)(v & 0xff);
        out[1] = (unsigned char)((v >> 8) & 0xff);
        out[2] = (unsigned char)((v >> 16) & 0xff);
        out[3] = (unsigned char)((v >> 24) & 0xff);
    } else {
        out[0] = (unsigned char)((v >> 24) & 0xff);
        out[1] = (unsigned char)((v >> 16) & 0xff);
        out[2] = (unsigned char)((v >> 8) & 0xff);
        out[3] = (unsigned char)(v & 0xff);
    }
}

/* Write an IPv6 address the short way, with the longest run of zeroes
 * collapsed to "::" - the same rule everything else uses, so the output
 * matches what you would type into a firewall rule. */
static void write_v6(const unsigned char *b, char *out)
{
    unsigned int group[8];
    int best_at = -1, best_len = 0;
    int run_at = -1, run_len = 0;
    int i;
    char *p = out;

    for (i = 0; i < 8; i++)
        group[i] = (unsigned int)((b[i * 2] << 8) | b[i * 2 + 1]);

    /* An address that starts with 80 zero bits then ffff is really an
     * IPv4 address wearing an IPv6 coat. Saying "::ffff:10.0.0.5" instead
     * of the raw form saves the reader a translation step. */
    for (i = 0; i < 5; i++)
        if (group[i] != 0)
            break;
    if (i == 5 && group[5] == 0xffff) {
        sprintf(out, "::ffff:%u.%u.%u.%u", b[12], b[13], b[14], b[15]);
        return;
    }

    for (i = 0; i < 8; i++) {
        if (group[i] == 0) {
            if (run_at < 0) { run_at = i; run_len = 0; }
            run_len++;
            if (run_len > best_len) { best_len = run_len; best_at = run_at; }
        } else {
            run_at = -1;
        }
    }
    /* A single zero group is written out in full: "::" in place of one
     * group saves nothing and reads worse. */
    if (best_len < 2)
        best_at = -1;

    i = 0;
    while (i < 8) {
        if (i == best_at) {
            /* Two colons every time. At the start of the address they are
             * the whole "::"; in the middle, the first one is the ordinary
             * separator after the group before and the second opens the
             * gap. Writing one is the classic off by one here, and it
             * turns 2001:db8::9 into 2001:db8:9, which is a different
             * address. */
            *p++ = ':';
            *p++ = ':';
            i += best_len;
            continue;
        }
        if (i > 0 && *(p - 1) != ':')
            *p++ = ':';
        p += sprintf(p, "%x", group[i]);
        i++;
    }
    *p = '\0';
}

/* Decode the hex address field. 8 characters is IPv4, 32 is IPv6. */
static void decode_addr(const char *hex, char *out, int *family)
{
    unsigned char b[16];
    size_t len = strlen(hex);
    int i;

    if (len == 8) {
        *family = 4;
        word_bytes(hex, b);
        sprintf(out, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
        return;
    }
    if (len == 32) {
        char word[9];
        *family = 6;
        for (i = 0; i < 4; i++) {
            memcpy(word, hex + i * 8, 8);
            word[8] = '\0';
            word_bytes(word, b + i * 4);
        }
        write_v6(b, out);
        return;
    }
    *family = 0;
    strcpy(out, "?");
}

/* ================================================================
 * What lives on a port, and why it matters.
 *
 * This table is the opinionated part of the tool and it is deliberately
 * short. It is not trying to be /etc/services with its thousands of
 * entries, most of which nobody has run since 1998. It is the list of
 * things that actually turn up on small business machines and actually
 * change the answer.
 *
 * "no_password" is the field that earns this table its place. Several of
 * these services shipped for years with no authentication at all, on the
 * assumption that only the machine itself would ever connect. That
 * assumption is fine right up until somebody binds them to 0.0.0.0, and
 * then the port being open IS the breach - there is nothing else to get
 * past. Redis and Memcached are the famous ones; Docker's API is the worst
 * of them, because reaching it is equivalent to being root.
 * ================================================================ */

struct port_fact {
    int port;
    const char *name;
    int kind;
    int no_password;   /* 1 = wide open by default, historically or still */
};

static const struct port_fact PORTS[] = {
    /* Doors that are meant to be open. */
    {   22, "SSH",                     C_EXPECTED, 0 },
    {   80, "a web server",            C_EXPECTED, 0 },
    {  443, "a web server (HTTPS)",    C_EXPECTED, 0 },
    {   25, "SMTP, incoming mail",     C_EXPECTED, 0 },
    {  587, "SMTP submission",         C_EXPECTED, 0 },
    {  465, "SMTP over TLS",           C_EXPECTED, 0 },
    {  993, "IMAP over TLS",           C_EXPECTED, 0 },
    {  995, "POP3 over TLS",           C_EXPECTED, 0 },

    /* Remote control. Open to the internet, these are what gets brute
     * forced all day, every day. */
    { 3389, "Windows Remote Desktop",  C_ADMIN,    0 },
    { 5900, "VNC remote desktop",      C_ADMIN,    1 },
    { 5901, "VNC remote desktop",      C_ADMIN,    1 },
    { 5902, "VNC remote desktop",      C_ADMIN,    1 },
    { 2375, "the Docker API, unencrypted", C_ADMIN, 1 },
    { 2376, "the Docker API",          C_ADMIN,    0 },
    {10250, "the Kubernetes kubelet",  C_ADMIN,    1 },
    { 6443, "the Kubernetes API",      C_ADMIN,    0 },
    { 9090, "a Prometheus or admin console", C_ADMIN, 1 },
    { 8080, "a web admin panel or proxy", C_ADMIN, 0 },
    { 8443, "a web admin panel (HTTPS)", C_ADMIN, 0 },

    /* Databases and caches. None of these belong on a public address. */
    { 3306, "MySQL or MariaDB",        C_DATA,     0 },
    { 5432, "PostgreSQL",              C_DATA,     0 },
    { 1433, "Microsoft SQL Server",    C_DATA,     0 },
    { 1521, "Oracle",                  C_DATA,     0 },
    {27017, "MongoDB",                 C_DATA,     1 },
    {27018, "MongoDB",                 C_DATA,     1 },
    { 6379, "Redis",                   C_DATA,     1 },
    {11211, "Memcached",               C_DATA,     1 },
    { 9200, "Elasticsearch",           C_DATA,     1 },
    { 9300, "Elasticsearch, node to node", C_DATA, 1 },
    { 5984, "CouchDB",                 C_DATA,     1 },
    { 9042, "Cassandra",               C_DATA,     1 },
    { 2379, "etcd",                    C_DATA,     1 },
    { 5672, "RabbitMQ",                C_DATA,     0 },
    {15672, "the RabbitMQ web console", C_DATA,    0 },

    /* File and printer sharing. Fine on an office network, never on a
     * public one - and these are what ransomware travels along. */
    {  445, "Windows file sharing (SMB)", C_SHARE, 0 },
    {  139, "Windows file sharing (NetBIOS)", C_SHARE, 0 },
    { 2049, "NFS file sharing",        C_SHARE,    0 },
    {  111, "rpcbind, which NFS needs", C_SHARE,   0 },
    {  631, "CUPS printer sharing",    C_SHARE,    0 },

    /* Services that answer a small question with a big answer. Somebody
     * forges your customer's address, asks these a question, and your
     * machine posts the large reply at them. See traffic-analyzer for the
     * receiving end of this. */
    {   53, "DNS",                     C_AMPLIFY,  0 },
    {  123, "NTP, the clock service",  C_AMPLIFY,  0 },
    {  161, "SNMP",                    C_AMPLIFY,  1 },
    { 1900, "SSDP, used to find devices", C_AMPLIFY, 0 },
    { 5353, "mDNS, used to find devices", C_AMPLIFY, 0 },
    {  389, "LDAP",                    C_AMPLIFY,  0 },
    {   19, "chargen, an ancient test service", C_AMPLIFY, 1 },
    {   17, "qotd, an ancient test service",    C_AMPLIFY, 1 },

    /* Protocols that send the password across the network in the clear.
     * Anybody on the path can read it, and on a wireless network that
     * means anybody in the building. */
    {   23, "telnet",                  C_LEGACY,   0 },
    {   21, "FTP",                     C_LEGACY,   0 },
    {  512, "rexec",                   C_LEGACY,   0 },
    {  513, "rlogin",                  C_LEGACY,   0 },
    {  514, "rsh",                     C_LEGACY,   0 },
    {  143, "IMAP without TLS",        C_LEGACY,   0 },
    {  110, "POP3 without TLS",        C_LEGACY,   0 }
};

#define N_PORTS ((int)(sizeof(PORTS) / sizeof(PORTS[0])))

static const struct port_fact *port_fact(int port)
{
    int i;

    for (i = 0; i < N_PORTS; i++)
        if (PORTS[i].port == port)
            return &PORTS[i];
    return NULL;
}

/* One sentence explaining why this kind of service matters when it can be
 * reached from another machine. Said once per finding, in the place the
 * reader is already looking, rather than in a footnote nobody reads. */
static const char *kind_reason(int kind)
{
    switch (kind) {
    case C_ADMIN:
        return "this controls the machine, so anyone who gets past it owns it";
    case C_DATA:
        return "this is a database, and databases are the thing being stolen";
    case C_SHARE:
        return "file sharing is how ransomware spreads from one machine to the rest";
    case C_AMPLIFY:
        return "this can be abused to throw traffic at somebody else in your name";
    case C_LEGACY:
        return "this sends the password across the network in readable text";
    default:
        return "";
    }
}

/* ================================================================
 * Reading the socket tables.
 *
 * /proc/net/tcp and friends are a fixed width table. One line per socket,
 * one header line at the top. The columns we want are the local address,
 * the remote address, the state, the owning user id, and the inode - and
 * that last one is the important one, because the inode is the only thread
 * connecting a socket to the program holding it open.
 * ================================================================ */

/* Linux TCP states, as printed in the "st" column. We only need two of
 * them by name: a socket in LISTEN is a door, a socket in ESTABLISHED is
 * somebody currently standing in it. */
#define TCP_ESTABLISHED 0x01
#define TCP_LISTEN      0x0A

struct sock_row {
    int   proto;              /* P_TCP or P_UDP */
    int   family;             /* 4 or 6 */
    char  laddr[IPLEN];
    int   lport;
    char  raddr[IPLEN];
    int   rport;
    int   state;
    int   uid;
    unsigned long inode;
    int   listening;
    int   reach;              /* R_LOCAL, R_ANY, R_ONE */
    /* Filled in later, if we are allowed to see it. */
    int   pid;                /* 0 = we could not find out */
    char  comm[64];
    char  exe[PATHLEN];
    int   exe_deleted;
};

static struct sock_row socks[MAX_SOCKS];
static int n_socks = 0;
static int socks_overflowed = 0;

/* A loopback address is one nothing outside this machine can route to.
 * 127.0.0.0/8 is the whole first octet, not just 127.0.0.1 - services
 * sometimes bind 127.0.1.1 or similar and it is equally unreachable. */
static int is_loopback(const char *ip, int family)
{
    if (family == 4)
        return strncmp(ip, "127.", 4) == 0;
    if (strcmp(ip, "::1") == 0)
        return 1;
    /* An IPv4 address in IPv6 clothing follows the IPv4 rule. */
    if (strncmp(ip, "::ffff:127.", 11) == 0)
        return 1;
    return 0;
}

/* The wildcard: bind to this and you accept connections through every
 * network card the machine has, including ones plugged in later. */
static int is_wildcard(const char *ip, int family)
{
    if (family == 4)
        return strcmp(ip, "0.0.0.0") == 0;
    return strcmp(ip, "::") == 0 || strcmp(ip, "::ffff:0.0.0.0") == 0;
}

static void classify_reach(struct sock_row *s)
{
    if (is_loopback(s->laddr, s->family))
        s->reach = R_LOCAL;
    else if (is_wildcard(s->laddr, s->family))
        s->reach = R_ANY;
    else
        s->reach = R_ONE;
}

static void read_socket_table(const char *tail, int proto)
{
    char path[PATHLEN];
    char line[LINELEN];
    FILE *fp;

    proc_path(path, tail);
    fp = fopen(path, "r");
    if (fp == NULL)
        return;

    while (fgets(line, sizeof line, fp) != NULL) {
        char lhex[64], rhex[64];
        unsigned int lport, rport, state;
        int uid;
        unsigned long inode;
        struct sock_row *s;
        int fam_r;

        if (sscanf(line, "%*d: %40[0-9A-Fa-f]:%X %40[0-9A-Fa-f]:%X %X"
                         " %*X:%*X %*X:%*X %*X %d %*d %lu",
                   lhex, &lport, rhex, &rport, &state, &uid, &inode) != 7)
            continue;   /* the header line, and anything malformed */

        if (n_socks >= MAX_SOCKS) {
            socks_overflowed = 1;
            break;
        }

        s = &socks[n_socks];
        memset(s, 0, sizeof *s);
        s->proto = proto;
        s->lport = (int)lport;
        s->rport = (int)rport;
        s->state = (int)state;
        s->uid = uid;
        s->inode = inode;
        decode_addr(lhex, s->laddr, &s->family);
        decode_addr(rhex, s->raddr, &fam_r);

        /* What counts as "listening" differs by protocol. TCP says so
         * outright with a state. UDP has no states worth the name, so a
         * UDP socket with no remote address is one waiting to be spoken
         * to, which is the same thing for our purposes. */
        if (proto == P_TCP)
            s->listening = (s->state == TCP_LISTEN);
        else
            s->listening = (s->rport == 0);

        classify_reach(s);
        n_socks++;
    }
    fclose(fp);
}

/* ================================================================
 * Putting a name to each socket.
 *
 * The kernel never says "nginx is listening on 443". It says "inode
 * 41207 is listening on 443", and separately, under each process, it
 * lists the inodes that process holds open. Joining those two is the
 * whole job, and it is also why this needs sudo: you can only read
 * /proc/<pid>/fd for your own processes.
 *
 * We walk every process once and look at the sockets it holds, rather
 * than walking the processes once per socket. On a busy machine that is
 * the difference between instant and noticeably slow.
 * ================================================================ */

static int unowned = 0;        /* sockets we were not allowed to trace */
static int scanned_procs = 0;
static int denied_procs = 0;

/* /proc/<pid>/exe points at the program file. If the file has been
 * replaced since the program started - a package upgrade, usually - the
 * kernel appends " (deleted)". That is worth saying out loud: the machine
 * has the fixed version on disk and the old one still running in memory,
 * and it will stay that way until somebody restarts the service. It is a
 * very common way for a patched machine to still be vulnerable. */
static void read_exe(const char *pid, char *out, int *deleted)
{
    char path[PATHLEN];
    char target[PATHLEN];
    int len;
    size_t tail;

    out[0] = '\0';
    *deleted = 0;
    sprintf(path, "%.200s/proc/%.20s/exe", root_dir, pid);
    len = (int)readlink(path, target, sizeof target - 1);
    if (len <= 0)
        return;
    target[len] = '\0';

    tail = strlen(target);
    if (tail > 10 && strcmp(target + tail - 10, " (deleted)") == 0) {
        target[tail - 10] = '\0';
        *deleted = 1;
    }
    sprintf(out, "%.500s", target);
}

static void read_comm(const char *pid, char *out, size_t max)
{
    char path[PATHLEN];

    sprintf(path, "%.200s/proc/%.20s/comm", root_dir, pid);
    if (!read_line(path, out, max))
        sprintf(out, "%.30s", "?");
}

static void attach_processes(void)
{
    char procdir[PATHLEN];
    DIR *proc;
    struct dirent *ent;

    proc_path(procdir, "");
    proc = opendir(procdir);
    if (proc == NULL)
        return;

    while ((ent = readdir(proc)) != NULL) {
        char fddir[PATHLEN];
        char comm[64];
        char exe[PATHLEN];
        int deleted = 0;
        int loaded = 0;
        DIR *fds;
        struct dirent *fd;

        if (!all_digits(ent->d_name))
            continue;
        scanned_procs++;

        sprintf(fddir, "%.200s/proc/%.20s/fd", root_dir, ent->d_name);
        fds = opendir(fddir);
        if (fds == NULL) {
            /* Almost always "not yours, not allowed". Counted rather than
             * ignored, so the report can say how much it could not see. */
            denied_procs++;
            continue;
        }

        comm[0] = '\0';
        exe[0] = '\0';

        while ((fd = readdir(fds)) != NULL) {
            char link[PATHLEN];
            char target[PATHLEN];
            unsigned long inode;
            int len, i;

            if (fd->d_name[0] == '.')
                continue;
            sprintf(link, "%.400s/%.60s", fddir, fd->d_name);
            len = (int)readlink(link, target, sizeof target - 1);
            if (len <= 0)
                continue;
            target[len] = '\0';
            if (sscanf(target, "socket:[%lu]", &inode) != 1)
                continue;

            for (i = 0; i < n_socks; i++) {
                if (socks[i].inode != inode || socks[i].pid != 0)
                    continue;
                if (!loaded) {
                    read_comm(ent->d_name, comm, sizeof comm);
                    read_exe(ent->d_name, exe, &deleted);
                    loaded = 1;
                }
                socks[i].pid = atoi(ent->d_name);
                sprintf(socks[i].comm, "%.60s", comm);
                sprintf(socks[i].exe, "%.500s", exe);
                socks[i].exe_deleted = deleted;
            }
        }
        closedir(fds);
    }
    closedir(proc);
}

/* ================================================================
 * User names.
 *
 * /proc gives us a number. "running as 0" means nothing to most people
 * and "running as root" means everything, so we translate. /etc/passwd
 * is read directly rather than through getpwuid, because getpwuid on a
 * machine wired up to a directory server will go and ask it over the
 * network, and this tool does not talk to the network.
 * ================================================================ */

struct user_row { int uid; char name[64]; };
static struct user_row users[MAX_USERS];
static int n_users = 0;

static void load_users(void)
{
    char path[PATHLEN];
    char line[LINELEN];
    FILE *fp;

    sprintf(path, "%.200s/etc/passwd", root_dir);
    fp = fopen(path, "r");
    if (fp == NULL)
        return;
    while (fgets(line, sizeof line, fp) != NULL && n_users < MAX_USERS) {
        char name[64];
        int uid;

        if (sscanf(line, "%63[^:]:%*[^:]:%d:", name, &uid) != 2)
            continue;
        users[n_users].uid = uid;
        sprintf(users[n_users].name, "%.60s", name);
        n_users++;
    }
    fclose(fp);
}

static const char *user_name(int uid)
{
    static char fallback[32];
    int i;

    for (i = 0; i < n_users; i++)
        if (users[i].uid == uid)
            return users[i].name;
    sprintf(fallback, "user %d", uid);
    return fallback;
}

/* ================================================================
 * Which networks this machine is actually on.
 *
 * "Bound to 0.0.0.0" means every network card. Whether that includes the
 * internet depends on whether one of those cards has a public address,
 * and that changes the answer completely: a database on 0.0.0.0 behind a
 * home router is a bad habit, the same database on 0.0.0.0 on a rented
 * server is a breach that has already happened.
 *
 * So rather than saying "0.0.0.0, could be anything", we look up what
 * this machine's addresses actually are and say which it is. IPv4 comes
 * out of /proc/net/fib_trie, where the machine's own addresses are the
 * ones marked "host LOCAL"; IPv6 comes out of /proc/net/if_inet6, where
 * the scope column says whether an address is global.
 * ================================================================ */

#define A_LOOPBACK  0
#define A_PRIVATE   1   /* an office or home network */
#define A_PUBLIC    2   /* reachable from the internet */

struct local_addr { char ip[IPLEN]; int family; int scope; };
static struct local_addr locals[64];
static int n_locals = 0;
static int have_public = 0;

/* The address ranges set aside for private networks. Anything outside
 * them, that is not loopback or a link-local stopgap, is an address the
 * rest of the internet can route to. */
static int v4_scope(const char *ip)
{
    unsigned int a = 0, b = 0;

    if (sscanf(ip, "%u.%u", &a, &b) != 2)
        return A_PRIVATE;
    if (a == 127)
        return A_LOOPBACK;
    if (a == 10)
        return A_PRIVATE;
    if (a == 192 && b == 168)
        return A_PRIVATE;
    if (a == 172 && b >= 16 && b <= 31)
        return A_PRIVATE;
    if (a == 169 && b == 254)
        return A_PRIVATE;     /* no DHCP answered; goes nowhere */
    if (a == 100 && b >= 64 && b <= 127)
        return A_PRIVATE;     /* carrier grade NAT, still not yours */
    return A_PUBLIC;
}

static void add_local(const char *ip, int family, int scope)
{
    int i;

    if (n_locals >= 64)
        return;
    /* fib_trie prints the same addresses once per routing table, so the
     * same address arrives more than once. Listing it twice would suggest
     * the machine has two of them. */
    for (i = 0; i < n_locals; i++)
        if (locals[i].family == family && strcmp(locals[i].ip, ip) == 0)
            return;
    sprintf(locals[n_locals].ip, "%.60s", ip);
    locals[n_locals].family = family;
    locals[n_locals].scope = scope;
    n_locals++;
    if (scope == A_PUBLIC)
        have_public = 1;
}

static void load_local_addresses(void)
{
    char path[PATHLEN];
    char line[LINELEN];
    char pending[IPLEN];
    FILE *fp;

    pending[0] = '\0';
    proc_path(path, "/net/fib_trie");
    fp = fopen(path, "r");
    if (fp != NULL) {
        while (fgets(line, sizeof line, fp) != NULL) {
            char addr[IPLEN];

            if (sscanf(line, " |-- %63s", addr) == 1) {
                sprintf(pending, "%.60s", addr);
                continue;
            }
            /* The line after the address says what it is. "/32 host
             * LOCAL" means this exact address belongs to the machine.
             * The same file also carries the network itself (/8, /24) and
             * the broadcast address, neither of which is somewhere a
             * program can be reached, so the prefix length matters. */
            if (pending[0] != '\0' && strstr(line, "/32 host LOCAL") != NULL) {
                add_local(pending, 4, v4_scope(pending));
                pending[0] = '\0';
            }
        }
        fclose(fp);
    }

    proc_path(path, "/net/if_inet6");
    fp = fopen(path, "r");
    if (fp != NULL) {
        while (fgets(line, sizeof line, fp) != NULL) {
            char hex[64], text[IPLEN];
            unsigned int scope;
            unsigned char b[16];
            char word[9];
            int i, fam;

            if (sscanf(line, "%32s %*x %*x %x", hex, &scope) != 2)
                continue;
            if (strlen(hex) != 32)
                continue;
            /* if_inet6 prints the address in reading order rather than
             * in machine word order, so unlike /proc/net/tcp6 this one is
             * a straight hex read with no byte swapping. */
            for (i = 0; i < 4; i++) {
                unsigned long v;

                memcpy(word, hex + i * 8, 8);
                word[8] = '\0';
                v = strtoul(word, NULL, 16);
                b[i * 4 + 0] = (unsigned char)((v >> 24) & 0xff);
                b[i * 4 + 1] = (unsigned char)((v >> 16) & 0xff);
                b[i * 4 + 2] = (unsigned char)((v >> 8) & 0xff);
                b[i * 4 + 3] = (unsigned char)(v & 0xff);
            }
            write_v6(b, text);
            fam = 6;
            /* Scope 0 is global, 0x10 is this machine only, 0x20 is the
             * local link and goes no further than the nearest switch. */
            if (scope == 0x10)
                add_local(text, fam, A_LOOPBACK);
            else if (scope == 0)
                add_local(text, fam, A_PUBLIC);
            else
                add_local(text, fam, A_PRIVATE);
        }
        fclose(fp);
    }
}

/* Whether a specific bind address is one the wider world can reach. */
static int addr_scope(const char *ip, int family)
{
    if (is_loopback(ip, family))
        return A_LOOPBACK;
    if (family == 4)
        return v4_scope(ip);
    if (strncmp(ip, "::ffff:", 7) == 0)
        return v4_scope(ip + 7);
    if (strncmp(ip, "fe80", 4) == 0)
        return A_PRIVATE;
    if ((ip[0] == 'f' && (ip[1] == 'c' || ip[1] == 'd')))
        return A_PRIVATE;
    return A_PUBLIC;
}

/* ================================================================
 * Saying it.
 * ================================================================ */

static const char *proto_name(int proto)
{
    return proto == P_TCP ? "TCP" : "UDP";
}

/* Where this door can be knocked on from. This sentence is the one the
 * whole tool exists to get right, so it is spelled out rather than
 * abbreviated to a bind address the reader has to interpret. */
static void reach_words(const struct sock_row *s, char *out)
{
    if (s->reach == R_ANY) {
        if (have_public)
            sprintf(out, "every network this machine is on, and one of those "
                         "is the internet");
        else
            sprintf(out, "every network this machine is on");
        return;
    }
    if (addr_scope(s->laddr, s->family) == A_PUBLIC)
        sprintf(out, "the internet, through %.40s", s->laddr);
    else
        sprintf(out, "the local network, through %.40s", s->laddr);
}

/* Who is holding the door open. */
static void owner_words(const struct sock_row *s, char *out)
{
    if (s->pid == 0) {
        /* Two very different reasons for a blank, and saying the wrong one
         * sends somebody chasing the wrong thing. If processes were closed
         * to us it is permissions; if every one of them was readable, the
         * owner genuinely is not on this side of the fence. */
        if (denied_procs > 0)
            sprintf(out, "held open by a program this account may not look "
                         "at - run with sudo");
        else
            sprintf(out, "held open by nothing visible from here - likely a "
                         "container or virtual machine sharing this network");
        return;
    }
    sprintf(out, "held open by %.40s (process %d), running as %.30s",
            s->comm[0] ? s->comm : "an unnamed program", s->pid,
            user_name(s->uid));
}

/* How many connections are live on a given listening port right now.
 * This is the number that decides whether closing a port is safe: a
 * forgotten service with nobody connected can go today, and one with
 * fourteen sessions on it needs a conversation first. */
static int live_connections(int proto, int port)
{
    int i, count = 0;

    for (i = 0; i < n_socks; i++)
        if (socks[i].proto == proto && socks[i].lport == port &&
            socks[i].state == TCP_ESTABLISHED && !socks[i].listening)
            count++;
    return count;
}

/* The verdict for one reachable door. Everything above this point was
 * reading files; this is the part with an opinion in it. */
static void judge(const struct sock_row *s, const struct port_fact *pf)
{
    char msg[LINELEN];
    int public_facing = (s->reach == R_ANY && have_public) ||
                        (s->reach == R_ONE &&
                         addr_scope(s->laddr, s->family) == A_PUBLIC);

    /* An unrecognised port is a question, not a verdict. Calling it a
     * risk would be guessing, and calling it fine would be worse. It gets
     * named and handed back to whoever knows what runs on this machine. */
    if (pf == NULL) {
        if (s->pid == 0 && denied_procs > 0)
            sprintf(msg, "Nothing here says what this is, and this account "
                         "cannot see which program owns it. Run again with "
                         "sudo before deciding it is harmless.%s",
                    public_facing ? " It is facing the internet." : "");
        else if (s->pid == 0)
            sprintf(msg, "An open port with no owner anywhere on this "
                         "machine. Find out which container or virtual "
                         "machine it belongs to.%s",
                    public_facing ? " It is facing the internet." : "");
        else
            sprintf(msg, "I do not recognise this port. %.40s put it there - "
                         "find out why before leaving it reachable.%s",
                    s->comm[0] ? s->comm : "Some program",
                    public_facing ? " It is facing the internet, so this is "
                                    "the first one to answer." : "");
        look(msg);
        return;
    }

    switch (pf->kind) {
    case C_DATA:
        if (pf->no_password)
            sprintf(msg, "%.40s should never be reachable from another "
                         "machine, and this one historically ships with no "
                         "password at all - reaching it may be the whole "
                         "attack. Bind it to 127.0.0.1.", pf->name);
        else
            sprintf(msg, "%.40s is a database and %s. Bind it to 127.0.0.1, "
                         "or to the one address that needs it.",
                    pf->name, kind_reason(C_DATA));
        risk(msg);
        return;

    case C_LEGACY:
        sprintf(msg, "%.40s: %s. Replace it - SSH for telnet and the "
                     "r-services, SFTP for FTP, TLS for the mail ports.",
                pf->name, kind_reason(C_LEGACY));
        risk(msg);
        return;

    case C_ADMIN:
        if (pf->no_password) {
            sprintf(msg, "%.40s, reachable and commonly left with no "
                         "password. Anyone who can reach this owns the "
                         "machine.", pf->name);
            risk(msg);
        } else if (public_facing) {
            sprintf(msg, "%.40s is facing the internet. %s. Put it behind a "
                         "VPN or restrict it to known addresses.",
                    pf->name, kind_reason(C_ADMIN));
            risk(msg);
        } else {
            sprintf(msg, "%.40s, reachable on the local network. Fine if "
                         "that is deliberate; %s.", pf->name,
                    kind_reason(C_ADMIN));
            look(msg);
        }
        return;

    case C_SHARE:
        if (public_facing) {
            sprintf(msg, "%.40s is facing the internet. %s, and this is "
                         "exactly how it gets in.", pf->name,
                    kind_reason(C_SHARE));
            risk(msg);
        } else {
            sprintf(msg, "%.40s, on the local network. Normal in an office; "
                         "%s.", pf->name, kind_reason(C_SHARE));
            look(msg);
        }
        return;

    case C_AMPLIFY:
        if (public_facing) {
            sprintf(msg, "%.40s answers small questions with large replies. "
                         "Facing the internet, %s. Restrict who may ask, or "
                         "bind it inward.", pf->name, kind_reason(C_AMPLIFY));
            risk(msg);
        } else {
            sprintf(msg, "%.40s, answering on the local network only. That "
                         "is where it belongs.", pf->name);
            ok(msg);
        }
        return;

    default:
        if (s->lport == 22)
            sprintf(msg, "SSH, which is meant to be reachable. Worth "
                         "confirming password logins are off and only keys "
                         "are accepted.");
        else
            sprintf(msg, "%.60s. Expected to be reachable.", pf->name);
        ok(msg);
        return;
    }
}

/* One door, printed. Returns 1 if it printed anything. */
static void show_listener(const struct sock_row *s, int dual, int quiet)
{
    const struct port_fact *pf = port_fact(s->lport);
    char where[LINELEN];
    char who[LINELEN];
    char head[LINELEN];
    int live;

    reach_words(s, where);
    owner_words(s, who);

    if (quiet) {
        /* --check is meant to be a list of things to do, so it drops the
         * explanation - but never the port, or there is nothing to act on. */
        printf("\n  %s port %d on %.40s\n", proto_name(s->proto), s->lport,
               s->laddr);
    }

    if (!quiet) {
        sprintf(head, "%s port %d%s%.60s%s - reachable from %.200s",
                proto_name(s->proto), s->lport,
                pf ? " (" : "", pf ? pf->name : "", pf ? ")" : "",
                where);
        wrapped("\n  ", "      ", head);
        wrapped("          ", "          ", who);

        if (dual)
            note("listening on IPv4 and IPv6");
        if (s->exe_deleted)
            note("the program file on disk has been replaced since this "
                 "started - see below");

        live = s->proto == P_TCP ? live_connections(P_TCP, s->lport) : 0;
        if (live == 1)
            note("one connection is live on it right now");
        else if (live > 1) {
            char m[64];
            sprintf(m, "%d connections are live on it right now", live);
            note(m);
        }
    }
    judge(s, pf);
}

/* ================================================================
 * A version of the same thing a script can read.
 *
 * --list prints one line per reachable door and nothing else: no
 * verdicts, no wrapping, no blank lines. It exists so the notify wrapper
 * can compare today's doors against last week's and tell you what
 * changed, which is a far more useful email than a weekly report saying
 * the same thing every time. Somebody opening a port on Tuesday is the
 * event worth knowing about.
 *
 * The format is deliberately dull and will not be prettied up later:
 *
 *   tcp 6379 0.0.0.0 redis-server redis
 *
 * protocol, port, bind address, program, user. A "-" where we could not
 * tell, so the column count never changes.
 * ================================================================ */

static void report_list(void)
{
    int i;

    for (i = 0; i < n_socks; i++) {
        if (!socks[i].listening || socks[i].reach == R_LOCAL)
            continue;
        printf("%s %d %s %s %s\n",
               socks[i].proto == P_TCP ? "tcp" : "udp",
               socks[i].lport,
               socks[i].laddr,
               socks[i].pid && socks[i].comm[0] ? socks[i].comm : "-",
               socks[i].pid ? user_name(socks[i].uid) : "-");
    }
}

/* ================================================================
 * The report.
 * ================================================================ */

/* A service that listens on both IPv4 and IPv6 shows up twice, which is
 * correct but reads as two problems. We print the pair once and say so.
 * The flag lives here rather than in the parse because it is a
 * presentation decision, not a fact about the machine. */
static char shown[MAX_SOCKS];

static int same_service(const struct sock_row *a, const struct sock_row *b)
{
    return a->proto == b->proto && a->lport == b->lport &&
           a->reach == b->reach && a->pid == b->pid &&
           a->family != b->family;
}

static void report_reachable(int quiet)
{
    int i, j, found = 0;

    printf("\nDoors other machines can reach\n");

    for (i = 0; i < n_socks; i++) {
        int dual = 0;

        if (!socks[i].listening || socks[i].reach == R_LOCAL || shown[i])
            continue;
        for (j = i + 1; j < n_socks; j++) {
            if (!shown[j] && socks[j].listening && same_service(&socks[i], &socks[j])) {
                shown[j] = 1;
                dual = 1;
            }
        }
        shown[i] = 1;
        found++;
        show_listener(&socks[i], dual, quiet);
    }

    if (found == 0)
        ok("nothing on this machine is accepting connections from anywhere "
           "else. That is the safest a machine gets.");
}

static void report_local(void)
{
    int i, j, found = 0;

    printf("\nDoors only this machine can reach\n");
    printf("  These are programs on this machine talking to each other. Nothing\n"
           "  outside can connect to them, so none of them is exposure. They are\n"
           "  listed because knowing what runs here is half of knowing the machine.\n\n");

    for (i = 0; i < n_socks; i++) {
        const struct port_fact *pf;
        int dual = 0;

        if (!socks[i].listening || socks[i].reach != R_LOCAL || shown[i])
            continue;
        for (j = i + 1; j < n_socks; j++) {
            if (!shown[j] && socks[j].listening &&
                same_service(&socks[i], &socks[j])) {
                shown[j] = 1;
                dual = 1;
            }
        }
        shown[i] = 1;
        found++;

        pf = port_fact(socks[i].lport);
        printf("  %-3s %s:%d%s\n", proto_name(socks[i].proto),
               socks[i].laddr, socks[i].lport,
               dual ? "  (v4 and v6)" : "");
        printf("      %-30.30s %s\n",
               pf ? pf->name : "not a port I recognise",
               socks[i].pid ? socks[i].comm : "owner not visible");
    }

    if (found == 0)
        printf("  None.\n");
}

/* ================================================================
 * The things that are not doors.
 *
 * A raw socket or a packet socket does not accept connections, so none of
 * the above applies to it - but both are worth knowing about, because both
 * are how a program reads traffic that was not addressed to it. That is
 * what tcpdump does, and it is also what something hiding on the machine
 * does. The tool does not claim to know which; it says one exists and who
 * owns it, and leaves the judgement to somebody who knows what should be
 * running here.
 * ================================================================ */

static void report_ears(void)
{
    char path[PATHLEN];
    char line[LINELEN];
    char msg[LINELEN];
    FILE *fp;
    int packet_socks = 0;
    int raw_socks = 0;

    proc_path(path, "/net/packet");
    fp = fopen(path, "r");
    if (fp != NULL) {
        while (fgets(line, sizeof line, fp) != NULL) {
            unsigned long inode;
            if (sscanf(line, "%*s %*d %*d %*x %*d %*d %*d %*d %lu", &inode) == 1)
                packet_socks++;
        }
        fclose(fp);
    }

    proc_path(path, "/net/raw");
    fp = fopen(path, "r");
    if (fp != NULL) {
        while (fgets(line, sizeof line, fp) != NULL) {
            unsigned int dummy;
            if (sscanf(line, "%*d: %*8[0-9A-Fa-f]:%X", &dummy) == 1)
                raw_socks++;
        }
        fclose(fp);
    }

    if (packet_socks > 0) {
        sprintf(msg, "%d program(s) are reading raw network traffic off a "
                     "network card. That is what a packet capture looks "
                     "like. If you are running one, this is it. If you are "
                     "not, find out what is.", packet_socks);
        look(msg);
    }
    if (raw_socks > 0) {
        sprintf(msg, "%d raw socket(s) are open. Ping uses one, so a small "
                     "number here is normal.", raw_socks);
        note(msg);
    }
}

/* Programs still running code that has since been replaced on disk. */
static void report_stale(void)
{
    char msg[LINELEN];
    int i, j, found = 0;

    for (i = 0; i < n_socks; i++) {
        if (!socks[i].listening || !socks[i].exe_deleted || socks[i].pid == 0)
            continue;
        /* Say it once per program, not once per socket. */
        for (j = 0; j < i; j++)
            if (socks[j].pid == socks[i].pid && socks[j].exe_deleted)
                break;
        if (j < i)
            continue;
        found++;
        sprintf(msg, "%.30s (process %d) is still running a copy of %.200s "
                     "that no longer exists on disk. The file was replaced - "
                     "an update, usually - and the running program was never "
                     "restarted, so the machine has the fix installed and is "
                     "not using it. Restart the service.",
                socks[i].comm, socks[i].pid, socks[i].exe);
        look(msg);
    }
    (void)found;
}

/* The IPv6 trap: on most machines a socket bound to :: also accepts IPv4
 * connections through the same socket. People close a port in the IPv4
 * firewall, see it disappear from `netstat -4`, and leave it wide open. */
static void report_v6_trap(void)
{
    char path[PATHLEN];
    char value[64];
    int i;
    int v6_any = 0;

    for (i = 0; i < n_socks; i++)
        if (socks[i].listening && socks[i].family == 6 && socks[i].reach == R_ANY)
            v6_any++;
    if (v6_any == 0)
        return;

    sprintf(path, "%.200s/proc/sys/net/ipv6/bindv6only", root_dir);
    if (read_line(path, value, sizeof value) && atoi(value) == 0) {
        char msg[LINELEN];
        sprintf(msg, "%d socket(s) are bound to the IPv6 wildcard, and this "
                     "machine is set to let those accept IPv4 connections "
                     "too. A firewall rule written only for IPv4 will not "
                     "close them.", v6_any);
        look(msg);
    }
}

static void report_addresses(void)
{
    int i;

    printf("\nThis machine's own addresses\n");
    if (n_locals == 0) {
        printf("  Could not tell. Without them, \"every network\" below cannot\n"
               "  be pinned down to whether that includes the internet.\n");
        return;
    }
    for (i = 0; i < n_locals; i++)
        printf("  %-40.40s %s\n", locals[i].ip,
               locals[i].scope == A_LOOPBACK ? "this machine only" :
               locals[i].scope == A_PUBLIC   ? "reachable from the internet" :
                                               "a private network");
}

/* ================================================================
 * What we could not see.
 *
 * This section exists because of the rule the rest of this suite follows:
 * never a silent wrong answer. Run without sudo, this tool can still list
 * every open door - the socket tables are world readable - but it cannot
 * tell you which program is behind most of them. A report that quietly
 * left those blank would read as "nothing important there", which is the
 * opposite of what a blank means.
 * ================================================================ */

static void report_blind_spots(void)
{
    char msg[LINELEN];
    int i;

    unowned = 0;
    for (i = 0; i < n_socks; i++)
        if (socks[i].listening && socks[i].pid == 0)
            unowned++;

    if (socks_overflowed) {
        sprintf(msg, "This machine has more sockets than this tool holds "
                     "(%d). The report above is incomplete and the counts "
                     "below are wrong. Rebuild with a larger MAX_SOCKS.",
                MAX_SOCKS);
        look(msg);
    }

    if (unowned > 0 && denied_procs > 0) {
        sprintf(msg, "%d of the doors above could not be traced to a "
                     "program: %d of this machine's %d processes would not "
                     "let this account look inside them, which is what "
                     "happens when you are not root. Run it again with "
                     "sudo. Those blanks are not nothing, they are unread.",
                unowned, denied_procs, scanned_procs);
        look(msg);
    } else if (unowned > 0) {
        sprintf(msg, "%d of the doors above could not be traced to a "
                     "program, and it is not a permissions problem - every "
                     "one of the %d processes here was readable. That means "
                     "whatever holds those ports open is not visible from "
                     "here at all: usually a container or a virtual machine "
                     "sharing this network, occasionally a program that has "
                     "since exited. Worth chasing down rather than "
                     "assuming.", unowned, scanned_procs);
        look(msg);
    }
}

static int summary(void)
{
    printf("\nSummary\n");
    printf("  %d fine, %d worth a look, %d a real risk.\n", n_ok, n_look, n_risk);

    if (n_risk > 0) {
        printf("\n  Start with the [RISK] lines. Each one names the program\n"
               "  holding the port open, so the fix is a configuration change\n"
               "  in that program - usually one line changing the address it\n"
               "  binds to from 0.0.0.0 to 127.0.0.1 - and a restart.\n");
        return 2;
    }
    if (n_look > 0) {
        printf("\n  Nothing here is on fire. The [LOOK] lines are things that\n"
               "  are fine if somebody decided them on purpose, and are worth\n"
               "  asking about if nobody remembers deciding them.\n");
        return 1;
    }
    printf("\n  Nothing reachable that should not be.\n");
    return 0;
}

static void usage(const char *me)
{
    printf("%s - what can reach this machine, and what is behind each door.\n\n", me);
    printf("  %s              the full report\n", me);
    printf("  %s --what       every open door, local ones included\n", me);
    printf("  %s --check      only the things worth acting on\n", me);
    printf("  %s --list       one plain line per reachable door, for scripts\n", me);
    printf("  %s --root DIR   read DIR/proc instead of /proc\n", me);
    printf("  %s --help       this text\n\n", me);
    printf("Run it with sudo, or most doors will be listed with no owner.\n");
    printf("It reads files and nothing else: no commands, no scanning, and\n");
    printf("nothing leaves the machine.\n\n");
    printf("Exit code: 0 nothing to do, 1 worth a look, 2 a real risk.\n");
}

int main(int argc, char **argv)
{
    int list_local = 0;
    int want_list = 0;
    int quiet = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--what") == 0) {
            list_local = 1;
        } else if (strcmp(argv[i], "--list") == 0) {
            want_list = 1;
        } else if (strcmp(argv[i], "--check") == 0) {
            only_problems = 1;
            quiet = 1;
        } else if (strcmp(argv[i], "--root") == 0 && i + 1 < argc) {
            root_dir = argv[++i];
        } else {
            fprintf(stderr, "%s: do not understand \"%s\". Try --help.\n",
                    argv[0], argv[i]);
            return 3;
        }
    }

    load_users();
    load_local_addresses();
    read_socket_table("/net/tcp",  P_TCP);
    read_socket_table("/net/tcp6", P_TCP);
    read_socket_table("/net/udp",  P_UDP);
    read_socket_table("/net/udp6", P_UDP);
    attach_processes();

    if (n_socks == 0) {
        printf("Could not read the socket tables under %s/proc/net.\n",
               root_dir[0] ? root_dir : "");
        printf("On Linux those are always there, so either this is not Linux,\n");
        printf("or /proc is not mounted, or --root points somewhere wrong.\n");
        return 3;
    }

    if (want_list) {
        report_list();
        return 0;
    }

    printf("What can reach this machine\n");
    printf("===========================\n");

    if (!only_problems)
        report_addresses();

    /* The reachable doors come first even in the full report, because
     * that is the question. The local ones are context. */
    report_reachable(quiet);

    if (list_local && !only_problems)
        report_local();

    printf("\nOther things worth knowing\n");
    report_v6_trap();
    report_stale();
    report_ears();
    report_blind_spots();
    if (n_ok + n_look + n_risk == 0)
        printf("  Nothing.\n");

    return summary();
}
