/*
 * plain-check - a quick health and security look at a Linux machine,
 *               reported in plain English.
 *
 * Most system tools answer questions nobody asked, in a language nobody
 * speaks. This one walks through a short list of things that actually
 * bite small businesses - full disks, forgotten open ports, accounts
 * without passwords - and explains each finding like a human would.
 *
 * It only ever READS. It changes nothing on the machine.
 *
 * Build:  cc -ansi -pedantic -Wall -Wextra -o plain-check plain-check.c
 * Run:    ./plain-check          (run with sudo for the password checks)
 *
 * Written in plain ANSI C on purpose: no dependencies, compiles on
 * basically anything, and the code is meant to be read.
 *
 * DhWonder, Plaintext IT - MIT license.
 */

#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>

/* How full a disk can get before we consider it a problem, in percent. */
#define DISK_WORRY   85
#define DISK_ALARM   95

/* An uptime past this many days usually means updates are being skipped. */
#define UPTIME_WORRY_DAYS 60

/* Counters for the final summary. */
static int n_ok = 0;
static int n_look = 0;
static int n_risk = 0;

/* Three kinds of line: fine, worth a look, and a real risk.
 * The wording matters more than the checks - the report should read
 * like a calm person explaining, not like an alarm going off. */
static void ok(const char *msg)   { printf("  [ OK ]  %s\n", msg); n_ok++; }
static void look(const char *msg) { printf("  [LOOK]  %s\n", msg); n_look++; }
static void risk(const char *msg) { printf("  [RISK]  %s\n", msg); n_risk++; }

/* ----------------------------------------------------------------
 * Check 1: is the main disk about to fill up?
 * A full disk is the most boring disaster there is. Databases stop,
 * mail stops, and the machine often can't even log what went wrong.
 * ---------------------------------------------------------------- */
static void check_disk(void)
{
    struct statvfs vfs;
    double used_pct;
    char msg[160];

    printf("\nDisk space\n");

    if (statvfs("/", &vfs) != 0) {
        look("could not read disk usage for '/' - unusual, worth a manual look with 'df -h'.");
        return;
    }

    used_pct = 100.0 - (100.0 * (double)vfs.f_bavail / (double)vfs.f_blocks);

    sprintf(msg, "the main disk is %.0f%% full.", used_pct);

    if (used_pct >= DISK_ALARM) {
        strcat(msg, " Above 95% things start breaking quietly. Free space soon.");
        risk(msg);
    } else if (used_pct >= DISK_WORRY) {
        strcat(msg, " Not urgent, but plan a cleanup before it becomes urgent.");
        look(msg);
    } else {
        strcat(msg, " Plenty of room.");
        ok(msg);
    }
}

/* ----------------------------------------------------------------
 * Check 2: how long since the last reboot?
 * Long uptime sounds impressive but usually means security updates
 * are installed-but-not-applied, or not installed at all.
 * ---------------------------------------------------------------- */
static void check_uptime(void)
{
    struct sysinfo si;
    long days;
    char msg[160];

    printf("\nRestarts and updates\n");

    if (sysinfo(&si) != 0) {
        look("could not read system uptime.");
        return;
    }

    days = si.uptime / 86400L;
    sprintf(msg, "last restart was %ld day(s) ago.", days);

    if (days >= UPTIME_WORRY_DAYS) {
        strcat(msg, " Months without a restart usually means updates aren't being applied. Pick a quiet evening and reboot.");
        look(msg);
    } else {
        strcat(msg, " Restarting now and then lets updates actually take effect.");
        ok(msg);
    }
}

/* ----------------------------------------------------------------
 * Check 3: which network ports are listening?
 * Every listening port is a door. Most are fine; a few are famous
 * trouble (old remote-desktop and file-sharing doors especially).
 * We read /proc/net/tcp and tcp6, where state 0A means "listening".
 * ---------------------------------------------------------------- */
static const char *port_note(int port)
{
    switch (port) {
        case 21:   return "FTP (21) - passwords travel unencrypted. Retire it if possible";
        case 23:   return "Telnet (23) - decades obsolete and unsafe. Should be closed";
        case 3389: return "Remote Desktop (3389) - a favourite target. Should never face the internet directly";
        case 5900: return "VNC (5900) - remote control, often weakly protected. Check who needs it";
        case 445:  return "Windows file sharing (445) - fine inside an office, dangerous exposed to the internet";
        default:   return NULL;
    }
}

static int scan_tcp_file(const char *path, int *ports, int max, int count)
{
    FILE *fp;
    char line[512];
    unsigned int port, state;
    int i, seen;

    fp = fopen(path, "r");
    if (fp == NULL)
        return count;

    /* Skip the header line. */
    if (fgets(line, sizeof line, fp) == NULL) {
        fclose(fp);
        return count;
    }

    while (fgets(line, sizeof line, fp) != NULL) {
        if (sscanf(line, "%*d: %*[0-9A-Fa-f]:%x %*[0-9A-Fa-f]:%*x %x",
                   &port, &state) != 2)
            continue;
        if (state != 0x0A)   /* 0A = LISTEN */
            continue;

        /* Keep each port once - v4 and v6 often both listen. */
        seen = 0;
        for (i = 0; i < count; i++)
            if (ports[i] == (int)port)
                seen = 1;
        if (!seen && count < max)
            ports[count++] = (int)port;
    }

    fclose(fp);
    return count;
}

static void check_ports(void)
{
    int ports[256];
    int count = 0;
    int i, flagged = 0;
    char msg[200];
    const char *note;

    printf("\nOpen network doors (listening ports)\n");

    count = scan_tcp_file("/proc/net/tcp", ports, 256, count);
    count = scan_tcp_file("/proc/net/tcp6", ports, 256, count);

    if (count == 0) {
        ok("no listening TCP ports found - nothing is accepting network connections.");
        return;
    }

    for (i = 0; i < count; i++) {
        note = port_note(ports[i]);
        if (note != NULL) {
            sprintf(msg, "%s.", note);
            look(msg);
            flagged++;
        }
    }

    sprintf(msg, "%d port(s) are listening in total.", count);
    if (flagged == 0) {
        strcat(msg, " None of them are on my known-trouble list.");
        ok(msg);
    } else {
        strcat(msg, " The flagged ones above deserve a conversation.");
        look(msg);
    }
}

/* ----------------------------------------------------------------
 * Check 4: accounts that could log in with no password, and
 * accounts that secretly have administrator (root) power.
 * Needs root to read /etc/shadow; degrades politely without it.
 * ---------------------------------------------------------------- */
static void check_accounts(void)
{
    FILE *fp;
    char line[512];
    char *first, *second, *third;
    long uid;
    int extra_root = 0, empty_pw = 0;
    char msg[200];

    printf("\nUser accounts\n");

    /* Part one: /etc/passwd - anyone besides root with user id 0
     * is a full administrator, whatever the account is called. */
    fp = fopen("/etc/passwd", "r");
    if (fp != NULL) {
        while (fgets(line, sizeof line, fp) != NULL) {
            first = strchr(line, ':');
            if (first == NULL) continue;
            second = strchr(first + 1, ':');
            if (second == NULL) continue;
            third = strchr(second + 1, ':');
            if (third == NULL) continue;

            uid = strtol(second + 1, NULL, 10);
            if (uid == 0) {
                *first = '\0';
                if (strcmp(line, "root") != 0) {
                    extra_root++;
                    sprintf(msg, "account '%.60s' has full administrator power (user id 0) but is not root. That is either deliberate and unusual, or a break-in.", line);
                    risk(msg);
                }
            }
        }
        fclose(fp);
        if (extra_root == 0)
            ok("only 'root' has administrator-level user id. As it should be.");
    } else {
        look("could not read the account list (/etc/passwd).");
    }

    /* Part two: /etc/shadow - an empty second field means that
     * account can log in with no password at all. */
    fp = fopen("/etc/shadow", "r");
    if (fp == NULL) {
        look("password check skipped - run me with sudo to verify no account has an empty password.");
        return;
    }
    while (fgets(line, sizeof line, fp) != NULL) {
        /* The password lives between the first and second colon.
         * "user::rest" means that field is empty - no password. */
        first = strchr(line, ':');
        if (first != NULL && first[1] == ':') {
            *first = '\0';
            empty_pw++;
            sprintf(msg, "account '%.60s' has NO password. Anyone at the keyboard can become them. Set a password or lock the account today.", line);
            risk(msg);
        }
    }
    fclose(fp);
    if (empty_pw == 0)
        ok("every account has a password set.");
}

/* ----------------------------------------------------------------
 * Check 5: system configuration files anyone can edit.
 * A world-writable file in /etc means any user - or any program a
 * user accidentally runs - can rewrite system behaviour.
 * ---------------------------------------------------------------- */
static int ww_found = 0;

static void scan_world_writable(const char *dir, int depth)
{
    DIR *d;
    struct dirent *entry;
    struct stat st;
    char path[1024];
    char msg[1200];

    if (depth > 2 || ww_found >= 5)
        return;

    d = opendir(dir);
    if (d == NULL)
        return;

    while ((entry = readdir(d)) != NULL && ww_found < 5) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        if (strlen(dir) + strlen(entry->d_name) + 2 > sizeof path)
            continue;
        sprintf(path, "%s/%s", dir, entry->d_name);

        if (lstat(path, &st) != 0)
            continue;
        if (S_ISLNK(st.st_mode))
            continue;

        if (S_ISREG(st.st_mode) && (st.st_mode & S_IWOTH)) {
            ww_found++;
            sprintf(msg, "'%s' can be modified by every user on this machine. System files should not be open to everyone - worth fixing.", path);
            risk(msg);
        }
        if (S_ISDIR(st.st_mode))
            scan_world_writable(path, depth + 1);
    }
    closedir(d);
}

static void check_world_writable(void)
{
    printf("\nSystem files anyone can edit\n");
    ww_found = 0;
    scan_world_writable("/etc", 0);
    if (ww_found == 0)
        ok("no system configuration files are open for everyone to edit.");
    else if (ww_found >= 5)
        look("stopped listing after five findings - there may be more. This machine needs a proper permissions cleanup.");
}

/* ---------------------------------------------------------------- */
int main(void)
{
    printf("plain-check: a quick look at this machine, in plain English.\n");
    printf("(read-only - nothing on the system is changed)\n");

    check_disk();
    check_uptime();
    check_ports();
    check_accounts();
    check_world_writable();

    printf("\n----------------------------------------------------------\n");
    printf("Summary: %d fine, %d worth a look, %d real risk(s).\n",
           n_ok, n_look, n_risk);

    if (n_risk > 0)
        printf("The [RISK] lines above are the ones to act on this week.\n");
    else if (n_look > 0)
        printf("Nothing alarming. The [LOOK] items are worth ten minutes sometime soon.\n");
    else
        printf("This machine looks healthy. Check again in a month.\n");

    return (n_risk > 0) ? 2 : (n_look > 0) ? 1 : 0;
}
