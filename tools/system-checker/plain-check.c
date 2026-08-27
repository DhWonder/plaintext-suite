/*
 * plain-check - what is this machine, and is anything wrong with it?
 *               Reported in plain English.
 *
 * Two jobs in one run, in the order you actually need them:
 *
 *   1. What am I looking at.  Make and model, operating system, processor,
 *      memory, graphics, disks, network, and whether this is real hardware
 *      or a virtual machine. This is the part you want when you sit down at
 *      an unfamiliar machine and need to know what it is before you touch
 *      anything.
 *
 *   2. Is anything wrong.  Full disks, forgotten open ports, accounts with
 *      no password, system files anyone can edit. The short list of things
 *      that actually bite small businesses.
 *
 * It only ever READS. It changes nothing on the machine, starts nothing,
 * and sends nothing anywhere.
 *
 * Build:  make            (or: cc -ansi -pedantic -Wall -Wextra -o plain-check plain-check.c)
 * Run:    ./plain-check               everything
 *         ./plain-check --what        just what the machine is
 *         ./plain-check --check       just the health and security checks
 *
 * Run it with sudo if you want the password check to work; without it the
 * tool says so rather than quietly skipping.
 *
 * Everything here comes from files the kernel already publishes: /proc,
 * /sys and /etc. No commands are run, nothing is installed, and if a file
 * is missing the tool says it could not tell rather than inventing a value.
 *
 * This one is Linux. For a Windows machine use windows-check.ps1 in this
 * same folder, which asks Windows the same questions and prints the same
 * report. `sh system-check.sh` will ask you which you are looking at.
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
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>

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

/* A plain fact, with no judgement attached. The inventory half of the
 * report is all facts: it is describing the machine, not grading it. */
static void fact(const char *label, const char *value)
{
    printf("  %-14s %s\n", label, value);
}

/* ================================================================
 * Small helpers for reading the files the kernel publishes.
 * Every one of them fails quietly and lets the caller say
 * "could not tell", because a made up number is worse than a gap.
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

/* Read the first line of a file. Returns 1 on success. */

/* Find "key" in a "key: value" or "key=value" file and return its value.
 * Used for /proc/cpuinfo, /proc/meminfo and /etc/os-release, which are
 * three different shapes of the same idea. */
static int read_field(const char *path, const char *key, char sep,
                      char *out, size_t max)
{
    FILE *fp;
    char line[512];
    size_t keylen = strlen(key);
    char *value;

    out[0] = '\0';
    fp = fopen(path, "r");
    if (fp == NULL)
        return 0;

    while (fgets(line, sizeof line, fp) != NULL) {
        if (strncmp(line, key, keylen) != 0)
            continue;
        value = strchr(line + keylen, sep);
        if (value == NULL)
            continue;
        value++;
        trim(value);
        /* os-release quotes its values. Nobody wants to read the quotes. */
        if (value[0] == '"') {
            size_t vlen;
            value++;
            vlen = strlen(value);
            if (vlen > 0 && value[vlen - 1] == '"')
                value[vlen - 1] = '\0';
        }
        strncpy(out, value, max - 1);
        out[max - 1] = '\0';
        fclose(fp);
        return out[0] != '\0';
    }
    fclose(fp);
    return 0;
}

/* Does this path exist at all? Some questions are answered by the mere
 * presence of a file, and asking "does it contain nothing" to mean that
 * is the kind of cleverness that confuses the next reader. */
static int file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/* Does a file exist and contain this text? For the small yes/no questions. */
static int file_contains(const char *path, const char *needle)
{
    FILE *fp;
    char line[512];

    fp = fopen(path, "r");
    if (fp == NULL)
        return 0;
    while (fgets(line, sizeof line, fp) != NULL) {
        if (strstr(line, needle) != NULL) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

/* Turn a size in kilobytes into something a person reads without counting
 * digits. Memory and disks are the two places raw byte counts help nobody. */
static void human_kb(double kb, char *out, size_t max)
{
    if (kb >= 1024.0 * 1024.0)
        sprintf(out, "%.1f GB", kb / (1024.0 * 1024.0));
    else if (kb >= 1024.0)
        sprintf(out, "%.0f MB", kb / 1024.0);
    else
        sprintf(out, "%.0f KB", kb);
    (void)max;
}

/* ================================================================
 * PART ONE: what is this machine.
 * ================================================================ */

/* ----------------------------------------------------------------
 * The operating system, and how old the running kernel is.
 * ---------------------------------------------------------------- */
static void report_os(void)
{
    struct utsname u;
    char value[256];
    char msg[512];

    printf("\nOperating system\n");

    if (read_field("/etc/os-release", "PRETTY_NAME", '=', value, sizeof value))
        fact("distribution", value);
    else if (read_field("/etc/os-release", "NAME", '=', value, sizeof value))
        fact("distribution", value);
    else
        fact("distribution", "could not tell (no /etc/os-release)");

    if (uname(&u) == 0) {
        sprintf(msg, "%.60s %.80s", u.sysname, u.release);
        fact("kernel", msg);
        fact("architecture", u.machine);
        fact("hostname", u.nodename);
    } else {
        fact("kernel", "could not tell");
    }

    /* Worth knowing before you trust anything else on the box. */
    if (read_line("/proc/sys/kernel/tainted", value, sizeof value)) {
        if (strcmp(value, "0") != 0)
            fact("kernel state", "tainted (out of tree or proprietary modules loaded)");
    }
}

/* ----------------------------------------------------------------
 * Make, model and serial. The first thing anybody asks about a machine
 * they have been handed, and the thing that goes on the invoice.
 * ---------------------------------------------------------------- */
static void report_machine(void)
{
    char vendor[256], product[256], serial[256], bios[256], board[256];
    char msg[600];
    int have_any = 0;

    printf("\nThe machine itself\n");

    vendor[0] = product[0] = serial[0] = bios[0] = board[0] = '\0';
    read_line("/sys/class/dmi/id/sys_vendor", vendor, sizeof vendor);
    read_line("/sys/class/dmi/id/product_name", product, sizeof product);
    read_line("/sys/class/dmi/id/product_serial", serial, sizeof serial);
    read_line("/sys/class/dmi/id/bios_version", bios, sizeof bios);
    read_line("/sys/class/dmi/id/board_name", board, sizeof board);

    if (vendor[0] != '\0' || product[0] != '\0') {
        sprintf(msg, "%.200s %.200s",
                vendor[0] ? vendor : "", product[0] ? product : "");
        trim(msg);
        fact("make and model", msg);
        have_any = 1;
    }
    if (board[0] != '\0') {
        fact("mainboard", board);
        have_any = 1;
    }
    if (bios[0] != '\0') {
        fact("firmware", bios);
        have_any = 1;
    }

    /* The serial is worth having on an invoice, and is readable only by
     * root on most systems. Only worth mentioning at all on a machine that
     * publishes hardware details in the first place: saying "serial not
     * readable" about a container is noise. */
    if (serial[0] != '\0') {
        fact("serial", serial);
        have_any = 1;
    } else if (have_any) {
        fact("serial", "not readable (run with sudo to see it)");
    }

    if (!have_any)
        fact("hardware", "nothing published - normal in a container or a "
                         "virtual machine with no firmware details");
}

/* ----------------------------------------------------------------
 * Real hardware, a virtual machine, or a container?
 * This changes what every other number means, so it comes early.
 * ---------------------------------------------------------------- */
static void report_virtual(void)
{
    char product[256];
    char msg[400];
    const char *found = NULL;

    printf("\nReal or virtual\n");

    /* A container first: it is the case people most often miss, because
     * everything else looks like the host it is running on. */
    if (file_contains("/proc/1/cgroup", "docker") ||
        file_contains("/proc/1/cgroup", "containerd")) {
        fact("running in", "a Docker or containerd container");
        ok("this is a container, so the disks, memory and ports below belong "
           "to the host as much as to this. Read them with that in mind.");
        return;
    }
    if (file_contains("/proc/1/cgroup", "lxc")) {
        fact("running in", "an LXC container");
        return;
    }
    if (file_contains("/proc/1/environ", "container=") ||
        file_exists("/run/systemd/container") ||
        file_exists("/.dockerenv")) {
        fact("running in", "a container");
        return;
    }

    /* Then a virtual machine, named by whatever the firmware admits to. */
    product[0] = '\0';
    read_line("/sys/class/dmi/id/product_name", product, sizeof product);
    if (strstr(product, "VMware") != NULL)            found = "VMware";
    else if (strstr(product, "VirtualBox") != NULL)   found = "VirtualBox";
    else if (strstr(product, "KVM") != NULL)          found = "KVM";
    else if (strstr(product, "QEMU") != NULL)         found = "QEMU";
    else if (strstr(product, "Hyper-V") != NULL)      found = "Hyper-V";
    else if (strstr(product, "Virtual Machine") != NULL) found = "a hypervisor";
    else if (strstr(product, "Droplet") != NULL)      found = "DigitalOcean";
    else if (strstr(product, "Google") != NULL)       found = "Google Cloud";
    else if (strstr(product, "Amazon") != NULL)       found = "Amazon EC2";

    if (found == NULL && file_contains("/proc/cpuinfo", "hypervisor"))
        found = "a hypervisor the firmware does not name";

    if (found != NULL) {
        sprintf(msg, "a virtual machine on %s", found);
        fact("running on", msg);
    } else {
        fact("running on", "real hardware, as far as this can tell");
    }
}

/* ----------------------------------------------------------------
 * The processor. Model, how many of them, and whether the machine can
 * run virtual machines of its own.
 * ---------------------------------------------------------------- */
static void report_cpu(void)
{
    FILE *fp;
    char line[512];
    char model[256];
    char vendor[256];
    char mhz[64];
    char msg[400];
    int logical = 0;
    int physical_ids[64];
    int physical_count = 0;
    int i, seen;
    long id;

    printf("\nProcessor\n");

    model[0] = vendor[0] = mhz[0] = '\0';
    read_field("/proc/cpuinfo", "model name", ':', model, sizeof model);
    read_field("/proc/cpuinfo", "vendor_id", ':', vendor, sizeof vendor);
    read_field("/proc/cpuinfo", "cpu MHz", ':', mhz, sizeof mhz);

    /* Count the logical processors, and the distinct physical chips.
     * "8 cores" means something different on one socket and on two. */
    fp = fopen("/proc/cpuinfo", "r");
    if (fp != NULL) {
        while (fgets(line, sizeof line, fp) != NULL) {
            if (strncmp(line, "processor", 9) == 0)
                logical++;
            if (strncmp(line, "physical id", 11) == 0) {
                char *colon = strchr(line, ':');
                if (colon == NULL)
                    continue;
                id = strtol(colon + 1, NULL, 10);
                seen = 0;
                for (i = 0; i < physical_count; i++)
                    if (physical_ids[i] == (int)id)
                        seen = 1;
                if (!seen && physical_count < 64)
                    physical_ids[physical_count++] = (int)id;
            }
        }
        fclose(fp);
    }

    if (model[0] != '\0')
        fact("model", model);
    else if (vendor[0] != '\0')
        fact("model", vendor);
    else
        fact("model", "could not tell (no /proc/cpuinfo)");

    if (logical > 0) {
        if (physical_count > 1)
            sprintf(msg, "%d logical processors across %d physical chips",
                    logical, physical_count);
        else
            sprintf(msg, "%d logical processors", logical);
        fact("count", msg);
    }

    if (mhz[0] != '\0') {
        sprintf(msg, "%.20s MHz as measured right now", mhz);
        fact("speed", msg);
    }

    /* Can this machine host virtual machines? Worth knowing before you
     * promise a client it can. */
    if (file_contains("/proc/cpuinfo", " vmx") ||
        file_contains("/proc/cpuinfo", " svm"))
        fact("virtualisation", "supported by the processor");
    else
        fact("virtualisation", "not available (or turned off in firmware)");
}

/* ----------------------------------------------------------------
 * Memory. How much is fitted, how much is genuinely free, and whether
 * there is swap to fall back on.
 * ---------------------------------------------------------------- */
static void report_memory(void)
{
    char value[128];
    char human[64];
    char msg[400];
    double total = 0.0, available = 0.0, swap = 0.0;

    printf("\nMemory\n");

    if (read_field("/proc/meminfo", "MemTotal", ':', value, sizeof value))
        total = atof(value);
    if (read_field("/proc/meminfo", "MemAvailable", ':', value, sizeof value))
        available = atof(value);
    if (read_field("/proc/meminfo", "SwapTotal", ':', value, sizeof value))
        swap = atof(value);

    if (total <= 0.0) {
        fact("fitted", "could not tell (no /proc/meminfo)");
        return;
    }

    human_kb(total, human, sizeof human);
    fact("fitted", human);

    if (available > 0.0) {
        human_kb(available, human, sizeof human);
        sprintf(msg, "%s (%.0f%% of the total)", human, 100.0 * available / total);
        fact("free right now", msg);

        /* A machine with almost nothing left is slow in a way people
         * describe as "the computer is old". Usually it is not. */
        if (available / total < 0.10) {
            sprintf(msg, "only %.0f%% of memory is free. This machine will feel "
                         "slow, and it is memory, not age.", 100.0 * available / total);
            look(msg);
        }
    }

    if (swap > 0.0) {
        human_kb(swap, human, sizeof human);
        fact("swap", human);
    } else {
        fact("swap", "none configured");
    }
}

/* ----------------------------------------------------------------
 * Graphics. Read from the PCI ids the kernel exposes, so it works
 * with no drivers installed and no commands run.
 * ---------------------------------------------------------------- */
static const char *pci_vendor_name(const char *id)
{
    if (strcmp(id, "0x10de") == 0) return "NVIDIA";
    if (strcmp(id, "0x1002") == 0) return "AMD";
    if (strcmp(id, "0x1022") == 0) return "AMD";
    if (strcmp(id, "0x8086") == 0) return "Intel";
    if (strcmp(id, "0x1a03") == 0) return "ASPEED (server management chip)";
    if (strcmp(id, "0x102b") == 0) return "Matrox (server management chip)";
    if (strcmp(id, "0x15ad") == 0) return "VMware (virtual display)";
    if (strcmp(id, "0x1234") == 0) return "QEMU (virtual display)";
    if (strcmp(id, "0x1414") == 0) return "Microsoft (virtual display)";
    return NULL;
}

static void report_gpu(void)
{
    DIR *d;
    struct dirent *entry;
    char path[512];
    char vendor[64], device[64];
    char msg[400];
    const char *name;
    int found = 0;

    printf("\nGraphics\n");

    d = opendir("/sys/class/drm");
    if (d == NULL) {
        fact("graphics", "could not tell (no /sys/class/drm on this kernel)");
        return;
    }

    while ((entry = readdir(d)) != NULL) {
        /* card0, card1 ... and not card0-HDMI-A-1, which is an output
         * on a card we have already counted. */
        if (strncmp(entry->d_name, "card", 4) != 0)
            continue;
        if (strchr(entry->d_name, '-') != NULL)
            continue;

        sprintf(path, "/sys/class/drm/%.100s/device/vendor", entry->d_name);
        if (!read_line(path, vendor, sizeof vendor))
            continue;
        sprintf(path, "/sys/class/drm/%.100s/device/device", entry->d_name);
        read_line(path, device, sizeof device);

        name = pci_vendor_name(vendor);
        if (name != NULL)
            sprintf(msg, "%s (PCI id %.20s:%.20s)", name, vendor, device);
        else
            sprintf(msg, "PCI vendor %.20s, device %.20s", vendor, device);
        fact(found == 0 ? "display" : "also", msg);
        found++;
    }
    closedir(d);

    if (found == 0)
        fact("display", "none found - normal on a server with no graphics chip");
}

/* ----------------------------------------------------------------
 * Storage. The physical drives, and how full each mounted filesystem is.
 * ---------------------------------------------------------------- */
static void report_storage(void)
{
    DIR *d;
    struct dirent *entry;
    FILE *fp;
    char path[512];
    char size_text[64], model[256], rotational[16];
    char human[64];
    char msg[500];
    char line[1024];
    char device[256], mount[256], type[128];
    double sectors;
    struct statvfs vfs;
    int found = 0, shown = 0;

    printf("\nStorage\n");

    /* The drives themselves. /sys/block lists them; size is in 512 byte
     * sectors, which is the one unit here nobody guesses right. */
    d = opendir("/sys/block");
    if (d != NULL) {
        while ((entry = readdir(d)) != NULL) {
            if (entry->d_name[0] == '.')
                continue;
            /* Skip loop, ram and device mapper entries: they are real to
             * the kernel but they are not drives anybody bought. */
            if (strncmp(entry->d_name, "loop", 4) == 0) continue;
            if (strncmp(entry->d_name, "ram", 3) == 0)  continue;
            if (strncmp(entry->d_name, "dm-", 3) == 0)  continue;
            if (strncmp(entry->d_name, "sr", 2) == 0)   continue;

            sprintf(path, "/sys/block/%.100s/size", entry->d_name);
            if (!read_line(path, size_text, sizeof size_text))
                continue;
            sectors = atof(size_text);
            if (sectors <= 0.0)
                continue;

            model[0] = '\0';
            sprintf(path, "/sys/block/%.100s/device/model", entry->d_name);
            read_line(path, model, sizeof model);

            rotational[0] = '\0';
            sprintf(path, "/sys/block/%.100s/queue/rotational", entry->d_name);
            read_line(path, rotational, sizeof rotational);

            human_kb(sectors / 2.0, human, sizeof human);   /* 512b -> KB */
            sprintf(msg, "%.20s, %s%s%s%s", entry->d_name, human,
                    model[0] ? ", " : "", model,
                    rotational[0] == '0' ? " (solid state)" :
                    rotational[0] == '1' ? " (spinning disk)" : "");
            fact(found == 0 ? "drives" : "", msg);
            found++;
        }
        closedir(d);
    }
    if (found == 0)
        fact("drives", "could not tell (no /sys/block)");

    /* Then the filesystems people actually run out of room on. */
    fp = fopen("/proc/mounts", "r");
    if (fp == NULL)
        return;
    while (fgets(line, sizeof line, fp) != NULL && shown < 8) {
        if (sscanf(line, "%255s %255s %127s", device, mount, type) != 3)
            continue;
        /* Only real filesystems on real devices. The rest is kernel
         * bookkeeping that would bury the two lines that matter. */
        if (strncmp(device, "/dev/", 5) != 0)
            continue;
        if (strcmp(type, "squashfs") == 0)
            continue;
        if (statvfs(mount, &vfs) != 0)
            continue;
        if (vfs.f_blocks == 0)
            continue;

        human_kb((double)vfs.f_blocks * (double)vfs.f_frsize / 1024.0,
                 human, sizeof human);
        sprintf(msg, "%.60s  %s, %.0f%% used  (%.40s)", mount, human,
                100.0 - (100.0 * (double)vfs.f_bavail / (double)vfs.f_blocks),
                type);
        fact(shown == 0 ? "mounted" : "", msg);
        shown++;
    }
    fclose(fp);
}

/* ----------------------------------------------------------------
 * Network. Which cards exist, what they are called, and which one the
 * machine actually sends traffic out of.
 * ---------------------------------------------------------------- */
static void report_network(void)
{
    FILE *fp;
    char line[512];
    char name[128];
    char path[512];
    char mac[64], state[64], speed[64];
    char msg[500];
    char gateway_if[128];
    char *colon;
    int found = 0;

    printf("\nNetwork\n");

    gateway_if[0] = '\0';

    /* /proc/net/route lists the default route as destination 00000000.
     * Whichever interface owns that line is the way out of the machine. */
    fp = fopen("/proc/net/route", "r");
    if (fp != NULL) {
        if (fgets(line, sizeof line, fp) != NULL) {     /* header */
            while (fgets(line, sizeof line, fp) != NULL) {
                char iface[128], dest[64];
                if (sscanf(line, "%127s %63s", iface, dest) != 2)
                    continue;
                if (strcmp(dest, "00000000") == 0) {
                    strncpy(gateway_if, iface, sizeof gateway_if - 1);
                    gateway_if[sizeof gateway_if - 1] = '\0';
                    break;
                }
            }
        }
        fclose(fp);
    }

    fp = fopen("/proc/net/dev", "r");
    if (fp == NULL) {
        fact("interfaces", "could not tell (no /proc/net/dev)");
        return;
    }
    /* Two header lines before the data starts. */
    if (fgets(line, sizeof line, fp) == NULL ||
        fgets(line, sizeof line, fp) == NULL) {
        fclose(fp);
        return;
    }

    while (fgets(line, sizeof line, fp) != NULL) {
        colon = strchr(line, ':');
        if (colon == NULL)
            continue;
        *colon = '\0';
        strncpy(name, line, sizeof name - 1);
        name[sizeof name - 1] = '\0';
        trim(name);
        if (strcmp(name, "lo") == 0)
            continue;

        mac[0] = state[0] = speed[0] = '\0';
        sprintf(path, "/sys/class/net/%.60s/address", name);
        read_line(path, mac, sizeof mac);
        sprintf(path, "/sys/class/net/%.60s/operstate", name);
        read_line(path, state, sizeof state);
        sprintf(path, "/sys/class/net/%.60s/speed", name);
        read_line(path, speed, sizeof speed);

        sprintf(msg, "%.20s  %s%s%s%s%s%s", name,
                state[0] ? state : "state unknown",
                mac[0] ? ", " : "", mac,
                (speed[0] && speed[0] != '-') ? ", " : "",
                (speed[0] && speed[0] != '-') ? speed : "",
                (speed[0] && speed[0] != '-') ? " Mbit/s" : "");
        if (strcmp(name, gateway_if) == 0)
            strcat(msg, "  <- the way out");
        fact(found == 0 ? "interfaces" : "", msg);
        found++;
    }
    fclose(fp);

    if (found == 0)
        fact("interfaces", "none besides loopback");
    if (gateway_if[0] == '\0')
        look("this machine has no default route, so it cannot reach the "
             "internet. Deliberate on an isolated box, a fault anywhere else.");
}

/* ================================================================
 * PART TWO: is anything wrong. These are the original checks, in the
 * order they were, because that order is the order somebody reads.
 * ================================================================ */

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
static void usage(void)
{
    printf("plain-check - what is this machine, and is anything wrong with it?\n\n");
    printf("  ./plain-check          both halves: what it is, then what is wrong\n");
    printf("  ./plain-check --what   just the inventory\n");
    printf("  ./plain-check --check  just the health and security checks\n");
    printf("  ./plain-check --help   this\n\n");
    printf("Run it with sudo to include the password check and the serial number.\n");
    printf("It only reads. Nothing on this machine is changed.\n\n");
    printf("This one is Linux. For a Windows machine use windows-check.ps1\n");
    printf("in this folder, or run 'sh system-check.sh' to be asked which.\n");
}

int main(int argc, char **argv)
{
    int want_what = 1;
    int want_check = 1;

    if (argc > 1) {
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            usage();
            return 0;
        } else if (strcmp(argv[1], "--what") == 0) {
            want_check = 0;
        } else if (strcmp(argv[1], "--check") == 0) {
            want_what = 0;
        } else {
            printf("I do not know the option '%s'.\n\n", argv[1]);
            usage();
            return 2;
        }
    }

    printf("plain-check: a look at this machine, in plain English.\n");
    printf("(read-only - nothing on the system is changed)\n");

    if (want_what) {
        report_os();
        report_machine();
        report_virtual();
        report_cpu();
        report_memory();
        report_gpu();
        report_storage();
        report_network();
    }

    if (want_check) {
        check_disk();
        check_uptime();
        check_ports();
        check_accounts();
        check_world_writable();
    }

    printf("\n----------------------------------------------------------\n");

    if (!want_check) {
        printf("That is what this machine is. Run without --what to check it too.\n");
        return 0;
    }

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
