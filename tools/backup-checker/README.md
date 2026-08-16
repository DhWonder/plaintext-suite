# backup-witness

A small script that answers two questions every business should be able to answer
and almost none can:

1. **Did my backup actually run recently?**
2. **If I needed a file back, would it actually come back?**

## Why this exists

In my repair-technician years I met the same disaster over and over: a business had
"backups," the backup job had quietly died months earlier, and everyone found out on
the worst possible day. The backup software itself rarely warns you loudly enough —
it fails politely, in a log nobody reads.

A backup nobody has tested is not a backup. It's a hope.

## What it does, in plain English

**`check` mode** looks at your backup folder and tells you:

- whether anything is in it at all,
- whether something new was written recently (a daily backup that hasn't produced
  anything in 30 hours has probably stopped),
- whether the backup suddenly shrank compared to the last time you checked — a
  classic quiet sign of trouble.

**`drill` mode** does the thing almost nobody does: it picks a random file out of
the backup, compares it byte-for-byte with the original, and tells you whether a
restore would actually work. I recommend running a drill once a month. It takes
seconds and turns "I think we have backups" into "I checked."

## How to use it

```
sh backup-witness.sh check  /mnt/backup-drive/office-backup
sh backup-witness.sh drill  /mnt/backup-drive/office-backup  /home/office/documents
```

It prints a short human-readable report and ends with a verdict. No configuration
files, no installation — it's one script. (One optional extra: `--notify` emails
you the report, and that does need settings, below.)

If you want it to watch your backups automatically, run the `check` from cron and
you'll only hear from it when something needs attention (it exits silently-successful
when all is well, which cron treats as "nothing to report"):

```
0 9 * * * sh /path/to/backup-witness.sh check /mnt/backup-drive/office-backup || echo "backup needs a look"
```

That line assumes cron on this machine can email you, which on a modern server
it usually cannot. `--notify` does it directly instead:

```
sh backup-witness.sh notify setup                    write ~/.plaintext/notify.conf
sh backup-witness.sh notify test                     prove it can actually send
0 9 * * * sh /path/to/backup-witness.sh check /mnt/backup-drive/office-backup --notify
```

You hear from it when the backup has stopped, has shrunk, or a drill failed, and
the email is the same report you would have read on screen. A run that finds
nothing wrong sends nothing. It needs `notify.py`, which sits next to this
script, and python3; see [`../notifications`](../notifications).

## What it deliberately doesn't do

It doesn't replace your backup software, doesn't copy anything, and never writes to
your backup folder. It only reads and reports. The one thing it saves is a small
size-history file in `~/.backup-witness/` so it can notice shrinkage between runs.

## Honest limitations

- The restore drill tests one random file, not your whole backup. It's a smoke
  alarm, not a fire inspection. (A monthly one-file drill still puts you ahead of
  roughly everyone.)
- A MISMATCH in the drill can simply mean the file changed since the backup last
  ran — the output explains how to tell the difference.
- Works with backups that are plain folders (rsync-style, file-copy style, most
  NAS setups). Encrypted archive formats (restic, Borg) need their own check
  commands — ask me and I'll show you.

---

Written by DhWonder · Plaintext IT — technology,
translated. MIT license: use it, share it, no strings.
