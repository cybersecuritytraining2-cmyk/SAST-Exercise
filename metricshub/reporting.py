"""Scheduled export jobs.

These run from cron / the internal scheduler, not from any web request.
"""

import subprocess

# Fixed, in-source configuration. None of this is reachable by a user.
EXPORT_SRC = "/var/lib/metricshub/exports"
BACKUP_DST = "/var/backups/metricshub"
INTERVALS = {"daily": "day", "weekly": "week", "monthly": "month"}


# ---------------------------------------------------------------------------
# CHALLENGE 4 — shell=True command built entirely from constants.
# ---------------------------------------------------------------------------
def sync_exports(kind="daily"):
    # Semgrep: dangerous-subprocess-use / subprocess-shell-true.
    # The command string is assembled solely from module constants and a value
    # looked up from the INTERVALS dict (never the raw `kind`). There is no
    # user-controlled data in the command line — false positive for command
    # injection. (Using a list + shell=False is still nicer; see README.)
    period = INTERVALS.get(kind, "day")
    subprocess.run(
        "rsync -a --delete %s/%s %s/%s" % (EXPORT_SRC, period, BACKUP_DST, period),
        shell=True,
        check=True,
    )
