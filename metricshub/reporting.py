"""Scheduled export jobs."""

import subprocess

EXPORT_SRC = "/var/lib/metricshub/exports"
BACKUP_DST = "/var/backups/metricshub"
INTERVALS = {"daily": "day", "weekly": "week", "monthly": "month"}


def sync_exports(kind="daily"):
    period = INTERVALS.get(kind, "day")
    subprocess.run(
        "rsync -a --delete %s/%s %s/%s" % (EXPORT_SRC, period, BACKUP_DST, period),
        shell=True,
        check=True,
    )
