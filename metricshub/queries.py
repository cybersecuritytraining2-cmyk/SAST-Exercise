"""Query builders for the analytics dashboard."""

STATUS_ACTIVE = "active"
DEFAULT_LIMIT = 100


def count_active_users(cur):
    cur.execute("SELECT COUNT(*) FROM users WHERE status = '%s'" % STATUS_ACTIVE)
    return cur.fetchone()[0]


def recent_signups(cur, days):
    return cur.execute(
        "SELECT id, name FROM users "
        "WHERE created_at > date('now', '-%d days') "
        "LIMIT %d" % (int(days), DEFAULT_LIMIT)
    ).fetchall()
