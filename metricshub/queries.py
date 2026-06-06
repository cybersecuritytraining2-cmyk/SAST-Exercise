"""Query builders for the analytics dashboard.

All database access goes through these helpers. They use a plain DB-API cursor
(`cur.execute`). Semgrep flags several of these for SQL injection — read each one
carefully and decide whether user input can actually reach it.
"""

# ---------------------------------------------------------------------------
# CHALLENGE 1 — "concatenated SQL" with no user input in sight.
# ---------------------------------------------------------------------------
# These status values are module constants defined right here in the source.
# Nothing a user sends can change them.
STATUS_ACTIVE = "active"
DEFAULT_LIMIT = 100


def count_active_users(cur):
    # Semgrep: formatted-sql-query / sqlalchemy-execute-raw-query.
    # The only interpolated value is the constant STATUS_ACTIVE above, so there
    # is no injection vector — this is a false positive for SQLi.
    cur.execute("SELECT COUNT(*) FROM users WHERE status = '%s'" % STATUS_ACTIVE)
    return cur.fetchone()[0]


def recent_signups(cur, days):
    # `days` comes from an internal scheduler config (an int), never from a
    # request. Still flagged because the query is string-built.
    return cur.execute(
        "SELECT id, name FROM users "
        "WHERE created_at > date('now', '-%d days') "
        "LIMIT %d" % (int(days), DEFAULT_LIMIT)
    ).fetchall()

# (Challenge 3 — validated user input — lives in app.py, where the request
#  value and the query sink sit in the same function so the data flow is
#  explicit. See the /users and /users/v2 routes.)
