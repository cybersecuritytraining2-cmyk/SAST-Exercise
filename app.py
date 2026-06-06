"""MetricsHub — Flask entrypoint and HTTP routes.

Wires the query/render helpers to a handful of endpoints. This is where
user-controlled values (request.args) actually enter the system, so the
data-flow story for each Challenge becomes concrete here.

Run the app (optional):  flask --app app run
Scan the app (the point):  see README.md
"""

import sqlite3

from flask import Flask, request, abort, render_template_string
from markupsafe import escape

from metricshub import queries, reporting
from metricshub.validators import is_allowed_sort, safe_sort

# NOTE: Challenge 3 keeps the request value and the SQL sink in the SAME function
# on purpose, so the data flow Semgrep's taint analysis sees is explicit.

app = Flask(__name__)


def get_cursor():
    conn = sqlite3.connect("metricshub.db")
    return conn.cursor()


@app.get("/stats/active")
def active():
    # Challenge 1 lives in queries.count_active_users (constant SQL).
    return {"active_users": queries.count_active_users(get_cursor())}


@app.get("/users")
def users():
    # Challenge 3a — guard-clause validation.
    # The sort column comes from the query string, so taint rules flag the query
    # below. But we reject anything that is not an allow-listed column first, so
    # only a fixed set of literals can actually reach it — a false positive.
    cur = get_cursor()
    sort = request.args.get("sort", "created_at")
    if not is_allowed_sort(sort):
        abort(400, "invalid sort column")
    rows = cur.execute("SELECT * FROM users ORDER BY " + sort).fetchall()
    return {"rows": [list(r) for r in rows]}


@app.get("/users/v2")
def users_v2():
    # Challenge 3b — sanitiser-style validation.
    # safe_sort() can only ever return an allow-listed literal, so the value
    # reaching the query is provably safe. A custom taint rule can be taught to
    # treat safe_sort() as a sanitiser (see .semgrep/rules/), but a pattern-based
    # registry rule will still flag the raw cur.execute.
    cur = get_cursor()
    sort = safe_sort(request.args.get("sort", "created_at"))
    rows = cur.execute("SELECT * FROM users ORDER BY " + sort).fetchall()
    return {"rows": [list(r) for r in rows]}


@app.get("/hello")
def hello():
    # Challenge 2 — reflected input, HTML-escaped before output.
    # Semgrep: raw-html-format / directly-returned-format-string. But escape()
    # (markupsafe) turns & < > " ' into entities, so the value renders as inert
    # text, not markup. No XSS — false positive.
    name = request.args.get("name", "there")
    return "<h1>Hello, " + escape(name) + "</h1>"


@app.get("/welcome")
def welcome():
    # Contrast — looks almost identical to /hello, but is a GENUINE bug.
    # escape() neutralises HTML, yet render_template_string still EVALUATES
    # Jinja, and escape() does not touch `{{ }}`. Input like {{7*7}} is server-
    # side template injection. This finding is REAL — fix it, don't suppress it.
    name = escape(request.args.get("name", "there"))
    return render_template_string("<h1>Welcome, " + str(name) + "</h1>")


@app.post("/admin/sync")
def sync():
    # Challenge 4 — kicks off an export sync (command built from constants).
    reporting.sync_exports(request.form.get("kind", "daily"))
    return {"status": "started"}


if __name__ == "__main__":
    app.run(debug=False)
