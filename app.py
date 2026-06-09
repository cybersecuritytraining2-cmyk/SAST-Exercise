"""MetricsHub — Flask entrypoint and HTTP routes."""

import sqlite3

from flask import Flask, request, abort, render_template_string, Response
from markupsafe import escape

from metricshub import queries, reporting
from metricshub.validators import is_allowed_sort, safe_sort

app = Flask(__name__)


def get_cursor():
    conn = sqlite3.connect("metricshub.db")
    return conn.cursor()


@app.get("/")
def index():
    return Response("""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MetricsHub</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; padding: 2rem; }
    header { max-width: 800px; margin: 0 auto 2.5rem; }
    h1 { font-size: 1.75rem; font-weight: 700; color: #f8fafc; }
    h1 span { color: #38bdf8; }
    .subtitle { margin-top: .5rem; color: #94a3b8; font-size: .95rem; }
    .grid { max-width: 800px; margin: 0 auto; display: grid; gap: 1rem; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: .75rem; padding: 1.25rem 1.5rem; }
    .card h2 { font-size: 1rem; font-weight: 600; color: #f1f5f9; margin-bottom: .4rem; }
    .card p  { font-size: .875rem; color: #94a3b8; line-height: 1.5; }
    .links { display: flex; flex-wrap: wrap; gap: .5rem; margin-top: .85rem; }
    .links a { font-size: .8rem; font-family: monospace; background: #0f172a; color: #38bdf8;
               border: 1px solid #1e40af; border-radius: .4rem; padding: .25rem .6rem;
               text-decoration: none; transition: background .15s; }
    .links a:hover { background: #1e3a5f; }
    footer { max-width: 800px; margin: 2.5rem auto 0; font-size: .8rem; color: #475569; text-align: center; }
  </style>
</head>
<body>
  <header>
    <h1>Metrics<span>Hub</span></h1>
    <p class="subtitle">A small metrics service. Use the endpoints below to interact with the application.</p>
  </header>

  <div class="grid">

    <div class="card">
      <h2>GET /stats/active</h2>
      <p>Returns the count of currently active users.</p>
      <div class="links">
        <a href="/stats/active">/stats/active</a>
      </div>
    </div>

    <div class="card">
      <h2>GET /hello</h2>
      <p>Returns a personalised greeting. Accepts a <code>name</code> query parameter.</p>
      <div class="links">
        <a href="/hello?name=Alice">/hello?name=Alice</a>
        <a href="/hello?name=&lt;b&gt;bold&lt;/b&gt;">/hello?name=&lt;b&gt;bold&lt;/b&gt;</a>
      </div>
    </div>

    <div class="card">
      <h2>GET /welcome</h2>
      <p>Returns a welcome message. Accepts a <code>name</code> query parameter.</p>
      <div class="links">
        <a href="/welcome?name=Alice">/welcome?name=Alice</a>
        <a href="/welcome?name=world">/welcome?name=world</a>
      </div>
    </div>

    <div class="card">
      <h2>GET /users</h2>
      <p>Returns the user list. Accepts a <code>sort</code> query parameter (column name).</p>
      <div class="links">
        <a href="/users?sort=email">/users?sort=email</a>
        <a href="/users?sort=created_at">/users?sort=created_at</a>
      </div>
    </div>

    <div class="card">
      <h2>GET /users/v2</h2>
      <p>Returns the user list using the v2 query builder. Accepts a <code>sort</code> query parameter.</p>
      <div class="links">
        <a href="/users/v2?sort=email">/users/v2?sort=email</a>
        <a href="/users/v2?sort=created_at">/users/v2?sort=created_at</a>
      </div>
    </div>

    <div class="card">
      <h2>POST /admin/sync</h2>
      <p>Triggers an export sync job. Accepts a <code>kind</code> form field (<code>daily</code> or <code>weekly</code>).</p>
      <div class="links">
        <a href="#" onclick="fetch('/admin/sync',{method:'POST',body:new URLSearchParams({kind:'daily'})}).then(r=>r.json()).then(d=>alert(JSON.stringify(d)));return false;">POST /admin/sync kind=daily</a>
      </div>
    </div>

  </div>

  <footer>Run <code>semgrep scan --config p/default</code> from the exercise directory to generate the findings.</footer>
</body>
</html>""", mimetype="text/html")


@app.get("/stats/active")
def active():
    return {"active_users": queries.count_active_users(get_cursor())}


@app.get("/users")
def users():
    cur = get_cursor()
    sort = request.args.get("sort", "created_at")
    if not is_allowed_sort(sort):
        abort(400, "invalid sort column")
    rows = cur.execute("SELECT * FROM users ORDER BY " + sort).fetchall()
    return {"rows": [list(r) for r in rows]}


@app.get("/users/v2")
def users_v2():
    cur = get_cursor()
    sort = safe_sort(request.args.get("sort", "created_at"))
    rows = cur.execute("SELECT * FROM users ORDER BY " + sort).fetchall()
    return {"rows": [list(r) for r in rows]}


@app.get("/hello")
def hello():
    name = request.args.get("name", "there")
    return "<h1>Hello, " + escape(name) + "</h1>"


@app.get("/welcome")
def welcome():
    name = escape(request.args.get("name", "there"))
    return render_template_string("<h1>Welcome, " + str(name) + "</h1>")


@app.post("/admin/sync")
def sync():
    reporting.sync_exports(request.form.get("kind", "daily"))
    return {"status": "started"}


if __name__ == "__main__":
    app.run(debug=False)
