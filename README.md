# SAST False Positives — a Semgrep triage exercise

SAST scanners are pattern matchers and data-flow analysers, not oracles. They flag
code that *looks* dangerous, and a large share of what they report is a **false
positive (FP)** — code that matches a risky shape but cannot actually be exploited.
Learning to triage findings — separating real bugs from noise, and tuning the
scanner so the noise stops coming back — is a core application-security skill.

This exercise is a small, realistic Flask service, **MetricsHub**, that Semgrep
flags 18 times across six code locations. Almost every finding is a false positive.
**One is a real vulnerability.** Your job is to tell them apart and then reduce the
FPs without losing the true positive.

> Companion to the OWASP and CI/CD exercises in this repo. Where those teach you to
> *find* and *exploit* bugs, this one teaches you to *judge a scanner's output*.

---

## The application

```
SAST-False-Positives/
├── app.py                       # Flask routes — where user input (request.args) enters
├── metricshub/
│   ├── queries.py               # SQL builders (Challenge 1)
│   ├── validators.py            # allow-list validators (used by Challenge 3)
│   └── reporting.py             # scheduled export jobs (Challenge 4)
├── .semgrep/rules/
│   └── sql-order-by-taint.yml   # a tuned, taint-aware replacement rule
├── .semgrepignore               # path-exclusion example
└── requirements.txt
```

It is written like a tidy real service — that is the point. Real false positives
hide in normal-looking code, not in obviously contrived snippets.

---

## Prerequisites

- **Python 3.9+**
- **Semgrep**: `pipx install semgrep` (or `pip install --user semgrep`) — see
  <https://semgrep.dev/docs/getting-started/>
- Network access the first time you run (Semgrep downloads the registry rulesets).

Installing the app's own deps is optional — you are scanning the code, not running it:
```bash
pip install -r requirements.txt   # only needed if you want to run the app
```

---

## Run the scan

From the exercise directory:

```bash
semgrep scan --config p/default --config p/python --config p/flask
```

You'll get **18 findings** across six locations (several lines trip more than one
rule). Work through each below before reading the verdict.
For a compact machine-readable view:

```bash
semgrep scan --config p/default --config p/python --config p/flask --json \
  | jq -r '.results[] | "\(.path):\(.start.line)  \(.check_id | split(".") | last)"' | sort -u
```

---

## The challenges

### Challenge 1 — "concatenated SQL", but no user input
**Where:** `metricshub/queries.py` → `count_active_users`, `recent_signups`
**Semgrep says:** `formatted-sql-query`, `sqlalchemy-execute-raw-query`
**Verdict: FALSE POSITIVE.** These rules are **pattern-based** — they match *any*
string-built query, regardless of where the data comes from. The only interpolated
values here are a module constant (`STATUS_ACTIVE`) and an integer from an internal
scheduler. No user input reaches the query, so there is no injection.
**Note the nuance:** the same constant-SQL pattern in Ruby or JavaScript would
**not** be flagged, because those registry rules are taint-based — a reminder that
"is it flagged?" depends on the rule's engine, not just the code.

### Challenge 2 — reflected input that is escaped before output
**Where:** `app.py` → `/hello`
**Semgrep says:** `raw-html-format`, `directly-returned-format-string`
**Verdict: FALSE POSITIVE.** The user's `name` is wrapped in `markupsafe.escape()`,
which converts `& < > " '` to HTML entities before it reaches the response. The
browser renders it as inert text, so there is no XSS. Semgrep sees "request data
concatenated into an HTML response" and flags the shape, not the escaping.

### Challenge 3 — user input that *is* validated first
**Where:** `app.py` → `/users` (guard clause) and `/users/v2` (sanitiser)
**Semgrep says:** `tainted-sql-string`, `sql-injection-db-cursor-execute`,
`sqlalchemy-execute-raw-query`
**Verdict: FALSE POSITIVE — and the most interesting one.** The `sort` column really
does come from `request.args`, so **taint-based** rules correctly trace it to the
query. What they miss is the validation in between:
- `/users` uses a **guard clause** (`if not is_allowed_sort(sort): abort(400)`). The
  value can only ever be an allow-listed column by the time it reaches the query —
  but because the guard doesn't *transform* the value, the taint engine can't tell.
- `/users/v2` uses `safe_sort()`, which **returns** a value that is provably one of a
  fixed set of literals. This is the form a scanner can be taught to trust (below).

### Challenge 4 — `shell=True` command built from constants
**Where:** `metricshub/reporting.py` → `sync_exports`
**Semgrep says:** `subprocess-shell-true` / `dangerous-subprocess-use`
**Verdict: FALSE POSITIVE.** The command string is assembled entirely from module
constants and a value looked up from a fixed `INTERVALS` dict — never from the raw
argument. No user-controlled data reaches the shell. (`shell=False` with a list of
args is still the better habit; see "fix the code" below.)

### Contrast — the one that is REAL
**Where:** `app.py` → `/welcome`
**Semgrep says:** `render-template-string`, `raw-html-format`
**Verdict: TRUE POSITIVE — do not suppress this.** It looks almost identical to the
`/hello` false positive: user input, escaped with `escape()`, returned as HTML. But
`render_template_string` **evaluates Jinja**, and `escape()` only touches HTML
characters — it does **not** escape `{{ }}`. Input like `{{7*7}}` (or worse) is
**server-side template injection**. The lesson: two findings can look the same to a
scanner *and* to a careless reviewer; only the data flow tells you which is real.

---

## Reducing false positives

Apply these roughly in order. The goal is a quiet, trustworthy scan — not a silent one.

### 0. Triage before you suppress
Understand the data flow first. A finding is only an FP once you can articulate *why*
the dangerous input can't reach the sink. Suppressing on a hunch is how the `/welcome`
bug ships.

### 1. Inline suppression — `# nosemgrep` (for individual, reviewed findings)
Put the comment **on the same line as the finding**:
```python
# suppress every rule on this line:
cur.execute("... ORDER BY " + sort)   # nosemgrep

# suppress one specific rule (others on the line still report) — use the FULL id:
cur.execute("... ORDER BY " + sort)   # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
```
**Verified behaviour:** bare `# nosemgrep` clears all rules on the line; the
`nosemgrep: <id>` form clears only that id, so a line with several findings needs
several ids (comma-separated) or the bare form. Always pair it with a comment saying
*why* it's safe — a naked suppression is indistinguishable from a missed bug at review.

### 2. Path exclusion — `.semgrepignore` / `--exclude`
Don't scan code you don't assess: vendored deps, generated files, migrations, test
fixtures. See the included `.semgrepignore`. One-off:
```bash
semgrep scan --config p/python --exclude 'tests/fixtures/*'
```

### 3. Tune the rule — custom taint rule with a sanitiser
The Challenge 3 findings are systematic, not one-offs, so suppressing each by hand is
the wrong tool. Instead, encode your sanitiser. The bundled
`.semgrep/rules/sql-order-by-taint.yml` is a **taint rule** that registers
`safe_sort()` as a `pattern-sanitizers` entry:
```bash
semgrep scan --config .semgrep/rules/sql-order-by-taint.yml
```
**Verified behaviour:** it flags the `/users` guard-clause path (the value isn't
transformed, so it's still suspect) and **clears** the `/users/v2` `safe_sort` path —
while still catching any genuinely unvalidated query. To adopt it, run your tuned rule
*instead of* the noisy registry rule (exclude the latter with `--exclude-rule <id>` or
a curated config that omits it).
> Takeaway: a guard clause is hard for a taint engine to trust; a sanitiser that
> **returns a known-good value** is both easier to verify and better security design.

### 4. Fix the code so the finding is true *and* gone
Often the cleanest "FP reduction" is to remove the risky shape entirely — which also
removes the real risk class:
- **Parameterise** queries: `cur.execute("... WHERE status = ?", (status,))` instead of `%`-formatting.
- For dynamic identifiers (ORDER BY), map through an allow-list that **returns** the column (`safe_sort`).
- **`shell=False`** with a list: `subprocess.run(["rsync", "-a", src, dst])`.
- Render via **templates** (Jinja auto-escapes) rather than hand-built HTML strings.

### 5. Baseline & platform triage (for existing codebases / CI)
- `semgrep scan --baseline-commit <sha>` reports only findings **new** since that
  commit, so a backlog of known FPs doesn't drown new signal.
- In the Semgrep AppSec Platform (or GitHub code scanning), triage a finding as
  *ignored / false positive* **with a reason**; the decision sticks across scans and
  is auditable — better than scattering suppressions through the code.

### 6. Config hygiene
Prefer curated, intentional rulesets (`--config p/python`, a pinned ruleset, or your
own pack) over a kitchen-sink scan. Filter by severity/confidence when you need signal
fast: `--severity ERROR`.

---

## Summary

| # | Location | Rule(s) | Verdict | Action |
|---|----------|---------|---------|--------|
| 1 | `queries.py` (active/signups) | formatted-sql-query, sqlalchemy-execute-raw-query | False positive (no user input) | `# nosemgrep` + comment, or parameterise |
| 2 | `/hello` | raw-html-format, directly-returned-format-string | False positive (escaped) | `# nosemgrep`, or render via template |
| 3 | `/users`, `/users/v2` | tainted-sql-string, sql-injection-db-cursor-execute | False positive (validated) | Custom taint rule w/ `safe_sort` sanitiser |
| 4 | `reporting.py` | subprocess-shell-true | False positive (constants only) | `# nosemgrep`, or `shell=False` + list |
| ⚠ | `/welcome` | render-template-string, raw-html-format | **TRUE POSITIVE (SSTI)** | **Fix it** — don't render user input as a template |

### Key takeaways
- **Know the engine.** Pattern-based rules flag a *shape* (Challenge 1 fires even with
  zero user input); taint-based rules follow *data flow* (Challenge 3) but miss
  validation they can't model.
- **A false positive is not "ignore me" — it's "explain me."** You only know it's an FP
  once you've traced the data flow.
- **Never blanket-suppress.** The `/welcome` SSTI is one careless `# nosemgrep` away
  from shipping. Suppress specific, reviewed findings — with a reason.
- **Tune, don't just mute.** Encoding your sanitisers as rules fixes the whole class of
  noise and keeps catching the real thing.

### Discovery methods
- **Manual triage:** read each finding, trace input → sink, decide FP vs TP.
- **Code review:** the validators and constants that make findings safe live a few lines
  (or one function) away from the sink.
- **Tooling:** re-run with the tuned rule and with suppressions to confirm the scan goes
  quiet *without* dropping the true positive.
