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

## Run the app (optional)

If you want to interact with MetricsHub in a browser while you triage:

```bash
# create and activate a virtual environment (recommended)
python3 -m venv sastvenv
source sastvenv/bin/activate      # Windows: sastvenv\Scripts\activate

# install dependencies
pip install -r requirements.txt

# start the dev server
flask --app app run --debug --port 5001
```

The app will be available at <http://127.0.0.1:5001>.

> Port 5000 may be reserved on your machine. Use `--port 5001` or any other free port.

> Running the app is not required — every challenge can be worked through by reading
> the code and the scan output alone.

---

## Run the scan

From the **exercise directory** (`SAST-False-Positives/`):

```bash
semgrep scan --config p/default
```

You'll get **18 findings** across six locations (several lines trip more than one
rule). Work through each challenge below before reading the verdict.

> **Important:** run this command from inside the `SAST-False-Positives/` directory.
> Running it from a parent directory will scan unrelated files and produce many more findings.

### Save output to a file

Plain text (same as terminal output):
```bash
semgrep scan --config p/default --output findings.txt
```

Compact one-line-per-finding summary:
```bash
semgrep scan --config p/default --json \
  | jq -r '.results[] | "\(.path):\(.start.line)  \(.check_id | split(".") | last)"' \
  | sort -u | tee findings-summary.txt
```

Full JSON (machine-readable, preserves all metadata):
```bash
semgrep scan --config p/default --json --output findings.json
```

---

## The challenges

For each finding, trace the data flow from source to sink and decide: can user-controlled
input actually reach the dangerous operation? If not, it is a false positive.

### Challenge 1 — concatenated SQL
**Where:** `metricshub/queries.py` → `count_active_users`, `recent_signups`
**Semgrep says:** `formatted-sql-query`, `sqlalchemy-execute-raw-query`

The rules flag *any* string-built query, regardless of where the data comes from.
Look at what values are actually interpolated into these queries.

**Note the nuance:** the same constant-SQL pattern in Ruby or JavaScript would
**not** be flagged by those registry rules — a reminder that "is it flagged?" depends
on the rule's engine, not just the code.

### Challenge 2 — reflected input
**Where:** `app.py` → `/hello`
**Semgrep says:** `raw-html-format`, `directly-returned-format-string`

The user's `name` is processed before it reaches the response. Read the line carefully —
what does `markupsafe.escape()` do to `& < > " '`?

### Challenge 3 — user input into SQL
**Where:** `app.py` → `/users` (guard clause) and `/users/v2` (sanitiser)
**Semgrep says:** `tainted-sql-string`, `sql-injection-db-cursor-execute`,
`sqlalchemy-execute-raw-query`

The `sort` column really does come from `request.args`, so taint-based rules correctly
trace it to the query. Look at what happens to it *between* the request and the query:
- `/users` uses a **guard clause** — what does it check? Can the value be anything
  other than an allow-listed column by the time it reaches the query?
- `/users/v2` uses `safe_sort()` — what does that function return?

### Challenge 4 — `shell=True`
**Where:** `metricshub/reporting.py` → `sync_exports`
**Semgrep says:** `subprocess-shell-true` / `dangerous-subprocess-use`

`shell=True` is risky when user input reaches the shell. Trace where the command
string comes from. Is any part of it user-controlled?

### Contrast — a finding that looks similar to Challenge 2
**Where:** `app.py` → `/welcome`
**Semgrep says:** `render-template-string`, `raw-html-format`

It looks almost identical to the `/hello` endpoint: user input, `escape()`, returned
as HTML. What is different about how the response is generated here? Does `escape()`
protect against the same things in both cases?

---

## Reducing false positives

Apply these roughly in order. The goal is a quiet, trustworthy scan — not a silent one.

### 0. Triage before you suppress
Understand the data flow first. A finding is only an FP once you can articulate *why*
the dangerous input can't reach the sink. Suppressing on a hunch is how real bugs ship.

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
semgrep scan --config p/default --exclude 'tests/fixtures/*'
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
Often the cleanest "FP reduction" is to remove the risky shape entirely:
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
Prefer curated, intentional rulesets (`--config p/default`, a pinned ruleset, or your
own pack) over a kitchen-sink scan. Filter by severity/confidence when you need signal
fast: `--severity ERROR`.

---

## Summary table

| # | Location | Rule(s) | Action |
|---|----------|---------|--------|
| 1 | `queries.py` (active/signups) | formatted-sql-query, sqlalchemy-execute-raw-query | `# nosemgrep` + comment, or parameterise |
| 2 | `/hello` | raw-html-format, directly-returned-format-string | `# nosemgrep`, or render via template |
| 3 | `/users`, `/users/v2` | tainted-sql-string, sql-injection-db-cursor-execute | Custom taint rule w/ `safe_sort` sanitiser |
| 4 | `reporting.py` | subprocess-shell-true | `# nosemgrep`, or `shell=False` + list |
| 5 | `/welcome` | render-template-string, raw-html-format | See answer key below |

### Key takeaways
- **Know the engine.** Pattern-based rules flag a *shape* (Challenge 1 fires even with
  zero user input); taint-based rules follow *data flow* (Challenge 3) but miss
  validation they can't model.
- **A false positive is not "ignore me" — it's "explain me."** You only know it's an FP
  once you've traced the data flow.
- **Never blanket-suppress.** Suppress specific, reviewed findings — with a reason.
- **Tune, don't just mute.** Encoding your sanitisers as rules fixes the whole class of
  noise and keeps catching the real thing.

### Discovery methods
- **Manual triage:** read each finding, trace input → sink, decide FP vs TP.
- **Code review:** the validators and constants that make findings safe live a few lines
  (or one function) away from the sink.
- **Tooling:** re-run with the tuned rule and with suppressions to confirm the scan goes
  quiet *without* dropping the true positive.

---

---

## Answer key

> **Stop here if you haven't worked through the challenges yet.**

<details>
<summary>Reveal verdicts</summary>

| # | Location | Verdict | Reason |
|---|----------|---------|--------|
| 1 | `queries.py` | **FALSE POSITIVE** | Only module constants are interpolated — no user input reaches the query. Rules are pattern-based and fire regardless of data origin. |
| 2 | `/hello` | **FALSE POSITIVE** | `markupsafe.escape()` converts `& < > " '` to HTML entities. The value renders as inert text; no XSS. |
| 3 | `/users`, `/users/v2` | **FALSE POSITIVE** | The taint trace is real, but `/users` rejects any value not on the allow-list before it reaches the query; `/users/v2` returns a provably safe literal from `safe_sort()`. |
| 4 | `reporting.py` | **FALSE POSITIVE** | The shell command is assembled from module constants and a fixed dict — no user-controlled data reaches the shell. |
| 5 | `/welcome` | **TRUE POSITIVE — do not suppress** | `escape()` neutralises HTML characters but does **not** escape `{{ }}`. `render_template_string` evaluates Jinja, so input like `{{7*7}}` executes on the server — **Server-Side Template Injection (SSTI)**. Fix it; don't suppress it. |

The lesson: two findings can look identical to a scanner *and* to a careless reviewer
(`/hello` vs `/welcome`). Only tracing the data flow reveals which is real.

</details>
