# PostgreSQL Query Logs
Tags: #tooling #postgresql #database #logging #sql-injection #methodology

## Why This Matters

When you can read what the database actually receives, source code stops being theory. A line of Java that *looks* like it concatenates a string can still end up parameterized, and vice versa. The query log is the **ground truth** — whatever shows up here is exactly what hit the SQL parser, with no abstraction in the way.

The log turns auditing into a feedback loop:

```
You read the source         → "this looks vulnerable"
You send a request          → "let's see what happens"
You watch the log           → "ah, here's what the DB actually got"
You compare to your guess   → confirm or revise
```

That loop is the entire reason database logging matters to an attacker.

## The Forever Hook

> **"Source code is the recipe. The query log is the meal. Always check what the kitchen actually served."**

## What "Parameterized vs Concatenated" Looks Like in the Log

This is the single most useful pattern to recognize. When PostgreSQL logs an executed statement, the *shape* of the query tells you instantly whether the developer used a placeholder or glued user input straight into the string.

```sql
-- ✅ PARAMETERIZED — safe
SELECT * FROM users WHERE email = $1
-- The $1 is a real placeholder. The actual value travels in a
-- separate "Bind" message and never touches the SQL parser as syntax.

-- ❌ CONCATENATED — vulnerable
SELECT * FROM users WHERE email = 'attacker@evil.com'
-- The literal value is baked directly into the SQL string.
-- If you can change what's inside the quotes, you can break out of them.
```

| What you see in the log | What it means |
|---|---|
| `$1`, `$2`, `$3` (or `?` on other DBs) | Parameterized — your payload is being passed as data, not code |
| Quoted literal that *exactly matches what you typed* | Concatenated — your payload is being parsed as SQL |
| Quoted literal that's been escaped/cleaned | Some sanitization layer in between — investigate it |

If your payload appears as `$1` no matter what you send, that endpoint is not SQL-injectable on that parameter — stop wasting time and move on. If your payload appears inline as a quoted (or unquoted) literal, you have a candidate.

## The Two-Terminal Exploit Workspace

The fastest feedback loop in the world is:

```
┌─────────────────────────────┐   ┌─────────────────────────────┐
│ TERMINAL 1                  │   │ TERMINAL 2                  │
│ curl / Burp Repeater /      │   │ tail -f postgresql-*.log    │
│ browser sending payloads    │   │ live stream of every query  │
└─────────────────────────────┘   └─────────────────────────────┘
```

Send a payload on the left. Watch the exact SQL the server built on the right. Send another payload. Watch again. Within thirty seconds you know exactly how your input is being mangled, escaped, or passed through.

```bash
# Stream the log live
tail -f /var/lib/postgresql/data/log/postgresql-*.log

# Same idea, polled — useful when tail -f buffers oddly
watch -n 1 "tail -n 20 /var/lib/postgresql/data/log/postgresql-*.log"

# Filter to just statements involving a target table
tail -f /var/lib/postgresql/data/log/postgresql-*.log | grep -i "users"
```

## Enabling Logging — The Settings That Matter

PostgreSQL doesn't log statements by default. Configuration lives in `postgresql.conf`. Edit, then `SELECT pg_reload_conf();` (or restart) to apply.

| Setting | What it does | Recommended for audit |
|---|---|---|
| `logging_collector = on` | Turns on the background process that writes logs to files. Without this, logs only go to stderr. | **on** |
| `log_statement = 'all'` | Which statements to log. `none`, `ddl`, `mod`, or `all`. `all` captures every SELECT/INSERT/UPDATE/DELETE — what you want. | **'all'** |
| `log_directory = 'log'` | Where the log files live (relative to the data directory unless absolute). | leave default or set absolute |
| `log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'` | Filename pattern with `strftime` substitutions. | leave default |
| `log_min_duration_statement = 0` | Log every statement *with its execution time*. `0` = log all, `-1` = disabled. | **0** for full visibility |
| `log_line_prefix = '%m [%p] %q%u@%d '` | Per-line prefix — timestamp, PID, user, database. Helps you correlate sessions. | enable user/db fields |
| `log_connections = on` / `log_disconnections = on` | Logs every connection setup/teardown — see `application_name`, client IP, auth method. | **on** |

After enabling, find the active log file:

```bash
# Inside the container / box
ls -lt /var/lib/postgresql/data/log/ | head

# Or ask Postgres itself
psql -c "SELECT pg_current_logfile();"
```

## Reading a Connection Line — The `application_name` Field

When `log_connections = on`, PostgreSQL records who connected and how. One of the fields is `application_name`, a free-text label the *client* sends during connection setup. It exists so DBAs can tell which app is doing what (`psql`, `pgAdmin`, `myapp-backend`, etc.).

```
2026-04-09 10:23:14.521 UTC [4421] LOG:  connection authorized:
  user=bluebird database=bluebird application_name=PostgreSQL JDBC Driver
```

Why this is interesting:

- It tells you **what client library the application is using** — JDBC, psycopg2, libpq, Npgsql — which fingerprints the backend stack.
- The client controls it. If you ever get to influence a connection string (config file write, SSRF to a Postgres-aware service), you can set it to anything — including payloads aimed at log-injection or analytics dashboards that render it.
- It's a free reconnaissance signal: if you're auditing a Spring Boot app and the log says `PostgreSQL JDBC Driver`, you're confirming the framework you guessed from the source.

## The 6-Step Static + Live Workflow Loop

This is the actual mental loop you run when hunting SQLi in a box you have local DB access to:

```
1. STATIC AUDIT      Read the controller. Find every SQL string.
                     Mark candidates: '+' concatenation, f-strings,
                     dynamic ORDER BY, raw query escape hatches.

2. LIVE OBSERVATION  tail -f the query log. Hit each candidate
                     endpoint with a normal request and a marker
                     payload like AUDIT_PROBE_001.

3. COMPARE           Did your marker show up as $1 (safe) or as
                     a quoted literal (candidate confirmed)?

4. PROBE             For confirmed candidates, send a single quote.
                     Watch the log: does the query break? Does the
                     server log a syntax error? You now know the
                     injection context (string vs numeric).

5. ITERATE           Build payloads informed by what the log shows.
                     Each payload + log read tightens the shape of
                     the bug — quote style, escape behavior, comment
                     handling.

6. CONFIRM EXPLOIT   Land the working payload via the normal HTTP
                     interface. The log is now your oracle —
                     everything you send shows up exactly as the DB
                     sees it.
```

You stop guessing. You stop waiting on response diffs. The log collapses every "is it injectable?" question into a single glance.

## Post-Exploitation Value of the Log

The log is useful even *after* you have shell or DB access. Treat it as a forensic read:

- **Credentials in queries.** Login flows, password reset endpoints, and migration scripts often pass plaintext or hashed passwords as literal values. A `tail` of the log can hand you working credentials for users who logged in while you were watching.
- **Schema reconstruction without SELECT.** Even if you can't run `\d` or query `information_schema`, every executed query reveals table and column names.
- **Internal endpoints and cron jobs.** Background tasks running on a schedule show up in the log — IDs, batch sizes, the queries admin tooling runs. Free intel about the app's internals.
- **Other users' activity.** Anything any user does on the box flows through here. Useful for chained attacks where you want to wait for an admin action and replay it.
- **`COPY` and file operations.** PostgreSQL's `COPY ... FROM '/path'` and `COPY ... TO '/path'` calls are logged — instant pointer to file paths the DB user can read or write.
- **Pivot for LFI/RCE chains.** If you have an LFI but no RCE, reading `postgresql-*.log` is often a quiet way to escalate — you get credentials, query history, and sometimes session tokens without ever hitting a `/etc/passwd` honeypot.

## What This Looks Like in Other Databases

The PostgreSQL specifics translate. Same idea, different filenames and settings:

| Database | Enable query log | Default log location |
|---|---|---|
| PostgreSQL | `log_statement = 'all'` in `postgresql.conf` | `pg_log/` or `data/log/` |
| MySQL / MariaDB | `SET GLOBAL general_log = 'ON'; SET GLOBAL general_log_file = '/var/log/mysql/general.log';` | `/var/log/mysql/` |
| MSSQL | SQL Server Profiler / Extended Events session | depends on session config |
| SQLite | `sqlite3_trace_v2()` API (no built-in log file) | in-process only |
| Oracle | `AUDIT` policies / SQL trace (`10046` event) | `udump/` directory |

The placeholder marker also varies — `$1` (Postgres), `?` (MySQL/JDBC), `@p1` (MSSQL), `:1` (Oracle). Whatever the marker, the rule is the same: **placeholder in the log = parameterized = safe**.

## Where Security Breaks (For the Defenders)

If you're on the blue side, the same log is a double-edged sword:

- Logs may contain PII, password hashes, session tokens, and credit card numbers as literal values inside queries. Treat the log directory like the database itself — same access controls, same rotation policy, same encryption-at-rest.
- A read of `postgresql-*.log` should be as alarming in your IDS as a read of `/etc/shadow`.
- `log_statement = 'all'` in production is loud — useful for debugging, dangerous left on. Many DPA/PCI rules require redacting or disabling parameter logging.

## Links

- [[SQL Injection]] — the vulnerability the log helps you find and exploit
- [[Database Queries]] — how parameterized vs concatenated queries are built in code
- [[Auditing: SQL Injection]] — the methodology this tool plugs into
- [[Wireshark]] — the network-level equivalent for non-DB protocols
- [[Burp Suite]] — the HTTP-level equivalent for the request side of the loop

## My Notes
