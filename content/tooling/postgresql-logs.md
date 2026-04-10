# PostgreSQL Query Logs
Tags: #tooling #postgresql #database #logging #sql-injection #methodology

## Core

> "Source code is the recipe. The query log is the meal. Always check what the kitchen actually served."

The query log is ground truth — whatever shows up is exactly what hit the SQL parser. It turns auditing into a feedback loop: read source → send request → watch log → confirm or revise.

## Parameterized vs Concatenated in the Log

| What you see | Meaning |
|---|---|
| `$1`, `$2`, `$3` (or `?` on other DBs) | Parameterized — data, not code. Not injectable. Move on. |
| Quoted literal matching your input exactly | Concatenated — parsed as SQL. Candidate. |
| Quoted literal that's been cleaned | Sanitization layer — investigate |

## Two-Terminal Workspace

```
┌──────────────────────────┐  ┌──────────────────────────┐
│ TERMINAL 1               │  │ TERMINAL 2               │
│ curl / Burp / browser    │  │ tail -f postgresql-*.log  │
│ sending payloads         │  │ live query stream         │
└──────────────────────────┘  └──────────────────────────┘
```

Send payload on left, watch exact SQL on right. Within 30 seconds you know how input is mangled.

```bash
tail -f /var/lib/postgresql/data/log/postgresql-*.log
tail -f ... | grep -i "users"   # filter to target table
```

## Enabling Logging

| Setting | Value | Purpose |
|---|---|---|
| `logging_collector` | `on` | Write logs to files |
| `log_statement` | `'all'` | Capture every query |
| `log_min_duration_statement` | `0` | Include execution time |
| `log_line_prefix` | `'%m [%p] %q%u@%d '` | Timestamp, PID, user, DB |
| `log_connections` | `on` | See client library (`application_name`), auth method |

Apply with `SELECT pg_reload_conf();` or restart.

## 6-Step Static + Live Workflow

1. **Static audit** — read controller, find SQL strings, mark candidates (`+` concat, f-strings, raw escapes)
2. **Live observation** — tail log, hit candidates with normal request + marker payload
3. **Compare** — marker shows as `$1` (safe) or quoted literal (confirmed candidate)?
4. **Probe** — send single quote, watch log for syntax error → injection context
5. **Iterate** — build payloads informed by what the log shows
6. **Confirm exploit** — land working payload via HTTP, log is your oracle

## Post-Exploitation Value

- **Credentials in queries** — login flows pass plaintext/hashed passwords as literals
- **Schema reconstruction** — every executed query reveals table and column names
- **Cron/background jobs** — scheduled tasks expose IDs, batch sizes, admin queries
- **COPY operations** — `COPY FROM/TO` calls point to readable/writable file paths
- **Pivot for LFI** — reading the log via LFI yields credentials and query history

## Cross-Database Reference

| Database | Enable log | Placeholder marker |
|---|---|---|
| PostgreSQL | `log_statement = 'all'` | `$1` |
| MySQL | `SET GLOBAL general_log = 'ON'` | `?` |
| MSSQL | SQL Profiler / Extended Events | `@p1` |
| Oracle | `AUDIT` policies / trace 10046 | `:1` |

Placeholder in log = parameterized = safe. Inline literal = concatenated = investigate.

## My Notes
