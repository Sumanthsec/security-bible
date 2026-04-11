# SQL Injection
Tags: #vulnerability #injection #database #day1 #day4

## What Is SQLi

When user input is concatenated into a SQL query string instead of bound as a parameter, the database parser executes the input as SQL. The attacker controls the query structure.

Sanitization is a losing strategy — you're writing your own SQL parser to defeat the real one. Multibyte encodings break escaping (CVE-2006-2753: in GBK, the second byte of a two-byte character can be a backslash, so `\'` becomes a valid character followed by an unescaped quote). Keyword stripping backfires (`UNUNIONION` → strip `UNION` → `UNION`). MySQL version comments (`/*!50000UNION*/`) hide keywords from filters but the parser still executes them. The fix is parameterized queries, which operate at the protocol level.

OWASP A03:2021 (Injection). Still top 3 after 20+ years.

## Flavors

Same concatenation bug, different output channel. How much information the page returns determines which flavor you get.

| Flavor | Channel | Bandwidth | When |
|---|---|---|---|
| UNION / in-band | Rows rendered on page | Full query result | Page displays query output |
| Error-based | DB error in response | Full value per error | App leaks error messages |
| Boolean-blind | Page diff (200/404, content change) | 1 bit | Login forms, exists-checks |
| Time-based blind | Response timing | 1 bit | Output identical — only timing leaks |
| Out-of-band | DNS/HTTP to attacker server | Full value per request | DB has outbound network |

## DB Identification and Enumeration

Determines everything downstream — syntax, system tables, aggregation functions, escalation primitives all differ per database. Identify first, then enumerate, then extract.

**1. Identify the database** — inject sleep functions, observe behavior:

| Database | Sleep |
|---|---|
| MySQL | `SLEEP(5)` |
| PostgreSQL | `pg_sleep(5)` |
| MSSQL | `WAITFOR DELAY '0:0:5'` |
| Oracle | `DBMS_PIPE.RECEIVE_MESSAGE('x',5)` |
| SQLite | heavy query |

**2. Enumerate table names** — query the system catalog:

| Database | Query |
|---|---|
| MySQL / PG / MSSQL | `SELECT table_name FROM information_schema.tables WHERE table_schema = '...'` |
| Oracle | `SELECT table_name FROM ALL_TABLES` |
| SQLite | `SELECT name FROM sqlite_master WHERE type = 'table'` |

**3. Enumerate column names** — once you have tables:

| Database | Query |
|---|---|
| MySQL / PG / MSSQL | `SELECT column_name FROM information_schema.columns WHERE table_name = '...'` |
| Oracle | `SELECT column_name FROM ALL_TAB_COLUMNS WHERE table_name = '...'` |
| SQLite | `PRAGMA table_info('...')` |

**4. Extract data** — now you know the table and column names, pull the actual values using whichever flavor is available (UNION, error-based, blind).

## Data Extraction by Flavor

**Error-based — per-DB tricks.** Databases are helpful — they include your data in error messages meant for debugging.

| Database | Trick | Error contains |
|---|---|---|
| PostgreSQL | `CAST((SELECT secret) AS int)` | "invalid input syntax: \<secret\>" |
| PostgreSQL | `QUERY_TO_XML(...)::text::int` | Whole table as XML |
| MySQL ≤5.7 | `EXTRACTVALUE(1, CONCAT(0x7e, (SELECT secret)))` | XPath error with secret |
| MySQL 8+ | `JSON_KEYS((SELECT CONCAT('{"',secret,'":1}')))` | JSON parse error |
| MSSQL | `CONVERT(int, (SELECT secret))` | Conversion error |
| Oracle | `UTL_INADDR.GET_HOST_NAME((SELECT secret FROM dual))` | Hostname lookup error |

If errors aren't visible, check for a debug gate (trusted IP headers that flip debug mode, stack traces that leak DB errors).

## SQLi → RCE

A database is a Linux process running as an OS user. Superuser SQLi doesn't just give you data — it gives you that process's capabilities. These are features, not bugs.

```
LEVEL 0  ─ Confirm            (' breaks query)
LEVEL 1  ─ Read data          (UNION/error/blind)
LEVEL 2  ─ Read OS files      (COPY FROM / LOAD_FILE)
LEVEL 3  ─ Write OS files     (COPY TO / INTO OUTFILE / large objects)
LEVEL 4  ─ Execute commands   (COPY FROM PROGRAM / xp_cmdshell / UDF)
LEVEL 5  ─ Interactive shell  (reverse shell → privesc)
```

**Gate check:** `SELECT current_user, current_setting('is_superuser');` — if `on`, levels 2–5 are minutes of typing. Default installs ship superuser.

**Key primitives:** PostgreSQL `COPY FROM PROGRAM` (CVE-2019-9193, closed as "this is a feature"), MSSQL `xp_cmdshell`, MySQL `LOAD_FILE`/`INTO OUTFILE`/UDF, Oracle `DBMS_SCHEDULER`. PostgreSQL large objects (`lo_import`/`lo_export`) write arbitrary binary — including compiled `.so` for C extensions.

**PoLP determines blast radius.** The same SQLi bug is a P3 info-leak or a P0 RCE depending entirely on the DB role's privileges. The escalation is gated on `is_superuser`, not on the injection itself.

## Fixing SQLi

**Parameterized queries** — the actual fix. `COM_STMT_PREPARE` sends the query structure, `COM_STMT_EXECUTE` sends data as typed binary in a separate message. The parser is done before data arrives. This isn't escaping (one string, hoping the parser handles it) — it's complete channel separation.

**ORMs** generate parameterized queries automatically — Django's `User.objects.filter(email=input)` becomes `SELECT ... WHERE email = $1`. Use them. But their escape hatches drop back to raw SQL: `.raw()`, `.extra()` (Django), `text()` (SQLAlchemy), `createNativeQuery()` (JPA), `knex.raw()` (Knex.js). These are where SQLi lives in modern codebases.

**Allowlisting** — you can't parameterize SQL structure (table names, column names, ORDER BY, operators). Compare user input against a hardcoded list of valid values, default everything else. Blocklisting fails for the same reason sanitization fails — you're trying to enumerate the bad instead of defining the good.

**Common mistakes by language:**

| Language | Vulnerable (concatenation) | Safe (parameterized) |
|---|---|---|
| Python | `cursor.execute("... %s" % var)` | `cursor.execute("... %s", (var,))` |
| Java | `"SELECT ... " + userInput` | `PreparedStatement` with `?` |
| PHP | `"SELECT ... '$var'"` | PDO `->prepare()` + `->execute()` |
| Node.js | `` `SELECT ... ${input}` `` | `pool.query('SELECT ... $1', [input])` |

In any language: building SQL with f-strings, `format()`, or string concatenation is the bug. The comma-separated tuple (Python) or the `?` placeholder is the fix.

**Second-order SQLi** — input stored safely (parameterized INSERT), but retrieved later and concatenated into a different query without parameterization. Happens because developers trust their own database: "we wrote it, so it's safe." The INSERT was safe — the SELECT that uses the stored value later isn't. Spans code paths and time, nearly invisible to scanners. This is why parameterizing some queries isn't enough — every query that touches stored data needs it too.

**Principle of Least Privilege** — parameterization stops the bug, PoLP stops the escalation. The app's DB user should never be superuser. No FILE privilege, no DDL, no `pg_read_server_files` / `pg_write_server_files`. The app needs SELECT/INSERT/UPDATE/DELETE on its own tables — nothing more. Default installs ship superuser. Same SQLi bug is info-leak or full RCE depending entirely on the DB role's privileges.

**Real breaches** — Sony 2011 (plaintext passwords leaked), Heartland 2008 (130M payment cards), TalkTalk 2015 (teenager with sqlmap), MOVEit 2023 (Cl0p mass exploitation). Same bug, 15 years apart.

## Finding SQLi

A database is a process running on the OS — it listens on a port (PostgreSQL 5432, MySQL 3306, MSSQL 1433), reads and writes files on disk, and runs as a service account. The application connects to it over a network socket using a connection string with credentials. When you find SQLi, you're not just reading tables — you're executing operations as that service account on that machine. The DB's privileges, OS user, and network position determine what happens next.

### Log Observation

When you have access to query logs (white-box, lab, or post-compromise), tail them while sending requests. The log shows exactly what SQL the parser received — it's ground truth.

`$1` / `?` / `@p1` in the log = parameterized = safe. Your input appearing as a quoted literal = concatenated = investigate. Your input appearing cleaned or modified = sanitization layer, dig deeper.

| Database | Enable log | Parameterized marker |
|---|---|---|
| PostgreSQL | `log_statement = 'all'` | `$1` |
| MySQL | `SET GLOBAL general_log = 'ON'` | `?` |
| MSSQL | SQL Profiler / Extended Events | `@p1` |
| Oracle | `AUDIT` policies / trace 10046 | `:1` |

The loop: read source → find candidate sink → send request with marker input → check log → confirm parameterized or concatenated → if concatenated, send single quote → watch for syntax error in log → build payload.

### Black-Box

**DB identification first** — sleep functions determine which DB you're talking to. Syntax differs for everything after this.

**Technique determination — always pick the highest-bandwidth channel:**

1. UNION SELECT with NULLs — see output? → UNION-based
2. Inject syntax error — see DB error? → Error-based
3. `AND 1=1` vs `AND 1=2` — page differs? → Boolean-blind
4. `AND SLEEP(5)` — timing differs? → Time-blind
5. DNS/HTTP callback — received? → OOB

Before defaulting to bisection (~7 req/char), check: does the page have any output with >2 possible values and a controllable index? That's a multi-bit side channel — one request per byte.

### Red Flags

- Single quote `'` causes 500 error or different behavior
- DB error messages visible on page
- Different HTTP status for valid vs invalid query logic
- `ORDER BY 1` works but `ORDER BY 100` errors
- WAF blocks `UNION SELECT` but not `/*!50000UNION*//*!50000SELECT*/`
- Homemade regex or blacklist in front of query
- `matches()` in Java filter code
- Filters running before URL decoding (double-encoding opportunity)
- Page renders rows by ID or result counts alongside a controllable query (side-channel)
- `+` in a Java SQL string — primary code review red flag for concatenation

**Front door locked, try side door** — `/login` is the most audited endpoint. `/forgot-password`, `/signup`, `/reset`, `/api/v1/*` are where bugs live.

**Multi-finding density** — one 40-line controller function can have 6 findings. Read the whole function, map the whole graph. Don't stop at the SQLi.

## My Notes
