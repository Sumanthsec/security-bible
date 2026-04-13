# SQL Injection
Tags: #vulnerability #injection #database #day1 #day4

## What is SQLi and why does it exist?

Developers concatenate user input directly into SQL query strings. The database parser receives one string and can't tell which parts are code and which are data — so attacker input gets executed as SQL.

It exists because developers focus on making the product work — does the query return results? Does the page display them? Security at every endpoint isn't the priority when shipping. OWASP A03:2021 (Injection), still top 3 after 20+ years.

## How does the injection actually work?

Take a query: `SELECT name, price FROM products WHERE category = 'USER_INPUT'`

The developer expects a category name between those quotes. But if the attacker sends `' UNION SELECT password FROM users--`, the query becomes:

`SELECT name, price FROM products WHERE category = '' UNION SELECT password FROM users--'`

The `'` closes the developer's opening quote. Everything after it is now SQL, not a string value. The `--` comments out the developer's trailing quote so the syntax doesn't break.

That single quote is the critical moment — it's how the attacker escapes from being data into being code.

## What types of SQLi exist?

Same concatenation bug, different output channel. How much information the page returns determines which flavor you get.

| Flavor | Channel | Bandwidth | When |
|---|---|---|---|
| UNION / in-band | Rows rendered on page | Full query result | Page displays query output |
| Error-based | DB error in response | Full value per error | App leaks error messages |
| Boolean-blind | Page diff (200/404, content change) | 1 bit | Login forms, exists-checks |
| Time-based blind | Response timing | 1 bit | Output identical — only timing leaks |
| Out-of-band | DNS/HTTP to attacker server | Full value per request | DB has outbound network |

Boolean-blind: you use true/false conditions (`AND 1=1` vs `AND 1=2`) to extract data one bit at a time based on page differences. Time-based: same logic but using `SLEEP(5)` when even true/false gives no visible change — you measure response time instead.

## How do you confirm it's injectable?

Single quote `'` is the classic first test — if you get a 500 or a DB error, strong signal. But if the app handles errors gracefully, you need logic-based tests:

- Numeric context: send `id=5-0` (should work like `id=5`) then `id=5-1` (should work like `id=4`). If results change accordingly, your input is being evaluated as SQL math.
- String context: send `' AND '1'='1` (true, normal page) vs `' AND '1'='2` (false, different page). If the page changes, your input is being interpreted as SQL logic.

These work even when errors are hidden — cleaner than just throwing a quote and hoping for a 500.

**Where to look:** SQLi hides beyond just URL parameters — HTTP headers (Cookie, User-Agent, Referer, X-Forwarded-For), POST body fields, JSON/XML payloads, file upload filenames. Anywhere the app takes input and puts it into a query. Devs sanitize GET params but forget the logging system inserts User-Agent into a DB unsanitized.

**Front door locked, try side door** — `/login` is the most audited endpoint. `/forgot-password`, `/signup`, `/reset`, `/api/v1/*` are where bugs live.

## How do you know which database you're on?

This determines everything — syntax, system tables, what you can escalate to. Identify first.

| Database | Sleep |
|---|---|
| MySQL | `SLEEP(5)` |
| PostgreSQL | `pg_sleep(5)` |
| MSSQL | `WAITFOR DELAY '0:0:5'` |
| Oracle | `DBMS_PIPE.RECEIVE_MESSAGE('x',5)` |
| SQLite | heavy query |

Error messages, version queries, and syntax differences also reveal the DB type.

## How do you enumerate and extract data?

**1. Enumerate tables** — query the system catalog:

| Database | Query |
|---|---|
| MySQL / PG / MSSQL | `SELECT table_name FROM information_schema.tables WHERE table_schema = '...'` |
| Oracle | `SELECT table_name FROM ALL_TABLES` |
| SQLite | `SELECT name FROM sqlite_master WHERE type = 'table'` |

**2. Enumerate columns** — once you have table names:

| Database | Query |
|---|---|
| MySQL / PG / MSSQL | `SELECT column_name FROM information_schema.columns WHERE table_name = '...'` |
| Oracle | `SELECT column_name FROM ALL_TAB_COLUMNS WHERE table_name = '...'` |
| SQLite | `PRAGMA table_info('...')` |

**3. Extract** — pull values using whichever flavor is available. For UNION, both SELECTs must return the same number of columns — UNION combines two result sets into one, so the structure has to match or the DB throws an error. Enumerate the column count with `ORDER BY 1`, `ORDER BY 2`, etc. until it errors, or `UNION SELECT NULL, NULL, NULL...` increasing NULLs until it works.

**Error-based extraction** — databases include your data in error messages meant for debugging:

| Database | Trick | Error contains |
|---|---|---|
| PostgreSQL | `CAST((SELECT secret) AS int)` | "invalid input syntax: \<secret\>" |
| PostgreSQL | `QUERY_TO_XML(...)::text::int` | Whole table as XML |
| MySQL ≤5.7 | `EXTRACTVALUE(1, CONCAT(0x7e, (SELECT secret)))` | XPath error with secret |
| MySQL 8+ | `JSON_KEYS((SELECT CONCAT('{"',secret,'":1}')))` | JSON parse error |
| MSSQL | `CONVERT(int, (SELECT secret))` | Conversion error |
| Oracle | `UTL_INADDR.GET_HOST_NAME((SELECT secret FROM dual))` | Hostname lookup error |

If errors aren't visible, check for a debug gate (trusted IP headers that flip debug mode, stack traces that leak DB errors).

## How far can you go beyond reading data?

A database is a process running on the OS — it listens on a port (PostgreSQL 5432, MySQL 3306, MSSQL 1433), reads and writes files on disk, and runs as a service account. When you find SQLi, you're executing operations as that service account on that machine.

**Write/modify/delete data** — INSERT, UPDATE, DELETE are standard SQL. If stacked queries work (`;` to start a new statement), you can run `; DROP TABLE users--`. Stacked queries depend on the DB and driver:

| Database + Driver | Stacked queries? |
|---|---|
| PostgreSQL + psycopg2 | Yes |
| MySQL + most drivers | No (needs `allowMultiQueries=true`) |
| MSSQL + most drivers | Yes |
| Oracle | No |

**Read/write files** — databases need to import/export data, so these features exist. MySQL `LOAD_FILE('/etc/passwd')` reads files, `INTO OUTFILE` writes them. Write a PHP webshell to the web root and you have command execution through the browser. Requires FILE privilege.

**Execute OS commands** — SQL Server `xp_cmdshell` runs system commands directly (disabled by default, sysadmin can re-enable). PostgreSQL `COPY FROM PROGRAM` pipes data through shell commands (CVE-2019-9193, closed as "this is a feature"). These exist because databases were designed as powerful admin tools, not just data stores.

**The escalation ladder:**

```
LEVEL 0  ─ Confirm            (' breaks query)
LEVEL 1  ─ Read data          (UNION/error/blind)
LEVEL 2  ─ Read OS files      (COPY FROM / LOAD_FILE)
LEVEL 3  ─ Write OS files     (COPY TO / INTO OUTFILE / large objects)
LEVEL 4  ─ Execute commands   (COPY FROM PROGRAM / xp_cmdshell / UDF)
LEVEL 5  ─ Interactive shell  (reverse shell → privesc)
```

**Gate check:** `SELECT current_user, current_setting('is_superuser');` — if `on`, levels 2–5 are minutes of typing. Default installs ship superuser.

## Why does it matter which database you're on?

| | SQL Server | PostgreSQL | MySQL |
|---|---|---|---|
| Stacked queries | Yes | Yes | No (by default) |
| OS command exec | `xp_cmdshell` | `COPY FROM PROGRAM` (superuser) | No built-in |
| File read/write | Yes | Yes (superuser) | Needs FILE privilege |
| Default risk | Highest — often high privs on Windows | Medium — powerful but perms usually tighter | Most limited |

Same SQLi vulnerability, but on SQL Server the worst-case impact is significantly higher out of the box. Fingerprinting the DB early tells you which techniques are available, which syntax to use, and what the maximum impact could be.

## How do you fix it?

**Parameterized queries** — the actual fix. The database handles the query in two steps:
1. **Prepare** — app sends the query template with placeholders (`WHERE category = ?`). The database parses the SQL structure and finalizes it.
2. **Execute** — app sends user input separately. The structure is already locked in. Even if the input contains `' UNION SELECT...`, the database treats it as a literal string — parsing already happened.

This isn't escaping (one string, hoping the parser handles it). It's complete channel separation — `COM_STMT_PREPARE` sends structure, `COM_STMT_EXECUTE` sends data as typed binary. The parser is done before data arrives.

**Common mistakes by language:**

| Language | Vulnerable (concatenation) | Safe (parameterized) |
|---|---|---|
| Python | `cursor.execute("... %s" % var)` | `cursor.execute("... %s", (var,))` |
| Java | `"SELECT ... " + userInput` | `PreparedStatement` with `?` |
| PHP | `"SELECT ... '$var'"` | PDO `->prepare()` + `->execute()` |
| Node.js | `` `SELECT ... ${input}` `` | `pool.query('SELECT ... $1', [input])` |

In any language: f-strings, `format()`, or string concatenation in SQL = the bug. The placeholder is the fix.

**Why does sanitization fail?** You're writing your own SQL parser to defeat the real one. Multibyte encodings break escaping (CVE-2006-2753: in GBK, the second byte of a two-byte character can be a backslash, so `\'` becomes a valid character followed by an unescaped quote). Keyword stripping backfires (`UNUNIONION` → strip `UNION` → `UNION`). You can't enumerate every edge case in a parser you didn't write.

## What about ORMs?

ORMs generate parameterized queries automatically — `User.objects.filter(email=input)` becomes `SELECT ... WHERE email = $1`. Safe by default.

But every ORM has escape hatches that drop back to raw SQL: `.raw()`, `.extra()` (Django), `text()` (SQLAlchemy), `createNativeQuery()` (JPA), `knex.raw()` (Knex.js). The moment a developer uses raw SQL with concatenation inside an ORM, they're vulnerable again. These escape hatches are where SQLi lives in modern codebases.

## What can't be parameterized?

SQL structure — table names, column names, ORDER BY direction, operators. Parameters can only go where literal values go, because the parser needs structure to build the execution plan.

Fix: allowlist the valid values against a hardcoded list, default everything else. `if sort_by not in ['name', 'price']: sort_by = 'name'`. Blocklisting fails for the same reason sanitization fails — you're trying to enumerate the bad instead of defining the good.

## What about stored procedures?

Not inherently safe. If the procedure internally builds dynamic SQL with concatenation and executes it with `EXEC` or `EXECUTE IMMEDIATE`, it's just as vulnerable. The injection happens inside the procedure instead of in the application code. Only safe if they use parameterized queries internally.

## What is second-order SQLi?

The payload is stored first, triggered later. Attacker registers a username containing SQL syntax (parameterized INSERT — stored safely). Later, an admin panel query pulls that username and concatenates it into a different query without parameterization.

The INSERT was safe — the SELECT that uses the stored value isn't. Happens because developers trust their own database: "we wrote it, so it's safe." Spans code paths and time, nearly invisible to scanners. This is why parameterizing some queries isn't enough — every query that touches stored data needs it too.

## Why does Principle of Least Privilege matter?

Parameterization stops the bug. PoLP stops the escalation.

The app's DB user should never be superuser. No FILE privilege, no DDL, no `pg_read_server_files` / `pg_write_server_files`. The app needs SELECT/INSERT/UPDATE/DELETE on its own tables — nothing more. Default installs ship superuser — fix this before fixing anything else.

Same SQLi bug is info-leak or full RCE depending entirely on the DB role's privileges. If this credential leaked tomorrow, what could the attacker do?

## How do you find SQLi in practice?

### Log Observation

When you have access to query logs (white-box, lab, or post-compromise), tail them while sending requests. The log shows exactly what SQL the parser received — it's ground truth.

`$1` / `?` / `@p1` in the log = parameterized = safe. Your input appearing as a quoted literal = concatenated = investigate.

| Database | Enable log | Parameterized marker |
|---|---|---|
| PostgreSQL | `log_statement = 'all'` | `$1` |
| MySQL | `SET GLOBAL general_log = 'ON'` | `?` |
| MSSQL | SQL Profiler / Extended Events | `@p1` |
| Oracle | `AUDIT` policies / trace 10046 | `:1` |

The loop: read source → find candidate sink → send request → check log → confirm parameterized or concatenated → if concatenated, send single quote → watch for syntax error → build payload.

### Black-Box

**DB identification first** — sleep functions determine which DB. Syntax differs for everything after.

**Technique determination — always pick the highest-bandwidth channel:**

1. UNION SELECT with NULLs — see output? → UNION-based
2. Inject syntax error — see DB error? → Error-based
3. `AND 1=1` vs `AND 1=2` — page differs? → Boolean-blind
4. `AND SLEEP(5)` — timing differs? → Time-blind
5. DNS/HTTP callback — received? → OOB

### Red Flags

- Single quote `'` causes 500 or different behavior
- DB error messages visible on page
- Different HTTP status for valid vs invalid query logic
- `ORDER BY 1` works but `ORDER BY 100` errors
- Homemade regex or blacklist in front of query
- `+` in a Java SQL string — primary code review red flag
- `matches()` in Java filter code (checks whole string, not substring — almost always bypassable)

**Multi-finding density** — one 40-line controller function can have 6 findings. Read the whole function, map the whole graph. Don't stop at the SQLi.

**Real breaches** — Sony 2011 (plaintext passwords leaked), Heartland 2008 (130M payment cards), TalkTalk 2015 (teenager with sqlmap), MOVEit 2023 (Cl0p mass exploitation). Same bug, 15 years apart.

## My Notes
