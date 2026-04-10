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

### Read Any Filter Code Right Next to the Sink

When the developer wrote a custom regex/blacklist filter in front of the query (instead of using parameterization), read it adversarially. The filter is **not** a wall — it's a list of specific things they thought to block. Your job is to find what they didn't list.

The single most common Java filter trap:

```java
Pattern p = Pattern.compile("'|''");
if (p.matcher(input).matches()) reject();   // ← matches() = whole string only
if (p.matcher(input).find())    reject();   // ← find() = any substring
```

`matches()` only fires when the *entire* input equals the pattern — so `a'--` slips right through a "no single quotes" filter built with `matches()`. `find()` would actually catch it. This is a one-line bug worth grepping every Java codebase for:

```bash
grep -rnE 'Pattern\.compile|matcher\(.*\)\.matches\(' --include="*.java" .
```

When you see `Matcher.matches()` used as a blacklist guard against a short pattern, mark it as a confirmed bypass before you even read the rest of the controller.

For other filter shapes, the questions to ask are always:

| If the filter blocks... | Try... |
|---|---|
| The literal space character | `/**/` (SQL comment as whitespace), `%0a`, `%09` |
| Single quotes | Dollar-quoted `$x$` (Postgres), hex `0x...` (MySQL), `CHAR()`/`CHR()`, `q'[...]'` (Oracle) |
| Specific keywords (`UNION`, `SELECT`) | Case mixing, comment-splitting `UN/**/ION`, MySQL version comments `/*!50000UNION*/` |
| Whole-input regex via `matches()` | Anything where the forbidden substring is part of a larger payload |
| URL-decoded input only | Double-encoding (`%2527` → `%27` → `'`) if the filter runs before the second decode |
| **Shape regex** (email/URL/phone/UUID) | Stuff the payload into the part the regex doesn't inspect — for emails, everything before `@` is `.*` and SQL `--` comments out everything after. Payload: `' or 1=1--@anything.tld` |

See [[SQL Injection]] → "Filter Bypass — Picking the Locks" for the full lock-picking reference.

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

The flavors are not different bugs — they're the same bug seen through different output channels. **Bandwidth ranking, high to low:** in-band > error-based > boolean-blind > time-based. Always pick the highest-bandwidth channel the page gives you.

### Side-Channel Thinking — Don't Default to Bisection

Before bisecting (~7 requests/char), check if the page has any output with >2 possible values and a controllable index (row IDs, avatars, redirect targets, result counts). If so, encode the secret directly into that index for one-request-per-byte extraction. See [[SQL Injection]] → "The Side-Channel / Precomputation Trick."

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

## Step 3: Live Observation — Close the Feedback Loop

> **Forever-hook:** "Source code is the recipe. The query log is the meal. Always check what the kitchen actually served."

When you have DB access (HTB, lab, post-exploitation), tail the query log alongside your payloads. The log shows you exactly what the parser received — no more guessing about WAF behavior or abstraction layers.

**The tell:** `$1` (Postgres) / `?` (JDBC) / `@p1` (MSSQL) = parameterized, move on. Your literal payload baked in as a quoted string = concatenated, start probing.

See [[PostgreSQL Query Logs]] for the full two-terminal workspace setup, the 6-step static+live loop, and post-exploitation log reading techniques.

## Don't Stop at the SQLi — Read the Whole Function

Once you find a SQLi candidate, **resist the urge to fixate**. Read the rest of the function with the same intensity. Sensitive controllers (login, register, password reset, profile edit, payment) typically have 4–6 findings in 30–50 lines, and only one of them is the SQLi. The catch block, the IP check, the logger calls, the token generation, the rate-limit absence — every one of those is a real finding that often chains into something bigger than the SQLi.

A worked example from a single password-reset method:

| Finding | Severity |
|---|---|
| SQL injection in email concatenation | High |
| Trust of `X-Forwarded-For` for an IP-based debug check | High |
| Stack trace disclosure when the IP check passes | Medium |
| Reset link logged via `logger.error` | Medium (account takeover via log read) |
| Reset token is `MD5(id:email:hash)` — offline-computable | Medium-High |
| No rate limiting on the endpoint | Low-Medium |

Six findings, one function. The hacker mindset is "map the whole graph", not "find one bug class at a time." See [[Auditing: Code Review for Spring Boot Apps]] → "The Multi-Finding Density Mindset" for the full reading checklist.

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
- A homemade regex/blacklist sitting in front of the query — every one of these is a list of things the dev thought to block, and your job is to find what they didn't list
- `Pattern.compile(...).matcher(input).matches()` in Java code — almost certainly a bypassable filter (use `find()` instead)
- Filters that run before URL decoding — try double-encoding (`%2527` → `%27` → `'`)
- A vulnerable query on a page that already renders rows by ID, avatars, redirect targets, or result counts — that's a side channel for one-request-per-byte extraction

## WAF Bypass

WAFs are blocklist-based — same fundamental weakness as input sanitization. They parse HTTP, not SQL. The gap between the WAF's parser and the database's parser is where bypasses live. See [[SQL Injection]] → "Filter Bypass" for the full technique table (comment whitespace, case mixing, hex literals, function alternatives, double-encoding, no-space parenthesis tricks).

## Links

- [[SQL Injection]] — main vulnerability reference
- [[Database Queries]] — how web apps interact with databases
- [[PostgreSQL Query Logs]] — the live-observation tool for the static + live loop

## My Notes
