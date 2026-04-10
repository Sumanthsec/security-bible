# Auditing: SQL Injection
Tags: #auditing #sqli #methodology #day1 #day4

## Code Review

**Sink patterns by language:**

Python: `cursor.execute(`, `cursor.executemany(`, `.raw(`, `.extra(`, `engine.execute(`, `session.execute(`, `text(`
Java: `.executeQuery(`, `.executeUpdate(`, `.execute(`, `createStatement()`, `createNativeQuery(`, `jdbcTemplate.query(`
Node.js: `.query(`, `pool.query(`, `connection.query(`, `sequelize.query(`, `knex.raw(`
PHP: `mysqli_query(`, `mysql_query(`, `->query(`, `->exec(`

**Classify each sink:**

| Pattern | Status |
|---|---|
| `cursor.execute("... %s", (var,))` — parameterized tuple | Safe |
| `cursor.execute("... %s" % var)` — string formatting | Vulnerable |
| `cursor.execute(f"... {var}")` — f-string | Vulnerable |
| `cursor.execute("..." + var)` — concatenation | Vulnerable |
| Hardcoded values only | Safe |
| Variable passed in — trace it | Investigate |

`+` in a SQL string is blood in the water — in Java code review, it's the primary red flag.

**Trace to source:**

- `request.*` / `req.query` / `$_GET` / `@RequestParam` → user-controlled
- Function parameter → check all callers
- Database value → second-order risk, check who wrote it
- Config/environment → probably safe, verify

**ORM escape hatches to grep for:** `.raw()`, `.extra()`, `text()`, `createNativeQuery()`, `knex.raw()`, `sequelize.query()`. These bypass the ORM's parameterization — treat as raw SQL sinks.

**Structural injection (can't parameterize, need allowlisting):**

- `ORDER BY` with user-controlled column/direction
- Dynamic table or column names
- User-controlled operators in search builders
- `IN (...)` clauses built dynamically

## Black-Box

**DB identification first** — sleep functions determine which DB you're talking to. Syntax differs for everything after this.

**Technique determination — always pick the highest-bandwidth channel:**

1. UNION SELECT with NULLs — see output? → UNION-based
2. Inject syntax error — see DB error? → Error-based
3. `AND 1=1` vs `AND 1=2` — page differs? → Boolean-blind
4. `AND SLEEP(5)` — timing differs? → Time-blind
5. DNS/HTTP callback — received? → OOB

Before defaulting to bisection (~7 req/char), check: does the page have any output with >2 possible values and a controllable index? That's a multi-bit side channel — one request per byte.

## Filter Analysis

| Filter blocks... | Try... |
|---|---|
| Space character | `/**/`, `%0a`, `%09` |
| Single quotes | Dollar-quoted `$x$` (PG), hex `0x...` (MySQL), `CHAR()` / `CHR()` |
| Keywords (`UNION`, `SELECT`) | Case mixing, `UN/**/ION`, `/*!50000UNION*/` |
| Whole-input regex via `matches()` | Partial payloads in a larger valid string |
| URL-decoded only | Double-encoding: `%2527` → `%27` → `'` |
| Shape regex (email/URL) | Payload in the dead zone — email: before `@` with `--` to comment the rest |

`Pattern.compile(...).matcher(input).matches()` in Java checks the whole string — almost always bypassable. `find()` checks any substring. Developers confuse these constantly.

## Red Flags

- Single quote `'` causes 500 error or different behavior
- DB error messages visible on page
- Different HTTP status for valid vs invalid query logic
- `ORDER BY 1` works but `ORDER BY 100` errors
- WAF blocks `UNION SELECT` but not `/*!50000UNION*//*!50000SELECT*/`
- Homemade regex or blacklist in front of query
- `matches()` in Java filter code
- Filters running before URL decoding (double-encoding opportunity)
- Page renders rows by ID or result counts alongside a controllable query (side-channel)

**Front door locked, try side door** — `/login` is the most audited endpoint. `/forgot-password`, `/signup`, `/reset`, `/api/v1/*` are where bugs live.

**Multi-finding density** — one 40-line controller function can have 6 findings. Read the whole function, map the whole graph. Don't stop at the SQLi.

## Chains

- [[SQL Injection]] — main vulnerability reference
- [[Fixing SQLi]] — parameterization, ORMs, PoLP
- [[Database Queries]] — how apps build queries

## My Notes
