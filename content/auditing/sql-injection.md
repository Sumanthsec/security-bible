# Auditing: SQL Injection
Tags: #auditing #sqli #methodology #day1

## Approach

Find every function that executes SQL (sinks), classify each as parameterized or concatenated, trace concatenated variables back to their source. Then test black-box to determine the highest-bandwidth exploitation channel.

## Sink Patterns by Language

**Python:** `cursor.execute(`, `cursor.executemany(`, `.raw(`, `.extra(`, `engine.execute(`, `session.execute(`, `text(`

**Java:** `.executeQuery(`, `.executeUpdate(`, `.execute(`, `createStatement()`, `createNativeQuery(`, `jdbcTemplate.query(`

**Node.js:** `.query(`, `pool.query(`, `connection.query(`, `sequelize.query(`, `knex.raw(`

**PHP:** `mysqli_query(`, `mysql_query(`, `->query(`, `->exec(`

## What to Look For

### Classify Each Sink

| Pattern | Status |
|---------|--------|
| `cursor.execute("... %s", (var,))` — parameterized tuple | Safe |
| `cursor.execute("... %s" % var)` — string formatting | **Vulnerable** |
| `cursor.execute(f"... {var}")` — f-string | **Vulnerable** |
| `cursor.execute("..." + var)` — concatenation | **Vulnerable** |
| Hardcoded values only | Safe |
| Variable passed in — trace it | **Investigate** |

### Trace Back to Source

- `request.*` / `req.query` / `$_GET` / `@RequestParam` → **User-controlled**
- Function parameter → **Check all callers**
- Database value → **Second-order risk — check who wrote it**
- Config/environment → **Probably safe, verify**

### Filter Analysis

| Filter blocks... | Try... |
|---|---|
| Space character | `/**/`, `%0a`, `%09` |
| Single quotes | Dollar-quoted `$x$` (PG), hex `0x...` (MySQL), `CHAR()` / `CHR()` |
| Keywords (`UNION`, `SELECT`) | Case mixing, `UN/**/ION`, `/*!50000UNION*/` |
| Whole-input regex via `matches()` | Partial payloads in a larger string |
| URL-decoded only | Double-encoding `%2527` → `%27` → `'` |
| Shape regex (email/URL) | Payload in the dead zone — email: before `@` with `--` to comment the rest |

`Pattern.compile(...).matcher(input).matches()` in Java = almost always bypassable. `matches()` checks the whole string; `find()` checks any substring.

### Structural Injection Points (can't parameterize, need allowlisting)

- `ORDER BY` with user-controlled column/direction
- Dynamic table or column names
- User-controlled operators in search builders
- `IN (...)` clauses built dynamically

## Black-Box Technique Determination

1. Inject UNION SELECT with NULLs — see output? → **UNION-based**
2. Inject syntax error — see DB error? → **Error-based**
3. AND 1=1 vs AND 1=2 — page differs? → **Boolean-blind**
4. AND SLEEP(5) — timing differs? → **Time-blind**
5. DNS/HTTP callback — received? → **OOB**

Always pick the highest-bandwidth channel. Before bisecting (~7 req/char), check if the page has any output with >2 values and a controllable index — that's a multi-bit side channel.

## Multi-Finding Density

Don't stop at the SQLi. Read the whole function — sensitive controllers typically have 4-6 findings in 30-50 lines.

| Finding | Severity |
|---|---|
| SQL injection in email concatenation | High |
| Trust of `X-Forwarded-For` for IP-based debug check | High |
| Stack trace disclosure when IP check passes | Medium |
| Reset link logged via `logger.error` | Medium |
| Reset token is `MD5(id:email:hash)` — offline-computable | Medium-High |
| No rate limiting | Low-Medium |

## Red Flags

- DB error messages visible on page
- Different HTTP status for valid vs invalid queries
- Measurable timing difference on `SLEEP()` injection
- `ORDER BY 1` works but `ORDER BY 100` errors
- Single quote `'` causes 500 error
- WAF blocking `UNION SELECT` but not `/*!50000UNION*//*!50000SELECT*/`
- Homemade regex/blacklist in front of query
- `matches()` in Java filter code
- Filters running before URL decoding (double-encoding opportunity)
- Page renders rows by ID, avatars, or result counts alongside a vulnerable query (side-channel)

## Chains

- [[SQL Injection]] — main vulnerability reference
- [[Database Queries]] — how apps build queries
- [[PostgreSQL Query Logs]] — live-observation tool for the static+live loop

## My Notes
