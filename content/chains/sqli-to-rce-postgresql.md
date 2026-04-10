# SQLi → RCE on PostgreSQL (The Full Escalation Ladder)
Tags: #chain #sqli #postgresql #rce #post-exploitation #escalation #day4

## The Attack Narrative

SQLi is the front door, not the prize. On a PostgreSQL-backed app with superuser, the climb runs:

```
LEVEL 0  ─ Confirm bug              (' breaks the query)
LEVEL 1  ─ Read data                (UNION / error / blind)
LEVEL 2  ─ Read OS files            (COPY FROM / large objects)
LEVEL 3  ─ Write OS files           (COPY TO / large objects)
LEVEL 4  ─ Execute commands         (COPY FROM PROGRAM / C extension)
LEVEL 5  ─ Interactive shell        (reverse shell → privesc)
```

Each level uses features PostgreSQL ships on purpose. None require a second vulnerability.

## Act I — Find the Door (Levels 0-1)

Static review finds a controller concatenating input into a WHERE clause. Black-box probe: email-shape regex bypass (`' or 1=1--@x.tld`). Flip the debug gate with `X-Forwarded-For: 127.0.0.1` ([[Client-Controlled IP Headers]] + [[Debug Mode Disclosure]]) — blind SQLi becomes error-based. Leak schema with `CAST((SELECT ...) AS int)`.

Most engagements stop at data exfiltration. This is where the attacker keeps climbing.

## Act II — Gate Check

```sql
SELECT current_user, current_setting('is_superuser');
```

`is_superuser = on` → the rest is unlocked. PostgreSQL ships with superuser by default in most installs. If `off` → look for `pg_read_server_files` / `pg_write_server_files` grants, or priv escalation CVEs (2018-1058, 2019-9193, 2022-1552).

## Act III — Read Files (Level 2)

Two paths: `COPY t FROM '/etc/passwd';` or `lo_import('/etc/passwd')` + read from `pg_largeobject`.

Priority reads: `/etc/passwd` (confirms read, lists users), `/proc/self/environ` (AWS creds, JWT secrets), `postgresql.conf` (data dir), `pg_hba.conf` (auth rules, `trust` lines), query logs (credentials as literals).

## Act IV — Write Files (Level 3)

Three paths: `COPY (SELECT ...) TO '/path'` (ASCII), `lo_create` + `INSERT INTO pg_largeobject` + `lo_export` (arbitrary binary, 2KB pages), or CREATE FUNCTION tricks.

Large object route matters for RCE — it writes arbitrary bytes including compiled `.so` files.

## Act V — Execute Commands (Level 4)

**Path A — COPY FROM PROGRAM (the cheat code):**
`COPY t FROM PROGRAM 'id; whoami';` — runs shell command as postgres OS user, pipes stdout into table. Single statement. CVE-2019-9193 was closed as "this is a feature."

**Path B — C extension (when FROM PROGRAM is blocked):**
Write a compiled `.so` via large objects → `CREATE FUNCTION pwn() AS '/tmp/pwn.so', 'pwn' LANGUAGE C;` → `SELECT pwn();`. Reverse shell connects back.

## Act VI — Shell and Climb (Level 5)

Reverse shell as postgres user → standard Linux post-foothold: `id`/`groups`, `sudo -l`, SUID binaries, cron as root, kernel exploits, credential harvesting from other processes, pivoting to internal hosts.

## Act VII — Cleanup

```sql
DROP FUNCTION IF EXISTS pwn();
SELECT lo_unlink(31337);
DROP TABLE IF EXISTS pwn, leak;
```

On real engagements, document every command with timestamps.

## Why Each Link Works

Every level uses a vendor-designed feature: bulk CSV loading (file read), query export (file write), external tool integration (COPY FROM PROGRAM), extension loading (LANGUAGE C). Superuser is the trust boundary. See [[Database as a Process]] for the architectural picture.

> "A database is not a black box. It's a Linux process. If your SQLi gives you superuser, it gives you the OS user."

Three structural decisions create this: (1) superuser-by-default at install, (2) no sandbox between DB process and OS, (3) app connection string = attacker identity once SQLi happens.

## Hardening

| Mitigation | Closes level | Why |
|---|---|---|
| Parameterize every query | Level 0 | No SQLi = no chain |
| App user NOT superuser | Levels 2-4 | COPY, lo_import, LANGUAGE C require superuser |
| Revoke `pg_read/write_server_files`, `pg_execute_server_program` | Levels 2-4 | Gates the dangerous primitives |
| Dedicated OS user, minimal fs perms | Level 5 | OS user can't escalate trivially |
| Disable `COPY FROM PROGRAM` where supported | Level 4 | Removes the cheat-code path |
| Read-only mounts, AppArmor/SELinux | Levels 2-3 | OS refuses the syscall |
| Log + alert on `FROM PROGRAM`, `LANGUAGE C`, `lo_import/export` | Detection | Post-exploit moves are loud |
| Egress firewall on DB host | Level 5 | Reverse shells can't dial out |

The right answer is all of the above, in layers. Each is one application of [[Principle of Least Privilege]].

## My Notes
