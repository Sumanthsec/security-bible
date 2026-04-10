# Principle of Least Privilege
Tags: #architecture #defense #hardening #principle #least-privilege #day4

## What This Is and Why It Exists

The Principle of Least Privilege (PoLP) is the single oldest, simplest, and most-violated rule in computer security:

> **Every component — every user, every process, every service account, every line of code — should run with the smallest set of privileges necessary to do its job, and no more.**

It was articulated by Saltzer and Schroeder in 1975 ("The Protection of Information in Computer Systems"). Fifty years later, the *reason* almost every modern breach escalates so far is that PoLP was not applied somewhere along the chain. Every time a SQLi turns into RCE, every time a phished helpdesk account leads to domain admin, every time a compromised npm package exfiltrates AWS secrets — somewhere, some component had more privilege than its job required, and the attacker inherited the surplus.

PoLP is not a tool, a feature, or a product. It's a **design discipline** you apply at every layer of the stack:

- **Code level** — functions only get the data they need
- **Process level** — services run as a dedicated OS user with minimal permissions
- **Database level** — application accounts have only the SELECT/INSERT they need, never DDL or superuser
- **Filesystem level** — services can only read/write the directories they actually use
- **Network level** — services can only reach the hosts they actually call
- **Cloud IAM level** — roles only get the API actions they actually invoke
- **Container level** — capabilities, syscalls, and mounts narrowed to the minimum

The forever-hook:

> **"Every privilege a component has that it doesn't strictly need is a privilege the next attacker inherits for free. PoLP is the thing that decides how big a foothold becomes."**

## How It Looks in Practice

### The Capability Surplus Is the Blast Radius

Every component has two privilege sets:

```
┌─────────────────────────────────────┐
│ ACTUAL CAPABILITIES (what it CAN do)│
│   ┌───────────────────────────────┐ │
│   │ NEEDED CAPABILITIES           │ │
│   │ (what its job requires)       │ │
│   └───────────────────────────────┘ │
│           ↑                         │
│           │ everything outside      │
│           │ this box is the         │
│           │ "capability surplus"    │
│           │ — free privilege        │
│           │ for the attacker        │
└─────────────────────────────────────┘
```

The attacker compromises the component (via SQLi, phishing, supply chain, whatever) and immediately inherits the **outer** box. The job needs the **inner** box. The gap is the blast radius. PoLP is the discipline of squeezing the outer box down until it equals the inner box.

### Layered Examples

#### 1. Database connections (the SQLi-to-RCE story)

```sql
-- ❌ Maximum capability surplus — every install ships like this by default
CREATE USER app WITH SUPERUSER PASSWORD 'app';
-- App can now: read every table, write every table, read /etc/passwd via COPY,
-- write /var/www/shell.php, run COPY FROM PROGRAM 'bash -i ...'
-- The app's actual job: SELECT/INSERT/UPDATE on 12 tables.

-- ✅ Least privilege — the role is shaped to the job
CREATE USER app WITH PASSWORD 'app';
GRANT CONNECT ON DATABASE prod TO app;
GRANT USAGE ON SCHEMA public TO app;
GRANT SELECT, INSERT, UPDATE ON users, sessions, posts, ... TO app;
-- (no DDL, no DELETE on audit tables, no superuser, no role grants)
REVOKE pg_read_server_files, pg_write_server_files, pg_execute_server_program FROM app;
```

The first version is fine until SQLi exists. The second version *contains* the SQLi to data exfiltration on twelve tables — Levels 2–5 of [[SQLi to RCE on PostgreSQL]] are simply unreachable because the privileges aren't there. Same SQLi bug. Wildly different outcome. See [[Database as a Process]] for why this gap is the entire game.

#### 2. OS user

`id postgres` shows `groups=postgres,docker,sudo` → foothold = root. PoLP: postgres in its own group only, no sudo, no docker. The attacker now needs a *second* bug to escalate.

#### 3. Filesystem

World-writable web root → webshell drop. PoLP: `drwxr-x--- www-data:www-data`. Config files: `-rw------- root:myapp`. OS enforces the rule regardless of the application state.

#### 4. Network (egress firewall)

DB host `OUTPUT ACCEPT all` → reverse shell dials out freely. PoLP: `OUTPUT DROP` with explicit `ACCEPT` only to app servers + monitoring. The reverse shell from Level 5 of the SQLi chain *doesn't connect*.

#### 5. Cloud IAM

`"Action": "*", "Resource": "*"` → credential theft = full AWS account. PoLP: scope to `s3:GetObject`/`s3:PutObject` on one bucket. Same SSRF, same credential theft, vastly different blast radius.

#### 6. Container capabilities

`privileged: true` → pod escape. PoLP: `runAsNonRoot`, `readOnlyRootFilesystem`, `capabilities: drop: ["ALL"]`, `seccompProfile: RuntimeDefault`. Nothing to escalate with.

## Security Implications

### PoLP Decides How Far Every Bug Goes

This is the lemma worth stamping into memory:

> **The exploitability of a vulnerability is determined by the bug. The blast radius is determined by least privilege.**

You cannot prevent every bug. Code review misses things, dependencies have CVEs, humans get phished, supply chains get poisoned. What you *can* control is what an attacker inherits when one of those bugs lands. PoLP is the only defense-in-depth principle that costs almost nothing to add and pays off in proportion to how bad the bug turns out to be.

Every layer that practices PoLP raises the cost of escalation by one bug:

```
Bug class       PoLP layer that contains it
─────────────   ────────────────────────────────
SQLi            DB role privileges (no superuser, no FILE, no DDL)
RCE in app      OS user permissions (dedicated user, no sudo, no docker grp)
File write      Filesystem perms / read-only mount / immutable bits
Webshell drop   Web root not writable by app user
Reverse shell   Egress firewall denies outbound
Cred theft      IAM scoped to one bucket / one secret / one resource
Pivot           Network ACLs deny lateral connections
```

The first column is "the bug." The second is "what stops it." Every defender's job is making the right column thick enough that the first column doesn't make the news.

### Why PoLP Keeps Getting Skipped

1. **Convenience.** "Just run it as root, we'll fix it later." It never gets scoped down.
2. **Defaults are wrong.** PostgreSQL ships `postgres` superuser, MySQL ships `root`, AWS ships `AdministratorAccess`. The path of least resistance = maximum surplus.
3. **Invisible until exploited.** No test checks "the code can also do twelve things it shouldn't." PoLP violations are undetectable until the breach.

### "Security Theater" vs Real PoLP

Creating a non-superuser role with `ALL PRIVILEGES ON DATABASE prod` isn't PoLP — it's a less-bad version of full privilege. The real test:

> **"If this credential leaked tomorrow, what could the attacker do?"** If the answer is bigger than the component's job description, you don't have least privilege.

## What to Look For During an Engagement

### Quick wins (signs PoLP is being skipped)

```bash
# Database connection strings — any superuser-class username is a finding
grep -rnE 'jdbc:.*://(postgres|root|sa|admin|dba|sysadmin|sysdba)' .
grep -rnE '(spring\.datasource\.username|DATABASE_URL|DB_USER)\s*=\s*(postgres|root|sa|admin)' .

# Cloud IAM — wildcards in policy documents
grep -rn '"Action"\s*:\s*"\*"' --include="*.json" --include="*.yaml" .
grep -rn '"Resource"\s*:\s*"\*"' --include="*.json" --include="*.yaml" .

# Kubernetes — privileged pods, root users, missing securityContext
grep -rn 'privileged:\s*true' --include="*.yaml" .
grep -rn 'runAsUser:\s*0' --include="*.yaml" .

# Container Dockerfiles — running as root
grep -rn '^USER\s*root\|^USER\s*0\b' Dockerfile* .

# Sudo with no password
grep -rn 'NOPASSWD' /etc/sudoers /etc/sudoers.d/

# SUID binaries (post-foothold recon)
find / -perm -4000 -type f 2>/dev/null
```

### The "If this leaked tomorrow" audit prompt

For every credential, role, and service account in the system, write down the answer to:

> *"If this credential leaked tomorrow, list every action the attacker could take with it."*

If the answer is longer than the job the credential exists to do, you've found a PoLP violation. Document each one with the **exact** delta between actual and needed — that's the report.

## Where PoLP Lives in This Vault

PoLP isn't a single bug class — it shows up everywhere data crosses a trust boundary. Every file in the vault that discusses defense or blast radius references this concept. Key touchpoints: [[SQL Injection]], [[Database as a Process]], [[SQLi to RCE on PostgreSQL]], [[Client-Controlled IP Headers]], [[Debug Mode Disclosure]], [[Auditing: Code Review for Spring Boot Apps]].

## Forever Hooks

> **"PoLP is not a tool. It's a discipline you apply at every layer of the stack — code, process, database, filesystem, network, cloud IAM, container."**

> **"The exploitability of a bug is determined by the bug. The blast radius is determined by least privilege."**

> **"If this credential leaked tomorrow, what could the attacker do?" — that's the only PoLP test that matters.**

> **"Every privilege a component has that it doesn't strictly need is a privilege the next attacker inherits for free."**

## Links

- [[Database as a Process]] — the architectural picture that makes PoLP-at-the-DB-layer feel obvious
- [[SQLi to RCE on PostgreSQL]] — what happens when PoLP at the database layer is skipped
- [[SQL Injection]] — the front-door bug that PoLP at the DB layer contains
- [[Client-Controlled IP Headers]] — trust scoping as a PoLP failure
- [[Debug Mode Disclosure]] — debug endpoints as a PoLP failure
- [[Auditing: Code Review for Spring Boot Apps]] — the prove-impact mindset and the superuser-connection-string grep

## My Notes
