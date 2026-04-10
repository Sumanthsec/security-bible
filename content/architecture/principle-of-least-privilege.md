# Principle of Least Privilege
Tags: #architecture #defense #hardening #principle #least-privilege #day4

## The Rule

> "Every component — every user, process, service account, line of code — should run with the smallest set of privileges necessary to do its job, and no more."

PoLP is not a tool. It's a **design discipline** applied at every layer: code, process, database, filesystem, network, cloud IAM, container. Every privilege a component has that it doesn't strictly need is a privilege the next attacker inherits for free.

> "The exploitability of a bug is determined by the bug. The blast radius is determined by least privilege."

## Applied

| Bug class | PoLP layer that contains it |
|---|---|
| SQLi | DB role privileges (no superuser, no FILE, no DDL) |
| RCE in app | OS user permissions (dedicated user, no sudo, no docker group) |
| File write | Filesystem perms / read-only mount / immutable bits |
| Webshell drop | Web root not writable by app user |
| Reverse shell | Egress firewall denies outbound |
| Credential theft | IAM scoped to one bucket / one secret |
| Pivot | Network ACLs deny lateral connections |

Every layer that practices PoLP raises the cost of escalation by one bug.

## The Test

> "If this credential leaked tomorrow, what could the attacker do?" If the answer is bigger than the component's job description, you don't have least privilege.

## Why It Gets Skipped

1. **Convenience** — "Just run as root, we'll fix later." Never gets scoped down.
2. **Wrong defaults** — PostgreSQL ships `postgres` superuser, MySQL ships `root`, AWS ships `AdministratorAccess`. Path of least resistance = maximum surplus.
3. **Invisible until exploited** — no test checks "this code can also do twelve things it shouldn't."

## What to Look For

### Superuser connection strings (finding before reading any code)

```
spring.datasource.username=postgres     spring.datasource.username=root
spring.datasource.username=sa           DATABASE_URL containing postgres/root/sa
```

### Cloud IAM wildcards

```json
"Action": "*", "Resource": "*"
```

### Container misconfigs

`privileged: true`, `runAsUser: 0`, missing `securityContext`

### OS-level

- `id postgres` showing `docker` or `sudo` groups
- `NOPASSWD` in sudoers
- SUID binaries (`find / -perm -4000`)
- World-writable web root

## Forever Hooks

> "PoLP is not a tool. It's a discipline at every layer — code, process, database, filesystem, network, cloud IAM, container."

> "The exploitability of a bug is determined by the bug. The blast radius is determined by least privilege."

> "If this credential leaked tomorrow, what could the attacker do?"

> "Every privilege a component has that it doesn't strictly need is a privilege the next attacker inherits for free."

## My Notes
