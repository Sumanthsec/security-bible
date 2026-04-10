# Fixing SQLi
Tags: #vulnerability #injection #defense #database

## Parameterized Queries

The fix operates at the protocol level. `COM_STMT_PREPARE` sends the query structure to the parser. `COM_STMT_EXECUTE` sends data values as binary in a separate message. The parser is done before data arrives — there is nothing to confuse.

This is not escaping. Escaping still sends one string and hopes the parser handles it correctly. Parameterization separates the channels entirely — structure in one message, data in another.

Every language has this: `?` placeholders (JDBC, PHP PDO), `$1` (PostgreSQL), `%s` with tuple (Python psycopg2), `@param` (MSSQL). The syntax varies, the principle is identical.

## What Can't Be Parameterized

SQL structure — table names, column names, ORDER BY direction, operators — can't be sent as parameters because the parser needs them to build the query plan. Parameters can only go where literal values go.

The fix is allowlisting: compare the user's input against a hardcoded list of valid values. Everything else becomes a default. `if column not in ['name', 'email', 'created_at']: column = 'created_at'`.

Blocklisting fails here for the same reason sanitization fails everywhere — you're trying to enumerate the bad instead of defining the good.

## ORMs

ORMs prevent SQLi by generating parameterized queries automatically. You write `User.objects.filter(email=input)` and the ORM produces `SELECT ... WHERE email = $1` with the value bound separately.

The escape hatches: `.raw()` (Django), `.extra()` (Django, deprecated), `text()` (SQLAlchemy), `createNativeQuery()` (JPA/Hibernate), `knex.raw()` (Knex.js), `sequelize.query()` (Sequelize). Each drops back to raw SQL string handling — grep for these, they're where [[SQL Injection]] lives in modern codebases.

## PoLP at the DB Layer

Parameterization stops the bug. [[Principle of Least Privilege]] stops the escalation.

The application's database user should never be superuser. Restrict: no `FILE` privilege, no superuser role, no DDL, no `pg_read_server_files` / `pg_write_server_files` / `pg_execute_server_program`. The app needs SELECT/INSERT/UPDATE/DELETE on its own tables — nothing more.

"If this credential leaked tomorrow, what could the attacker do?" — the same SQLi bug is a data leak or full RCE depending entirely on the answer.

Default installs ship superuser. Fix this before fixing anything else.

## Why WAFs Are Not a Fix

WAFs parse HTTP. Databases parse SQL. These are fundamentally different parsers with different grammars — the gap between them is where every bypass lives. A WAF is a blocklist enforced by the wrong parser.

Defense in depth, not primary defense. A WAF that catches `' OR 1=1` misses `%2527`, `/*!50000UNION*/`, and everything the next researcher discovers.

## My Notes
