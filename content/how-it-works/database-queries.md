# Database Queries
Tags: #how-it-works #database #sql #fundamentals #day1

## Core

Web apps send SQL strings to a database over TCP/socket and get result sets back. The developer reads user input from the HTTP request, builds a SQL string, sends it, and formats the result. How they build that string determines the SQLi risk.

## Three Layers

**Raw SQL drivers** (JDBC, psycopg2, PDO): Developer writes SQL directly. Safety depends entirely on using `?`/`$1` placeholders vs string concatenation. Full control, highest risk.

**Query builders** (Knex.js, SQLAlchemy core): Programmatic query construction, auto-parameterized. Low risk unless using `.raw()`.

**ORMs** (Django ORM, JPA/Hibernate, Sequelize): Map objects to tables, generate parameterized queries automatically. Lowest risk — but every ORM has escape hatches.

## ORM Escape Hatches

These functions break the ORM's safety and let developers write raw SQL:

- Django: `.raw()`, `.extra()`
- SQLAlchemy: `text()`, `session.execute()`
- JPA/Hibernate: `createNativeQuery()`, `@Query` with concatenation
- Sequelize: `sequelize.query()`
- Knex: `knex.raw()`

These are where SQLi lives in ORM-heavy codebases.

## Config That Matters

- **`sql_mode`** (MySQL) — strict vs permissive affects query behavior
- **Connection charset** — multi-byte charsets (GBK) can break escaping (CVE-2006-2753)
- **`multiple_statements`** flag — enables stacked queries, greatly expanding SQLi impact
- **DB user privileges** — `FILE` enables `LOAD_FILE`/`INTO OUTFILE`, `EXECUTE` enables stored procs
- **Error display** — dev configs showing DB errors enable error-based extraction

## Attack Surface

1. String concatenation into raw SQL — the classic
2. ORM escape hatches with string formatting
3. Dynamic structural elements — ORDER BY, table/column names from user input
4. Stored procedures with dynamic SQL
5. Second-order — data from DB concatenated into new query
6. Multiple statement support — stacked queries enable INSERT/UPDATE/DELETE/RCE

## Audit

- [ ] Identify all SQL execution points (grep for sinks)
- [ ] Each sink: parameterized or concatenated?
- [ ] Trace concatenated variables back to source
- [ ] Check ORM usage for raw query escape hatches
- [ ] Look for dynamic ORDER BY, table/column names from user input
- [ ] Check stored procedures for dynamic SQL
- [ ] Review DB user privileges (FILE, EXECUTE, xp_cmdshell)
- [ ] Error messages exposed to users?
- [ ] Connection charset config (multi-byte bypass risk)

## My Notes
