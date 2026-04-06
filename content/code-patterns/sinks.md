# Sinks

## SQL Execution — Functions That Run Queries

### Python
| Function | Library | Notes |
|----------|---------|-------|
| `cursor.execute()` | mysql-connector, psycopg2, sqlite3 | Safe if parameterized tuple: `execute("...%s", (var,))` — vulnerable if string formatted: `execute(f"...{var}")` |
| `cursor.executemany()` | mysql-connector, psycopg2, sqlite3 | Same rules as execute() |
| `.raw()` | Django ORM | Raw SQL escape hatch — vulnerable if concatenated |
| `.extra()` | Django ORM | Accepts raw SQL fragments in `where=[]` — vulnerable if concatenated |
| `engine.execute()` | SQLAlchemy | Direct SQL execution |
| `session.execute()` | SQLAlchemy | Safe with `text()` + bind params, vulnerable with `text()` + f-string |
| `text()` | SQLAlchemy | Safe: `text("...WHERE x = :val"), {"val": input}` — Vulnerable: `text(f"...WHERE x = '{input}'")` |

### Java
| Function | Library | Notes |
|----------|---------|-------|
| `statement.executeQuery()` | JDBC | `Statement` = unsafe (string concat), `PreparedStatement` = safe |
| `statement.executeUpdate()` | JDBC | Same as above |
| `statement.execute()` | JDBC | Same as above |
| `createStatement()` | JDBC | Returns `Statement` — no parameterization, always suspect |
| `createNativeQuery()` | JPA/Hibernate | Raw SQL escape hatch from the ORM |
| `jdbcTemplate.query()` | Spring JDBC | Safe with `?` placeholders, vulnerable with concatenation |

### Node.js
| Function | Library | Notes |
|----------|---------|-------|
| `pool.query()` | mysql2, pg | Safe with `?` placeholders |
| `pool.execute()` | mysql2 | Safe with `?` placeholders |
| `connection.query()` | mysql2, pg | Safe with `?` placeholders |
| `sequelize.query()` | Sequelize | Raw SQL escape hatch |
| `knex.raw()` | Knex.js | Raw SQL escape hatch |

### PHP
| Function | Library | Notes |
|----------|---------|-------|
| `mysqli_query()` | MySQLi | No parameterization in the function itself |
| `mysql_query()` | mysql (deprecated) | No parameterization, deprecated but still everywhere |
| `->query()` | PDO | Direct query execution |
| `->exec()` | PDO | Direct query execution, no result set |
| `->prepare()` | PDO | Safe IF followed by `->execute()` with bound params |
