# Database Queries
Tags: #how-it-works #database #sql #fundamentals #day1

## The Problem This Solves

Every dynamic web application needs to store and retrieve data — users, products, orders, sessions. The application needs a way to ask the database questions ("find all products matching this search") and get structured answers back.

## How a Developer Implements This

The application connects to a database (MySQL, PostgreSQL, MSSQL, Oracle) over TCP or a Unix socket. It sends SQL strings — literal text — and receives result sets back. At the protocol level (visible in Wireshark), you'd see a MySQL `COM_QUERY` packet containing:

```sql
SELECT name, price FROM products WHERE name LIKE '%shoes%'
```

The developer writes a handler function that:
1. Reads user input from the HTTP request
2. Builds a SQL string
3. Sends it to the database
4. Formats the result into an HTTP response

### Raw database drivers (direct SQL)

The lowest level. Developer writes SQL strings and sends them through a database driver:

```java
// Java — JDBC (pattern is identical in Python/psycopg2, Node/pg, PHP/PDO)
Connection conn = DriverManager.getConnection("jdbc:mysql://db/store", "app", "secret");
PreparedStatement ps = conn.prepareStatement("SELECT name, price FROM products WHERE id = ?");
ps.setInt(1, productId);
ResultSet rs = ps.executeQuery();
```

### ORMs (Object-Relational Mappers)

An abstraction layer that maps application objects to database tables. The developer works with objects instead of SQL — the ORM generates parameterized queries under the hood:

```python
# Django ORM — maps objects to tables, generates parameterized queries under the hood
product = Product.objects.get(id=product_id)      # Generates: SELECT ... WHERE id = ?
results = Product.objects.filter(name__contains=q) # Generates: SELECT ... WHERE name LIKE ?
```

**Why developers choose ORMs:** automatic parameterization, less boilerplate. **Why they bypass them:** complex queries, performance, DB-specific features. The bypass = raw SQL escape hatches (`.raw()`, `.extra()`, `text()`, `knex.raw()`) — and that's where SQLi lives.

### Query builders

Middle ground between raw SQL and full ORMs. Build queries programmatically but closer to SQL:

```javascript
// Knex.js
const results = await knex('products').where('name', 'like', `%${query}%`).select('name', 'price');
// Safe — parameterized under the hood

// Knex.js raw — unsafe if concatenated
const results = await knex.raw(`SELECT * FROM products WHERE name LIKE '%${query}%'`);
```

## Why Developers Choose Different Approaches

| Approach | Pros | Cons | SQLi Risk |
|----------|------|------|-----------|
| Raw SQL | Full control, best performance | Verbose, manual parameterization | High if concatenating |
| Query builder | Cleaner API, auto-parameterization | Less control than raw SQL | Low, unless using `.raw()` |
| ORM | Least code, automatic safety | Learning curve, complex queries hard | Low, unless using escape hatches |

## What the Code Actually Looks Like

A typical Flask endpoint with database interaction:

```python
@app.route('/search')
def search():
    query = request.args.get('q')                        # Read from HTTP request
    cursor.execute(
        "SELECT name, price FROM products WHERE name LIKE %s",
        ('%' + query + '%',)                              # Parameterized
    )
    results = cursor.fetchall()                           # Get rows
    return render_template('results.html', products=results)  # Render HTML
```

A typical Spring Boot endpoint:

```java
@GetMapping("/search")
public List<Product> search(@RequestParam String q) {
    return productRepository.findByNameContaining(q);    // JPA method — safe
}
```

## Configuration and Defaults That Matter

- **MySQL `sql_mode`** — strict mode vs permissive mode affects what queries succeed or error
- **Connection charset** — GBK and other multi-byte charsets can break escaping (CVE-2006-2753)
- **`multiple_statements` flag** — if enabled, allows stacked queries (`;`), greatly expanding SQLi impact
- **Database user privileges** — `FILE` privilege enables `LOAD_FILE`/`INTO OUTFILE`, `EXECUTE` enables stored procedures
- **Error display** — development configs that show database errors to the user enable error-based extraction

## Where Security Breaks

1. **String concatenation into raw SQL** — the classic, across all languages
2. **ORM escape hatches** — `.raw()`, `.extra()`, `text()` with string formatting
3. **Dynamic structural elements** — ORDER BY, table names, column names from user input
4. **Stored procedures with dynamic SQL** — concatenation inside the procedure
5. **Second-order** — data read from the database concatenated into a new query (trusting your own data)
6. **Multiple statement support** — stacked queries enable INSERT/UPDATE/DELETE/command execution

## Auditing Checklist

- [ ] Identify all SQL execution points (grep for sinks)
- [ ] Check each sink: parameterized or concatenated?
- [ ] Trace concatenated variables back to their source
- [ ] Check ORM usage for raw query escape hatches
- [ ] Look for dynamic ORDER BY, table/column names from user input
- [ ] Check stored procedures for dynamic SQL
- [ ] Review database user privileges (FILE, EXECUTE, xp_cmdshell)
- [ ] Check if error messages are exposed to users
- [ ] Check connection charset configuration (multi-byte bypass risk)

## My Notes
