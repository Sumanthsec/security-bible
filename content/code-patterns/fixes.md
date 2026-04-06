# Fixes

## SQL Injection — Parameterized Queries

The only architecturally correct fix. Separates SQL structure from data values at the database protocol level.

### Python
```python
# mysql-connector / psycopg2 — %s placeholder with tuple
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
cursor.execute("SELECT * FROM products WHERE name LIKE %s", ('%' + query + '%',))

# CRITICAL DISTINCTION:
# cursor.execute("... %s" % var)    ← STRING FORMATTING — VULNERABLE
# cursor.execute("... %s", (var,))  ← PARAMETERIZED BINDING — SAFE
# The comma-separated tuple makes the difference

# SQLAlchemy — text() with bind parameters
session.execute(text("SELECT * FROM users WHERE email = :email"), {"email": user_input})

# Django ORM raw — positional parameters
User.objects.raw("SELECT * FROM users WHERE email = %s", [user_input])
```

### Java
```java
// PreparedStatement — ? placeholders with typed setters
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, userId);
ResultSet rs = ps.executeQuery();

// NEVER use Statement with concatenation — always PreparedStatement
```

### Node.js
```javascript
// mysql2 / pg — ? placeholders with array
const [rows] = await pool.execute('SELECT * FROM users WHERE id = ?', [userId]);
```

### PHP
```php
// PDO — ? placeholders with array
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$userId]);

// PDO — named placeholders
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $userId]);
```

## SQL Injection — Allowlisting for Structural Elements

For SQL structure that can't be parameterized (ORDER BY, table/column names, operators):

```python
ALLOWED_SORT_COLUMNS = {'name', 'price', 'created_at'}
ALLOWED_DIRECTIONS = {'asc', 'desc'}
ALLOWED_FILTER_COLUMNS = {'email', 'role', 'status'}
ALLOWED_OPERATORS = {'=', 'LIKE', '>', '<', '>=', '<='}

sort = request.args.get('sort', 'name')
direction = request.args.get('dir', 'asc')

if sort not in ALLOWED_SORT_COLUMNS:
    sort = 'name'           # Replace with safe default
if direction.lower() not in ALLOWED_DIRECTIONS:
    direction = 'asc'

# Now safe to concatenate — value is guaranteed to be from known-good set
cursor.execute(f"SELECT * FROM products ORDER BY {sort} {direction}")
```
