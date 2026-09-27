# GraphQL Security
Tags: #vulnerability #graphql #api #injection #idor #dos #day5

## What is GraphQL and how is it different from REST?

REST has fixed endpoints returning fixed data — `GET /api/users/1` returns all fields, `GET /api/users/1/orders` is a separate call. Over-fetching and multiple round trips.

GraphQL has **one endpoint** (`/graphql`) and the client specifies exactly what data it wants:

```graphql
query {
  user(id: 1) {
    name
    email
    orders {
      id
      total
      items { name price }
    }
  }
}
```

One request, client picks the fields, including nested relationships. Server returns only what was asked.

Why this is a security problem: in REST, each endpoint can have its own auth checks, rate limiting, and validation. In GraphQL, everything goes through one endpoint and the complexity is hidden inside the query.

## How does introspection give attackers a complete map?

GraphQL has a built-in feature that returns the **entire API schema**:

```graphql
query {
  __schema {
    types {
      name
      fields {
        name
        type { name }
      }
    }
  }
}
```

This reveals every type (`User`, `Admin`, `Payment`, `InternalConfig`), every field (`password_hash`, `ssn`, `api_key`), every mutation (`deleteUser`, `promoteToAdmin`, `transferFunds`), and every relationship. In REST, attackers brute-force endpoint discovery. In GraphQL, they just ask.

Even with introspection disabled, **field suggestion errors** leak the schema gradually — send a wrong field name and the error says "Did you mean `password_hash`?"

**Fix:** Disable introspection in production AND suppress field suggestions with generic error messages.

## Why is authorization harder in GraphQL than REST?

In REST, `GET /api/users/1/orders` has one path to protect with one auth check.

In GraphQL, the same data is reachable through **multiple paths**:

```graphql
# Path 1 — direct
query { user(id: 1) { orders { total } } }

# Path 2 — through a product review
query { product(id: 5) { reviews { author { orders { total } } } } }

# Path 3 — through an organization
query { organization(id: 3) { members { orders { total } } } }
```

Developer protects path 1 but forgets paths 2 and 3 also reach the same orders. Every relationship is a potential [[IDOR]] path. The more connected the schema, the more paths exist.

**Fix:** Authorization must be on the **data layer**, not the query layer. Every resolver checks permissions independently regardless of how the query reached it. Better: push auth down to a service layer so it runs whether accessed via GraphQL, REST, or internal calls.

## How does GraphQL enable denial of service?

**Query depth** — the client controls nesting depth:

```graphql
query {
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {  # 50 levels deep — exponential DB queries
          }
        }
      }
    }
  }
}
```

**Alias duplication** — same field requested thousands of times:

```graphql
query {
  a1: orders { total }
  a2: orders { total }
  a3: orders { total }
  # ...1000 aliases, each triggers a separate DB query
}
```

**Circular fragments** — fragments A and B reference each other creating infinite recursion.

**Fix:** Depth limiting (max 5-10 levels), cost analysis (each field gets a score, nested fields multiply, reject queries exceeding the budget), query timeout (kill anything over 5 seconds).

## How does batching bypass rate limiting?

GraphQL supports multiple queries in one HTTP request:

```json
[
  {"query": "mutation { login(user:\"admin\", pass:\"pass1\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"pass2\") { token } }"},
  ...
  {"query": "mutation { login(user:\"admin\", pass:\"pass10000\") { token } }"}
]
```

10,000 login attempts in one HTTP request. Traditional rate limiting counts requests — one request, no limit triggered.

**Fix:** Disable batching if not needed. If needed, limit batch size and rate limit by **operation count**, not request count.

## How does injection work through GraphQL?

GraphQL doesn't protect against injection. If the resolver concatenates arguments into a query:

```javascript
// Vulnerable resolver
resolve(parent, args) {
  return db.query(`SELECT * FROM users WHERE name = '${args.name}'`);
}
```

```graphql
query {
  user(name: "' OR '1'='1") {
    name
    email
    password_hash
  }
}
```

Standard [[SQL Injection]] through a GraphQL argument. Same root cause, different transport.

**Fix:** Parameterized queries in resolvers. Use GraphQL's type system for input validation with constraints on length, pattern, and range.

## What about mutations without authorization?

Developers sometimes protect queries but forget mutations:

```graphql
mutation {
  updateUserRole(userId: 1542, role: "admin") {
    id
    role
  }
}
```

If this doesn't check if the requesting user is an admin, anyone can promote themselves.

**Fix:** Every mutation must check permissions. Default deny — if a mutation lacks an `@auth` directive, it should fail closed with no access.

## How do you fix GraphQL — the complete checklist?

| Issue | Fix |
|---|---|
| Introspection | Disable in production |
| Field suggestions | Suppress in error messages — generic errors only |
| Authorization | Resolver-level or data-layer checks on every query and mutation |
| Query depth | Depth limiting (max 5-10) |
| Query complexity | Cost analysis with per-field scoring |
| Query timeout | Kill queries over 5 seconds |
| Batching | Disable or limit batch size |
| Rate limiting | Count operations, not requests |
| Injection | Parameterized queries in resolvers |
| Input validation | Use GraphQL type system with constraints |
| Mutations | Auth check on every mutation, default deny |
| Error messages | Generic errors only in production — no stack traces, no suggestions |
| Fragments | Use modern library with cycle detection (built into Apollo, graphql-js) |

## How do you test GraphQL security?

1. **Find the endpoint** — `/graphql`, `/graphql/v1`, `/api/graphql`, `/gql`
2. **Try introspection** — if enabled, you have the full map
3. **If introspection disabled** — use tools like Clairvoyance to reconstruct schema from error messages
4. **Test every mutation for authorization** — create two accounts, try each mutation with the other user's session
5. **Test arguments for injection** — same as testing REST parameters
6. **Test query depth and batching** — check if limits exist
7. **Look for sensitive fields** — `password`, `token`, `secret`, `internal` in the schema

**Tools:** GraphQL Voyager (schema visualization), InQL (Burp extension), Clairvoyance (schema reconstruction), BatchQL (batching tests).

## My Notes
