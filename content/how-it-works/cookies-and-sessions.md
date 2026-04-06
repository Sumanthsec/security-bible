# Cookies and Sessions
Tags: #how-it-works #cookies #sessions #authentication #fundamentals #web-app-flows

## The Problem This Solves

HTTP is stateless — every request is independent. The server doesn't inherently know that the person requesting `/dashboard` is the same person who just logged in on `/login`. Cookies and sessions solve this by giving the browser a token it sends with every request, allowing the server to identify returning users.

## How a Developer Implements This

### The Full Cookie Lifecycle

```
Step 1: User logs in successfully
  POST /login → server validates credentials → server creates a session

  Response:
    HTTP/1.1 302 Found
    Set-Cookie: session_id=a1b2c3d4e5f6; Path=/; HttpOnly; Secure; SameSite=Lax
    Location: /dashboard

Step 2: Browser stores the cookie
  Browser sees Set-Cookie → stores in cookie jar for this domain

Step 3: Every subsequent request — browser sends it automatically
  GET /dashboard HTTP/1.1
  Cookie: session_id=a1b2c3d4e5f6     ← browser adds this, no JS needed

  GET /api/profile HTTP/1.1
  Cookie: session_id=a1b2c3d4e5f6     ← automatic on every request to this domain

Step 4: Server looks up the session
  Reads "session_id=a1b2c3d4e5f6" from Cookie header
  → looks up in session store (Redis, database, memory)
  → finds: {user: "alice", role: "admin", logged_in_at: "2026-04-05T10:30:00"}
  → knows this request is from Alice
```

**Critical:** the browser sends cookies **automatically** with every request to that domain. The user doesn't choose to send them. JavaScript doesn't need to attach them. This automatic behavior is what makes [[CSRF]] possible.

## Why Developers Choose Different Approaches

### Server-Side Sessions

The cookie is just a random **identifier**. Session data lives on the server:

```python
# Server-side session store (Redis, database, memory)
{
    "a1b2c3d4e5f6": {
        "user_id": 42,
        "username": "alice",
        "role": "admin",
        "logged_in_at": "2026-04-05T10:30:00"
    }
}
```

Pros: server controls all data, can invalidate sessions instantly (logout = delete from store).
Cons: requires server-side storage, shared state across multiple servers needs shared store (Redis).

### Signed Cookies (Client-Side Sessions)

Session data is IN the cookie itself, base64-encoded, with a cryptographic signature:

```
Set-Cookie: session=eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoiYWRtaW4ifQ.signature
```

Flask does this by default. The signature prevents tampering — if the user modifies the data, the signature won't match and the server rejects it.

Pros: no server-side storage needed, stateless.
Cons: can't truly invalidate sessions (cookie still valid until expiry), data visible to the user (base64 is encoding, not encryption).

### JWT (JSON Web Tokens)

Common for APIs. Similar to signed cookies but typically sent in the `Authorization` header instead of `Cookie`:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWxpY2UifQ.signature
```

Not automatically sent by the browser (unlike cookies) — JavaScript must attach it. This makes JWT immune to [[CSRF]] but vulnerable to [[XSS]] (if stored in localStorage, JS can read and steal it).

## What the Code Actually Looks Like

### Setting a Cookie (Server-Side)

```python
# Flask
response.set_cookie('session_id', value='a1b2c3d4e5f6',
                     httponly=True, secure=True, samesite='Lax',
                     max_age=3600)
```

```javascript
// Express
res.cookie('session_id', 'a1b2c3d4e5f6', {
    httpOnly: true, secure: true, sameSite: 'lax',
    maxAge: 3600000
});
```

### Reading a Cookie (Server-Side)

```python
# Flask
session_id = request.cookies.get('session_id')
```

```javascript
// Express (with cookie-parser)
const sessionId = req.cookies.session_id;
```

## Configuration and Defaults That Matter

### Cookie Attributes — Each One Has Security Impact

```http
Set-Cookie: session_id=abc123; Path=/; Domain=.example.com; HttpOnly; Secure; SameSite=Lax; Max-Age=3600
```

| Attribute | What It Does | Security Impact |
|-----------|-------------|-----------------|
| `HttpOnly` | JavaScript **cannot** read this cookie (`document.cookie` won't show it) | Prevents [[XSS]] from stealing session cookies |
| `Secure` | Cookie only sent over HTTPS, never HTTP | Prevents sniffing on unencrypted connections |
| `SameSite=Lax` | Cookie not sent on cross-site POST requests | Prevents [[CSRF]] attacks |
| `SameSite=Strict` | Cookie not sent on ANY cross-site request | Strongest CSRF protection but breaks inbound links |
| `SameSite=None` | Cookie sent everywhere (requires `Secure`) | Needed for cross-site APIs but enables CSRF if no other protection |
| `Path=/` | Cookie sent for all paths under `/` | `Path=/admin` limits scope |
| `Domain=.example.com` | Cookie sent to all subdomains | Subdomain takeover can steal cookies |
| `Max-Age=3600` | Expires in 3600 seconds | No Max-Age/Expires = session cookie (deleted when browser closes) |

### Where Cookies Are Stored

- **Session cookies** (no Max-Age/Expires) — browser memory, gone when browser closes
- **Persistent cookies** (has Max-Age/Expires) — browser disk, survives restart
- Viewable in: Chrome DevTools → Application tab → Cookies

## Where Security Breaks

- **Missing `HttpOnly`** — [[XSS]] can steal session with `document.cookie`
- **Missing `Secure`** — network attacker sniffs cookie on HTTP
- **Missing `SameSite`** — [[CSRF]] attacks can make authenticated requests using the victim's cookies
- **Predictable session IDs** — attacker brute-forces valid session tokens
- **Session fixation** — attacker sets the session cookie before the victim logs in, then uses the same session after login
- **No server-side invalidation** — logging out doesn't actually destroy the session, old cookie still works
- **`Domain` set too broadly** — subdomain takeover lets attacker read cookies for the parent domain
- **JWT in localStorage** — accessible to any JavaScript, so [[XSS]] steals the token directly

## Auditing Checklist

- [ ] Check all `Set-Cookie` headers for `HttpOnly`, `Secure`, `SameSite` flags
- [ ] Test session invalidation — does logout actually destroy the server-side session?
- [ ] Check session ID randomness — are tokens long enough and unpredictable?
- [ ] Test for session fixation — does the session ID change after login?
- [ ] Check cookie scope — is `Domain` set too broadly?
- [ ] Check cookie expiration — do session cookies persist too long?
- [ ] Look for sensitive data in cookies (especially client-side sessions — is data encrypted or just signed?)
- [ ] Test what happens when you modify a signed cookie — does the server reject it?

## My Notes
