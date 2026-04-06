# HTTP Request & Response
Tags: #how-it-works #http #fundamentals #web-app-flows

## The Problem This Solves

Web applications need a standard way for browsers (clients) to ask servers for resources and for servers to send those resources back. HTTP (HyperText Transfer Protocol) is that standard — a text-based protocol where the client sends a structured request and the server sends a structured response, all inside a [[TLS and PKI|TLS-encrypted]] [[TCP Connections|TCP connection]].

## How a Developer Implements This

Developers rarely write raw HTTP — frameworks handle parsing. But understanding the raw format is critical for security testing because what you see in Burp Suite is the raw HTTP.

## Why Developers Choose Different Approaches

- **Server-rendered HTML** (Flask, Django, Rails) — server builds full HTML pages, returns `Content-Type: text/html`
- **JSON APIs** (Express, FastAPI, Spring Boot) — server returns data, frontend JavaScript renders it, `Content-Type: application/json`
- **Both** — most modern apps use server-rendered pages for initial load, then JSON APIs for dynamic updates

## What the Code Actually Looks Like

### The HTTP Request — Every Component

```http
GET /dashboard?tab=overview HTTP/1.1          ← Request line: METHOD PATH VERSION
Host: www.example.com                          ← Required: which site (virtual hosting)
User-Agent: Mozilla/5.0 (Windows NT 10.0...)   ← Browser identification
Accept: text/html,application/xhtml+xml        ← Response formats I accept
Accept-Language: en-US,en;q=0.9                ← Preferred languages
Accept-Encoding: gzip, deflate, br             ← Compression I support
Cookie: session_id=abc123; theme=dark          ← Cookies sent automatically
Referer: https://www.example.com/login         ← Page I came from
Connection: keep-alive                          ← Keep TCP connection open
                                                ← Empty line = end of headers
                                                ← (GET requests have no body)
```

### POST Request — Form Data

```http
POST /api/login HTTP/1.1
Host: www.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Cookie: csrf_token=xyz789
                                                ← Empty line
username=alice&password=s3cret%21               ← Body (URL-encoded)
```

### POST Request — JSON

```http
POST /api/login HTTP/1.1
Host: www.example.com
Content-Type: application/json
Content-Length: 47

{"username": "alice", "password": "s3cret!"}
```

### The HTTP Response

```http
HTTP/1.1 200 OK                                    ← Status line
Date: Sat, 05 Apr 2026 10:30:00 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 4523
Set-Cookie: session_id=abc123; Path=/; HttpOnly; Secure; SameSite=Lax
Cache-Control: no-store
X-Content-Type-Options: nosniff                     ← Security header
X-Frame-Options: DENY                               ← Prevents clickjacking
Strict-Transport-Security: max-age=31536000         ← Force HTTPS for 1 year
Content-Security-Policy: default-src 'self'         ← XSS protection
                                                     ← Empty line
<!DOCTYPE html>                                      ← Body begins
<html>...
```

## Configuration and Defaults That Matter

### HTTP Methods

| Method | Purpose | Has Body | Idempotent |
|--------|---------|----------|------------|
| `GET` | Retrieve data | No | Yes — safe to repeat |
| `POST` | Submit/create data | Yes | No — may create duplicates |
| `PUT` | Replace entire resource | Yes | Yes — same result if repeated |
| `PATCH` | Partial update | Yes | No |
| `DELETE` | Remove resource | Usually no | Yes |
| `OPTIONS` | Ask what methods are allowed | No | Yes — used in CORS preflight |
| `HEAD` | GET but headers only, no body | No | Yes |

### HTTP Status Codes

```
2xx — Success
  200 OK — request succeeded
  201 Created — resource created (after POST)
  204 No Content — success but no body (after DELETE)

3xx — Redirect
  301 Moved Permanently — resource URL changed forever
  302 Found — temporary redirect (often after login)
  304 Not Modified — use your cached copy

4xx — Client Error
  400 Bad Request — malformed request
  401 Unauthorized — not authenticated (need to log in)
  403 Forbidden — authenticated but not authorized (no permission)
  404 Not Found — resource doesn't exist
  405 Method Not Allowed — wrong HTTP method
  429 Too Many Requests — rate limited

5xx — Server Error
  500 Internal Server Error — app crashed (look for stack traces!)
  502 Bad Gateway — reverse proxy can't reach backend
  503 Service Unavailable — server overloaded
```

### Security-Relevant Headers

| Header | Purpose | Security Impact |
|--------|---------|-----------------|
| `Strict-Transport-Security` | Force HTTPS | Prevents SSL stripping attacks |
| `Content-Security-Policy` | Restrict resource loading | Mitigates [[XSS]] |
| `X-Frame-Options` | Prevent framing | Mitigates [[Clickjacking]] |
| `X-Content-Type-Options: nosniff` | Prevent MIME sniffing | Prevents type confusion attacks |
| `Referrer-Policy` | Control Referer header | Prevents URL leakage |
| `Set-Cookie` flags | Cookie security | See [[Cookies and Sessions]] |

## Where Security Breaks

- **401 vs 403 responses** reveal whether authentication or authorization failed — useful for enumeration
- **500 errors** may leak stack traces, file paths, database errors (useful for [[SQL Injection]] error-based extraction)
- **302 redirects** after login reveal the application's "home" page and flow
- **Missing security headers** open the door for XSS, clickjacking, SSL stripping
- **HTTP methods** not properly restricted — a GET endpoint that modifies data enables [[CSRF]] via `<img>` tags
- **`Referer` header** can leak sensitive URL parameters (tokens, IDs) to third-party resources

## Auditing Checklist

- [ ] Check all security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- [ ] Test HTTP methods — does the endpoint accept methods it shouldn't? (PUT, DELETE on read-only resources)
- [ ] Check for sensitive data in URL parameters (tokens, credentials) — these leak via Referer
- [ ] Look for verbose error responses (500s with stack traces)
- [ ] Check Cache-Control on sensitive pages — are auth pages cached?
- [ ] Test for HTTP request smuggling on HTTP/1.1 endpoints behind reverse proxies

## My Notes
