# HTTP Request & Response
Tags: #how-it-works #http #fundamentals #web-app-flows

## Core

HTTP is a text-based request/response protocol inside a [[TLS and PKI|TLS-encrypted]] [[TCP Connections|TCP connection]]. What you see in Burp Suite is the raw HTTP. Understanding this format is essential for security testing.

## GET Request

```http
GET /dashboard?tab=overview HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0...)
Accept: text/html,application/xhtml+xml
Cookie: session_id=abc123; theme=dark
Referer: https://www.example.com/login
Connection: keep-alive
```

## POST Request (form)

```http
POST /api/login HTTP/1.1
Host: www.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Cookie: csrf_token=xyz789

username=alice&password=s3cret%21
```

## Response

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Set-Cookie: session_id=abc123; Path=/; HttpOnly; Secure; SameSite=Lax
Cache-Control: no-store
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'

<!DOCTYPE html>...
```

## HTTP Methods

| Method | Purpose | Has Body | Idempotent |
|--------|---------|----------|------------|
| `GET` | Retrieve data | No | Yes |
| `POST` | Submit/create | Yes | No |
| `PUT` | Replace resource | Yes | Yes |
| `PATCH` | Partial update | Yes | No |
| `DELETE` | Remove resource | Usually no | Yes |
| `OPTIONS` | Allowed methods query | No | Yes (CORS preflight) |
| `HEAD` | GET headers only | No | Yes |

## Status Codes

```
2xx Success:   200 OK, 201 Created, 204 No Content
3xx Redirect:  301 Permanent, 302 Found (temp), 304 Not Modified
4xx Client:    400 Bad Request, 401 Unauthenticated, 403 Forbidden,
               404 Not Found, 405 Method Not Allowed, 429 Rate Limited
5xx Server:    500 Internal Error, 502 Bad Gateway, 503 Unavailable
```

## Security Headers

| Header | Purpose | Security Impact |
|--------|---------|-----------------|
| `Strict-Transport-Security` | Force HTTPS | Prevents SSL stripping |
| `Content-Security-Policy` | Restrict resource loading | Mitigates [[XSS]] |
| `X-Frame-Options` | Prevent framing | Mitigates [[Clickjacking]] |
| `X-Content-Type-Options: nosniff` | Prevent MIME sniffing | Prevents type confusion |
| `Referrer-Policy` | Control Referer header | Prevents URL leakage |
| `Set-Cookie` flags | Cookie security | See [[Cookies and Sessions]] |

## Attack Surface

- **401 vs 403** reveals auth vs authz failure — useful for enumeration
- **500 errors** may leak stack traces, DB errors (error-based [[SQL Injection]])
- **Missing security headers** → XSS, clickjacking, SSL stripping
- **Unrestricted HTTP methods** — GET that modifies data enables [[CSRF]] via `<img>` tags
- **`Referer` header** leaks sensitive URL params to third parties

## Audit

- [ ] Check all security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- [ ] Test HTTP methods — endpoint accepts methods it shouldn't?
- [ ] Sensitive data in URL params (tokens, creds) — leak via Referer
- [ ] Verbose 500 errors with stack traces
- [ ] Cache-Control on sensitive pages — auth pages cached?
- [ ] HTTP request smuggling on HTTP/1.1 behind reverse proxies

## My Notes
