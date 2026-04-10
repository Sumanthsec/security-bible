# Cookies and Sessions
Tags: #how-it-works #cookies #sessions #authentication #fundamentals #web-app-flows

## Core

HTTP is stateless. Cookies let the server attach a token to the browser that's sent automatically with every request to that domain. Sessions use that token to identify returning users. The automatic sending is what makes [[CSRF]] possible.

## Cookie Attributes

| Attribute | What It Does | Security Impact |
|---|---|---|
| `HttpOnly` | JS cannot read (`document.cookie` won't show it) | Prevents [[XSS]] from stealing session cookies |
| `Secure` | Only sent over HTTPS | Prevents sniffing on HTTP |
| `SameSite=Lax` | Not sent on cross-site POST | Prevents [[CSRF]] |
| `SameSite=Strict` | Not sent on ANY cross-site request | Strongest CSRF protection, breaks inbound links |
| `SameSite=None` | Sent everywhere (requires `Secure`) | Needed for cross-site APIs, enables CSRF without other protection |
| `Path=/` | Sent for all paths under `/` | `Path=/admin` limits scope |
| `Domain=.example.com` | Sent to all subdomains | Subdomain takeover can steal cookies |
| `Max-Age=3600` | Expires in 3600s | No Max-Age = session cookie (gone when browser closes) |

## Session Types

**Server-side sessions:** Cookie is just a random ID. Data lives on the server (Redis, DB, memory). Can invalidate instantly.
**Signed cookies:** Session data IN the cookie, base64-encoded with cryptographic signature. Can't truly invalidate before expiry. Data visible to user.
**JWT:** Similar to signed cookies, typically in `Authorization` header. Not auto-sent by browser → immune to CSRF, vulnerable to XSS if in localStorage.

## Attack Surface

- **Missing `HttpOnly`** — [[XSS]] steals session via `document.cookie`
- **Missing `Secure`** — network attacker sniffs cookie on HTTP
- **Missing `SameSite`** — [[CSRF]] makes authenticated requests with victim's cookies
- **Predictable session IDs** — brute-force valid tokens
- **Session fixation** — attacker sets cookie before victim logs in, reuses after
- **No server-side invalidation** — logout doesn't destroy session, old cookie works
- **`Domain` too broad** — subdomain takeover reads parent domain cookies
- **JWT in localStorage** — any JS can steal it

## Audit

- [ ] All `Set-Cookie` headers have `HttpOnly`, `Secure`, `SameSite`
- [ ] Logout destroys server-side session
- [ ] Session IDs are long and unpredictable
- [ ] Session ID changes after login (fixation defense)
- [ ] Cookie `Domain` scope not too broad
- [ ] Cookie expiration reasonable
- [ ] Sensitive data in cookies encrypted, not just signed
- [ ] Modified signed cookies rejected by server

## My Notes
