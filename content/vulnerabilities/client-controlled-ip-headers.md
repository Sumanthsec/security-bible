# Client-Controlled IP Headers (X-Forwarded-For Trust Failure)
Tags: #vulnerability #access-control #headers #spoofing #authentication-bypass #day4

## Understand the Feature First

Modern web apps almost never see the real client. The browser talks to a CDN, the CDN talks to a load balancer, the load balancer talks to a reverse proxy, the reverse proxy talks to the application server. By the time the HTTP request reaches the app, `request.getRemoteAddr()` (or its equivalent) returns the IP of the *nearest hop* — usually a proxy, not the actual end user.

To preserve the original client IP through this chain, proxies inject a header. The de-facto standard is `X-Forwarded-For`, plus a half-dozen vendor variants (`X-Real-IP`, `Forwarded`, `True-Client-IP`, `Client-IP`, `X-Originating-IP`, `CF-Connecting-IP`, `Via`...). The application server is then expected to read that header and treat it as "the real client."

This is a legitimate, necessary pattern. Geo-routing, audit logging, abuse detection, rate limiting, GDPR consent flows — all of them need the actual client IP, and the only way to get it through a proxy chain is via these headers.

## Why It Exists (Root Cause)

The bug is **trusting the header without verifying who it came from.**

```java
String ipAddress = request.getHeader("X-FORWARDED-FOR");
if (ipAddress == null) {
    ipAddress = request.getRemoteAddr();
}
if (ipAddress.equals("127.0.1.1")) {
    // show debug info
}
```

The developer asks "is this request from localhost?" and answers it by reading a header **the client just sent them**. The client can put anything in that header. There's no signature, no MAC, no proof. It's a string the attacker controls.

> **Forever-hook:** "X-Forwarded-For, X-Real-IP, Forwarded, Client-IP, True-Client-IP, X-Originating-IP, CF-Connecting-IP, Via — ALL of these come from the client. The only IP you can actually trust is `request.getRemoteAddr()`, and even that one is only trustworthy if no reverse proxy sits in front of you."

The reason developers fall into this is that in a *correctly configured* environment with a *trusted* proxy that strips inbound `X-Forwarded-For` and writes a fresh one, the header genuinely is the real client IP. The bug is reading it without first verifying the request came from your own proxy. If the backend is reachable directly, or if the proxy passes inbound headers through unchanged, the attacker controls the value end-to-end.

> **Forever-hook:** "Whenever you see code that compares an 'IP address' to a magic value like 127.0.0.1 or an internal range, immediately ask: where did they get that IP from? If the answer is a header, it's a bypass."

## The Data Flow

```
ATTACKER                     APP SERVER
   │                              │
   │  POST /forgot HTTP/1.1       │
   │  X-Forwarded-For: 127.0.0.1  │
   │  email=...                   │
   ├─────────────────────────────►│
   │                              │
   │                              ▼
   │                         request.getHeader("X-FORWARDED-FOR")
   │                              │  returns "127.0.0.1"
   │                              ▼
   │                         if (ip.equals("127.0.1.1"))
   │                              │  TRUE — gate flips
   │                              ▼
   │                         show debug info / stack trace / admin features
   │                              │
   │◄─────────────────────────────┤
   │   200 OK + sensitive data    │
```

The attacker never had to be on localhost. They never had to ARP-poison a network. They sent a string in an HTTP header, and the application took their word for it.

## What the Developer Should Have Done

There is no safe way to read `X-Forwarded-For` from an arbitrary client. The only correct patterns are:

1. **Use `request.getRemoteAddr()` (or your stack's equivalent) — and only that** — for any decision that matters (auth, debug gating, rate limiting, IP allowlists). Accept that if you're behind a proxy, this returns the proxy's IP, and bake that assumption into your design.
2. **If you genuinely need the original client IP**, configure a trusted proxy chain:
   - Make sure the application is **not directly reachable** from the internet.
   - Configure the proxy to **strip any inbound `X-Forwarded-For`** and write a fresh one.
   - In the application, only trust `X-Forwarded-For` when `request.getRemoteAddr()` matches the proxy's known IP. Walk the comma-separated list from right to left, dropping hops until you reach an untrusted IP — that's the real client.
3. **Use a framework feature instead of rolling your own.** Spring's `ForwardedHeaderFilter`, Django's `USE_X_FORWARDED_HOST`, Express's `app.set('trust proxy', ...)`, ASP.NET Core's `ForwardedHeadersMiddleware` all do the right thing *only* when you tell them which proxies to trust.
4. **Never** use any of these for **authentication** or **authorization** decisions. IP-based trust is reconnaissance metadata, not an identity claim.

## Exploitation

The full bypass payload is one line of `curl`:

```bash
curl -H "X-Forwarded-For: 127.0.0.1" https://target/some-endpoint
```

That's it. If the endpoint reads any of the trusted-IP headers and gates behavior on the value, you've flipped the gate.

### Headers to try

When auditing, send the request with each of these one at a time and diff the response. If anything changes, you've found the header the app trusts:

```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
Forwarded: for=127.0.0.1
Via: 127.0.0.1
```

Useful target IPs depending on what you're trying to unlock:

| Target IP | What it usually unlocks |
|---|---|
| `127.0.0.1` / `127.0.1.1` / `::1` | Localhost-gated debug or admin |
| `10.0.0.1` / `192.168.0.1` / `172.16.0.1` | "Internal network only" features |
| `169.254.169.254` | AWS instance metadata (when chained with SSRF) |
| Any IP in the company's CIDR | Geo-fenced or office-only features |
| Country-specific IP from a public IP-to-country DB | Region-locked features (GDPR, ads, paywalls) |

### What this bug typically unlocks

- **IP-based access control bypass.** "Admin panel only allowed from 10.0.0.0/8" → set the header.
- **Rate-limit bypass.** Rotate the header per request and never get throttled.
- **Audit log poisoning.** Logs record `client_ip` from the header → frame anyone or hide your tracks.
- **Geo-locked feature unlock.** EU-only GDPR pages, US-only ads, country paywalls.
- **Debug-mode unlock.** "If localhost, show stack traces / SQL errors / dev tools" → all of it lights up. (See [[Debug Mode Disclosure]].)
- **SSRF amplification.** Some apps embed the "client IP" in outbound requests or webhooks; you can pivot the spoofed IP into other internal calls.
- **WAF allowlist bypass.** WAFs sometimes treat internal IPs as trusted and skip rules — set the header and the WAF goes silent.

## What the Vulnerable Code Looks Like

### Java / Spring

```java
// Dead obvious — uses the header first
String ip = request.getHeader("X-FORWARDED-FOR");
if (ip == null) ip = request.getRemoteAddr();
if (ip.equals("127.0.0.1")) showDebugInfo();

// Slightly less obvious — splits the comma list and takes the first hop
String xff = request.getHeader("X-Forwarded-For");
String clientIp = (xff != null) ? xff.split(",")[0].trim() : request.getRemoteAddr();
// Still attacker-controlled — they can put anything in the leftmost slot.
```

### Python / Django / Flask

```python
# Django — only safe if USE_X_FORWARDED_HOST is set AND you're behind a trusted proxy
ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')

# Flask — same trap
ip = request.headers.get('X-Forwarded-For', request.remote_addr)
if ip == '127.0.0.1':
    return render_template('debug.html')
```

### Node.js / Express

```javascript
// Express — req.ip is safe ONLY if app.set('trust proxy', ...) is configured correctly
const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
if (ip === '127.0.0.1') return res.json(secrets);

// Even req.ip is dangerous if 'trust proxy' is set to true (trusts all hops blindly)
app.set('trust proxy', true);  // ← BAD: trusts any X-Forwarded-For
app.set('trust proxy', 'loopback');  // ← OK: only trusts loopback
```

### PHP

```php
// Direct read
$ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];
if ($ip === '127.0.0.1') { /* show debug */ }
```

## What the Fix Looks Like

```java
// Java — use the socket peer, never the header
String ip = request.getRemoteAddr();
if (ip.equals("127.0.0.1") || ip.equals("0:0:0:0:0:0:0:1")) {
    showDebugInfo();
}
// And put the app behind a proxy that won't allow direct connections.
```

```javascript
// Express — explicit trust list
app.set('trust proxy', ['loopback', '10.0.0.0/8']); // only these proxies
// req.ip will now reflect the leftmost untrusted hop, not whatever the client sends
```

```python
# Django — set USE_X_FORWARDED_HOST = True only after locking down the proxy
# Then use a hardened helper:
def get_real_ip(request):
    # Walk X-Forwarded-For from right to left, drop trusted proxies, return first
    # untrusted hop. Return REMOTE_ADDR if no proxy chain.
    ...
```

**The mental rule:** never make a security decision on a value the client can set. If you must use IP for anything that matters, use the socket peer and architect the proxy chain so that's the real client.

**Why this is a [[Principle of Least Privilege]] failure too.** PoLP isn't only about database roles and OS users — it's about *trust scoping*. The application is implicitly granting the entire internet the same trust level as a localhost developer the moment it reads `X-Forwarded-For` without verifying the proxy. The fix is one application of PoLP at the trust-boundary layer: only the socket peer is trusted, only known proxies can speak about other clients, debug surfaces are scoped to "reachable from a specific admin host over a separate channel" rather than "anyone who sends the right header." Every "trust the header" bug is the same shape as every "give the app superuser" bug — over-broad trust granted to a component that didn't need it.

## Chains With

- [[Debug Mode Disclosure]] — header spoofing flips the dev/prod conditional and unlocks the developer view
- [[SQL Injection]] — header-spoofed access to a debug-only error path turns blind SQLi into error-based SQLi (this is exactly what BlueBird's `/forgot` does)
- [[SSRF]] — combine with `X-Forwarded-For: 169.254.169.254` to convince an internal service it's being called by AWS metadata
- [[CSRF]] — header-spoofed "internal request" can defeat origin checks that allowlist internal IPs
- [[Rate Limit Bypass]] — rotate the header per request to evade per-IP throttles
- [[Authentication Bypass]] — apps that allowlist internal IPs as "no login required"

## Key Q&A From This Session

**Q: The dev says "but proxies set this header" — is it a real bug?**
A: The header is meaningful from a trusted proxy. The bug is reading it without verifying the request came from that proxy. Fix = configuration (strip inbound XFF at the proxy, only trust when `getRemoteAddr()` matches), not just code.

**Q: How to detect this in black-box testing?**
A: Send the request twice — without header, then with `X-Forwarded-For: 127.0.0.1`. If the response differs (content, status, timing, new fields, stack traces), the app trusts the header. Burp Intruder against a wordlist of header names for the systematic version.

## Lab Work

- PortSwigger Web Security Academy — Access control labs (some involve `X-Forwarded-For`-style bypasses)
- HTB BlueBird — `/forgot` endpoint uses `X-Forwarded-For` to gate stack-trace disclosure
- Any CTF box with "admin only from localhost" reverse-engineered access controls

## Key Insights

- **Any header naming an IP comes from the client.** The only IP the network stack guarantees is `request.getRemoteAddr()`.
- **One header unlocks many bug classes.** A single `X-Forwarded-For: 127.0.0.1` can bypass auth, unlock debug info, defeat rate limits, and poison logs simultaneously.
- **1 in 5 web apps.** Every framework has this footgun. Developers reach for it before understanding it.
- **A dozen aliases.** `X-Real-IP`, `Forwarded`, `True-Client-IP`, `CF-Connecting-IP`, `X-Client-IP`, `X-Originating-IP`, `Via` — all spoofable, all worth testing.

## Questions That Came Up

- How do you walk a comma-separated `X-Forwarded-For` list correctly when you have multiple legitimate proxies?
- What are the exact framework defaults for Spring, Express, Django, ASP.NET — which trust the header out of the box?
- How do CDNs like Cloudflare's `CF-Connecting-IP` differ — is that header authenticated cryptographically or just by source IP allowlist?

## Links

- [[Debug Mode Disclosure]] — the bug class this most often unlocks
- [[SQL Injection]] — chains via debug-gated error paths becoming attacker-reachable
- [[Authentication and JWT]] — auth flows that use IP as a trust signal
- [[Auditing: Code Review for Spring Boot Apps]] — where the header-trust red flag lives in the audit checklist
- [[Principle of Least Privilege]] — header-trust failures are PoLP failures at the trust-scoping layer

## My Notes
