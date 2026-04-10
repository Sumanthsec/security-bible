# Client-Controlled IP Headers (X-Forwarded-For Trust Failure)
Tags: #vulnerability #access-control #headers #spoofing #authentication-bypass #day4

## Core

Apps behind proxies read `X-Forwarded-For` (and variants) to get the "real" client IP. The bug: trusting that header without verifying it came from a trusted proxy. The client can put anything in it. There's no signature, no MAC, no proof.

## Mindset

> "X-Forwarded-For, X-Real-IP, Forwarded, Client-IP, True-Client-IP, X-Originating-IP, CF-Connecting-IP, Via — ALL of these come from the client. The only IP you can trust is `request.getRemoteAddr()`, and only if no reverse proxy sits in front."

> "Whenever you see code that compares an 'IP address' to a magic value like 127.0.0.1, immediately ask: where did they get that IP from? If the answer is a header, it's a bypass."

## Headers to Check

```
X-Forwarded-For       X-Real-IP           X-Originating-IP
X-Client-IP           X-Remote-IP         X-Remote-Addr
True-Client-IP        CF-Connecting-IP    Forwarded: for=
Via
```

Send each one at a time with `127.0.0.1`, diff the response. If anything changes, the app trusts it.

## Target IPs

| Target IP | What it typically unlocks |
|---|---|
| `127.0.0.1` / `127.0.1.1` / `::1` | Localhost-gated debug or admin |
| `10.0.0.1` / `192.168.0.1` / `172.16.0.1` | "Internal network only" features |
| `169.254.169.254` | AWS instance metadata (chain with SSRF) |
| Company CIDR | Geo-fenced or office-only features |
| Country-specific IP | Region-locked features (GDPR, ads, paywalls) |

## What This Bug Enables

- **IP-based access control bypass** — "admin only from 10.0.0.0/8" → set the header
- **Rate-limit bypass** — rotate the header per request
- **Audit log poisoning** — logs record spoofed `client_ip`
- **Debug-mode unlock** — "if localhost, show stack traces" → [[Debug Mode Disclosure]]
- **WAF allowlist bypass** — WAFs treating internal IPs as trusted skip rules
- **SSRF amplification** — spoofed IP embedded in outbound requests

## Chains

- [[Debug Mode Disclosure]] — header spoofing flips the dev/prod conditional
- [[SQL Injection]] — header-spoofed debug access turns blind SQLi into error-based
- [[SSRF]] — `X-Forwarded-For: 169.254.169.254` to convince internal service it's AWS metadata
- [[Rate Limit Bypass]] — rotate header per request to evade per-IP throttles
- [[Authentication Bypass]] — apps that allowlist internal IPs as "no login required"

## Key Watchpoints

- One header can simultaneously bypass auth, unlock debug, defeat rate limits, and poison logs
- ~1 in 5 web apps trust these headers without proxy verification
- Even splitting the comma-separated XFF list and taking the first hop is attacker-controlled
- Express `app.set('trust proxy', true)` trusts all hops blindly — must specify explicit proxy IPs
- This is a [[Principle of Least Privilege]] failure at the trust-scoping layer

## My Notes
