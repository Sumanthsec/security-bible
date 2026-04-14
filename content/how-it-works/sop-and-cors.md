# Same-Origin Policy and CORS
Tags: #how-it-works #sop #cors #browser-security #day5

## What problem does Same-Origin Policy solve?

You're logged into bank.com in one tab. You open evil.com in another tab. Both tabs run in the same browser, with access to the same cookies. Without restrictions, evil.com's JavaScript could `fetch('https://bank.com/api/account-details')`, read your balance, SSN, everything, and send it to the attacker's server. You'd never know.

SOP is the browser's fundamental security boundary: JavaScript on one origin can only read responses from the same origin.

An origin is defined by three things — **scheme + host + port**:

| URL | Same origin as `https://bank.com`? | Why |
|---|---|---|
| `https://bank.com/api/data` | Yes | Same scheme, host, port |
| `http://bank.com` | No | Different scheme |
| `https://bank.com:8080` | No | Different port |
| `https://api.bank.com` | No | Different host |
| `https://evil.com` | No | Different host |

When evil.com tries to `fetch('https://bank.com/api/...')`, the browser actually sends the request — but blocks evil.com's JavaScript from reading the response. The request reaches the server, but evil.com never sees what came back.

This is why CSRF works but data theft doesn't — CSRF triggers an action (the request is sent) but can't read the response. SOP blocks the reading, not the sending.

## What problem does SOP create?

SOP is strict. But legitimate applications need cross-origin communication. Your frontend at `app.example.com` needs to call your API at `api.example.com`. A third-party widget needs to load data from its own server. SOP blocks all of this because they're different origins.

## What is CORS and how does it relate to SOP?

CORS (Cross-Origin Resource Sharing) is the controlled exception to SOP. It lets the server say "I trust this specific origin to read my responses" through response headers:

`Access-Control-Allow-Origin: https://app.example.com`

The flow:
1. JavaScript on `app.example.com` makes a request to `api.example.com`
2. Browser sends the request with an `Origin: https://app.example.com` header
3. Server responds with `Access-Control-Allow-Origin: https://app.example.com`
4. Browser checks: does the Origin match? Yes → JavaScript can read the response

**Preflight requests:** for "complex" requests (PUT, DELETE, custom headers, JSON content type), the browser sends an OPTIONS request first asking "will you accept this?" The server responds with which methods, headers, and origins are allowed. Only if the preflight passes does the browser send the actual request.

## How is SOP/CORS different from CSP?

They sound similar but control different things.

**SOP/CORS** — controls which **other websites** can read your data. "Can evil.com's JavaScript read responses from bank.com?" Protects your server's data from untrusted origins.

**CSP** — controls what **your own page** can load and execute. "What scripts, images, and connections is my page allowed to use?" Protects your users from malicious content injected into your page (XSS).

If there's no XSS, CSP isn't relevant — nothing malicious is on your page. But SOP is still protecting your data from other sites. If there IS XSS, SOP doesn't help — the malicious script is already on your origin, so SOP considers it trusted. But CSP can block it.

Different attacks, different defenses.

## If curl bypasses CORS, what's the point of it?

The attacker wants to steal YOUR data — not their own. If the attacker curls `bank.com/api/account`, whose account do they see? Their own — or nobody's, if they don't have credentials. Curl doesn't have your cookies or your session.

The only way the attacker can make an authenticated request as you is through YOUR browser — because your browser holds your session cookie. The attacker needs evil.com to make your browser send a request to bank.com, and your browser automatically attaches your cookies.

CORS stops exactly this — it prevents evil.com from reading bank.com's response through your browser.

Two layers protect against two different attack paths:

| Attack path | What stops it |
|---|---|
| Victim visits evil.com → attacker uses victim's browser to read bank.com | CORS blocks it |
| Attacker directly hits bank.com (curl/Postman) → no valid credentials | Auth blocks it |
| Attacker already stole credentials (XSS, sniffing) | Neither helps — need token revocation, short sessions |

Both defenses are needed. Without CORS, every website you visit could read every other website's data using your active sessions.

## Why is CORS not a replacement for server-side auth?

CORS is enforced by the browser. No browser involved → no CORS enforcement. `curl`, Postman, Python scripts — all ignore CORS entirely.

If your endpoint has no authentication and you're relying on CORS to prevent unauthorized access, anyone with curl can hit it directly. Common mistake with internal APIs behind a firewall — developers think "it's only accessible from our network, we don't need auth." Then an SSRF or compromised service hits those endpoints. No browser, no CORS, no auth — full access.

CORS protects users' browsers. Server-side authentication and authorization on every endpoint protects everything else.

## How do developers misconfigure CORS?

**Reflecting the Origin header** — the worst one. Developer wants CORS to work with cookies but can't use `*` with credentials (spec forbids it). Lazy shortcut: echo back whatever Origin the request sends.

```python
origin = request.headers.get('Origin')
response.headers['Access-Control-Allow-Origin'] = origin  # reflects anything
response.headers['Access-Control-Allow-Credentials'] = 'true'
```

evil.com sends a request → server responds with `Access-Control-Allow-Origin: https://evil.com` + credentials allowed → browser lets evil.com read authenticated responses. SOP effectively disabled.

**Trusting null origin** — `Access-Control-Allow-Origin: null` with credentials. Attackers manufacture null origins using sandboxed iframes: `<iframe sandbox="allow-scripts" src="data:text/html,...">`. The request has `Origin: null`, server trusts it, attacker reads authenticated data.

Why developers add null: they see it during local development (opening HTML files directly from `file://` protocol) and add it to their config. It goes to production.

**Weak regex matching** — server checks if the origin "contains" `bank.com`. Attacker uses `evil-bank.com` or `bank.com.evil.com`. Or server checks suffix without the dot — `evilbank.com` matches.

**Trusting all subdomains** — `*.bank.com` is allowed. If any subdomain has XSS — `blog.bank.com`, `staging.bank.com` — the attacker uses that XSS to make credentialed CORS requests to `api.bank.com`. The subdomain is trusted.

## How do you implement CORS correctly?

**Explicit allowlist of trusted origins.** Don't reflect, don't regex, don't wildcard.

```python
ALLOWED_ORIGINS = ['https://app.bank.com', 'https://admin.bank.com']

origin = request.headers.get('Origin')
if origin in ALLOWED_ORIGINS:
    response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Credentials'] = 'true'
# If origin isn't in the list, don't set the header at all
```

**Only allow credentials when necessary.** If the endpoint doesn't need cookies (public data), use `Access-Control-Allow-Origin: *` without `Allow-Credentials`.

**Restrict methods and headers.** Only what your frontend actually needs — don't allow everything.

**Never trust null origin.** There's almost no legitimate reason.

**Server-side auth on every endpoint regardless.** CORS is a browser courtesy, not access control.

## How do you test for CORS misconfigurations?

**1. Test origin reflection.** In Burp, add `Origin: https://evil.com` to an authenticated request. If the response contains `Access-Control-Allow-Origin: https://evil.com` with `Access-Control-Allow-Credentials: true` — full misconfiguration. Any website can read authenticated responses.

**2. Test null origin.** Send `Origin: null`. If accepted with credentials, exploitable via sandboxed iframes.

**3. Test subdomain trust.** Send `Origin: https://anything.bank.com`. If accepted, any XSS on any subdomain can read data from the main API.

**4. Test regex bypasses.** Try `https://evil-bank.com`, `https://bank.com.evil.com`, `https://evilbank.com` — check if the origin validation is weak.

**5. Test with no Origin header.** Remove it entirely. Some servers only apply CORS restrictions when the header is present.

**6. Check preflight responses.** Send OPTIONS and examine `Access-Control-Allow-Methods` and `Access-Control-Allow-Headers` — overly permissive preflight expands what cross-origin requests can do.

**7. Automate across all endpoints.** Different endpoints might have different CORS configs. In Burp, use "Match and Replace" to add `Origin: https://evil.com` to every request, then scan responses.

**8. Verify exploitability.** Build a proof of concept — host a page that makes a credentialed fetch to the target API and displays the response. If you see the victim's data, exploitation confirmed.

## My Notes
