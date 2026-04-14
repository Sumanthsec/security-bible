# Authentication Flaws
Tags: #vulnerability #authentication #sessions #jwt #csrf #day5

## How do server-side sessions work?

User logs in with credentials. Server validates them, creates a session object (user ID, role, expiration) stored server-side (memory, database, Redis), and generates a random session ID. That ID goes back to the browser in a `Set-Cookie` header. Every subsequent request includes the cookie automatically — the server looks up the session ID, finds the session object, and knows who you are.

The session ID is the only thing the client holds. All actual session data lives on the server. The client never sees or controls its own role, permissions, or identity — it just presents a key, and the server decides what that key maps to.

## What makes a session ID secure?

**Randomness** — if an attacker can predict the next session ID, they can forge sessions without credentials. It must come from a cryptographically secure random generator, not `Math.random()` or timestamps.

**Length** — short IDs can be brute-forced. 128+ bits of entropy makes enumeration infeasible.

**No meaning** — the ID shouldn't encode user data (user ID, role). If it does, the attacker can modify it. It's a lookup key, nothing more.

## What do cookie flags actually protect against?

| Flag | What it does | What it prevents |
|---|---|---|
| `HttpOnly` | JavaScript can't read the cookie via `document.cookie` | XSS stealing session ID |
| `Secure` | Cookie only sent over HTTPS | Network sniffing on HTTP |
| `SameSite=Strict` | Cookie never sent on cross-site requests | CSRF completely |
| `SameSite=Lax` | Cookie sent on cross-site top-level GET navigations only | CSRF on POST (not GET) |
| `Expires`/`Max-Age` | Cookie dies after set time | Indefinite session persistence |

`HttpOnly` doesn't prevent XSS — the attacker still has JavaScript execution. It prevents one specific XSS action: reading the cookie. The attacker can still make authenticated requests from the page, modify the DOM, or redirect the user. It removes the easiest exfiltration path.

## What is session fixation?

The attacker sets the victim's session ID before they log in. If the app doesn't regenerate the session ID after authentication, the attacker already knows the post-login session ID because they chose it.

Attack flow: attacker gets a valid session ID from the server → tricks the victim into using that ID (via URL parameter, meta tag, or XSS) → victim logs in → server upgrades that same session to authenticated → attacker uses the same ID, now authenticated as the victim.

Fix: always regenerate the session ID after login. The pre-auth and post-auth session IDs must be different.

## What is CSRF and what conditions does it need?

Cross-Site Request Forgery — the attacker's site makes the victim's browser send a request to a target site, and the browser attaches the victim's cookies automatically. The server can't tell if the request came from its own UI or from `evil.com`.

Three conditions must all be true:
1. **Cookie-based auth** — the browser must automatically attach credentials
2. **No unpredictable parameter** — the attacker must be able to construct the full request without knowing any user-specific values
3. **State-changing action worth exploiting** — changing password, transferring money, modifying settings

If any one is missing, CSRF doesn't work. If there's a CSRF token the attacker can't predict, they can't construct the request. If the action requires the current password, the attacker doesn't know it.

## How does SameSite actually work?

**SameSite=Strict** — cookie is never sent on any cross-site request. If you're on `evil.com` and click a link to `bank.com`, the cookie isn't sent. Completely kills CSRF, but breaks usability — clicking a link from email or Google to `bank.com` also drops the cookie, so you're logged out.

**SameSite=Lax** — cookie is sent on cross-site top-level GET navigations (clicking a link, typing in address bar) but not on POST, not in iframes, not in AJAX. This is the browser default.

Lax blocks the classic CSRF (hidden form POST from `evil.com`). But if the app does state-changing operations on GET (`/api/transfer?to=attacker&amount=1000`), Lax doesn't save you — the GET goes through with cookies. That's why GET requests must never change state.

**SameSite=None** — cookie sent everywhere, cross-site included. Must have `Secure` flag. Used for legitimate cross-site scenarios (embedded widgets, OAuth flows). No CSRF protection.

## What are CSRF tokens and why do they work?

Server generates a random, unpredictable token tied to the user's session. Embeds it in forms as a hidden field. When the form is submitted, server checks: does the token in the request match the one I issued for this session?

The attacker on `evil.com` can't read the token because same-origin policy prevents reading responses from `bank.com`. They can make the browser send requests to `bank.com`, but they can't read `bank.com`'s pages to extract the token. Without the token, the server rejects the request.

**Custom headers work the same way** — adding `X-Requested-With: XMLHttpRequest` to AJAX requests. Cross-site requests can't set custom headers without CORS preflight approval. If the server requires the header, simple cross-site form submissions fail.

## How should logout actually work?

The session must be destroyed server-side. Deleting the cookie from the browser is not enough — if the attacker already captured the session ID (via XSS, network sniffing, logs), they can still use it until it expires.

Proper logout: server deletes the session object from its store (memory, Redis, database), then tells the browser to clear the cookie. The session ID is now invalid even if someone has a copy.

**Password change should invalidate all sessions.** If the user changes their password because they suspect compromise, every existing session for that user must be destroyed — otherwise the attacker's already-established session keeps working.

## What are JWTs and how are they different from sessions?

**Server-side sessions** = stateful. Server stores session data and the client holds just a lookup key. Server must check its store on every request.

**JWTs** = stateless. All session data (user ID, role, expiration) lives inside the token itself, signed by the server. The server doesn't store anything — it verifies the signature on each request and trusts the claims inside if the signature is valid.

JWT structure: `header.payload.signature` — three Base64URL-encoded parts separated by dots.

- **Header** — algorithm used (`HS256`, `RS256`) and token type
- **Payload** — the claims (user ID, role, `exp`, `iat`). Not encrypted — anyone can decode it. Don't put secrets here.
- **Signature** — `HMAC-SHA256(base64(header) + "." + base64(payload), secret)` for symmetric, or RSA/ECDSA sign for asymmetric. This is the only thing preventing tampering.

The server signs the token on login and gives it to the client. On every request, the server recalculates the signature and compares. If the payload was modified (changed role from "user" to "admin"), the signature won't match, and the server rejects it.

## Why is `alg: none` an attack?

The JWT header specifies which algorithm to use for verification. If the server trusts this field and the attacker sets `"alg": "none"`, the server skips signature verification entirely. The attacker can now modify any claim (set admin=true) and the token is accepted without a valid signature.

This works because the JWT spec includes `none` as a valid algorithm for unsecured tokens. Libraries that implemented the spec literally would accept it. The fix: never let the token tell you how to verify it. The server must enforce the expected algorithm, not read it from the header.

## How does weak secret brute-forcing work?

For HMAC-signed JWTs (HS256), the server uses a shared secret to sign. If the secret is weak (`password123`, `secret`, the company name), the attacker can brute-force it offline.

They have the token (header + payload + signature). They try secrets from a wordlist, compute the signature for each, and compare. If it matches — they now have the signing key. They can forge any token with any claims.

This is an offline attack — no interaction with the server needed, no rate limiting possible, no logs generated. Tools like `hashcat` or `jwt_tool` automate this. The fix: use a long random secret (256+ bits), or use asymmetric algorithms (RS256) where the private key never leaves the server.

## What is the RS256→HS256 algorithm confusion attack?

RS256 uses asymmetric crypto — private key signs, public key verifies. The public key is often accessible (JWKS endpoint, certificate, config file). HS256 uses symmetric crypto — the same key signs and verifies.

The attack: change the JWT header from `RS256` to `HS256`. Sign the modified token using the server's public key as the HMAC secret. If the server reads the algorithm from the token header and switches to HS256 verification, it will use its public key (which it has loaded for RS256 verification) as the HMAC key — and the signature matches because that's exactly what the attacker used to sign.

The root cause is the same as `alg: none` — the server trusts the token to tell it how to verify the token. The token is untrusted input. Verification parameters must come from server configuration, not from the thing being verified.

## How does `kid` injection work?

The `kid` (Key ID) header parameter tells the server which key to use for verification — useful when rotating keys. The server takes the `kid` value and looks up the corresponding key.

If that lookup hits a database: `SELECT key FROM keys WHERE kid = '...'` — and the `kid` isn't parameterized, it's SQL injection through the JWT header. The attacker injects `' UNION SELECT 'known-secret' --` as the `kid`, the query returns their chosen secret, and they sign the token with that secret.

If the lookup reads a file: `open("/keys/" + kid)` — and the path isn't validated, it's path traversal. The attacker sets `kid` to `../../dev/null` (which reads as empty/null bytes), signs the token with an empty secret, and the signatures match.

The pattern: any JWT header field that the server uses in a backend operation (database query, file read, HTTP request) is an injection point. The JWT header is attacker-controlled input.

## What are `jku` and `x5u` attacks?

`jku` (JWK Set URL) tells the server where to fetch the public key for verification. If the server trusts this field, the attacker sets it to their own server hosting their own public key. The server fetches the attacker's key and uses it to verify the token — which the attacker signed with their own private key. Verification passes.

`x5u` works the same way but points to an X.509 certificate URL.

This is SSRF through the JWT header. The server makes an outbound request to a URL the attacker controls. The fix: never fetch keys from URLs specified in the token. Use a hardcoded JWKS endpoint or pre-loaded keys.

Similarly, the `jwk` header parameter can embed a public key directly in the token. If the server uses the embedded key to verify the token that contains it — that's self-signed. The attacker generates their own key pair, embeds the public key in the JWT header, signs with the private key.

## Where should JWTs be stored?

| Storage | XSS risk | CSRF risk |
|---|---|---|
| `localStorage` | JavaScript can read it — XSS steals the token | No CSRF — token isn't sent automatically |
| `HttpOnly` cookie | JavaScript can't read it | CSRF possible — browser sends cookie automatically |

There's no perfect answer. `localStorage` means any XSS exfiltrates the token. `HttpOnly` cookie means you need CSRF protection. Most recommendations lean toward `HttpOnly` cookie because CSRF is easier to defend against (tokens, SameSite) than XSS is to fully prevent.

## What are refresh tokens and why do they exist?

Short-lived access token (minutes) + long-lived refresh token (days/weeks). When the access token expires, the client sends the refresh token to get a new access token without re-entering credentials.

**Why not just use a long-lived access token?** If a long-lived token is stolen, the attacker has access for the entire lifetime. With short-lived access tokens, a stolen token expires quickly. The refresh token is only sent to one specific endpoint (`/token/refresh`), reducing its exposure surface.

**How the browser knows to refresh:** the client gets the expiration time from the token payload (or a separate response field). Before or when a request fails with 401, it sends the refresh token to the refresh endpoint, gets a new access token, and retries.

**Common flaws:**
- Refresh token stored in `localStorage` — defeats the purpose, XSS steals it
- Refresh token never expires — attacker has permanent access
- Refresh token not invalidated on logout — same as not destroying a session
- No refresh token rotation — the same refresh token works forever. Proper rotation: each refresh returns a new refresh token, and the old one is invalidated. If an old refresh token is used (attacker replaying a stolen one), invalidate all tokens for that user.

## My Notes
