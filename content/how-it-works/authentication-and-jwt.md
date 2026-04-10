# Authentication and JWT
Tags: #how-it-works #authentication #jwt #spring-security #cookies

## Core

HTTP is stateless. After login, the server needs to recognize the user on every subsequent request. JWTs solve this by issuing a signed token (in a cookie or header) that proves identity without server-side session storage.

## The Nightclub Model

| Character | Code equivalent | Job |
|---|---|---|
| Doorman | Login controller | Takes credentials, passes to Bouncer |
| Bouncer | `AuthenticationManager` | Decides if you're legit |
| Guestbook Keeper | `UserDetailsService.loadUserByUsername` | Looks up user in DB |
| Lock-Smith | `BCryptPasswordEncoder` | Compares password hash |
| Stamp Guy | `JwtUtils.generateJwtToken` | Issues signed wristband (JWT) |

**The flow:** Doorman takes credentials → Bouncer delegates to Guestbook + Lock-Smith → match? → Stamp Guy issues JWT in HttpOnly cookie → every subsequent request, the filter scans the wristband.

> "Doorman takes the paper, Bouncer checks the guestbook with the Lock-Smith, Stamp Guy gives you a wristband, and every door inside just scans the wristband."

## JWT Structure

Three base64 parts joined by dots: `header.payload.signature`. Header = algorithm. Payload = claims (`sub`, `iat`, `exp`). **Payload is base64, not encrypted** — anyone can decode and read it. Never put secrets in the payload.

**Signature** = `HMAC-SHA512(header + "." + payload, jwtSecret)`. Server recomputes and compares. Can't forge without the secret.

## Why Forging Matters

**Without the secret:** attacker can't compute the right signature → server rejects.
**With the secret** (leaked from config, weak/default): attacker computes valid JWT for any user including admin. The JWT secret is the single most valuable thing in the codebase.

## Attack Surface

- **Weak or leaked JWT secret** → token forgery for any user
- **`alg: none` accepted** → tokens with no signature pass validation
- **Algorithm confusion** → RS256/HS256 swap tricks server into using public key as HMAC secret
- **No token expiration** → stolen tokens valid forever
- **No revocation mechanism** → password change but old JWTs still work
- **JWT in localStorage** → [[XSS]] reads it directly
- **Sensitive data in JWT payload** → base64 is encoding, not encryption
- **User enumeration** → different errors for "not found" vs "wrong password"
- **No rate limiting on `/login`** → brute force

## Audit

- [ ] Find login controller — check password storage (BCrypt/Argon2/scrypt, not MD5/SHA1/plaintext)
- [ ] Find JWT secret in config — strong, random, env-loaded? Or hardcoded/default?
- [ ] JWT expiration reasonable (hours, not months)?
- [ ] Cookie flags: `HttpOnly`, `Secure`, `SameSite` all set?
- [ ] `validateJwtToken` properly verifies signature and rejects `alg: none`?
- [ ] Same error for "user doesn't exist" vs "wrong password"?
- [ ] Rate limiting on `/login`?
- [ ] Logout invalidates server-side, or just deletes cookie?
- [ ] Check `/forgot`, `/signup`, `/reset` — side doors, often less protected

## My Notes
