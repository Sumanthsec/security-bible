# Authentication and JWT
Tags: #how-it-works #authentication #jwt #spring-security #cookies

## The Problem This Solves

HTTP is stateless. After a user proves who they are once (username + password), the server needs a way to recognize them on every subsequent request without asking for credentials again. There are two solutions: **server-side sessions** (covered in [[Cookies and Sessions]]) and **JWTs** (covered here). Both end up living in a cookie or header that the browser sends automatically.

## The Nightclub — A Mental Model You'll Never Forget

Picture the entire web app as a nightclub called **Bluebird**. You want to get in and stay in all night without showing ID at every bar inside. Five characters run the door:

| Character | What it is in code | Their job |
|---|---|---|
| 🚪 The Doorman | The login controller (`AuthController.loginPOST`) | Greets you at the front, takes your ID card, passes it to the Bouncer |
| 🕶️ The Bouncer | `AuthenticationManager` (Spring Security) | The pro who actually decides if you're legit |
| 📖 The Guestbook Keeper | `UserDetailsServiceImpl.loadUserByUsername` | Walks to the back office, opens the big book, finds your name |
| 🔐 The Lock-Smith | `BCryptPasswordEncoder` | Compares your secret handshake to the one written next to your name |
| 🎟️ The Stamp Guy | `JwtUtils.generateJwtToken` | Stamps your wrist with a glowing UV mark so every bar inside recognizes you |

Five people. One night out. That's the whole auth system.

### Your Night at Bluebird, Scene by Scene

**Scene 1 — You walk up to the door.** You hand the Doorman a piece of paper that says: *"I'm `username`, my secret is `password`."* The Doorman doesn't actually verify anything. He's a polite messenger. He folds the paper and passes it to the Bouncer behind him.

**Mental model:** The controller never checks passwords itself. It's a messenger.

**Scene 2 — The Bouncer takes over.** The Bouncer is a professional. He doesn't remember faces — he sends the Guestbook Keeper to the back office: *"Look up someone called `username`. Bring me their file."* The Guestbook Keeper runs a SQL query against the `users` table and brings back a folder containing the username, email, and a **hash** of the real password (not the password itself — a scrambled fingerprint).

**Scene 3 — The handshake test.** The Bouncer now has two things: the password you claimed, and the scrambled fingerprint from the guestbook. He calls the Lock-Smith over. The Lock-Smith's superpower: he can take your raw password, scramble it the same way, and check if it matches. He **cannot** un-scramble the original — only re-scramble and compare.

- ❌ No match → Bouncer yells *"GET OUT!"* → redirect to `/login?e=Invalid+username+or+password`
- ✅ Match → Bouncer nods at the Doorman: *"He's good."*

**Scene 4 — The wristband.** The Doorman calls over the Stamp Guy. The Stamp Guy writes a tiny note: *"This person is `username`. Issued at 9pm. Expires at 2am. — Signed, Bluebird Management."* He signs it with a secret marker only Bluebird owns (`jwtSecret`). The signature is the magic part — anyone can read the note, but nobody can forge it without the marker. He folds the note into a cookie and slips it in your pocket. The cookie is `HttpOnly` — you can't even pull it out yourself, only the club's staff can read it. Door opens.

**Scene 5 — Inside the club, forever after.** Every bar, every dance floor, every VIP room has a little scanner at the entrance (`AuthTokenFilter`). You walk up, the scanner peeks into your pocket, reads the note, checks the signature is real, and goes: *"Yep, you're `username`. Come on in."* You never have to show your password again. The wristband does all the talking until 2am, when it expires and you get kicked back to the front door.

### The Forever Hook

> **"Doorman takes the paper, Bouncer checks the guestbook with the Lock-Smith, Stamp Guy gives you a wristband, and every door inside just scans the wristband."**

Say that out loud once. That sentence IS the entire auth flow of about 80% of the Spring Boot apps you'll ever encounter.

## How a Developer Implements This

### The Login Endpoint (Controller)

```java
@PostMapping("/login")
public void loginPOST(@RequestParam String username,
                      @RequestParam String password,
                      HttpServletResponse response) throws IOException {
    try {
        // 1. Doorman hands the paper to the Bouncer
        Authentication auth = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(username, password));

        // 2. Sticky note for this request: "user is logged in"
        SecurityContextHolder.getContext().setAuthentication(auth);

        // 3. Stamp Guy makes a wristband
        String jwt = jwtUtils.generateJwtToken(auth);

        // 4. Slip wristband into a cookie
        Cookie cookie = new Cookie(jwtCookieName, jwt);
        cookie.setHttpOnly(true);
        cookie.setMaxAge(jwtExpirationMs);
        response.addCookie(cookie);
        response.sendRedirect("/");

    } catch (BadCredentialsException e) {
        response.sendRedirect("/login?e=Invalid+username+or+password");
    }
}
```

**The single most important line:** `authenticationManager.authenticate(...)`. This one call hides the entire database lookup, BCrypt comparison, and validation logic. From the controller's view, it's a black box — either it returns an authenticated `Authentication` object, or it throws `BadCredentialsException`.

### The Database Lookup (Hidden Inside the Bouncer)

```java
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired JdbcTemplate jdbcTemplate;

    public UserDetails loadUserByUsername(String username) {
        // Parameterized query — SQLi-proof
        String sql = "SELECT * FROM users WHERE username = ?";
        User user = jdbcTemplate.queryForObject(
            sql, new Object[]{username}, new BeanPropertyRowMapper<>(User.class));
        return UserDetailsImpl.build(user);
    }
}
```

This is the Guestbook Keeper. The `?` placeholder is the safe pattern — the actual `username` value is passed separately and the database driver inserts it safely. The login path itself is **not** SQL-injectable on `username` because of this.

### The JWT Generator (Stamp Guy)

```java
public String generateJwtToken(Authentication authentication) {
    UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
    return Jwts.builder()
               .setSubject(userPrincipal.getUsername())              // who is this?
               .setIssuedAt(new Date())                              // when issued?
               .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))  // when does it die?
               .signWith(SignatureAlgorithm.HS512, jwtSecret)        // sign with the secret marker
               .compact();
}
```

Reading it as filling out a form: `setSubject` (whose token), `setIssuedAt` (when), `setExpiration` (until when), `signWith` (sign it), `compact` (squish into one string).

### The Filter That Scans the Wristband (On Every Request)

```java
public class AuthTokenFilter extends OncePerRequestFilter {
    protected void doFilterInternal(HttpServletRequest req, ...) {
        String jwt = parseJwtFromCookie(req);
        if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
            String username = jwtUtils.getUsernameFromJwtToken(jwt);
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities()));
        }
        filterChain.doFilter(req, res);
    }
}
```

This runs on every single request. It reads the cookie, validates the JWT signature, extracts the username, re-loads the user from the DB, and stuffs an authenticated principal into the request context. That's why the user "stays logged in" without server-side sessions.

## The Parameter Journey — One Diagram to Rule Them All

```
browser form
   │  username, password (form-urlencoded POST)
   ▼
AuthController.loginPOST(@RequestParam String username, @RequestParam String password)
   │  wraps in UsernamePasswordAuthenticationToken
   ▼
AuthenticationManager.authenticate(token)              ← 🕶️ THE BOUNCER
   │
   ├─► UserDetailsServiceImpl.loadUserByUsername(username)   ← 📖 GUESTBOOK
   │       └─► parameterized SELECT (safe)
   │       └─► returns User with hashed password
   │
   └─► BCryptPasswordEncoder.matches(rawPassword, hash)      ← 🔐 LOCK-SMITH
           │ ok? returns authenticated Authentication
           ▼
JwtUtils.generateJwtToken(auth)                        ← 🎟️ STAMP GUY
   │  HS512-signed JWT, subject = username
   ▼
HttpOnly cookie set, redirect to "/"
   │
   ▼ (every subsequent request)
AuthTokenFilter reads cookie, validates JWT,
re-loads user, populates SecurityContextHolder
```

## How JWTs Actually Work

A JWT is three base64-encoded parts joined by dots: `header.payload.signature`

```
eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhbGljZSIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDg2NDAwfQ.signature
└────── header ──────┘└─────────────────── payload ──────────────────┘└─ signature ─┘
```

**Header (decoded):** `{"alg": "HS512"}` — which algorithm signed it.

**Payload (decoded):** `{"sub": "alice", "iat": 1700000000, "exp": 1700086400}` — who, when issued, when expires. **This is base64-encoded, not encrypted.** Anyone can decode it and read the contents. Never put secrets in a JWT payload.

**Signature:** `HMAC-SHA512(base64(header) + "." + base64(payload), jwtSecret)` — a hash of the header and payload, salted with the server's secret. The server can recompute this and verify it matches. An attacker can't forge a valid signature without the secret.

### Why Forging Is Hard

```
Without the secret:
  Attacker tries: header.modified_payload.???
  → can't compute the right signature
  → server's validateJwtToken() rejects it

With the secret (e.g., leaked from application.properties):
  Attacker computes: HMAC-SHA512(header + payload, stolen_secret)
  → produces a perfectly valid JWT for any user they want
  → "I am admin" is now legal
```

This is why the JWT secret is the single most valuable thing in the codebase. Find it leaked or weak, and you forge tokens for any account.

## Configuration and Defaults That Matter

- **`bluebird.app.jwtSecret`** in `application.properties` — the signing key. If weak, leaked, or default, the entire auth system collapses.
- **`bluebird.app.jwtExpirationMs`** — token lifetime. Long lifetime + no revocation = stolen tokens stay valid.
- **`HttpOnly` flag on the JWT cookie** — prevents JavaScript from reading the cookie ([[XSS]] can't directly steal it).
- **`Secure` flag on the JWT cookie** — only sent over HTTPS. If missing, network attackers can sniff it on HTTP.
- **`SameSite` flag** — prevents the cookie being sent on cross-site requests ([[CSRF]] mitigation).
- **JWT vs server-side session** — JWTs are stateless (server doesn't store anything). The downside: you **cannot truly invalidate a JWT** before its expiration without adding a server-side blocklist, defeating the point. Logging out can only delete the cookie locally.

## Where Security Breaks

- **Weak or leaked JWT secret** → attacker forges tokens for any user (including admin)
- **`alg: none` accepted** → some JWT libraries accept tokens with no signature if header says `"alg": "none"`. Always check the library's behavior.
- **Algorithm confusion** → server expects `HS256` (symmetric), attacker sends `RS256` (asymmetric) and tricks server into using the public key as the HMAC secret
- **No token expiration** → stolen tokens are valid forever
- **No revocation mechanism** → user changes password but old JWTs still work
- **JWT in localStorage** (instead of HttpOnly cookie) → [[XSS]] reads `localStorage.token` directly
- **Sensitive data in JWT payload** → payload is base64, not encrypted; users can read their own JWT contents
- **Predictable user enumeration** → different errors for "user not found" vs "wrong password" let attackers enumerate valid accounts
- **No rate limiting on `/login`** → brute force the password directly

## Auditing Checklist

- [ ] Find the login controller (`grep -rn "@PostMapping.*login"`)
- [ ] Check the password storage — is BCrypt/Argon2/scrypt used? Or plaintext / MD5 / SHA1?
- [ ] Find the JWT secret in `application.properties` — is it strong, random, environment-loaded? Or hardcoded/default?
- [ ] Check JWT expiration — is it reasonable (hours, not months)?
- [ ] Check cookie flags — `HttpOnly`, `Secure`, `SameSite` all set?
- [ ] Check `validateJwtToken` — does it properly verify the signature? Reject `alg: none`?
- [ ] Test for username enumeration — same error message for "user doesn't exist" vs "wrong password"?
- [ ] Test brute-force protection — is there rate limiting on `/login`?
- [ ] Test logout — does the server actually invalidate the session, or just delete the cookie locally?
- [ ] Look for `/forgot`, `/signup`, `/reset` endpoints — these are the side doors and often less protected than `/login`

## Links

- [[Cookies and Sessions]] — broader cookie/session model and attributes
- [[Spring Boot Basics]] — the framework conventions used here
- [[SQL Injection]] — the most common vulnerability in `/forgot`-style endpoints

## My Notes
