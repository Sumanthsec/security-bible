# Auditing: Code Review for Spring Boot Apps
Tags: #auditing #code-review #spring-boot #methodology #java

## Approach

> "Annotations tell me WHERE, RequestParams tell me WHAT, AuthenticationManager is a black box I trust, and `+` in SQL is always blood in the water."

You don't read every file. Map the surface first — controllers are the attack surface. Then follow user input from entry to dangerous sink.

### Surface Mapping

1. **List every endpoint:** grep for `@GetMapping` / `@PostMapping` / etc.
2. **Glance at `@Autowired` fields per controller:** `JdbcTemplate` = raw SQL (high risk), `RestTemplate` = outbound HTTP (SSRF risk), `ProcessBuilder` = shell (RCE risk)
3. **For each endpoint, list inputs:** `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue`, plus `request.getParameter()` / `request.getHeader()`

## The 6-Step Playbook

1. **`@Autowired` fields** — know the toolkit (JDBC? JWT? RestTemplate?)
2. **List every `@*Mapping`** — every endpoint is a door
3. **Trace input to sinks** — SQL string → [[SQL Injection]], file path → path traversal, shell command → RCE, template → XSS, redirect URL → open redirect, outbound URL → SSRF
4. **Find every SQL query** — `?` placeholder = safe, `+` concatenation with user input = vulnerable
5. **Find every redirect** — `sendRedirect` / `return "redirect:"` built from user input = open redirect
6. **Find every cookie creation** — missing `setHttpOnly(true)` / `setSecure(true)` = finding

## Reviewer Instincts

**SQLi antenna:** `JdbcTemplate` in `@Autowired` → check every query for `?` vs `+`.

**Side doors:** Login path is most-audited. Real bugs live on `/forgot`, `/signup`, `/reset-password`, search/filter endpoints, admin panels. When the front door looks too clean, walk around the building.

**Second-order:** `user.getEmail()` looks internal, but trace it back — if user controls email via registration, it's second-order SQLi when concatenated later.

**JWT secret:** Always check `application.properties` for the signing secret. Hardcoded/default/weak = forge tokens for any user.

**Error handler:** Read every catch block. Conditional error disclosure based on IP/header/env = [[Debug Mode Disclosure]]. Often the difference between blind and error-based SQLi.

**XFF trust:** Any read of `X-Forwarded-For` / `X-Real-IP` / `True-Client-IP` / etc. compared to `127.0.0.1` or internal ranges = bypass via [[Client-Controlled IP Headers]].

**Dev-mode conditional:** Any branch that says "if dev/debug/internal, show extra info" — condition is almost always attacker-flippable.

## application.properties Red Flags

```properties
spring.profiles.active=dev
management.endpoints.web.exposure.include=*
debug=true
server.error.include-stacktrace=always
server.error.include-message=always
spring.boot.admin.client.enabled=true
```

Each is a finding on its own.

## Multi-Finding Density

> "A hacker maps the whole graph, not one bug class at a time."

| Finding | Severity | Tell |
|---|---|---|
| SQLi in email concatenation | High | `WHERE email = '" + email + "'` |
| XFF trust for IP gating | High | `getHeader("X-FORWARDED-FOR")` → `.equals("127.0.0.1")` |
| Stack trace disclosure | Medium | `e.getStackTrace()` rendered when IP check passes |
| Reset link in error log | Medium | `logger.error("TODO- Send email with " + resetLink)` |
| Predictable reset token | Medium-High | `MD5(id + ":" + email + ":" + hash)` |
| Missing rate limiting | Low-Medium | No throttle in controller or filter chain |

**Reading checklist for any sensitive function:**
1. Where does user input enter?
2. Where does it touch a sink?
3. What trust assumptions are made?
4. Where does sensitive data end up?
5. What's missing that should be there?
6. What does the catch block do?

## Prove-Impact

> "Defenders prove a bug exists. Attackers prove a bug matters."

After every confirmed bug: check `application.properties` for the DB username. `postgres`/`root`/`sa` = the SQLi is a path to RCE, not just a data leak. That's a [[Principle of Least Privilege]] failure. Trace the chain: data → file read → file write → commands → shell.

## Common Patterns

| Pattern | Risk |
|---|---|
| App connects as `postgres`/`root`/`sa` | Any SQLi → RCE via [[Database as a Process]] |
| Login uses `?`, but `/forgot` concatenates | SQLi on the less-audited path |
| JWT secret in `application.properties` | Token forgery |
| Raw `getHeader("X-Forwarded-For")` for trust | Header spoofing bypass |
| Stored input re-used in query | Second-order SQLi |
| `csrf().disable()` in WebSecurityConfig | CSRF |
| File path from user input | Path traversal |
| Debug-gated stack trace | [[Debug Mode Disclosure]] |
| Sensitive values in logger calls | Account takeover via log read |
| `MD5`/`SHA1` reset tokens from deterministic inputs | Offline-computable tokens |
| `matches()` blacklist filter | Bypassable — use `find()` |

## Red Flags

- `spring.datasource.username=postgres` (or root/sa) — any SQLi escalates to RCE
- `@Autowired JdbcTemplate` + any `+` in SQL string
- Different errors for "user not found" vs "wrong password"
- Stack traces in HTTP responses
- Cookies without `HttpOnly`/`Secure`
- `csrf().disable()` in security config
- Hardcoded secrets in `application.properties`
- `@PreAuthorize` missing on sensitive endpoints
- User input flowing into `Runtime.exec`, `ProcessBuilder`, `RestTemplate`
- Any IP header read compared to localhost/internal ranges
- `spring.profiles.active=dev` or `management.endpoints.web.exposure.include=*`
- Shape regex used to gate input that gets concatenated into SQL
- No rate limiting on sensitive endpoints

## My Notes
