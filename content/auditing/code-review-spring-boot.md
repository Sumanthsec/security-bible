# Auditing: Code Review for Spring Boot Apps
Tags: #auditing #code-review #spring-boot #methodology #java

## Mindset Before Touching Anything

You don't read every file in a codebase. You build a map first, then follow user input from where it enters to where it touches something dangerous. In a Spring Boot app, user input always enters through a **controller method** marked with `@RequestMapping`-style annotations. Every vulnerability lives at the end of a path that starts there. Your job is to walk those paths.

You don't need to be a senior Java developer. You need to recognize four annotations, understand that `+` in a SQL string is blood in the water, and trust that anything past `authenticationManager.authenticate(...)` is a black box that Spring Security handles correctly.

## The Forever Hook

> **"Annotations tell me WHERE, RequestParams tell me WHAT, AuthenticationManager is a black box I trust, and `+` in SQL is always blood in the water."**

Repeat that once. That sentence is the entire reviewer mindset.

## Step 1: Map the Surface

### List Every Endpoint (the Attack Surface)

```bash
grep -rnE "@(Get|Post|Put|Delete|Patch|Request)Mapping" --include="*.java" .
```

Make a list of every URL the app exposes:

```
GET  /                       IndexController.index()
GET  /find-user              IndexController.findUser()
POST /login                  AuthController.loginPOST()
POST /register               AuthController.registerPOST()
POST /forgot                 AuthController.forgotPOST()
GET  /profile/{id}           ProfileController.profile()
POST /profile/edit           ProfileController.editPOST()
POST /post                   PostController.createPost()
```

Every entry on this list is a potential vulnerability. If you don't know the entry points, you don't know what to test.

### Glance at `@Autowired` Fields Per Controller

Before reading method bodies, look at the top of each controller class:

```java
@Autowired JdbcTemplate jdbcTemplate;            // ← raw SQL — high risk
@Autowired JwtUtils jwtUtils;                    // ← token issuance
@Autowired AuthenticationManager authManager;    // ← Spring Security
@Autowired RestTemplate restTemplate;            // ← outbound HTTP — SSRF risk
@Autowired ProcessBuilder processBuilder;        // ← shell execution — RCE risk
```

The injected fields tell you what tools the controller can reach. `JdbcTemplate` means raw SQL is on the table. `RestTemplate` means outbound HTTP requests (potential SSRF). The controller's toolbox = the controller's risk profile.

### For Each Endpoint, Identify the Inputs

Every controller method's parameter list is a list of user-controlled values:

```java
@PostMapping("/forgot")
public String forgotPOST(@RequestParam String email,        // ← user input
                         Model model,
                         HttpServletRequest request,         // ← contains headers + cookies (also user-controlled!)
                         HttpServletResponse response) {
```

Source annotations to recognize:

| Annotation | Source |
|---|---|
| `@RequestParam String x` | Query string OR form field |
| `@PathVariable int id` | URL path segment |
| `@RequestBody Object o` | JSON/XML body |
| `@RequestHeader("X") String h` | HTTP header |
| `@CookieValue String c` | Cookie |
| `request.getParameter("x")` | Servlet API |
| `request.getHeader("X")` | Servlet API — headers like `X-Forwarded-For` |

## Step 2: Test Systematically — The 6-Step Playbook

When you open any controller file on any Spring Boot app, do these six things in order:

### 1. Glance at `@Autowired` fields
Know the toolkit. JDBC? JPA? JWT? Sessions? RestTemplate? You'll instantly know what categories of bugs are even possible.

### 2. List every `@GetMapping` and `@PostMapping`
Every one is a door. Make a checklist.

### 3. For each handler, trace user input to its first dangerous sink
Ask: where does each `@RequestParam` / `@PathVariable` / `@RequestBody` value end up?
- SQL string → [[SQL Injection]]
- File path → path traversal
- Shell command → command injection
- HTML template → [[XSS]]
- Redirect URL → open redirect
- Outbound HTTP URL → SSRF
- Deserialization → insecure deserialization

### 4. Find every SQL query
Run these greps on the decompiled source:

```bash
# Any line that builds a SQL string
grep -rnE '"(SELECT|UPDATE|DELETE|INSERT|CREATE|ALTER|DROP)' --include="*.java" .

# String concatenation in WHERE/VALUES — classic SQLi
grep -rnE '(WHERE|VALUES).*"\s*\+' --include="*.java" .

# Variable named "sql" being built
grep -rnE 'String\s+sql\s*=' --include="*.java" .

# JdbcTemplate calls
grep -rn "jdbcTemplate" --include="*.java" .
```

For every SQL query, apply the rule:

```java
jdbcTemplate.query("... WHERE x = ?", new Object[]{value}, ...)   // ✅ SAFE
jdbcTemplate.query("... WHERE x = '" + value + "'", ...)          // ❌ SQL INJECTION
```

If you see `+` gluing user input into a SQL string, **stop reading and check if that input comes from the user**. If yes, you found a bug.

### 5. Find every redirect
```bash
grep -rn "sendRedirect\|RedirectView\|return \"redirect:" --include="*.java" .
```

Check: is the redirect URL built from user input? → open redirect bug.

### 6. Find every cookie creation
```bash
grep -rn "new Cookie\|setCookie\|addCookie" --include="*.java" .
```

For each cookie, check: `setHttpOnly(true)`? `setSecure(true)`? Sensible expiration? Missing flags = findings.

## Reviewer Instincts to Burn In

### The SQL Injection Antenna

Anytime you see `JdbcTemplate` in `@Autowired`, your antenna goes up. Then for every query:

- `?` placeholder + value passed as separate argument → **safe**
- Hardcoded string with no concatenation → **safe**
- Any `+` operator concatenating a variable into the SQL string → **investigate where the variable came from**

### The "Front Door is Locked, Try the Side Door" Heuristic

When you read the login flow and find it's parameterized and tight, **don't conclude the app is safe**. The login path is the most-audited part of every app. Real bugs live on the bathroom windows: `/forgot`, `/signup`, `/reset-password`, `/profile/edit`, search/filter endpoints, admin panels, export/report features. **When the front door looks too clean, walk around the building.**

### The Hidden Source — Stored Data Becomes Input Again

```java
sql = "SELECT * FROM posts WHERE email = '" + user.getEmail() + "' ORDER BY ...";
```

`user.getEmail()` looks like an internal value, not user input. But trace it back: where did `user` come from? If it was loaded from the database, where did the email get into the database? If the user controls their own email (registration, profile edit), then this is **second-order SQL injection**. The malicious payload is stored in the DB during registration, then re-used unsafely later. See [[SQL Injection]].

### The JWT Secret Heuristic

Always check `application.properties` / `application.yml` for the JWT signing secret. Hardcoded, default, weak, or short → forge tokens for any user including admin. This is a free win on many HTB Spring boxes.

### The Error Handler Reveal

```java
} catch (Exception var12) {
    String ip = request.getHeader("X-FORWARDED-FOR");
    if (ip == null) ip = request.getRemoteAddr();
    if (ip.equals("127.0.1.1")) {
        model.addAttribute("errorMsg", var12.getMessage());
        model.addAttribute("errorStackTrace", Arrays.toString(var12.getStackTrace()));
    }
}
```

Read every catch block. Look for conditional error disclosure based on IP, header, environment, or any "is this a developer?" check. These are often the difference between blind and error-based [[SQL Injection]] — and they unlock far more than that. See [[Debug Mode Disclosure]] for the full pattern.

### The X-Forwarded-For Trust Failure (Look for It Everywhere)

> **Forever-hook:** "Whenever you see code that compares an 'IP address' to a magic value like 127.0.0.1 or an internal range, immediately ask: where did they get that IP from? If the answer is a header, it's a bypass."

This is the single most common authn/authz bypass in modern Java web apps. The shape:

```java
String ip = request.getHeader("X-FORWARDED-FOR");
if (ip == null) ip = request.getRemoteAddr();
if (ip.equals("127.0.0.1") || ip.startsWith("10.")) { /* trusted */ }
```

The bug isn't reading the header — proxies legitimately set it. The bug is reading it without verifying the request actually came from a trusted proxy. If the backend is reachable directly, the attacker controls every byte.

Greps to run on every Spring codebase:

```bash
grep -rn 'getHeader("X-Forwarded' --include="*.java" .
grep -rn 'getHeader("X-Real-IP' --include="*.java" .
grep -rn 'getHeader("True-Client-IP' --include="*.java" .
grep -rn 'getHeader("X-Originating-IP' --include="*.java" .
grep -rn 'getHeader("CF-Connecting-IP' --include="*.java" .
grep -rn 'getHeader("Forwarded' --include="*.java" .
grep -rn 'getHeader("Via' --include="*.java" .
```

Every hit is a potential bypass. Trace what the value gets compared to and what path opens up when the comparison passes. The free-lunch payload is `curl -H "X-Forwarded-For: 127.0.0.1" target` — see [[Client-Controlled IP Headers]].

### The Dev-Mode Conditional Antenna

> **Forever-hook:** "Every conditional that switches between 'helpful for the developer' and 'safe for the user' is a vulnerability waiting to happen. Find the conditional, find the way to flip it, get the developer view."

Look for any branch that says "if developer/internal/debug, show extra info." The condition is almost always flippable by the attacker. Variants to grep for:

```bash
grep -rn 'X-Debug\|debug=\|isDebug\|DEBUG_MODE' --include="*.java" .
grep -rn 'Profile\|"dev"\|"prod"\|"local"' --include="*.java" .
grep -rn '@company\.com\|endsWith.*@' --include="*.java" .
grep -rn 'getStackTrace\|printStackTrace' --include="*.java" .
grep -rn 'application\.properties\|application\.yml' .
```

And in `application.properties` / `application.yml`:

```properties
spring.profiles.active=dev                           # ← left on in prod
management.endpoints.web.exposure.include=*          # ← actuator wide open
debug=true                                            # ← Spring Boot debug logging
server.error.include-stacktrace=always               # ← stack traces in HTTP responses
server.error.include-message=always                  # ← exception messages in HTTP responses
spring.boot.admin.client.enabled=true                # ← admin console
```

Each of these is a finding on its own. See [[Debug Mode Disclosure]] for the unified pattern.

## Developer Perspective: Why This Is Hard

- Spring Boot makes it trivial to write working code without understanding what's happening under the hood — `@Autowired` and `@PostMapping` look magical, so devs cargo-cult patterns from Stack Overflow without understanding the security implications.
- `JdbcTemplate` is the lowest-friction tool for raw SQL — concatenation is the most natural way to use it, and the safe `?` placeholder pattern requires the developer to consciously remember.
- Spring Security's defaults are good, but every framework has escape hatches (`csrf().disable()`, custom authentication providers, raw query builders) that developers reach for when the defaults are inconvenient.
- Multiple developers on a team mean inconsistent coding styles — one part of the codebase uses parameterized queries everywhere, another part has concatenation. You only need to find one careless file.

## The Multi-Finding Density Mindset

> **Forever-hook:** "A hacker maps the whole graph, not one bug class at a time. Every security-sensitive function has more findings than the headline bug."

Junior reviewers find one bug per function and move on. Senior reviewers find five — because they read the whole function asking "what could go wrong here?" instead of "where's the SQLi?". When you read a security-sensitive controller (login, register, password reset, profile edit, file upload, payment), expect to find **multiple** distinct findings in 30–50 lines of code.

A worked example — a single `forgotPOST` method, ~40 lines:

| Finding | Severity | What gives it away |
|---|---|---|
| SQL injection in email concatenation | High | `WHERE email = '" + email + "'` — direct concat |
| Trust of `X-Forwarded-For` for IP-based gating | High | `request.getHeader("X-FORWARDED-FOR")` then `.equals("127.0.0.1")` |
| Stack trace disclosure to "debug" clients | Medium | `e.getStackTrace()` rendered when IP check passes |
| Logging the password reset link to the error log | Medium | `logger.error("TODO- Send email with " + resetLink)` — anyone with log access takes over any account |
| Predictable password reset token | Medium-High | Token is `MD5(id + ":" + email + ":" + passwordHash)` — no random salt, no timestamp; if you know the email and password hash, you compute the token offline |
| Missing rate limiting on the endpoint | Low-Medium | No throttling visible in the controller or filter chain |

That's six findings in one function. Only one of them is the SQLi the box "wants" you to find. The other five are real bugs that would be reported in any pro pentest, and most of them chain into things bigger than the SQLi.

**The reading checklist for any sensitive function:**

1. **Where does user input enter?** `@RequestParam`, `@PathVariable`, `@RequestBody`, `request.getHeader`, cookies, multipart files.
2. **Where does it touch a sink?** SQL strings, file paths, shell commands, HTTP clients, deserializers, template engines.
3. **What trust assumptions are being made?** "This IP is internal", "this header proves localhost", "this email is one of ours", "this token is unforgeable", "this exception will never happen in prod".
4. **Where does sensitive data end up?** Logs, error messages, response bodies, external services, the database.
5. **What's missing that should be there?** Rate limiting, CSRF token check, authorization decorator, audit logging, transaction boundary, error handling.
6. **What does the catch block do?** Almost always more than the developer realized.

Run those six questions on every function. The single-bug-per-function reflex is the difference between finding the SQLi and finding the SQLi *plus* the IP spoof *plus* the stack trace *plus* the predictable token *plus* the credential in the log *plus* the missing rate limit. Same 30 seconds of reading, six reports.

## The Prove-Impact Mindset

> **Forever-hook:** "Defenders prove a bug exists. Attackers prove a bug matters. The same SQLi is a $500 finding or a $50k finding depending on whether the report ends at 'I leaked one row' or 'here's a screenshot of `id` from the DB host.'"

After every confirmed bug, ask two questions:

1. **What does the app user have access to?** Check `application.properties` for the DB username. `postgres`/`root`/`sa` = the SQLi is a path to RCE, not just a data leak. That's a [[Principle of Least Privilege]] failure.
2. **Where does the chain stop?** Trace the climb in your head: data → file read → file write → commands → shell. Write the worst-case in the report.

**Grep for superuser connections before reading any Java:**

```bash
grep -rnE 'spring\.datasource\.username\s*=\s*(postgres|root|sa|admin|dba)' .
grep -rnE 'jdbc:postgresql.*://(postgres|root|admin)' --include="*.properties" --include="*.yml" .
```

A hit is a finding before you've read a single controller. "Application connects as superuser → any SQLi escalates to RCE via [[SQLi to RCE on PostgreSQL]]." File the PoLP violation alongside the bug — the DB role finding may be more urgent than the SQLi itself because it covers every undiscovered SQLi too.

## Common Patterns in the Wild

| Pattern | What it looks like | Risk |
|---|---|---|
| Application connects to the database as `postgres` / `root` / `sa` | `spring.datasource.username=postgres` | Any SQLi escalates to RCE via [[SQLi to RCE on PostgreSQL]] / [[Database as a Process]] |
| Login uses `?` placeholders, but `/forgot` concatenates | Login looks safe; forgot-password isn't | SQL injection on `/forgot` |
| User data echoed back in profile pages | `model.addAttribute("user", user)` + Thymeleaf `${user.bio}` without escaping | Stored XSS |
| JWT secret in `application.properties` | `bluebird.app.jwtSecret=secret` | Token forgery |
| Raw `request.getHeader("X-Forwarded-For")` used for trust decisions | `if (ip.equals("127.0.0.1"))` | Header spoofing |
| Stored input re-used in a query later | `user.getEmail()` from DB → concatenated | Second-order SQL injection |
| `csrf().disable()` in `WebSecurityConfig` | Anywhere in security config | CSRF |
| File path built from user input | `new File("/uploads/" + filename)` | Path traversal |
| `getHeader("X-Forwarded-For")` used in any check | `if (ip.equals("127.0.0.1"))` | [[Client-Controlled IP Headers]] — full bypass via spoofed header |
| Conditional stack trace / debug info disclosure | `if (isDev) model.addAttribute("stack", e.getStackTrace())` | [[Debug Mode Disclosure]] — flip the conditional, get the developer view |
| `logger.error("...send email with " + resetLink)` | Any sensitive value in a log line | Account takeover via log read |
| Reset token built from deterministic inputs | `MD5(id + ":" + email + ":" + passwordHash)` | Offline-computable reset tokens |
| Email regex used as a SQLi guard | `Pattern.compile("^.*@[A-Za-z]*\\.[A-Za-z]*$")` then concat | Shape-bypass — the email syntax has a dead zone before `@` |
| `Pattern.compile(...).matcher(input).matches()` blacklist | Blocking single quotes via `matches()` | `matches()` checks the whole string only — slip the char in as part of a larger payload |

## Red Flags During Testing

- `spring.datasource.username=postgres` (or `root`/`sa`/`admin`/`dba`) — any SQLi in the codebase becomes a path to RCE on the database host
- A controller class with `@Autowired JdbcTemplate` and any method building SQL with `+`
- Different error messages for "user doesn't exist" vs "wrong password" on `/login`
- Verbose error pages or stack traces in HTTP responses
- Cookies created without `setHttpOnly(true)` or `setSecure(true)`
- `csrf().disable()` anywhere in security configuration
- Hardcoded secrets in `application.properties` (database passwords, JWT secrets, API keys)
- `@PreAuthorize` missing on admin/sensitive endpoints
- User-controlled strings flowing into `Runtime.exec`, `ProcessBuilder`, or `RestTemplate`
- Catch blocks that include `e.getMessage()` or `e.getStackTrace()` in the response
- **Any** read of `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, `True-Client-IP`, `CF-Connecting-IP`, `Via`, `X-Originating-IP`, `X-Client-IP` — every one is a potential bypass
- **Any** comparison of an IP to `127.0.0.1`, `localhost`, internal CIDRs, or country/region IDs that came from a header
- `spring.profiles.active=dev` in a deployed `application.properties`
- `management.endpoints.web.exposure.include=*` exposing all Actuator endpoints
- `server.error.include-stacktrace=always` or `include-message=always`
- `Pattern.compile(...).matcher(x).matches()` used as an input filter (use `find()` instead)
- A regex that validates a "shape" (email/URL/phone/UUID) used to gate input that then gets concatenated into SQL
- Logger calls that include sensitive values (`reset link`, `password`, `token`, `secret`) in the message
- Reset/recovery tokens built from `MD5`/`SHA1` of deterministic inputs (no random salt, no expiry)
- Any sensitive endpoint without rate limiting (`Bucket4j`, `@RateLimited`, filter-chain throttle)

## Links

- [[Spring Boot Basics]] — the framework conventions you need to read this code
- [[Authentication and JWT]] — the auth flow you'll see in every controller
- [[SQL Injection]] — the most common bug in Spring Boot controllers
- [[Database Queries]] — JdbcTemplate, JPA, and the safe vs unsafe patterns
- [[Client-Controlled IP Headers]] — the X-Forwarded-For trust failure pattern
- [[Debug Mode Disclosure]] — the dev-mode-conditional vulnerability class
- [[Auditing: SQL Injection]] — the systematic SQLi testing methodology
- [[PostgreSQL Query Logs]] — the live-observation tool for the static + live audit loop
- [[SQLi to RCE on PostgreSQL]] — the chain narrative the prove-impact section calls home to
- [[Database as a Process]] — the architectural reason any SQLi against a superuser connection becomes RCE
- [[Principle of Least Privilege]] — the defensive discipline the prove-impact mindset is built on

## My Notes
