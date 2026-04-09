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
    if (request.getRemoteAddr().equals("127.0.1.1")) {
        model.addAttribute("errorMsg", var12.getMessage());
        model.addAttribute("errorStackTrace", Arrays.toString(var12.getStackTrace()));
    }
}
```

Read every catch block. Look for conditional error disclosure based on IP, header, or environment. These are often the difference between blind and error-based [[SQL Injection]]. Also check headers like `X-Forwarded-For` — if the app trusts a client header to determine who's "internal," you can spoof it.

## Developer Perspective: Why This Is Hard

- Spring Boot makes it trivial to write working code without understanding what's happening under the hood — `@Autowired` and `@PostMapping` look magical, so devs cargo-cult patterns from Stack Overflow without understanding the security implications.
- `JdbcTemplate` is the lowest-friction tool for raw SQL — concatenation is the most natural way to use it, and the safe `?` placeholder pattern requires the developer to consciously remember.
- Spring Security's defaults are good, but every framework has escape hatches (`csrf().disable()`, custom authentication providers, raw query builders) that developers reach for when the defaults are inconvenient.
- Multiple developers on a team mean inconsistent coding styles — one part of the codebase uses parameterized queries everywhere, another part has concatenation. You only need to find one careless file.

## Common Patterns in the Wild

| Pattern | What it looks like | Risk |
|---|---|---|
| Login uses `?` placeholders, but `/forgot` concatenates | Login looks safe; forgot-password isn't | SQL injection on `/forgot` |
| User data echoed back in profile pages | `model.addAttribute("user", user)` + Thymeleaf `${user.bio}` without escaping | Stored XSS |
| JWT secret in `application.properties` | `bluebird.app.jwtSecret=secret` | Token forgery |
| Raw `request.getHeader("X-Forwarded-For")` used for trust decisions | `if (ip.equals("127.0.0.1"))` | Header spoofing |
| Stored input re-used in a query later | `user.getEmail()` from DB → concatenated | Second-order SQL injection |
| `csrf().disable()` in `WebSecurityConfig` | Anywhere in security config | CSRF |
| File path built from user input | `new File("/uploads/" + filename)` | Path traversal |

## Red Flags During Testing

- A controller class with `@Autowired JdbcTemplate` and any method building SQL with `+`
- Different error messages for "user doesn't exist" vs "wrong password" on `/login`
- Verbose error pages or stack traces in HTTP responses
- Cookies created without `setHttpOnly(true)` or `setSecure(true)`
- `csrf().disable()` anywhere in security configuration
- Hardcoded secrets in `application.properties` (database passwords, JWT secrets, API keys)
- `@PreAuthorize` missing on admin/sensitive endpoints
- User-controlled strings flowing into `Runtime.exec`, `ProcessBuilder`, or `RestTemplate`
- Catch blocks that include `e.getMessage()` or `e.getStackTrace()` in the response

## Links

- [[Spring Boot Basics]] — the framework conventions you need to read this code
- [[Authentication and JWT]] — the auth flow you'll see in every controller
- [[SQL Injection]] — the most common bug in Spring Boot controllers
- [[Database Queries]] — JdbcTemplate, JPA, and the safe vs unsafe patterns

## My Notes
