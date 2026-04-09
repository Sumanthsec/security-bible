# Spring Boot Basics
Tags: #how-it-works #spring-boot #java #frameworks #code-review

## The Problem This Solves

Java web apps used to require massive amounts of XML configuration, manual wiring of components, and tons of boilerplate. Spring Boot wraps Spring with sensible defaults so a developer can write a working web service with almost no setup. Most enterprise Java apps you'll audit are Spring Boot — recognizing its conventions instantly tells you how the app is wired.

## The Mental Model

A Spring Boot application is a collection of **classes that Spring manages for you**. You annotate a class to say "Spring, please create one of these and keep it ready." Then anywhere else in the codebase you say "Spring, hand me the one you already created." That's it. The whole framework is built on this idea — you stop calling `new` on things, and Spring builds and connects everything for you.

This is called **dependency injection**. The "container" is Spring's bag of pre-built objects. The "beans" are the objects in the bag.

## The 4 Annotations That Run 80% of Spring Boot

If you can read these four, you can read most controllers in any Spring Boot app:

| You see... | It means... | Mental shortcut |
|---|---|---|
| `@Controller` / `@RestController` / `@Component` / `@Service` | "Spring, please create one of these and keep it ready" | "Spring, manage this" |
| `@Autowired` | "Spring, hand me the one you already created" | "Inject this here" |
| `@GetMapping("/x")` / `@PostMapping("/x")` | "When the browser hits URL `/x`, run this method" | "URL → method" |
| `@RequestParam String foo` | "Pull the form field named `foo` from the HTTP request" | "Form field → variable" |

Memorize that table. Everything else in a controller is just business logic between these.

## Project Structure — How a Spring Boot App Is Laid Out

Every Spring Boot app follows the same conventions. Once you know them, you can navigate any of them:

```
com/<company>/<app>/
├── <App>Application.java          ← entry point (main method, @SpringBootApplication)
├── controller/                     ← HTTP endpoints — your attack surface
│   ├── AuthController.java
│   ├── ProfileController.java
│   └── ...
├── model/ or entity/               ← data classes (User, Post...)
├── repository/                     ← database access (JPA repositories)
├── service/                        ← business logic
└── security/                       ← Spring Security config + filters
    └── services/
        └── UserDetailsServiceImpl.java
```

**Why this matters as a reviewer:** when you open an unfamiliar Spring Boot app, you don't read every file. You go straight to `controller/` because that's where user input enters. Everything else is plumbing that controllers call into.

## What the Code Actually Looks Like

### A Controller Class — The Anatomy

```java
@Controller                                          // "Spring, manage me"
public class AuthController {

    @Autowired JdbcTemplate jdbcTemplate;            // "Hand me the DB tool"
    @Autowired JwtUtils jwtUtils;                    // "Hand me the JWT helper"
    @Autowired AuthenticationManager authManager;    // "Hand me Spring Security"
```

**Reviewer instinct:** before reading any method, glance at the `@Autowired` fields. They tell you what tools the controller uses. If you see `JdbcTemplate` injected, your antenna goes up — that's the raw SQL tool, and it's only safe when every query uses `?` placeholders.

### A Handler Method — The Anatomy

```java
@PostMapping("/login")                                // URL + method
public void loginPOST(@RequestParam String username,  // form field → variable
                      @RequestParam String password,
                      HttpServletResponse response)   // raw response object
        throws IOException {
    // ... handler logic
}
```

Reading this:
- `@PostMapping("/login")` → "When browser POSTs to `/login`, run me"
- `@RequestParam String username` → "Spring, grab the `username` form field"
- `HttpServletResponse response` → "Also give me the raw response so I can set cookies and redirect"
- `void` (no return) → "I'm not returning a webpage; I'll handle redirects myself"

**Two styles to recognize:**
- `void` + `HttpServletResponse` → handles its own redirects via `response.sendRedirect(...)`
- `String` return → renders a template named after the returned string (e.g., return `"profile"` → renders `profile.html`)

### Annotations for User Input — The Source Map

| Annotation | Where it reads from | Example URL/request |
|---|---|---|
| `@RequestParam String x` | Query string OR form field | `?x=value` or POST body `x=value` |
| `@PathVariable int id` | URL path segment | `/profile/123` with mapping `/profile/{id}` |
| `@RequestBody Object o` | JSON/XML request body | POST with JSON body |
| `@RequestHeader("X-Foo") String h` | HTTP header | `X-Foo: value` header |
| `@CookieValue String session` | Cookie value | `Cookie: session=abc` |

**Every one of these is user-controlled.** When you trace data flow, these are your sources.

## Why Developers Choose Different Approaches

- **`JdbcTemplate`** — raw SQL, fine-grained control. Common in older codebases. **Safety depends entirely on the developer using `?` placeholders.** Easy to misuse.
- **JPA / Hibernate** — ORM, generates SQL automatically from method names like `findByEmail(...)`. Safer by default but has escape hatches (`createNativeQuery`, `@Query` with concatenation).
- **Spring Data JPA repositories** — even higher-level, derive queries from interface method names. Hardest to misuse for SQLi.

When you see `JdbcTemplate` everywhere → expect SQLi opportunities. When you see `JpaRepository` interfaces → SQLi is rarer, look elsewhere.

## Configuration and Defaults That Matter

- **`application.properties` / `application.yml`** — config file. Loaded with `@Value("${property.name}")`. Often contains JWT secrets, database passwords, API keys.
- **`@SpringBootApplication`** — single annotation on the main class that turns on auto-configuration, component scanning, and embedded server.
- **Auto-configuration** — Spring detects what's on the classpath and configures sensible defaults. If you add `spring-boot-starter-security`, Spring Security is auto-enabled.
- **Embedded Tomcat** — Spring Boot apps ship their own web server. They run as `java -jar app.jar`, not deployed to an external Tomcat.

## Where Security Breaks

- **`JdbcTemplate` + string concatenation** → [[SQL Injection]]
- **`@RequestParam` flowing unchecked into file paths** → path traversal
- **`@RequestParam` flowing into shell commands** → command injection
- **JWT secret hardcoded or default in `application.properties`** → token forgery (see [[Authentication and JWT]])
- **`@PreAuthorize` missing on sensitive endpoints** → broken access control
- **CSRF protection disabled** in `WebSecurityConfig` → [[CSRF]]
- **Verbose error pages** in dev profile leaked to production → information disclosure

## Auditing Checklist

- [ ] Find every controller class (`grep -rn "@Controller\|@RestController"`)
- [ ] List every endpoint (`grep -rn "@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping"`)
- [ ] For each endpoint, identify all `@RequestParam`, `@PathVariable`, `@RequestBody` parameters
- [ ] Check `@Autowired` fields per class to see what tools the controller uses
- [ ] Open `application.properties` / `application.yml` for hardcoded secrets
- [ ] Open `WebSecurityConfig` (or any `@Configuration` class) to see the security rules
- [ ] Check for `JdbcTemplate` usage and audit every query for `?` placeholders vs `+` concatenation

## My Notes
