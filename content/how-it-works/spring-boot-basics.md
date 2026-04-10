# Spring Boot Basics
Tags: #how-it-works #spring-boot #java #frameworks #code-review

## Core

Spring Boot wraps Spring with sensible defaults so a Java web app requires almost no boilerplate. Most enterprise Java apps you'll audit are Spring Boot. Recognizing its conventions instantly tells you how the app is wired — start at `controller/` because that's where user input enters.

## The 4 Annotations That Run 80% of Spring Boot

| Annotation | Meaning | Shortcut |
|---|---|---|
| `@Controller` / `@RestController` / `@Service` | "Spring, create and manage this class" | "Spring, manage this" |
| `@Autowired` | "Spring, inject the instance you already created" | "Inject this here" |
| `@GetMapping("/x")` / `@PostMapping("/x")` | "When browser hits `/x`, run this method" | "URL → method" |
| `@RequestParam String foo` | "Pull `foo` from the HTTP request" | "Form field → variable" |

## Project Structure

```
com/<company>/<app>/
├── <App>Application.java      ← entry point (@SpringBootApplication)
├── controller/                 ← HTTP endpoints — attack surface
├── model/ or entity/           ← data classes (User, Post...)
├── repository/                 ← database access (JPA repositories)
├── service/                    ← business logic
└── security/                   ← Spring Security config + filters
```

## Input Annotations (Source Map)

| Annotation | Source | Example |
|---|---|---|
| `@RequestParam String x` | Query string or form field | `?x=value` |
| `@PathVariable int id` | URL path segment | `/profile/{id}` |
| `@RequestBody Object o` | JSON/XML body | POST with JSON |
| `@RequestHeader("X-Foo") String h` | HTTP header | `X-Foo: value` |
| `@CookieValue String session` | Cookie | `Cookie: session=abc` |

**Every one of these is user-controlled.** These are your sources when tracing data flow.

## DB Access Tiers

**JdbcTemplate** — raw SQL, safety depends entirely on `?` placeholders vs `+` concatenation. Easy to misuse. High SQLi risk.
**JPA / Hibernate** — ORM, generates SQL from method names. Safer by default, but escape hatches exist (`createNativeQuery`, `@Query` with concatenation).
**Spring Data JPA** — highest level, derives queries from interface method names. Hardest to misuse.

When you see `JdbcTemplate` → expect SQLi opportunities. When you see `JpaRepository` → look elsewhere.

## Attack Surface

- **`JdbcTemplate` + string concatenation** → [[SQL Injection]]
- **`@RequestParam` into file paths** → path traversal
- **`@RequestParam` into shell commands** → command injection
- **JWT secret hardcoded in `application.properties`** → token forgery ([[Authentication and JWT]])
- **`@PreAuthorize` missing** → broken access control
- **CSRF protection disabled** in `WebSecurityConfig` → [[CSRF]]
- **Verbose error pages** in dev profile leaked to prod → info disclosure

## Audit

- [ ] Find every controller (`@Controller` / `@RestController`)
- [ ] List every endpoint (`@GetMapping` / `@PostMapping` / etc.)
- [ ] Identify all input params per endpoint
- [ ] Check `@Autowired` fields per class — `JdbcTemplate` = antenna up
- [ ] Open `application.properties` / `application.yml` for hardcoded secrets
- [ ] Open `WebSecurityConfig` for security rules
- [ ] Audit every `JdbcTemplate` query: `?` placeholders vs `+` concatenation

## My Notes
