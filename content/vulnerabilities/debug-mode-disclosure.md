# Debug Mode Information Disclosure
Tags: #vulnerability #information-disclosure #debug #stack-traces #conditional-gating #day4

## Understand the Feature First

Every developer wants two things at the same time:

1. **Useful diagnostics during development** — stack traces, SQL errors, request dumps, query plans, profiling data, the full request body echoed back. Without these, debugging is misery.
2. **Hidden internals in production** — none of the above, because all of it is reconnaissance gold for an attacker.

The intuitive solution is a conditional: *"if I'm in dev mode, show the helpful stuff; if I'm in prod, hide it."* Frameworks ship with this baked in (`app.debug = True`, `Spring.profiles.active=dev`, `NODE_ENV=development`, `display_errors = On`), and developers also write their own conditionals: "if request is from localhost, show stack trace", "if user email ends in @company.com, show admin tools", "if the X-Debug header is set, return the SQL".

The conditional itself isn't the bug. The bug is that the **switch** between "developer view" and "user view" is **flippable by an attacker**.

## Why It Exists (Root Cause)

> **Forever-hook:** "Every conditional that switches between 'helpful for the developer' and 'safe for the user' is a vulnerability waiting to happen. Find the conditional, find the way to flip it, get the developer view."

This is a vulnerability **class**, not a specific bug. The shape is always the same:

```
if (someConditionThatProvesItsTheDeveloper) {
    showDangerouslyHelpfulInformation();
}
```

Every variant of this pattern fails the same way — the condition turns out to be checkable against attacker input:

| Condition | How attacker flips it |
|---|---|
| `if (request.getHeader("X-Debug") != null)` | Send `X-Debug: 1` |
| `if (System.getProperty("env").equals("dev"))` | Look for SSRF/file write that influences env, or for an env-leaking endpoint |
| `if (user.getEmail().endsWith("@company.com"))` | Register `attacker@company.com` (or any DNS subdomain trick) |
| `if (request.getRemoteAddr().equals("127.0.0.1"))` | SSRF via a localhost-bound endpoint, or just spoof the upstream header (see [[Client-Controlled IP Headers]]) |
| `if (cookie.get("debug") == "1")` | Set the cookie in the browser console |
| `if (Spring.profiles.active.contains("dev"))` | Find a config endpoint, find an env-var injection, or just hit the leftover dev profile in prod |
| `if (DEBUG)` constant left set to `true` in prod | Flag never reset during deployment — the most embarrassing variant |

The reason this keeps happening is that **the developer is the only person they're modeling when they write the conditional**. They imagine themselves at their laptop, hitting the localhost endpoint, seeing the stack trace, fixing the bug. They don't imagine the attacker at *their* laptop, sending the same request with one extra header.

## The Data Flow

There isn't a "data flow" the way there is for SQLi — the bug is structural. Picture it as two universes that share the same code:

```
DEVELOPER UNIVERSE                    ATTACKER UNIVERSE
   │                                     │
   │ hits localhost                      │ sends X-Forwarded-For: 127.0.0.1
   │ sees stack trace, SQL,              │ sees stack trace, SQL,
   │ env vars, query results             │ env vars, query results
   │                                     │
   ▼                                     ▼
   "great, debug info, fixing bug"       "great, debug info, exploiting bug"
```

The same gate. The same view. The only thing the developer relied on to keep the attacker out is something the attacker can change.

## What the Developer Should Have Done

The only safe stance is **debug information should not exist in the production binary at all**, or at minimum should be gated by something the attacker cannot influence. This is [[Principle of Least Privilege]] applied to *information*: production users get the least possible information about internals (just an opaque error ID), and the rich diagnostic view is granted only to a tightly-scoped audience over a separate, authenticated channel.

1. **Strip debug paths at build time, not runtime.** Use compile-time flags, build profiles, or separate artifacts. If the debug code isn't in the deployed JAR/binary/bundle, no header or env trick can reach it.
2. **If debug *must* exist at runtime, gate it on something the user cannot change.** A cryptographic signature on a debug token issued by an out-of-band channel. A short-lived JWT signed by an offline key. SSH-tunneled access only. Never an HTTP header, cookie, query string, or remote IP.
3. **Default deny.** All errors return a generic "Something went wrong, error ID xyz." The full trace is logged server-side under that ID. Devs grep the log; users see nothing.
4. **Disable framework debug at the framework level.** `app.debug = False` in Flask, `DEBUG = False` in Django, `spring.profiles.active=prod`, `display_errors = Off` in PHP. Set them in deployment configuration, not in code, so they can't be flipped by a config bug.
5. **Sanitize stack traces in handlers.** Even if a stack trace escapes, scrub class names, file paths, query fragments, and environment variable contents before rendering.
6. **Log the trace, return the ID.** The user-facing response says `Error 500: reference id 8a4f-b1c2`. The actual stack lives in your log aggregator. Support staff can look it up. Attackers can't.

## Exploitation

The exploitation is the same for every variant — find the gate, identify what flips it, flip it, read the leaked information.

### Reconnaissance — Find the Gate

```bash
# Send a request that you expect to error (bad ID, bad SQL char, missing field)
curl https://target/profile/abcdef       # 404 generic page → no leak
curl https://target/profile/'           # Same generic page

# Now try classic dev triggers
curl -H "X-Debug: 1" https://target/profile/'
curl -H "X-Forwarded-For: 127.0.0.1" https://target/profile/'
curl -H "Cookie: debug=1" https://target/profile/'
curl https://target/profile/'?debug=1
curl https://target/profile/'?_profile=true
curl https://target/profile/'?XDEBUG_SESSION_START=1

# Also try framework debug endpoints directly
curl https://target/actuator/env       # Spring Boot Actuator
curl https://target/actuator/heapdump  # Spring Boot Actuator
curl https://target/_profiler          # Symfony
curl https://target/__debug__/         # Django Debug Toolbar
curl https://target/debug/pprof/       # Go pprof
```

If any of these return a fuller error, more headers, JSON instead of HTML, framework banner text, or stack trace fragments, you've found a gate. Focus on it.

### Read What Leaked

A real production stack trace is a free reconnaissance dump:

```
ERROR: invalid input syntax for type integer: "abc"
  at com.bluebird.controllers.ProfileController.getProfile(ProfileController.java:47)
  at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
  ...
  Spring Framework 5.3.18, Postgres JDBC 42.5.0, Java 11.0.16
  config: spring.datasource.url=jdbc:postgresql://db.internal:5432/bluebird
          spring.datasource.username=bluebird_app
          jwt.secret=********** (sometimes literally not redacted)
```

That single trace tells you:

- **Framework + version** → known CVEs
- **Library + version** → more known CVEs
- **JVM/runtime version** → more known CVEs
- **Internal hostname** (`db.internal:5432`) → SSRF / network mapping target
- **Database type and credentials** → direct lateral movement
- **File paths** → know the deployment layout for LFI / path traversal
- **Class names** → infer the controller structure
- **Sometimes secrets in plain text** → JWT secret, API keys, S3 credentials

This is why "just an info disclosure" is rarely just an info disclosure. It's the first link in every chain.

### Combine With Other Bugs

A debug gate is most powerful when chained:

- **+ Blind SQLi → Error-based SQLi.** Exactly what HTB BlueBird's `/forgot` does. The blind SQLi is real but slow. Spoof `X-Forwarded-For: 127.0.0.1`, the catch block now renders the database error, and you can use `CAST` / `EXTRACTVALUE` to leak data in single requests instead of bisecting one bit at a time. See [[SQL Injection]] → "Error-Based".
- **+ SSRF → Internal endpoint discovery.** SSRF the app into hitting `localhost/actuator/env`, read the leaked debug data.
- **+ Verbose 500 → Source code disclosure.** Some frameworks (older Django, dev Flask) render the source of the failing function in the error page.

## What the Vulnerable Code Looks Like

### The Header-Gated Stack Trace (Java/Spring)

```java
} catch (Exception e) {
    String ip = request.getHeader("X-FORWARDED-FOR");
    if (ip == null) ip = request.getRemoteAddr();
    if (ip.equals("127.0.1.1")) {
        model.addAttribute("errorMsg", e.getMessage());
        model.addAttribute("errorStackTrace", Arrays.toString(e.getStackTrace()));
    }
    return "error";
}
```

Spoof the header, see the trace.

### The Cookie/Header Toggle (Express)

```javascript
app.use((req, res, next) => {
    if (req.headers['x-debug'] || req.cookies.debug === '1') {
        res.locals.debug = true;
    }
    next();
});

app.use((err, req, res, next) => {
    if (res.locals.debug) {
        res.status(500).json({ error: err.message, stack: err.stack });
    } else {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
```

`X-Debug: 1` flips the gate.

### The Profile-Left-On (Spring Boot)

```properties
# application.properties accidentally shipped to prod
spring.profiles.active=dev
management.endpoints.web.exposure.include=*
```

Now `/actuator/env`, `/actuator/heapdump`, `/actuator/configprops` are wide open. Attacker just hits the URLs.

### The Email-Domain Check

```java
public boolean isInternal(User user) {
    return user.getEmail().endsWith("@company.com");
}

if (isInternal(currentUser)) {
    showDebugConsole();
}
```

Register an account with email `attacker@evil.com.company.com` (some validators), or compromise a real `@company.com` email, or find any signup flow that doesn't verify the domain you claim.

### The Default-True Flag

```python
DEBUG = True   # TODO: change before deploy
```

Never gets changed. Django renders full tracebacks in production.

## What the Fix Looks Like

```java
// Java — log the full trace, return only an opaque reference
} catch (Exception e) {
    String errorId = UUID.randomUUID().toString();
    logger.error("[errId={}] forgot password failed", errorId, e);
    model.addAttribute("errorMsg", "Something went wrong. Reference: " + errorId);
    return "error";
}
```

```javascript
// Express — never echo errors to clients in prod
app.use((err, req, res, next) => {
    const errorId = crypto.randomUUID();
    logger.error({ errorId, err });
    res.status(500).json({ error: 'Internal Server Error', referenceId: errorId });
});
```

```python
# Django — set DEBUG via env var, default False, never check it in
DEBUG = os.environ.get('DJANGO_DEBUG', '').lower() == 'true'
```

```properties
# Spring — separate prod profile, lock down actuator
spring.profiles.active=prod
management.endpoints.web.exposure.include=health
management.endpoint.health.show-details=never
```

The unifying principle: **the only error a user sees is "something went wrong, here is an opaque reference id."** Everything diagnostic lives in logs the attacker cannot read.

## Chains With

- [[Client-Controlled IP Headers]] — the most common way to flip a localhost-gated debug switch
- [[SQL Injection]] — debug-gated error paths upgrade blind SQLi to error-based SQLi
- [[SSRF]] — fetch internal debug endpoints (`/actuator/env`, `/debug/pprof`)
- [[Insecure Deserialization]] — Spring Actuator's `/jolokia` and `/heapdump` endpoints leak the entire JVM state
- [[Authentication Bypass]] — debug endpoints often skip authentication entirely
- [[Hardcoded Secrets]] — leaked stack traces and `/actuator/env` dumps frequently contain JWT secrets and DB credentials

## Key Q&A From This Session

**Q: What's the most dangerous thing leaked by a stack trace?**
A: Internal hostnames (`db.internal:5432`) → free network map. DB credentials → direct lateral movement without needing SQLi.

**Q: Why do Spring Actuator / Django Debug Toolbar keep getting exposed?**
A: One config flag from production. `management.endpoints.web.exposure.include=*` opens everything. Legacy deployments + copy-pasted Stack Overflow configs.

## Lab Work

- HTB BlueBird — `/forgot` endpoint gates stack traces on `X-Forwarded-For`
- Any Spring Boot app with `/actuator/*` exposed
- PortSwigger — Information disclosure labs
- Search shodan/censys for `actuator/env` exposed Spring boxes (educational, with permission)

## Key Insights

- **It's a vulnerability class, not a single bug.** The shape is "developer-only conditional, attacker-flippable switch."
- **A stack trace is a free recon dump.** Versions, internal hostnames, credentials, file paths — all in one response.
- **The fix is opaque error IDs**, not better filtering. If the response *can* contain diagnostics, someone will make it leak.
- **It chains into everything.** Blind SQLi → error-based. SSRF → internal env vars. Always check for a debug gate before settling for the slow version of any technique.
- **The attacker's question:** "If I were debugging this, what would I want to see?" That finds these bugs.

## Questions That Came Up

- How does Spring Actuator's `/heapdump` endpoint actually serialize a JVM heap, and what's the easiest way to extract secrets from one?
- What's the right way to handle "I want detailed errors for my own staff" without ever rendering them to a client?
- Are there any frameworks that get this right by default in 2026?

## Links

- [[Client-Controlled IP Headers]] — the most common way to flip a debug gate
- [[SQL Injection]] — error-based SQLi is unlocked exactly by this bug
- [[Auditing: Code Review for Spring Boot Apps]] — where the dev-mode-conditional red flag lives in the audit checklist
- [[Authentication and JWT]] — debug endpoints often skip auth entirely
- [[Principle of Least Privilege]] — debug surfaces should be PoLP-scoped to a known admin host over a separate channel, never gated on a header

## My Notes
