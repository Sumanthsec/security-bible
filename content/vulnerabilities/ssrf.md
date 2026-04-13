# Server-Side Request Forgery (SSRF)
Tags: #vulnerability #ssrf #cloud #day5

## What is SSRF and why does it exist?

The server makes an HTTP request to a URL the attacker controls. Instead of pointing it at a normal resource, the attacker points it at internal services, cloud metadata endpoints, or other things only the server can reach.

It exists because developers build legitimate features that need to fetch URLs — link previews, webhook callbacks, image imports, PDF generators. The functionality is intentional. The problem is trusting the user to supply a "normal" URL.

OWASP A10:2021 (Server-Side Request Forgery).

## What features make SSRF possible?

Any feature where the user controls a URL and the server fetches it:

- **URL previews / link unfurling** — paste a link, see a preview. Server fetches the URL to grab title, image, description.
- **Webhook endpoints** — user supplies a callback URL, server sends data to it.
- **File imports from URL** — "import profile picture from URL," "fetch RSS feed," "load CSV from this link."
- **PDF/HTML rendering** — server-side PDF generators (wkhtmltopdf, Puppeteer, WeasyPrint) that render HTML containing URL references.
- **Proxy functionality** — translation services, content scrapers, "read this article without ads."
- **Integrations** — connecting third-party services where the user provides an API endpoint.

The common thread: user controls the destination, server makes the request.

## Why is the server's request more dangerous than the attacker's own?

The server sits inside the network perimeter — behind firewalls, with access to things the attacker can't reach from the outside. Internal endpoints, localhost services, cloud metadata, other microservices. The server becomes the attacker's proxy into the internal network.

Most internal services rely on network-level trust — "if you can reach me, you must be authorized." SSRF completely breaks that assumption because the request comes from a trusted internal IP.

## What are the high-value targets?

**Cloud metadata services** — the big prize, especially in AWS:

| Cloud | Endpoint | What leaks |
|---|---|---|
| AWS | `169.254.169.254/latest/meta-data/iam/security-credentials/` | Temporary Access Key, Secret Key, Session Token |
| GCP | `metadata.google.internal` | Service account tokens |
| Azure | `169.254.169.254` (with `Metadata: true` header) | Managed identity tokens |

With stolen AWS credentials, the attacker can access S3 buckets, databases, other services — whatever the instance's IAM role permits. This is how the 2019 Capital One breach happened — SSRF to metadata endpoint, grabbed IAM credentials, accessed 100+ million customer records.

**Internal services on localhost:**

- Admin panels on `127.0.0.1:8080` with no auth because "they're only accessible locally"
- Databases with no auth on localhost — Redis (6379), Memcached (11211), Elasticsearch (9200)
- Debug endpoints — Spring Boot Actuator, Flask debugger

**Internal network services:**

- Other microservices that trust requests from internal IPs — no auth, no verification
- Kubernetes API server, Docker API
- Other hosts the attacker can scan by sweeping `10.x.x.x` or `192.168.x.x` — SSRF becomes a port scanner

## What is IMDSv2 and how does it defend against SSRF?

AWS introduced IMDSv2 to make the metadata endpoint harder to hit through SSRF.

**IMDSv1 (old)** — simple GET to `169.254.169.254`, no authentication. SSRF hits it directly, one request, game over.

**IMDSv2 (new)** — two-step process:
1. Make a **PUT** request with a custom header `X-aws-ec2-metadata-token-ttl-seconds` to get a session token.
2. Use that token in a header on your **GET** request to the metadata endpoint.

**Why this works against most SSRF:** most SSRF vulnerabilities only let the attacker control the URL, not the HTTP method or headers. If you can only trigger a GET, you can't do the PUT to get the token. IMDSv2 exploits the assumption that most SSRF = URL-only control.

**TTL=1:** the token response has a hop limit of 1 at the IP level — the packet can only survive one network hop. If it has to cross a container boundary or go through a proxy, the TTL hits 0 and the packet gets dropped. This specifically blocks containerized scenarios where there's an extra network layer between the app and the metadata endpoint.

**Not bulletproof.** If the SSRF gives full control over method and headers (like a webhook feature with custom header config), IMDSv2 doesn't save you. And many organizations still haven't enforced IMDSv2-only — if v1 is still enabled as fallback, the attacker just uses v1.

## Why doesn't IAM stop SSRF?

IAM controls what the instance's role is allowed to do. But when the attacker grabs credentials through SSRF, they're using the server's own legitimate identity. From AWS's perspective, it looks like the server itself is making those API calls — there's no way to tell the difference.

IAM limits the blast radius (a tightly scoped role means stolen creds can do less), but it can't prevent the theft itself. That's why least-privilege IAM roles matter — if the role has admin access, the attacker gets admin access.

## How do attackers bypass SSRF defenses?

Developers usually try blocklisting internal IPs and metadata endpoints first. This is weak — the attack surface for bypasses is enormous.

**Alternate representations of 127.0.0.1:**

| Format | Value |
|---|---|
| Decimal | `2130706433` |
| Hex | `0x7f000001` |
| Octal | `0177.0.0.1` |
| IPv6 | `::1` or `0:0:0:0:0:0:0:1` |
| Short form | `127.1` |

**DNS-based bypasses:**
- Register a domain that resolves to `127.0.0.1`. Blocklist checks the URL string, sees the domain, allows it — but the server resolves it to localhost.
- **DNS rebinding** — domain resolves to a safe IP on first lookup (when the blocklist checks), then switches to `127.0.0.1` on the second lookup (when the server actually fetches).

**URL parser tricks:**
- `http://attacker.com@127.0.0.1` — some parsers treat the part before `@` as credentials
- Redirects — attacker's URL returns a 302 redirect to `http://169.254.169.254`. Blocklist checks the original URL, server follows the redirect to the internal target.
- URL encoding: `http://127.0.0.%31`

**Proper defenses:**
- **Allowlisting** — only permit specific domains or IP ranges the feature actually needs
- **Resolve DNS first, then check the IP** before making the request — and don't follow redirects blindly
- **Outbound proxy** — all outbound requests go through a locked-down proxy that can't reach internal networks
- **Network segmentation** — the server making outbound requests shouldn't have access to sensitive internal services

## What's the difference between blind SSRF and full-response SSRF?

**Full-response** — you supply a URL, the server fetches it and shows you the response. Point it at `169.254.169.254` and the metadata comes back on the page. Straightforward.

**Blind SSRF** — the server makes the request but you never see the response. Just "success" or "failed," or nothing. This is more common in the real world — webhook features, image validators, health check features.

**How you still exploit blind SSRF:**
- **Out-of-band detection** — point the URL at a server you control (Burp Collaborator, interactsh). If you get a callback, SSRF is confirmed.
- **Port scanning** — different response times or status codes for open vs closed internal ports. `http://10.0.0.5:22` might timeout while `http://10.0.0.5:80` returns quickly — you're mapping the internal network without seeing responses.
- **Triggering actions** — you can't read responses, but you can hit internal APIs that perform actions on GET: `http://internal-admin/delete-cache`, `http://internal-api/restart`. The action itself is the impact.
- **Chain with another vuln** — if you can redirect the response somewhere you can read it, you can still steal credentials.

## Where does SSRF hide beyond obvious URL inputs?

**PDF generators** — render HTML to PDF server-side. Inject `<img src="http://169.254.169.254/latest/meta-data/">` or `<iframe src="http://internal-admin/">` into the content being rendered. The server fetches those URLs during rendering and the response shows up embedded in the PDF you download. Developers rarely think of their PDF generator as an SSRF vector.

**SVG files** — SVGs are XML. They support `<image href="http://internal/...">` and `<foreignObject>` tags. Upload an SVG as your profile picture, the server processes it, and the image parser fetches internal URLs.

**XXE to SSRF** — if the application parses XML, an attacker defines an external entity: `<!ENTITY xxe SYSTEM "http://169.254.169.254/...">`. The XML parser fetches the URL when resolving the entity. Common in SOAP APIs, file uploads that accept XLSX/DOCX (which are ZIP files containing XML).

**Document imports** — XLSX, DOCX files contain references to external resources. Crafted spreadsheet formulas like `=WEBSERVICE("http://internal/")` get resolved by server-side processors.

The pattern: any server-side component that processes user-supplied content and resolves URLs or external references is an SSRF vector. Developers think about SSRF in their URL-fetching endpoint but forget their PDF renderer, image processor, and XML parser all do the same thing.

## What is protocol smuggling and why is gopher:// dangerous?

`gopher://` is an old protocol that lets you send raw bytes to any port. That means you can craft arbitrary protocol data — valid Redis commands, raw SMTP, raw HTTP POSTs:

`gopher://127.0.0.1:6379/_SET%20shell%20"<?php system($_GET['cmd']);?>"`

This turns SSRF from "I can make GET requests to internal services" into "I can speak any protocol to any internal port." That's why blocking `file://`, `gopher://`, `dict://` schemes is critical — not just blocking internal IPs.

## How do you test for SSRF?

**1. Map the attack surface** — identify every feature where the app makes outbound requests. URL inputs, webhook configs, import features, integrations, file uploads (SVG/XML/XLSX/DOCX), PDF generation, link previews. Check API docs for parameters like `callback_url`, `icon_url`, `redirect_uri`, `feed_url`, `avatar_url`.

**2. Confirm outbound requests** — set up a listener (Burp Collaborator, interactsh, your own VPS). Supply your server's URL in every identified input. Watch for callbacks — a hit means the server is fetching your URL.

**3. Test response visibility** — does the response body come back to you (full-response SSRF), or just status/timing differences (blind)? This determines your exploitation path.

**4. Test internal access** — try `http://127.0.0.1`, common internal ports (80, 443, 8080, 8443, 9200, 6379, 11211, 3306). Try cloud metadata: `http://169.254.169.254/latest/meta-data/`.

**5. Test filter bypasses** — alternate IP formats, DNS rebinding, redirects from your server, scheme switching (`file://`, `gopher://`), open redirect on the target app itself (`http://target.com/redirect?url=http://169.254.169.254` — might bypass blocklist since the initial URL is their own domain).

**6. Enumerate internal network (if blind)** — sweep common ranges (`10.0.0.x`, `172.16.0.x`, `192.168.x.x`) with common ports. Use response time differences to map live hosts and open ports.

**7. Escalate** — cloud credentials from metadata, test what the IAM role can access. Internal admin panels, unauthenticated actions. Internal services (Redis, Elasticsearch), extract or write data. Chain with other vulns for deeper impact.

## My Notes
