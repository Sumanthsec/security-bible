# Insecure Direct Object Reference (IDOR)
Tags: #vulnerability #idor #access-control #day5

## What is IDOR and why does it exist?

The server receives a request like "give me invoice #1234," fetches it from the database, and returns it — without ever asking "does this user have permission to see invoice #1234?" The authorization check simply doesn't exist. It's not a bypass of access control — it's the absence of access control.

OWASP A01:2021 (Broken Access Control). The #1 finding in real pentests.

## Why does it keep happening?

**Frameworks don't enforce it automatically.** SQLi is largely solved because frameworks default to parameterized queries. But no framework automatically checks "does this user own this object?" — that's business logic specific to each application. The developer has to write it manually for every single endpoint.

**Endpoint explosion.** A typical API has hundreds of endpoints — users, orders, documents, messages, settings, notifications. Each one needs an authorization check. Miss one and you have an IDOR. It's a numbers game.

**Developers test happy paths.** Log in as User A, request User A's data, it works — ship it. They never test "what if User A requests User B's data?" because that's not how the feature is supposed to be used.

**Microservices make it worse.** Service A validates ownership, but Service B downstream assumes "if Service A sent me this request, it must be authorized" — and the attacker hits Service B directly.

**Copy-paste development.** Developer builds one endpoint correctly with auth checks, copies it for the next five, accidentally strips the auth check during modification.

## What kinds of objects do attackers target?

IDOR targets anything with an identifier the user can manipulate:

- **User data** — `/api/user/1542/profile` — change 1542 to 1543, see someone else's profile, address, payment info
- **Documents and files** — `/api/documents/8837/download` — invoices, medical records, tax documents, contracts. This is where IDOR gets high severity — PII, financial records, health data
- **Transactions and orders** — `/api/orders/44201` — view order history, shipping address, payment method. Or `/api/orders/44201/cancel` — modify or cancel someone else's order
- **Messages and conversations** — `/api/messages/conversation/772` — read private messages between other users
- **Admin functions** — `/api/users/1542/role` with a PUT — if there's no auth check, promote yourself to admin. IDOR on a write operation, not just read
- **Objects people forget** — support tickets, uploaded attachments, notification settings, API keys, payment methods, saved addresses

IDOR isn't just about reading data — it's about any operation. Read, update, delete, create. An IDOR on a DELETE endpoint is arguably worse than one on a GET.

## Do UUIDs fix IDOR?

No. UUIDs make enumeration harder — you can't just increment from 1 to 2 to 3. But they don't fix the vulnerability. If the attacker obtains a valid UUID — through a leaked API response, a shared link, a log file, an email notification, or another IDOR — and there's still no authorization check on the server, they're in.

UUIDs are obscurity, not security. If your defense relies on the attacker not knowing something, it's weak. If your defense relies on a server-side check that runs every time, it's strong.

## What's the difference between horizontal and vertical IDOR?

**Horizontal** — same privilege level, different user. User A accesses User B's data. The fix is an **ownership check**: does `resource.owner_id == current_user.id`? If not, reject.

**Vertical** — lower privilege accessing higher privilege functionality. Regular user hits `/api/admin/users`. The fix is a **role/permission check**: does `current_user.role == 'admin'`? Usually implemented as middleware or decorators (`@require_role('admin')`).

You need both. An admin panel needs a role check. A user's invoice page needs an ownership check. Some endpoints need both — "only admins can view any user's invoice, regular users can only view their own."

**Common mistake:** developers implement role checks on obviously admin pages like `/admin/dashboard` but forget the underlying API endpoints. The admin button is hidden in the UI for regular users, but `/api/admin/users` has no role check — the developer relied on the UI to enforce security.

## Why is "security through UI" dangerous?

The UI is for user experience, not security. Even without brute-forcing hidden endpoints, the attacker opens browser dev tools — the JavaScript source, network requests, and HTML all contain the API endpoint URLs including the "hidden" admin ones. Then they call them directly with curl, Burp, or Postman.

Anything the client can see, the attacker can see. Anything the client can send, the attacker can send. Every authorization decision must happen server-side.

## How do you find IDOR?

**1. Set up two accounts.** Create User A and User B with the same privilege level. You'll use one to generate valid requests and the other to test cross-account access. This is the most important step.

**2. Map every endpoint that touches user-specific data.** Walk through the entire app as User A — profile, orders, messages, documents, settings, everything. Capture every request in Burp. Look for identifiers anywhere — URL path (`/api/user/1542`), query params (`?invoice_id=883`), JSON body (`{"userId": 1542}`), headers, cookies.

**3. Swap and replay.** Take User A's requests and replay them using User B's session token. If User B can access User A's data — IDOR confirmed. Two accounts prove cross-user access, not just guessing.

**4. Test every HTTP method.** The GET might be protected but the PUT or DELETE might not. Developers often add auth checks to read operations but forget write and delete. Try GET, PUT, PATCH, DELETE on every endpoint.

**5. Check indirect references.** The ID isn't always in the URL — it can be in a hidden form field, a JWT payload, a cookie value, or a nested JSON object. Look everywhere.

**6. Test vertical access.** Beyond user-to-user (horizontal), test user-to-admin. Can a regular user access `/api/admin/users` or PUT to `/api/users/1542/role`?

**7. Burp Authorize extension** — automatically replays every request with a different user's session and highlights where authorization is missing. Saves massive time.

## How do you fix IDOR?

**Ownership check on every request** — query the database for the resource, verify `resource.owner_id == current_user.id`. If not, reject. This has to happen on every endpoint that returns or modifies user-specific data.

**Role check for privileged operations** — verify the user has the required role before allowing access. Implement as middleware that runs before the endpoint logic, not inside it.

**Don't rely on UUIDs** — use them for defense in depth (makes enumeration harder) but always pair with server-side authorization.

**Don't rely on the UI** — hiding buttons, graying out options, removing links from navigation does nothing. The API must enforce access control independently.

## How does IDOR chain with other vulnerabilities?

**IDOR + SQLi** — find an IDOR on `/api/users/1542/search?q=` where there's no ownership check. Discover the `q` parameter is also injectable. Now you can run SQL injection in the context of any user, accessing data scoped per-user in the database.

**IDOR + SSRF** — app lets users configure a webhook URL at `/api/users/1542/webhook`. IDOR lets you update any user's webhook. Point an admin's webhook at your server or at `http://169.254.169.254` — internal data gets sent to you.

**IDOR + Information Disclosure** — IDOR #1 leaks another user's email and UUID. That UUID was supposed to be "unguessable" — but now you use it to exploit IDOR #2 elsewhere. The first IDOR makes the second one exploitable. This is exactly why UUIDs don't fix the problem.

The pattern: IDOR often acts as the enabler — it gives you access to data or functionality that makes another vulnerability exploitable or increases its impact.

## My Notes
