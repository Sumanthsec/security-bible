# HTTP Request Smuggling
Tags: #vulnerability #request-smuggling #http #desync #day5

## What is HTTP request smuggling?

Modern web architecture puts a front-end (reverse proxy, CDN, load balancer) in front of a back-end (application server). Both need to parse where one HTTP request ends and the next begins on the same TCP connection. Request smuggling exploits a disagreement between them — the front-end thinks request A is N bytes long, the back-end disagrees. The leftover bytes become a "smuggled" prefix that the back-end attaches to the next legitimate user's request.

This isn't a bug in HTTP — it's a consequence of two independent parsers interpreting the same byte stream with subtly different rules.

## Why does HTTP allow two ways to mark request boundaries?

HTTP/1.1 has two mechanisms:

**Content-Length** — declares the exact body size in bytes. `Content-Length: 13` means "read exactly 13 bytes after the headers, then the next request starts."

**Transfer-Encoding: chunked** — body sent in chunks. Each chunk: hex size + `\r\n` + data + `\r\n`. Terminated by a zero-length chunk: `0\r\n\r\n`.

```
POST / HTTP/1.1
Transfer-Encoding: chunked

b\r\n           ← 0x0b = 11 bytes follow
hello world\r\n
0\r\n           ← zero chunk = end
\r\n            ← final terminator
```

RFC 2616 says: if both headers are present, Transfer-Encoding takes priority. But not every implementation follows the RFC the same way. That gap is where smuggling lives.

## What are the three smuggling variants?

The naming convention is **front-end.back-end** — which header each side uses to determine body length.

| Variant | Front-end uses | Back-end uses | Classic setup |
|---|---|---|---|
| CL.TE | Content-Length | Transfer-Encoding | CDN ignores TE, app server honors it |
| TE.CL | Transfer-Encoding | Content-Length | Reverse proxy honors TE, app ignores it |
| TE.TE | Transfer-Encoding | Transfer-Encoding | Both honor TE, but one can be confused by obfuscation |

**CL.TE** — front-end reads Content-Length bytes, forwards them all. Back-end parses Transfer-Encoding, hits `0\r\n\r\n` (end of chunks) partway through, and treats everything after that as the start of a new request. The leftover bytes sit in the TCP buffer waiting for the next request.

**TE.CL** — front-end reads chunked encoding, forwards the full chunked body. Back-end reads Content-Length, stops early, leaves the rest in the buffer as a new request prefix.

**TE.TE** — both servers support Transfer-Encoding, but you obfuscate it so one parses it and the other falls back to Content-Length:

```
Transfer-Encoding: chunked
Transfer-Encoding: x
```
```
Transfer-Encoding : chunked     ← space before colon
```
```
Transfer-Encoding: chunked
Transfer-encoding: x            ← different capitalization
```
```
Transfer-Encoding:
 chunked                        ← line folding
```

Whichever server fails to parse the obfuscated TE falls back to Content-Length — and now you have CL.TE or TE.CL.

## Why does the smuggled data persist between requests?

HTTP/1.1 keep-alive reuses TCP connections. The front-end sends multiple users' requests down the same TCP connection to the back-end. The back-end reads from a single byte stream — it has no concept of "this chunk belongs to user A, that chunk belongs to user B."

When the back-end finishes parsing one request (according to its understanding of the boundary), whatever bytes remain in the TCP receive buffer become the start of the next request. If the attacker left crafted bytes there, those bytes prefix the next legitimate user's request. The back-end concatenates the smuggled prefix + the victim's actual request and processes the combined result.

This is why smuggling is a **connection-level** attack — it poisons the TCP stream, not a single request.

## How do you count bytes for a CL.TE payload?

Every byte matters. `\r\n` is 2 bytes. A wrong count means the smuggled prefix is too short (partial, fails) or too long (eats into the next request's headers, malformed).

```
POST / HTTP/1.1
Host: target.com
Content-Length: 35
Transfer-Encoding: chunked

0\r\n                              ← 3 bytes (0 + \r\n)
\r\n                               ← 2 bytes (chunk terminator)
GET /admin HTTP/1.1\r\n            ← 21 bytes
Host: target.com\r\n               ← 9 bytes...
```

Content-Length must equal the total bytes the front-end needs to forward — from the start of the body through the end of your smuggled prefix. The front-end reads exactly that many bytes and sends them to the back-end. The back-end hits `0\r\n\r\n`, considers the chunked body done, and treats `GET /admin...` as a new request.

For hex chunk sizes: `b` = 11 bytes, `1a` = 26 bytes. Off by one and the parser either waits forever or chokes.

## What can you actually do with a smuggled request?

### 1. Bypass WAF / front-end security

The front-end checks `GET /public` — looks fine, forwards it. But the smuggled prefix is `GET /admin`. The back-end processes `GET /admin` without the front-end ever seeing it. Any front-end access control, WAF rule, or rate limit is bypassed because the front-end never parsed that request.

### 2. Steal other users' requests

Smuggle an incomplete `POST` with a large Content-Length:

```
POST /log HTTP/1.1
Host: target.com
Content-Length: 400

body=
```

The back-end waits for 400 bytes. The next legitimate user's full request (headers, cookies, auth tokens) fills the remaining bytes. The combined body gets sent to `/log` — the attacker reads it from wherever that endpoint stores data.

### 3. Cache poisoning

CDN caches responses by URL. Smuggle a request for `/evil` that the CDN thinks is a response for `/homepage`. Now every user hitting `/homepage` gets the cached response from `/evil`. One smuggled request poisons the cache for thousands of users until TTL expires.

### 4. Reflected XSS amplification

Turn a reflected XSS that requires victim interaction into a stored-XSS-like attack. Smuggle a request containing the XSS payload — the response gets cached. Every user who hits that cached URL gets the XSS payload delivered automatically. No click required.

### 5. Redirect hijacking

If the app has an open redirect, smuggle a request that triggers it. The redirect response gets served to the next user, sending their browser (with cookies) to the attacker's domain.

### 6. Authentication bypass

Smuggle a request that includes the internal header the front-end adds for authenticated users: `X-Authenticated-User: admin`. The back-end trusts this header because it "came from" the front-end.

## Where does the smuggled request physically live?

In the TCP socket's receive buffer — kernel memory on the back-end server. When the front-end sends bytes over the keep-alive connection, the OS kernel buffers them. The back-end application reads from this buffer. After it finishes one request (by its boundary rules), the remaining unread bytes stay in the kernel buffer. The next `read()` call picks up those leftover bytes first, before any new data arrives.

The smuggled request is not stored in any application-level queue — it exists purely as unread bytes in the TCP stream. This is why it seamlessly prefixes the next request: from the back-end's perspective, it's just reading a continuous byte stream.

## How does HTTP/2 prevent smuggling?

HTTP/2 uses binary framing instead of text parsing. Each request is a stream with explicit frame boundaries — `HEADERS` frame + `DATA` frame(s) + `END_STREAM` flag. The protocol enforces boundaries at the framing layer, not by parsing text headers.

There's no Content-Length vs Transfer-Encoding ambiguity because the frame length field is authoritative. You can't "smuggle" extra bytes because the protocol knows exactly where each stream's data starts and ends.

**But**: HTTP/2 only prevents smuggling if it's used end-to-end. Many architectures terminate HTTP/2 at the front-end and speak HTTP/1.1 to the back-end — this re-introduces the text parsing layer and smuggling is possible again. This is **H2 desync** (HTTP/2 downgrade smuggling).

| Setup | Smuggling possible? |
|---|---|
| H2 front → H2 back | No — binary framing throughout |
| H2 front → H1 back | Yes — H2 desync. Front translates to H1, re-introducing text parsing |
| H1 front → H1 back | Yes — classic smuggling |

## What are HTTP/2-specific attacks?

HTTP/2 has its own vulnerability classes:

| Attack | Mechanism |
|---|---|
| Rapid Reset (CVE-2023-44487) | Open stream, immediately RST_STREAM, repeat. Server allocates resources per stream but client cancels before response. Asymmetric DoS. |
| HPACK bomb | Compressed header block that decompresses to massive size. Memory exhaustion. |
| Stream flooding | Open max concurrent streams, send requests slowly. Ties up server resources. |

These attack HTTP/2's resource management, not its request boundary parsing.

## How do you defend against request smuggling?

**Use HTTP/2 end-to-end** — eliminates the text parsing ambiguity entirely. This is the real fix.

**Reject ambiguous requests** — if a request contains both Content-Length and Transfer-Encoding, drop it. Don't try to decide which to honor.

**Normalize before forwarding** — front-end should fully parse the request, then re-serialize it in a canonical form before sending to the back-end. Eliminates parser differential.

**Disable keep-alive to the back-end** — one TCP connection per request eliminates the shared-connection prerequisite. Significant performance cost, but eliminates the attack surface.

**Strict Transfer-Encoding parsing** — reject obfuscated TE headers (extra spaces, line folding, duplicate headers). Don't be lenient.

## How do you test for request smuggling?

**1. Identify the architecture.** Is there a front-end proxy? CDN? Load balancer? Check response headers (`Server`, `Via`, `X-Forwarded-For`). Smuggling requires at least two HTTP parsers in the chain.

**2. Timing-based detection.** Send a CL.TE probe where the smuggled portion is an incomplete request. If the back-end hangs waiting for more data (long response time), the desync worked. Compare normal response time vs probe response time.

**3. Test each variant:**
- CL.TE: Content-Length covers full payload, chunked encoding ends early
- TE.CL: Chunked encoding covers full payload, Content-Length is short
- TE.TE: Obfuscated Transfer-Encoding headers

**4. Confirm with differential responses.** Smuggle a request to a different endpoint. If you get back a response from the smuggled endpoint instead of the one you actually requested, the desync is confirmed.

**5. Escalate carefully.** In production, smuggling affects real users on the same connection. Use techniques that confirm the vulnerability without disrupting other users — timing-based detection is safest.

Tools: Burp Suite's HTTP Request Smuggler extension automates probe generation. James Kettle's research (PortSwigger) is the definitive reference.

## My Notes
