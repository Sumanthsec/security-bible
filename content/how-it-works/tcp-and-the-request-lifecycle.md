# TCP and the Request Lifecycle
Tags: #how-it-works #tcp #networking #fundamentals #day2

## What happens when you visit https://tractive.com?

Five steps, in order. Every website visit, forever.

```
You type "https://tractive.com" and press Enter
│
│  ┌──────────────────────────────────────────────────────┐
│  │  STEP 1: DNS RESOLUTION                              │
│  │                                                      │
│  │  "What IP address is tractive.com?"                  │
│  │                                                      │
│  │  Resolver → Root → .com TLD → AWS Route 53           │
│  │  → Answer: 3.168.86.104 (one of four IPs)            │
│  └──────────────────────────────────────────────────────┘
│
│  ┌──────────────────────────────────────────────────────┐
│  │  STEP 2: TCP THREE-WAY HANDSHAKE                     │
│  │                                                      │
│  │  Before ANY data can flow, establish a reliable       │
│  │  connection with the server.                          │
│  │                                                      │
│  │  You  ----SYN---->  Server   "I want to connect"     │
│  │  You  <--SYN-ACK--  Server   "OK, I acknowledge"     │
│  │  You  ----ACK---->  Server   "Great, connected"      │
│  │                                                      │
│  │  TCP connection OPEN on port 443.                    │
│  │  No data exchanged yet — just a channel.             │
│  └──────────────────────────────────────────────────────┘
│
│  ┌──────────────────────────────────────────────────────┐
│  │  STEP 3: TLS HANDSHAKE                               │
│  │                                                      │
│  │  Secure the TCP channel. Happens INSIDE the          │
│  │  TCP connection we just opened.                      │
│  │                                                      │
│  │  You  --ClientHello-->  Server                       │
│  │    "I support TLS 1.3, here are my cipher suites"    │
│  │                                                      │
│  │  You  <--ServerHello--  Server                       │
│  │    "TLS 1.3 + AES-128-GCM, here's my certificate"   │
│  │                                                      │
│  │  Verify: chain ✓, domain ✓, not expired ✓            │
│  │  Both sides compute shared secret.                   │
│  │  Encrypted tunnel ACTIVE.                            │
│  └──────────────────────────────────────────────────────┘
│
│  ┌──────────────────────────────────────────────────────┐
│  │  STEP 4: HTTP REQUEST                                │
│  │                                                      │
│  │  The actual web request, encrypted inside TLS,       │
│  │  over the TCP connection.                            │
│  │                                                      │
│  │  You  ---->  GET / HTTP/2                            │
│  │              Host: tractive.com                      │
│  │                                                      │
│  │  You  <----  HTTP/2 200 OK                           │
│  │              content-type: text/html                 │
│  │              [HTML body...]                          │
│  └──────────────────────────────────────────────────────┘
│
│  ┌──────────────────────────────────────────────────────┐
│  │  STEP 5: RENDERING                                   │
│  │                                                      │
│  │  Browser parses HTML, fetches CSS/JS/images.         │
│  │  Each may need its own DNS → TCP → TLS → HTTP       │
│  │  cycle, unless they reuse the connection via         │
│  │  HTTP/2 multiplexing.                                │
│  └──────────────────────────────────────────────────────┘
│
▼ Page is visible.
```

## What is TCP and why does it exist?

TCP is the transport layer. It sits between IP (raw packet delivery) and TLS (encryption).

IP is unreliable by design — packets can arrive out of order, get lost, get duplicated, and there's no concept of a "connection." TCP fixes all of this. It provides a reliable, ordered, connection-oriented stream of bytes.

## Why does the handshake need three steps?

```
Client                    Server
  |                          |
  |------- SYN seq=100 ---->|     1. "I want to talk. My starting
  |                          |         sequence number is 100."
  |                          |
  |<-- SYN-ACK seq=300 -----|     2. "I heard you. My starting sequence
  |     ack=101              |         number is 300. I expect your
  |                          |         next byte to be 101."
  |                          |
  |------- ACK ------------>|     3. "I heard you too. We're in sync."
  |     ack=301              |
  |                          |
  |===== CONNECTION OPEN ===|
```

Both sides need to confirm they can both send AND receive. With only two steps, the server wouldn't know if the client received its response. Three steps proves bidirectional communication works.

**Sequence numbers** — each side picks a random starting number. Every byte of data sent increments it. This is how TCP knows if packets arrive out of order or are missing. If the client sends bytes 101-200, the server ACKs "I got up to 201, send more." If byte 150 is lost, the server says "I only got up to 150" and the client resends.

## What are ports and why does 443 matter?

Ports are like apartment numbers in a building — the IP address gets you to the building (server), the port gets you to the right service.

| Port | Service | Protocol |
|---|---|---|
| 80 | HTTP | Unencrypted web |
| 443 | HTTPS | Encrypted web (TLS + HTTP) |
| 22 | SSH | Secure shell |
| 25 | SMTP | Email sending |
| 53 | DNS | Domain name resolution |

## What can an attacker see at the TCP level?

TCP is unencrypted. An attacker on your network can see:
- Source IP (you) and destination IP (server)
- That you're connecting to port 443 (so they know it's HTTPS)
- The TCP handshake happening
- Packet sizes and timing

They **cannot** see (thanks to TLS):
- What URL you're visiting (just the IP, not the path)
- Any content — request or response
- Cookies, passwords, anything

**One exception: SNI.** During the TLS ClientHello, your client sends the hostname `tractive.com` in plaintext. The server needs this to know which certificate to present (multiple sites can share one IP). An attacker CAN see which domain you're connecting to. TLS 1.3 has ECH (Encrypted Client Hello) to fix this, but it's not widely deployed yet.

## How do the network layers stack?

Each layer wraps the one above it like an envelope. Each layer only talks to its peer — TCP doesn't know about HTTP, TLS doesn't know about IP.

```
┌─────────────────────────────────────────────┐
│  LAYER 7: HTTP                              │
│  GET /en/shop  HTTP/2                       │
│  Cookie: session=abc123                     │
│  ← What the developer writes                │
├─────────────────────────────────────────────┤
│  LAYER 6/5: TLS                             │
│  Encrypts everything above                  │
│  Certificate verification, key exchange     │
│  ← Nobody between you and server can read   │
├─────────────────────────────────────────────┤
│  LAYER 4: TCP                               │
│  Reliable delivery, ordering, flow control  │
│  SYN → SYN-ACK → ACK                       │
│  ← Makes sure all bytes arrive correctly    │
├─────────────────────────────────────────────┤
│  LAYER 3: IP                                │
│  Source: 172.27.64.93 → Dest: 3.168.86.104  │
│  Routing between networks                   │
│  ← Gets packets from your machine to theirs │
├─────────────────────────────────────────────┤
│  LAYER 2: Ethernet/WiFi                     │
│  MAC addresses, local network frames        │
│  ← Gets packets to your router              │
├─────────────────────────────────────────────┤
│  LAYER 1: Physical                          │
│  Electrical signals, radio waves, light     │
│  ← Actual electrons or photons moving       │
└─────────────────────────────────────────────┘

Physical [ Ethernet [ IP [ TCP [ TLS [ HTTP [ Your data ] ] ] ] ] ]
```

## What do the real timings tell you?

```
DNS:          0 → 24ms     (24ms)  ← resolver cache was warm
TCP connect: 24 → 35ms     (10ms)  ← 10ms round trip to CloudFront edge
TLS:         35 → 62ms     (28ms)  ← 1 round trip for TLS 1.3
First byte:  62 → 74ms     (12ms)  ← server processing + response
Total:                      104ms
```

The 10ms TCP connect time means the CloudFront edge server is physically close — same city or region. Connecting to another continent would be 100-200ms. This is exactly why CDNs exist — they put servers close to users.

TLS took 28ms — roughly 2-3x the TCP time. TLS 1.3 needs 1 full round trip. TLS 1.2 would need 2 round trips (~20ms more). This is one of TLS 1.3's performance wins.

**ALPN** (Application-Layer Protocol Negotiation) happens during the TLS handshake. Client says "I can speak HTTP/2 and HTTP/1.1," server picks HTTP/2. Avoids a separate negotiation step — baked into the handshake for efficiency.

Measure any site yourself:

```bash
curl -w "DNS: %{time_namelookup}s\nTCP: %{time_connect}s\nTLS: %{time_appconnect}s\nTTFB: %{time_starttransfer}s\nTotal: %{time_total}s\n" -so /dev/null https://ANY-SITE-HERE
```

## How do you know which layer broke?

Each step can fail independently. The error type tells you which layer:

| Error | Layer that broke |
|---|---|
| `ERR_NAME_NOT_RESOLVED` | DNS — domain doesn't resolve |
| `ERR_CONNECTION_REFUSED` | TCP — port not open or server not listening |
| `ERR_CONNECTION_TIMED_OUT` | TCP — packets aren't getting through (firewall, server down) |
| `ERR_CERT_AUTHORITY_INVALID` | TLS — certificate not trusted |
| `ERR_SSL_PROTOCOL_ERROR` | TLS — handshake failure |
| 4xx / 5xx status codes | HTTP — server processed request but returned error |

## My Notes
