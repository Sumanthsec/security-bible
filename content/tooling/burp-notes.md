# Burp Suite
Tags: #tooling #burp #proxy #web-testing

## How It Works

Burp Suite is a **man-in-the-middle (MITM) HTTP proxy**. Not a packet capturer — it sits between the browser and the server, terminating and re-establishing TLS connections.

```
Normal:
  Browser ————————————————→ Server
            direct HTTPS

With Burp:
  Browser ———→ Burp (127.0.0.1:8080) ———→ Server
            ↑                            ↑
      Connection 1:                Connection 2:
      Browser ↔ Burp               Burp ↔ Server
      TLS with Burp's cert         TLS with server's real cert
```

**Two separate TLS connections:**
1. Browser → Burp: browser thinks Burp is the server. Burp presents its own certificate signed by Burp's CA.
2. Burp → Server: Burp connects to the real server as a normal client.

Burp decrypts traffic from connection 1, shows it to you (letting you modify it), re-encrypts on connection 2.

**Why you must install Burp's CA certificate:** Without it, the browser sees Burp's cert, checks the chain, finds no trusted root → certificate error. With Burp's CA installed, the browser trusts Burp's dynamically-generated certificates for any domain. Same mechanism used by corporate TLS inspection proxies.

## What It Can See

```
✓ Full HTTP requests — method, URL (full path + query), all headers, body
✓ Full HTTP responses — status code, headers, body (HTML, JSON, images)
✓ Cookies — Set-Cookie from server and Cookie from browser
✓ Authentication tokens — Bearer tokens, API keys, JWTs in headers
✓ WebSocket messages — full frames after HTTP upgrade
✓ Can MODIFY requests before they reach the server (Intercept)
✓ Can REPLAY requests with modifications (Repeater)
✓ Can AUTOMATE parameter fuzzing (Intruder)
```

## What It Cannot See

```
✗ DNS resolution — browser resolves DNS before connecting to the proxy
  WHY: proxy protocol works at HTTP level, browser sends "CONNECT host:443"

✗ TCP-level details — no SYN/ACK, sequence numbers, retransmissions
  WHY: Burp works above TCP, uses Java HTTP libraries that abstract TCP away

✗ TLS handshake details — no cipher negotiation or cert chain as-seen-by-browser
  WHY: Burp terminates TLS itself, you see HTTP after decryption

✗ Non-HTTP traffic — raw TCP, SSH, database protocols, DNS, custom protocols
  WHY: Burp is an HTTP proxy, it understands HTTP grammar only

✗ Traffic bypassing the proxy — apps making direct connections that ignore
  system proxy settings (some mobile apps, CLI tools, desktop apps)

✗ Certificate-pinned apps — apps that hardcode which cert to trust reject
  Burp's cert even with Burp's CA in the trust store
  Bypass: patch the app's pinning (Frida, objection on mobile)
```

## Comparison with Other Tools

```
                    Wireshark          Burp Suite         Browser DevTools
───────────────────────────────────────────────────────────────────────────
Operates at         Network interface  HTTP proxy          Inside browser
DNS queries         ✓                  ✗                   ✓ (timing only)
TCP handshake       ✓                  ✗                   ✗
TLS handshake       ✓ (encrypted       ✗                   ✓ (Security tab)
                     content hidden)
HTTP headers/body   Only if decrypted  ✓                   ✓
Modify requests     ✗ (passive)        ✓ (Intercept)       ✗
Replay requests     ✗                  ✓ (Repeater)        ✗
Non-HTTP traffic    ✓                  ✗                   ✗
JavaScript/DOM      ✗                  ✗                   ✓
localStorage        ✗                  ✗                   ✓ (Application)
```

**Wireshark:** what's on the wire (ground truth, but encrypted content is opaque).
**Burp:** what's in the HTTP conversation (decrypted, but no network-layer visibility).
**DevTools:** what the browser experiences (JS execution, DOM, storage — invisible to others).

## Key Tabs

- **Proxy → Intercept** — pause and modify requests in real-time
- **Proxy → HTTP History** — log of all requests/responses
- **Repeater** — manually modify and resend individual requests
- **Intruder** — automated parameter fuzzing and brute-forcing
- **Decoder** — encode/decode Base64, URL encoding, hex, etc.
- **Comparer** — diff two requests or responses side by side

## My Notes
