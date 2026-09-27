# Buffer Overflow
Tags: #vulnerability #buffer-overflow #memory-safety #rce #day5

## What is a buffer overflow?

When a program allocates a fixed-size buffer in memory and writes more data than it can hold, the excess overwrites adjacent memory. In C/C++, functions like `strcpy()`, `scanf()`, `gets()` don't check bounds. The attacker's input spills past the buffer onto the stack — overwriting the return address, gaining control of execution flow, achieving RCE.

Modern web apps (Python, Java, Node.js) handle memory automatically — no buffer overflows in application code. But everything **around** the application is written in C/C++ and potentially vulnerable.

## Where do buffer overflows exist in modern systems?

Your application code is the one safe layer in the middle. Everything above and below it is C/C++:

```
Internet
    │
    ▼
┌─────────────────┐
│ Firewall / VPN  │ ← C/C++, overflows HERE
└────────┬────────┘
    ▼
┌─────────────────┐
│ Load Balancer   │ ← C (HAProxy, Nginx), overflows HERE
└────────┬────────┘
    ▼
┌─────────────────┐
│ Web Server      │ ← C (Nginx, Apache), overflows HERE
└────────┬────────┘
    ▼
┌─────────────────┐
│ Application     │ ← Python/Java/Node — memory safe
│                 │    BUT calls C libraries for:
│                 │    → image processing (overflow HERE)
│                 │    → PDF handling (overflow HERE)
│                 │    → compression (overflow HERE)
│                 │    → crypto (overflow HERE)
└────────┬────────┘
    ▼
┌─────────────────┐
│ Database        │ ← C (MySQL, PostgreSQL), overflows HERE
└─────────────────┘
```

## What are the real-world attack surfaces?

### Network infrastructure — the perimeter

| Target | Example CVEs | Entry point |
|---|---|---|
| SSL VPN (Fortinet, Pulse Secure) | CVE-2023-27997 (FortiGate heap overflow) | Pre-auth HTTPS request to VPN login page |
| Web servers (Nginx, Apache) | Oversized HTTP headers, chunked encoding | Port 80/443 |
| TLS libraries (OpenSSL) | CVE-2014-0187 (Heartbleed) | TLS handshake on any HTTPS port |
| DNS servers (BIND, dnsmasq) | DNSpooq (CVE-2020-25681) | Crafted DNS response on port 53 |
| SMB (Windows) | CVE-2017-0144 (EternalBlue → WannaCry) | Crafted SMB packet on port 445 |
| SSH (OpenSSH) | Crafted auth packets | Port 22 |

VPN endpoints are the most critical — internet-facing, process untrusted input **before** authentication, run as privileged processes. Successful overflow = inside the corporate network.

### File processing libraries — where uploads hit C code

**Image processing** — user uploads a crafted image, your Python app calls a C library to process it:

| Library | Language | Triggered by |
|---|---|---|
| ImageMagick | C | Crafted PNG/JPEG/TIFF with malformed chunks |
| libwebp | C | CVE-2023-4863 — crafted WebP viewed in any browser |
| libpng, libjpeg | C | Oversized IDAT chunks, malformed Huffman tables |
| Pillow/PIL | Python wrapping C | Same underlying C library vulnerabilities |

**PDF processing** — resume upload, document preview:

| Library | Triggered by |
|---|---|
| Poppler, MuPDF | Crafted font data, malformed stream decompression |
| Ghostscript | Cross-reference table parsing, embedded JavaScript |

**Video/audio** — FFmpeg, libavcodec. Crafted MP4 atom sizes, H.264 NAL units, malformed subtitle files.

**Compression** — zlib, libarchive, bzip2. Decompression with incorrect size fields, oversized archive filenames.

### Browser engines — the user is the endpoint

```html
<img src="evil.webp">           → libwebp overflow
<script>complex_js()</script>   → V8 JIT compiler overflow
<video src="evil.mp4">          → media decoder overflow
```

No click required. Just visiting a page with a crafted image or script triggers the overflow in Chrome (V8/Blink), Firefox (SpiderMonkey/Gecko), or Safari (WebKit).

### IoT and embedded devices

Routers, cameras, smart home devices — firmware written in C, often **without** ASLR, NX, or stack canaries. 1990s-style exploitation still works. Entry points: login page fields, WiFi SSID name, DHCP hostname, UPnP SOAP requests, firmware update parsing.

### OS kernels

Linux and Windows kernel — network stack, filesystem drivers, device drivers all process untrusted input. Kernel overflow = ring-0 privileges, invisible to all security software. EternalBlue was a kernel-level SMB overflow that powered WannaCry ransomware across hundreds of thousands of machines.

## What are the protections and how are they bypassed?

**NX/DEP** (No Execute) — stack is not executable, can't put shellcode there.
Bypass: **ROP (Return-Oriented Programming)** — chain together small snippets of existing executable code ("gadgets") ending in `ret`. Attacker overwrites return addresses to chain gadgets for arbitrary operations using code already marked executable.

**Stack canaries** — random value before the return address. If overwritten, program detects overflow and crashes.
Bypass: Leak the canary via separate info disclosure or format string bug. Or target **heap overflows** instead — heap has no canaries.

**ASLR** — memory addresses randomized. Attacker doesn't know where code/data lives.
Bypass: Information leak revealing one pointer → calculate library base address. Or brute force on 32-bit (only ~16 bits of entropy, ~65K attempts).

## Key CVEs to know

| CVE | Target | Impact |
|---|---|---|
| CVE-2014-0187 (Heartbleed) | OpenSSL | Buffer over-**read** — server leaks 64KB of RAM (private keys, passwords) per crafted heartbeat request. Affected millions of servers. |
| CVE-2017-0144 (EternalBlue) | Windows SMB | Kernel-level overflow via port 445. No auth. Powered WannaCry ransomware. |
| CVE-2023-27997 | Fortinet SSL VPN | Heap overflow in pre-auth VPN handler. RCE on the firewall itself. |
| CVE-2023-4863 | libwebp (Chrome/Firefox/Safari) | Heap overflow from crafted WebP image. RCE by visiting a web page. |
| DNSpooq (2020) | dnsmasq | Multiple overflows in DNS response parsing. RCE on routers. |

## My Notes
