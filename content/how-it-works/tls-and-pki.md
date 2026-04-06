# TLS and PKI
Tags: #how-it-works #tls #pki #cryptography #certificates #fundamentals #web-app-flows

## The Problem This Solves

A [[TCP Connections|TCP connection]] is plaintext — anyone on the network path can read and modify the data. TLS (Transport Layer Security) provides three guarantees on top of TCP:

1. **Confidentiality** — data is encrypted, only the endpoints can read it
2. **Integrity** — data can't be modified in transit without detection
3. **Authentication** — the server is verified to be who it claims to be

PKI (Public Key Infrastructure) is the system of Certificate Authorities, certificates, and trust chains that makes authentication work.

## Symmetric vs Asymmetric Encryption

There are only two kinds of encryption. TLS uses both.

### Symmetric Encryption

One key. Same key encrypts and decrypts.

```
Key: "secretkey123"
Encrypt: plaintext + key → ciphertext
Decrypt: ciphertext + key → plaintext
```

Examples: AES-256-GCM, ChaCha20-Poly1305. Extremely fast — AES is hardware-accelerated on every modern CPU, encrypts gigabytes per second.

**Weakness:** How do you get the same key to both sides? Sending the key over the network means anyone watching gets it too.

### Asymmetric Encryption

Two keys. What one locks, only the other unlocks.

```
Encrypt: plaintext + PUBLIC key  → ciphertext
Decrypt: ciphertext + PRIVATE key → plaintext

Sign:    data + PRIVATE key → signature
Verify:  data + signature + PUBLIC key → valid/invalid
```

Examples: RSA, ECDSA, Ed25519. About **1000x slower** than symmetric. Cannot practically encrypt bulk data.

**Strength:** You can share the public key openly. The private key never moves.

### How TLS Uses Both

Asymmetric solves the key-sharing problem. Symmetric handles bulk data.

```
Handshake (asymmetric, slow, ~2-5 KB of data):
  ECDHE:  key exchange → both sides get shared secret
  RSA/ECDSA signature: server proves identity

Data transfer (symmetric, fast, potentially gigabytes):
  AES-256-GCM: encrypt all HTTP traffic using keys derived from the shared secret
```

Asymmetric is the armored truck that delivers the key. Symmetric is the lock that uses it. Expensive truck once, fast lock forever after.

## The TLS 1.3 Handshake

```
Browser                                         Server
   |                                               |
   |--- ClientHello ----------------------------→  |
   |    Supported TLS versions, cipher suites      |
   |    Key share: A (ECDHE public key)            |
   |    SNI: www.example.com (plaintext!)          |
   |                                               |
   |←-- ServerHello ----------------------------   |
   |    Chosen cipher: TLS_AES_256_GCM_SHA384      |
   |    Key share: B (server ECDHE public key)     |
   |                                               |
   |    [Both compute shared secret from ECDHE]    |
   |    [Derive encryption keys via HKDF]          |
   |                                               |
   |←-- {Certificate} -------------------------    |  ← encrypted from here
   |←-- {CertificateVerify} -------------------    |  ← proves server has private key
   |←-- {Finished} ----------------------------    |
   |                                               |
   |--- {Finished} ----------------------------→   |
   |                                               |
   |========= ENCRYPTED HTTP TRAFFIC ==========    |
```

**SNI (Server Name Indication):** The browser sends the hostname in plaintext in the ClientHello. This is necessary because one IP can host hundreds of sites — the server needs to know which certificate to present. Even with HTTPS, anyone on the network can see which **domain** you're connecting to (via SNI and [[DNS]]). They can't see the URL path, headers, or body.

## Key Exchange — ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)

### The Problem

Both sides need to agree on an encryption key. But the conversation itself isn't private — an attacker could be watching. How do you create a shared secret when the channel is public?

### How It Works

```
Public parameter: an agreed elliptic curve (e.g., X25519) with a base point G

Browser:
  1. Generate random private key: a (256 bits)
  2. Compute public key: A = a × G (point multiplication on the curve)
  3. Send A in ClientHello

Server:
  1. Generate random private key: b (256 bits)
  2. Compute public key: B = b × G
  3. Send B in ServerHello

Both compute the shared secret:
  Browser: secret = a × B = a × (b × G) = (ab) × G
  Server:  secret = b × A = b × (a × G) = (ab) × G
           ↑ SAME VALUE

Attacker sees: G, A, B (all public)
Needs to find: a from A = a × G → elliptic curve discrete log problem → infeasible
```

Computing `A = a × G` (point multiplication) is fast. Reversing it — finding `a` from `A` and `G` — is computationally infeasible. Same one-way property as regular Diffie-Hellman but with much smaller keys (256-bit ECC ≈ 3072-bit RSA security).

### The "Ephemeral" Part — Forward Secrecy

The **E** in ECDHE means new random keys for **every single session**. After the session ends, the private values `a` and `b` are deleted from memory. They exist nowhere.

This is why ECDHE was created — to fix a critical problem with the old approach:

**Old way (RSA key exchange, used from 1995-2018):**
```
Browser encrypts pre-master secret with server's RSA public key
Server decrypts with its long-lived RSA private key
Same RSA private key used for EVERY session, for months or years
```

**The fatal flaw:**
```
Year 1: Attacker records all encrypted traffic (can't read it yet)
Year 2: Attacker steals the server's RSA private key (breach, Heartbleed, court order)
Now:    Attacker decrypts EVERY recorded pre-master secret from Year 1
        Derives all session keys, decrypts ALL past traffic retroactively
```

One key compromise unlocked all past sessions. Intelligence agencies recorded bulk encrypted traffic betting they could get keys later ("record now, decrypt later").

**ECDHE fix:**
```
Year 1: Each session uses unique random ephemeral keys (a, b)
        Keys deleted after each session
Year 2: Attacker steals server's RSA private key
Now:    RSA key was only used for SIGNATURES (proving identity)
        Never used for key exchange
        Ephemeral keys a, b no longer exist — nowhere on disk, nowhere in memory
        Past traffic CANNOT be decrypted. Ever.
```

TLS 1.3 (2018) removed RSA key exchange entirely. Only ECDHE is allowed. Forward secrecy is mandatory.

### From Shared Secret to Encryption Keys

The DH shared secret goes through a key derivation function to produce separate keys:

```
Shared secret (from ECDHE)
    ↓
HKDF (key derivation function)
    ↓
    ├── Client write key    (browser → server encryption)
    ├── Server write key    (server → browser encryption)
    ├── Client IV           (nonce for client's encryption)
    └── Server IV           (nonce for server's encryption)
```

Separate keys per direction — a message encrypted for one direction can't be decrypted as the other. IVs ensure encrypting the same data twice produces different ciphertext.

All HTTP traffic is then encrypted with AES-256-GCM. The GCM authentication tag provides integrity — if anyone modifies the ciphertext in transit, decryption fails.

## PKI — How Certificates Work

### What a Certificate Contains

```
Subject: CN=www.example.com                     ← who this cert is for
Issuer:  CN=Let's Encrypt Authority X3          ← who signed it
Validity: 2026-01-05 to 2026-07-04              ← expiration dates
Public Key: ECDSA P-256 [key bytes]             ← server's public key
Subject Alternative Names: example.com, www.example.com  ← domains covered
Signature Algorithm: SHA256withRSA
Signature: [signed with the issuer's PRIVATE key]
```

### How a Certificate Is Created

```
Step 1: Server generates a key pair
  openssl genrsa -out myapp.com.key 2048
  → private key (secret) + public key (derived from it)

Step 2: Server creates a CSR (Certificate Signing Request)
  openssl req -new -key myapp.com.key -out myapp.com.csr
  CSR contains: domain name + public key + proof you have the private key

Step 3: CA validates domain ownership
  HTTP-01: "Put this token at http://myapp.com/.well-known/acme-challenge/xyz"
  DNS-01:  "Create TXT record _acme-challenge.myapp.com with value abc"
  CA fetches/queries to confirm you control the domain

Step 4: CA signs the certificate
  CA takes your CSR data, signs it with the CA's PRIVATE key
  → produces the certificate file

Step 5: Install on server
  Configure nginx/Apache with the cert + your private key
```

### The Trust Chain

CAs don't sign certs with their root key directly. Root keys are kept offline in hardware security modules. Instead there's a hierarchy:

```
Root CA (self-signed, pre-installed in browser/OS trust store)
│   Key: offline in HSM, used rarely
│   Validity: 20-30 years
│
└── Intermediate CA (signed by root)
    │   Key: online, signs leaf certs daily
    │   Validity: 5-10 years
    │
    └── myapp.com (leaf cert, signed by intermediate)
            Validity: 90 days to 1 year
```

Why the indirection: if an intermediate is compromised, revoke it. The root stays safe. If the root were compromised, every cert ever issued by that CA would be untrusted.

### How the Browser Validates a Certificate

Server sends: leaf cert + intermediate cert(s). Browser performs:

```
1. BUILD THE CHAIN
   Leaf → Intermediate → Root (from trust store)

2. VERIFY EACH SIGNATURE
   Hash leaf cert data → verify with intermediate's public key → match?
   Hash intermediate cert data → verify with root's public key → match?
   (Each cert's signature was created by the issuer's private key.
    Verification uses the issuer's public key. If the hashes match,
    the cert was genuinely signed by that issuer and hasn't been tampered with.)

3. CHECK ROOT IS TRUSTED
   Is the root cert in the browser/OS trust store? (Pre-installed by vendor)

4. CHECK DOMAIN MATCH
   Does cert's SAN or CN match the URL hostname?
   *.example.com matches www.example.com ✓
   *.example.com does NOT match a.b.example.com ✗ (one level only)

5. CHECK VALIDITY PERIOD
   Is current time between Not Before and Not After?

6. CHECK REVOCATION
   OCSP query: "Is this cert's serial number still valid?"
   Or OCSP stapling: server includes a pre-fetched signed OCSP response
   Or CRLite (Firefox): compressed revocation data pushed to all browsers

7. CHECK KEY USAGE
   Does the cert have "TLS Web Server Authentication" in Extended Key Usage?
   Does the intermediate have CA:TRUE in Basic Constraints?

ALL PASS → padlock, connection proceeds
ANY FAILS → certificate error
```

### CertificateVerify — Proving Private Key Possession

The certificate is public — anyone could copy it. The server proves it has the matching private key by signing the handshake transcript:

```
Server: hash all handshake messages so far → sign with private key → send signature
Browser: hash same messages → verify signature with cert's public key
Valid → server definitely has the private key
Invalid → stolen/replayed certificate → abort
```

### Why Burp Suite Needs Its CA Installed

```
Normal:  Browser validates cert: myapp.com → signed by Let's Encrypt → root in trust store ✓

With Burp (no CA installed):
  Burp generates fake cert for myapp.com signed by "PortSwigger CA"
  Browser: "PortSwigger CA" not in trust store → ✗ certificate error

With Burp (CA installed):
  Browser: "PortSwigger CA" is in trust store → ✓ connection proceeds
  Burp decrypts traffic from browser, inspects it, re-encrypts to server
```

Same mechanism used by corporate TLS inspection proxies — company installs their root CA on employee devices so the proxy can MITM all HTTPS traffic.

### Certificate Pinning

Some apps bypass the trust store entirely:

```
Normal:   "Is this cert signed by ANY trusted CA?" → Yes → Accept
Pinning:  "Is this cert's public key hash EXACTLY sha256/YLh1dUR9y6...?" → Yes → Accept
```

Mobile banking apps, some security-critical apps use pinning. This defeats Burp/corporate proxies because the app rejects any cert not matching the pin, regardless of trust store. Bypass requires patching the app (Frida/objection).

### Real-World PKI Failures

- **DigiNotar (2011)** — CA compromised, attacker issued valid `*.google.com` cert, used for MITM against Iranian users. DigiNotar removed from all trust stores, went bankrupt.
- **Symantec (2017)** — mis-issued thousands of certs without proper validation. Chrome gradually distrusted all Symantec certs.
- **Flame malware (2012)** — forged a Microsoft certificate using an MD5 collision. Led to industry-wide migration away from MD5 signatures.

These drove **Certificate Transparency (CT)** — public append-only logs of all issued certificates. CAs must submit every cert to CT logs. Anyone can monitor for unauthorized certs at `crt.sh`.

## Where Security Breaks

- **Missing HSTS** — allows SSL stripping (downgrade HTTPS to HTTP)
- **Expired certificates** — users click through warnings, training them to ignore cert errors
- **Weak cipher suites** — TLS 1.0/1.1 have known vulnerabilities (BEAST, POODLE)
- **Private key compromise** — without forward secrecy (ECDHE), past traffic is exposed
- **Rogue CA** — compromised or malicious CA can issue certs for any domain
- **SNI leaks the domain** — even with HTTPS, the domain you're visiting is visible in plaintext

## Auditing Checklist

- [ ] Check TLS version (must be 1.2+ minimum, prefer 1.3)
- [ ] Check cipher suites (no RC4, no 3DES, no export ciphers)
- [ ] Verify HSTS header is set with adequate max-age
- [ ] Check certificate chain validity (ssllabs.com)
- [ ] Check for certificate transparency monitoring
- [ ] Test for TLS downgrade vulnerabilities
- [ ] Verify forward secrecy is enabled (ECDHE cipher suites)

## My Notes
