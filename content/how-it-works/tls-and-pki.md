# TLS and PKI
Tags: #how-it-works #tls #pki #cryptography #certificates #fundamentals #day2

## What does TLS actually guarantee?

Three things on top of [[tcp-and-the-request-lifecycle|TCP]]:

1. **Confidentiality** — encrypted. Nobody between you and the server can read the data.
2. **Integrity** — tamper-detected. If anyone modifies the data in transit, both sides know.
3. **Authentication** — server verified. You're actually talking to bank.com, not an impostor.

Without TLS, HTTP is plaintext — anyone on the network path (coffee shop WiFi, ISP, compromised router) can read every request, every response, every cookie, every password.

## Why does TLS need both symmetric and asymmetric crypto?

**Symmetric** (AES-256-GCM, ChaCha20) — same key encrypts and decrypts. Like a padlock where the same key locks and unlocks. Extremely fast. AES-128 has 2^128 possible keys — every computer on earth couldn't brute-force it before the heat death of the universe.

Problem: how do you share the key? If you send it over the internet, anyone watching grabs it.

**Asymmetric** (RSA, ECDSA, Ed25519) — two mathematically linked keys. What one encrypts, only the other can decrypt. Public key shared with the world, private key never leaves the server. ~1000x slower than symmetric.

```
SYMMETRIC:                              ASYMMETRIC:
Same key locks and unlocks              Public key encrypts, private key decrypts
                                        Private key signs, public key verifies
plaintext → [KEY] → ciphertext
ciphertext → [KEY] → plaintext          plaintext → [PUBLIC KEY] → ciphertext
                                        ciphertext → [PRIVATE KEY] → plaintext
```

TLS uses both: asymmetric to agree on a shared symmetric key, then symmetric for all the actual data. Best of both — secure key exchange, fast encryption.

## How does Diffie-Hellman key exchange work?

This lets two parties who've never met create a shared secret while everyone watches, and nobody else can figure out what the secret is.

```
         YOU                                    SERVER
          │                                        │
          │     AGREE ON PUBLIC COLOR: Yellow       │
          │                                        │
   Pick SECRET:                             Pick SECRET:
     Red                                     Blue
          │                                        │
   Mix yellow + red                          Mix yellow + blue
     = ORANGE                                 = GREEN
          │                                        │
          ├──── Send ORANGE over internet ────────►│
          │◄──── Send GREEN over internet ─────────┤
          │                                        │
   Mix GREEN + red                           Mix ORANGE + blue
     = BROWN                                  = BROWN
          │                                        │
          └──── SAME COLOR! That's the key! ───────┘

   Attacker saw: Yellow, Orange, Green
   Attacker CANNOT get Brown without knowing Red or Blue
   Because unmixing colors is essentially impossible
```

Mathematically: public values `g` and `p`. You pick secret `a`, compute `g^a mod p` and send it. Server picks secret `b`, computes `g^b mod p` and sends it. Both compute `g^(ab) mod p` — same number. The attacker would need to solve the discrete logarithm problem from the public values — computationally infeasible for large numbers.

**X25519** — same concept but with elliptic curve math. Equivalent security with much smaller keys (256-bit EC vs 3072-bit RSA). Smaller keys = faster handshakes.

**X25519MLKEM768** (what CloudFront uses) — hybrid key exchange. X25519 for classical security + MLKEM768 (lattice-based, formerly Kyber) for quantum resistance. Attacker would need to break both. This is "harvest now, decrypt later" protection — if someone records traffic today and builds a quantum computer in 20 years, the MLKEM768 component still protects it.

## How does the TLS 1.3 handshake work, message by message?

```
Browser                                         Server
   |--- ClientHello ----------------------------→  |
   |    Supported versions, cipher suites          |
   |    Key share (X25519 public value)            |
   |    SNI: bulmax.com (plaintext!)             |
   |                                               |
   |←-- ServerHello ----------------------------   |
   |    Chosen cipher, Key share                   |
   |    [Both compute shared secret]               |
   |                                               |
   |←-- {EncryptedExtensions} -----------------    |  ← ENCRYPTED from here
   |←-- {Certificate} -------------------------    |  ← ENCRYPTED
   |←-- {CertificateVerify} -------------------    |  ← proves private key possession
   |←-- {Finished} ----------------------------    |
   |--- {Finished} ----------------------------→   |
   |========= ENCRYPTED HTTP TRAFFIC ==========    |
```

**ClientHello** — "Here's everything I support." Contains: client random (32 bytes), supported TLS versions, cipher suites (ordered preference), key shares (precomputed — TLS 1.3 sends key material immediately instead of waiting), SNI (hostname in plaintext), ALPN (HTTP/2 or HTTP/1.1 preference).

**ServerHello** — "I picked these options." Server's random, chosen cipher, server's key share. At this exact moment, both sides independently compute the same shared secret. Everything after this is encrypted.

**Certificate** (encrypted) — the full certificate chain. In TLS 1.3, the certificate is encrypted — an attacker on the network can see the SNI but not the certificate itself. In TLS 1.2, certificates were sent in plaintext.

**CertificateVerify** (encrypted) — server signs a hash of the entire handshake transcript with its private key. Proves: (1) server possesses the private key matching the certificate, (2) nobody tampered with any handshake messages.

**Finished** — MAC over all handshake messages using derived keys. If any bit was altered by an attacker, the MAC won't match and the connection is aborted.

Total: **1 round trip.** TLS 1.2 needed 2.

## What changed from TLS 1.2 to 1.3?

| Feature | TLS 1.2 | TLS 1.3 |
|---|---|---|
| Round trips | 2 | 1 |
| Certificate visibility | Plaintext (anyone can see) | Encrypted |
| Cipher suites | ~300+ possible (many weak) | 5 total (all strong) |
| Forward secrecy | Optional (can use static RSA) | Mandatory |
| RSA key exchange | Allowed (no forward secrecy) | Removed entirely |
| CBC mode ciphers | Allowed (attack surface) | Removed |
| Renegotiation | Supported (attack surface) | Forbidden |
| Compression | Allowed (CRIME attack) | Removed |
| 0-RTT resumption | No | Yes (with caveats) |

TLS 1.3 got secure by removing options. Every vulnerability in TLS 1.2 came from supporting old, weak configurations. TLS 1.3 says "there are exactly 5 cipher suites and you can't configure your way into a bad one."

## What is forward secrecy and why does it matter?

The **E** in ECDHE = **ephemeral**. New random key exchange values every session, deleted afterward.

**Without forward secrecy (RSA key exchange, TLS 1.2):** server has one RSA key pair that never changes. Every session encrypts the shared secret with that same key. If the private key is EVER compromised — hacked, stolen, legally compelled — attacker decrypts ALL recorded past sessions. Years of traffic, exposed.

**With forward secrecy (ECDHE):** every session generates a fresh ephemeral key pair → derives shared secret → keys deleted after session. If the server's RSA key is compromised, attacker can impersonate the server going forward but CANNOT decrypt any past recorded traffic. Each session's key was unique and is gone forever.

TLS 1.3 made ECDHE mandatory and removed RSA key exchange entirely. This kills "record now, decrypt later" attacks.

## How do you decode a cipher suite name?

**TLS 1.3:** `TLS_AES_128_GCM_SHA256` — simple because key exchange and authentication are negotiated separately.

```
TLS _ AES_128 _ GCM _ SHA256
 │      │        │      └─ Hash for key derivation
 │      │        └─ Mode (Galois Counter Mode — AEAD)
 │      └─ Bulk cipher + key size
 └─ TLS 1.3
```

**TLS 1.2:** `ECDHE-RSA-AES128-GCM-SHA256` — everything packed into one name.

```
ECDHE - RSA - AES128 - GCM - SHA256
  │      │      │       │      └─ MAC/PRF hash
  │      │      │       └─ Mode (AEAD)
  │      │      └─ Bulk cipher + key size
  │      └─ Authentication (server identity proof)
  └─ Key exchange (Ephemeral Elliptic Curve Diffie-Hellman)
```

**GCM** = Galois/Counter Mode, an AEAD cipher (Authenticated Encryption with Associated Data). Encrypts AND authenticates in one pass. CBC mode (older) only encrypts — authentication done separately with HMAC, and the ordering was a source of many vulnerabilities (POODLE, Lucky13, BEAST). TLS 1.3 only allows AEAD ciphers.

## What is a certificate and what's inside it?

A certificate binds a domain name to a public key, vouched for by a trusted third party (Certificate Authority).

```
Subject:    CN=www.example.com
Issuer:     CN=Let's Encrypt Authority X3
Validity:   2026-01-05 to 2026-07-04
Public Key: ECDSA P-256 [key bytes]
SANs:       example.com, www.example.com, *.example.com
Signature:  [signed with issuer's PRIVATE key]
```

**SANs** — which domains the cert covers. Wildcard (`*.example.com`) covers one subdomain level only — `app.example.com` matches, `a.b.example.com` doesn't.

**Signature** — the CA signed the certificate with its private key. Anyone with the CA's public key can verify the signature is genuine and the cert hasn't been modified.

## How does the trust chain work?

```
Root CA (self-signed, pre-installed in browser/OS trust store, 20-30yr validity)
└── Intermediate CA (signed by root, online, 5-10yr)
    └── Leaf cert (signed by intermediate, 90 days to 1 year)
```

~150 root CA certificates are pre-installed in your browser and OS. Root signs intermediate, intermediate signs leaf. Each signature is verifiable using the signer's public key.

Why the indirection? Root CA private keys are kept offline in hardware security modules. If an intermediate is compromised, revoke just that intermediate. If roots signed leaf certs directly, a compromise would mean revoking a root that millions of sites depend on.

## How does the browser validate a certificate?

1. Build chain: leaf → intermediate → root (from trust store)
2. Verify each signature up the chain
3. Confirm root is in trust store
4. Check domain matches SAN/CN
5. Check validity period (not expired, not yet valid)
6. Check revocation (OCSP / CRLite)
7. Check key usage extensions

All pass → padlock. Any fail → certificate error.

## What happens when a certificate needs to be revoked?

Certificates last up to 13 months. If the private key is stolen on day 2, you can't wait.

**CRL (Certificate Revocation List)** — CA publishes a list of revoked serial numbers. Browser downloads the full list. Problem: lists get huge, downloads are slow, browsers skip the check.

**OCSP (Online Certificate Status Protocol)** — browser asks the CA in real-time: "Is serial XYZ still good?" Problem: privacy — the CA knows every site you visit. Also: if OCSP server is down, what do you do?

**OCSP Stapling** — the best approach. The server periodically asks the CA about its own cert, gets a signed timestamped response, and staples it to the TLS handshake. Browser gets proof of validity right in the handshake — no need to contact the CA. No privacy leak, no extra connection, works even if the CA's OCSP server is down (until the stapled response expires).

## Why does SNI leak the domain name?

The server might host multiple websites on one IP. It needs to know which certificate to present before encryption starts. So the browser sends the hostname in plaintext in the ClientHello.

Even with HTTPS, anyone on the network sees which domain you're connecting to. They can't see the path, headers, body, or anything after the handshake — but the domain name is visible.

**ECH (Encrypted Client Hello)** — TLS 1.3 extension. Server publishes an encryption key in DNS, client encrypts the SNI using that key. Attacker sees only a generic cover name. Requires both server and client support — still being rolled out.

## How does Burp Suite intercept HTTPS?

Burp acts as a man-in-the-middle. When you visit `bank.com` through Burp:

1. Burp intercepts and makes its own TLS connection to `bank.com`
2. Burp generates a fake certificate for `bank.com` on the fly, signed by "PortSwigger CA"
3. Burp presents this fake cert to your browser

Without Burp's CA installed → certificate error (untrusted issuer). With it in your trust store → browser trusts the fake cert → Burp decrypts, inspects, modifies, re-encrypts. Same mechanism corporate TLS inspection proxies use.

This is why the trust store is security-critical. Anyone who can add a root CA to your trust store can silently intercept all your HTTPS traffic.

## What is certificate pinning?

App hardcodes the expected certificate's public key hash. On every connection: does the server's cert match my pin? If not, reject — regardless of trust store. Defeats Burp, corporate proxies, and compromised CAs.

Bypass requires patching the app binary — tools like Frida and objection automate this for mobile app testing.

## What is HSTS and why does it matter?

`Strict-Transport-Security: max-age=31536000; includeSubDomains`

Tells the browser: "for the next year, never connect to this domain over plain HTTP. Always use HTTPS, no exceptions."

Without HSTS, an attacker can perform **SSL stripping** — intercept the initial HTTP request (before the redirect to HTTPS) and keep the victim on HTTP. The attacker talks HTTPS to the server, HTTP to the victim. Victim sees `http://bank.com` (no padlock) but might not notice.

With HSTS, the browser upgrades to HTTPS internally before any network traffic. SSL stripping is blocked.

**HSTS preload list** — browsers ship with a hardcoded list of HTTPS-only domains, protecting even the first visit (before the browser has seen the HSTS header).

## What TLS attacks should you know?

Almost every attack exploited an old, weak option kept for backwards compatibility. TLS 1.3 fixed this by removing all of them.

| Attack | Year | What it exploited | Fix |
|---|---|---|---|
| BEAST | 2011 | CBC mode in TLS 1.0 — predictable IV | TLS 1.1+ or GCM ciphers |
| CRIME | 2012 | TLS compression leaked data via size | Disable TLS compression |
| Lucky13 | 2013 | CBC padding timing side-channel | GCM/AEAD ciphers |
| Heartbleed | 2014 | OpenSSL bug — read server memory | Patch OpenSSL (not a protocol flaw) |
| POODLE | 2014 | SSL 3.0 CBC padding oracle | Disable SSL 3.0 |
| FREAK | 2015 | Export-grade 512-bit RSA keys | Remove export ciphers |
| Logjam | 2015 | Weak 512-bit DH parameters | 2048+ bit DH or ECDHE |
| DROWN | 2016 | SSLv2 cross-protocol attack | Disable SSLv2 |
| ROBOT | 2017 | RSA key exchange Bleichenbacher variant | Remove RSA key exchange |

The pattern: TLS 1.3 removed CBC, RSA key exchange, compression, renegotiation, and weak DH groups. No more configuring your way into a vulnerability.

## What should you check during an audit?

- TLS 1.2+ minimum, prefer 1.3
- No RC4, 3DES, CBC, or export ciphers
- Forward secrecy enforced (ECDHE only, no static RSA key exchange)
- HSTS header with adequate `max-age` and `includeSubDomains`
- Certificate chain valid and trusted (ssllabs.com)
- OCSP stapling active
- No TLS compression (CRIME)
- No renegotiation support (or patched with renegotiation_info)
- Certificate Transparency monitoring
- Certificate pinning on mobile apps (if applicable)
- No mixed content on HTTPS pages
- SNI leakage awareness

## My Notes
