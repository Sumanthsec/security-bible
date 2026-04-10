# TLS and PKI
Tags: #how-it-works #tls #pki #cryptography #certificates #fundamentals #web-app-flows

## Core

TLS provides three guarantees on top of [[TCP Connections|TCP]]: **confidentiality** (encrypted), **integrity** (tamper-detected), **authentication** (server verified). PKI is the system of CAs, certificates, and trust chains that makes authentication work.

## Symmetric vs Asymmetric

**Symmetric** (AES-256-GCM, ChaCha20): one key, both sides, extremely fast. Problem: how to share the key.
**Asymmetric** (RSA, ECDSA, Ed25519): two keys (public/private), ~1000x slower. Solves the key-sharing problem.
TLS uses asymmetric for the handshake (key exchange + identity proof), symmetric for bulk data.

## TLS 1.3 Handshake

```
Browser                                         Server
   |--- ClientHello ----------------------------→  |
   |    Supported versions, cipher suites          |
   |    Key share: A (ECDHE public key)            |
   |    SNI: www.example.com (plaintext!)          |
   |                                               |
   |←-- ServerHello ----------------------------   |
   |    Chosen cipher, Key share: B                |
   |    [Both compute shared secret via ECDHE]     |
   |                                               |
   |←-- {Certificate} -------------------------    |  ← encrypted from here
   |←-- {CertificateVerify} -------------------    |  ← proves private key possession
   |←-- {Finished} ----------------------------    |
   |--- {Finished} ----------------------------→   |
   |========= ENCRYPTED HTTP TRAFFIC ==========    |
```

**SNI leaks the domain:** Browser sends hostname in plaintext in ClientHello so the server knows which cert to present. Even with HTTPS, anyone on the network sees which domain you're connecting to. They can't see path, headers, or body.

## Forward Secrecy (ECDHE)

The **E** in ECDHE = ephemeral — new random keys per session, deleted afterward. Past traffic is permanently unrecoverable even if the server's signing key leaks later. TLS 1.3 made ECDHE mandatory and removed RSA key exchange entirely. This kills "record now, decrypt later" attacks.

## Certificate Contents

```
Subject:    CN=www.example.com
Issuer:     CN=Let's Encrypt Authority X3
Validity:   2026-01-05 to 2026-07-04
Public Key: ECDSA P-256 [key bytes]
SANs:       example.com, www.example.com
Signature:  [signed with issuer's PRIVATE key]
```

## Trust Chain

```
Root CA (self-signed, pre-installed in browser/OS trust store, 20-30yr validity)
└── Intermediate CA (signed by root, online, 5-10yr)
    └── Leaf cert (signed by intermediate, 90 days to 1 year)
```

Why the indirection: if an intermediate is compromised, revoke it without affecting the root.

## Browser Validation

1. Build chain: leaf → intermediate → root (from trust store)
2. Verify each signature up the chain
3. Confirm root is in trust store
4. Check domain matches SAN/CN (wildcard = one level only)
5. Check validity period
6. Check revocation (OCSP / CRLite)
7. Check key usage extensions

All pass → padlock. Any fail → certificate error.

## Burp / MITM CA

Burp generates a fake cert for the target domain signed by "PortSwigger CA." Without the CA installed → cert error. With it installed → browser trusts it → Burp decrypts, inspects, re-encrypts. Same mechanism used by corporate TLS inspection proxies.

## Certificate Pinning

App hardcodes the expected cert's public key hash. Rejects any cert not matching the pin, regardless of trust store. Defeats Burp/corporate proxies. Bypass requires patching the app (Frida/objection).

## Attack Surface

- **Missing HSTS** — allows SSL stripping (downgrade HTTPS to HTTP)
- **Expired certificates** — users click through warnings, training to ignore errors
- **Weak cipher suites** — TLS 1.0/1.1 have known vulns (BEAST, POODLE)
- **Private key compromise** — without forward secrecy, past traffic exposed
- **Rogue CA** — compromised CA can issue certs for any domain
- **SNI leaks the domain** — visible in plaintext even with HTTPS

## Audit

- [ ] TLS version 1.2+ minimum, prefer 1.3
- [ ] No RC4, 3DES, or export ciphers
- [ ] HSTS header with adequate max-age
- [ ] Certificate chain valid (ssllabs.com)
- [ ] Certificate transparency monitoring
- [ ] Forward secrecy enabled (ECDHE suites)
- [ ] Test for TLS downgrade vulnerabilities

## My Notes
