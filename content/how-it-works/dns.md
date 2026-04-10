# DNS
Tags: #how-it-works #dns #networking #fundamentals #web-app-flows

## Core

DNS translates domain names to IP addresses. Every web request starts with a DNS lookup. Uses UDP port 53, unencrypted by default — anyone on the network path sees what domains you look up.

## Record Types

- **A** — domain → IPv4 (`example.com → 93.184.216.34`)
- **AAAA** — domain → IPv6
- **CNAME** — alias (`www.example.com → example.com`)
- **MX** — mail servers
- **TXT** — domain verification, SPF, DKIM, DMARC
- **NS** — authoritative nameservers

## Resolution Process

```
Browser cache → OS cache → Configured resolver (8.8.8.8, ISP)
  → Root server (.): "ask .com"
  → .com NS: "ask example.com's NS"
  → example.com NS: "93.184.216.34, TTL 3600"
  → Cached at every level for TTL duration
```

## Key Concepts

- **TTL** — how long resolvers cache answers. Low = more queries, faster failover. High = fewer queries, slow updates.
- **DoH / DoT** — encrypt DNS queries so the network path can't see your lookups.

## Attack Surface

- **DNS is plaintext** — lookups visible without DoH/DoT
- **DNS spoofing/poisoning** — false responses redirect to malicious IP (mitigated by DNSSEC)
- **DNS exfiltration** — data smuggled via subdomain lookups: `stolen-data.attacker.com`. Used in [[SQL Injection]] OOB and malware C2
- **Subdomain takeover** — dangling CNAME to decommissioned service (Heroku, S3) → attacker claims it
- **DNS rebinding** — domain resolves to attacker IP first (passes origin checks), then re-resolves to internal IP (127.0.0.1, 169.254.169.254)

## Audit

- [ ] Dangling CNAME records (subdomain takeover)
- [ ] Enumerate subdomains (subfinder, amass)
- [ ] Zone transfer misconfiguration (`dig axfr`)
- [ ] DNSSEC configured
- [ ] Internal DNS names leaking externally

## My Notes
