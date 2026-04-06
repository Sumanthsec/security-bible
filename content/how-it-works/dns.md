# DNS
Tags: #how-it-works #dns #networking #fundamentals #web-app-flows

## The Problem This Solves

Humans use domain names (`www.google.com`). Networks use IP addresses (`142.250.80.4`). DNS (Domain Name System) translates one to the other. Every web request starts with a DNS lookup before any connection is made.

## How a Developer Implements This

Developers don't implement DNS directly — the OS handles it. But they configure DNS records for their domains and rely on DNS resolution working correctly.

## Why Developers Choose Different Approaches

- **A records** — map a domain to an IPv4 address (`example.com → 93.184.216.34`)
- **AAAA records** — map to IPv6
- **CNAME records** — alias one domain to another (`www.example.com → example.com`)
- **MX records** — mail servers for the domain
- **TXT records** — arbitrary text (used for domain verification, SPF, DKIM, DMARC)
- **NS records** — which nameservers are authoritative for this domain

## What the Code Actually Looks Like

### The Resolution Process

```
Browser: "I need to reach www.example.com"
    ↓
1. Browser DNS cache (chrome://net-internals/#dns)
    ↓ (miss)
2. OS DNS cache (Linux: systemd-resolved, Windows: ipconfig /displaydns)
    ↓ (miss)
3. Query configured DNS resolver (e.g., 8.8.8.8, ISP's resolver)
    ↓
4. Resolver walks the hierarchy:
   Root server (.):         "ask the .com nameserver"
   .com nameserver:         "ask example.com's nameserver"
   example.com nameserver:  "93.184.216.34, TTL 3600"
    ↓
5. Answer cached at every level for the TTL duration
```

### What It Looks Like in Wireshark

Filter: `dns`

```
Query:    UDP, Src Port: 54321, Dst Port: 53
          DNS Query: www.example.com Type A Class IN

Response: UDP, Src Port: 53, Dst Port: 54321
          DNS Response: www.example.com A 93.184.216.34 TTL 3600
```

DNS uses **UDP port 53** for most queries. It's unencrypted — anyone on the network path can see what domains you're looking up.

## Configuration and Defaults That Matter

- **TTL (Time To Live)** — how long resolvers cache the answer (seconds). Low TTL = more DNS queries but faster failover. High TTL = fewer queries but slow to update.
- **DNS resolver** — who you ask. 8.8.8.8 (Google), 1.1.1.1 (Cloudflare), ISP resolver, or corporate resolver. Your resolver sees every domain you visit.
- **DNS-over-HTTPS (DoH) / DNS-over-TLS (DoT)** — encrypt DNS queries so the network path can't see your lookups. Supported by modern browsers and resolvers.

## Where Security Breaks

- **DNS is plaintext** — anyone on the network can see what domains you look up (without DoH/DoT)
- **DNS spoofing/poisoning** — attacker injects false DNS responses, redirecting you to a malicious IP. Mitigated by DNSSEC (signed responses).
- **DNS exfiltration** — data smuggled out via subdomain lookups: `stolen-data.attacker.com`. Used in [[SQL Injection]] OOB techniques and malware C2 channels.
- **Subdomain takeover** — if a CNAME points to a service you no longer use (e.g., old Heroku app), an attacker can claim that service and serve content on your subdomain.
- **DNS rebinding** — attacker's domain resolves to their IP first (passes same-origin checks), then re-resolves to an internal IP (127.0.0.1, 169.254.169.254), bypassing network restrictions.

## Auditing Checklist

- [ ] Check for dangling CNAME records (subdomain takeover risk)
- [ ] Enumerate subdomains (tools: subfinder, amass, DNS brute-force)
- [ ] Check for zone transfer misconfiguration (`dig axfr @nameserver domain.com`)
- [ ] Verify DNSSEC is configured if available
- [ ] Check if internal DNS names leak externally

## My Notes
