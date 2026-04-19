# DNS
Tags: #how-it-works #dns #networking #fundamentals #day2

## What is DNS and why does it exist?

DNS is a phone book for the internet. Your browser doesn't know how to reach "tractive.com" — it only understands IP addresses like `3.168.86.112`. DNS translates human-readable names into IP addresses.

Every single time you visit a website, DNS happens first, before anything else. No DNS = no connection. Uses UDP port 53, unencrypted by default — anyone on the network path sees what domains you look up.

## How is DNS organized?

DNS is a hierarchy, like a file system:

```
                    . (root)
                    |
        +-----------+-----------+
        |           |           |
      .com        .org        .net
        |
    tractive.com
        |
   +----+----+----+
   |    |    |    |
  app  api  help  my
```

Every domain is read right to left: `app.tractive.com.` → start at `.` (root) → go to `com` → go to `tractive` → go to `app`.

That trailing dot you sometimes see? It means "root." Every domain technically ends with a dot.

## How does a DNS lookup actually work, step by step?

**Hop 1 — Root servers (`.`)**

Your resolver asks your local DNS server (router or ISP). It already knows the 13 root server addresses — run by ICANN, US Army, NASA, Verisign. There are only 13 root server addresses but hundreds of actual machines worldwide using anycast.

The root servers' response: "I don't know what tractive.com is, but I know who handles `.com` — go ask the .com TLD servers."

**Hop 2 — TLD servers (`.com`)**

The resolver asks a root server "who handles `.com`?" and gets back 13 TLD (Top Level Domain) servers for `.com`, operated by Verisign.

The `.com` servers' response: "I don't know the IP for tractive.com, but I know which nameservers handle it — go ask these AWS nameservers."

**Hop 3 — Authoritative nameservers**

The resolver asks the `.com` TLD server "who handles `tractive.com`?" and gets directed to four AWS Route 53 nameservers across four different TLDs (`.com`, `.net`, `.org`, `.co.uk`) — redundancy. If one TLD has issues, the resolver can still reach the others.

**Hop 4 — The final answer**

The resolver asks Tractive's own nameserver "what's the IP for tractive.com?" and gets the real answer: four A records pointing to CloudFront edge IPs.

```
Browser cache → OS cache → Configured resolver (8.8.8.8, ISP)
  → Root server (.): "ask .com"
  → .com NS: "ask tractive.com's NS"
  → tractive.com NS: "3.168.86.112, TTL 60"
  → Cached at every level for TTL duration
```

## What does each DNS record type tell you?

**A record** — maps domain to IPv4 address. The most fundamental record. Multiple A records = load balancing and redundancy. TTL of 60 seconds (very short) means it's likely behind a CDN — CDNs use low TTLs to shift traffic between edge servers quickly. Compare to root servers' TTL of 86400 (24 hours) — those never change.

**AAAA record** — maps domain to IPv6 address. Many companies don't have one yet.

**CNAME record** — alias. "This name is actually an alias for that other name." `www.tractive.com` might CNAME to a CloudFront distribution. Important rule: you cannot put a CNAME on the root domain alongside other records like MX or TXT — that's why roots use A records directly.

**NS record** — declares which DNS servers are authoritative for this domain. If an attacker changes your NS records (registrar compromise), they control your entire domain. All traffic goes wherever they point it. This is DNS hijacking — catastrophic. Registrar accounts need strong 2FA.

**SOA record** — Start of Authority. Administrative metadata: primary nameserver, admin email (first `.` is actually `@`), serial number, refresh/retry/expire timers, negative caching TTL. Confirms whether DNS is self-hosted or managed (AWS, Cloudflare, etc.).

**MX record** — Mail Exchange. Where to deliver email. Priority numbers (lower = preferred) determine failover order. `aspmx.l.google.com` = Google Workspace. `*-outlook.com` = Microsoft 365. Reveals their email provider.

**TXT records** — the information goldmine. Carry arbitrary text used for verification and email security.

## What do TXT records reveal about an organization?

**SPF (Sender Policy Framework)** — "Who is allowed to send email as @tractive.com?"

```
"v=spf1 include:_netblocks.google.com include:amazonses.com include:mail.zendesk.com include:sparkpostmail.com -all"
```

| Entry | What it means |
|---|---|
| `include:_netblocks.google.com` | Google Workspace can send (employee email) |
| `include:amazonses.com` | Amazon SES can send (transactional/app notifications) |
| `include:mail.zendesk.com` | Zendesk can send (support ticket replies) |
| `include:sparkpostmail.com` | SparkPost can send (marketing/newsletters) |
| `-all` | Everyone else is REJECTED (strict setting) |

`-all` (hard fail) = reject unauthorized senders. `~all` (soft fail) = mark suspicious but maybe deliver. `-all` is the correct, secure choice.

Architecture insight: one SPF record reveals four email-sending services — a picture of their business operations from DNS alone.

**DKIM (DomainKeys Identified Mail)** — cryptographic email signing. When Google sends email on behalf of `@tractive.com`, it signs with a private key. The receiving server looks up the DKIM TXT record, gets the public key, and verifies the signature. Proves the email was actually sent by an authorized server AND wasn't modified in transit. SPF checks who sent it. DKIM checks it hasn't been tampered with.

**DMARC** — ties SPF and DKIM together. Tells receiving servers what to do when both fail.

```
"v=DMARC1; p=reject; rua=mailto:postmaster@tractive.com"
```

| Policy | Meaning |
|---|---|
| `p=none` | Monitor only — do nothing (weakest) |
| `p=quarantine` | Send to spam |
| `p=reject` | Reject entirely — never reaches inbox (strongest) |

SPF + DKIM + DMARC together: attacker tries to spoof `@tractive.com` → SPF fails (unauthorized server) → DKIM fails (can't sign with private key) → DMARC says reject → email never delivered.

**Verification records** — domain ownership proofs. `google-site-verification=...` (Google Search Console), `atlassian-domain-verification=...` (Jira/Confluence — reveals internal tooling). Each verification record leaks which services the organization uses.

## What does TTL mean and why does it matter?

TTL (Time To Live) in seconds — how long resolvers cache an answer before asking again.

| TTL | Duration | Typical use |
|---|---|---|
| 60 | 1 minute | CDNs (CloudFront, Cloudflare) — need fast traffic shifts |
| 3600 | 1 hour | Normal websites |
| 86400 | 24 hours | Root servers, records that rarely change |
| 172800 | 48 hours | TLD servers |

Low TTL = more DNS queries but faster failover. High TTL = fewer queries but slow to update. CDNs use low TTLs because if a data center has issues, they update DNS and within 60 seconds everyone is pointed elsewhere.

## What can you learn about an organization from DNS alone?

`dig` commands to run on any target:

```
dig <domain> NS        → Who manages their DNS? (self-hosted vs AWS/Cloudflare)
dig <domain> A         → What IPs? → whois → CDN? Cloud? Self-hosted?
dig <domain> MX        → Email provider? (Google/Microsoft/self-hosted)
dig <domain> TXT       → SPF, DKIM, DMARC, verification records
dig <domain> CNAME     → Alias to another service?
dig <domain> SOA       → Zone admin, refresh timers
dig _dmarc.<domain> TXT → Email spoofing protection policy
dig +trace <domain>    → Full resolution chain
```

What you're building: infrastructure map (cloud provider, CDN, email, support stack), email security posture (can someone spoof their domain?), attack surface size (what services are exposed?), organizational clues (internal tools).

## What are the DNS-related attack vectors?

- **DNS spoofing/poisoning** — false responses redirect to malicious IP. Mitigated by DNSSEC (cryptographic chain of trust — root zone vouches for `.com` zone's signing key, `.com` vouches for `tractive.com`).
- **DNS exfiltration** — data smuggled via subdomain lookups: `stolen-data.attacker.com`. Used in [[SQL Injection]] OOB and malware C2. DNS almost always gets through firewalls.
- **Subdomain takeover** — dangling CNAME to decommissioned service (Heroku, S3) → attacker claims it. The CNAME still points there but nobody owns the resource anymore.
- **DNS rebinding** — domain resolves to attacker IP first (passes origin checks), then re-resolves to internal IP (`127.0.0.1`, `169.254.169.254`). Bypasses [[SSRF]] blocklists that check DNS on first lookup.
- **DNS hijacking** — attacker compromises registrar account and changes NS records. Controls the entire domain. All traffic, email, everything goes to the attacker.
- **Zone transfer misconfiguration** — `dig axfr` against a misconfigured nameserver dumps every record in the zone. Full subdomain enumeration in one query.

## What should you check during an audit?

- Dangling CNAME records (subdomain takeover)
- Enumerate subdomains (subfinder, amass)
- Zone transfer misconfiguration (`dig axfr`)
- DNSSEC configured
- Internal DNS names leaking externally
- SPF/DKIM/DMARC presence and strictness
- Email security: `p=reject` or weaker?
- DoH/DoT availability (encrypted DNS)

## My Notes
