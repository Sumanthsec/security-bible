# Cloud Security
Tags: #cloud #section-index

The cloud isn't "someone else's computer" — it's someone else's computer *plus an API that provisions, connects, and grants access to everything*. That API, and the identity model behind it, is where cloud security lives or dies. This section collects the durable mental models; individual services come and go, but these patterns don't.

## Why is cloud security a different discipline?

On-prem, the perimeter was the network — a firewall stood between the internet and your machines, and getting inside the network largely meant getting access.

In the cloud, **identity is the perimeter**. There's no network edge to hide behind; every resource has a public control-plane API, and what you can reach is decided by *who the request is authenticated as* and *what policy allows*. A leaked key or an over-broad role is the equivalent of walking through the front door — the network never gets a say.

The second shift: **everything is an API call**. Creating a server, opening a port, reading a storage bucket, minting a new credential — all the same kind of authenticated request. That means misconfiguration, not memory corruption, is the dominant vulnerability class. The bugs are in *policy*, not code.

## What is the Shared Responsibility Model, and why does it trip people up?

The provider secures the cloud (the hardware, the hypervisor, the managed-service internals). **You secure what you put in it** — your data, your identity/access config, your network rules, your OS patches (for anything you run yourself).

The trap is assuming "managed" means "secured for me." A managed database is patched by the provider, but if *you* leave its access policy open to the world, that's your side of the line. Most real cloud breaches are customer-side misconfigurations, not provider failures.

## What are the recurring vulnerability classes to look for?

- **Identity & access misconfiguration** — over-privileged roles, wildcard permissions, unused-but-live credentials, and trust relationships that let one identity assume another. The core question is always *what can this identity actually do, transitively?*
- **Publicly exposed storage & services** — buckets, databases, and dashboards reachable from the internet, often unauthenticated, usually by accident.
- **Metadata service abuse** — an app that can be coaxed into making outbound requests can often reach the instance metadata endpoint and pull the machine's own credentials. This is why [[../vulnerabilities/ssrf|SSRF]] is far more dangerous in the cloud than on-prem.
- **Privilege escalation via the control plane** — using one granted permission to grant yourself more (e.g. a permission to modify policy, or to pass a more powerful role to a new resource).
- **Secrets sprawl** — keys in source, in environment variables, in build logs, in container images. See the `pw.md` lesson: credentials in a repo are a breach waiting on a `git push`.

## What's the mindset when auditing a cloud environment?

Enumerate identity first, resources second. Ask: *which identities exist, what can each one do, and which of those permissions could be chained into more access or into reaching data?* The interesting findings are rarely a single "critical" setting — they're a **path**: a modest permission plus a trust relationship plus an exposed resource that together add up to impact.

## Section contents

_Starter section — notes to be added:_

- Identity & access model (roles, policies, trust, assume-role chains)
- The metadata service & SSRF-to-credentials pipeline
- Storage exposure patterns
- Control-plane privilege escalation paths
- Logging & detection (what the audit trail does and doesn't capture)

## My Notes
