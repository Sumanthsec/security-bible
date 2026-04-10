# Debug Mode Information Disclosure
Tags: #vulnerability #information-disclosure #debug #stack-traces #conditional-gating #day4

## Core

Every framework has a conditional that switches between "developer view" (stack traces, SQL errors, env vars) and "user view" (opaque error). The bug is that the switch is flippable by an attacker. It's a vulnerability class, not a single bug — the shape is always `if (someCondition) { showDiagnostics(); }` where the condition is attacker-influenced.

## Mindset

> "Every conditional that switches between 'helpful for the developer' and 'safe for the user' is a vulnerability waiting to happen. Find the conditional, find the way to flip it, get the developer view."

## The Gate Conditions

| Condition | How attacker flips it |
|---|---|
| `request.getHeader("X-Debug") != null` | Send `X-Debug: 1` |
| `env.equals("dev")` | Look for SSRF/file write that influences env, or env-leaking endpoint |
| `user.getEmail().endsWith("@company.com")` | Register `attacker@company.com` (or DNS subdomain trick) |
| `request.getRemoteAddr().equals("127.0.0.1")` | Spoof via [[Client-Controlled IP Headers]] |
| `cookie.get("debug") == "1"` | Set the cookie |
| `Spring.profiles.active.contains("dev")` | Config endpoint, env-var injection, or left-on in prod |
| `DEBUG = True` constant left in prod | The most embarrassing variant — flag never reset |

## What a Stack Trace Reveals

- **Framework + version** → known CVEs
- **Internal hostnames** (`db.internal:5432`) → network mapping target
- **DB credentials** → direct lateral movement
- **File paths** → deployment layout for LFI/path traversal
- **Class names** → controller structure inference
- **Sometimes secrets in plain text** → JWT secret, API keys, S3 credentials

## Framework Debug Endpoints

Spring Boot Actuator: `/actuator/env`, `/actuator/heapdump`, `/actuator/configprops`. Symfony: `/_profiler`. Django: `/__debug__/`. Go: `/debug/pprof/`. PHP: `?XDEBUG_SESSION_START=1`.

## Chains

- [[Client-Controlled IP Headers]] — the most common way to flip a localhost-gated debug switch
- [[SQL Injection]] — debug-gated error paths upgrade blind SQLi to error-based
- [[SSRF]] — fetch internal debug endpoints
- [[Insecure Deserialization]] — Actuator's `/jolokia` and `/heapdump` leak entire JVM state
- [[Authentication Bypass]] — debug endpoints often skip auth entirely
- [[Hardcoded Secrets]] — leaked stack traces and `/actuator/env` frequently contain JWT secrets and DB credentials

## Key Watchpoints

- "Just an info disclosure" is almost never just that — it's the first link in every chain
- The fix is opaque error IDs (`Error 500: ref 8a4f-b1c2`), not better filtering
- Spring Actuator + `management.endpoints.web.exposure.include=*` = one config flag from full exposure
- The attacker's question: "If I were debugging this, what would I want to see?" — that finds these bugs
- Always check for a debug gate before settling for the slow version of any technique

## My Notes
