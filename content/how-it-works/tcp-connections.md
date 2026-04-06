# TCP Connections
Tags: #how-it-works #tcp #networking #fundamentals #web-app-flows

## The Problem This Solves

IP can deliver packets between machines, but packets can arrive out of order, get duplicated, or get lost entirely. TCP (Transmission Control Protocol) provides **reliable, ordered delivery** on top of IP. HTTP and TLS run over TCP.

## How a Developer Implements This

Developers don't manage TCP directly — the OS network stack handles it. But understanding TCP is essential for interpreting Wireshark captures, understanding network-level attacks, and knowing what happens before HTTP.

## What the Code Actually Looks Like

### The Three-Way Handshake

Every TCP connection starts with this:

```
Your Machine                        Server (93.184.216.34:443)
    |                                    |
    |--- SYN (seq=100) ---------------→ |    "I want to connect"
    |                                    |
    |←-- SYN-ACK (seq=300, ack=101) --- |    "OK, I acknowledge"
    |                                    |
    |--- ACK (ack=301) ---------------→ |    "Got it, connected"
    |                                    |
    [TCP connection established — data can flow]
```

### What It Looks Like in Wireshark

Filter: `tcp.port == 443 && tcp.flags.syn == 1`

Each packet shows:
- Source/destination IP
- Source port (random high port, e.g., 54321) / destination port (443 for HTTPS, 80 for HTTP)
- Sequence and acknowledgment numbers (track data ordering)
- TCP flags: SYN, ACK, FIN, RST, PSH

### Connection Termination

```
    |--- FIN -------------------------→ |    "I'm done sending"
    |←-- ACK ------------------------- |    "Acknowledged"
    |←-- FIN ------------------------- |    "I'm done too"
    |--- ACK -------------------------→ |    "Acknowledged, connection closed"
```

Or abruptly: RST (reset) — immediately kills the connection without graceful shutdown.

## Configuration and Defaults That Matter

- **Ports** define services: 80=HTTP, 443=HTTPS, 22=SSH, 3306=MySQL, 5432=PostgreSQL, 8080=common dev server
- **Source port** is random (ephemeral port, typically 49152-65535)
- **TCP keepalive** — periodic probes to detect dead connections
- **TCP window size** — flow control, how much data can be in-flight before requiring acknowledgment

## Where Security Breaks

- **Port scanning** (nmap) — sending SYN packets to every port to see which respond with SYN-ACK (port open) vs RST (port closed) or silence (filtered by firewall)
- **SYN flood** — DDoS attack that sends millions of SYN packets without completing the handshake, exhausting the server's connection table
- **TCP RST injection** — attacker sends forged RST packets to kill active connections (used for censorship)
- **Sequence number prediction** — if sequence numbers are predictable, attacker can inject data into a TCP stream (modern OSes randomize these)

## Auditing Checklist

- [ ] Port scan target to identify exposed services
- [ ] Check for unnecessary open ports (database ports, admin panels exposed to internet)
- [ ] Verify firewall rules match intended exposure

## My Notes
