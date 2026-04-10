# TCP Connections
Tags: #how-it-works #tcp #networking #fundamentals #web-app-flows

## Core

IP delivers packets but they can arrive out of order, duplicated, or lost. TCP provides **reliable, ordered delivery** on top of IP. HTTP and TLS run over TCP.

## Three-Way Handshake

```
Client                              Server
  |--- SYN (seq=100) -----------→  |    "I want to connect"
  |←-- SYN-ACK (seq=300,ack=101)  |    "OK, acknowledged"
  |--- ACK (ack=301) -----------→  |    "Connected"
  [TCP established — data flows]
```

Termination: FIN → ACK → FIN → ACK (graceful) or RST (abrupt kill).

## Key Concepts

- **Ports** define services: 80=HTTP, 443=HTTPS, 22=SSH, 3306=MySQL, 5432=PostgreSQL, 8080=dev server
- **Source port** is ephemeral (49152-65535)
- **Wireshark filter:** `tcp.port == 443 && tcp.flags.syn == 1`

## Attack Surface

- **Port scanning** (nmap) — SYN to every port; SYN-ACK = open, RST = closed, silence = filtered
- **SYN flood** — millions of SYN packets without completing handshake, exhausting connection table
- **TCP RST injection** — forged RST packets kill active connections (censorship)
- **Sequence number prediction** — if predictable, attacker injects into stream (modern OSes randomize)

## Audit

- [ ] Port scan to identify exposed services
- [ ] Unnecessary open ports (DB ports, admin panels)
- [ ] Firewall rules match intended exposure

## My Notes
