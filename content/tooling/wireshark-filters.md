# Wireshark
Tags: #tooling #wireshark #networking #packet-capture

## How It Works

Wireshark is a **packet capture tool** operating at the **network interface level**. It tells the OS network stack: "give me a copy of every packet that passes through this interface."

```
Normal traffic:
  Application → OS network stack → NIC → Wire

Wireshark hooks in:
  Application → OS network stack → NIC → Wire
                      ↓
                Wireshark gets a copy
                (via libpcap on Linux, npcap on Windows)
```

It uses `libpcap` (Linux) / `npcap` (Windows) to create a raw socket and can put the NIC into **promiscuous mode** — accepting all packets, not just ones addressed to your MAC. On a switched network you normally only see your own traffic. On WiFi or with a mirror port, you can see others' traffic.

## What It Can See

```
✓ Ethernet frames — source/destination MAC addresses
✓ ARP requests/responses
✓ IP headers — source/destination IP, TTL, protocol
✓ TCP headers — ports, seq/ack numbers, flags (SYN/ACK/FIN/RST), window size
✓ UDP headers — ports, length
✓ DNS queries and responses (plaintext over UDP 53)
✓ TLS handshake — ClientHello (with SNI hostname), ServerHello, certificate chain
✓ Unencrypted HTTP — full request and response
✓ Any plaintext protocol — FTP, SMTP, Telnet, unencrypted MySQL
```

## What It Cannot See

```
✗ HTTPS content — after TLS handshake, all data is "Application Data" (encrypted blob)
  WHY: Wireshark captures packets on the wire. TLS encrypted the data before
  it reached the wire. Wireshark sees ciphertext, not the HTTP inside.

✗ Traffic on other network segments — switched networks only deliver packets
  addressed to your MAC. Need mirror port, ARP spoofing, or WiFi monitor mode
  to see others' traffic.

✗ Application-layer context — sees packets not "requests". Can reassemble TCP
  streams but doesn't understand application logic.
```

**Exception — TLS decryption:** Set `SSLKEYLOGFILE` environment variable and your browser dumps TLS session keys to a file. Load in Wireshark (Preferences → Protocols → TLS) to decrypt HTTPS.

```bash
export SSLKEYLOGFILE=~/tlskeys.log
firefox &
# Wireshark: Edit → Preferences → Protocols → TLS → Pre-Master-Secret log filename → ~/tlskeys.log
```

**Loopback capture:** localhost traffic may not hit the NIC. Select the `lo` interface (Linux) or `Npcap Loopback` (Windows).

## Useful Filters

```
# DNS
dns
dns.qry.name contains "example"

# TCP handshake
tcp.flags.syn == 1
tcp.port == 443

# TLS handshake
tls.handshake.type == 1                    # ClientHello
tls.handshake.type == 2                    # ServerHello
tls.handshake.type == 11                   # Certificate

# HTTP (unencrypted only, or with SSLKEYLOGFILE)
http.request.method == "GET"
http.request.method == "POST"
http.response.code == 500
http.host contains "example"

# Filter by IP
ip.addr == 192.168.1.100
ip.src == 192.168.1.100
ip.dst == 93.184.216.34

# Filter by port
tcp.port == 80
tcp.port == 3306                           # MySQL

# Exclude noise
!(arp || dns || icmp)
```

## My Notes
