# Creating Synthetic Data

Synthetic captures serve many purposes: reproducing a protocol exchange without
a live network, populating a test suite with edge cases that are hard to trigger
in production, generating labelled datasets for ML, or producing a pcap whose
contents you control from first byte to last.

packeteer offers three levels of control:

| Level | API | Best for |
|-------|-----|----------|
| **Session builders** | `TCPSession`, `UDPSession`, `SCTPSession` | Any exchange where you want to supply payloads and have the protocol handled for you |
| **Stream generators** | `generate_tcp_stream`, `generate_udp_stream`, `generate_sctp_stream` | Statistical traffic with realistic random payloads, anomaly injection, or packet-level hooks |
| **Packet builder** | `PacketBuilder` | Hand-crafting individual packets or unusual layer combinations |

## Session builders — start here

Session builders are the most direct route from "here is my application data"
to "here is a pcap file".  You queue payloads with `.send()` and `.recv()`,
then call `.build()`.

### TCP

```python
from packeteer.generate import TCPSession
from packeteer.pcap import write_pcap

stream = (TCPSession(client_ip="10.0.0.1", server_ip="10.0.0.2", server_port=80)
    .send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    .recv(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!")
    .build()
)
write_pcap(stream.to_pcap_tuples(), path="http.pcap")
```

The resulting pcap contains the three-way handshake, the two data exchanges
with correct sequence numbers and ACKs, and the four-way teardown — 11 packets
in total for this example.  Large payloads are split into MSS-sized segments
automatically; PSH is set on the last segment of each exchange.

### UDP

```python
from packeteer.generate import UDPSession
from packeteer.pcap import write_pcap

# DNS query/response
stream = (UDPSession(client_ip="10.0.0.1", server_ip="8.8.8.8", server_port=53)
    .send(dns_query_bytes)
    .recv(dns_response_bytes)
    .build()
)
write_pcap(stream.to_pcap_tuples(), path="dns.pcap")
```

No handshake or teardown is generated — datagrams are emitted in queue order.

### SCTP

```python
from packeteer.generate import SCTPSession
from packeteer.pcap import write_pcap

stream = (SCTPSession(
        client_ip="10.0.0.1", server_ip="10.0.0.2", server_port=36412)
    .send(s1ap_setup_request)
    .recv(s1ap_setup_response)
    .build()
)
write_pcap(stream.to_pcap_tuples(), path="s1ap.pcap")
```

`SCTPSession` generates the four-way SCTP handshake, DATA+SACK exchanges, and
graceful shutdown with correct TSNs and CRC-32c checksums throughout.

## Unidirectional streams

Call only `.send()` (or only `.recv()`) for a one-sided flow — the other side
emits pure ACKs:

```python
# Client uploads N records; server only ACKs
stream = (TCPSession(client_ip="10.0.0.1", server_ip="10.0.0.2", server_port=9000)
    .send_many(100, lambda i: f"record {i}\n".encode())
    .build()
)
```

`.send_many(n, fn)` and `.recv_many(n, fn)` call `fn(index)` for each
datagram, so you can vary the content across packets without pre-building the
list yourself.

## Writing to pcap or pcapng

All three session builders return the same stream types as the low-level
generators (`TCPStream`, `UDPStream`, `SCTPStream`), so the same write calls
work everywhere:

```python
from packeteer.pcap import write_pcap, write_pcapng

write_pcap(stream.to_pcap_tuples(), path="out.pcap")
write_pcapng(stream.to_pcap_tuples(), path="out.pcapng")
```

## Manipulating packets before writing

Because `stream.packets` is a plain list, you can inspect or reorder it before
writing:

```python
# Inspect what was generated
for pkt in stream.packets:
    print(f"{pkt.label:12s}  {pkt.direction}  {len(pkt.raw)} bytes")

# Drop the SYN-ACK to simulate a lost handshake packet
stream.packets = [p for p in stream.packets if p.label != "SYN-ACK"]
```

`TCPStreamPacket` also exposes `seq`, `ack`, and `flags`, and
`SCTPStreamPacket` exposes `tsn`, so you can target specific packets precisely.

## Standalone protocol helpers

When you are assembling a capture manually and just need the bytes for a
handshake, use the standalone helpers instead of building a full session:

```python
from packeteer.generate import tcp_handshake, tcp_teardown, sctp_handshake

# [SYN, SYN-ACK, ACK]
hs = tcp_handshake(client_ip="10.0.0.1", server_ip="10.0.0.2")

# [INIT, INIT-ACK, COOKIE-ECHO, COOKIE-ACK]
sctp_hs = sctp_handshake(client_ip="10.0.0.1", server_ip="10.0.0.2")
```

Each function returns a list of raw `bytes` objects with correct checksums.

## When to use the low-level generators

The session builders cover most synthetic-data use cases.  Reach for
`generate_tcp_stream` and friends when you need features they don't expose:

- **Realistic random payloads** with `payload_distribution="bimodal"` or
  `"fixed"` — sizes drawn from a statistical model rather than exact bytes
- **Anomaly injection** — packet loss, spurious retransmissions, payload
  corruption, RST, or stray/hijack packets
- **Timestamp jitter** — `gap_jitter` models capture delay and produces
  genuine out-of-order timestamps
- **IP fragmentation** — `mtu` splits packets at a simulated middlebox
- **Packet hooks** — `TCPStreamConfig.packet_hooks` applies arbitrary
  transformations or drops during generation

See {doc}`../stream/python-api` for the full parameter reference.

## Encapsulation

All session builders and stream generators accept an `encap` keyword that
wraps every packet in one or more network encapsulation layers (VLAN, QinQ,
MPLS, PPPoE, GRE, EtherIP, IP-in-IP):

```python
from packeteer.generate import TCPSession, VLANEncap, GREEncap

# VLAN-tagged exchange
stream = (TCPSession(
        client_ip="10.0.0.1", server_ip="10.0.0.2",
        encap=VLANEncap(vid=100))
    .send(b"data")
    .build()
)

# GRE tunnel — stream IPs become inner; outer IPs wrap them
stream = (TCPSession(
        client_ip="10.0.0.1", server_ip="10.0.0.2",
        encap=GREEncap(src_ip="203.0.113.1", dst_ip="203.0.113.2"))
    .send(b"tunnelled data")
    .build()
)
```

See {doc}`../stream/python-api` for all available encapsulation types and
stacking rules.
