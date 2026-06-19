# Generating Synthetic Data

Synthetic captures serve many purposes: reproducing a protocol exchange without
a live network, populating a test suite with edge cases that are hard to trigger
in production, generating labelled datasets for ML, or producing a pcap whose
contents you control from first byte to last.

packeteer offers three levels of control:

| Level | API | Best for |
|-------|-----|----------|
| **Session builders** | `TCPSession`, `UDPSession`, `SCTPSession` | Supplying real application payloads and having the protocol handled automatically |
| **Stream generators** | `generate_tcp_stream`, `generate_udp_stream`, `generate_sctp_stream` | Statistical traffic with random payloads, anomaly injection, or packet-level hooks |
| **Packet builder** | `PacketBuilder` | Hand-crafting individual packets or unusual layer combinations |

## Session builders

Session builders are the most direct route from "here is my application data"
to "here is a pcap file".  Queue payloads with `.send()` and `.recv()`, then
call `.build()`.

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

The pcap contains a three-way handshake, the two data exchanges with correct
sequence numbers and ACKs, and a four-way teardown — 11 packets for this
example.  Large payloads are segmented at MSS automatically; PSH is set on the
last segment of each exchange.

### UDP

```python
from packeteer.generate import UDPSession
from packeteer.pcap import write_pcap

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

## Multiple payloads and unidirectional streams

Chain as many `.send()` / `.recv()` calls as needed for a multi-turn exchange:

```python
stream = (TCPSession(client_ip="10.0.0.1", server_ip="10.0.0.2", server_port=9000)
    .send(b"HELLO")
    .recv(b"HELLO OK")
    .send(b"PING")
    .recv(b"PONG")
    .send(b"BYE")
    .recv(b"BYE OK")
    .build()
)
```

Call only `.send()` (or only `.recv()`) for a one-sided flow — the other side
emits pure ACKs.  This is useful for modelling a bulk upload or a server push:

```python
# Client uploads data; server only ACKs
stream = (TCPSession(client_ip="10.0.0.1", server_ip="10.0.0.2", server_port=9000)
    .send(b"first chunk")
    .send(b"second chunk")
    .send(b"third chunk")
    .build()
)
```

For many payloads of the same shape, use `.send_many(n, fn)` and
`.recv_many(n, fn)`.  The callable receives the index of each datagram, so
you can vary the content without pre-building the list:

```python
# Client uploads 100 records; server only ACKs
stream = (TCPSession(client_ip="10.0.0.1", server_ip="10.0.0.2", server_port=9000)
    .send_many(100, lambda i: f"record {i}\n".encode())
    .build()
)
```

## Generating many sessions at once

{func}`~packeteer.generate.session_mix.generate_session_mix` produces several
independent conversations and interleaves them into one capture.  Session `i`
uses `client_ip + i` and `server_ip + i`; the client and server IP ranges must
not overlap, so pick base addresses in separate subnets.  The protocol is
selected by the config type, and a `seed` makes the whole mix reproducible.

```python
from packeteer.generate import generate_session_mix, TCPStreamConfig
from packeteer.pcap import write_pcap

mix = generate_session_mix(
    sessions=20,
    client_ip="10.0.0.1",          # clients 10.0.0.1 .. 10.0.0.20
    server_ip="10.1.0.1",          # servers 10.1.0.1 .. 10.1.0.20
    num_data_packets=5,
    session_stagger=2.0,           # start times spread over 2 seconds
    config=TCPStreamConfig(seed=42),
)
write_pcap(mix.to_pcap_tuples(), path="busy.pcap")
```

To combine streams you have generated yourself, use
{func}`~packeteer.generate.session_mix.merge_streams`, which concatenates and
timestamp-sorts their packets.

## Simulating an HTTP REST client

{func}`~packeteer.generate.payloads.http.generate_http_stream` fabricates random
HTTP/1.1 request/response traffic — varied methods, REST paths, query strings,
headers, and JSON bodies — and renders it onto TCP connection(s).  `requests`
sets the number of transactions and `requests_per_connection` controls
connection reuse (`None` = one keep-alive connection; `1` = a connection per
request).  The result round-trips through `packeteer parse`.

```python
from packeteer.generate import generate_http_stream
from packeteer.pcap import write_pcap

mix = generate_http_stream(
    client_ip="10.0.0.1", server_ip="10.1.0.1",
    requests=50, requests_per_connection=1,   # 50 short connections
    seed=42,
)
write_pcap(mix.to_pcap_tuples(), path="rest.pcap")
```

It composes with `sessions` (distinct client/server IP pairs, each running the
full workload), and is exposed on the CLI as `packeteer stream --payload http`.

## Simulating a fictive VPN

{func}`~packeteer.generate.payloads.vpn.generate_vpn_stream` generates a small
binary VPN protocol over two UDP ports: a key-exchange channel (a three-message
handshake per epoch) and a CTR-mode data channel whose packets carry a counter.
`epochs` key negotiations each precede `packets_per_epoch` bidirectional data
packets (a rekey every `packets_per_epoch` packets), with per-direction counters
that reset each epoch.

```python
from packeteer.generate import generate_vpn_stream
from packeteer.pcap import write_pcap

mix = generate_vpn_stream(
    client_ip="10.0.0.1", server_ip="10.1.0.1",
    epochs=4, packets_per_epoch=20, seed=42,
)
write_pcap(mix.to_pcap_tuples(), path="vpn.pcap")
```

Exposed on the CLI as `packeteer stream --payload vpn`.

## Writing to pcap or pcapng

All session builders return a stream object with a `.to_pcap_tuples()` method:

```python
from packeteer.pcap import write_pcap, write_pcapng

write_pcap(stream.to_pcap_tuples(), path="out.pcap")
write_pcapng(stream.to_pcap_tuples(), path="out.pcapng")
```

## Inspecting and editing the packet list

`stream.packets` is a plain list, so you can inspect or modify it before
writing:

```python
for pkt in stream.packets:
    print(f"{pkt.label:12s}  {pkt.direction}  {len(pkt.raw)} bytes")

# Drop the SYN-ACK to simulate a lost handshake packet
stream.packets = [p for p in stream.packets if p.label != "SYN-ACK"]
```

`TCPStreamPacket` exposes `seq`, `ack`, `flags`, and `label`;
`SCTPStreamPacket` exposes `tsn` — enough to target specific packets precisely.

## Encapsulation

All session builders accept an `encap` keyword that wraps every packet in
one or more network encapsulation layers:

```python
from packeteer.generate import TCPSession, VLANEncap, GREEncap

# 802.1Q VLAN tag
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

Encapsulation types fall into two categories:

- **Tag-based** — `VLANEncap`, `QinQEncap`, `MPLSEncap`, `PPPoEEncap`.  These
  insert layer-2 tags; the stream's own transport (TCP/UDP/SCTP) stays on the
  wire as the outer transport.
- **Tunnel** — `GREEncap`, `EtherIPEncap`, `IPIPEncap`, `VXLANEncap`,
  `GeneveEncap`.  These add their own outer headers and carry the whole stream
  as *inner* traffic.  Any stream generator accepts any tunnel, so
  `generate_tcp_stream(..., encap=VXLANEncap(...))` tunnels the TCP conversation
  *inside* VXLAN — the TCP is the inner protocol.  `VXLANEncap` and `GeneveEncap`
  always use an outer UDP datagram (port 4789 / 6081) regardless of the inner
  stream protocol; they never run over TCP or SCTP themselves.

See the Reference section for stacking rules and full parameter lists.

For pseudowire traffic (MPLS + RFC 4385 control word + inner Ethernet/IP)
and other layer combinations not covered by the `encap` keyword, use
{class}`~packeteer.generate.builder.PacketBuilder` directly — see
[Packet builder](#packet-builder) below.

## Standalone protocol helpers

When you are assembling a capture manually and only need the bytes for a
handshake, use the standalone helpers:

```python
from packeteer.generate import tcp_handshake, tcp_teardown, sctp_handshake

# Returns [SYN, SYN-ACK, ACK]
hs = tcp_handshake(client_ip="10.0.0.1", server_ip="10.0.0.2")

# Returns [INIT, INIT-ACK, COOKIE-ECHO, COOKIE-ACK]
sctp_hs = sctp_handshake(client_ip="10.0.0.1", server_ip="10.0.0.2")
```

Each function returns a list of raw `bytes` objects with correct checksums.

## Packet builder

For packets that don't fit the session-builder model — unusual layer
combinations, crafted headers, one-off anomalies — use
{class}`~packeteer.generate.builder.PacketBuilder` directly.  Layers chain
fluently and the correct EtherType / protocol fields are filled in
automatically:

```python
from packeteer.generate import PacketBuilder, TCP_SYN

pkt = (PacketBuilder()
    .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .tcp(dst_port=443, flags=TCP_SYN)
    .payload(size=64)
    .build()
)
# pkt is bytes — pass to write_pcap, send via socket, inspect, etc.
```

IPv6 is auto-detected from the source address format:

```python
pkt = (PacketBuilder()
    .ip(src="2001:db8::1", dst="2001:db8::2", ttl=128)
    .tcp(dst_port=443)
    .build()
)
```

### Binary payloads

Pass `data=` to `.payload()` to embed an exact byte sequence.  Use
`struct.pack` to construct structured binary payloads with specific field
widths and byte order:

```python
import struct
from packeteer.generate import PacketBuilder
from packeteer.pcap import write_pcap

# Hypothetical proprietary protocol over UDP:
#   2 bytes  message type  (big-endian uint16)
#   2 bytes  flags         (big-endian uint16)
#   4 bytes  sequence num  (big-endian uint32)
#   n bytes  body
MSG_TYPE_DATA = 0x0001

body = b"sensor-reading:42.7"
header = struct.pack(">HHI", MSG_TYPE_DATA, 0x0000, 1)
message = header + body

pkt = (PacketBuilder()
    .ethernet(src_mac="00:0a:00:00:00:01", dst_mac="00:0a:00:00:00:02")
    .ip(src="192.168.1.10", dst="192.168.1.20")
    .udp(src_port=5000, dst_port=5001)
    .payload(data=message)
    .build()
)
write_pcap([(pkt, 0, 0)], path="sensor.pcap")
```

The assembled packet will have the correct UDP length and checksum computed
around the binary body.  Wireshark will show the raw bytes of `message`
inside the UDP datagram exactly as packed.

### Pseudowire and other advanced encapsulations

`PacketBuilder` supports layer combinations that have no `encap=` equivalent,
such as MPLS pseudowire (RFC 4385):

```python
from packeteer.generate import PacketBuilder

pkt = (PacketBuilder()
    .ethernet()
    .mpls(label=100)
    .pseudowire()
    .ethernet(src_mac="cc:dd:ee:00:00:01", dst_mac="cc:dd:ee:00:00:02")
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .tcp(dst_port=80)
    .build()
)
```

## When to use the stream generators

The session builders cover most synthetic-data use cases.  Reach for
`generate_tcp_stream` and friends when you need features they don't expose:

- **Statistical random payloads** — `payload_distribution="bimodal"` or
  `"fixed"` draws sizes from a model rather than using exact bytes
- **Anomaly injection** — packet loss, spurious retransmissions, payload
  corruption, RST mid-stream, or stray/hijack packets
- **Timestamp jitter** — `gap_jitter` models capture delay and produces
  genuine out-of-order timestamps
- **IP fragmentation** — `mtu` splits packets at a simulated middlebox
- **Reproducible captures** — pass `seed` in the config object (`TCPStreamConfig`,
  `UDPStreamConfig`, or `SCTPStreamConfig`) to pin the RNG; two calls with the
  same seed and parameters produce byte-identical output, useful for regression
  tests and diff-based workflows
- **Packet hooks** — `TCPStreamConfig.packet_hooks` applies arbitrary
  transformations or drops during generation

See {doc}`../api/stream-generators` for the full parameter reference.

## Next steps

- {doc}`pcap` — reading and writing pcap files directly
- {doc}`../api/stream-generators` — complete parameter tables for `TCPSession`,
  `UDPSession`, `SCTPSession`, and the stream generators
