# Python API

## TCP stream — `generate_tcp_stream`

`generate_tcp_stream` produces a complete TCP connection with correct sequence
and acknowledgement numbers, 32-bit wrap-around, and per-packet timestamps.

```python
from packeteer.generate import generate_tcp_stream
from packeteer.pcap import write_pcap

stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    server_port=80,
    num_data_packets=20,
)
write_pcap(stream.to_pcap_tuples(), path="out.pcap")
```

### Packet sequence

The baseline stream contains `2 * num_data_packets + 7` packets:

| # | Sender | Flags | Label |
|---|--------|-------|-------|
| 0 | client | SYN | `"SYN"` |
| 1 | server | SYN+ACK | `"SYN-ACK"` |
| 2 | client | ACK | `"ACK"` |
| 3, 5, … 2N+1 | client | ACK (PSH with probability `config.psh_probability`) | `"DATA[0]"` … `"DATA[N-1]"` |
| 4, 6, … 2N+2 | server | ACK | `"ACK[0]"` … `"ACK[N-1]"` |
| 2N+3 | client | FIN+ACK | `"FIN-ACK"` |
| 2N+4 | server | ACK | `"ACK"` |
| 2N+5 | server | FIN+ACK | `"FIN-ACK"` |
| 2N+6 | client | ACK | `"ACK"` |

Anomaly parameters (RST, corruption, retransmissions, packet loss) add or
remove packets.  Initial sequence numbers are chosen at random, matching real
TCP behaviour.

### Parameters

#### Core parameters (passed directly to `generate_tcp_stream`)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `client_ip` | *(required)* | Client IP address (IPv4 or IPv6) |
| `server_ip` | *(required)* | Server IP address (same family) |
| `client_port` | `54321` | Client source port |
| `server_port` | `80` | Server destination port |
| `client_mac` | `"00:00:00:00:00:01"` | Client MAC address |
| `server_mac` | `"00:00:00:00:00:02"` | Server MAC address |
| `num_data_packets` | `10` | Number of client DATA segments |
| `min_payload` | `40` | Minimum payload size in bytes |
| `max_payload` | `1460` | Maximum payload size in bytes |
| `payload_distribution` | `"uniform"` | `"uniform"`, `"bimodal"`, or `"fixed"` |
| `client_isn` | `None` | Client initial sequence number (random if `None`) |
| `server_isn` | `None` | Server initial sequence number (random if `None`) |
| `include_ethernet` | `True` | Include Ethernet headers |
| `ip_ttl` | `64` | IP TTL / hop limit |
| `inter_packet_gap` | `0.001` | Base time between packets in seconds |
| `mtu` | `None` | Fragment packets whose IP-layer size exceeds this value |
| `encap` | `None` | Encapsulation layer(s) — see [Encapsulation](#encapsulation) |
| `config` | `None` | `TCPStreamConfig` for timing and anomaly settings — see below |

#### `TCPStreamConfig` — timing, anomaly injection, and hooks

Optional parameters are grouped into a `TCPStreamConfig` dataclass.  Pass an
instance as the `config` keyword argument; any field left unset uses its default.

```python
from packeteer.generate import TCPStreamConfig

stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    num_data_packets=20,
    config=TCPStreamConfig(
        window=32768,
        retransmission_probability=0.05,
    ),
)
```

| Field | Default | Description |
|-------|---------|-------------|
| `payload_sizes` | `None` | Explicit list of per-packet sizes, overrides distribution |
| `psh_probability` | `0.5` | Probability PSH is set on each data segment |
| `window` | `65535` | TCP receive window size |
| `client_options` | `None` | `TCPOptions` to include on SYN |
| `server_options` | `None` | `TCPOptions` to include on SYN-ACK |
| `base_time` | `None` | Unix timestamp for the first packet (current time if `None`) |
| `gap_jitter` | `0.0` | Max extra capture delay per packet; output re-sorted by timestamp |
| `packet_loss_probability` | `0.0` | Probability any packet is dropped from the capture |
| `retransmission_probability` | `0.0` | Probability each data segment is spuriously retransmitted |
| `retransmission_timeout` | `0.2` | Seconds after original send that the retransmit fires |
| `payload_corruption_probability` | `0.0` | Probability a data segment payload is corrupted in transit |
| `server_rst_probability` | `0.0` | Probability the server terminates mid-stream with a RST |
| `rst_propagation_delay` | `0.0` | Seconds for the RST to reach the client |
| `stray_packet_count` | `0` | Number of forged TCP hijack packets to inject |
| `stray_timing_window` | `None` | If set, constrain each stray timestamp to within N packets of its target |
| `packet_hooks` | `None` | List of callables applied to each packet — see [Hooks](#hooks) |
| `payload_fn` | `None` | Callable `(index, direction) -> bytes` supplying each data-packet payload; overrides all size parameters |

### Timestamp jitter

Set `gap_jitter` in `TCPStreamConfig` to model capture delay: each packet gets
an extra delay drawn from `uniform(0, gap_jitter)`.  Because delays are
independent, packets can overtake each other, producing genuine out-of-order
timestamps in the sorted stream.

```python
from packeteer.generate import TCPStreamConfig

# 1 ms base gap with up to 0.8 ms extra jitter
stream = generate_tcp_stream(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    num_data_packets=20, inter_packet_gap=0.001,
    config=TCPStreamConfig(gap_jitter=0.0008),
)
```

### TCP anomalies

**Spurious retransmissions** — `retransmission_probability`:

Each data segment independently rolls; if it fires, a copy is added with the
same seq/flags/payload but timestamped at `original_time + retransmission_timeout`.
Labelled `RETRANS[i]`.

**Payload corruption** — `payload_corruption_probability`:

The last byte of the payload is XOR-flipped, invalidating the TCP checksum.
The receiver silently drops it; the client retransmits after `retransmission_timeout`.
Three labels appear per event: `CORRUPT[i]`, `RETRANS[i]`, and `ACK[i]`.

**Server RST** — `server_rst_probability`:

A random split point *k* is chosen.  Packets 0…k are exchanged normally.  The
server then sends a RST; the client keeps sending during the `rst_propagation_delay`
window.  Labelled `RST`.

**Packet loss** — `packet_loss_probability`:

Each packet is independently dropped from the capture; seq/ack numbers remain
correct as if the packet was transmitted.

**Stray packets** — `stray_packet_count`:

Forged client-sourced packets with seq/ack stolen from real data segments and
an all-`x` payload.  Simulate an off-path attacker injecting into the stream.
Labelled `STRAY[n]`.  Use `stray_timing_window` to constrain their timestamps.

### TCP options

Pass {class}`~packeteer.generate.tcp.TCPOptions` instances to include options on
the SYN and SYN-ACK:

```python
from packeteer.generate import TCPOptions
from packeteer.generate import TCPStreamConfig

stream = generate_tcp_stream(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    num_data_packets=10,
    config=TCPStreamConfig(
        client_options=TCPOptions(mss=1460, window_scale=7, sack_permitted=True),
        server_options=TCPOptions(mss=1460, window_scale=6, sack_permitted=True),
    ),
)
```

Options are encoded only on SYN and SYN-ACK; data and teardown packets carry
no options.

---

## UDP stream — `generate_udp_stream`

`generate_udp_stream` produces a sequence of client→server UDP datagrams —
suitable for DNS queries, TFTP, syslog, or any unidirectional datagram flow.
There is no handshake or teardown; all `num_data_packets` packets carry
direction `"c2s"` and are labelled `DATA[0]`, `DATA[1]`, …

```python
from packeteer.generate import generate_udp_stream
from packeteer.pcap import write_pcap

stream = generate_udp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    server_port=53,
    num_data_packets=5,
)
write_pcap(stream.to_pcap_tuples(), path="dns_queries.pcap")
```

UDP streams accept the same core parameters as TCP (`client_ip`, `server_ip`,
`num_data_packets`, `inter_packet_gap`, `gap_jitter`, `min_payload`,
`max_payload`, `payload_distribution`, `payload_sizes`, `include_ethernet`,
`ip_ttl`, `mtu`, `encap`).  TCP-specific parameters (retransmissions, RST, PSH,
stray packets, etc.) are not available.

---

## SCTP stream — `generate_sctp_stream`

`generate_sctp_stream` produces a complete SCTP association — four-way
handshake, DATA+SACK exchange, and graceful shutdown — with verification tags,
TSNs, CRC-32c checksums, and State Cookie TLVs all computed correctly per
RFC 9260.

```python
from packeteer.generate import generate_sctp_stream
from packeteer.pcap import write_pcap

stream = generate_sctp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    server_port=9999,
    num_data_packets=10,
    payload_distribution="bimodal",
)
write_pcap(stream.to_pcap_tuples(), path="sctp_flow.pcap")
```

### Packet sequence

The stream contains `2 * num_data_packets + 7` packets:

| Phase | Direction | Chunk | Label |
|-------|-----------|-------|-------|
| Handshake | c2s | INIT | `"INIT"` |
| Handshake | s2c | INIT ACK | `"INIT-ACK"` |
| Handshake | c2s | COOKIE ECHO | `"COOKIE-ECHO"` |
| Handshake | s2c | COOKIE ACK | `"COOKIE-ACK"` |
| Data (×N) | c2s | DATA | `"DATA[0]"` … `"DATA[N-1]"` |
| Data (×N) | s2c | SACK | `"SACK[0]"` … `"SACK[N-1]"` |
| Shutdown | c2s | SHUTDOWN | `"SHUTDOWN"` |
| Shutdown | s2c | SHUTDOWN ACK | `"SHUTDOWN-ACK"` |
| Shutdown | c2s | SHUTDOWN COMPLETE | `"SHUTDOWN-COMPLETE"` |

Verification tag rules (RFC 9260 §5.1): INIT is sent with vtag=0; all
subsequent c2s packets carry the server's Initiate Tag; all s2c packets carry
the client's Initiate Tag.

SCTP streams accept the same core parameters as TCP and UDP.  TCP-specific
anomaly parameters are not available.

---

## Session builders

Session builders let you focus on the application-layer payload and have all
the protocol machinery — handshakes, sequence numbers, ACKs, teardowns —
handled automatically.  Call `.send()` and `.recv()` to describe what each
side transmits, then call `.build()` to get the same stream type as the
corresponding low-level generator.

### `TCPSession`

```python
from packeteer.generate import TCPSession
from packeteer.pcap import write_pcap

# Bidirectional HTTP-style exchange
stream = (TCPSession(client_ip="10.0.0.1", server_ip="10.0.0.2", server_port=80)
    .send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    .recv(b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 4000)
    .build()
)
write_pcap(stream.to_pcap_tuples(), path="http.pcap")
```

`TCPSession` generates a three-way handshake, the queued exchanges (MSS-segmented,
PSH set on the last segment of each exchange), and a four-way teardown.
Unidirectional flows are expressed naturally — use only `.send()` or only `.recv()`.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `client_ip` | *(required)* | Client IP address (IPv4 or IPv6) |
| `server_ip` | *(required)* | Server IP address (same family) |
| `client_port` | `54321` | Client source port |
| `server_port` | `80` | Server destination port |
| `client_mac` | `"00:00:00:00:00:01"` | Client MAC address |
| `server_mac` | `"00:00:00:00:00:02"` | Server MAC address |
| `mss` | `1460` | Maximum segment size for large payload splitting |
| `include_ethernet` | `True` | Include Ethernet headers |
| `ip_ttl` | `64` | IP TTL / hop limit |
| `inter_packet_gap` | `0.001` | Seconds between consecutive packets |
| `client_isn` | `None` | Client initial sequence number (random if `None`) |
| `server_isn` | `None` | Server initial sequence number (random if `None`) |
| `base_time` | `None` | Unix timestamp for the first packet (current time if `None`) |
| `encap` | `None` | Encapsulation layer(s) — see [Encapsulation](#encapsulation) |

**Queuing methods:**

| Method | Description |
|--------|-------------|
| `.send(data)` | Queue *data* as a client→server payload |
| `.recv(data)` | Queue *data* as a server→client payload |
| `.send_many(n, fn)` | Queue *n* client→server payloads from `fn(index) -> bytes` |
| `.recv_many(n, fn)` | Queue *n* server→client payloads from `fn(index) -> bytes` |
| `.build()` | Assemble and return the `TCPStream` |

```python
# Unidirectional log stream (server pushes N events)
stream = (TCPSession(client_ip="10.0.0.1", server_ip="10.0.0.2", server_port=9000)
    .recv_many(50, lambda i: f"event {i}\n".encode())
    .build()
)
```

### `UDPSession`

```python
from packeteer.generate import UDPSession

# DNS query/response
stream = (UDPSession(client_ip="10.0.0.1", server_ip="8.8.8.8", server_port=53)
    .send(dns_query_bytes)
    .recv(dns_response_bytes)
    .build()
)

# Unidirectional syslog
stream = (UDPSession(client_ip="10.0.0.1", server_ip="10.0.0.2", server_port=514)
    .send_many(100, lambda i: f"<134>event {i}\n".encode())
    .build()
)
```

`UDPSession` has the same constructor parameters as `TCPSession` minus `mss`,
`client_isn`, and `server_isn`.  Datagrams are emitted in queue order with no
handshake or teardown.

### `SCTPSession`

```python
from packeteer.generate import SCTPSession

stream = (SCTPSession(
        client_ip="10.0.0.1", server_ip="10.0.0.2", server_port=36412)
    .send(s1ap_setup_request)
    .recv(s1ap_setup_response)
    .build()
)
```

`SCTPSession` generates the four-way SCTP handshake (INIT / INIT-ACK /
COOKIE-ECHO / COOKIE-ACK), the queued DATA+SACK exchanges, and a graceful
shutdown sequence.  TSN tracking is per-direction so bidirectional exchanges
produce independent, correct TSN sequences.

---

## Standalone helpers

### `tcp_handshake`

Returns `[SYN, SYN-ACK, ACK]` as raw bytes with correct checksums.  Useful
when assembling packet sequences manually; for full session flows use
`TCPSession` instead.

```python
from packeteer.generate import tcp_handshake

packets = tcp_handshake(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    client_isn=1000, server_isn=5000,
)
```

### `tcp_teardown`

Returns `[FIN-ACK, ACK, FIN-ACK, ACK]` as raw bytes.  The `client_seq`,
`client_ack`, `server_seq`, and `server_ack` parameters should reflect TCP
state at the moment the connection is closed.

```python
from packeteer.generate import tcp_teardown

packets = tcp_teardown(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    client_seq=5000, client_ack=7000,
    server_seq=7000, server_ack=5000,
)
```

### `sctp_handshake`

Returns `[INIT, INIT-ACK, COOKIE-ECHO, COOKIE-ACK]` as raw bytes with
correct CRC-32c checksums and a randomly-generated state cookie.

```python
from packeteer.generate import sctp_handshake

packets = sctp_handshake(
    client_ip="10.0.0.1", server_ip="10.0.0.2", server_port=36412,
)
```

---

## Custom payloads with `TCPStreamConfig.payload_fn`

For `generate_tcp_stream`, pass `payload_fn` in `TCPStreamConfig` to supply
each data-packet payload from a callable:

```python
from packeteer.generate import generate_tcp_stream, TCPStreamConfig

def my_payload(index: int, direction: str) -> bytes:
    return f"packet {index}\n".encode()

stream = generate_tcp_stream(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    num_data_packets=5,
    config=TCPStreamConfig(payload_fn=my_payload),
)
```

When `payload_fn` is set, `min_payload`, `max_payload`, `payload_distribution`,
and `payload_sizes` are all ignored.  For bidirectional custom payloads, use
`TCPSession` instead.

---

## Stream objects and inspection

Each generator returns a typed stream object — `TCPStream`, `UDPStream`, or
`SCTPStream` — containing a `packets` list of per-packet dataclass objects.

### Writing to a file

```python
from packeteer.pcap import write_pcap, write_pcapng, LINKTYPE_ETHERNET

write_pcap(stream.to_pcap_tuples(), path="out.pcap", link_type=LINKTYPE_ETHERNET)
write_pcapng(stream.to_pcap_tuples(), path="out.pcapng")
```

`to_pcap_tuples()` returns a list of `(raw_bytes, ts_sec, ts_usec)` triples
ready for the pcap/pcapng writer.

### Filtering by direction

```python
client_pkts = stream.client_packets()   # direction == "c2s"
server_pkts = stream.server_packets()   # direction == "s2c"
```

### Per-packet fields

All packet types share these fields:

| Field | Description |
|-------|-------------|
| `raw` | Raw packet bytes |
| `ts_sec` | Capture timestamp — whole seconds |
| `ts_usec` | Capture timestamp — microsecond fraction |
| `direction` | `"c2s"` (client→server) or `"s2c"` (server→client) |
| `payload_len` | Payload bytes in this packet |
| `label` | Human-readable label (e.g. `"SYN"`, `"DATA[3]"`, `"FRAG[DATA[0]][1]"`) |

`TCPStreamPacket` also has `seq`, `ack`, and `flags` (TCP control flags).
`SCTPStreamPacket` also has `tsn` (DATA chunk TSN; 0 for control packets).

```python
# Print a summary of every packet in the stream
for pkt in stream.packets:
    print(f"{pkt.label:20s}  {pkt.direction}  {pkt.payload_len}B")

# TCP-specific fields
for pkt in tcp_stream.packets:
    print(f"{pkt.label:10s}  seq={pkt.seq}  ack={pkt.ack}  flags={pkt.flags:#04x}")

# SCTP TSN tracking
for pkt in sctp_stream.packets:
    if pkt.label.startswith("DATA"):
        print(f"{pkt.label}  tsn={pkt.tsn}")
```

Because `packets` is a plain list, you can also reorder, duplicate, or insert
packets freely after generation before writing:

```python
# Duplicate DATA[0] to simulate a retransmit
data0 = stream.packets[3]
stream.packets.insert(4, data0)

write_pcap(stream.to_pcap_tuples(), path="retransmit.pcap")
```

---

## Payload distribution

The `payload_distribution` parameter controls how per-packet payload sizes
are chosen from the `[min_payload, max_payload]` range:

| Value | Behaviour |
|-------|-----------|
| `"uniform"` *(default)* | Each size drawn uniformly at random |
| `"bimodal"` | 70 % small (near `min_payload`) / 30 % large (near `max_payload`) — approximates mixed HTTP/TLS traffic |
| `"fixed"` | Every data packet is exactly `max_payload` bytes |

Pass an explicit `payload_sizes` list to override the distribution entirely:

```python
from packeteer.generate import TCPStreamConfig

stream = generate_tcp_stream(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    num_data_packets=3,
    config=TCPStreamConfig(payload_sizes=[200, 1460, 80]),
)
```

All data across the transfer is drawn from a continuously-tiled payload file
(`default_payload.txt`), so the byte content looks like realistic application
data rather than repeated zeros.

---

## Middlebox fragmentation

Set `mtu` to simulate a low-MTU router or VPN tunnel.  Any packet whose
IP-layer size (excluding the Ethernet header) exceeds `mtu` is replaced with
a sequence of IP fragments.

IPv4 uses the Flags/Fragment Offset fields (RFC 791); IPv6 uses the Fragment
Extension Header (RFC 8200 §4.5).  Each fragment is labelled
`FRAG[<orig>][<n>]` where `<orig>` is the original packet's label.

```python
# Simulate a 576-byte MTU middlebox
stream = generate_tcp_stream(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    num_data_packets=20, mtu=576,
)
```

| MTU | Scenario |
|-----|----------|
| 576 | Historical IPv4 minimum (RFC 791) |
| 1280 | IPv6 minimum link MTU (RFC 8200) |
| 1400 | VPN tunnel with header overhead |

---

## Encapsulation

All three generators accept an `encap` keyword that wraps every packet in one
or more encapsulation layers.  Pass a single descriptor, a list of descriptors
(outermost first), or `None` (default — no encapsulation).

```python
from packeteer.generate import (
    VLANEncap, QinQEncap, MPLSEncap, PPPoEEncap,
    GREEncap, EtherIPEncap, IPIPEncap,
)
```

### Available encapsulation types

| Type | Parameters | Description |
|------|------------|-------------|
| `VLANEncap` | `vid`, `pcp=0`, `dei=0` | Single IEEE 802.1Q VLAN tag |
| `QinQEncap` | `outer_vid`, `inner_vid`, `outer_pcp=0`, `outer_dei=0`, `inner_pcp=0`, `inner_dei=0` | QinQ double VLAN (802.1ad) |
| `MPLSEncap` | `labels`, `tc=0`, `ttl=64` | One or more MPLS label stack entries (RFC 3032) |
| `PPPoEEncap` | `session_id=1` | PPPoE session frame (RFC 2516) |
| `GREEncap` | `src_ip`, `dst_ip`, `key=None`, `ttl=64` | GRE tunnel — stream IPs become inner (RFC 2784 / 2890) |
| `EtherIPEncap` | `src_ip`, `dst_ip`, `ttl=64` | EtherIP tunnel (RFC 3378) |
| `IPIPEncap` | `src_ip`, `dst_ip`, `ttl=64` | IP-in-IP tunnel (RFC 2003 / 4213) |

### Single-layer examples

```python
# 802.1Q VLAN-tagged TCP stream
stream = generate_tcp_stream(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    encap=VLANEncap(vid=100),
)

# GRE-tunnelled UDP stream — stream IPs become inner; outer IPs wrap them
from packeteer.generate import generate_udp_stream

stream = generate_udp_stream(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    encap=GREEncap(src_ip="203.0.113.1", dst_ip="203.0.113.2", key=42),
)

# IP-in-IP tunnel
stream = generate_tcp_stream(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    encap=IPIPEncap(src_ip="203.0.113.1", dst_ip="203.0.113.2"),
)
```

### Stacking multiple layers

Pass a list to combine tag-based and tunnel encapsulations.  Tag-based layers
(VLAN/QinQ → MPLS → PPPoE) are inserted between Ethernet and the inner IP;
tunnel layers add an outer IP header.

```python
# VLAN + GRE: eth → vlan(100) → outer-IP(GRE) → inner-IP → TCP
stream = generate_tcp_stream(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    encap=[VLANEncap(vid=100), GREEncap("203.0.113.1", "203.0.113.2")],
)

# MPLS label stack + IP-in-IP: eth → MPLS(100) → MPLS(200) → outer-IP → inner-IP → TCP
stream = generate_tcp_stream(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    encap=[MPLSEncap(labels=[100, 200]), IPIPEncap("203.0.113.1", "203.0.113.2")],
)
```

**Constraints:** `VLANEncap` and `QinQEncap` are mutually exclusive.  At most
one tunnel type (`GREEncap`, `EtherIPEncap`, `IPIPEncap`) per stack.

`mtu` works correctly with all encapsulation types: tag-based layers fragment
the inner IP at the correct offset; tunnel layers fragment the outer IP
datagram.  PPPoE payload length fields are updated in each fragment.

See {doc}`../api/stream-encap` for the full class reference.

---

## Hooks

The `packet_hooks` field in `TCPStreamConfig` (TCP only) accepts a list of
callables applied to each packet as it is generated.  A hook receives
`(packet, index)` and returns either a modified `TCPStreamPacket` or `None`
to drop the packet.

```python
from dataclasses import replace
from packeteer.generate import TCPStreamConfig

def corrupt_checksum(pkt, idx):
    """Flip the last two bytes of packet 5 to corrupt the TCP checksum."""
    if idx == 5:
        raw = bytearray(pkt.raw)
        raw[-2] ^= 0xFF
        raw[-1] ^= 0xFF
        return replace(pkt, raw=bytes(raw))
    return pkt

def drop_synack(pkt, idx):
    """Silently drop the SYN-ACK — simulates a lost handshake packet."""
    return None if pkt.label == "SYN-ACK" else pkt

stream = generate_tcp_stream(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    num_data_packets=10,
    config=TCPStreamConfig(packet_hooks=[corrupt_checksum, drop_synack]),
)
```

---

See {doc}`../api/stream-generators` for the full API reference.
