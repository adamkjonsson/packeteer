# TCP Stream Generation

`generate_tcp_stream` produces a complete, realistic TCP connection as a
sequence of byte-accurate packets: three-way handshake, data transfer, and
four-way teardown.  Sequence and acknowledgement numbers are computed
correctly for every packet, including 32-bit wrap-around.

The stream can be written directly to a pcap or pcapng file, or accessed
packet-by-packet for inspection or error injection before writing.

---

## Quick example

```python
from packet_generator.tcp_stream import generate_tcp_stream
from packet_generator import write_pcap

stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    server_port=80,
    num_data_packets=20,
)
write_pcap(stream.to_pcap_tuples(), path="out.pcap")
```

---

## Packet sequence

The baseline stream contains `2 * num_data_packets + 7` packets in this order:

| # | Sender | Flags | Label |
|---|--------|-------|-------|
| 0 | client | SYN | `"SYN"` |
| 1 | server | SYN+ACK | `"SYN-ACK"` |
| 2 | client | ACK | `"ACK"` |
| 3, 5, … 2N+1 | client | ACK (PSH with probability `psh_probability`) | `"DATA[0]"` … `"DATA[N-1]"` |
| 4, 6, … 2N+2 | server | ACK | `"ACK[0]"` … `"ACK[N-1]"` |
| 2N+3 | client | FIN+ACK | `"FIN-ACK"` |
| 2N+4 | server | ACK | `"ACK"` |
| 2N+5 | server | FIN+ACK | `"FIN-ACK"` |
| 2N+6 | client | ACK | `"ACK"` |

Anomaly parameters (RST, corruption, retransmissions, packet loss) may add
or remove packets from the final list.  Data flows from client to server
only.  Initial sequence numbers are chosen at random by default, matching
real TCP behaviour.

---

## Timestamp jitter

By default all packets are spaced exactly `inter_packet_gap` seconds apart.
Set `gap_jitter` to model interception delay: packet *n* is sent at
`base_time + n * inter_packet_gap` and assigned a capture timestamp of
`sent_time + uniform(0, gap_jitter)`.  Because each delay is independent, a
later packet can overtake an earlier one, producing genuine out-of-order
timestamps.  `generate_tcp_stream` sorts the final list by timestamp before
returning, matching what a real capture would show.

```python
# 1 ms base gap with up to 0.8 ms extra delay — occasional out-of-order timestamps
stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    num_data_packets=20,
    inter_packet_gap=0.001,
    gap_jitter=0.0008,
)
```

---

## Server RST (abrupt connection termination)

Set `server_rst_probability` to simulate the server application crashing
mid-stream.  The OS terminates the connection by sending a TCP RST rather than
performing the normal four-way teardown.

A random split point *k* is chosen among the data packets.  Packets 0…k are
exchanged normally with ACKs.  The server then sends a `RST` packet.  Because
the RST takes time to reach the client (`rst_propagation_delay` seconds), the
client keeps sending the remaining data packets during that window — those
segments arrive with no ACKs, exactly as a real analyser would see.

| Label | Description |
|---|---|
| `DATA[0]`…`DATA[k]`, `ACK[0]`…`ACK[k]` | Normal exchange |
| `DATA[k+1]`… | Client sends with no ACK (RST in transit) |
| `RST` | Server OS sends RST\|ACK, connection terminated |

```python
# 20 % chance the server crashes; 50 ms RST propagation delay
stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    num_data_packets=20,
    server_rst_probability=0.2,
    rst_propagation_delay=0.05,
)
```

---

## Payload corruption

Set `payload_corruption_probability` to simulate a data segment's payload
being corrupted in transit.  The last byte of the payload is XOR-flipped,
which invalidates the TCP checksum — the receiver silently drops the packet
without sending an ACK.  The client's retransmission timer fires after
`retransmission_timeout` seconds and resends the original clean data.

The capture shows three events per corrupted segment:

| Label | Description |
|---|---|
| `CORRUPT[i]` | Original packet with one byte flipped and bad checksum |
| `RETRANS[i]` | Clean retransmit after RTO |
| `ACK[i]` | Server ACK, timestamp shifted to follow the retransmit |

```python
# ~8 % of data segments corrupted, 300 ms RTO
stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    num_data_packets=50,
    payload_corruption_probability=0.08,
    retransmission_timeout=0.3,
)
```

---

## Spurious retransmissions

Set `retransmission_probability` to simulate the client resending a segment
because its retransmission timer fired before the server's ACK arrived.  Each
data segment independently rolls against the probability; if it fires, a copy
of that segment is added to the stream with the same sequence number, flags,
and payload, but timestamped at the original capture time plus
`retransmission_timeout`.  Because the RTO fires after the ACK was already in
flight, the retransmit often appears *after* the ACK in the sorted stream —
which is exactly what Wireshark labels as a spurious retransmission.

Handshake and teardown packets are never retransmitted.

```python
# ~10 % of data segments retransmitted, 300 ms RTO
stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    num_data_packets=50,
    retransmission_probability=0.1,
    retransmission_timeout=0.3,
)
```

---

## Packet loss

Set `packet_loss_probability` to simulate packets being lost on the wire.
Each packet is independently dropped from the capture with that probability.
Sequence and acknowledgement numbers are computed as if every packet was
transmitted — only the capture record is omitted, matching what an analyser
would see when loss occurs mid-stream.

```python
# 5 % packet loss
stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    num_data_packets=100,
    packet_loss_probability=0.05,
)
```

---

## Stray packets (TCP hijacking simulation)

Set `stray_packet_count` to inject forged packets from an attacker who has been
passively sniffing the connection.  The attacker knows the exact TCP state and
sends packets using the same source/destination endpoints as the real client,
but with an all-`x` payload of random size and a seq/ack pair stolen from a
randomly chosen data packet.

Stray packet timestamps are drawn uniformly from the data-transfer window, so
they may arrive before or after the real segment they overlap with — exactly as
you would expect from an off-path attacker with imperfect timing.  Each stray
packet is labelled `STRAY[n]` in the output.

```python
# Inject 5 forged packets scattered across the full data-transfer window
stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    num_data_packets=50,
    stray_packet_count=5,
)

# Tighten timing: each stray arrives within 3 packets of its target segment
stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    num_data_packets=50,
    stray_packet_count=5,
    stray_timing_window=3,
)
```

---

## Middlebox fragmentation

Set `middlebox_mtu` to simulate packets being fragmented by a router or other
middlebox with a low MTU.  Any packet whose IP-layer size (excluding the
Ethernet header) exceeds `middlebox_mtu` is replaced with a sequence of IP
fragments.

IPv4 uses the standard Flags/Fragment Offset fields (RFC 791).  IPv6 uses a
Fragment Extension Header (next header = 44, RFC 8200 §4.5).

Each fragment appears in the capture labelled `FRAG[<orig>][<n>]` where
`<orig>` is the original packet label (e.g. `DATA[2]`) and `<n>` is the
fragment index starting at zero.  Fragment 0 carries the TCP header and the
first chunk of the payload; subsequent fragments carry only payload bytes.
Handshake and teardown packets are typically small and will not be fragmented
at realistic MTU values.

```python
# Simulate a 576-byte MTU middlebox (conservative router minimum for IPv4)
stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    num_data_packets=20,
    middlebox_mtu=576,
)
```

Typical `middlebox_mtu` values:

| Value | Scenario |
|-------|----------|
| 576   | Historical IPv4 minimum (RFC 791) |
| 1280  | IPv6 minimum link MTU (RFC 8200) |
| 1400  | VPN tunnel with header overhead |
| 1500  | Standard Ethernet (no fragmentation for typical traffic) |

---

## PSH flag behaviour

Real TCP stacks do not set PSH on every data segment — they use it to signal
the receiver to flush its buffer immediately, typically on the last segment of
a logical message.  The `psh_probability` parameter controls how often PSH
appears on data segments:

```python
# Always set PSH (old-style behaviour)
stream = generate_tcp_stream(..., psh_probability=1.0)

# Never set PSH
stream = generate_tcp_stream(..., psh_probability=0.0)

# 30 % of data segments carry PSH (more realistic for bulk transfers)
stream = generate_tcp_stream(..., psh_probability=0.3)
```

The default is ``0.5``.  Handshake and teardown packets are not affected.

---

## Payload size distribution

The `payload_distribution` parameter controls how per-packet payload sizes
are chosen:

| Value | Behaviour |
|-------|-----------|
| `"uniform"` *(default)* | Random between `min_payload` and `max_payload` |
| `"bimodal"` | 70 % small (near `min_payload`) / 30 % large (near `max_payload`) — approximates mixed HTTP/TLS traffic |
| `"fixed"` | Every data packet is exactly `max_payload` bytes |

Pass an explicit `payload_sizes` list to override the distribution entirely:

```python
stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    num_data_packets=3,
    payload_sizes=[200, 1460, 80],   # one size per data packet
)
```

---

## TCP options on SYN / SYN-ACK

Pass a {class}`~packet_generator.tcp.TCPOptions` instance to include TCP
options on the handshake packets:

```python
from packet_generator import TCPOptions
from packet_generator.tcp_stream import generate_tcp_stream

stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    client_options=TCPOptions(mss=1460, window_scale=7, sack_permitted=True),
    server_options=TCPOptions(mss=1460, window_scale=6, sack_permitted=True),
    num_data_packets=10,
)
```

Options are encoded only on SYN and SYN-ACK; data and teardown packets carry
no options.

---

## IPv6

Pass IPv6 addresses — the IP version is detected automatically from the
address string, exactly as with {class}`~packet_generator.builder.PacketBuilder`:

```python
stream = generate_tcp_stream(
    client_ip="2001:db8::1",
    server_ip="2001:db8::2",
    server_port=443,
    num_data_packets=10,
)
```

---

## Raw-IP captures (no Ethernet)

Set `include_ethernet=False` to produce packets without an Ethernet header.
Use `LINKTYPE_RAW` when writing to pcap:

```python
from packet_generator import write_pcap, LINKTYPE_RAW
from packet_generator.tcp_stream import generate_tcp_stream

stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    num_data_packets=5,
    include_ethernet=False,
)
write_pcap(stream.to_pcap_tuples(), path="raw.pcap", link_type=LINKTYPE_RAW)
```

---

## Inspecting the stream

{class}`~packet_generator.tcp_stream.TCPStream` is a plain dataclass with a
`packets` list of {class}`~packet_generator.tcp_stream.TCPStreamPacket`
objects.  Each packet carries its raw bytes alongside metadata:

```python
for pkt in stream.packets:
    print(f"{pkt.label:10s}  {pkt.direction}  seq={pkt.seq}  ack={pkt.ack}  payload={pkt.payload_len}B")
```

Filter by direction with the helper methods:

```python
client_pkts = stream.client_packets()   # c2s only
server_pkts = stream.server_packets()   # s2c only
```

---

## Error and anomaly injection

The `packet_hooks` parameter accepts a list of callables that are applied to
each packet as it is generated.  A hook receives `(packet, index)` and
returns a modified {class}`~packet_generator.tcp_stream.TCPStreamPacket` or
`None` to drop the packet from the stream.

```python
from dataclasses import replace

def corrupt_checksum(pkt, idx):
    """Flip the last two bytes of packet 5 to corrupt the TCP checksum."""
    if idx == 5:
        raw = bytearray(pkt.raw)
        raw[-2] ^= 0xFF
        raw[-1] ^= 0xFF
        return replace(pkt, raw=bytes(raw))
    return pkt

def drop_packet(pkt, idx):
    """Silently drop the server's SYN-ACK."""
    if pkt.label == "SYN-ACK":
        return None
    return pkt

stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    num_data_packets=10,
    packet_hooks=[corrupt_checksum, drop_packet],
)
```

Because `stream.packets` is a plain list, you can also reorder, duplicate,
or insert packets freely after generation:

```python
# Duplicate DATA[0] to simulate a retransmit
data0 = stream.packets[3]
stream.packets.insert(4, data0)

write_pcap(stream.to_pcap_tuples(), path="retransmit.pcap")
```

---

## Full API reference

```{eval-rst}
.. autofunction:: packet_generator.tcp_stream.generate_tcp_stream
```

```{eval-rst}
.. autoclass:: packet_generator.tcp_stream.TCPStream
   :members:
```

```{eval-rst}
.. autoclass:: packet_generator.tcp_stream.TCPStreamPacket
```

---

## Config file

All `packeteer stream` parameters can be stored in an INI file and passed
with `--config`.  CLI flags always override file values, so the file acts as
a saved profile that individual runs can still adjust:

```bash
packeteer stream --config session.ini
packeteer stream --config session.ini --packets 200 --distribution bimodal
```

A fully commented template is at
[src/packet_generator/stream.ini.template](../src/packet_generator/stream.ini.template).
The file uses a single `[stream]` section; key names match the CLI long flags
with hyphens replaced by underscores (e.g. `gap_jitter`, `psh_probability`).
Two keys differ from their CLI flag names: `packet_loss` (CLI: `--packet-loss`)
and `server_rst` (CLI: `--server-rst`).

```ini
[stream]
client_ip = 10.0.0.1
server_ip = 10.0.0.2
pcap = out.pcap
packets = 50
distribution = bimodal
gap = 0.002
gap_jitter = 0.001
psh_probability = 0.3
packet_loss = 0.02
retransmission_probability = 0.05
retransmission_timeout = 0.2
payload_corruption_probability = 0.02
server_rst_probability = 0.0
rst_propagation_delay = 0.0
middlebox_mtu = 576
stray_packet_count = 3
```

---

## CLI

The `packeteer stream` subcommand exposes the most commonly used parameters
without writing any Python.  See {doc}`cli` for the full flag reference.

```bash
# 50-packet stream to a pcap file
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 --packets 50 --pcap out.pcap

# HTTPS session with bimodal payload distribution, written as pcapng
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --server-port 443 --distribution bimodal --pcapng tls.pcapng

# IPv6, custom ports, fixed 512-byte payloads, 10 ms inter-packet gap
packeteer stream --client-ip 2001:db8::1 --server-ip 2001:db8::2 \
    --client-port 12345 --server-port 8080 \
    --distribution fixed --max-payload 512 --gap 0.01 --pcap out.pcap
```
