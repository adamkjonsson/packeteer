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

Every stream contains exactly `2 * num_data_packets + 7` packets in this order:

| # | Sender | Flags | Label |
|---|--------|-------|-------|
| 0 | client | SYN | `"SYN"` |
| 1 | server | SYN+ACK | `"SYN-ACK"` |
| 2 | client | ACK | `"ACK"` |
| 3, 5, … 2N+1 | client | PSH+ACK | `"DATA[0]"` … `"DATA[N-1]"` |
| 4, 6, … 2N+2 | server | ACK | `"ACK[0]"` … `"ACK[N-1]"` |
| 2N+3 | client | FIN+ACK | `"FIN-ACK"` |
| 2N+4 | server | ACK | `"ACK"` |
| 2N+5 | server | FIN+ACK | `"FIN-ACK"` |
| 2N+6 | client | ACK | `"ACK"` |

Data flows from client to server only.  Initial sequence numbers are chosen
at random by default, matching real TCP behaviour.

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
# 1 ms base gap with ±0.8 ms jitter — occasional out-of-order timestamps
stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    num_data_packets=20,
    inter_packet_gap=0.001,
    gap_jitter=0.0008,
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
The one exception is `packet_loss` (maps to `--packet-loss`).

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
