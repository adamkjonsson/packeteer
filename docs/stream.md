# Stream Generation

packeteer generates complete, byte-accurate network streams in two ways: from
the CLI using `packeteer stream`, or directly from Python using one of the three
generator functions.  Both paths produce realistic packet sequences — including
correct protocol state, sequence numbers, checksums, timestamps, and optional
impairments — that can be written to pcap, pcapng, or JSON config files.

Three protocols are supported:

| Protocol | What is generated |
|----------|-------------------|
| `tcp` *(default)* | Three-way handshake, data transfer, four-way teardown with correct seq/ack numbers |
| `udp` | Sequence of client→server datagrams with realistic timestamps |
| `sctp` | Full SCTP association: 4-way handshake, DATA+SACK pairs, graceful shutdown per RFC 9260 |

---

## `packeteer stream` — CLI

```
packeteer stream --client-ip IP --server-ip IP
                 (--pcap FILE | --pcapng FILE | --json FILE)
                 [options]
```

Generates a complete synthetic network stream and writes it to the chosen
output format.  All required arguments can come from the command line, from an
INI config file (`--config`), or from a combination of both — CLI flags always
take precedence over config file values.

### Output formats

Exactly one output flag is required; they are mutually exclusive.

| Flag | Output |
|------|--------|
| `--pcap FILE` | libpcap (`.pcap`) file with microsecond timestamps |
| `--pcapng FILE` | pcapng (`.pcapng`) file |
| `--json FILE` | JSON config file — same format produced by `packeteer parse`, replayable with `packeteer build`.  Each packet's `packet_metadata` block gains two extra fields: `direction` (`"c2s"` or `"s2c"`) and `label` (e.g. `"SYN"`, `"DATA[3]"`) that identify the packet's role in the stream. |

### General arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--config FILE` | — | INI config file with a `[stream]` section |
| `--protocol` | `tcp` | Transport protocol: `tcp`, `udp`, or `sctp` |
| `--client-ip IP` | *(required)* | Client IP address (IPv4 or IPv6) |
| `--server-ip IP` | *(required)* | Server IP address (same family as client) |
| `--client-port PORT` | `54321` | Client source port |
| `--server-port PORT` | `80` | Server destination port |
| `--client-mac MAC` | `00:00:00:00:00:01` | Client Ethernet MAC address |
| `--server-mac MAC` | `00:00:00:00:00:02` | Server Ethernet MAC address |
| `--no-ethernet` | off | Omit Ethernet headers (produces raw IP packets) |
| `--packets N` | `10` | Number of data packets sent by the client |
| `--min-payload BYTES` | `40` | Minimum payload size per data packet |
| `--max-payload BYTES` | `1460` | Maximum payload size per data packet |
| `--distribution` | `uniform` | Payload size strategy: `uniform`, `bimodal`, or `fixed` (see [Payload distribution](#payload-distribution)) |
| `--ttl N` | `64` | IP TTL / hop limit |
| `--gap SECONDS` | `0.001` | Base inter-packet gap (1 ms) |
| `--gap-jitter SECONDS` | `0.0` | Maximum additional delay per packet; output is re-sorted by timestamp |
| `--mtu BYTES` | off | Fragment packets exceeding this IP-layer size, simulating a low-MTU middlebox |

### TCP-only arguments

These flags are silently ignored for `--protocol udp` and `--protocol sctp`.

| Argument | Default | Description |
|----------|---------|-------------|
| `--window BYTES` | `65535` | TCP receive window size |
| `--psh-probability PROB` | `0.5` | Probability (0–1) that PSH is set on each data segment |
| `--packet-loss PROB` | `0.0` | Probability (0–1) that any packet is dropped from the capture |
| `--retransmission-probability PROB` | `0.0` | Probability (0–1) that each data segment is spuriously retransmitted |
| `--retransmission-timeout SECONDS` | `0.2` | RTO — time after original send that the retransmit fires |
| `--payload-corruption PROB` | `0.0` | Probability (0–1) that a segment's payload is corrupted in transit |
| `--server-rst PROB` | `0.0` | Probability (0–1) that the server terminates mid-stream with a RST |
| `--rst-propagation-delay SECONDS` | `0.0` | Seconds for the RST to reach the client |
| `--stray-packets N` | `0` | Number of forged TCP hijack packets to inject |
| `--stray-timing-window N` | off | Constrain each stray packet's timestamp to within N packets of its target |

### Encapsulation flags

Wrap every packet in one or more encapsulation layers.  Layers are applied in
the fixed order VLAN/QinQ → MPLS → PPPoE → tunnel.  At most one of `--vlan`
and `--qinq` may be given; at most one tunnel type (`--gre`, `--etherip`,
`--ipip`) may be given.

| Flag | Description |
|------|-------------|
| `--vlan VID` | Single 802.1Q VLAN tag |
| `--vlan-pcp N` | VLAN Priority Code Point (0–7, default 0) |
| `--vlan-dei N` | VLAN Drop Eligible Indicator (0 or 1, default 0) |
| `--qinq OUTER INNER` | QinQ double VLAN tag (outer VID then inner VID) |
| `--qinq-outer-pcp N` | Outer tag PCP (default 0) |
| `--qinq-outer-dei N` | Outer tag DEI (default 0) |
| `--qinq-inner-pcp N` | Inner tag PCP (default 0) |
| `--qinq-inner-dei N` | Inner tag DEI (default 0) |
| `--mpls LABEL…` | MPLS label stack (one or more 20-bit labels, outermost first) |
| `--mpls-tc N` | MPLS Traffic Class for all labels (0–7, default 0) |
| `--mpls-ttl N` | MPLS TTL for all labels (default 64) |
| `--pppoe SESSION_ID` | PPPoE session frame with given 16-bit session ID |
| `--gre SRC_IP DST_IP` | GRE tunnel; stream IPs become inner; outer IPs are SRC/DST |
| `--gre-key N` | RFC 2890 32-bit GRE Key field |
| `--gre-ttl N` | Outer IP TTL for GRE (default 64) |
| `--etherip SRC_IP DST_IP` | EtherIP tunnel (RFC 3378) |
| `--etherip-ttl N` | Outer IP TTL for EtherIP (default 64) |
| `--ipip SRC_IP DST_IP` | IP-in-IP tunnel (RFC 2003 / 4213) |
| `--ipip-ttl N` | Outer IP TTL for IP-in-IP (default 64) |

### INI config file

All parameters can be stored in a `[stream]` section of an INI file and passed
with `--config`.  Key names match the CLI long flags with hyphens replaced by
underscores (e.g. `gap_jitter`, `psh_probability`).  Two keys differ from their
flag names: `packet_loss` (flag: `--packet-loss`) and `server_rst` (flag:
`--server-rst`).

A fully commented template is at
[stream.ini.template](../stream.ini.template).

```ini
[stream]
client_ip  = 10.0.0.1
server_ip  = 10.0.0.2
pcap       = out.pcap
protocol   = tcp
packets    = 50
distribution = bimodal
gap        = 0.002
gap_jitter = 0.001
mtu        = 576
psh_probability            = 0.3   # TCP only
packet_loss                = 0.02  # TCP only
retransmission_probability = 0.05  # TCP only
```

CLI flags override config file values, so the file acts as a saved profile that
individual runs can still adjust:

```bash
packeteer stream --config session.ini
packeteer stream --config session.ini --packets 200 --distribution bimodal
```

### Examples

**TCP: 50-packet HTTP session:**

```bash
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --server-port 80 --packets 50 --pcap session.pcap
```

**UDP: DNS-like datagram flow:**

```bash
packeteer stream --protocol udp \
    --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --server-port 53 --packets 5 --pcap dns.pcap
```

**SCTP: full association with bimodal payload sizes:**

```bash
packeteer stream --protocol sctp \
    --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --server-port 9999 --packets 20 --distribution bimodal --pcap sctp.pcap
```

**IPv6, fixed 512-byte payloads, 10 ms inter-packet gap:**

```bash
packeteer stream --client-ip 2001:db8::1 --server-ip 2001:db8::2 \
    --server-port 8080 --distribution fixed --max-payload 512 \
    --gap 0.01 --pcapng out.pcapng
```

**VLAN-tagged stream with middlebox fragmentation:**

```bash
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --vlan 100 --mtu 576 --pcap vlan_frag.pcap
```

**GRE tunnel with MPLS labels:**

```bash
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --mpls 100 200 --gre 203.0.113.1 203.0.113.2 --pcap mpls_gre.pcap
```

**Generate JSON for downstream editing or sanitisation:**

```bash
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 --packets 10 \
    --json stream.json
packeteer sanitise stream.json --ports --payload --output clean.json
packeteer build clean.json --pcap clean.pcap
```

---

## Python API

### TCP stream — `generate_tcp_stream`

`generate_tcp_stream` produces a complete TCP connection with correct sequence
and acknowledgement numbers, 32-bit wrap-around, and per-packet timestamps.

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

#### Packet sequence

The baseline stream contains `2 * num_data_packets + 7` packets:

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

Anomaly parameters (RST, corruption, retransmissions, packet loss) add or
remove packets.  Initial sequence numbers are chosen at random, matching real
TCP behaviour.

#### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `client_ip` | *(required)* | Client IP address (IPv4 or IPv6) |
| `server_ip` | *(required)* | Server IP address (same family) |
| `client_port` | `54321` | Client source port |
| `server_port` | `80` | Server destination port |
| `client_mac` | `"00:00:00:00:00:01"` | Client MAC address |
| `server_mac` | `"00:00:00:00:00:02"` | Server MAC address |
| `num_data_packets` | `10` | Number of client DATA segments |
| `include_ethernet` | `True` | Include Ethernet headers |
| `ip_ttl` | `64` | IP TTL / hop limit |
| `window` | `65535` | TCP receive window size |
| `inter_packet_gap` | `0.001` | Base time between packets in seconds |
| `gap_jitter` | `0.0` | Max extra delay per packet; output re-sorted by timestamp |
| `min_payload` | `40` | Minimum payload size in bytes |
| `max_payload` | `1460` | Maximum payload size in bytes |
| `payload_distribution` | `"uniform"` | `"uniform"`, `"bimodal"`, or `"fixed"` |
| `payload_sizes` | `None` | Explicit list of per-packet sizes, overrides distribution |
| `psh_probability` | `0.5` | Probability PSH is set on each data segment |
| `packet_loss_probability` | `0.0` | Probability any packet is dropped from the capture |
| `retransmission_probability` | `0.0` | Probability each data segment is spuriously retransmitted |
| `retransmission_timeout` | `0.2` | Seconds after original send that the retransmit fires |
| `payload_corruption_probability` | `0.0` | Probability a data segment payload is corrupted in transit |
| `server_rst_probability` | `0.0` | Probability the server terminates mid-stream with a RST |
| `rst_propagation_delay` | `0.0` | Seconds for the RST to reach the client |
| `stray_packet_count` | `0` | Number of forged TCP hijack packets to inject |
| `stray_timing_window` | `None` | If set, constrain each stray timestamp to within N packets of its target |
| `mtu` | `None` | Fragment packets whose IP-layer size exceeds this value |
| `client_options` | `None` | `TCPOptions` to include on SYN |
| `server_options` | `None` | `TCPOptions` to include on SYN-ACK |
| `encap` | `None` | Encapsulation layer(s) — see [Encapsulation](#encapsulation) |
| `packet_hooks` | `[]` | List of callables applied to each packet — see [Hooks](#hooks) |

#### Timestamp jitter

Set `gap_jitter` to model capture delay: each packet gets an extra delay drawn
from `uniform(0, gap_jitter)`.  Because delays are independent, packets can
overtake each other, producing genuine out-of-order timestamps in the sorted
stream.

```python
# 1 ms base gap with up to 0.8 ms extra jitter
stream = generate_tcp_stream(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    num_data_packets=20, inter_packet_gap=0.001, gap_jitter=0.0008,
)
```

#### TCP anomalies

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

#### TCP options

Pass {class}`~packet_generator.tcp.TCPOptions` instances to include options on
the SYN and SYN-ACK:

```python
from packet_generator.tcp import TCPOptions

stream = generate_tcp_stream(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    client_options=TCPOptions(mss=1460, window_scale=7, sack_permitted=True),
    server_options=TCPOptions(mss=1460, window_scale=6, sack_permitted=True),
    num_data_packets=10,
)
```

Options are encoded only on SYN and SYN-ACK; data and teardown packets carry
no options.

---

### UDP stream — `generate_udp_stream`

`generate_udp_stream` produces a sequence of client→server UDP datagrams —
suitable for DNS queries, TFTP, syslog, or any unidirectional datagram flow.
There is no handshake or teardown; all `num_data_packets` packets carry
direction `"c2s"` and are labelled `DATA[0]`, `DATA[1]`, …

```python
from packet_generator.udp_stream import generate_udp_stream
from packet_generator import write_pcap

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

### SCTP stream — `generate_sctp_stream`

`generate_sctp_stream` produces a complete SCTP association — four-way
handshake, DATA+SACK exchange, and graceful shutdown — with verification tags,
TSNs, CRC-32c checksums, and State Cookie TLVs all computed correctly per
RFC 9260.

```python
from packet_generator.sctp_stream import generate_sctp_stream
from packet_generator import write_pcap

stream = generate_sctp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    server_port=9999,
    num_data_packets=10,
    payload_distribution="bimodal",
)
write_pcap(stream.to_pcap_tuples(), path="sctp_flow.pcap")
```

#### Packet sequence

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

### Stream objects and inspection

Each generator returns a typed stream object — `TCPStream`, `UDPStream`, or
`SCTPStream` — containing a `packets` list of per-packet dataclass objects.

#### Writing to a file

```python
from packet_generator import write_pcap, write_pcapng, LINKTYPE_ETHERNET

write_pcap(stream.to_pcap_tuples(), path="out.pcap", link_type=LINKTYPE_ETHERNET)
write_pcapng(stream.to_pcap_tuples(), path="out.pcapng")
```

`to_pcap_tuples()` returns a list of `(raw_bytes, ts_sec, ts_usec)` triples
ready for the pcap/pcapng writer.

#### Filtering by direction

```python
client_pkts = stream.client_packets()   # direction == "c2s"
server_pkts = stream.server_packets()   # direction == "s2c"
```

#### Per-packet fields

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

### Payload distribution

The `payload_distribution` parameter controls how per-packet payload sizes
are chosen from the `[min_payload, max_payload]` range:

| Value | Behaviour |
|-------|-----------|
| `"uniform"` *(default)* | Each size drawn uniformly at random |
| `"bimodal"` | 70 % small (near `min_payload`) / 30 % large (near `max_payload`) — approximates mixed HTTP/TLS traffic |
| `"fixed"` | Every data packet is exactly `max_payload` bytes |

Pass an explicit `payload_sizes` list to override the distribution entirely:

```python
stream = generate_tcp_stream(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    num_data_packets=3, payload_sizes=[200, 1460, 80],
)
```

All data across the transfer is drawn from a continuously-tiled payload file
(`default_payload.txt`), so the byte content looks like realistic application
data rather than repeated zeros.

---

### Middlebox fragmentation

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

### Encapsulation

All three generators accept an `encap` keyword that wraps every packet in one
or more encapsulation layers.  Pass a single descriptor, a list of descriptors
(outermost first), or `None` (default — no encapsulation).

```python
from packet_generator.stream_encap import (
    VLANEncap, QinQEncap, MPLSEncap, PPPoEEncap,
    GREEncap, EtherIPEncap, IPIPEncap,
)
```

#### Available encapsulation types

| Type | Parameters | Description |
|------|------------|-------------|
| `VLANEncap` | `vid`, `pcp=0`, `dei=0` | Single IEEE 802.1Q VLAN tag |
| `QinQEncap` | `outer_vid`, `inner_vid`, `outer_pcp=0`, `outer_dei=0`, `inner_pcp=0`, `inner_dei=0` | QinQ double VLAN (802.1ad) |
| `MPLSEncap` | `labels`, `tc=0`, `ttl=64` | One or more MPLS label stack entries (RFC 3032) |
| `PPPoEEncap` | `session_id=1` | PPPoE session frame (RFC 2516) |
| `GREEncap` | `src_ip`, `dst_ip`, `key=None`, `ttl=64` | GRE tunnel — stream IPs become inner (RFC 2784 / 2890) |
| `EtherIPEncap` | `src_ip`, `dst_ip`, `ttl=64` | EtherIP tunnel (RFC 3378) |
| `IPIPEncap` | `src_ip`, `dst_ip`, `ttl=64` | IP-in-IP tunnel (RFC 2003 / 4213) |

#### Single-layer examples

```python
# 802.1Q VLAN-tagged TCP stream
stream = generate_tcp_stream(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    encap=VLANEncap(vid=100),
)

# GRE-tunnelled UDP stream — stream IPs become inner; outer IPs wrap them
from packet_generator.udp_stream import generate_udp_stream

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

#### Stacking multiple layers

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

See {doc}`api/stream-encap` for the full class reference.

---

### Hooks

The `packet_hooks` parameter (TCP only) accepts a list of callables applied to
each packet as it is generated.  A hook receives `(packet, index)` and returns
either a modified `TCPStreamPacket` or `None` to drop the packet.

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

def drop_synack(pkt, idx):
    """Silently drop the SYN-ACK — simulates a lost handshake packet."""
    return None if pkt.label == "SYN-ACK" else pkt

stream = generate_tcp_stream(
    client_ip="10.0.0.1", server_ip="10.0.0.2",
    num_data_packets=10,
    packet_hooks=[corrupt_checksum, drop_synack],
)
```

---

### Full API reference

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

```{eval-rst}
.. autofunction:: packet_generator.udp_stream.generate_udp_stream
```

```{eval-rst}
.. autoclass:: packet_generator.udp_stream.UDPStream
   :members:
```

```{eval-rst}
.. autoclass:: packet_generator.udp_stream.UDPStreamPacket
```

```{eval-rst}
.. autofunction:: packet_generator.sctp_stream.generate_sctp_stream
```

```{eval-rst}
.. autoclass:: packet_generator.sctp_stream.SCTPStream
   :members:
```

```{eval-rst}
.. autoclass:: packet_generator.sctp_stream.SCTPStreamPacket
```
