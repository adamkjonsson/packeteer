# packet-generator

A pure-Python library for building, fragmenting, and parsing complete,
byte-accurate raw network packets. Construct Ethernet II frames containing IPv4
or IPv6 headers, TCP, UDP, ICMPv4, and ICMPv6 transport layers — all with
correct checksums computed automatically per RFC. Large payloads can be split
into RFC-compliant IP fragments in one call. The companion `packet_parser`
module can decode each layer back to its header dataclass and read libpcap
files written by any tool.

No external dependencies. Python 3.10+ and the standard library only.

---

## Features

- **Ethernet II** framing with configurable MAC addresses and automatic EtherType
- **IEEE 802.1Q VLAN tagging** — inserts a 4-byte VLAN tag (TPID `0x8100` + TCI) into the Ethernet header; configurable VID (1–4094), PCP (0–7), and DEI
- **IPv4** headers (RFC 791) with RFC 1071 header checksum
- **IPv6** fixed headers (RFC 8200) — no header checksum, 40 bytes
- **TCP** (RFC 9293) with pseudo-header checksum for IPv4 and IPv6
- **UDP** (RFC 768) with pseudo-header checksum for IPv4 and IPv6
- **ICMPv4** (RFC 792) Echo Request/Reply — no pseudo-header
- **ICMPv6** (RFC 4443) Echo Request/Reply — mandatory IPv6 pseudo-header checksum
- IP version **auto-detected** from address strings (no explicit flag needed)
- **IPv4 fragmentation** (RFC 791) — Flags/Fragment Offset in IP header, MF flag, shared identification
- **IPv6 fragmentation** (RFC 8200 §4.5) — Fragment Extension Header (next header = 44), 32-bit identification
- High-level `PacketBuilder.fragment(mtu)` and low-level `fragment_ipv4` / `fragment_ipv6` functions
- Payload: random bytes of a given size, or supply your own
- Optional Ethernet header — produce raw IP packets when not needed
- `packet_lab.py` CLI with `build` and `parse` subcommands — build packets and write pcap/pcapng files, or parse captures back to a JSON config for replay
- **`packet_parser` module** — parse each layer back to its header dataclass; roundtrip-compatible with all `packet_generator` builders
  - Parsers for Ethernet II (with optional 802.1Q VLAN tag), IPv4, IPv6, ICMP, ICMPv6, UDP, and TCP
  - Each parser returns `(header_size, next_layer_id, HeaderObject)` — chain parsers by slicing `data[header_size:]`
  - `read_pcap` reads both libpcap (`.pcap`) and pcapng (`.pcapng`) files, auto-detected from the file magic (microsecond and nanosecond timestamps, little- and big-endian)
  - `parse_packet(data)` — parse a raw `bytes` object through all layers at once, returning a `ParsedPacket` dataclass
  - `parse_pcap_packet(record, file_header)` — parse one record from a `PcapFile`, with `link_type` and timestamps filled in automatically
  - `parse_pcap_file(path=…)` — parse every packet in a pcap or pcapng file and return a ready-to-use JSON config string
  - `packet_parser.to_config` — convert parsed headers to a JSON config dict accepted by `packet_lab.py build --config`; build up the config one protocol layer at a time with `update_config`

---

## Installation

Clone the repository and use the package directly — no build step or `pip install`
required:

```bash
git clone https://github.com/adamkjonsson/packet-generator.git
cd packet-generator
```

Python 3.10 or later is required (uses the `X | Y` union type syntax).

---

## Quick start

### Build packets with `packet_lab.py build`

```bash
# Build from a JSON config and write a pcap file
python packet_lab.py build packets.json --pcap out.pcap

# Build from a JSON config and write a pcapng file
python packet_lab.py build packets.json --pcapng out.pcapng
```

### Parse a pcap file with `packet_lab.py parse`

```bash
# Print the JSON config for every packet in a capture
python packet_lab.py parse capture.pcap

# Save the JSON config to a file
python packet_lab.py parse capture.pcap --output replay.json

# Round-trip: parse a capture and rebuild it as a new pcap
python packet_lab.py parse capture.pcap --output config.json
python packet_lab.py build config.json --pcap replayed.pcap

# Parse a pcapng file and rebuild it as pcapng
python packet_lab.py parse capture.pcapng --output config.json
python packet_lab.py build config.json --pcapng replayed.pcapng
```

---

## JSON config file

A JSON config file is loaded with `--config`. It must contain a top-level
`packets` array with one object per packet to build. A top-level `file_metadata`
block records information about the file the config was parsed from (`from_file`,
`type`, `nanoseconds`). Per-packet `metadata` supports `mtu`, `timestamp_s`,
`timestamp_us`, and `timestamp_ns` (when `file_metadata.nanoseconds` is `true`).

```json
{
  "packets": [
    {
      "network": {
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "protocol": "tcp"
      },
      "transport": {
        "src_port": 12345,
        "dst_port": 80,
        "seq": 100,
        "flags": 2
      },
      "payload": { "size": 64 },
      "metadata": { "timestamp_s": 1000, "timestamp_us": 0 }
    },
    {
      "network": {
        "src": "10.0.0.2",
        "dst": "10.0.0.1",
        "protocol": "tcp"
      },
      "transport": {
        "src_port": 80,
        "dst_port": 12345,
        "seq": 1
      },
      "payload": { "size": 128 },
      "metadata": { "timestamp_s": 1000, "timestamp_us": 500000 }
    }
  ],
  "file_metadata": {
    "from_file": "conversation.pcap",
    "type": "pcap",
    "nanoseconds": false
  }
}
```

All packets in a multi-packet pcap or pcapng must use the same link layer type
(either all with Ethernet or all without). If every packet sets
`ethernet.enabled: false` the file uses link type 101 (raw IP); otherwise
link type 1 (Ethernet) is used. CLI flags are ignored for multi-packet configs.

### Field reference

#### `ethernet`

| Field | Default | Description |
|-------|---------|-------------|
| `src_mac` | `"00:00:00:00:00:01"` | Source MAC address |
| `dst_mac` | `"00:00:00:00:00:02"` | Destination MAC address |
| `enabled` | `true` | Set to `false` to omit the Ethernet header (equivalent to `--no-ethernet`) |
| `pad` | `false` | Pad the frame to the IEEE 802.3 minimum of 60 bytes (before FCS) when `true` |
| `vlan.id` | — | VLAN ID 1–4094; omit the `vlan` key entirely to disable VLAN tagging |
| `vlan.pcp` | `0` | VLAN Priority Code Point (0–7) |
| `vlan.dei` | `0` | VLAN Drop Eligible Indicator (0 or 1) |

#### `network`

| Field | Required | Description |
|-------|----------|-------------|
| `src` | yes | Source IP address (IPv4 or IPv6) |
| `dst` | yes | Destination IP address |
| `protocol` | yes | `"tcp"`, `"udp"`, `"icmp"`, or `"icmpv6"` |
| `ttl` | no (default `64`) | TTL (IPv4) / Hop Limit (IPv6) |
| `tos` | no (default `0`) | IPv4 Type of Service / DSCP byte |
| `identification` | no (default `0`) | IPv4 16-bit packet identification field |
| `flags` | no (default `2`) | IPv4 3-bit flags field — bit 1 is the Don't Fragment (DF) bit |
| `fragment_offset` | no (default `0`) | IPv4 13-bit fragment offset (in 8-byte units) |
| `traffic_class` | no (default `0`) | IPv6 Traffic Class — 8-bit DSCP + ECN field |
| `flow_label` | no (default `0`) | IPv6 20-bit Flow Label for QoS |

#### `transport`

| Field | Default | Description |
|-------|---------|-------------|
| `src_port` | `12345` | Source port (TCP/UDP) |
| `dst_port` | `80` | Destination port (TCP/UDP) |
| `seq` | `0` | TCP sequence number |
| `ack` | `0` | TCP acknowledgement number |
| `reserved` | `0` | TCP 4-bit reserved field (RFC 9293 §3.1); should be `0` |
| `flags` | `2` | TCP 8-bit control flags integer — `TCP_CWR`=128, `TCP_ECE`=64, `TCP_URG`=32, `TCP_ACK`=16, `TCP_PSH`=8, `TCP_RST`=4, `TCP_SYN`=2, `TCP_FIN`=1; add values to combine (e.g. `24` for PSH+ACK) |
| `window` | `65535` | TCP receive-window size in bytes |
| `urgent_ptr` | `0` | TCP urgent pointer (relevant only when URG flag is set) |
| `options.mss` | — | TCP MSS option — Maximum Segment Size in bytes |
| `options.window_scale` | — | TCP Window Scale option — shift count 0–14 |
| `options.sack_permitted` | `false` | TCP SACK Permitted option |
| `options.sack` | `[]` | TCP SACK blocks — array of `[left_edge, right_edge]` pairs |
| `options.timestamps` | — | TCP Timestamps option — `[TSval, TSecr]` array |
| `type` | `8` / `128` | ICMP/ICMPv6 message type — default `8` (Echo Request) for ICMP, `128` for ICMPv6 |
| `code` | `0` | ICMP/ICMPv6 sub-type code |
| `identifier` | `1` | ICMP/ICMPv6 16-bit identifier used to match replies to requests |
| `sequence` | `1` | ICMP/ICMPv6 16-bit sequence number |

#### `payload`

`size` and `data` are mutually exclusive; `data` takes precedence.

| Field | Description |
|-------|-------------|
| `size` | Generate N random bytes as the payload |
| `data` | Explicit payload as a hex string (e.g. `"48656c6c6f"` = `Hello`) |

#### `file_metadata` (top-level, set by `packet_lab.py parse`)

Read-only metadata about the file the config was parsed from.
`packet_lab.py build` uses `type` and `nanoseconds` for format settings but ignores `from_file`.

| Field | Default | Description |
|-------|---------|-------------|
| `from_file` | — | Path of the pcap or pcapng file the config was parsed from |
| `type` | — | Format of the source file: `pcap` or `pcapng` |
| `nanoseconds` | `false` | When `true`, timestamps are nanosecond-resolution — use `timestamp_ns` per-packet; for pcap magic `0xA1B23C4D`, for pcapng `if_tsresol=9` |

#### `metadata` (per-packet)

Timestamp fields only affect pcap and pcapng output. Use `timestamp_us` when
the top-level `nanoseconds` is `false` (default); use `timestamp_ns` when it
is `true`.

| Field | Default | Description |
|-------|---------|-------------|
| `mtu` | — | Fragment the packet; each IP datagram will be at most this many bytes |
| `timestamp_s` | `0` | Capture timestamp — whole seconds written to `ts_sec` in the pcap packet record header |
| `timestamp_us` | `0` | Capture timestamp — microseconds fraction (0–999999); used when `file_metadata.nanoseconds` is `false` |
| `timestamp_ns` | `0` | Capture timestamp — nanoseconds fraction (0–999999999); used when `file_metadata.nanoseconds` is `true` |

---

## Fragmentation

### High-level — `PacketBuilder.fragment(mtu)`

```python
from packet_generator import PacketBuilder

# Split a 4000-byte UDP payload across ~3 IPv4 fragments (MTU 1500)
fragments = (PacketBuilder()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .udp()
    .payload(size=4000)
    .fragment(mtu=1500)
)

print(f"{len(fragments)} fragments")
for i, frag in enumerate(fragments):
    print(f"  fragment {i+1}: {len(frag)} bytes")

# IPv6 fragmentation uses the Fragment Extension Header (RFC 8200 §4.5)
fragments = (PacketBuilder()
    .ip(src="fe80::1", dst="fe80::2")
    .tcp()
    .payload(size=3000)
    .fragment(mtu=1280)   # IPv6 minimum MTU
)

# No Ethernet header on each fragment
fragments = (PacketBuilder()
    .ip(src="::1", dst="::2")
    .udp()
    .payload(size=2000)
    .fragment(mtu=576)    # IPv4 minimum reassembly buffer
)
```

`fragment()` always returns a list. When the payload fits within one datagram
the list has a single element.

### Low-level — `fragment_ipv4` / `fragment_ipv6`

For fine-grained control, call the underlying functions directly:

```python
import socket
from packet_generator import fragment_ipv4, fragment_ipv6
from packet_generator.ip import IPHeader
from packet_generator.ipv6 import IPv6Header
from packet_generator.ethernet import EthernetHeader, ETHERTYPE_IPV4, ETHERTYPE_IPV6

# IPv4
ip_hdr = IPHeader("10.0.0.1", "10.0.0.2", socket.IPPROTO_UDP, ttl=64)
eth_hdr = EthernetHeader("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", ETHERTYPE_IPV4)
frags = fragment_ipv4(ip_hdr, transport_data, mtu=576, eth_header=eth_hdr)

# IPv6
ip_hdr = IPv6Header("::1", "::2", next_header=17, hop_limit=64)  # 17 = UDP
frags = fragment_ipv6(ip_hdr, transport_data, mtu=1280, eth_header=None)
```

### RFC behaviour

| Detail | IPv4 (RFC 791) | IPv6 (RFC 8200 §4.5) |
|--------|---------------|----------------------|
| Fragment header | IP Flags + Fragment Offset fields | Fragment Extension Header (8 bytes, next header = 44) |
| DF flag | Always cleared (0) on fragments | N/A |
| MF flag | Set on all but the last fragment | M flag in extension header |
| Offset units | 8 bytes | 8 bytes |
| Identification | 16-bit, shared across all fragments | 32-bit, shared across all fragments |
| Min fragment data | 8 bytes (except last) | 8 bytes (except last) |

---

## API reference

### Quick start

```python
from packet_generator import PacketBuilder

# IPv4 TCP packet — Ethernet + IP + TCP + 64 random payload bytes
pkt = (PacketBuilder()
    .ethernet()
    .ip(src="192.168.1.10", dst="8.8.8.8")
    .tcp(dst_port=443)
    .payload(size=64)
    .build()
)
print(f"Built {len(pkt)}-byte packet: {pkt.hex()}")

# IPv6 UDP packet — no Ethernet header
pkt = (PacketBuilder()
    .ip(src="fe80::1", dst="fe80::2")
    .udp()
    .payload(size=20)
    .build()
)

# ICMPv6 Echo Request with an explicit payload
pkt = (PacketBuilder()
    .ethernet()
    .ip(src="::1", dst="::2")
    .icmpv6()
    .payload(data=b"hello ipv6")
    .build()
)

# IPv4 UDP packet on VLAN 100 with priority 5
pkt = (PacketBuilder()
    .ethernet()
    .vlan(vid=100, pcp=5)
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .udp()
    .payload(size=32)
    .build()
)
# Ethernet header is now 18 bytes (TPID 0x8100 + TCI + inner EtherType)
```

---

### Multi-protocol example

The following example builds a realistic packet capture containing a full TCP
session (three-way handshake, one data exchange, and a FIN teardown), a UDP
DNS query, and an ICMPv4 Echo Request. All packets are written to a single
`.pcap` file that can be opened in Wireshark or replayed with `tcpreplay`.

```python
import time
from packet_generator import PacketBuilder, write_pcap, LINKTYPE_ETHERNET
from packet_generator import TCP_SYN, TCP_ACK, TCP_PSH, TCP_FIN

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
C_MAC  = "00:00:00:00:00:01"
S_MAC  = "00:00:00:00:00:02"
C_PORT = 54321
S_PORT = 80

def build_tcp(src, dst, smac, dmac, seq=0, ack=0, flags=TCP_ACK,
              sport=C_PORT, dport=S_PORT, payload=None, size=0):
    b = (PacketBuilder()
         .ethernet(src_mac=smac, dst_mac=dmac)
         .ip(src=src, dst=dst)
         .tcp(src_port=sport, dst_port=dport, seq=seq, ack=ack, flags=flags))
    if payload is not None:
        b = b.payload(data=payload)
    elif size:
        b = b.payload(size=size)
    return b.build()

collection = []
t = int(time.time())

def append(pkt, usec):
    collection.append((pkt, t, usec))

# ── TCP three-way handshake ──────────────────────────────────────────────────
# SYN  (client → server)
append(build_tcp(CLIENT, SERVER, C_MAC, S_MAC,
                 seq=1000, ack=0, flags=TCP_SYN), 0)
# SYN-ACK  (server → client)
append(build_tcp(SERVER, CLIENT, S_MAC, C_MAC,
                 seq=5000, ack=1001, flags=TCP_SYN | TCP_ACK,
                 sport=S_PORT, dport=C_PORT), 100_000)
# ACK  (client → server)
append(build_tcp(CLIENT, SERVER, C_MAC, S_MAC,
                 seq=1001, ack=5001, flags=TCP_ACK), 200_000)

# ── TCP data exchange ────────────────────────────────────────────────────────
request  = b"GET / HTTP/1.1\r\nHost: 10.0.0.2\r\n\r\n"
response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello"

# PSH+ACK carrying the HTTP request  (client → server)
append(build_tcp(CLIENT, SERVER, C_MAC, S_MAC,
                 seq=1001, ack=5001, flags=TCP_PSH | TCP_ACK,
                 payload=request), 300_000)
# PSH+ACK carrying the HTTP response  (server → client)
append(build_tcp(SERVER, CLIENT, S_MAC, C_MAC,
                 seq=5001, ack=1001 + len(request), flags=TCP_PSH | TCP_ACK,
                 sport=S_PORT, dport=C_PORT, payload=response), 400_000)

# ── TCP teardown  (FIN-ACK exchange) ────────────────────────────────────────
append(build_tcp(CLIENT, SERVER, C_MAC, S_MAC,
                 seq=1001 + len(request), ack=5001 + len(response),
                 flags=TCP_FIN | TCP_ACK), 500_000)
append(build_tcp(SERVER, CLIENT, S_MAC, C_MAC,
                 seq=5001 + len(response), ack=1001 + len(request) + 1,
                 flags=TCP_FIN | TCP_ACK, sport=S_PORT, dport=C_PORT), 600_000)

# ── UDP DNS query ────────────────────────────────────────────────────────────
dns_query = bytes.fromhex(
    "0001010000010000000000000377777706676f6f676c6503636f6d0000010001"
)
append(PacketBuilder()
    .ethernet(src_mac=C_MAC, dst_mac=S_MAC)
    .ip(src=CLIENT, dst="8.8.8.8")
    .udp(src_port=54400, dst_port=53)
    .payload(data=dns_query)
    .build(), 700_000)

# ── ICMPv4 Echo Request (ping) ───────────────────────────────────────────────
append(PacketBuilder()
    .ethernet(src_mac=C_MAC, dst_mac=S_MAC)
    .ip(src=CLIENT, dst=SERVER)
    .icmp(identifier=1, sequence=1)
    .payload(size=32)
    .build(), 800_000)

write_pcap(collection, path="session.pcap", link_type=LINKTYPE_ETHERNET)
print(f"Wrote {len(collection)} packets to session.pcap")
```

Open `session.pcap` in Wireshark and you will see the complete exchange across
all three protocols in the correct order with accurate timestamps.

---

### `PacketBuilder`

The primary entry point. Build packets layer by layer using a fluent API, then
call `.build()` or `.fragment()` to produce the final bytes.

```python
from packet_generator import PacketBuilder

pkt = (PacketBuilder()
    .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02", pad=False)
    .vlan(vid=100, pcp=0, dei=0)          # optional; only meaningful after .ethernet()
    .ip(src="10.0.0.1", dst="10.0.0.2", ttl=64)
    .tcp(src_port=12345, dst_port=80, seq=0, ack=0, flags=TCP_ACK, window=65535)
    .payload(size=64)                     # OR .payload(data=b"hello")
    .build()
)
```

Omitting `.ethernet()` produces a raw IP packet with no layer-2 framing.
Omitting `.payload()` produces a zero-byte payload.

#### Layer methods

| Method | Description |
|--------|-------------|
| `.ethernet(src_mac, dst_mac, pad=False)` | Add an Ethernet II header. `pad=True` zero-pads the frame to the IEEE 802.3 minimum of 60 bytes. |
| `.vlan(vid, pcp=0, dei=0)` | Add an 802.1Q VLAN tag (call after `.ethernet()`). |
| `.ip(src, dst, ttl=64, tos=0, identification=0, flags=0b010, fragment_offset=0, traffic_class=0, flow_label=0)` | Add an IPv4 or IPv6 header (auto-detected from `src`). IPv4-only params are ignored for IPv6 and vice versa. |
| `.tcp(src_port=12345, dst_port=80, seq=0, ack=0, flags=TCP_ACK, window=65535, urgent_ptr=0, reserved=0, options=None)` | Add a TCP transport header. |
| `.udp(src_port=12345, dst_port=80)` | Add a UDP transport header. |
| `.icmp(type=8, code=0, identifier=1, sequence=1)` | Add an ICMPv4 transport header (use with IPv4 addresses). |
| `.icmpv6(type=128, code=0, identifier=1, sequence=1)` | Add an ICMPv6 transport header (use with IPv6 addresses). |
| `.payload(size=0, data=None)` | Set the payload. `data` takes precedence over `size`. Random bytes are generated for `size` and cached. |

#### Assembly methods

```python
pkt: bytes         = builder.build()             # assemble and return the complete packet
frags: list[bytes] = builder.fragment(mtu=1500)  # fragment into ≤ mtu-byte IP datagrams
```

`.build()` raises `ValueError` if `.ip()` or a transport method has not been called.

---

### Header dataclasses

Each header type is also available for direct use when you need fine-grained
control over individual fields.

#### `EthernetHeader` and `VLANTag`

```python
from packet_generator import EthernetHeader, VLANTag
from packet_generator.ethernet import build_ethernet_header, ETHERTYPE_IPV4, ETHERTYPE_IPV6

# Plain Ethernet II header — 14 bytes
hdr = EthernetHeader(
    dst_mac="aa:bb:cc:dd:ee:ff",
    src_mac="11:22:33:44:55:66",
    ethertype=ETHERTYPE_IPV4,   # 0x0800
)
raw: bytes = build_ethernet_header(hdr)  # 14 bytes

# IEEE 802.1Q tagged header — 18 bytes
#   dst_mac (6) | src_mac (6) | TPID 0x8100 (2) | TCI (2) | inner EtherType (2)
hdr = EthernetHeader(
    dst_mac="aa:bb:cc:dd:ee:ff",
    src_mac="11:22:33:44:55:66",
    ethertype=ETHERTYPE_IPV4,
    vlan_tag=VLANTag(vid=100, pcp=3, dei=0),
)
raw: bytes = build_ethernet_header(hdr)  # 18 bytes
```

`VLANTag` fields:

| Field | Range | Description |
|-------|-------|-------------|
| `vid` | 0–4095 | VLAN Identifier. Values 1–4094 identify a specific VLAN; 0 = priority tag only; 4095 reserved. |
| `pcp` | 0–7 | Priority Code Point (IEEE 802.1p class of service). |
| `dei` | 0–1 | Drop Eligible Indicator — frame may be dropped under congestion. |

#### `IPHeader` (IPv4)

```python
from packet_generator import IPHeader
from packet_generator.ip import build_ip_header
import socket

hdr = IPHeader(
    src="10.0.0.1",
    dst="10.0.0.2",
    protocol=socket.IPPROTO_TCP,
    ttl=64,
)
raw: bytes = build_ip_header(hdr, payload=b"\x00" * 20)  # 20 bytes, checksum included
```

#### `IPv6Header`

```python
from packet_generator import IPv6Header
from packet_generator.ipv6 import build_ipv6_header

hdr = IPv6Header(
    src="fe80::1",
    dst="fe80::2",
    next_header=6,   # TCP
    hop_limit=64,
)
raw: bytes = build_ipv6_header(hdr, payload=b"\x00" * 20)  # 40 bytes, no checksum
```

#### TCP flag constants

```python
from packet_generator import TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG
```

| Constant | Value | Description |
|----------|-------|-------------|
| `TCP_FIN` | `0x001` | No more data from sender |
| `TCP_SYN` | `0x002` | Synchronise sequence numbers |
| `TCP_RST` | `0x004` | Reset the connection |
| `TCP_PSH` | `0x008` | Push buffered data to the application |
| `TCP_ACK` | `0x010` | Acknowledgement field is significant |
| `TCP_URG` | `0x020` | Urgent pointer field is significant |
| `TCP_ECE` | `0x040` | ECN-Echo — SYN=1: sender is ECN-capable; SYN=0: congestion experienced (RFC 3168) |
| `TCP_CWR` | `0x080` | Congestion Window Reduced — sender reduced its congestion window (RFC 3168) |

Combine flags with `|`:

```python
flags=TCP_PSH | TCP_ACK          # 0x018 — data segment
flags=TCP_SYN | TCP_ACK          # 0x012 — SYN-ACK handshake reply
flags=TCP_FIN | TCP_ACK          # 0x011 — graceful close
flags=TCP_SYN | TCP_ECE | TCP_CWR  # ECN-capable SYN
```

#### `TCPHeader`

```python
from packet_generator import TCPHeader, TCPOptions
from packet_generator import TCP_SYN, TCP_ACK, TCP_PSH, TCP_RST, TCP_FIN, TCP_URG, TCP_ECE, TCP_CWR
from packet_generator.tcp import build_tcp_header

hdr = TCPHeader(src_port=12345, dst_port=80, flags=TCP_SYN)
raw: bytes = build_tcp_header(hdr, payload=b"", src_ip="10.0.0.1", dst_ip="10.0.0.2")
# For IPv6: ip_version=6

# Combine flags with |
hdr = TCPHeader(src_port=12345, dst_port=80, flags=TCP_PSH | TCP_ACK)
raw: bytes = build_tcp_header(hdr, payload=b"hello", src_ip="10.0.0.1", dst_ip="10.0.0.2")

# SYN with MSS, Window Scale, SACK Permitted, and Timestamps options
hdr = TCPHeader(
    src_port=12345, dst_port=80, flags=TCP_SYN,
    options=TCPOptions(mss=1460, window_scale=7, sack_permitted=True, timestamps=(0, 0)),
)
raw: bytes = build_tcp_header(hdr, payload=b"", src_ip="10.0.0.1", dst_ip="10.0.0.2")

# Custom sequence number
hdr = TCPHeader(src_port=12345, dst_port=80, seq=0xDEADBEEF)
raw: bytes = build_tcp_header(hdr, payload=b"", src_ip="10.0.0.1", dst_ip="10.0.0.2")
```

#### `TCPOptions`

```python
from packet_generator import TCPOptions

TCPOptions(
    mss: int | None = None,
    window_scale: int | None = None,
    sack_permitted: bool = False,
    sack_blocks: list[tuple[int, int]] = [],
    timestamps: tuple[int, int] | None = None,
)
```

| Field | Description |
|-------|-------------|
| `mss` | Maximum Segment Size in bytes (kind 2). Typical: `1460` (Ethernet/IPv4), `1440` (Ethernet/IPv6). |
| `window_scale` | Window Scale shift count 0–14 (kind 3, RFC 7323). Scales `window` by `2**window_scale`. |
| `sack_permitted` | SACK Permitted flag (kind 4). Send on SYN/SYN-ACK to enable selective acknowledgement. |
| `sack_blocks` | List of `(left_edge, right_edge)` 32-bit sequence-number pairs (kind 5, RFC 2018). Up to 4 blocks. |
| `timestamps` | `(TSval, TSecr)` tuple of 32-bit values (kind 8, RFC 7323). |

Options are encoded in the order MSS → Window Scale → SACK Permitted → Timestamps → SACK, padded to a 4-byte boundary with NOP bytes. The Data Offset field is updated automatically.

#### `UDPHeader`

```python
from packet_generator import UDPHeader
from packet_generator.udp import build_udp_header

hdr = UDPHeader(src_port=5000, dst_port=53)
raw: bytes = build_udp_header(hdr, payload=b"query", src_ip="10.0.0.1", dst_ip="8.8.8.8")
```

#### `ICMPHeader` (ICMPv4)

```python
from packet_generator import ICMPHeader
from packet_generator.icmp import build_icmp_header

hdr = ICMPHeader(type=8, code=0, identifier=1, sequence=1)  # Echo Request
raw: bytes = build_icmp_header(hdr, payload=b"ping")  # 8 bytes, checksum included
```

#### `ICMPv6Header`

```python
from packet_generator import ICMPv6Header
from packet_generator.icmpv6 import build_icmpv6_header

hdr = ICMPv6Header(type=128, code=0, identifier=1, sequence=1)  # Echo Request
raw: bytes = build_icmpv6_header(hdr, payload=b"ping", src_ip="::1", dst_ip="::2")
```

---

### `write_pcap`

Write one or more raw packet byte strings to a libpcap (`.pcap`) file.

```python
from packet_generator import write_pcap, LINKTYPE_ETHERNET, LINKTYPE_RAW
```

```python
write_pcap(
    packets: list[tuple[bytes, int, int]],
    *,
    path: str | os.PathLike | None = None,
    file_object: io.IOBase | None = None,
    link_type: int = LINKTYPE_ETHERNET,
    nanoseconds: bool = False,
)
```

Each element of `packets` is a `(raw_bytes, ts_sec, ts_frac)` tuple where
`ts_frac` is microseconds when `nanoseconds=False` (default) or nanoseconds
when `nanoseconds=True`.

| Parameter | Description |
|-----------|-------------|
| `packets` | List of `(raw_bytes, ts_sec, ts_frac)` tuples, one per pcap record. |
| `path` | Destination file path. Created or overwritten. |
| `file_object` | Destination file object (open in binary mode). |
| `link_type` | Link-layer type written into the global header. `LINKTYPE_ETHERNET` (`1`, default) or `LINKTYPE_RAW` (`101`). |
| `nanoseconds` | When `True`, writes magic `0xA1B23C4D` so readers interpret `ts_frac` as nanoseconds. Default `False` writes magic `0xA1B2C3D4` (microseconds). |

```python
import time
from packet_generator import PacketBuilder, Protocol, write_pcap, LINKTYPE_RAW

# Microsecond timestamps (default)
t = int(time.time())
pkts = [
    (PacketBuilder("10.0.0.1", "10.0.0.2", Protocol.TCP).build(), t, 0),
    (PacketBuilder("10.0.0.2", "10.0.0.1", Protocol.TCP).build(), t, 500_000),
]
write_pcap(pkts, path="out.pcap")

# Nanosecond timestamps
now_ns = time.time_ns()
sec, nsec = divmod(now_ns, 1_000_000_000)
pkts = [(PacketBuilder("10.0.0.1", "10.0.0.2", Protocol.UDP).build(), sec, nsec)]
write_pcap(pkts, path="out_ns.pcap", nanoseconds=True)

# Raw IP packets (no Ethernet header)
pkts = [(PacketBuilder("::1", "::2", Protocol.UDP, include_ethernet=False).build(), 0, 0)]
write_pcap(pkts, path="raw.pcap", link_type=LINKTYPE_RAW)
```

---

### `write_pcapng`

Write one or more raw packet byte strings to a pcapng (`.pcapng`) file.
pcapng is the successor to libpcap and is supported by Wireshark, tcpdump,
and most modern packet analysis tools.

```python
from packet_generator.pcap import write_pcapng, LINKTYPE_ETHERNET, LINKTYPE_RAW
```

```python
write_pcapng(
    packets: list[tuple[bytes, int, int]],
    *,
    path: str | os.PathLike | None = None,
    file_object: io.IOBase | None = None,
    link_type: int = LINKTYPE_ETHERNET,
    nanoseconds: bool = False,
)
```

The call signature is identical to `write_pcap`.  The output file contains one
Section Header Block, one Interface Description Block (with the appropriate
`if_tsresol` option), and one Enhanced Packet Block per packet.

```python
import time
from packet_generator import PacketBuilder, Protocol
from packet_generator.pcap import write_pcapng

now_ns = time.time_ns()
sec, nsec = divmod(now_ns, 1_000_000_000)
pkt = PacketBuilder("10.0.0.1", "10.0.0.2", Protocol.TCP).build()
write_pcapng([(pkt, sec, nsec)], path="out.pcapng", nanoseconds=True)
```

---

### `read_pcap`

Read a libpcap (`.pcap`) **or pcapng (`.pcapng`)** file.  The format is
detected automatically from the file's first four bytes — no extension
checking, no extra arguments needed.

```python
from packet_parser.pcap import read_pcap
```

```python
read_pcap(
    *,
    path: str | os.PathLike | None = None,
    file_object: io.IOBase | None = None,
) -> PcapFile
```

`PcapFile` has two fields:

| Attribute | Type | Description |
|-----------|------|-------------|
| `header` | `PcapFileHeader` | Global pcap header metadata |
| `packets` | `list[tuple[bytes, int, int]]` | `(raw_bytes, ts_sec, ts_frac)` per record |

`PcapFileHeader` fields:

| Field | Description |
|-------|-------------|
| `link_type` | Link-layer type |
| `version_major` / `version_minor` | Format version — `2`/`4` for pcap, `1`/`0` for pcapng |
| `snaplen` | Maximum capture length |
| `nanoseconds` | `True` when the file uses nanosecond timestamps |

For pcap: supports little-endian and big-endian files and both the microsecond
(`0xA1B2C3D4`) and nanosecond (`0xA1B23C4D`) magic variants.
For pcapng: link type and timestamp resolution are read from the Interface
Description Block; EPB and Obsolete Packet Block records are supported.

```python
from packet_parser.pcap import read_pcap
from packet_parser import ethernet_packet_parser, ip_packet_parser, tcp_packet_parser

pcap = read_pcap(path="capture.pcap")
print(f"link type {pcap.header.link_type}, nanoseconds={pcap.header.nanoseconds}")

for raw, ts_sec, ts_frac in pcap.packets:
    eth_size, ethertype, eth_hdr = ethernet_packet_parser(raw)
    ip_size,  proto,     ip_hdr  = ip_packet_parser(raw[eth_size:])
    tcp_size, dst_port,  tcp_hdr = tcp_packet_parser(raw[eth_size + ip_size:])
    print(f"  {ts_sec}.{ts_frac:06d}  {ip_hdr.src} → {ip_hdr.dst}:{dst_port}")
```

---

## `packet_parser`

Each parser function lives in its own module and follows the same calling
convention:

```
(header_size, next_layer_id, HeaderObject | None) = parser(data: bytes)
```

On success `header_size > 0` and the next layer's bytes start at
`data[header_size:]`. On failure all three fields are `(0, None, None)`.

```python
from packet_parser import (
    ethernet_packet_parser,
    vlan_packet_parser,
    ip_packet_parser,
    icmp_packet_parser,
    icmpv6_packet_parser,
    udp_packet_parser,
    tcp_packet_parser,
)
```

| Parser | Module | Returns `next_layer_id` as | `HeaderObject` type |
|--------|--------|---------------------------|---------------------|
| `ethernet_packet_parser` | `packet_parser.ethernet` | EtherType | `EthernetHeader` |
| `vlan_packet_parser` | `packet_parser.vlan` | Inner EtherType | `VLANTag` |
| `ip_packet_parser` | `packet_parser.ip` | IP protocol number | `IPHeader` or `IPv6Header` |
| `icmp_packet_parser` | `packet_parser.icmp` | ICMP type | `ICMPHeader` |
| `icmpv6_packet_parser` | `packet_parser.icmpv6` | ICMPv6 type | `ICMPv6Header` |
| `udp_packet_parser` | `packet_parser.udp` | Destination port | `UDPHeader` |
| `tcp_packet_parser` | `packet_parser.tcp` | Destination port | `TCPHeader` |

The returned `HeaderObject` is the same dataclass produced by the corresponding
`packet_generator` builder, so all fields are directly comparable.

### `parse_packet` and `parse_pcap_packet`

`packet_parser.parser` provides a high-level entry point that chains all layer
parsers automatically and returns a single `ParsedPacket` dataclass.

#### `ParsedPacket`

| Field | Type | Description |
|-------|------|-------------|
| `ethernet` | `EthernetHeader \| None` | Ethernet II header (VLAN tag included when present) |
| `ip` | `IPHeader \| IPv6Header \| None` | IPv4 or IPv6 header |
| `transport` | `TCPHeader \| UDPHeader \| ICMPHeader \| ICMPv6Header \| None` | Transport-layer header |
| `payload` | `bytes` | Bytes after the deepest parsed header |
| `ts_sec` | `int` | Capture timestamp whole seconds (populated by `parse_pcap_packet`) |
| `ts_frac` | `int` | Capture timestamp sub-second fraction — µs or ns (populated by `parse_pcap_packet`) |

#### `parse_packet(data, *, link_type=LINKTYPE_ETHERNET)`

```python
from packet_parser.parser import parse_packet
from packet_generator import PacketBuilder, Protocol

raw = PacketBuilder("10.0.0.1", "10.0.0.2", Protocol.TCP, dst_port=443).build()
pkt = parse_packet(raw)

print(pkt.ip.src, "→", pkt.ip.dst)
print("dst_port:", pkt.transport.dst_port)
```

Pass `link_type=LINKTYPE_RAW` for packets without an Ethernet header.

#### `parse_pcap_packet(record, file_header)`

Parses one `(data, ts_sec, ts_frac)` record from `PcapFile.packets`, using the
`link_type` from `file_header` and copying the timestamps into the result.

```python
from packet_parser.pcap import read_pcap
from packet_parser.parser import parse_pcap_packet

pcap = read_pcap(path="capture.pcap")
for record in pcap.packets:
    pkt = parse_pcap_packet(record, pcap.header)
    if pkt.transport:
        frac_label = "ns" if pcap.header.nanoseconds else "µs"
        print(f"{pkt.ts_sec}.{pkt.ts_frac:09d} {frac_label}  "
              f"{pkt.ip.src} → {pkt.ip.dst}:{pkt.transport.dst_port}")
```

#### `parse_pcap_file(*, path=…, file_object=…, output=…)`

Reads a pcap file, parses every packet through all layers, and returns a JSON
string in the format accepted by `packet_lab.py build --config`.

- Per-packet `metadata` block contains `timestamp_s` and `timestamp_us` (or
  `timestamp_ns` for nanosecond-resolution files).
- When the source file uses nanosecond timestamps, `"nanoseconds": true` is
  added to the top-level `file_metadata` block automatically.
- The top-level `file_metadata` block always includes `from_file` (set to the
  source path) and `type` (auto-detected as `pcap` or `pcapng`).
- Pass `output={…}` to pre-populate or override fields; they are merged with
  the auto-detected fields.

```python
from packet_parser.parser import parse_pcap_file

# Parse and print
print(parse_pcap_file(path="capture.pcap"))

# Parse with explicit from_file metadata
json_cfg = parse_pcap_file(path="capture.pcap", output={"from_file": "capture.pcap"})
with open("replay.json", "w") as f:
    f.write(json_cfg)
# python packet_lab.py build --config replay.json
```

### Chaining parsers

```python
from packet_parser import ethernet_packet_parser, ip_packet_parser, tcp_packet_parser

raw = b"..."  # bytes from a pcap record or socket

eth_size, ethertype, eth_hdr = ethernet_packet_parser(raw)
ip_size,  proto,     ip_hdr  = ip_packet_parser(raw[eth_size:])
tcp_size, dst_port,  tcp_hdr = tcp_packet_parser(raw[eth_size + ip_size:])

if tcp_hdr:
    print(f"{ip_hdr.src}:{tcp_hdr.src_port} → {ip_hdr.dst}:{tcp_hdr.dst_port}")
    print(f"  seq={tcp_hdr.seq}  ack={tcp_hdr.ack}  flags=0x{tcp_hdr.flags:02x}")
```

### `update_config` — convert parsed headers to a JSON config

`packet_parser.to_config` converts parsed header objects into the JSON config
format accepted by `packet_lab.py build --config`. Call `update_config(config, layer)` once
per parsed layer; it dispatches on the header type, fills the matching section
of the dict, and returns the same dict for optional chaining.

| *layer* type | Section written |
|---|---|
| `EthernetHeader` | `ethernet` (src_mac, dst_mac, enabled, optional vlan) |
| `IPHeader` / `IPv6Header` | `network` (src, dst, protocol, ttl; non-default fields only) |
| `TCPHeader` | `transport` (src_port, dst_port, seq, ack, flags, window; optional options) |
| `UDPHeader` | `transport` (src_port, dst_port) |
| `ICMPHeader` / `ICMPv6Header` | `transport` (type, code, identifier, sequence) |
| `bytes` | `payload` (hex-encoded) |

```python
from packet_parser import ethernet_packet_parser, ip_packet_parser, tcp_packet_parser
from packet_parser.pcap import read_pcap
from packet_parser.to_config import update_config, to_json_config, to_json_string

pcap = read_pcap(path="capture.pcap")
packet_configs = []

for raw, ts_sec, ts_frac in pcap.packets:
    cfg = {}
    eth_size, _, eth_hdr = ethernet_packet_parser(raw)
    update_config(cfg, eth_hdr)
    ip_size,  _, ip_hdr  = ip_packet_parser(raw[eth_size:])
    update_config(cfg, ip_hdr)
    tcp_size, _, tcp_hdr = tcp_packet_parser(raw[eth_size + ip_size:])
    update_config(cfg, tcp_hdr)
    payload = raw[eth_size + ip_size + tcp_size:]
    if payload:
        update_config(cfg, payload)
    cfg.setdefault("metadata", {}).update({"timestamp_s": ts_sec, "timestamp_us": ts_frac})
    packet_configs.append(cfg)

# Write config JSON that can be replayed with: python packet_lab.py build --config replay.json
replay = to_json_config(packet_configs, file_metadata={"from_file": "capture.pcap", "type": "pcap"})
with open("replay.json", "w") as f:
    f.write(to_json_string(replay))
```

---

## Packet sizes

| Protocol | IP version | With Ethernet | With Ethernet + VLAN | Without Ethernet |
|----------|-----------|--------------|---------------------|-----------------|
| TCP      | IPv4      | 14 + 20 + 20 + N | 18 + 20 + 20 + N | 20 + 20 + N |
| UDP      | IPv4      | 14 + 20 + 8 + N  | 18 + 20 + 8 + N  | 20 + 8 + N  |
| ICMP     | IPv4      | 14 + 20 + 8 + N  | 18 + 20 + 8 + N  | 20 + 8 + N  |
| TCP      | IPv6      | 14 + 40 + 20 + N | 18 + 40 + 20 + N | 40 + 20 + N |
| UDP      | IPv6      | 14 + 40 + 8 + N  | 18 + 40 + 8 + N  | 40 + 8 + N  |
| ICMPv6   | IPv6      | 14 + 40 + 8 + N  | 18 + 40 + 8 + N  | 40 + 8 + N  |

*N = payload size in bytes. The 802.1Q VLAN tag adds 4 bytes to the Ethernet header (14 → 18 bytes).*

---

## CLI

`packet_lab.py` is the single command-line entry point with two subcommands:
`build` constructs packets and writes them to a pcap or pcapng file (or prints
hex to stdout); `parse` reads a pcap or pcapng file and produces a JSON config
that can be fed back to `build --config`.

### `packet_lab.py build`

```
python packet_lab.py build <config.json> (--pcap FILE | --pcapng FILE)
```

| Argument | Description |
|----------|-------------|
| `FILE` | *(required)* JSON config file with a `packets` array |
| `--pcap FILE` | Write packets to a libpcap (`.pcap`) file |
| `--pcapng FILE` | Write packets to a pcapng (`.pcapng`) file |

`--pcap` and `--pcapng` are mutually exclusive; one is required.

#### Examples

```bash
# Build from a JSON config and write a pcap file
python packet_lab.py build packets.json --pcap out.pcap

# Build from a JSON config and write a pcapng file
python packet_lab.py build packets.json --pcapng out.pcapng
```

### `packet_lab.py parse`

Parses every packet in a pcap or pcapng file and writes the corresponding
JSON config.  Both formats are accepted transparently.

```
python packet_lab.py parse <pcap-file> [options]
```

| Option | Description |
|--------|-------------|
| `FILE` | *(required)* Input `.pcap` or `.pcapng` file to parse |
| `--output FILE`, `-o FILE` | Write the JSON config to FILE instead of printing to stdout |
| `--replay-pcap FILE` | Set `file_metadata.type` to `pcap` in the generated config |
| `--replay-pcapng FILE` | Set `file_metadata.type` to `pcapng` in the generated config (mutually exclusive with `--replay-pcap`) |

#### Examples

```bash
# Print JSON config to stdout
python packet_lab.py parse capture.pcap

# Save JSON config to a file
python packet_lab.py parse capture.pcap --output replay.json

# Save and embed a replay pcap path in the config
python packet_lab.py parse capture.pcap --output replay.json --replay-pcap replayed.pcap

# Parse a pcapng file (auto-detected)
python packet_lab.py parse capture.pcapng --output replay.json

# Round-trip: parse pcapng → config → rebuild as pcapng
python packet_lab.py parse capture.pcapng --output config.json
python packet_lab.py build config.json --pcapng out.pcapng

# Round-trip: capture → config → rebuild as pcap
python packet_lab.py parse capture.pcap --output config.json
python packet_lab.py build config.json --pcap out.pcap
```

---

## Project structure

```
packet-generator/
  packet_generator/
    __init__.py        # public API re-exports
    builder.py         # PacketBuilder and Protocol — main entry point
    checksum.py        # RFC 1071 one's-complement checksum utility
    ethernet.py        # Ethernet II header (14 bytes, 18 with 802.1Q VLAN tag)
    fragmentation.py   # fragment_ipv4 and fragment_ipv6
    ip.py              # IPv4 header (20 bytes)
    ipv6.py            # IPv6 header (40 bytes)
    tcp.py             # TCP header (20+ bytes, variable via data offset)
    udp.py             # UDP header (8 bytes)
    icmp.py            # ICMPv4 header (8 bytes)
    icmpv6.py          # ICMPv6 header (8 bytes)
    pcap.py            # write_pcap / write_pcapng — libpcap and pcapng file writers
  packet_parser/
    __init__.py        # exports all parsers with distinct names
    ethernet.py        # parse Ethernet II + optional 802.1Q VLAN tag
    vlan.py            # parse IEEE 802.1Q VLAN tag (4 bytes)
    ip.py              # parse IPv4 / IPv6 (version auto-detected)
    icmp.py            # parse ICMPv4 header (8 bytes)
    icmpv6.py          # parse ICMPv6 header (8 bytes)
    udp.py             # parse UDP header (8 bytes)
    tcp.py             # parse TCP header (variable length)
    pcap.py            # read_pcap — libpcap and pcapng file reader (auto-detect)
    to_config.py       # update_config / to_json_config / to_json_string
    parser.py          # parse_packet / parse_pcap_packet / parse_pcap_file / ParsedPacket
  tests/
    test_builder.py
    test_checksum.py
    test_fragmentation.py
    test_generator_ethernet.py
    test_generator_icmp.py
    test_generator_ip.py
    test_generator_ipv6.py
    test_generator_pcap.py
    test_generator_pcapng.py
    test_generator_tcp.py
    test_generator_udp.py
    test_parser_ethernet.py
    test_parser_icmp.py
    test_parser_ip.py
    test_parser_pcap.py
    test_parser_pcapng.py
    test_parser_tcp.py
    test_parser_udp.py
    test_parser_parser.py
    test_parser_to_config.py
    test_parser_vlan.py
  packet_lab.py   # unified CLI — 'build' and 'parse' subcommands
  README.md
```

---

## Running the tests

```bash
python -m unittest discover tests/ -v
```

All tests run in under a second and require no third-party packages.

---

## RFC references

| Standard | Scope |
|----------|-------|
| RFC 791  | Internet Protocol (IPv4) — including fragmentation |
| RFC 768  | User Datagram Protocol (UDP) |
| RFC 792  | Internet Control Message Protocol (ICMPv4) |
| RFC 793 / RFC 9293 | Transmission Control Protocol (TCP) |
| RFC 1071 | Computing the Internet Checksum |
| RFC 4443 | Internet Control Message Protocol for IPv6 (ICMPv6) |
| RFC 8200 | Internet Protocol, Version 6 (IPv6) — including §4.5 Fragment Extension Header |
| IEEE 802.3 | Ethernet |
| IEEE 802.1Q | Virtual LANs (VLAN tagging) |
