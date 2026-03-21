# packet-generator

A pure-Python library for building and fragmenting complete, byte-accurate raw
network packets. Construct Ethernet II frames containing IPv4 or IPv6 headers,
TCP, UDP, ICMPv4, and ICMPv6 transport layers — all with correct checksums
computed automatically per RFC. Large payloads can be split into RFC-compliant
IP fragments in one call.

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
- CLI for quick packet inspection and binary output, with `--mtu` for on-the-fly fragmentation and `--config` for JSON-driven multi-packet definitions

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

```python
from packet_generator import PacketBuilder, Protocol

# IPv4 TCP packet — Ethernet + IP + TCP + 64 random payload bytes
pkt = PacketBuilder(
    src_ip="192.168.1.10",
    dst_ip="8.8.8.8",
    protocol=Protocol.TCP,
    payload_size=64,
    dst_port=443,
).build()
print(f"Built {len(pkt)}-byte packet: {pkt.hex()}")

# IPv6 UDP packet — no Ethernet header
pkt = PacketBuilder(
    src_ip="fe80::1",
    dst_ip="fe80::2",
    protocol=Protocol.UDP,
    payload_size=20,
    include_ethernet=False,
).build()

# ICMPv6 Echo Request with an explicit payload
pkt = PacketBuilder(
    src_ip="::1",
    dst_ip="::2",
    protocol=Protocol.ICMPv6,
    payload=b"hello ipv6",
).build()

# IPv4 UDP packet on VLAN 100 with priority 5
pkt = PacketBuilder(
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    protocol=Protocol.UDP,
    payload_size=32,
    vlan_id=100,
    vlan_pcp=5,
).build()
# Ethernet header is now 18 bytes (TPID 0x8100 + TCI + inner EtherType)
```

---

## Multi-protocol example

The following example builds a realistic packet capture containing a full TCP
session (three-way handshake, one data exchange, and a FIN teardown), a UDP
DNS query, and an ICMPv4 Echo Request. All packets are written to a single
`.pcap` file that can be opened in Wireshark or replayed with `tcpreplay`.

```python
import time
from packet_generator import PacketBuilder, Protocol, write_pcap
from packet_generator import TCP_SYN, TCP_ACK, TCP_PSH, TCP_FIN

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
C_MAC  = "00:00:00:00:00:01"
S_MAC  = "00:00:00:00:00:02"
C_PORT = 54321
S_PORT = 80

def build(src, dst, smac, dmac, proto, seq=0, ack=0, flags=TCP_ACK,
          sport=C_PORT, dport=S_PORT, payload=None, size=0):
    return PacketBuilder(
        src_ip=src, dst_ip=dst,
        src_mac=smac, dst_mac=dmac,
        protocol=proto,
        src_port=sport, dst_port=dport,
        tcp_seq=seq, tcp_ack=ack, tcp_flags=flags,
        payload=payload, payload_size=size,
    ).build()

pkts = []
collection = []
t = int(time.time())

def append(pkt, usec):
    collection.append((pkt, t, usec))

# ── TCP three-way handshake ──────────────────────────────────────────────────
# SYN  (client → server)
append(build(CLIENT, SERVER, C_MAC, S_MAC, Protocol.TCP,
             seq=1000, ack=0, flags=TCP_SYN), 0)
# SYN-ACK  (server → client)
append(build(SERVER, CLIENT, S_MAC, C_MAC, Protocol.TCP,
             seq=5000, ack=1001, flags=TCP_SYN | TCP_ACK,
             sport=S_PORT, dport=C_PORT), 100_000)
# ACK  (client → server)
append(build(CLIENT, SERVER, C_MAC, S_MAC, Protocol.TCP,
             seq=1001, ack=5001, flags=TCP_ACK), 200_000)

# ── TCP data exchange ────────────────────────────────────────────────────────
request  = b"GET / HTTP/1.1\r\nHost: 10.0.0.2\r\n\r\n"
response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello"

# PSH+ACK carrying the HTTP request  (client → server)
append(build(CLIENT, SERVER, C_MAC, S_MAC, Protocol.TCP,
             seq=1001, ack=5001, flags=TCP_PSH | TCP_ACK,
             payload=request), 300_000)
# PSH+ACK carrying the HTTP response  (server → client)
append(build(SERVER, CLIENT, S_MAC, C_MAC, Protocol.TCP,
             seq=5001, ack=1001 + len(request), flags=TCP_PSH | TCP_ACK,
             sport=S_PORT, dport=C_PORT, payload=response), 400_000)

# ── TCP teardown  (FIN-ACK exchange) ────────────────────────────────────────
append(build(CLIENT, SERVER, C_MAC, S_MAC, Protocol.TCP,
             seq=1001 + len(request), ack=5001 + len(response),
             flags=TCP_FIN | TCP_ACK), 500_000)
append(build(SERVER, CLIENT, S_MAC, C_MAC, Protocol.TCP,
             seq=5001 + len(response), ack=1001 + len(request) + 1,
             flags=TCP_FIN | TCP_ACK, sport=S_PORT, dport=C_PORT), 600_000)

# ── UDP DNS query ────────────────────────────────────────────────────────────
dns_query = bytes.fromhex(
    "0001010000010000000000000377777706676f6f676c6503636f6d0000010001"
)
append(PacketBuilder(
    src_ip=CLIENT, dst_ip="8.8.8.8",
    src_mac=C_MAC, dst_mac=S_MAC,
    protocol=Protocol.UDP,
    src_port=54400, dst_port=53,
    payload=dns_query,
).build(), 700_000)

# ── ICMPv4 Echo Request (ping) ───────────────────────────────────────────────
append(PacketBuilder(
    src_ip=CLIENT, dst_ip=SERVER,
    src_mac=C_MAC, dst_mac=S_MAC,
    protocol=Protocol.ICMP,
    icmp_identifier=1, icmp_sequence=1,
    payload_size=32,
).build(), 800_000)

write_pcap(collection, path="session.pcap", link_type=LINKTYPE_ETHERNET)
print(f"Wrote {len(pkts)} packets to session.pcap")
```

Open `session.pcap` in Wireshark and you will see the complete exchange across
all three protocols in the correct order with accurate timestamps.

---

## Fragmentation

### High-level — `PacketBuilder.fragment(mtu)`

```python
from packet_generator import PacketBuilder, Protocol

# Split a 4000-byte UDP payload across ~3 IPv4 fragments (MTU 1500)
fragments = PacketBuilder(
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    protocol=Protocol.UDP,
    payload_size=4000,
).fragment(mtu=1500)

print(f"{len(fragments)} fragments")
for i, frag in enumerate(fragments):
    print(f"  fragment {i+1}: {len(frag)} bytes")

# IPv6 fragmentation uses the Fragment Extension Header (RFC 8200 §4.5)
fragments = PacketBuilder(
    src_ip="fe80::1",
    dst_ip="fe80::2",
    protocol=Protocol.TCP,
    payload_size=3000,
).fragment(mtu=1280)   # IPv6 minimum MTU

# No Ethernet header on each fragment
fragments = PacketBuilder(
    src_ip="::1",
    dst_ip="::2",
    protocol=Protocol.UDP,
    payload_size=2000,
    include_ethernet=False,
).fragment(mtu=576)    # IPv4 minimum reassembly buffer
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

### `PacketBuilder`

The primary entry point. Assembles all layers into a single `bytes` object.

```python
PacketBuilder(
    src_ip: str,
    dst_ip: str,
    protocol: Protocol,
    payload_size: int = 0,
    *,
    src_mac: str = "00:00:00:00:00:01",
    dst_mac: str = "00:00:00:00:00:02",
    src_port: int = 12345,
    dst_port: int = 80,
    ttl: int = 64,
    payload: bytes | None = None,
    include_ethernet: bool = True,
    tcp_seq: int = 0,
    vlan_id: int | None = None,
    vlan_pcp: int = 0,
    vlan_dei: int = 0,
)
```

| Parameter | Description |
|-----------|-------------|
| `src_ip` | Source IPv4 (dotted-decimal) or IPv6 (colon-hex) address. IP version is auto-detected. |
| `dst_ip` | Destination IP address in the same format. |
| `protocol` | `Protocol.TCP`, `Protocol.UDP`, `Protocol.ICMP` (IPv4 only), or `Protocol.ICMPv6` (IPv6 only). |
| `payload_size` | Number of random bytes to use as the payload. Ignored when `payload` is given. |
| `src_mac` | Source MAC address for the Ethernet header (colon or hyphen separated). |
| `dst_mac` | Destination MAC address for the Ethernet header. |
| `src_port` | Source port number (TCP/UDP only). |
| `dst_port` | Destination port number (TCP/UDP only). |
| `ttl` | IPv4 Time-To-Live or IPv6 Hop Limit. |
| `payload` | Explicit payload bytes. Overrides `payload_size`. |
| `include_ethernet` | Prepend an Ethernet II header when `True` (default). |
| `tcp_seq` | 32-bit TCP sequence number. Ignored for UDP and ICMP. Defaults to `0`. |
| `vlan_id` | IEEE 802.1Q VLAN ID (1–4094). When set, a 4-byte 802.1Q tag is inserted in the Ethernet header, expanding it from 14 to 18 bytes. Ignored when `include_ethernet=False`. Defaults to `None` (no tag). |
| `vlan_pcp` | VLAN Priority Code Point (0–7, IEEE 802.1p). Ignored when `vlan_id` is `None`. Defaults to `0`. |
| `vlan_dei` | VLAN Drop Eligible Indicator (0 or 1). Ignored when `vlan_id` is `None`. Defaults to `0`. |

#### Methods

```python
pkt: bytes          = builder.build()             # assemble and return the complete packet
frags: list[bytes]  = builder.fragment(mtu=1500)  # fragment into ≤ mtu-byte IP datagrams
data: bytes         = builder.payload             # the payload bytes (lazily generated, then cached)
```

---

### `Protocol`

```python
from packet_generator import Protocol

Protocol.TCP     # works with IPv4 and IPv6
Protocol.UDP     # works with IPv4 and IPv6
Protocol.ICMP    # ICMPv4 — requires IPv4 addresses
Protocol.ICMPv6  # ICMPv6 — requires IPv6 addresses
```

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
    path: str | os.PathLike,
    packets: list[bytes],
    *,
    link_type: int = LINKTYPE_ETHERNET,
    ts_sec: int | None = None,   # default: current time
    ts_usec: int = 0,
    timestamps: list[tuple[int, int]] | None = None,
)
```

| Parameter | Description |
|-----------|-------------|
| `path` | Destination file path. Created or overwritten. |
| `packets` | List of raw packet byte strings, one per pcap record. Typically the return value of `PacketBuilder.build()` or fragments from `PacketBuilder.fragment()`. |
| `link_type` | pcap link-layer type written into the global header. `LINKTYPE_ETHERNET` (`1`, default) for packets with an Ethernet header; `LINKTYPE_RAW` (`101`) for raw IP packets built with `include_ethernet=False`. |
| `ts_sec` | Capture timestamp whole seconds applied to every record. Defaults to the current wall-clock time. Ignored when `timestamps` is provided. |
| `ts_usec` | Capture timestamp microseconds fraction (0–999 999) applied to every record. Defaults to `0`. Ignored when `timestamps` is provided. |
| `timestamps` | Per-packet list of `(ts_sec, ts_usec)` tuples. Must be the same length as `packets`. Takes precedence over `ts_sec` / `ts_usec`. |

```python
from packet_generator import PacketBuilder, Protocol, write_pcap, LINKTYPE_RAW

# Shared timestamp — current time
pkts = [PacketBuilder("10.0.0.1", "10.0.0.2", Protocol.TCP).build()]
write_pcap("out.pcap", pkts)

# Per-packet timestamps
pkts = [...]
ts   = [(1000, 0), (1000, 500_000), (1001, 0)]
write_pcap("out.pcap", pkts, timestamps=ts)

# Raw IP packets (no Ethernet header)
pkts = [PacketBuilder("::1", "::2", Protocol.UDP, include_ethernet=False).build()]
write_pcap("raw.pcap", pkts, link_type=LINKTYPE_RAW)
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

```
python cli.py --src <ip> --dst <ip> --protocol <proto> [options]
python cli.py --config <file.json> [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--config` | — | Load a JSON config file with a `packets` array; builds all packets and writes to the configured output |
| `--src` | *(required)* | Source IP address (IPv4 or IPv6) |
| `--dst` | *(required)* | Destination IP address |
| `--protocol` | *(required)* | `tcp`, `udp`, `icmp`, or `icmpv6` |
| `--size` | `0` | Payload size in bytes (random bytes) |
| `--payload-data` | — | Explicit payload as a hex string (e.g. `48656c6c6f`); overrides `--size` |
| `--src-port` | `12345` | Source port (TCP/UDP) |
| `--dst-port` | `80` | Destination port (TCP/UDP) |
| `--tcp-seq` | `0` | TCP sequence number |
| `--vlan-id` | — | IEEE 802.1Q VLAN ID (1–4094). Adds a 4-byte 802.1Q tag to the Ethernet header. |
| `--vlan-pcp` | `0` | VLAN Priority Code Point (0–7) |
| `--vlan-dei` | `0` | VLAN Drop Eligible Indicator (0 or 1) |
| `--src-mac` | `00:00:00:00:00:01` | Source MAC address |
| `--dst-mac` | `00:00:00:00:00:02` | Destination MAC address |
| `--ttl` | `64` | TTL / Hop Limit |
| `--no-ethernet` | — | Omit the Ethernet header |
| `--mtu` | — | Fragment the packet; each IP datagram will be at most MTU bytes |
| `--output` | — | Write raw bytes to a file instead of printing hex |
| `--pcap` | — | Write packets to a libpcap (`.pcap`) file openable by Wireshark/tcpdump |
| `--timestamp-s` | *(current time)* | Capture timestamp — whole seconds (`ts_sec` in pcap record header) |
| `--timestamp-us` | `0` | Capture timestamp — microseconds fraction 0–999999 (`ts_usec` in pcap record header) |

### Examples

```bash
# IPv4 TCP — print hex to stdout
python cli.py --src 192.168.1.1 --dst 8.8.8.8 --protocol tcp --size 20

# TCP with a specific sequence number
python cli.py --src 10.0.0.1 --dst 10.0.0.2 --protocol tcp --tcp-seq 3735928559 --size 0

# IPv6 UDP — print hex
python cli.py --src ::1 --dst ::2 --protocol udp --size 10

# ICMPv6 ping — no Ethernet header, write binary to file
python cli.py --src fe80::1 --dst fe80::2 --protocol icmpv6 --no-ethernet --output ping.bin

# IPv4 UDP DNS query skeleton — custom ports
python cli.py --src 10.0.0.1 --dst 8.8.8.8 --protocol udp --src-port 5000 --dst-port 53 --size 0

# Fragment a large IPv4 UDP payload at MTU 576 — print each fragment
python cli.py --src 10.0.0.1 --dst 10.0.0.2 --protocol udp --size 2000 --mtu 576

# Fragment a large IPv6 TCP payload and save all fragments to a file
python cli.py --src ::1 --dst ::2 --protocol tcp --size 4000 --mtu 1280 --output frags.bin

# IPv4 UDP on VLAN 200, priority 6 — 18-byte Ethernet header
python cli.py --src 10.0.0.1 --dst 10.0.0.2 --protocol udp --size 32 --vlan-id 200 --vlan-pcp 6

# Write a single TCP packet as a pcap file (link type 1 = Ethernet)
python cli.py --src 10.0.0.1 --dst 10.0.0.2 --protocol tcp --size 64 --pcap capture.pcap

# Write fragmented UDP as a pcap (each fragment becomes a separate record)
python cli.py --src 10.0.0.1 --dst 10.0.0.2 --protocol udp --size 4000 --mtu 1500 --pcap frags.pcap

# Raw IPv6 TCP packet (no Ethernet header) — link type 101 = raw IP
python cli.py --src ::1 --dst ::2 --protocol tcp --size 40 --no-ethernet --pcap raw.pcap

# Explicit payload as hex bytes ("Hello")
python cli.py --src 10.0.0.1 --dst 10.0.0.2 --protocol udp --payload-data 48656c6c6f

# Build packets from a JSON config file
python cli.py --config packets.json

# pcap with a fixed capture timestamp (ts_sec=0, ts_usec=123456)
python cli.py --src 10.0.0.1 --dst 10.0.0.2 --protocol tcp --pcap out.pcap --timestamp-s 0 --timestamp-us 123456
```

---

## JSON config file

A JSON config file is loaded with `--config`. It must contain a top-level
`packets` array with one object per packet to build. A top-level `output`
block sets the shared output destination (`pcap` or `file`) for all packets.
Per-packet `output` supports `mtu`, `timestamp_s`, and `timestamp_us`.

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
      "output": { "timestamp_s": 1000, "timestamp_us": 0 }
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
      "output": { "timestamp_s": 1000, "timestamp_us": 500000 }
    }
  ],
  "output": {
    "pcap": "conversation.pcap"
  }
}
```

All packets in a multi-packet pcap must use the same link layer type (either
all with Ethernet or all without). If every packet sets `ethernet.enabled:
false` the file uses link type 101 (raw IP); otherwise link type 1 (Ethernet)
is used. CLI flags are ignored for multi-packet configs.

### Field reference

#### `ethernet`

| Field | Default | Description |
|-------|---------|-------------|
| `src_mac` | `"00:00:00:00:00:01"` | Source MAC address |
| `dst_mac` | `"00:00:00:00:00:02"` | Destination MAC address |
| `enabled` | `true` | Set to `false` to omit the Ethernet header (equivalent to `--no-ethernet`) |
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
| `flags` | `16` | TCP 8-bit control flags integer — `TCP_CWR`=128, `TCP_ECE`=64, `TCP_URG`=32, `TCP_ACK`=16, `TCP_PSH`=8, `TCP_RST`=4, `TCP_SYN`=2, `TCP_FIN`=1; add values to combine (e.g. `24` for PSH+ACK) |
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

#### `output` (top-level, shared across all packets)

`file` and `pcap` are mutually exclusive.

| Field | Default | Description |
|-------|---------|-------------|
| `file` | — | Write raw bytes to this path |
| `pcap` | — | Write a libpcap `.pcap` file to this path |

#### `output` (per-packet)

`timestamp_s` and `timestamp_us` only affect pcap output.

| Field | Default | Description |
|-------|---------|-------------|
| `mtu` | — | Fragment the packet; each IP datagram will be at most this many bytes |
| `timestamp_s` | *(current time)* | Capture timestamp — whole seconds written to `ts_sec` in each pcap packet record header; 32-bit unsigned integer |
| `timestamp_us` | `0` | Capture timestamp — microseconds fraction (0–999999) written to `ts_usec` in each pcap packet record header |

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
    tcp.py             # TCP header (20 bytes)
    udp.py             # UDP header (8 bytes)
    icmp.py            # ICMPv4 header (8 bytes)
    icmpv6.py          # ICMPv6 header (8 bytes)
  tests/
    test_builder.py
    test_checksum.py
    test_ethernet.py
    test_fragmentation.py
    test_icmp.py
    test_icmpv6.py
    test_ip.py
    test_ipv6.py
    test_pcap.py
    test_tcp.py
    test_udp.py
  cli.py            # command-line interface
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
