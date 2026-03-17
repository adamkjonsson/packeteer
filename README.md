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
- CLI for quick packet inspection and binary output, with `--mtu` for on-the-fly fragmentation

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
```

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

#### `EthernetHeader`

```python
from packet_generator import EthernetHeader
from packet_generator.ethernet import build_ethernet_header, ETHERTYPE_IPV4, ETHERTYPE_IPV6

hdr = EthernetHeader(
    dst_mac="aa:bb:cc:dd:ee:ff",
    src_mac="11:22:33:44:55:66",
    ethertype=ETHERTYPE_IPV4,   # 0x0800
)
raw: bytes = build_ethernet_header(hdr)  # 14 bytes
```

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

#### `TCPHeader`

```python
from packet_generator import TCPHeader
from packet_generator.tcp import build_tcp_header

hdr = TCPHeader(src_port=12345, dst_port=80, flags=0x002)  # SYN
raw: bytes = build_tcp_header(hdr, payload=b"", src_ip="10.0.0.1", dst_ip="10.0.0.2")
# For IPv6: ip_version=6
```

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

## Packet sizes

| Protocol | IP version | With Ethernet | Without Ethernet |
|----------|-----------|--------------|-----------------|
| TCP      | IPv4      | 14 + 20 + 20 + N | 20 + 20 + N |
| UDP      | IPv4      | 14 + 20 + 8 + N  | 20 + 8 + N  |
| ICMP     | IPv4      | 14 + 20 + 8 + N  | 20 + 8 + N  |
| TCP      | IPv6      | 14 + 40 + 20 + N | 40 + 20 + N |
| UDP      | IPv6      | 14 + 40 + 8 + N  | 40 + 8 + N  |
| ICMPv6   | IPv6      | 14 + 40 + 8 + N  | 40 + 8 + N  |

*N = payload size in bytes*

---

## CLI

```
python cli.py --src <ip> --dst <ip> --protocol <proto> [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--src` | *(required)* | Source IP address (IPv4 or IPv6) |
| `--dst` | *(required)* | Destination IP address |
| `--protocol` | *(required)* | `tcp`, `udp`, `icmp`, or `icmpv6` |
| `--size` | `0` | Payload size in bytes |
| `--src-port` | `12345` | Source port (TCP/UDP) |
| `--dst-port` | `80` | Destination port (TCP/UDP) |
| `--src-mac` | `00:00:00:00:00:01` | Source MAC address |
| `--dst-mac` | `00:00:00:00:00:02` | Destination MAC address |
| `--ttl` | `64` | TTL / Hop Limit |
| `--no-ethernet` | — | Omit the Ethernet header |
| `--mtu` | — | Fragment the packet; each IP datagram will be at most MTU bytes |
| `--output` | — | Write raw bytes to a file instead of printing hex |

### Examples

```bash
# IPv4 TCP — print hex to stdout
python cli.py --src 192.168.1.1 --dst 8.8.8.8 --protocol tcp --size 20

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
```

---

## Project structure

```
packet-generator/
  packet_generator/
    __init__.py        # public API re-exports
    builder.py         # PacketBuilder and Protocol — main entry point
    checksum.py        # RFC 1071 one's-complement checksum utility
    ethernet.py        # Ethernet II header (14 bytes)
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

All 103 tests run in under a second and require no third-party packages.

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
