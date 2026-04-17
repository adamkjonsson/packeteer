# Quick Start

## Build a packet in Python

Use {class}`packeteer.generate.builder.PacketBuilder` — a fluent, layer-by-layer
API.  Call methods in the order you want the layers stacked, then call
`.build()` to produce the raw bytes.

```python
from packeteer.generate import PacketBuilder

# Ethernet + IPv4 + TCP with a 64-byte random payload
pkt = (PacketBuilder()
    .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .tcp(dst_port=443)
    .payload(size=64)
    .build()
)
print(f"{len(pkt)} bytes: {pkt.hex()}")
```

IPv6 is detected automatically from the address string — no explicit flag needed:

```python
pkt = (PacketBuilder()
    .ip(src="fe80::1", dst="fe80::2")
    .udp(dst_port=5353)
    .payload(size=20)
    .build()
)
```

See {doc}`api/packet-builder` for the full method reference.

## Write to a pcap file

```python
import time
from packeteer.generate import PacketBuilder
from packeteer.pcap import write_pcap, LINKTYPE_ETHERNET

t = int(time.time())
packets = [
    (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2").tcp().build(), t, 0),
    (PacketBuilder().ethernet().ip(src="10.0.0.2", dst="10.0.0.1").tcp().build(), t, 500_000),
]
write_pcap(packets, path="out.pcap", link_type=LINKTYPE_ETHERNET)
```

Open `out.pcap` in Wireshark or replay it with `tcpreplay`.
See {doc}`api/pcap-io` for the full I/O reference.

## Use the CLI

```bash
# Build packets from a packet spec and write a pcap file
packeteer build packets.json --pcap out.pcap

# Parse a capture and print its packet spec
packeteer parse capture.pcap

# Round-trip: parse → spec → rebuild
packeteer parse capture.pcap --output config.json
packeteer build config.json --pcap replayed.pcap
```

See {doc}`build/index`, {doc}`parse/index`, {doc}`sanitiser/index`, and
{doc}`stream/index` for the full CLI and Python API reference for each
subcommand, and {doc}`packet-spec/index` for the JSON config format.

## Parse a packet

{func}`packeteer.parse.core.parse_packet` chains all layer parsers automatically
and returns a {class}`packeteer.parse.core.ParsedPacket` with every recognised
layer filled in.

```python
from packeteer.generate import PacketBuilder
from packeteer.pcap import LINKTYPE_RAW
from packeteer.parse import parse_packet

raw = (PacketBuilder()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .tcp(dst_port=443)
    .payload(size=32)
    .build()
)
pkt = parse_packet(raw, link_type=LINKTYPE_RAW)

print(pkt.ip.src, "->", pkt.ip.dst)
print("dst_port:", pkt.transport.dst_port)
print("payload:", pkt.payload.hex())
```

Pass `link_type=LINKTYPE_ETHERNET` (the default) when parsing frames that
include an Ethernet header.  See {doc}`api/parser` for the full parsing API.

## Tunnel example

Layers are just stacked in order — call `.gre()` between two `.ip()` calls to
produce a GRE tunnel packet:

```python
from packeteer.generate import PacketBuilder

pkt = (PacketBuilder()
    .ethernet()
    .ip(src="10.0.0.1", dst="10.0.0.2")   # outer (tunnel) IP
    .gre(key=1234)                          # GRE header with Key field
    .ip(src="192.168.1.1", dst="192.168.1.2")  # inner IP
    .tcp(dst_port=80)
    .build()
)
```

The outer IP protocol field (47), the GRE Protocol Type (0x0800 for IPv4), and
all checksums are set automatically.  The same stacking model works for
EtherIP (`.etherip()`), IP-in-IP (call `.ip()` twice), QinQ (call `.vlan()`
twice), and MPLS label stacks (call `.mpls()` for each label).

## SCTP example

SCTP (RFC 9260) uses `.sctp()` instead of `.tcp()` or `.udp()`.  Data lives
inside typed *chunks* rather than in a separate `.payload()` layer:

```python
from packeteer.generate import PacketBuilder
from packeteer.generate import (
    SCTPDataChunk, SCTPInitChunk,
    SCTP_DATA_FLAG_BEGINNING, SCTP_DATA_FLAG_ENDING,
)

# Single DATA chunk carrying a complete, unfragmented message
pkt = (PacketBuilder()
    .ethernet()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .sctp(
        src_port=1234,
        dst_port=9999,
        verification_tag=0xDEADBEEF,
        chunks=[SCTPDataChunk(
            tsn=0,
            stream_id=0,
            ppid=0,
            data=b"hello sctp",
            flags=SCTP_DATA_FLAG_BEGINNING | SCTP_DATA_FLAG_ENDING,
        )],
    )
    .build()
)
```

The CRC-32c checksum (Castagnoli, RFC 9260 §6.8) is computed automatically.
IP protocol number 132 (`IPPROTO_SCTP`) is set on the enclosing IP header.
See {doc}`api/header-dataclasses` for all chunk types and constants.
