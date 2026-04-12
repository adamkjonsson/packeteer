# packeteer

packeteer is a pure-Python toolkit for crafting, capturing, and generating
network traffic without any external dependencies.

Use it to build hand-crafted packets from a JSON description, parse real
pcap captures back into that same format, sanitise sensitive fields before
sharing, or generate complete synthetic network streams — TCP, UDP, or SCTP
— with realistic protocol state, timestamps, and optional impairments.

Everything runs from a CLI or directly from Python. No root, no libpcap, no
compiled extensions — Python 3.10+ and the standard library only.

## Features and supported protocols

- **Ethernet II**, 802.1Q VLAN (single/QinQ), MPLS label stacks, PPPoE
- **IPv4** (RFC 791) and **IPv6** (RFC 8200) with automatic checksums
- **TCP**, **UDP**, **SCTP** (RFC 9260), **ICMPv4**, **ICMPv6** with correct checksums
- **Tunnels**: IP-in-IP (RFC 2003/4213), EtherIP (RFC 3378), GRE (RFC 2784/2890) with Key, Sequence, Checksum, and TEB
- **IPv4 and IPv6 fragmentation** in one call
- **pcap and pcapng** file I/O with microsecond or nanosecond timestamps
- **Stream generation** — complete TCP / UDP / SCTP flows written to pcap, pcapng, or packet spec; all streams can be wrapped in any encapsulation layer (VLAN, QinQ, MPLS, PPPoE, GRE, EtherIP, IP-in-IP), combined as a stack, and fragmented through a simulated low-MTU middlebox
- **CLI** (`packeteer`) — build packets from a packet spec, parse captures to a packet spec, sanitise specs by replacing sensitive fields with synthetic data, or generate synthetic streams with `packeteer stream`

## Quick start

### CLI

```bash
# Parse a capture to an editable packet spec
packeteer parse capture.pcap --output capture.json

# Rebuild it as a new pcap
packeteer build capture.json --pcap replayed.pcap

# Sanitise sensitive fields before sharing
packeteer sanitise capture.json --ports --payload --output clean.json
packeteer build clean.json --pcap clean.pcap

# Generate a complete TCP stream (50 packets, bimodal payload sizes)
packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --server-port 80 --packets 50 --distribution bimodal --pcap session.pcap

# Generate a UDP flow and export as a packet spec for further editing
packeteer stream --protocol udp \
    --client-ip 10.0.0.1 --server-ip 10.0.0.2 \
    --server-port 53 --packets 5 --json dns.json
```

### Python API

```python
from packet_generator import PacketBuilder

# TCP SYN packet
pkt = (PacketBuilder()
    .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .tcp(dst_port=80)
    .payload(size=64)
    .build()
)

# SCTP (RFC 9260) — data lives inside chunks, not a separate payload layer
from packet_generator.sctp import SCTPDataChunk

pkt = (PacketBuilder()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .sctp(
        src_port=1234,
        dst_port=9999,
        verification_tag=0xDEADBEEF,
        chunks=[SCTPDataChunk(tsn=0, data=b"hello sctp")],
    )
    .build()
)
```

```python
# Generate a GRE-tunnelled TCP stream and write it to pcap
from packet_generator.tcp_stream import generate_tcp_stream
from packet_generator.stream_encap import GREEncap, MPLSEncap, IPIPEncap
from packet_generator import write_pcap

stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    encap=GREEncap(src_ip="203.0.113.1", dst_ip="203.0.113.2"),
    num_data_packets=20,
)
write_pcap(stream.to_pcap_tuples(), path="gre_tunnel.pcap")

# Stack MPLS labels + IP-in-IP tunnel
stream = generate_tcp_stream(
    client_ip="10.0.0.1",
    server_ip="10.0.0.2",
    encap=[MPLSEncap(labels=[100, 200]), IPIPEncap("203.0.113.1", "203.0.113.2")],
)
```

## Documentation

Full documentation lives in [`docs/`](docs/).  Build it locally:

```bash
pip install -r docs/requirements.txt
make -C docs html
# open docs/_build/html/index.html
```

Or read the source pages directly:

| Page | Content |
|------|---------|
| [docs/installation.md](docs/installation.md) | Install, run tests, build docs |
| [docs/quickstart.md](docs/quickstart.md) | Five worked examples |
| [docs/overview.md](docs/overview.md) | Purpose and use cases |
| [docs/build/](docs/build/) | `packeteer build` CLI, `PacketBuilder` Python API, and IP fragmentation |
| [docs/parse/](docs/parse/) | `packeteer parse` CLI and `packet_parser` Python API |
| [docs/sanitiser/](docs/sanitiser/) | `packeteer sanitise` — replacing sensitive fields with synthetic data |
| [docs/stream/](docs/stream/) | `packeteer stream` CLI and TCP / UDP / SCTP stream generators |
| [docs/packet-spec/](docs/packet-spec/) | Packet spec format reference and Python API |
| [docs/api/packet-builder.md](docs/api/packet-builder.md) | `PacketBuilder` API reference |
| [docs/api/header-dataclasses.md](docs/api/header-dataclasses.md) | Header dataclasses and constants |
| [docs/api/pcap-io.md](docs/api/pcap-io.md) | pcap/pcapng read and write |
| [docs/api/parser.md](docs/api/parser.md) | Parser API reference |
| [docs/reference/packet-sizes.md](docs/reference/packet-sizes.md) | Header size tables |
| [docs/reference/rfc-references.md](docs/reference/rfc-references.md) | RFC index |

## Running tests

```bash
PYTHONPATH=src python3 -m unittest discover -s src/tests -q
```
