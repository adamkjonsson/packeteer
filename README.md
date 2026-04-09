# packeteer

A pure-Python library for building, fragmenting, and parsing complete,
byte-accurate raw network packets.  No external dependencies — Python 3.10+
and the standard library only.

## Features

- **Ethernet II**, 802.1Q VLAN (single/QinQ), MPLS label stacks, PPPoE
- **IPv4** (RFC 791) and **IPv6** (RFC 8200) with automatic checksums
- **TCP**, **UDP**, **SCTP** (RFC 9260), **ICMPv4**, **ICMPv6** with correct checksums
- **Tunnels**: IP-in-IP (RFC 2003/4213), EtherIP (RFC 3378), GRE (RFC 2784/2890) with Key, Sequence, Checksum, and TEB
- **IPv4 and IPv6 fragmentation** in one call
- **pcap and pcapng** file I/O with microsecond or nanosecond timestamps
- **Stream generation** — complete TCP / UDP / SCTP flows written to pcap, pcapng, or JSON config; all streams can be wrapped in any encapsulation layer (VLAN, QinQ, MPLS, PPPoE, GRE, EtherIP, IP-in-IP), combined as a stack, and fragmented through a simulated low-MTU middlebox
- **CLI** (`packeteer`) — build packets from a JSON config, parse captures back to JSON, sanitise configs by replacing sensitive fields with synthetic data, or generate synthetic streams with `packeteer stream`

## Quick start

```python
from packet_generator import PacketBuilder

# TCP
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
from packet_generator.stream_encap import GREEncap, VLANEncap, MPLSEncap, IPIPEncap
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
| [docs/build.md](docs/build.md) | `packeteer build` CLI and `PacketBuilder` Python API |
| [docs/parse.md](docs/parse.md) | `packeteer parse` CLI and `packet_parser` Python API |
| [docs/sanitiser.md](docs/sanitiser.md) | `packeteer sanitise` — replacing sensitive fields with synthetic data |
| [docs/stream.md](docs/stream.md) | `packeteer stream` CLI and TCP / UDP / SCTP stream generators |
| [docs/cli.md](docs/cli.md) | Full CLI flag reference for all subcommands |
| [docs/json-config.md](docs/json-config.md) | JSON config format field reference |
| [docs/fragmentation.md](docs/fragmentation.md) | IPv4 and IPv6 fragmentation |
| [docs/api/packet-builder.md](docs/api/packet-builder.md) | `PacketBuilder` API |
| [docs/api/header-dataclasses.md](docs/api/header-dataclasses.md) | Header dataclasses and constants |
| [docs/api/pcap-io.md](docs/api/pcap-io.md) | pcap/pcapng read and write |
| [docs/api/parser.md](docs/api/parser.md) | Parser API |
| [docs/reference/packet-sizes.md](docs/reference/packet-sizes.md) | Header size tables |
| [docs/reference/rfc-references.md](docs/reference/rfc-references.md) | RFC index |

## Running tests

```bash
PYTHONPATH=src python3 -m unittest discover -s src/tests -q
```
