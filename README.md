# packet-generator

A pure-Python library for building, fragmenting, and parsing complete,
byte-accurate raw network packets.  No external dependencies — Python 3.10+
and the standard library only.

## Features

- **Ethernet II**, 802.1Q VLAN (single/QinQ), MPLS label stacks, PPPoE
- **IPv4** (RFC 791) and **IPv6** (RFC 8200) with automatic checksums
- **TCP**, **UDP**, **ICMPv4**, **ICMPv6** with correct pseudo-header checksums
- **Tunnels**: IP-in-IP (RFC 2003/4213), EtherIP (RFC 3378), GRE (RFC 2784/2890) with Key, Sequence, Checksum, and TEB
- **IPv4 and IPv6 fragmentation** in one call
- **pcap and pcapng** file I/O with microsecond or nanosecond timestamps
- **CLI** (`packet_lab.py`) — build from JSON config or parse captures back to JSON

## Quick start

```python
from packet_generator import PacketBuilder

pkt = (PacketBuilder()
    .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .tcp(dst_port=80)
    .payload(size=64)
    .build()
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
| [docs/cli.md](docs/cli.md) | `packet_lab.py build` / `parse` reference |
| [docs/json-config.md](docs/json-config.md) | JSON config format reference |
| [docs/fragmentation.md](docs/fragmentation.md) | IPv4 and IPv6 fragmentation |
| [docs/api/packet-builder.md](docs/api/packet-builder.md) | `PacketBuilder` API |
| [docs/api/header-dataclasses.md](docs/api/header-dataclasses.md) | Header dataclasses and constants |
| [docs/api/pcap-io.md](docs/api/pcap-io.md) | pcap/pcapng read and write |
| [docs/api/parser.md](docs/api/parser.md) | Parser API |
| [docs/reference/packet-sizes.md](docs/reference/packet-sizes.md) | Header size tables |
| [docs/reference/rfc-references.md](docs/reference/rfc-references.md) | RFC index |

## Running tests

```bash
python3 -m unittest discover -s tests -q
```
