# Building Packets

packeteer builds packets in two ways: from the CLI using a packet spec file, or
directly from Python using the {class}`~packet_generator.builder.PacketBuilder`
API.  Both paths produce identical byte-accurate output — the CLI is a thin
wrapper around the same builder that the Python API exposes.

All checksums (IPv4 header, TCP, UDP, ICMPv4, ICMPv6, GRE, SCTP CRC-32c) are
computed automatically.

```{toctree}
:maxdepth: 1

cli
python-api
fragmentation
```
