# API Reference

`packet_generator` builds packets; `packet_parser` decodes them.

**`packet_generator`** exposes {class}`~packet_generator.builder.PacketBuilder`
as the primary entry point, backed by individual header dataclasses (one per
protocol) and low-level builder functions.  All checksums are computed
automatically.

**`packet_parser`** provides {func}`~packet_parser.parser.parse_packet` and
{class}`~packet_parser.parser.ParsedPacket` as the high-level interface, plus
individual per-protocol parser functions that follow a common calling
convention.

```{toctree}
:maxdepth: 1

packet-builder
header-dataclasses
pcap-io
parser
```
