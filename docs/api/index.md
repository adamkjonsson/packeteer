# API Reference

`packet_generator` builds packets and generates streams; `packet_parser`
decodes them back to header dataclasses or packet spec; `replacer` sanitises
configs for safe sharing.

**`packet_generator`** exposes {class}`~packet_generator.builder.PacketBuilder`
as the primary entry point, backed by individual header dataclasses (one per
protocol) and low-level builder functions.  All checksums are computed
automatically.  Three stream generators — {func}`~packet_generator.tcp_stream.generate_tcp_stream`,
{func}`~packet_generator.udp_stream.generate_udp_stream`, and
{func}`~packet_generator.sctp_stream.generate_sctp_stream` — produce complete
packet sequences that can be written directly to pcap, pcapng, or packet spec.

**`packet_parser`** provides {func}`~packet_parser.parser.parse_packet` and
{class}`~packet_parser.parser.ParsedPacket` as the high-level interface, plus
individual per-protocol parser functions that follow a common calling
convention.  {func}`~packet_parser.to_config.update_config` and
{func}`~packet_parser.to_config.apply_tunneled` serialise parsed packets back
to the packet spec dict format.

**`replacer`** provides {func}`~replacer.sanitise` and
{class}`~replacer.SanitiseOptions` for stripping sensitive data from a config
before sharing or archiving.

```{toctree}
:maxdepth: 1

packet-builder
header-dataclasses
stream-generators
stream-encap
pcap-io
parser
fragmentation
sanitiser
```
