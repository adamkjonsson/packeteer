# API Reference

`packeteer.generator` builds packets and generates streams; `packeteer.parser`
decodes them back to header dataclasses or packet spec; `packeteer.sanitiser` sanitises
configs for safe sharing.

**`packeteer.generator`** exposes {class}`~packeteer.generator.builder.PacketBuilder`
as the primary entry point, backed by individual header dataclasses (one per
protocol) and low-level builder functions.  All checksums are computed
automatically.  Three stream generators — {func}`~packeteer.generator.tcp_stream.generate_tcp_stream`,
{func}`~packeteer.generator.udp_stream.generate_udp_stream`, and
{func}`~packeteer.generator.sctp_stream.generate_sctp_stream` — produce complete
packet sequences that can be written directly to pcap, pcapng, or packet spec.

**`packeteer.parser`** provides {func}`~packeteer.parser.core.parse_packet` and
{class}`~packeteer.parser.core.ParsedPacket` as the high-level interface, plus
individual per-protocol parser functions that follow a common calling
convention.  {func}`~packeteer.parser.to_config.update_config` and
{func}`~packeteer.parser.to_config.apply_tunneled` serialise parsed packets back
to the packet spec dict format.

**`packeteer.sanitiser`** provides {func}`~packeteer.sanitiser.sanitise` and
{class}`~packeteer.sanitiser.SanitiseOptions` for stripping sensitive data from a config
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
