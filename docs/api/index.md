# API Reference

`packeteer.generate` builds packets and generates streams; `packeteer.parse`
decodes them back to header dataclasses or packet spec; `packeteer.sanitise` sanitises
configs for safe sharing.

**`packeteer.generate`** exposes {class}`~packeteer.generate.builder.PacketBuilder`
as the primary entry point, backed by individual header dataclasses (one per
protocol) and low-level builder functions.  All checksums are computed
automatically.  Three stream generators — {func}`~packeteer.generate.tcp_stream.generate_tcp_stream`,
{func}`~packeteer.generate.udp_stream.generate_udp_stream`, and
{func}`~packeteer.generate.sctp_stream.generate_sctp_stream` — produce complete
packet sequences that can be written directly to pcap, pcapng, or packet spec.

**`packeteer.parse`** provides {func}`~packeteer.parse.core.parse_packet` and
{class}`~packeteer.parse.core.ParsedPacket` as the high-level interface, plus
individual per-protocol parser functions that follow a common calling
convention.  {func}`~packeteer.parse.to_config.update_config` and
{func}`~packeteer.parse.to_config.apply_tunneled` serialise parsed packets back
to the packet spec dict format.

**`packeteer.sanitise`** provides {func}`~packeteer.sanitise.sanitise` and
{class}`~packeteer.sanitise.SanitiseOptions` for stripping sensitive data from a config
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
