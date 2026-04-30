# Python API Guide

This part covers the packeteer Python API through a series of focused,
task-oriented chapters.  Each chapter shows how to accomplish a common goal
without exhaustive parameter lists — those live in {doc}`../api/index` and
{doc}`../packet-spec/format`.

All public names are importable from five top-level packages:

| Package | What it contains |
|---------|-----------------|
| `packeteer.parse` | `parse_packet`, `parse_pcap_file`, `read_pcap`, per-protocol parsers |
| `packeteer.generate` | `PacketBuilder`, session builders, stream generators, encapsulation types |
| `packeteer.filter` | `PacketFilter` |
| `packeteer.sanitise` | `sanitise`, `SanitiseOptions` |
| `packeteer.fuzz` | `fuzz`, `fuzz_bytes`, `FuzzOptions`, `FuzzVariant` |
| `packeteer.pcap` | `write_pcap`, `write_pcapng`, `read_pcap`, link-type constants |

```{toctree}
:maxdepth: 1

parsing
sanitising
generating
pcap
fuzzing
```
