# Python API Guide

This part covers the packeteer Python API through a series of focused,
task-oriented chapters.  Each chapter shows how to accomplish a common goal
without exhaustive parameter lists — those live in {doc}`../api/index` and
{doc}`../packet-spec/format`.

All public names are importable from eight top-level packages:

| Package | What it contains |
|---------|-----------------|
| `packeteer.parse` | `iter_packets`, `parse_packet`, `parse_pcap_file`, `pcap_info`, `defragment`, per-protocol parsers |
| `packeteer.generate` | `PacketBuilder`, session builders, stream generators, encapsulation types |
| `packeteer.filter` | `PacketFilter` |
| `packeteer.sanitise` | `sanitise`, `SanitiseOptions` |
| `packeteer.fuzz` | `fuzz`, `fuzz_bytes`, `FuzzOptions`, `FuzzVariant` |
| `packeteer.pcap` | `write_pcap`, `write_pcapng`, `read_pcap`, `open_pcap`, link-type constants |
| `packeteer.protocols` | `AppProtocol`, `register`, `registered` — see {doc}`adding-a-protocol` |
| `packeteer.conformance` | `check_protocol` — hold a protocol to the contract every one must meet |

```{note}
**packeteer has two ways to add a protocol, and keeps both.**  Compiling a
[spec](../protocols/index) is the one to reach for first; writing one
[by hand](adding-a-protocol) is what you need when the spec language cannot
express your protocol — delimiter framing, compression pointers, anything
needing code.  DNS, DHCP and HTTP are all in that second category, which is
why they are hand-written and will stay so.

Neither is legacy.  They produce the same
{class}`~packeteer.protocols.AppProtocol`, packeteer cannot tell them apart,
and {func}`packeteer.conformance.check_protocol` holds both to one contract.
```

```{toctree}
:maxdepth: 1

parsing
defragmenting
summarising
sanitising
generating
pcap
fuzzing
adding-a-protocol
```
