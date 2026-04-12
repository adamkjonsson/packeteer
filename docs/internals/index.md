# Developer internals

This section describes how packeteer works internally.  It is aimed at
contributors and at users who want to extend or embed the library beyond what
the public API exposes.

## Structure of this section

```{toctree}
:maxdepth: 1

architecture
packet-builder
parser-pipeline
stream-generators
encapsulation
sanitiser
```

## Module map

| Module | Purpose |
|--------|---------|
| `packet_generator/builder.py` | `PacketBuilder` — fluent layer-by-layer assembly |
| `packet_generator/*.py` | One module per protocol: header dataclass + `build_*` function |
| `packet_generator/fragmentation.py` | IPv4 and IPv6 IP fragmentation |
| `packet_generator/stream_encap.py` | Encap descriptor dataclasses + `_apply_encap` / `_encap_ip_start` |
| `packet_generator/tcp_stream.py` | `generate_tcp_stream` — full TCP lifecycle |
| `packet_generator/udp_stream.py` | `generate_udp_stream` — UDP datagram sequence |
| `packet_generator/sctp_stream.py` | `generate_sctp_stream` — full SCTP association |
| `packet_parser/parser.py` | `parse_packet` — layer-chaining state machine |
| `packet_parser/to_config.py` | `update_config` / `to_packet_spec` — parsed headers → packet spec dict |
| `packet_parser/*.py` | One module per protocol: `packet_parser(data)` function |
| `replacer.py` | `sanitise` — consistent value replacement using IANA-reserved ranges |
| `packeteer_cli.py` | CLI entry point — thin dispatcher to the library functions above |
