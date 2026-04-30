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
fuzzer
```

## Module map

| Module | Purpose |
|--------|---------|
| `packeteer/generate/builder.py` | `PacketBuilder` — fluent layer-by-layer assembly |
| `packeteer/generate/*.py` | One module per protocol: header dataclass + `_build_*` function |
| `packeteer/generate/fragmentation.py` | IPv4 and IPv6 IP fragmentation |
| `packeteer/generate/stream_encap.py` | Encap descriptor dataclasses + `_apply_encap` / `_encap_ip_start` |
| `packeteer/generate/tcp_stream.py` | `generate_tcp_stream` — full TCP lifecycle |
| `packeteer/generate/udp_stream.py` | `generate_udp_stream` — UDP datagram sequence |
| `packeteer/generate/sctp_stream.py` | `generate_sctp_stream` — full SCTP association |
| `packeteer/parse/parser.py` | `parse_packet` — layer-chaining state machine |
| `packeteer/parse/to_config.py` | `update_config` / `to_packet_spec` — parsed headers → packet spec dict |
| `packeteer/parse/*.py` | One module per protocol: `packet_parser(data)` function |
| `packeteer/sanitise.py` | `sanitise` — consistent value replacement using IANA-reserved ranges |
| `packeteer/fuzz.py` | `fuzz` / `fuzz_bytes` — spec-level and byte-level adversarial mutations |
| `packeteer_cli.py` | CLI entry point — thin dispatcher to the library functions above |
