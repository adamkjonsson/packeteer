# Changelog

All notable changes to packeteer are recorded in this file.

---

## Unreleased — 2026-04-12

### Stream JSON output

- `packeteer stream` gains a `--json FILE` output flag, mutually exclusive with `--pcap`/`--pcapng`.  The flag serialises the generated stream as a packet spec file in exactly the same format produced by `packeteer parse`, making it replayable with `packeteer build` and sanitisable with `packeteer sanitise`.
- Each per-packet `metadata` block carries `timestamp_s`, `timestamp_us`, `direction` (`"c2s"` / `"s2c"`), and `label` (e.g. `"SYN"`, `"DATA[0]"`) alongside the standard layer fields.
- All three protocols (TCP, UDP, SCTP) and all encapsulation types are supported; the raw bytes are parsed back through the existing `parse_packet` + `to_config` pipeline, so every layer is reproduced correctly.
- `json` key accepted in INI config files (consistent with `pcap` / `pcapng`).

### Stream encapsulation

- Added `packet_generator.stream_encap` module with seven encapsulation descriptor dataclasses: `VLANEncap` (802.1Q), `QinQEncap` (double 802.1Q), `MPLSEncap` (RFC 3032), `PPPoEEncap` (RFC 2516), `GREEncap` (RFC 2784/2890), `EtherIPEncap` (RFC 3378), `IPIPEncap` (RFC 2003/4213).
- `generate_tcp_stream`, `generate_udp_stream`, and `generate_sctp_stream` all accept a new `encap` keyword argument (`EncapSpec = StreamEncap | list[StreamEncap] | None`).  Passing a list stacks multiple layers (e.g. `[MPLSEncap(labels=[100]), IPIPEncap("203.0.113.1", "203.0.113.2")]` produces eth → MPLS → outer-IP → inner-IP → transport).
- Middlebox MTU fragmentation works correctly with all encapsulation types: tag-based layers (VLAN/QinQ/MPLS/PPPoE) fragment the inner IP at the correct offset; tunnel layers (GRE/EtherIP/IPIP) fragment the outer IP datagram; PPPoE payload length fields are automatically patched in each fragment.
- `packeteer stream` gains 20 encap flags: `--vlan VID`, `--vlan-pcp`, `--vlan-dei`, `--qinq OUTER INNER`, `--qinq-outer-pcp/dei`, `--qinq-inner-pcp/dei`, `--mpls LABEL…`, `--mpls-tc`, `--mpls-ttl`, `--pppoe SESSION_ID`, `--gre SRC DST`, `--gre-key`, `--gre-ttl`, `--etherip SRC DST`, `--etherip-ttl`, `--ipip SRC DST`, `--ipip-ttl`.  All are supported in INI config files.  Mutual exclusion is enforced: `--vlan`/`--qinq` are exclusive; at most one tunnel type.
- All seven encap types and their combinations exported from `packet_generator.__init__`.
- 57 new tests in `test_stream_encap.py` (99% coverage) and 32 new tests in `test_cli.py` covering `_parse_stream_encap` and end-to-end stream generation.

### Code quality

- Extracted `_stream_common.py` module to house helpers shared by all three stream generators (`_repeat_payload`, `_alloc_usec`, `_pkt_usec`, `_payload_sizes`, `_fragment_ip_raw`), eliminating duplicate implementations and cross-module private imports.
- `_fragment_ip_raw()` consolidates the IPv4 and IPv6 fragmentation logic that was previously duplicated across `tcp_stream.py`, `udp_stream.py`, and `sctp_stream.py`.  Each per-protocol fragment helper is now ~15 lines instead of ~55.
- Removed all `from .tcp_stream import _private_function` imports from `udp_stream.py` and `sctp_stream.py`.
- Normalised fragment timestamp loops across all three generators to the same `orig_usec + i` / `ts // 1_000_000` / `ts % 1_000_000` pattern.
- Merged the parallel `_STREAM_CONFIG_KEYS` and `_STREAM_DEFAULTS` dicts in `packeteer_cli.py` into a single `_STREAM_PARAMS: dict[str, tuple[dest, cast, default]]`, giving one canonical source of truth for all stream parameters.
- Extracted `_validate_stream_args(args) -> str` from `_cmd_stream`, separating protocol validation from argument defaulting.

### API change: `middlebox_mtu` renamed to `mtu`

- The `middlebox_mtu` parameter on all three stream generators and the `--middlebox-mtu` CLI flag have been renamed to `mtu` / `--mtu`.  The INI key, test suite, and all documentation updated accordingly.

### API addition: `apply_tunneled`

- `packet_parser.to_config.apply_tunneled(config, pkt)` is now a public function.  It serialises the tunnel layers (IP-in-IP, GRE, EtherIP) of a `ParsedPacket` into a config dict, handling all three types through a single call.  Previously callers had to import and invoke three private helpers directly; this was the root cause of `_stream_to_json` in `packeteer_cli.py` importing private names from `to_config`.

### JSON key rename: `metadata` / `packet_metadata`

- Per-packet `"metadata"` key renamed to `"packet_metadata"` throughout all source, test, and doc files.
- Top-level `"file_metadata"` key renamed to `"metadata"`.
- `to_json_config()` now always writes a top-level `"metadata"` block; `"nanoseconds"` is mandatory and defaults to `false`.
- `packeteer stream --json` produces the same mandatory `"metadata"` block.

### Rename: "JSON config" → "packet spec"

- The shared file format between `packeteer build`, `packeteer parse`, and
  `packeteer stream --json` is now called a **packet spec** throughout all
  documentation, help strings, docstrings, error messages, and comments.
- `to_json_config()` renamed to `to_packet_spec()` in `packet_parser.to_config`.
- `docs/json-config/` directory renamed to `docs/packet-spec/`.

### README and docs/index.md

- README Quick start section expanded with CLI examples (parse, build, sanitise,
  stream) placed before the Python API examples.
- `docs/index.md` intro replaced with a short elevator-pitch description.

### Documentation restructure

- API Reference expanded: new pages for stream generators (`api/stream-generators.md`), stream encapsulation types (`api/stream-encap.md`), IP fragmentation (`api/fragmentation.md`), and sanitiser (`api/sanitiser.md`).
- `docs/build.md` split into `docs/build/` subdirectory: `cli.md`, `python-api.md`, and `fragmentation.md` (moved from `docs/fragmentation.md`).
- `docs/parse.md` split into `docs/parse/`: `cli.md` and `python-api.md`.
- `docs/sanitiser.md` split into `docs/sanitiser/`: `index.md`, `cli.md`, and `python-api.md`.
- `docs/stream.md` split into `docs/stream/`: `index.md`, `cli.md`, and `python-api.md`.
- `docs/json-config.md` split into `docs/packet-spec/`: `index.md`, `format.md` (field-by-field spec), and `python-api.md` (programmatic packet spec usage).
- `docs/cli.md` removed — content was fully covered by the per-subcommand subpages.
- `docs/index.md` toctree updated to reference all new subdirectory index pages.

---

### SCTP support (RFC 9260)
- Added `SCTPHeader` dataclass and 13 typed chunk dataclasses (`SCTPDataChunk`, `SCTPInitChunk`, `SCTPInitAckChunk`, `SCTPSackChunk`, `SCTPHeartbeatChunk`, `SCTPHeartbeatAckChunk`, `SCTPAbortChunk`, `SCTPShutdownChunk`, `SCTPShutdownAckChunk`, `SCTPErrorChunk`, `SCTPCookieEchoChunk`, `SCTPCookieAckChunk`, `SCTPShutdownCompleteChunk`) plus `SCTPGenericChunk` for unknown types.
- Added `build_sctp_packet()` in `packet_generator.sctp`: encodes all chunk types to wire format, pads to 4-byte boundaries, and computes the CRC-32c (Castagnoli) checksum per RFC 9260 §6.8.
- Added `crc32c()` to `packet_generator.checksum`: pure-Python CRC-32c using a precomputed 256-entry lookup table (Castagnoli polynomial 0x82F63B78).
- Added `PacketBuilder.sctp()` fluent method: appends an SCTP transport layer to the builder stack; IP protocol number 132 (`IPPROTO_SCTP`) set automatically.
- Added SCTP parser in `packet_parser.sctp`: decodes the 12-byte common header and all chunk types; unknown types fall back to `SCTPGenericChunk`; checksum is read but not verified.
- Registered `socket.IPPROTO_SCTP` in `_TRANSPORT_PARSERS` so `parse_packet` / `parse_pcap_file` handle SCTP automatically.
- Added SCTP serialisation to `packet_parser.to_config`: `_serialise_sctp_chunk()` converts each chunk type to a JSON-compatible dict; `_apply_transport()` and `update_config()` extended.
- Added `"sctp"` dispatch branch to `packeteer_cli._dispatch_transport()` and `_parse_sctp_chunk()` helper for building SCTP packets from JSON configs.
- 69 new tests in `test_sctp.py` covering CRC-32c, all chunk encodings, multi-chunk packets, `PacketBuilder` integration, parser round-trips, `parse_packet` integration, and `to_config` serialisation.

### Multi-protocol stream generation
- Added `generate_udp_stream()` in `packet_generator.udp_stream`: generates a unidirectional client→server UDP datagram flow (`num_data_packets` packets labelled `DATA[0]`…`DATA[N-1]`).  Shares continuous-payload, timestamp-jitter, and middlebox-MTU fragmentation behaviour with the TCP generator.
- Added `generate_sctp_stream()` in `packet_generator.sctp_stream`: generates a complete SCTP association per RFC 9260 — four-way handshake (INIT / INIT-ACK / COOKIE-ECHO / COOKIE-ACK), `num_data_packets` DATA+SACK pairs, and graceful shutdown (SHUTDOWN / SHUTDOWN-ACK / SHUTDOWN-COMPLETE).  Verification tags, TSNs, CRC-32c checksums, and the State Cookie TLV (Type=7) are all computed correctly.  Total packet count: `2 * num_data_packets + 7`.
- Added `UDPStream`, `UDPStreamPacket`, `SCTPStream`, `SCTPStreamPacket` dataclasses with `to_pcap_tuples()`, `client_packets()`, and `server_packets()` helpers, matching the `TCPStream` API.
- All three generators are exported from `packet_generator.__init__`.
- Added `--protocol tcp|udp|sctp` flag to `packeteer stream` (default: `tcp`, fully backward-compatible).  TCP-only flags (`--window`, `--psh-probability`, `--packet-loss`, `--retransmission-*`, `--payload-corruption`, `--server-rst`, `--rst-propagation-delay`, `--stray-packets`, `--stray-timing-window`) are silently ignored for `udp` and `sctp`.
- Added `protocol` key to `stream.ini.template` with full commentary; all TCP-only keys annotated `[TCP only]`.
- 73 new tests: `test_udp_stream.py` (26 tests across basic structure, packet contents, timestamps, payload, and middlebox MTU) and `test_sctp_stream.py` (47 tests covering packet count formula, label order, per-packet directions, verification tag correctness, TSN incrementing, timestamps, payload sizes, raw packet contents, and middlebox MTU fragmentation).

### Sanitiser: SCTP payload support
- `replacer.sanitise()` now zeroes opaque binary fields inside SCTP chunks when `opts.payload = True`: `data` (DATA chunks), `params` (INIT/INIT-ACK State Cookie), `cookie` (COOKIE ECHO), `info` (HEARTBEAT/HEARTBEAT-ACK), `causes` (ERROR/ABORT), and `value` (generic chunks).  Port sanitisation already worked via the existing `transport.src_port`/`dst_port` path.
- 12 new tests in `TestSCTPSanitise` covering port replacement, per-chunk-type payload zeroing, unchanged-by-default behaviour, IP replacement, verification tag preservation, and original-not-mutated guarantee.

### Bug fix: SCTP INIT-ACK State Cookie malformed
- `sctp_stream.py`: the State Cookie was passed as raw bytes in the INIT-ACK `params` field.  RFC 9260 §3.3.3 requires it to be wrapped in a parameter TLV (Type=7, Length=4+n).  Wireshark reported the INIT-ACK as malformed.  Fixed by building `struct.pack("!HH", 7, 4 + len(cookie)) + cookie` before passing to `SCTPInitAckChunk.params`.

### Documentation updates
- `docs/stream.md` restructured as a multi-protocol reference: top-level `## TCP stream`, `## UDP stream`, and `## SCTP stream` sections, each with a packet-sequence table, quick example, and API autodoc stubs.  Config file template section updated with `protocol` key and `[TCP only]` annotations.
- `docs/cli.md`: `stream` subcommand table updated with `--protocol` row and `[TCP only]` annotations on TCP-specific flags; examples extended to show UDP and SCTP usage; programmatic-equivalent section updated.
- `docs/index.md`: feature list updated from "TCP stream generation" to "Stream generation" covering all three protocols.
- `src/packeteer_cli.py` module docstring: stream subcommand description and examples updated.
- `src/packet_generator/__init__.py` package docstring: SCTP added to the Layer 4 protocol list.

### TCP stream: stray packet injection (TCP hijacking simulation)
- Added `stray_packet_count` parameter to `generate_tcp_stream()` and `--stray-packets N` CLI flag.  Injects forged client→server packets that reuse seq/ack values stolen from randomly chosen data segments, carrying an all-`x` payload of random size.  Simulates a passive attacker attempting to hijack a connection.  Stray packets are labelled `STRAY[n]`.
- Added `stray_timing_window` parameter and `--stray-timing-window N` CLI flag.  When set, each stray packet's timestamp is constrained to within N packets of its reference DATA packet in the timestamp-sorted stream, simulating an attacker who injects close in time to the segment they are targeting.  Defaults to `None` (full data-transfer window).

---

## 2026-04-03

### TCP stream: middlebox MTU fragmentation
- Added `mtu` parameter to `generate_tcp_stream()` and `--mtu` CLI flag.  Any packet whose IP-layer size exceeds the configured MTU is split into IP fragments (IPv4 Flags/Fragment Offset; IPv6 Fragment Extension Header) as if it had passed through a low-MTU router or VPN tunnel.  Fragment packets are labelled `FRAG[<orig>][<n>]`.

### TCP stream: continuous payload stream
- Data segments now carry a continuous slice of the default payload across the entire transfer rather than each packet independently restarting from byte 0, matching the behaviour of a real application writing to a socket.

### Code quality
- Extracted `_pkt_usec()` and `_alloc_usec()` helpers in `tcp_stream.py`, eliminating several repeated inline expressions.
- Removed duplicate `_rfc1071_checksum()` from `gre.py`; now imports `ones_complement_checksum` from `checksum.py`.
- Simplified `1 if x else 0` flag expressions to `int(x)` in `gre.py`.
- Fixed `_ = checksum` post-unpack idiom in `udp.py`, `icmp.py`, and `icmpv6.py` — the discard now sits in the unpack pattern directly.
- Collapsed the GRE / EtherIP tunnel recursion in `replacer.py` into a single loop over `("ipip", "gre", "etherip")`.
- Removed O(n) `packets.index()` call in the payload-corruption block; replaced with a label-to-index dict.
- Moved shared `rto_usec` computation outside the retransmissions and corruption blocks.

### Documentation fixes
- `tcp_stream.py` module docstring: corrected import path from `packet_generator.stream` to `packet_generator.tcp_stream`.
- `tcp.py` module and `build_tcp_header()` docstrings: removed incorrect claim that the header is always 20 bytes with no options — the function fully supports TCP options (20–60 bytes).
- `pcap.py` `write_pcap()` and `write_pcapng()` examples: replaced non-existent `Protocol` class and invalid `PacketBuilder(...)` constructor call with correct fluent API usage.

---

## 2026-04-02

### TCP stream: anomaly injection
- **Server RST** (`server_rst_probability`, `rst_propagation_delay`): simulates the server application crashing mid-stream. A random split point is chosen; the server sends RST|ACK at the moment the next data packet would have been sent. The client continues transmitting until the RST propagates.
- **Payload corruption** (`payload_corruption_probability`): flips one byte in the payload, invalidating the TCP checksum so the receiver silently drops the segment. A retransmission follows after `retransmission_timeout`, and the server ACK timestamp is shifted accordingly.
- **Spurious retransmissions** (`retransmission_probability`, `retransmission_timeout`): re-sends data segments as if the retransmission timer fired before the ACK arrived.
- Timestamp collision avoidance: unique-timestamp nudging applied consistently across all anomaly types using a shared `used_ts` set.
- CLI test suite added (49 tests), raising overall coverage from 94 % to 97 %.

---

## 2026-04-01

### TCP stream: realism improvements
- **PSH flag probability** (`psh_probability`): PSH is now set on data segments with a configurable probability (default 0.5) rather than always or never.
- **Per-packet server ACKs**: the server now emits an individual ACK for every data segment received, matching real TCP behaviour.
- **Timestamp jitter** (`gap_jitter`): each packet is assigned a capture timestamp of `base + n×gap + uniform(0, gap_jitter)`. Because delays are independent, packets can overtake each other; the output is sorted by timestamp before being returned.
- **Packet loss** (`packet_loss_probability`): any packet can be silently dropped from the capture while sequence/acknowledgement numbers remain correct.
- **Repeating ASCII payload**: data segment payloads are now drawn from `default_payload.txt`, tiled as a continuous byte stream across all segments in a transfer.
- **INI config file** (`--config`): all `packeteer stream` parameters can be set via a `[stream]` section in a configparser INI file. CLI flags take precedence over config file values, which take precedence over built-in defaults. A fully-documented template is provided at `src/packet_generator/stream.ini.template`.

---

## 2026-03-31

### TCP stream generator
- Added `generate_tcp_stream()` in `packet_generator.tcp_stream`: generates a complete TCP connection (three-way handshake, configurable data transfer, four-way teardown) as a list of `TCPStreamPacket` objects with correct sequence/acknowledgement numbers, 32-bit wrap-around, and per-packet timestamps.
- Added `packeteer stream` subcommand exposing the most common parameters as CLI flags.
- Added `TCPStream.to_pcap_tuples()`, `client_packets()`, and `server_packets()` helpers.
- Added `packet_hooks` extensibility seam for custom anomaly injection.

### Project restructure
- Source tree reorganised into `src/` layout.
- `packet_lab.py` renamed to `packeteer_cli.py`; entry point updated accordingly.

---

## 2026-03-29

### Sanitise subcommand
- Added `replacer` module and `packeteer sanitise` subcommand. Replaces IP addresses, MAC addresses, port numbers, and payload data in a parsed JSON config with synthetic but structurally valid equivalents drawn from IANA-reserved ranges (RFC 5737 for IPv4, 2001:db8::/32 for IPv6, locally-administered MACs). Replacements are consistent within a single call, preserving communication structure.
- Project renamed from `packet_lab` to `packeteer`.

---

## 2026-03-28

### Sphinx documentation
- Added Sphinx documentation site with MyST-parser, covering all subcommands, the packet builder API, the parser pipeline, and the JSON config format.

### GRE tunnelling
- Added GRE tunnel support (RFC 2784 / RFC 2890): builder, parser, CLI, and docs. Supports optional Key, Sequence Number, and Checksum fields.

---

## 2026-03-27

### IP-in-IP tunnelling
- Added IP-in-IP encapsulation support (RFC 2003 IPv4-in-IPv4; RFC 4213 IPv6-in-IPv4 and IPv4-in-IPv6): builder, parser, CLI, and docs.
- Refactored `PacketBuilder`, `to_config`, and CLI to eliminate duplication introduced by the growing layer stack.

---

## 2026-03-26

### Encapsulation protocols
- **EtherIP** (RFC 3378): builder, parser, CLI, and docs.
- **PPPoE** (RFC 2516): builder, parser, CLI, and docs. Supports both Discovery and Session frames with tag encoding.
- **MPLS** (RFC 3031 / RFC 3032): label stack builder, parser, CLI, and docs.
- **QinQ / IEEE 802.1ad**: double-tagged VLAN support via the existing `PacketBuilder` layer stack.
- `PacketBuilder` refactored to an arbitrary-depth layer stack, replacing the previous fixed two-layer model.

---

## 2026-03-22

### pcapng support
- Added `write_pcapng()`: writes pcapng files with Section Header Block, Interface Description Block, and Enhanced Packet Blocks. Supports nanosecond timestamps.
- `packeteer parse` now writes pcapng output (`--pcapng`) and includes `file_metadata` in JSON output.

### Packet parser
- Added `packet_parser` pipeline: parses libpcap and pcapng files into structured dicts. Supports Ethernet, 802.1Q VLAN, IPv4, IPv6, TCP, UDP, ICMP, and ICMPv6.
- Added `packeteer parse` subcommand: reads a capture file and writes a JSON config (and optionally a replayed pcap/pcapng).
- Added nanosecond pcap read/write support.
- Added JSON config format documentation.

---

## 2026-03-21

### PacketBuilder improvements
- **IEEE 802.3 padding**: Ethernet frames shorter than 60 bytes are zero-padded when `pad=True`.
- **Full TCP header coverage** (RFC 9293): urgent pointer, reserved bits, and TCP options (MSS, window scale, SACK permitted, SACK blocks, timestamps) are now supported in both builder and parser.
- Exposed all IP and TCP header fields in JSON config and public API.
- Switched to multi-packet JSON config format; single-packet format removed.

---

## 2026-03-18

### CLI and pcap output
- Added `--pcap` flag to write libpcap output directly from the CLI.
- Added JSON config file support (`packeteer build <config.json>`): builds one or more packets from a declarative JSON description.

---

## 2026-03-17

### Initial release
- `PacketBuilder`: fluent API for assembling raw packets layer by layer — Ethernet II, IEEE 802.1Q VLAN, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6.
- IPv4 and IPv6 fragmentation (`fragment_ipv4()`, `fragment_ipv6()`).
- RFC 1071 checksum computation for IPv4 headers and TCP/UDP/ICMP pseudo-headers.
- `write_pcap()`: writes libpcap files with microsecond or nanosecond timestamps.
- Comprehensive docstrings, type hints, and README with full API reference.
