# Changelog

All notable changes to packeteer are recorded in this file.

---

## Unreleased — 2026-04-05

### TCP stream: stray packet injection (TCP hijacking simulation)
- Added `stray_packet_count` parameter to `generate_tcp_stream()` and `--stray-packets N` CLI flag.  Injects forged client→server packets that reuse seq/ack values stolen from randomly chosen data segments, carrying an all-`x` payload of random size.  Simulates a passive attacker attempting to hijack a connection.  Stray packets are labelled `STRAY[n]`.
- Added `stray_timing_window` parameter and `--stray-timing-window N` CLI flag.  When set, each stray packet's timestamp is constrained to within N packets of its reference DATA packet in the timestamp-sorted stream, simulating an attacker who injects close in time to the segment they are targeting.  Defaults to `None` (full data-transfer window).

---

## 2026-04-03

### TCP stream: middlebox MTU fragmentation
- Added `middlebox_mtu` parameter to `generate_tcp_stream()` and `--middlebox-mtu` CLI flag.  Any packet whose IP-layer size exceeds the configured MTU is split into IP fragments (IPv4 Flags/Fragment Offset; IPv6 Fragment Extension Header) as if it had passed through a low-MTU router or VPN tunnel.  Fragment packets are labelled `FRAG[<orig>][<n>]`.

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
