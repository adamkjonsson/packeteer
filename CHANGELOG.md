# Changelog

All notable changes to packeteer are recorded in this file.

---

## Unreleased

### New features

- **ARP support (RFC 826)** — the Address Resolution Protocol is now supported
  end-to-end across the builder, parser, packet-spec serialisation, `file-info`,
  and `sanitise`.  Previously an ARP frame's EtherType (`0x0806`) was
  unrecognised, so it was dropped to an opaque payload and could not be authored
  — a real gap given how common ARP is in Ethernet captures.

  ARP is modelled for the common IPv4-over-Ethernet case, with MAC/IP string
  fields; `hardware_type`, `protocol_type`, and `operation` are overridable, so
  ARP requests/replies, RARP, gratuitous ARP, probes, and announcements are all
  expressible.  It is a terminal Layer-2 protocol (no IP/transport, nothing
  follows), authored via the Python API or a packet spec — there is no `stream`
  encapsulation flag.

  - `PacketBuilder.arp(operation=…, sender_mac=…, sender_ip=…, target_mac=…,
    target_ip=…)` appends an ARP packet after `.ethernet()`; the Ethernet
    EtherType is set to `0x0806` automatically and the frame pads to the 60-byte
    minimum.
  - The parser recognises EtherType `0x0806` and decodes the packet into the new
    `ParsedPacket.arp` field (with `ip` / `transport` left `None`).
  - `packeteer parse` serialises ARP packets to a top-level `"arp"` key;
    `packeteer build` reconstructs them.
  - `packeteer file-info` reports an `arp` layer count.
  - `packeteer sanitise` rewrites the ARP sender/target MAC and IP addresses
    using the same replacement tables as the Ethernet/IP layers, so an address
    maps consistently wherever it appears.
  - New `ARPHeader` dataclass, `ETHERTYPE_ARP` (`0x0806`), and `ARP_OP_*` /
    `ARP_HW_ETHERNET` constants exported from `packeteer.generate`; new
    `packeteer.parse.arp` parser module.
  - New tests in `test_arp.py`.

- **GTP-U encapsulation (3GPP TS 29.281)** — GPRS Tunnelling Protocol, user
  plane (GTPv1-U), is now supported end-to-end across the builder, stream
  encapsulation, parser, packet-spec serialisation, and CLI.  GTP-U is
  ubiquitous in 4G/5G mobile captures.  It rides on UDP destination port 2152
  and, for the user-plane **G-PDU** message, carries an inner **IP** packet
  directly (no inner Ethernet frame) — so it is shaped like IP-in-GRE / IP-in-IP
  rather than the Ethernet-wrapping VXLAN/GENEVE.

  - `PacketBuilder.gtpu(teid=…, message_type=…, sequence=…, n_pdu=…,
    extension_headers=…)` inserts the GTP-U header after the outer UDP layer.
    The Length field, the E/S/PN flags, and the extension-header chaining are
    computed automatically; as with `.vxlan()`/`.geneve()` a preceding `.udp()`
    left on its default port is rewritten to 2152.
  - New `GTPUEncap(teid, src_ip, dst_ip, ttl=64, udp_src_port=2152, sequence=…,
    n_pdu=…, extension_headers=…)` stream descriptor wraps any TCP/UDP/SCTP
    stream's IP as the inner G-PDU payload.
  - `GTPUExtensionHeader(header_type, content)` models one extension header
    (the 5G PDU Session Container lives here); content is raw bytes.
  - The parser recognises GTP-U by the outer UDP destination port 2152, retains
    the outer UDP header in `ParsedPacket.transport`, and stores the decoded
    `GTPUHeader` (TEID, sequence, N-PDU, extension headers) in the new
    `ParsedPacket.gtpu` field.  For a G-PDU the inner IP packet is parsed
    recursively into `tunneled`; other message types leave their content in
    `payload`.
  - `packeteer parse` serialises GTP-U packets with a top-level `"gtpu"` key
    (TEID, optional fields, `extension_headers`, and the inner IP spec);
    `packeteer build` reconstructs them.  `packeteer stream` gains `--gtpu SRC
    DST`, `--gtpu-teid`, `--gtpu-ttl`, and `--gtpu-src-port` flags (sequence /
    extension headers are set via the Python API / packet spec).
  - New `GTPUHeader` / `GTPUExtensionHeader` dataclasses, `GTPU_PORT` (2152), and
    `GTPU_MSG_*` message-type constants exported from `packeteer.generate`; new
    `packeteer.parse.gtpu` parser module.  Control-message Information Elements
    are not modelled (a generic `message_type` lets control messages be built as
    headers).
  - New tests in `test_gtpu.py`, plus GTP-U cases in `test_stream_encap.py` and
    `test_cli.py`.

- **GENEVE encapsulation (RFC 8926)** — Generic Network Virtualization
  Encapsulation is now supported end-to-end across the builder, stream
  encapsulation, parser, packet-spec serialisation, and CLI.  GENEVE is VXLAN's
  successor: it also rides on UDP (destination port 6081) but adds a Protocol
  Type field (so it can carry an inner Ethernet frame *or* IPv4/IPv6 directly)
  and a list of variable-length TLV options.

  - `PacketBuilder.geneve(vni=…, options=…, oam=…)` inserts the GENEVE header
    after the outer UDP layer.  The Protocol Type is set automatically from the
    next layer (inner Ethernet → `0x6558`, IPv4 → `0x0800`, IPv6 → `0x86DD`),
    the Opt Len and C (critical) flag are computed from the options, and — as
    with `.vxlan()` — a preceding `.udp()` left on its default port is rewritten
    to 6081.
  - New `GeneveEncap(vni, src_ip, dst_ip, ttl=64, udp_src_port=6081, options=[])`
    stream encapsulation descriptor wraps any TCP/UDP/SCTP stream as inner
    traffic.
  - `GeneveOption(option_class, type, critical, data)` models one TLV option;
    option data is carried as raw bytes (a multiple of 4 bytes).
  - The parser recognises GENEVE by the outer UDP destination port 6081, retains
    the outer UDP header in `ParsedPacket.transport`, stores the decoded
    `GeneveHeader` (including options) in the new `ParsedPacket.geneve` field,
    and recurses into the inner frame — `LINKTYPE_ETHERNET` for TEB, otherwise
    raw IP — under `tunneled`.
  - `packeteer parse` serialises GENEVE packets with a top-level `"geneve"` key
    (VNI, `options`, and the nested inner-frame spec); `packeteer build`
    reconstructs them.  `packeteer stream` gains `--geneve SRC DST`,
    `--geneve-vni`, `--geneve-ttl`, and `--geneve-src-port` flags (options are
    set via the Python API / packet spec, not the CLI).
  - New `GeneveHeader` / `GeneveOption` dataclasses, `GENEVE_PORT` (6081), and
    `GENEVE_PROTO_*` constants exported from `packeteer.generate`; new
    `packeteer.parse.geneve` parser module.
  - New tests in `test_geneve.py`, plus GENEVE cases in `test_stream_encap.py`
    and `test_cli.py`.

- **VXLAN encapsulation (RFC 7348)** — Virtual eXtensible LAN tunnelling is now
  supported end-to-end across the builder, stream encapsulation, parser,
  packet-spec serialisation, and CLI.

  - `PacketBuilder.vxlan(vni=..., flags=...)` inserts the 8-byte VXLAN header
    after the outer UDP layer.  When the preceding `.udp()` is left on its
    default port, the destination port is switched to the standard VXLAN port
    (4789) automatically; an explicit non-default port is preserved.
  - New `VXLANEncap(vni, src_ip, dst_ip, ttl=64, udp_src_port=4789)` stream
    encapsulation descriptor wraps any generated TCP/UDP/SCTP stream as inner
    traffic inside an outer Ethernet / IP / UDP:4789 / VXLAN / inner-Ethernet
    stack.
  - Unlike the IP-protocol tunnels (GRE/EtherIP/IP-in-IP), VXLAN is recognised
    by the outer UDP destination port 4789, so the parser retains the outer UDP
    header in `ParsedPacket.transport` and stores the decoded `VXLANHeader` in
    the new `ParsedPacket.vxlan` field, with the inner Ethernet frame parsed
    recursively into `tunneled`.
  - `packeteer parse` serialises VXLAN packets with a top-level `"vxlan"` key
    (VNI plus the nested inner-frame spec) alongside the outer UDP transport;
    `packeteer build` reconstructs them.
  - `packeteer stream` gains `--vxlan SRC DST`, `--vxlan-vni`, `--vxlan-ttl`,
    and `--vxlan-src-port` flags (and matching INI keys).
  - New `VXLANHeader` dataclass, `VXLAN_PORT` (4789), and `VXLAN_FLAG_VALID_VNI`
    (`0x08`) exported from `packeteer.generate`; new `packeteer.parse.vxlan`
    parser module.
  - New tests in `test_vxlan.py`, plus VXLAN cases added to `test_stream_encap.py`
    and `test_cli.py`.

- **Fictive VPN payload type for `packeteer stream`** — `--payload vpn`
  generates a small binary VPN protocol over two UDP channels: a key-exchange
  channel (`--vpn-key-port`, default 51821) doing a three-message handshake
  (INIT → RESPONSE → CONFIRM, each carrying a random value) at the start of
  every key epoch, and a CTR-mode data channel (`--vpn-data-port`, default
  51820) whose packets each carry a 64-bit counter followed by random
  "ciphertext".

  `--vpn-epochs E` sets the number of key negotiations; `--packets N` data
  packets flow after each handshake, so a rekey happens every `N` packets.
  Data is bidirectional with an independent per-direction counter that resets at
  each rekey.  Composes with `--sessions`; `--seed` makes it reproducible.  In
  `--json` output, labels read e.g. `KEY-INIT[epoch=0]`, `DATA c2s ctr=3 epoch=0`.

  New Python API in `packeteer.generate`: `generate_vpn_stream` and `VPNConfig`,
  plus `render_udp_session` (a UDP analogue of `render_tcp_session`).
  `UDPSession.send`/`recv` now also accept an optional `label`.

- **HTTP REST payload generation for `packeteer stream`** — `--payload http`
  replaces random byte payloads with a simulated REST client.  It generates
  random but plausible HTTP/1.1 traffic — varied methods (GET/POST/PUT/DELETE/
  PATCH), REST paths with resource IDs, query strings, realistic headers, and
  JSON request/response bodies — as a genuine **bidirectional** request/response
  exchange.  Server responses carry status codes correlated to the method
  (e.g. POST→201, DELETE→204) with occasional 4xx/5xx.  The traffic is valid
  HTTP that round-trips through `packeteer parse`.

  `--requests N` sets the number of transactions; `--requests-per-connection K`
  groups them onto connections (omitted = one keep-alive connection; `1` = a
  new connection per request).  It composes with `--sessions`, and `--seed`
  makes the whole capture reproducible.  In `--json` output each data segment's
  label carries the HTTP semantics (e.g. `GET /api/v1/orders/4821`,
  `201 Created`).

  New Python API in `packeteer.generate`:

  ```python
  from packeteer.generate import generate_http_stream

  mix = generate_http_stream(
      client_ip="10.0.0.1", server_ip="10.1.0.1",
      requests=50, requests_per_connection=1, seed=42,
  )                                    # -> CombinedStream
  ```

  Built on a small payload abstraction (`AppMessage`, `render_tcp_session`,
  `generate_http_conversation`, `HTTPRestConfig`) that future payload types plug
  into.  `packeteer.generate.http.encode_http_message` is now public, and
  `TCPSession.send`/`recv` accept an optional `label`.

- **Multiple sessions in `packeteer stream`** — `--sessions N` generates `N`
  independent conversations (distinct IP pairs) in a single capture instead of
  one.  Session `i` uses `client-ip + i` and `server-ip + i`, and the sessions
  are **interleaved**: each starts at a random offset within `--session-stagger`
  seconds (default 1.0) and the packets are merged in timestamp order, so the
  output looks like concurrent traffic.

  Clients and servers are kept in clearly separated address ranges — if the two
  ranges would overlap the command errors out rather than emitting traffic where
  one session's client address is another session's server.  MAC addresses are
  shared across sessions (a common L2 next-hop), and `--seed` makes the whole
  mix reproducible.

  New Python API in `packeteer.generate`:

  ```python
  from packeteer.generate import generate_session_mix, merge_streams, TCPStreamConfig

  mix = generate_session_mix(
      sessions=20, client_ip="10.0.0.1", server_ip="10.1.0.1",
      config=TCPStreamConfig(seed=42),
  )                                    # -> CombinedStream
  ```

  `generate_session_mix` selects the protocol from the config type
  (`TCPStreamConfig` / `UDPStreamConfig` / `SCTPStreamConfig`); `merge_streams`
  combines and timestamp-sorts streams you build yourself.

- **`packeteer file-info` — capture summary report** — new subcommand and
  Python API for getting a quick overview of a pcap or pcapng file without
  fully decoding it to a packet spec.

  Reports the packet count, the number of **directional** sessions (unique
  ordered 5-tuples `(src, dst, src_port, dst_port, protocol)`), the capture
  duration, and per-protocol-layer statistics (how many packets contain each of
  `ethernet`, `vlan`, `mpls`, `pppoe`, `ipv4`, `ipv6`, `tcp`, `udp`, `icmp`,
  `dns`, `http`, and so on).

  The command auto-corrects a wrong link-layer type: it scores the type
  declared in the file header against the supported alternatives (`ethernet`
  and `raw`) by how many packets parse to a valid IP header, and uses whichever
  is cleanest.  The heuristic is conservative — it only overrides when the
  declared type clearly produces garbage — and is disabled by passing an
  explicit `--link-type` or `--no-auto-link-type`.

  Output is a human-readable text report by default, or JSON with `--json`.
  Malformed files (bad magic, short header, truncated records) fail with a
  readable error; structurally valid files with garbage packet contents are
  reported best-effort, and the text report flags captures where no packet
  contained an IP layer (a strong "corrupt or wrong link-type" signal).

  `--num N` (`-n`) analyses only the first `N` packets, stopping the read early
  so the rest of the file is never loaded.  This makes link-type detection fast
  on very large captures — the true type can usually be determined from a small
  sample.  The supporting `packeteer.pcap.read_pcap` gained a `max_packets`
  argument that drives this early-stopping, streaming read.

  Public Python API in `packeteer.parse`:

  ```python
  from packeteer.parse import pcap_info, format_pcap_info

  info = pcap_info(path="capture.pcap")   # -> PcapInfo
  print(info.packet_count, info.session_count, info.layer_counts)
  print(format_pcap_info(info))           # the text report the CLI prints
  ```

  `pcap_info` accepts the same `link_type` override as `read_pcap` /
  `parse_pcap_file`, plus `auto_link_type` to toggle the detection heuristic.

- **Link-layer type override when parsing captures** — captures sometimes
  declare the wrong link-layer type in their header, which drives incorrect
  parsing.  The recorded value can now be overridden at every level:

  - `read_pcap(..., link_type=...)` replaces the link type in the returned
    `PcapFile.header` after reading, so all downstream consumers see the
    corrected value.
  - `parse_pcap_file(..., link_type=...)` forwards the override to `read_pcap`;
    the corrected value also flows into the emitted `metadata.link_type` so the
    resulting spec replays with the right type.
  - `packeteer parse` and `packeteer sanitise` gain a `--link-type TYPE` flag
    accepting `ethernet`, `raw`, or an integer (e.g. `1`, `101`).  For
    `sanitise`, the flag is ignored when the input is a JSON packet spec.

- **`packeteer fuzz` — adversarial packet variant generator** — new subcommand
  and Python API for testing decoder robustness.  Give it a correctly-formed
  capture or packet spec and it produces a suite of deliberately unusual or
  malformed variants covering a wide range of protocol-edge and wire-format
  corner cases.

  Two complementary mutation families are provided:

  *Spec-level* — operate on the packet spec JSON and produce well-formed but
  unusual packets (suitable for replay through a real encoder):

  | Mutation | What it produces |
  |----------|-----------------|
  | `boundary` | Sets numeric header fields to their minimum, near-minimum, near-maximum, and maximum representable values (TTL, TOS, IP identification, fragment offset, TCP window/seq/ack, port numbers, ICMP id/seq, SCTP verification tag) |
  | `reserved-bits` | Sets the IPv4 "evil bit" (RFC 3514), the DF+MF combination (RFC-invalid), and the TCP reserved nibble |
  | `tcp-flags` | All classically pathological TCP flag combinations: SYN+FIN, SYN+RST, null scan, XMAS, FIN-only, PSH+URG without ACK, RST+ACK+URG, ECE+CWR |
  | `truncate` | Removes the payload or cuts it to 1 byte, 25%, or 50% of its original length |
  | `extend` | Appends extra zero bytes (1, 4, 8, 64, 512) or 16 random bytes after the existing payload |

  *Byte-level* — operate on raw serialised bytes and produce structurally
  invalid encodings that no spec-based builder can produce:

  | Mutation | What it produces |
  |----------|-----------------|
  | `bit-flip` | Flips a single random bit per variant; `--count` controls how many variants are produced per source packet |
  | `wrong-checksum` | Sets IP, TCP, and UDP checksum fields to `0x0000`, `0xffff`, and the bitwise inverse of the original value |
  | `wrong-length` | Sets IP total-length and UDP length fields to zero, IHL-only, off-by-one (both directions), and maximum (`0xffff`) |

  Public Python API in `packeteer.fuzz`:

  ```python
  from packeteer.fuzz import fuzz, fuzz_bytes, FuzzOptions

  # Spec-level variants — returns list[FuzzVariant]
  variants = fuzz(config, FuzzOptions(mutations=["boundary", "tcp-flags"], seed=42))
  for v in variants:
      print(v.source_idx, v.mutation, v.label)

  # Byte-level variants — returns list[(label, bytes)]
  for label, corrupted in fuzz_bytes(raw_pkt, FuzzOptions(seed=42)):
      write_to_pcap(corrupted)
  ```

  - `FuzzOptions` controls which mutations are applied, how many `bit-flip`
    variants are produced per packet (`count`, default 10), and the RNG seed
    for reproducibility.  The same `FuzzOptions` instance can be passed to both
    `fuzz()` and `fuzz_bytes()`; each silently ignores names irrelevant to its
    domain.
  - `FuzzVariant` carries `source_idx`, `mutation`, `label`, and `spec` (an
    independent deep copy of the mutated packet dict, ready for
    `{"packets": [v.spec]}` replay through `packeteer build`).
  - `MUTATION_NAMES`, `BYTE_MUTATION_NAMES`, and `ALL_MUTATION_NAMES` are
    exported constants listing the supported mutation type names.
  - `packeteer fuzz <FILE>` accepts a pcap, pcapng, or packet spec as input;
    output can be written to `--pcap`, `--pcapng`, and/or `--output` (JSON
    packet spec) simultaneously.  `--mutations`, `--count`, and `--seed` flags
    map directly to `FuzzOptions`.
  - 104 new tests in `test_fuzz.py` (1792 total).

- **IPv6 Hop-by-Hop Options extension header (RFC 8200 §4.3)** — the
  Hop-by-Hop Options header (next_header=0) is now supported end-to-end across
  the builder, parser, and packet-spec serialisation.

  - Three new option dataclasses exported from `packeteer.generate`:
    - `RouterAlertOption(value=0)` — RFC 2711 Router Alert; value `0`=MLD,
      `1`=RSVP, `2`=Active Networks (IANA registry).
    - `JumboPayloadOption(jumbo_length=N)` — RFC 2675 Jumbo Payload; carries
      an IPv6 payload length exceeding 65 535 bytes.
    - `RawOption(option_type, data)` — arbitrary or unrecognised option encoded
      as a raw type byte and value bytes.
  - New container dataclass `HopByHopOptions(options=[…])` holds a list of the
    above options.  Padding (Pad1 / PadN) to the required 8-byte boundary is
    computed automatically at build time and is not stored in the model.
  - `IPv6Header` gains an optional `hop_by_hop` field (default `None`).  When
    set, the wire `next_header` value is `0`; `IPv6Header.next_header` always
    reflects the actual transport protocol (e.g. `6` for TCP) for consistent
    config serialisation.
  - `PacketBuilder.hop_by_hop_options(options)` — new fluent method.  Call it
    immediately after `.ip()` (IPv6 address) and before the transport method.
    The enclosing IPv6 header's `next_header` is set to `0` automatically; the
    HBH extension header's `next_header` is set to the transport protocol:

    ```python
    from packeteer.generate import PacketBuilder, RouterAlertOption

    pkt = (PacketBuilder()
        .ip(src="::1", dst="::2")
        .hop_by_hop_options([RouterAlertOption(value=0)])  # MLD
        .udp(dst_port=9999)
        .build()
    )
    ```

  - The parser (`packeteer.parse.ip._parse_ipv6`) detects `next_header == 0`,
    walks the TLV option list (skipping Pad1/PadN), and populates
    `IPv6Header.hop_by_hop`.  The returned consumed-byte count advances past
    the extension header so the transport parser receives the correct slice.
    Malformed HBH headers (advertised size exceeds available bytes) produce
    `(0, None, None)` from `packet_parser`, consistent with other parse errors.
  - `packeteer.parse.to_config` serialises `hop_by_hop_options` as an array
    inside the `"network"` section when `hop_by_hop` is set:

    ```json
    "network": {
      "src": "::1", "dst": "::2", "protocol": "udp", "ttl": 64,
      "hop_by_hop_options": [
        { "type": "router_alert", "value": 0 }
      ]
    }
    ```

  - New constants: `HBH_NEXT_HEADER` (`0`), `HBH_OPT_ROUTER_ALERT` (`0x05`),
    `HBH_OPT_JUMBO_PAYLOAD` (`0xC2`) — all exported from `packeteer.generate`.
  - 36 new tests in `test_hbh_options.py` covering wire encoding, alignment,
    parsing, round-trips, `PacketBuilder` integration, and config serialisation
    (1529 total).

- **PII scanning in UTF-8 payloads** — `sanitise` now by default
  scans every UTF-8 encoded payload for email addresses and personal names
  and emit a warning for each unique finding.

  - New public class `PersonalDataWarning(UserWarning)` exported from
    `packeteer.sanitise`.  Carries four typed attributes: `kind` (`"email"` or
    `"name"`), `text` (the matched string), `match` (an excerpt with up to 40
    characters of surrounding context), and `packet_num` (1-based number of the
    first packet where the finding appeared).
  - Findings are consolidated across all packets in a single run: if the same
    email address appears in multiple packets, one consolidated warning is
    emitted listing all packet numbers and the first-occurrence context excerpt.
  - Detection patterns:
    - **Email addresses** — RFC 5321 local-part + domain regex.
    - **Display names (tier 1)** — RFC 5322 quoted (`"Alice Smith"`) or
      unquoted (`Alice Smith`) names immediately followed by `<addr@domain>`.
    - **Field-label names (tier 2)** — two-or-more title-case words after a
      recognised label (`name:`, `from:`, `recipient:`, `sender:`, `to:`,
      `contact:`, `full_name:`).
  - `SanitiseOptions` gains a new boolean field `scan_pii` (default `False`).
    Opt-in only — existing calls are unaffected.
  - New `--scan-pii` and `--no-scan-pii` flags added to `packeteer sanitise`.  The flags do not
    modify the output; combine with `--payload` to also zero the payloads.
  - Only `"utf8"` encoded payloads are scanned; hex payloads are never
    inspected.
  - 37 new tests in `test_sanitise_pii.py`.

- **`packet_num` in `packet_metadata`** — `parse_pcap_file` now writes a
  `packet_num` field (1-based integer) into each packet's `"packet_metadata"`
  section.  This makes it easy to identify specific packets in PII warnings and
  other tooling without manually counting positions in the JSON array.

### Enhancements

- **`packeteer file-info` reports the full tunnelled stack** — the layer
  statistics now recurse into tunnelled packets so the report is a comprehensive
  view of a capture's protocol content.  Previously only the outermost layers
  were counted, and the UDP-based overlays (VXLAN, GENEVE, GTP-U) were not
  recognised at all — a VXLAN-over-UDP capture showed only `ethernet` / `ipv4` /
  `udp`.  Now the outer layers, the tunnel type (`gre`, `etherip`, `ipip`,
  `pseudowire`, `vxlan`, `geneve`, `gtpu`), and the inner frame's layers all
  contribute.  A layer present at multiple depths in one packet counts that
  packet once (the counts remain "number of packets containing this layer").

- **`datetime` ↔ pcap timestamp converters** — two helpers in `packeteer.pcap`
  simplify the common case of working with `datetime.datetime` capture times,
  which `write_pcap` / `write_pcapng` / `read_pcap` otherwise express as a
  `(ts_sec, ts_frac)` pair:

  - `datetime_to_pcap_ts(dt, *, nanoseconds=False) -> (ts_sec, ts_frac)` for the
    write side — unpack it straight into a record tuple:
    `write_pcap([(raw, *datetime_to_pcap_ts(dt))], ...)`.  A naive *dt* is
    treated as UTC, conversion is integer-exact to the microsecond, and a
    `ValueError` is raised for timestamps outside the 32-bit `ts_sec` range
    (pre-1970 or beyond year 2106).
  - `pcap_ts_to_datetime(ts_sec, ts_frac, *, nanoseconds=False) -> datetime`
    for the read side — returns a timezone-aware UTC datetime.
  - `datetime` has only microsecond resolution, so nanosecond timestamps
    round-trip on a microsecond grid (documented on both helpers).
  - The `write_pcap` / `write_pcapng` signatures are unchanged — the helpers are
    opt-in converters, not a new accepted tuple shape.
  - 14 new tests in `test_pcap_timestamps.py`.

- **TCP flag constants used consistently throughout the codebase** — raw
  numeric literals (`0x002`, `0x018`, …) have been replaced with the named
  constants already exported from `packeteer.generate` (`TCP_SYN`,
  `TCP_PSH | TCP_ACK`, etc.).

  - `packeteer.fuzz` no longer defines its own private `_TCP_*` duplicates;
    it now imports the canonical constants from `packeteer.generate.tcp`.
  - `packeteer.__main__` uses `TCP_SYN` as the default flags value when
    building a TCP packet from a spec that omits the field.
  - All test files (`test_cli.py`, `test_filter.py`, `test_http.py`) import
    and use the named constants.

- **RNG seed and reproducibility for all stream generators** — passing `seed`
  to any stream generator produces byte-identical captures across runs.

  - `TCPStreamConfig`, `UDPStreamConfig`, and `SCTPStreamConfig` all expose a
    `seed: int | None` field (default `None` — non-deterministic).  Setting it
    to the same integer value on two calls with otherwise identical arguments
    produces bit-for-bit identical pcap output.
  - `UDPStreamConfig` and `SCTPStreamConfig` are new dataclasses (previously
    UDP and SCTP generators had no config object).  Each bundles the same four
    leading fields as `TCPStreamConfig`: `payload_sizes`, `base_time`,
    `gap_jitter`, and `seed` — making the three generator APIs consistent.
  - Each generator call creates a private `random.Random(seed)` instance,
    keeping the generator's random state fully isolated from the rest of the
    process.  All randomised decisions within a call (payload sizes, jitter,
    anomaly injection) draw from the same instance.
  - The shared `_payload_sizes` helper in `_stream_common.py` now accepts the
    `rng` instance explicitly so payload-size draws participate in the same
    deterministic sequence.
  - `--seed N` flag added to `packeteer stream`; accepted by all three
    protocols.  The `seed` key is also recognised in INI config files.
  - `UDPStreamConfig` and `SCTPStreamConfig` exported from `packeteer.generate`.

- **Informative warning for unsupported IP protocol numbers** — when the
  parser encounters an IP protocol number it does not recognise (anything other
  than TCP, UDP, ICMPv4, ICMPv6, SCTP, GRE, EtherIP, and IP-in-IP), it now
  issues an `UnsupportedIPProtocolWarning` instead of silently discarding the
  transport layer.

  - New public class `UnsupportedIPProtocolWarning(UserWarning)` exported from
    `packeteer.parse`.  Its `.protocol` attribute carries the unrecognised
    number so callers can filter or inspect it without parsing the message
    string.
  - Direct calls to `parse_packet` receive one warning per call.
  - `parse_pcap_file` (and therefore `packeteer parse` and `packeteer
    sanitise`) consolidates the per-packet warnings into **one summary per
    unique protocol**, with the packet count and source file name:

    ```
    UserWarning: IP protocol 89 is not supported; encountered in 47 packets
    in 'capture.pcap'. Bytes after each IP header are stored in the payload field.
    ```

- **UTF-8 payload encoding in packet specs** — the `"payload"` section now
  supports an optional `"encoding"` field alongside `"data"`.

  - `"encoding": "utf8"` — `"data"` is a plain UTF-8 string, making
    text-protocol captures (HTTP bodies, DNS TXT strings, custom protocols)
    easy to read and edit directly in the JSON.
  - `"encoding": "hex"` (or omitted) — `"data"` is a lower-case hex string,
    the existing default.  Omitting `"encoding"` is fully backward-compatible.
  - `packeteer parse` auto-selects UTF-8 encoding when the captured payload
    consists entirely of printable ASCII characters (byte values 0x20–0x7E),
    and falls back to hex otherwise.
  - `packeteer build` decodes `"utf8"` payloads by calling `.encode("utf-8")`
    on the string; unknown encoding values produce an error and exit.
  - `packeteer sanitise --payload` zeroes UTF-8 payloads correctly: the byte
    length is derived from the UTF-8 encoding of the string (not the character
    count), and the `"encoding"` key is removed from the result since zeroed
    bytes are not printable text.

- **`network.protocol` always present in packet spec** — `update_config` now
  always emits the `"protocol"` key in the `"network"` section.  For
  recognised protocols the value is a string (`"tcp"`, `"udp"`, …); for
  unrecognised protocols it is the raw integer (`89`, `112`, …).  Previously
  the field was silently omitted for unknown protocol numbers, making it
  impossible to tell from the JSON alone why the transport section was absent.

### Breaking changes

- **`ethernet.pad` defaults to `true`** — Ethernet frames are now zero-padded
  to the IEEE 802.3 minimum of 60 bytes by default in both `PacketBuilder` and
  `packeteer build`.  Set `pad: false` (or `.ethernet(pad=False)`) to suppress
  padding explicitly.

- **PII scanning enabled by default** — `SanitiseOptions.scan_pii` now defaults
  to `True`.  `packeteer sanitise` will emit `PersonalDataWarning` instances for
  any email addresses or names found in UTF-8 payloads unless `--no-scan-pii`
  is passed.  Code that calls `sanitise()` directly and does not want PII
  warnings should pass `SanitiseOptions(scan_pii=False)`.

### Documentation

- **Tag vs tunnel encapsulation clarified** — the stream-generator docstrings
  (`generate_tcp_stream` / `generate_udp_stream` / `generate_sctp_stream`), the
  `stream_encap` module, and the generating / stream-encap guide pages now
  distinguish **tag-based** encaps (VLAN/QinQ/MPLS/PPPoE), which leave the
  stream's own transport on the wire, from **tunnel** encaps
  (GRE/EtherIP/IPIP/VXLAN), which carry the whole stream as inner traffic.  This
  clarifies why every stream generator accepts every encap, and that VXLAN
  always uses an outer UDP datagram on port 4789 regardless of the inner stream
  protocol.  The previously-missing `VXLANEncap` was also added to those
  docstring lists.

- **`datetime` timestamp converters documented** — `docs/api/pcap-io.md` gains a
  "Timestamp conversion" section with autodoc for `datetime_to_pcap_ts` and
  `pcap_ts_to_datetime`, and `docs/guide/pcap.md` shows building record
  timestamps from `datetime` objects and reading them back.

- **Fuzzer documentation** — four new pages covering the `fuzz` feature:
  - `docs/cli/fuzz.md` — CLI reference: usage synopsis, output options, full
    mutation type tables for both spec-level and byte-level families, flags, and
    six worked examples.
  - `docs/guide/fuzzing.md` — task-oriented Python API guide covering quick
    start, mutation type descriptions, `FuzzOptions` usage, working with
    `FuzzVariant` objects, byte-level fuzzing with `fuzz_bytes`, reproducibility,
    and CLI equivalents.
  - `docs/api/fuzzer.md` — autodoc API reference for `FuzzOptions`,
    `FuzzVariant`, `fuzz`, `fuzz_bytes`, `MUTATION_NAMES`, `BYTE_MUTATION_NAMES`,
    and `ALL_MUTATION_NAMES`.
  - `docs/internals/fuzzer.md` — developer internals: design goals, the
    `_MUTATIONS` registry pattern, per-mutation implementation details
    (boundary tables, TCP flag combos, truncate deduplication, extend zero/random
    sizing), VLAN-aware `_ip_header_offset` algorithm, and `fuzz_bytes` dispatch.
  - All relevant index pages updated (`docs/cli/index.md`, `docs/guide/index.md`,
    `docs/api/index.md`, `docs/internals/index.md`).
  - `docs/internals/architecture.md` updated to include `packeteer/fuzz.py` in
    the component diagram and module description.
  - `README.md` updated: fuzzing bullet in the features list, two new CLI
    examples in the quick-start section, a new Python API code block, and three
    new rows in the documentation table.

- **TCP flag constants in code examples** — all Python snippets in the
  documentation (`docs/introduction/overview.md`, `docs/guide/generating.md`,
  `docs/guide/parsing.md`, `docs/guide/pcap.md`) now use `TCP_SYN` instead of
  the bare hex literal `0x002`, and import it from `packeteer.generate`.

- **Atheris integration guide** — documentation on combining packeteer with
  [Atheris](https://github.com/google/atheris) for coverage-guided fuzzing:
  - `docs/internals/atheris.md` — new internals chapter covering all three
    patterns: fuzzing the pcap reader (file-format resilience), fuzzing the
    packet parser (protocol decoding resilience), and fuzzing application-layer
    decoders (user's own code under test, with packeteer providing the network
    framing).  Includes seed corpus construction from live captures, stream
    generators, and `fuzz_bytes` pre-seeding, and guidance on instrumentation
    scope.
  - `docs/guide/fuzzing.md` — new "Coverage-guided fuzzing with Atheris"
    section with a worked example: Atheris mutates an application-layer sensor
    protocol payload, packeteer wraps it in Ethernet/IP/UDP, and the user's
    decoder is the code under test.  "Next steps" updated to link to the new
    internals chapter.

- **Stream generator documentation updated** for the RNG seed and config class
  additions:
  - `docs/internals/stream-generators.md` — new "Config dataclasses" section
    (common field layout for all three classes) and "RNG and reproducibility"
    section (per-call `Random(seed)` isolation); UDP and SCTP sections now
    reference their config classes; payload content description corrected
    (was `\x00\x01…\xff`, now `default_payload.txt`).
  - `docs/cli/stream.md` — `--seed N` row added to the General arguments table;
    `seed = 42` added to the INI example.
  - `docs/guide/generating.md` — "Reproducible captures" bullet added to the
    stream-generator feature list.
  - `docs/api/stream-generators.md` — `autoclass` directives added for
    `UDPStreamConfig` and `SCTPStreamConfig`.
  - `src/packeteer/generate/stream.ini.template` — `seed` entry added to the
    Timing section.

- Sanitiser internals page updated with the full PII scanning pipeline:
  `_maybe_scan_pii`, two-tier name detection, `_excerpt`, and warning
  consolidation.
- PDF output: raised `\tymin` to 60 pt in the LaTeX preamble so short-label
  first columns are no longer squeezed in reference tables.
- Expanded introductions for the CLI (`docs/cli/index.md`) and Reference
  (`docs/reference/index.md`) sections.
- Generating guide (`docs/guide/generating.md`): reorganised so
  `PacketBuilder` is no longer used in an example before its own section;
  added a binary-payload example using `struct.pack`.
- API parser reference (`docs/api/parser.md`): documented
  `UnsupportedIPProtocolWarning`, the `.protocol` attribute, the per-call vs.
  summary warning behaviour, and the suppression pattern.
- CLI reference: `packeteer parse` and `packeteer sanitise` pages each have a
  new *Unsupported IP protocol numbers* subsection.

---

## 0.6.1 - 2026-04-25

### Bug fixes

- **Pseudowire parse: all layers after MPLS silently dropped** —
  `parse_pcap_file` was not calling `apply_tunneled` for pseudowire packets,
  so the `"pseudowire"` key and all inner layers (inner Ethernet, IP, transport,
  payload) were missing from the serialised JSON output.  The condition in
  `parse/core.py` now includes `pkt.pseudowire is not None` alongside the
  existing GRE, EtherIP, and IP-in-IP checks.

- **Pseudowire sanitise: inner Ethernet MACs double-mapped** —
  The tunnel-recursion loop in `_sanitise_packet` called `_sanitise_ethernet`
  on the inner frame explicitly *before* the recursive `_sanitise_packet` call,
  but `_sanitise_packet` already calls `_sanitise_ethernet` as its first step.
  The duplicate call caused the inner MAC addresses to be mapped twice (original
  → synthetic₁ → synthetic₂), consuming two extra entries in the MAC counter
  and landing the inner MACs at wrong synthetic values.  The redundant explicit
  call has been removed.

### Documentation

- **Wireshark / tshark pseudowire CW heuristic warning** — added a note to
  the Sanitising guide explaining that Wireshark and tshark may misidentify
  sanitised MPLS pseudowire captures as *Ethernet PW without control word*
  (`pwethnocw`).  The heuristic fails when the synthetic inner Ethernet MAC
  addresses start with `02:` (locally administered), causing EtherType
  `0x0000` to be displayed.  The sanitised pcap is RFC 4385 compliant;
  `packeteer parse` decodes it correctly.

---

## 0.6.0 - 2026-04-23

### New features

- **RFC 4385 pseudowire support** — MPLS-based pseudowires with the RFC 4385
  control word are now supported end-to-end across the builder, parser,
  sanitiser, and CLI.

  - `PacketBuilder.pseudowire(flags, frag, length, sequence)` inserts the
    4-byte control word after the bottom-of-stack MPLS label.  The MPLS S bit
    is set automatically.  The inner payload can be a full inner Ethernet frame
    (Ethernet PW) or a raw IP packet (IP PW).
  - The MPLS parser now detects the version nibble `0x0` after the BOS label
    and routes to the new `parse/pseudowire.py` parser, which infers the inner
    payload type by peeking at the following byte.
  - `ParsedPacket` gains a `pseudowire` field (the parsed `PseudowireHeader`)
    and stores the inner frame in the existing `tunneled` field.
  - `packeteer parse` serialises pseudowire packets with a top-level
    `"pseudowire"` key whose value is the control word fields plus the nested
    inner-packet spec (same structure as `"gre"` or `"etherip"`).
  - `packeteer build` reconstructs pseudowire packets from the `"pseudowire"`
    spec key, without requiring an outer `"network"` section.
  - `packeteer sanitise` walks `"pseudowire"` recursively alongside
    `"gre"`, `"ipip"`, and `"etherip"`, applying the same IP and MAC
    replacement tables to the inner frame.

### Bug fixes

- **PDF documentation — Part I missing** — the LaTeX/PDF build was silently
  discarding the Introduction part.  A `{raw} latex` block in `docs/index.md`
  was overriding `\part` so that the first call (which should typeset
  "Part I: Introduction") merely restored the original definition without
  emitting anything; Parts II–IV appeared normally.  The workaround has been
  removed; all four parts now appear in the generated PDF.

- **QinQ (802.1ad) parsing** — `packeteer sanitise` (and `packeteer parse`)
  now correctly handles double-tagged frames.  Previously the Ethernet parser
  stopped after the outer VLAN tag because the inner EtherType `0x8100` was
  not a recognised next-layer, discarding all inner layers and causing the
  rebuild step to abort with "missing network.src, network.dst, or
  network.protocol".  The parser now consumes both VLAN tags and returns the
  true payload EtherType.  The packet spec gains an `"inner_vlan"` key in the
  `"ethernet"` section (alongside the existing `"vlan"` key) when QinQ is
  present; `packeteer build` reconstructs both tags faithfully.

---

## 0.5.1 - 2026-04-22

### Documentation restructure

The documentation has been reorganised into four parts that separate the
CLI reference from the Python API guide and the task-oriented guides from
the exhaustive API reference.

- **Part 1 — Introduction**: overview (updated to introduce both the CLI and
  the Python API) and installation.  The Quick Start chapter has been removed.
- **Part 2 — CLI reference**: four new self-contained pages (`docs/cli/parse.md`,
  `docs/cli/sanitise.md`, `docs/cli/build.md`, `docs/cli/stream.md`) covering
  every flag, filter, output format, and encapsulation option for each
  subcommand with worked examples.
- **Part 3 — Python API Guide**: four new task-oriented guide pages
  (`docs/guide/parsing.md`, `docs/guide/sanitising.md`,
  `docs/guide/generating.md`, `docs/guide/pcap.md`) explaining how to
  accomplish common goals from Python.  The guide index lists the five
  importable top-level packages (`packeteer.parse`, `.generate`, `.filter`,
  `.sanitise`, `.pcap`) so readers know where to look.
- **Part 4 — Reference**: existing API autodoc pages and packet-spec format
  reference, now grouped under a single reference index.
- Old per-subcommand subdirectories (`docs/build/`, `docs/parse/`,
  `docs/sanitiser/`, `docs/stream/`, `docs/synthetic/`) removed; all
  cross-references updated to point to their precise new targets.
- README documentation table updated to reflect the new four-part structure.

---

## 0.5.0 - 2026-04-21

### Session builders for synthetic data

- New `TCPSession`, `UDPSession`, and `SCTPSession` builder classes in
  `packeteer.generate.session`.  Each follows a `.send()` / `.recv()` /
  `.send_many()` / `.recv_many()` / `.build()` fluent API: queue application
  payloads and call `.build()` to receive a fully-assembled `TCPStream`,
  `UDPStream`, or `SCTPStream` with all handshakes, sequence numbers, ACKs,
  and teardowns handled automatically.
- `TCPSession` segments large payloads at the configured MSS and sets PSH on
  the last segment of each exchange.  Unidirectional streams (call only
  `.send()` or only `.recv()`) are supported natively.
- `SCTPSession` maintains independent per-direction TSN counters so
  bidirectional exchanges produce correct TSN sequences on both sides.
- New standalone helper functions `tcp_handshake`, `tcp_teardown`, and
  `sctp_handshake` return pre-built raw-bytes lists for workflows that
  assemble captures manually.
- `TCPStreamConfig` gains a `payload_fn` field: a callable
  `(index, direction) -> bytes` that supplies each data-packet payload for
  `generate_tcp_stream`, overriding all size parameters.  The parameter was
  moved from the function signature to `TCPStreamConfig` to keep the argument
  count within the project limit.
- All six new names exported from `packeteer.generate`.
- 44 new tests in `test_session.py` (1460 total).
- `docs/api/stream-generators.md` updated with autodoc entries for all new
  classes and functions.

---

## 0.4.0 — 2026-04-19

### Documentation

- Internals docs updated for DNS, DHCP, HTTP, and `PacketFilter`:
  `architecture.md` adds `packeteer.filter` to the component diagram and
  documents application-layer parsing; `parser-pipeline.md` adds the
  `dns`, `dhcp`, and `http` fields to `ParsedPacket` and a new
  Application-layer dispatch section; `sanitiser.md` adds `dns_ids`,
  `dhcp_xids`, and `http_headers` to `SanitiseOptions` and expands the
  replacement strategy table.
- `packeteer build` CLI page now cross-references `packeteer parse` and
  `packeteer sanitise` in the parse → edit → rebuild workflow example.
- `installation.md`: "Next: Quick Start" navigation link is now
  HTML-only (suppressed in the PDF via `:::{only} html`).
- PDF headers now show the chapter name (left mark) on even pages and
  the section name (right mark) on odd pages.

### Auto-detected metadata in `packeteer parse`

- `packeteer parse` now always writes `"type"` (`"pcap"` or `"pcapng"`) and
  `"from_file"` (source path) into the top-level `metadata` block of the
  packet spec, auto-detected from the file header.  No flags are needed.
- The `--replay-pcap` and `--replay-pcapng` flags have been removed; they are
  no longer necessary now that detection is automatic.
- To override the output format when rebuilding, use `--pcap` or `--pcapng`
  with `packeteer build` as before.
- `docs/parse/cli.md` and `docs/packet-spec/format.md` updated accordingly.

### Packet filtering in `packeteer parse`

- New module `packeteer.filter`: `PacketFilter` dataclass with fields
  `proto`, `port`, `src_port`, `dst_port`, `src`, `dst`, `host`, and `app`.
  All criteria are AND-combined; a packet must satisfy every set criterion to
  be kept.
- Any value may be prefixed with `!` to negate it (e.g. `proto="!tcp"`,
  `dst_port=["!80", "!443"]`).  For list fields all values must be
  consistently positive or consistently negative; mixing raises `ValueError`.
- `src`, `dst`, and `host` accept IPv4 and IPv6 addresses and CIDR prefixes
  (`10.0.0.0/24`, `2001:db8::/32`); matching uses the stdlib `ipaddress`
  module with no external dependencies.
- `PacketFilter.matches(pkt: dict) -> bool` operates on packet spec dicts and
  can be used independently of `parse_pcap_file` to post-filter an existing
  spec in memory.
- `parse_pcap_file` gains an optional `packet_filter: PacketFilter | None`
  keyword argument; packets that do not match are excluded from the output.
- `PacketFilter` exported from `packeteer.parse` and `packeteer.filter`.
- `packeteer parse` gains eight filter flags in a new `filtering` argument
  group: `--proto`, `--port`, `--src-port`, `--dst-port`, `--src`, `--dst`,
  `--host`, `--app`.  All support `!`-negation; `--port`/`--src-port`/
  `--dst-port` accept comma-separated port lists; `--src`/`--dst`/`--host`
  accept IP addresses and CIDR prefixes.
- 48 new tests in `TestPacketFilterValidation`, `TestProtoFilter`,
  `TestPortFilter`, `TestAddressFilter`, `TestAppFilter`,
  `TestAndCombination`, `TestParseWithFilter`, and `TestFilterCLI`
  (1416 total).
- Documentation: full `## Filtering` section added to `docs/parse/cli.md`
  and a `## PacketFilter` section added to `docs/parse/python-api.md`.

### `link_type` in packet spec metadata

- `packeteer parse` now writes `"link_type"` into the top-level `metadata`
  block of the packet spec (e.g. `1` for Ethernet, `101` for raw IP), read
  directly from the pcap/pcapng file header.
- `packeteer build` reads `link_type` from `metadata` when present and passes
  it to `write_pcap` / `write_pcapng`.  When the field is absent (hand-written
  specs), the previous inference behaviour is preserved: `LINKTYPE_RAW` if all
  packets have `ethernet.enabled: false`, otherwise `LINKTYPE_ETHERNET`.
- `link_type` documented in the `metadata` table in
  `docs/packet-spec/format.md`.
- 4 new tests in `TestLinkTypeMetadata` covering parse output for Ethernet and
  raw captures, build honouring the metadata field, and build fallback
  inference (1368 total).

### HTTP/1.x support (RFC 7230)

- New module `packeteer.generate.http`: `HTTPRequest` and `HTTPResponse`
  dataclasses and `_build_http_message()` wire-format encoder.  Both CRLF and
  bare-LF line endings are produced; `Content-Length` is added automatically
  when the body is non-empty and no explicit header is present.
- New module `packeteer.parse.http`: `parse_http()` decodes an HTTP/1.x
  message from raw TCP payload bytes.  Responses are identified by the
  `HTTP/` start token; both CRLF and bare-LF line endings are accepted.
  Body bytes are trimmed to `Content-Length` when present.
- `parse_packet` / `parse_pcap_file` dispatch to the HTTP parser on TCP ports
  80 and 8080.  The result is stored in `ParsedPacket.http`.  Parse failures
  leave `pkt.payload` unchanged.
- `PacketBuilder.http(msg)` encodes an `HTTPRequest` or `HTTPResponse` and
  appends it as the packet payload.
- `packeteer parse` serialises HTTP messages to the packet spec `http` section
  with all fields (type, method/status, path/reason, version, headers, body as
  hex).
- `packeteer build` reads the `http` section from a packet spec and rebuilds
  the HTTP wire payload.
- `packeteer sanitise` redacts sensitive HTTP header values (`Host`, `Cookie`,
  `Set-Cookie`, `Authorization`, `Location`, `Referer`, `Origin`) when the new
  `SanitiseOptions.http_headers` option is set (default `False`).  New
  `--http-headers` CLI flag enables this.
- 43 new tests in `TestHTTP*` covering wire encoding, decode round-trips,
  parser edge cases, builder integration, port dispatch, to_config
  serialisation, sanitisation, and the `--http-headers` CLI flag (1364 total).
- Documentation: `.http()` method documented in `docs/build/python-api.md`;
  `http` layer added to `docs/build/cli.md`; HTTP fields added to
  `docs/parse/python-api.md` and `docs/parse/cli.md`; `--http-headers` flag
  documented in `docs/sanitiser/cli.md` and `docs/sanitiser/python-api.md`;
  full `http` spec reference added to `docs/packet-spec/format.md`; RFC 7230
  entry added to `docs/reference/rfc-references.md`; HTTP feature added to
  `README.md`.

### DHCP support (RFC 2131 / RFC 2132)

- New module `packeteer.generate.dhcp`: wire-format encoder for DHCP messages.
  `DHCPMessage` dataclass holds all RFC 2131 fixed fields plus a typed option
  list; `_build_dhcp_message()` serialises to bytes.
- New module `packeteer.parse.dhcp`: `parse_dhcp()` decodes a UDP payload into
  a `DHCPMessage`, including all typed option dataclasses for the 12 most
  common RFC 2132 options.  Unknown options fall back to `DHCPOptRaw`.
- `parse_packet` / `parse_pcap_file` dispatch to the DHCP parser on UDP ports
  67 and 68.  The result is stored in `ParsedPacket.dhcp`.
- `PacketBuilder.dhcp(msg)` encodes a `DHCPMessage` and appends it as the
  packet payload.
- `packeteer parse` serialises DHCP packets to the packet spec `dhcp` section
  with all fixed fields and typed option objects.
- `packeteer build` reads the `dhcp` section from a packet spec and rebuilds
  the DHCP wire payload.
- `packeteer sanitise` replaces DHCP IP addresses (`ciaddr`, `yiaddr`,
  `siaddr`, `giaddr`, and IPs in options 1/3/6/50/54) and the client hardware
  address `chaddr` automatically.  New `SanitiseOptions.dhcp_xids` field
  (default `False`) and `--dhcp-xids` CLI flag zero the `xid` transaction ID.
- 54 new tests in `TestDHCP*` covering encoding, decode round-trips, parser
  edge cases, builder integration, to_config serialisation, sanitisation, and
  the `--dhcp-xids` CLI flag (1321 total).

### mDNS support (RFC 6762)

- Added `DNSQuestion.unicast_response` (`bool`, default `False`): the mDNS QU
  bit (RFC 6762 §5.4).  When `True`, the top bit of the `QCLASS` wire field is
  set, requesting that the response be sent unicast rather than multicast.
- Added `DNSResourceRecord.cache_flush` (`bool`, default `False`): the mDNS
  cache-flush bit (RFC 6762 §11.3).  When `True`, the top bit of the `RRCLASS`
  wire field is set, signalling that stale cache entries for this record should
  be flushed.
- Both bits survive encode → decode round-trips and are stripped from the parsed
  `qclass` / `rclass` values so callers always see the plain class integer.
- `parse_packet` / `parse_pcap_file` now dispatch to the DNS parser on port 5353
  (mDNS) in addition to port 53 (DNS).
- Added constants `MDNS_PORT` (`5353`), `MDNS_ADDR_IPV4` (`"224.0.0.251"`),
  `MDNS_ADDR_IPV6` (`"ff02::fb"`) exported from `packeteer.generate`.
- `to_packet_spec` serialisation includes `unicast_response` / `cache_flush` in
  the packet spec when `True`; omits them otherwise to keep existing output clean.
- `packeteer build` passes `unicast_response` and `cache_flush` through from the
  packet spec when present.
- 14 new tests in `TestMDNS` covering bit encode/decode, qclass/rrclass
  integrity, port 5353 dispatch, packet spec round-trips, and constant exports
  (1267 total).
- RFC 6762 entry added to `docs/reference/rfc-references.md`.

### DNS protocol support (RFC 1035)

- Added `packeteer.generate.dns` module: `DNSMessage`, `DNSFlags`, `DNSQuestion`,
  `DNSResourceRecord`, and nine RDATA dataclasses (`DNSRDataA`, `DNSRDataAAAA`,
  `DNSRDataCNAME`, `DNSRDataNS`, `DNSRDataPTR`, `DNSRDataMX`, `DNSRDataSOA`,
  `DNSRDataTXT`, `DNSRDataRaw`).  Wire encoding handles label compression
  (RFC 1035 §4.1.4) and the mandatory 2-byte TCP length prefix (§4.2.2).
- Added `PacketBuilder.dns(msg, *, tcp=False)` fluent method: appends a
  serialised `DNSMessage` as the transport payload; pass `tcp=True` to include
  the TCP length prefix.
- Added `packeteer.parse.dns` module: decodes DNS wire format from UDP or TCP
  payloads, following pointer compression chains.  `parse_packet` / `parse_pcap_file`
  now dispatch to the DNS parser automatically when the destination or source port
  is 53; parse failures leave `pkt.payload` unchanged.
- Added `to_packet_spec` serialisation: a parsed DNS message is written to the
  `"dns"` key of the per-packet config dict, with all question and resource record
  fields expanded.
- `packeteer build` deserialises the `"dns"` packet spec key and passes the
  reconstructed `DNSMessage` to `PacketBuilder.dns()`.
- `packeteer sanitise` now sanitises DNS content when a `"dns"` key is present:
  - DNS names are replaced label-by-label (`label0`, `label1`, …) with consistent
    mapping across all names in all packets in a file, preserving shared domain
    structure.
  - IP addresses in A/AAAA RDATA reuse the same `_Replacer.ip()` mapping as
    network-layer addresses, ensuring consistency across all packet fields.
- Added `--dns-ids` flag to `packeteer sanitise`: when set, DNS transaction IDs
  are replaced with sequential synthetic values (default: preserved).
- All DNS types and constants exported from `packeteer.generate`.
- 39 new tests in `test_dns.py` covering name encoding, round-trip serialisation,
  TCP length prefix, pointer-compression edge cases, DNS sanitisation, builder
  integration, and CLI `--dns-ids`.
- Documentation: `.dns()` method documented in `docs/build/python-api.md`;
  DNS layer added to `docs/build/cli.md`; DNS fields added to
  `docs/parse/python-api.md`; `--dns-ids` flag documented in
  `docs/sanitiser/cli.md` and `docs/sanitiser/python-api.md`; full `"dns"` spec
  reference in `docs/packet-spec/format.md`; DNS quick-start example in
  `docs/quickstart.md`; RFC 1035 entry added to `docs/reference/rfc-references.md`;
  DNS feature added to `README.md`.

### PDF documentation fix

- Suppressed the spurious "Part I — In this documentation" page that appeared on
  page 3 of the PDF build.  A `{raw} latex` injection immediately before the
  `## In this documentation` heading redefines `\part` for exactly one call so
  the resulting `\part{In this documentation}` silently disappears; all
  subsequent `\part` calls are unaffected.  The heading remains visible in the
  HTML build.

### `packeteer sanitise` — pcap input and pcap output

- `packeteer sanitise` now accepts a pcap or pcapng file directly as input.
  The file type is detected from its magic number (not the extension), so the
  parse step is no longer a separate command.
- New `--pcap FILE` and `--pcapng FILE` output flags trigger the build step
  automatically, collapsing the full parse → sanitise → build pipeline into
  one command: `packeteer sanitise capture.pcap --pcap clean.pcap`.
- `--output` (JSON), `--pcap`, and `--pcapng` are independent and may be
  combined to produce multiple output formats in a single run.
- Added `is_pcap_or_pcapng(path)` to `packeteer.pcap`: reads the first 4 bytes
  and checks against all known pcap/pcapng magic numbers.

---

## 0.3.0 — 2026-04-17

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

### Module rename

- `packet_generator` → `packeteer.generate`, `packet_parser` → `packeteer.parse`, `replacer.py` → `packeteer.sanitise`, `packeteer_cli.py` → `packeteer.__main__`.  All internal imports, tests, and documentation updated; clean break with no backward-compatibility shims.
- Final sub-package names settled after an intermediate rename pass: `packeteer.generate` (not `.generator`), `packeteer.parse` (not `.parser`), `packeteer.sanitise` (not `.sanitiser`).

### pcap I/O consolidated

- All pcap read/write logic (`read_pcap`, `write_pcap`, `write_pcapng`) moved to a single `packeteer.pcap` module.  Neither `packeteer.generate` nor `packeteer.parse` re-exports pcap functions; users import them directly from `packeteer.pcap`.

### Internal wire-assembly functions

- All 12 `build_*` wire-assembly functions renamed to `_build_*`, making them private implementation details.  The public entry point for building packets is `PacketBuilder`; the `_build_*` functions are no longer part of the public API.

### TCPStreamConfig

- `generate_tcp_stream()` now accepts a `TCPStreamConfig` dataclass instead of individual keyword arguments.  All stream parameters are grouped into one typed, inspectable object.  Exported from `packeteer.generate`.

### Public API completions

- `ETHERTYPE_IPV4`, `ETHERTYPE_IPV6`, and `ETHERTYPE_8021Q` are now exported from the `packeteer.generate` top-level package (previously only accessible via `packeteer.generate.ethernet`).
- `read_pcap`, `update_config`, `apply_tunneled`, `to_packet_spec`, and `to_json_string` are now exported from the `packeteer.parse` top-level package (previously only accessible via their sub-modules).
- `__all__` added to `packeteer.sanitise` and all `packeteer.generate` / `packeteer.parse` sub-modules to make the public API surface explicit.

### PDF documentation

- `docs/Makefile` gains `fresh`, `pdf`, and `fresh-pdf` targets.  `fresh`/`fresh-pdf` reinstall the package before building so the version number is always current.  `pdf`/`fresh-pdf` compile via `sphinx -b latex` + `latexmk` (two-step), which runs as many pdflatex passes as needed to resolve cross-references.
- Box-drawing characters (`┌─│┐└┘├┬┼`) and filled triangles (`▶`, `▼`) replaced with ASCII equivalents throughout all Markdown source files so pdflatex does not error on unsupported Unicode.
- `conf.py`: added `latex_toplevel_sectioning = "part"` and `latex_elements` with `\setcounter{tocdepth}{2}` so sections appear as chapters in the PDF and the table of contents shows two levels of depth.

### Developer documentation

- New `docs/internals/` section aimed at contributors and library extenders.
- Six pages covering: architecture and data flow, `PacketBuilder` assembly
  internals, parser pipeline state machine, stream generator internals (TCP
  connection state, anomaly injection, timestamp allocation), encapsulation
  internals (`_apply_encap`, `_encap_ip_start`, PPPoE length patching), and
  sanitiser internals (`_Replacer` state, IANA-reserved allocation ranges).

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
