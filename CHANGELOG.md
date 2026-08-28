# Changelog

All notable changes to packeteer are recorded in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the usual 0.x caveat: **while the version is below 1.0, a minor bump
(0.7 → 0.8) may break backwards compatibility.**  Breaking entries are marked
**Breaking:** so they are easy to find before upgrading.

Change types used here are the Keep a Changelog set — *Added*, *Changed*,
*Deprecated*, *Removed*, *Fixed*, *Security* — plus a project-specific
*Documentation* section for docs-only work.  Types with nothing to report are
omitted.

---

## [Unreleased]

<!--
Add entries here as work lands, under the change types listed above.
Releasing: rename this heading to `## [X.Y.Z] - YYYY-MM-DD`, add a fresh
Unreleased section above it, drop the `.devN` suffix from the version in
pyproject.toml, update the link definitions at the bottom of this file, tag
`vX.Y.Z`, and close the release's issues and milestone.
-->

### Added

- **`packeteer.protocols` — a registry for application-layer protocols**
  (#96) — `AppProtocol` is the contract an application protocol satisfies:
  the ports and transport that identify it, the message types it decodes to,
  and callables for `decode`, `encode`, `to_spec`, `from_spec` and an optional
  `sanitise`.  `register`, `unregister`, `registered`, `for_port`,
  `for_section` and `for_message` are the registry around it.

  A protocol's `name` doubles as its packet-spec section key, so registering
  one makes `parse` emit a section named after it and `build` read it back.
  `register` refuses a name that collides with a structural packet-spec key,
  a name, port or message type already claimed, or an unrecognised `over`
  value, naming what collided in each case.

  Nothing dispatches through the registry yet — DNS, DHCP and HTTP keep their
  existing hardwired paths until #98 onwards.

- **`packeteer.app` — DNS, DHCP and HTTP as registry entries** (#97) — each
  assembles one `AppProtocol` from the encoder in `packeteer.generate` and the
  decoder in `packeteer.parse`, and owns the packet-spec mapping in both
  directions: `packeteer.app.dns.to_spec` / `from_spec`, and the same for
  `dhcp` and `http`.

  `from_spec` **moved out of `packeteer.__main__`**, where a caller holding a
  packet spec could not reach it without importing the CLI.  The three
  `_build_*_from_spec` helpers are gone from the CLI, which now calls the
  public functions.

  Importing `packeteer.parse` or `packeteer.app` registers the three.
  `packeteer.generate` deliberately does not import `packeteer.app` — the
  modules there import `packeteer.generate.*`, so the reverse would be a
  cycle — and importing it alone therefore leaves the registry empty.

  Still nothing dispatched through the registry when this landed; the parser
  started doing so in #98.

- **`ParsedPacket.app` and `.app_protocol`** (#98) — the decoded
  application-layer message and the name of the protocol that produced it.
  Any registered protocol lands here; `dns`, `dhcp` and `http` are set in
  addition, and remain part of the public API.

### Changed

- **Application decode goes through the registry** (#98) — `parse` looks the
  transport ports up in `packeteer.protocols` instead of trying DNS, then
  DHCP, then HTTP in turn, so a registered protocol is decoded on the same
  footing as a built-in.  The destination port is consulted before the source
  port, and a decoder that rejects the bytes leaves them in `payload` as
  before.  No built-in changes behaviour: their ports do not overlap, so the
  single lookup resolves exactly as the three attempts did.

- **A parsed application message reaches the packet spec through the registry**
  (#99) — `update_config` resolves the message type against
  `packeteer.protocols` instead of testing for `DNSMessage`, `DHCPMessage` and
  `HTTPRequest`/`HTTPResponse` by name, and writes the section named after
  whichever protocol owns it.  Header types are still matched first, and an
  unrecognised object still raises `TypeError`.  With #98 this completes the
  path from capture to spec for a registered protocol: `packeteer parse` now
  emits a section for one.

- **A packet spec's application section is built through the registry** (#100)
  — `packeteer.app.apply_app_section` replaces the `dns`/`dhcp`/`http` ladder
  that the CLI carried twice, so `packeteer build` constructs a registered
  protocol's payload the same way it constructs a built-in's.  With #99 this
  closes the `parse` → edit → `build` round trip for a registered protocol.

- **Breaking: a packet spec carrying two application sections is now an
  error.**  Previously the first of `dns`, `dhcp`, `http` present was used and
  the others ignored silently.  A packet has one application payload, so a
  spec with two was always a mistake; it now fails naming both sections.
  Callers with such a spec should delete the section they did not mean.

- **`sanitise` redacts every registered protocol's section** (#101) — it
  looped over `dns`, `dhcp` and `http` by name, so a registered protocol's
  section passed through untouched.  It now calls each registered protocol's
  own `sanitise` callable.  A protocol registered without one is still skipped
  and its section still passes through: that is a deliberate choice by whoever
  registered it, and the one worth knowing about, since for `sanitise`
  specifically a protocol nobody taught it about is a leak rather than a
  missing feature.

- **`PacketBuilder.app`** (#102) — the generic form of `dns`, `dhcp` and
  `http`: it resolves the message type against the registry and encodes it
  with whichever protocol owns it.  The transport comes from the layer stack —
  the last `tcp()` or `udp()` call — which is what lets DNS decide about its
  length prefix without a `tcp=` keyword.  `dns`, `dhcp` and `http` are
  unchanged and keep their own signatures.

- **`ParsedPacket.datagram_truncated` and `packet_metadata.truncated`** (#94)
  — `true` when the IP header declares more payload than the packet holds, as
  after a capture taken with a snaplen.

  This is what 0.9.1 left missing.  Clearing `transport.checksum` on a
  truncated capture (#92) removed a false positive on every packet, but it
  merged two outcomes: an absent `checksum` came to mean "a rebuild can derive
  it" **or** "nobody can check it".  The flag separates them, and the spec
  marker carries the same answer through `packeteer parse` output.

  It is the *datagram* sense of truncation, not the capture's — what `parse`
  itself can see, available on every entry point including `parse_packet` on
  raw bytes.  Whether the **capture** was cut is a different question,
  answered by `ParsedPacket.source_records` where those exist.  The two
  disagree in both directions: a snaplen that cut only link-layer padding past
  the end of the datagram leaves this `false`, and an IPv4 header whose
  `total_length` lies sets it with no snaplen involved.  `false` for an IPv6
  jumbogram (RFC 2675), whose header states no payload length to compare.

### Documentation

- **A guide to adding an application protocol** (#103) — the `AppProtocol`
  contract, a worked example from message class to registered protocol, and
  what you get once it is registered: `parse` decodes it, the packet spec
  carries a section named after it, `build` reconstructs it, and `sanitise`
  redacts it.  Also covers replacing a built-in, and the limits — one message
  per packet payload, one application section per spec, and ports as the only
  trigger.
- The packet-spec format reference now says that its `##` headings are
  reserved names and that a registered protocol contributes a section of its
  own, and the API reference documents `packeteer.protocols` and
  `packeteer.app`.

---

## [0.9.1] - 2026-08-28

### Fixed

- **Truncated captures no longer read as corruption** (#92) — a capture taken
  with a snaplen kept `transport.checksum` (and `transport.length` for UDP) on
  every packet whose payload was cut, because the derived value was computed
  over the bytes that were kept rather than the ones the sender used.  Since
  the keys appear only where a rebuild could not derive them, a consumer reads
  a surviving `checksum` as "this was wrong on the wire" — and truncation made
  that false for every packet of the capture.

  `parse` now clears both when the IP header declares more bytes than the
  capture holds, on IPv4 and IPv6 and for both TCP and UDP.  The consequence,
  which is a limitation rather than a bug: **corruption cannot be reported at
  all in a truncated capture**, because the bytes the sender checksummed are
  not in the file.  A fragmented datagram's first fragment is unaffected — it
  carries exactly what its IP header declares — and still records both values.

---

## [0.9.0] - 2026-08-28

### Added

- **`transport.length` and `transport.checksum` in a packet spec** (#68) — two
  optional keys that override the derived values, absent from a spec whenever
  the derived value is what the capture held.

  - `UDPHeader` gains `length` and `checksum`; `TCPHeader` gains `checksum`
    (TCP has no length field of its own).  `PacketBuilder.udp()` and
    `.tcp()` take them as keyword arguments.  All default to `None`, meaning
    derive as before.
  - `packeteer parse` records them only where a rebuild could not work the
    value out for itself, so ordinary traffic is unaffected: across the test
    corpus the keys appear on 59 of 287 packets in `fragmentation.pcap` — its
    first fragments — on 11 of 218 in `payload_corruption.pcap` — the packets
    whose checksum was wrong on the wire — and on none at all in the other
    eleven captures.
  - An explicit checksum is written out exactly as given, including `0`, so a
    spec can now express a checksum that was wrong on the wire.  Previously
    only the byte-level fuzzer could do that.

- **Wire impairments work with `--payload http` and `--payload vpn`** (#83) —
  every TCP anomaly option was discarded with a warning when a payload type was
  given, so impaired *application* traffic — the case a protocol decoder is
  actually tested against — could not be generated at all.  It was reachable
  only by running `packeteer fuzz` over an existing capture, which mutates
  rather than generates and needs a capture to start from.

  - `--packet-loss`, `--retransmission-probability`, `--payload-corruption`,
    `--server-rst` and `--stray-packets` now all apply to `--payload http`, and
    the warning is gone.
  - They are applied **per connection**, so a RST cuts one connection short
    instead of reaching across a capture that `--sessions` and
    `--requests-per-connection` may have spread over many.
  - `--payload vpn` is UDP, which splits the options in two.  `--packet-loss`
    and `--payload-corruption` describe what a wire does to a datagram and now
    apply there too; `--retransmission-probability`, `--server-rst` and
    `--stray-packets` describe TCP connection behaviour and are still ignored,
    but the warning now names only those three instead of all five.
  - The passes moved to a new `packeteer.generate.impairments` module and are
    shared by every generator rather than living on one path.
    `ImpairmentConfig` is public and reachable as
    `from packeteer.generate import ImpairmentConfig`; the payload generators
    take one through `HTTPRestConfig.impairments` / `VPNConfig.impairments`.
  - A damaged segment's label names the message it came from, so
    `CORRUPT[GET /api/v1/orders [2/5]]` reads as "the second of five segments
    carrying that request".

- **`--mss` for `packeteer stream --payload http`** (#83) — `mss` was a
  parameter of `generate_http_stream` that the CLI never passed, so it was
  stuck at 1460 and unreachable from the command line or a config file.

  It matters most alongside the impairments above.  A generated HTTP message
  fits inside one 1460-byte segment, so at the default MSS losing a segment
  loses a whole request or response.  Lower it and a message spans several
  segments, where loss or corruption leaves a gap *inside* a message a decoder
  is already part-way through — and after the chunked support below, a chunk
  boundary can fall across a segment boundary, which is the case a streaming
  decoder is most likely to get wrong.

- **Chunked responses from `packeteer stream --payload http`** (#82) — every
  generated response was framed with `Content-Length`; `Transfer-Encoding:
  chunked` appeared nowhere in the generator, so no combination of options
  produced one.  Chunked is HTTP/1.1's other framing mechanism and the harder
  one to implement — the body's extent is not in a header, it is discovered by
  walking hex size lines — so a decoder that reads counted bodies correctly can
  still be completely wrong about chunked, and a corpus of only counted bodies
  will not say so.

  - `HTTPRestConfig.chunked_rate` (CLI `--chunked-rate P`) frames that
    proportion of the responses *with a body* as chunked.  A rate between the
    extremes puts both framings in one capture, which is what a decoder that
    has to choose between them needs.
  - `HTTPRestConfig.chunk_size` (CLI `--min-chunk` / `--max-chunk`) sets the
    bytes per chunk before the last, defaulting to `(8, 32)`.  The default is
    deliberately small relative to the generated JSON bodies (~70 bytes) so
    that bodies split into several chunks: a single-chunk body does not
    distinguish a decoder that walks the size lines from one that reads to the
    end.  A range with `min < 1` is rejected, since a zero-size chunk *is* the
    terminator and would end the body early and silently.
  - `HTTPRestConfig.trailer_rate` (CLI `--trailer-rate P`) adds a trailer
    section after the terminating chunk on that proportion of chunked bodies,
    announced by a `Trailer` header.  Legal per RFC 7230 §4.4 and widely
    forgotten by decoders.
  - Request bodies stay counted; the framing knobs apply to responses only.

  Chunked framing depends on the `Content-Length` fix below: without it every
  generated chunked message would have carried both headers.

- **TCP options on the application-payload paths** (#88) — `TCPSession` passed
  `None` unconditionally and had no parameter for them, so `--payload http`
  could never produce a realistic handshake.  It and `render_tcp_session` now
  take them, matching the low-level path.

- **`--error-rate` exposes the response-error knob on the CLI** (#82) —
  `HTTPRestConfig.error_rate` has existed since 0.7, but
  `packeteer stream --payload http` constructed `HTTPRestConfig()` with no
  arguments, so no HTTP content knob was reachable from the CLI at all.  All
  five are now settable as flags and as `[stream]` config-file keys, and appear
  in `--write-config` output.

  Captures generated with the new knobs left at their defaults are
  byte-identical to captures from previous versions with the same seed: the
  added random draws are skipped entirely when their rate is zero.

### Changed

- **Breaking: generated TCP handshakes now advertise TCP options** (#88) — a
  generated SYN carried none at all.  Across the shipped synthetic captures,
  **0 of 1 314 TCP packets carried any option**, where the one real capture has
  them on all 13.  Every modern stack advertises at least a Maximum Segment
  Size, so a bare 20-byte header is the most conspicuous mark of generated
  traffic in a TCP capture — and packeteer exists to feed tools that read
  captures.

  `TCPStreamConfig.client_options` / `server_options` and the new
  `HTTPRestConfig.syn_options` now default to
  `packeteer.generate.tcp.default_syn_options()`: MSS, SACK permitted and a
  window scale.  `--no-tcp-options` (config key `no_tcp_options`), or passing
  `None`, restores a bare SYN.

  **Captures generated with the defaults differ from previous versions for the
  same seed**, on every TCP-carrying generator.  This is the widest behaviour
  change in the release; pass `--no-tcp-options` to reproduce the old bytes.

  Timestamps are deliberately not advertised: only the handshake carries
  options, and a connection that negotiates timestamps carries one on every
  segment, so advertising them without sending them would trade one
  implausibility for another.  Carrying them properly is #90.


### Fixed

- **Packet loss no longer leaves acknowledgements for segments that were never
  delivered** (#85) — loss was applied to each packet independently, after the
  whole conversation had been assembled, so a capture could acknowledge a
  segment it did not contain.  A lost packet is lost *on the wire*: neither the
  capture point nor the far end sees it, and a receiver cannot acknowledge what
  it never got.

  Three things follow, and all three were wrong:

  - **A lost segment triggered an acknowledgement.**  It no longer does — there
    is nothing at the far end to answer.
  - **Every later acknowledgement was overstated.**  Acknowledgements are
    cumulative, so with a segment missing, the ones after it claimed bytes that
    never arrived.  The receiver's acknowledgement number now stops advancing
    at the gap, so the segments after it are answered with **duplicate ACKs** —
    the signal an analyser looks for around a loss event, and one packeteer
    could not previously produce.
  - **Losing a SYN produced an impossible capture**, in which the peers had
    never learnt each other's initial sequence numbers yet went on exchanging
    data with an acknowledgement number of zero.  The SYNs are now exempt from
    loss.  Modelling the real outcome — a connection that never establishes —
    needs setup retransmission the generator does not have.

  By default nothing retransmits, so a lost segment leaves a permanent hole in
  the byte range — the harsher input to test a decoder against.
  `--retransmit-lost` (`ImpairmentConfig.retransmit_lost`) resends it after the
  retransmission timeout instead, and the acknowledgement that follows jumps
  forward over everything the receiver had been holding, which is what recovery
  looks like on the wire.  It is a separate knob from
  `--retransmission-probability`, which duplicates a segment that *did* arrive:
  one models recovery, the other a spurious retransmission, and a capture can
  carry both.

  **`--packet-loss` therefore produces different captures for a given seed.**
  Every other option is unaffected — verified across 112 seed and option
  combinations, of which the 32 involving loss moved and the other 80 did not.

- **TCP option padding is placed where senders put it** (#88) — NOP padding was
  appended after every option; a sender puts it *ahead* of an option whose
  32-bit fields need aligning, which is the layout RFC 7323 §A.2 recommends for
  Timestamps and what real stacks emit.

  This also makes #87's replay rarer: with the padding in the right place the
  encoder reproduces the common layout on its own, so `options.raw` stops
  appearing on ordinary traffic.  Across the one real capture in the test
  corpus it went from 13 of 13 packets to none.

- **A capture's TCP option layout survives a round trip** (#87) — the option
  region was re-encoded in a canonical order with NOP padding appended, while
  senders put the padding ahead of the option it aligns.  The rebuilt region
  decoded to identical values, so nothing downstream of a parse noticed, but
  the bytes differed:

  ```
  captured: 0101080a21c6e61e65f1e0d5     NOP, NOP, Timestamps
  rebuilt : 080a21c6e61e65f1e0d50101     Timestamps, then NOP, NOP
  ```

  This was documented behaviour rather than an oversight, and no canonical
  order could have fixed it — Linux and macOS lay out a SYN's options
  differently, so matching one breaks the other.  `parse` now records the
  region as captured in `transport.options.raw` when re-encoding would not
  reproduce it, and `build` writes it verbatim.  `TCPOptions` gains a matching
  `raw` field, which **takes precedence over the decoded fields**: clear it
  before editing `mss` or `timestamps` on an instance that has one.

  Ordinary specs are unaffected — the key appears only where the layout is one
  the encoder does not produce.

  **With #68 and #86, every shipped capture now rebuilds byte-for-byte**,
  `testcases/*.pcapng` included.  A test asserts it across the whole corpus.

- **Short Ethernet frames keep their captured length through a round trip**
  (#86) — `packeteer build` pads a frame to the 60-byte Ethernet minimum, and
  `packeteer parse` recorded nothing about whether the frame it read was
  padded, so a captured 54-byte frame rebuilt as a 60-byte one.  Every original
  byte was reproduced correctly and six zeros were appended.

  Padding is added by the network hardware, so a capture taken above the driver
  never sees it — and the frames it affects are the ordinary TCP control
  packets, which is most of the short traffic in a typical capture.

  `parse` now writes `"pad": false` in the `ethernet` section when the captured
  frame was below the minimum, and omits the key otherwise; the build side
  already honoured it.  A tunnelled inner frame is never marked, since padding
  describes what went out on the wire.

  **With this and #68, every packet in every shipped `testcases/*.pcap` capture
  now rebuilds byte-for-byte** — `fragmentation.pcap` 115 → 287 of 287,
  `no_errors.pcap` 100 → 207 of 207 — and a test asserts it across the whole
  corpus so it stays that way.

- **A fragmented capture's first fragment now rebuilds byte-for-byte** (#68) —
  a transport header travels once, in the first fragment, and its length field
  describes the **whole** datagram rather than the bytes in that fragment.
  `packeteer build` derived both length and checksum from the bytes it was
  given, so rebuilding a first fragment produced different values than the
  capture had: for a 1032-byte UDP datagram fragmented at an MTU of 576, a UDP
  Length of `552` instead of `1032`, and a checksum over the fragment instead
  of the datagram.

  The rebuilt fragment was self-consistent but not what was on the wire, so a
  receiver reassembling the rebuilt capture computed a different datagram and
  rejected the checksum — a `parse` → edit → `build` cycle over a fragmented
  capture did not replay as valid traffic.  Later fragments were never
  affected, since they carry no transport header at all.

  Round-tripping `testcases/fragmentation.pcap` now reproduces 174 of its 287
  packets byte-for-byte, up from 115 — the 59 first fragments it previously
  got wrong.  Reassembling first with `--defragment` remains the recommended
  path when faithful datagrams matter, and is unaffected.

- **`--server-rst` combined with `--packet-loss` kept the wrong
  acknowledgements** (#83) — when both were used together, the RST pass decided
  which ACKs to keep by comparing the segment number in an ACK's label against
  a position in the list of segments that survived loss.  Those two numbers
  agree only when nothing has been dropped, so with loss the pass discarded
  acknowledgements for segments that had been delivered before the connection
  was reset, and kept some that came after it.  An ACK whose own segment was
  lost was mistaken for part of the teardown.

  Acknowledgements are now cut at the split point by time, which does not
  depend on any segment numbering.  **Captures generated with both
  `--server-rst` and `--packet-loss` set will differ from previous versions for
  the same seed.**  Every other combination, impaired or not, reproduces
  byte-for-byte — verified across 112 seed and option combinations.

- **`encode_http_message` no longer adds `Content-Length` beside
  `Transfer-Encoding`** (#81) — the encoder added the header whenever the body
  was non-empty and `Content-Length` was absent, without looking at
  `Transfer-Encoding`.  A caller hand-building a chunked message got both
  headers, which is the shape RFC 7230 §3.3.3 exists to resolve and the classic
  request-smuggling construction: two recipients that disagree about which
  header wins disagree about where the message ends.

  The added value was also wrong on its own terms.  `Content-Length` counts the
  payload body, but the encoder counted the *encoded* body — chunk sizes,
  CRLFs and terminator included.  A 4-byte payload framed as
  `4\r\nabcd\r\n0\r\n\r\n` was announced as 14 bytes, which is the length
  of nothing a recipient would reconstruct.

  The header is now added only when the message does not already frame itself,
  making a well-formed chunked message reachable through the encoder for the
  first time.  The encoder still never chunks a body itself: a caller who sets
  `Transfer-Encoding: chunked` supplies an already-chunked body.

- **Header names are matched case-insensitively when encoding** (#81) — the
  guard against overwriting a caller's `Content-Length` was a case-sensitive
  lookup on a plain dict, so a caller who wrote `content-length` got the header
  **twice**.  HTTP field names are case-insensitive per RFC 7230 §3.2 and are
  now treated as such.  The caller's own spelling is preserved on the wire;
  only the matching changed.

---

## [0.8.0] - 2026-08-15

### Added

- **`packeteer stream --write-config` — a config template to start from**
  (#78) — `packeteer stream` has enough options that reproducing an involved
  setup is best done from `--config FILE`, but writing that file meant
  assembling it from the CLI reference by hand.

  - `packeteer stream --write-config FILE` writes a fully commented template
    listing **every** recognised key with its default and an explanation;
    `-` writes it to stdout.  `packeteer.generate.stream_config_template()`
    returns the same text.
  - The template was already shipped as package data but nothing emitted it,
    and it had gone stale: 24 of the 73 recognised keys were missing —
    everything added in 0.7, including the VXLAN, GENEVE, GTP-U and IPsec
    encapsulations, the `http` and `vpn` payload types, and multi-session
    generation.  All are now documented.
  - Fourteen example lines carried their explanation on the same line, so
    uncommenting them produced `invalid value for 'vlan_pcp'` rather than a
    working config.  The prose moved to its own line.
  - A test asserts every key in the CLI's parameter table appears in the
    template, and that uncommenting every example still parses — so the
    template cannot silently drift out of date again, which is how it got
    here.

- **`iter_packets` returns a `PacketReader`** (#76) — it was a bare generator,
  so the two file-level facts a consumer needs alongside the packets were
  unreachable: the capture's header, and what reassembly discarded.  Iteration
  is unchanged — `for pkt in iter_packets(path=…)` still works exactly as
  documented — but the returned object now also carries:

  - `header`, the capture's `PcapFileHeader`, populated before the first
    packet.  Its `tick_hz` states what a packet's `ts_frac` is counted in;
    without it a fraction of `250` could be milliseconds, microseconds, or
    nanoseconds, which is the silent misreading #64 was filed to end.
  - `incomplete`, the `IncompleteDatagram` records reassembly gave up on,
    complete once iteration finishes.  Previously the only way to see them was
    to abandon `iter_packets` and drive `Defragmenter` by hand — the two were
    alternatives, not layers.
  - `close()` and the context-manager protocol, matching `PcapReader`.  The
    file is opened when the reader is created, so a malformed capture now
    raises there rather than on first iteration, and it is closed when
    iteration finishes or the generator is discarded.

- **Timestamps carry the unit they are counted in** — reading `ts_frac`
  required fetching `tick_hz` from somewhere else, and getting that wrong is
  silent.  The pair and its unit now travel together:

  - `PcapRecord.tick_hz`, plus `timestamp` (float seconds), `timestamp_ns`
    (exact integer nanoseconds), and `datetime()`.  For pcapng it is *this
    record's* interface resolution, which in a multi-interface capture can
    differ from the file header's.
  - `ParsedPacket.tick_hz` and `ParsedPacket.timestamp`, set by
    `parse_pcap_packet` and `iter_packets`.
  - `timestamp` is a float and cannot hold a modern epoch to nanosecond
    precision — roughly the last three digits are lost — so `ts_sec` /
    `ts_frac` / `tick_hz` remain the exact representation, with
    `timestamp_ns` for exact whole nanoseconds.

- **`iter_packets` — read a capture as whole, parsed packets** (#73) — opening
  a file, reassembling fragments, and parsing each result was a three-step
  incantation every consumer wrote by hand, and skipping the middle step is
  the common mistake: a fragmented datagram otherwise arrives as several
  packets, only the first with a transport header.

  ```python
  from packeteer.parse import iter_packets

  for pkt in iter_packets(path="capture.pcap"):
      print(pkt.ip.src, "->", pkt.ip.dst, len(pkt.payload))
  ```

  - Reassembly is **on by default** here, because a caller asking for packets
    almost never wants the pieces.  `defragment=False` yields the capture's
    records as they are.  `link_type` and `decode_app` are forwarded.
  - Packets stream one at a time, so a capture larger than memory is fine.
  - New `ParsedPacket.source_records` lists the capture records behind each
    packet — one for an ordinary packet, every contributing fragment for a
    reassembled datagram.  With `PcapRecord.data_offset` (#62) and
    `payload_offset` (#71) that is enough to cite where a payload's bytes
    live in the file.
  - `ts_sec` / `ts_frac` come from the record that completed the packet;
    `source_records[0]` has the first fragment's time.
  - Datagrams whose fragments never all arrive are dropped; use
    `Defragmenter` directly to see what was lost.

- **Opt-in reassembly for the packet-spec path** (#73) —
  `parse_pcap_file(defragment=True)` and `packeteer parse --defragment`
  reassemble fragmented datagrams into one packet each.

  It is **off by default there**, unlike `iter_packets`, because a spec is the
  round-trip format: a fragmented capture currently parses and rebuilds
  byte-for-byte, and reassembling first means `packeteer build` emits
  unfragmented packets and the capture no longer round-trips.  The two
  defaults differ because the two entry points are for different jobs —
  analysis versus reproduction.

- **Fragment provenance from `Defragmenter`** (#72) — `feed()` returned bare
  frames, so a reassembled datagram carried nothing identifying the fragments
  it was built from: not their timestamps, not their positions in the capture,
  not their byte offsets.  The failure path was well served by
  `IncompleteDatagram`; the success path reported nothing.

  - `feed(frame, ts, token=…)` now returns a list of `AssembledFrame`, with
    `frame`, `tokens` (every contributing fragment's token, in arrival order),
    and `fragment_count` (`1` for a frame that passed through untouched).
  - The token is opaque and never inspected — pass a `PcapRecord`, a packet
    number, or a file offset and get full provenance back, while the library
    stays agnostic about what provenance means.  A reassembled datagram's
    bytes span several discontiguous ranges of the capture, and that set
    cannot be recovered from the output frame.
  - `fragment_count == 1` is now the documented way to spot a passthrough,
    replacing an identity check (`result[0] is frame`) that worked but was
    never promised.
  - `IncompleteDatagram` gains `tokens` for the fragments that did arrive, so
    a report can name the packets that were lost as precisely as it names the
    ones that completed.
  - `defragment()` / `defragment_ipv4` / `defragment_ipv6` are unchanged and
    still yield bare frames — that wrapper exists for callers who only want
    the bytes.
  - This changes `feed`'s return type, but `Defragmenter` shipped in this same
    unreleased cycle, so no released version is affected and no `Breaking:`
    note applies.

- **`ParsedPacket.payload_offset`** (#71) — the index of `payload[0]` within
  the frame passed to `parse_packet`, or `None` when there is no payload.
  Every layer parser already returns a header size and the walk slices by it,
  so the offset was known during the parse and then discarded.

  - Added to `PcapRecord.data_offset` it gives the payload's byte offset
    within the capture file, which is what a consumer citing provenance —
    "these bytes came from file offsets X–Y" — needs.  Without it the two
    additions from #62 and #66 did not compose.
  - It cannot be derived as `len(frame) - len(payload)`: that assumes the
    payload runs to the end of the frame, which #66 deliberately made false.
    On a frame padded to the 60-byte Ethernet minimum the subtraction lands
    inside the padding and yields the wrong bytes with no error.
  - For a tunnelled packet the offset on a nested `tunneled` packet is
    relative to the **outer** frame as well, so one addition works at any
    depth — verified through VXLAN, GENEVE, GTP-U, GRE, IP-in-IP, and
    doubly-nested GRE.
  - Per-layer offsets (`ip_offset`, `transport_offset`, …) were considered and
    deferred to #74; `payload_offset` alone closes the gap this was raised
    for.

- **IP defragmentation** (#65) — `fragment_ipv4` / `fragment_ipv6` had no
  parse-side counterpart, so a fragmented datagram could only be dropped or
  reassembled by the caller.  New `packeteer.parse.defragment`, exported from
  `packeteer.parse`:

  - `defragment(frames, link_type=…, timeout_s=…)` reassembles both IP
    versions; `defragment_ipv4` / `defragment_ipv6` restrict it to one, with
    the same signature.  All take and return **raw frames**, mirroring the
    generate side and composing with `open_pcap` on one end and
    `parse_packet` on the other.  Non-fragments pass through untouched and in
    order; out-of-order fragments and interleaved datagrams are handled.
  - `Defragmenter` is the stateful primitive behind them — `feed(frame, ts)`,
    `flush()`, and an `incomplete` list of `IncompleteDatagram` records so a
    caller can see what never arrived, each with a `reason` of `"timeout"`,
    `"overlap"`, `"too_large"`, or `"evicted"`.  Incomplete datagrams are
    dropped rather than emitted partly assembled.
  - Documented policies, all security-relevant: IPv4 overlap keeps the
    first-arrival bytes (BSD behaviour) while IPv6 discards the whole
    datagram (RFC 5722); timeouts run on capture timestamps, not wall-clock
    time; and per-datagram and total buffer caps mean a capture full of
    first-fragments-only cannot exhaust memory.
  - A reassembled IPv4 header has its fragment fields cleared, Total Length
    corrected, and checksum recomputed; a reassembled IPv6 header has the
    Fragment extension header removed and Next Header restored — both match
    the datagram as it was before fragmentation, so
    `fragment_ipv4` → `defragment` round-trips.
  - Ethernet padding on a short final fragment is excluded from the
    reassembled payload, using the length declared in the IP header.

- **IPv6 Fragment extension header decoding** (#65) — `next_header == 44` was
  not decoded at all: it raised `UnsupportedIPProtocolWarning` and left the
  whole fragment opaque, so the identification needed to group fragments was
  unreachable.

  - New `FragmentHeader` dataclass (`fragment_offset`, `more_fragments`,
    `identification`) exported from `packeteer.generate`, and a new
    `IPv6Header.fragment` field holding it.
  - `PacketBuilder.fragment_header(…)` authors one, `packeteer parse` emits a
    `network.fragment` object, and `packeteer build` rebuilds the extension
    header from it.  Previously `packeteer build` **crashed** on a spec parsed
    from an IPv6-fragment capture, with an unhandled `AttributeError` from
    `network.protocol` being the integer `44`.
  - Known limitation: rebuilding a **first** fragment from a spec recomputes
    the transport length and checksum from that fragment's bytes, while the
    captured header states them for the whole datagram, so those two fields
    differ from the original.  A spec describes one packet and cannot express
    "this transport header belongs to a larger datagram".  Pre-existing for
    IPv4; IPv6 now behaves the same rather than crashing.  Later fragments
    rebuild byte-for-byte, and reassembling with `defragment()` before parsing
    avoids the issue entirely.

- **`open_pcap` — streaming pcap/pcapng reader with byte offsets** (#62) —
  `read_pcap` materialises every packet in a list and, without `max_packets`,
  slurped the whole file first, so processing a capture record by record still
  cost whole-file memory.  Multi-gigabyte captures are the normal case for
  session analysis.

  - `open_pcap(path=… | file_object=…, link_type=…)` returns a `PcapReader`:
    an iterator of `PcapRecord` objects whose `header` is populated before the
    first record is read.  It is a context manager — a reader opened from a
    path closes that file on exit, including when iteration stops early, while
    a caller's *file_object* is never closed.
  - `PcapRecord` carries `data`, `ts_sec`, `ts_frac`, `offset` (start of the
    record header or pcapng block), `data_offset` (first captured packet
    byte), and `orig_len` (on-wire length, larger than `len(data)` for a
    snaplen-truncated record).  The first three unpack like the tuples
    `read_pcap` returns, so `for data, ts_sec, ts_frac in reader` works.
  - The byte offsets cannot be reconstructed after the fact for pcapng —
    blocks are variable-length and option padding is invisible in the decoded
    data — so reading them here is the only way to cite a byte range of a
    capture afterwards.
  - `read_pcap` is now a thin wrapper over the same machinery, replacing the
    separate buffered and streaming code paths it used to choose between;
    `max_packets` is an `islice`.  Its behaviour and signature are unchanged.

- **`PcapFileHeader.tick_hz` — the capture's real timestamp resolution** (#64)
  — the header modelled resolution as a single `nanoseconds` boolean, so any
  pcapng declaring something else through `if_tsresol` had its sub-second
  timestamps silently misread.  `_parse_idb_tsresol` already decoded the full
  option, including binary (`2**n`) forms, and the result was then discarded
  unless it happened to be exactly 1e9.

  - `tick_hz` records ticks per second — `1_000_000`, `1_000_000_000`,
    `1_000`, `1024`, whatever the file declares — and is the field to use for
    timestamp arithmetic.
  - `nanoseconds` remains as a derived convenience view and still drives the
    writers.  The two are reconciled in `__post_init__`: supply either one and
    the other follows, with `tick_hz` winning when both are given.  Existing
    `PcapFileHeader(..., nanoseconds=True)` calls are unaffected.
  - `PcapInfo` gains `tick_hz` (also in `to_dict()` / `file-info --json`), and
    the text report adds a `Timestamps: N ticks/s` line for a resolution that
    is neither microseconds nor nanoseconds.
  - New `TimestampResolutionWarning`, exported from `packeteer.parse`, is
    raised once by `parse_pcap_file` when a spec cannot express the source
    resolution; its `tick_hz` attribute carries the real value.

- **TCP options are decoded on the parse path** (#63) — `parse` honoured the
  Data Offset field when slicing the payload but never decoded the option
  bytes, so `TCPHeader.options` was always `None` from a real capture.
  packeteer could *build* MSS, window scale, SACK, and timestamps but not read
  them back, and the `options` branch in the packet-spec serialiser could
  never fire.

  - `packeteer.parse.tcp.packet_parser` now decodes the options region into
    the existing `TCPOptions` dataclass: MSS (kind 2), Window Scale (3),
    SACK Permitted (4), SACK blocks (5), and Timestamps (8).  `options` is
    `None` when the header carries no options, so specs stay clean.
  - Window scale is needed to interpret the `window` field at all on a modern
    connection; SACK blocks tell a reassembler which ranges arrived; and
    timestamps discriminate retransmits.
  - New `TCPOptions.unknown` field — `(kind, value)` pairs for options with no
    dedicated field, and for a recognised kind carrying an unexpected length.
    The builder re-emits them, so an option survives a parse → build round
    trip even when packeteer does not understand it.
  - Options are re-encoded in a canonical order, so a round trip preserves
    every option's presence and value but is not guaranteed byte-identical to
    a capture that ordered or padded them differently.
  - Structural padding (NOP, End of Option List) is consumed and not
    modelled.  A malformed list — a length byte below the 2-byte minimum, or
    one running past the end of the region — stops the walk, keeping whatever
    was decoded before it rather than discarding the header.
  - The packet spec gains `transport.options.unknown`, an array of
    `{"kind": N, "data": "<hex>"}` objects, read back by `packeteer build`.

- **`decode_app` — opt out of DNS/DHCP/HTTP decoding** (#61) — the parser ran
  its three application decoders unconditionally, and each replaced the
  payload it decoded, so `ParsedPacket.payload` came back empty for exactly
  the protocols most worth capturing.  Re-serialising the decoded object is
  not byte-exact — header casing, header order, whitespace, and duplicate
  headers are all normalised away — so those bytes were unrecoverable.

  - `parse_packet(data, *, link_type=…, decode_app=True)` and
    `parse_pcap_packet(record, file_header, *, decode_app=True)`.  With
    `decode_app=False` the DNS, DHCP, and HTTP decoders are skipped and
    `payload` holds the transport payload exactly as captured.
  - The setting propagates through every level of a tunnelled packet, so an
    HTTP payload inside VXLAN, GENEVE, GTP-U, GRE, EtherIP, IP-in-IP, AH, or
    an MPLS pseudowire is left raw as well.
  - Tunnel decoders themselves always run: VXLAN, GENEVE, and GTP-U are
    framing, not application content.
  - `parse_pcap_file(..., decode_app=True)` and `packeteer parse
    --no-decode-app` expose the same switch; the spec then carries a
    `payload` section instead of `dns` / `dhcp` / `http`.
  - The default is unchanged, so existing callers are unaffected.

- **IP length fields on parsed headers** (#66) — the parser now records what
  the IP header says about the datagram's size, so a caller can tell where the
  datagram ends without re-reading the raw bytes.

  - `IPHeader.total_length` — the IPv4 Total Length field (header + payload).
  - `IPv6Header.payload_length` — the IPv6 Payload Length field (everything
    after the 40-byte fixed header, including extension headers).
  - Both default to `None` and are populated only by
    `packeteer.parse.ip.packet_parser`; the builder ignores them and continues
    to derive the wire value from the actual payload, so every existing
    construction call is unaffected and the fields do not appear in packet
    specs.
  - Comparing the declared length against the bytes received detects a
    snaplen-truncated capture.

### Fixed

- **`pcap_ts_to_datetime` misread any capture that was neither microsecond nor
  nanosecond** — it took a `nanoseconds` boolean, the model #64 replaced
  everywhere else, so a millisecond capture's fraction came out a thousand
  times too small: `00:01:40.000250` where the truth was `00:01:40.250000`.
  The recipe documented in `docs/guide/pcap.md` had exactly that bug.

  It now accepts `tick_hz`, which takes precedence; `nanoseconds` still works
  for the two standard resolutions, so existing calls are unaffected.  This
  one predates 0.8.0 — the helper shipped in 0.7.0 and #64 left it behind.

- **Breaking: non-first fragments were decoded as if they had a transport
  header** (#65) — nothing on the parse path checked the fragment offset, so
  the payload bytes at the start of a non-first fragment were read as a TCP or
  UDP header.  Fragment 2 of a UDP datagram came back as a `UDPHeader` with
  ports invented out of user data (`8225` → `19019` → `29299` as the payload
  advanced), and the eight bytes it consumed vanished from the payload.  For a
  stream reassembler this is fabricated traffic.

  Such a fragment now has `transport = None` and keeps every byte in
  `payload`.  Code that read `.transport` on arbitrary packets should either
  reassemble first with `defragment()` or skip packets whose
  `ip.fragment_offset` is non-zero (IPv4) or whose `ip.fragment` is set with a
  non-zero offset (IPv6).

- **A packet spec dropped the payload of any packet with no transport layer**
  — `parse_pcap_file` emitted the `payload` section only for packets that had
  a transport header, so the bytes of a packet carrying an IP protocol the
  parser does not decode never reached the spec at all, despite
  `UnsupportedIPProtocolWarning` promising they were kept.  The same gap would
  have swallowed every non-first fragment's data once #65 stopped inventing a
  transport header for them.  The payload is now emitted whenever there is
  one, and `packeteer build` reconstructs such a packet: `PacketBuilder.ip()`
  gains a `protocol` argument for stating the protocol when no transport layer
  follows, and a non-first fragment no longer trips the "No transport layer
  configured" check.

- **`fragment_ipv6` announced IPv4 in the Ethernet header** — `EthernetHeader`
  defaults to EtherType `0x0800`, and `fragment_ipv6` used the caller's header
  as given, so `fragment_ipv6(..., eth_header=EthernetHeader(dst, src))`
  produced frames declaring IPv4 while carrying IPv6.  Wireshark misparses
  those.  A default EtherType is now switched to `0x86DD`; one set explicitly
  is left alone.

- **Obsolete Packet Block data was shifted four bytes** — a pcapng Packet
  Block (type `0x00000002`, the pre-standard predecessor of the Enhanced
  Packet Block, which this module reads for compatibility) has 20 bytes of
  fixed fields before its packet data: `interface_id`, `drops_count`, the two
  timestamp halves, `captured_len`, and `packet_len`.  The reader unpacked all
  20 bytes but sliced the data from offset 16, so every such packet began with
  the four bytes of `packet_len` and lost its last four real bytes.  Found
  while adding byte offsets in #62.

- **Non-microsecond pcapng timestamps were read as microseconds** (#64) — a
  capture declaring `if_tsresol = 3` (milliseconds, legal and emitted by some
  writers) had its sub-second fractions treated as microseconds by every
  consumer, a factor of 1000 out with nothing in the returned data to reveal
  it.  Binary resolutions were wrong by whatever factor applied.

  - `pcap_info` / `packeteer file-info` computed capture duration from the
    wrong unit: two packets half a second apart in a millisecond capture were
    reported as 0.0005 s apart.
  - `parse_pcap_file` labelled the fraction `timestamp_us` regardless, so a
    250 ms fraction was written as `250` microseconds rather than `250000`.
    Timestamps are now converted to the spec's unit and the value is correct.

- **Breaking: Ethernet padding no longer lands in `ParsedPacket.payload`**
  (#66) — a frame below the 60-byte IEEE 802.3 minimum is zero-padded by the
  sender, and that padding was being reported as transport payload.  A
  minimal Ethernet/IPv4/UDP frame returned 18 bytes of zeros as its payload;
  it now returns `b""`.  The parser trims the datagram to the length declared
  in the IP header before the transport layer is parsed.

  This matters most for stream reassembly, where the padding was bytes that
  were never sent being injected into the stream.  Callers that relied on the
  old behaviour to see the padding should read the frame bytes directly.

  When the declared length exceeds what was captured — a snaplen-truncated
  record — every captured byte is kept rather than trimmed, and
  `total_length` still reports what the sender declared.

### Documentation

- `docs/cli/stream.md` documents `--write-config` and no longer points at the
  template's path in the source tree, which is not where an installed package
  keeps it; `docs/api/stream-generators.md` documents
  `stream_config_template`.
- New "Working with timestamps" section in `docs/guide/pcap.md` covering
  `record.timestamp` / `timestamp_ns` / `datetime()`, the float precision
  caveat, and why `tick_hz` should be passed to `pcap_ts_to_datetime` rather
  than the `nanoseconds` flag.
- `docs/guide/parsing.md` now opens with "Reading a capture as packets"
  (`iter_packets`), with the spec and single-frame entry points below it and a
  note on why the spec path does not reassemble by default;
  `docs/cli/parse.md` documents `--defragment`; and
  `docs/guide/defragmenting.md` points at `iter_packets` first, for the
  callers who never need the module directly.
- New "Tracking which fragments made a datagram" section in
  `docs/guide/defragmenting.md` covering tokens, `AssembledFrame`, and the
  arrival-order caveat; `AssembledFrame` added to `docs/api/fragmentation.md`.
- New "Where the payload was in the frame" section in `docs/guide/parsing.md`
  covering `payload_offset`, combining it with `PcapRecord.data_offset` to
  cite file offsets, and why the two obvious shortcuts (length subtraction and
  `frame.find`) are wrong.
- New `docs/guide/defragmenting.md` chapter covering reassembly, what a
  fragment looks like before it, incomplete datagrams, and the overlap /
  timeout / memory policies; a "Reassembly" section in
  `docs/api/fragmentation.md`; and the `network.fragment` spec key documented
  in `docs/packet-spec/format.md`.
- New "Streaming a large capture" section in `docs/guide/pcap.md` and a
  "Streaming" section in `docs/api/pcap-io.md` documenting `open_pcap`,
  `PcapReader`, and `PcapRecord`.
- New "Timestamp resolution" section in `docs/guide/pcap.md`, a
  `TimestampResolutionWarning` section in `docs/api/parser.md`, and a note on
  `tick_hz` in `docs/cli/file-info.md`.
- New "TCP options" section in `docs/guide/parsing.md` covering the decoded
  fields, why window scale and SACK matter for reassembly, `unknown`, and the
  canonical-ordering caveat; `options.unknown` documented in
  `docs/packet-spec/format.md`.
- New "Keeping the payload as it appeared on the wire" section in
  `docs/guide/parsing.md`, and a `--no-decode-app` section in
  `docs/cli/parse.md` noting that raw HTTP payloads serialise as hex (CRLF
  falls outside the printable-ASCII range that selects UTF-8 encoding).
- New "Payload boundaries and Ethernet padding" section in
  `docs/guide/parsing.md` covering the trimming rule, the two length fields,
  and truncation detection.
- `docs/api/packet-builder.md` corrected: `.ethernet()` was still documented
  with `pad=False`, but the default changed to `pad=True` in 0.7.0.

---

## [0.7.0] - 2026-06-20

### Added

- **IPsec support — AH (RFC 4302) and ESP (RFC 4303)** — the two IPsec data-path
  protocols (IP protocols 51 and 50) are now supported end-to-end across the
  builder, parser, packet-spec serialisation, stream encaps, `file-info`, and
  `sanitise`.  packeteer performs **no cryptography**, which shapes the model:

  - **AH** is integrity-only — it does not encrypt — so its protected content
    stays in cleartext.  `parse` decodes the Authentication Header into the new
    `ParsedPacket.ah` field and walks past it to decode the protected payload,
    in both **transport** mode (`IP/AH/TCP`) and **tunnel** mode
    (`IP/AH/IP/TCP`, inner stack under `tunneled`).  The Integrity Check Value
    is modelled as opaque random bytes of a configurable length (default 12,
    HMAC-SHA1-96; `AH_ICV_LEN_SHA256_128` = 16 also provided).
  - **ESP** encrypts everything after the 8-byte SPI + Sequence-Number prefix,
    so without the Security Association key it is **opaque**.  `parse` reads the
    SPI and Sequence Number into the new `ParsedPacket.esp` field and treats the
    rest as an opaque payload — exactly what a real capture without the key
    looks like.  ESP cannot be decrypted on parse.
  - `PacketBuilder.ah(spi=…, sequence=…, icv=…, icv_len=…)` and
    `.esp(spi=…, sequence=…, payload=…, size=…, icv_len=…)` author both
    protocols; AH's Next Header is filled from the following layer, and inner
    layers placed after `.esp()` become the opaque (would-be-encrypted) payload.
    Both round-trip byte-for-byte through `parse` → `build`.
  - New `AHEncap` / `ESPEncap` stream encapsulations (tunnel mode) wrap a
    generated TCP/UDP/SCTP stream: `--ah SRC DST` keeps the inner stack visible,
    `--esp SRC DST` **scrambles** the whole inner stack into high-entropy
    ciphertext (a stand-in for encryption, so no structured headers leak; via
    the new `ESPHeader.opaque_random` / `.esp(opaque_random=True)`), with
    `--ipsec-spi` / `--ipsec-ttl` knobs.  The scramble is deterministic, so
    seeded streams stay reproducible.
  - `packeteer file-info` counts `ah` / `esp` layers; `sanitise` scrubs AH's
    cleartext inner addresses (and ESP's opaque payload via `--payload`), while
    leaving the SPI/sequence — which are not addresses or PII — unchanged.
  - New `AHHeader` / `ESPHeader` dataclasses, `IPPROTO_AH` / `IPPROTO_ESP` and
    `AH_ICV_LEN_*` constants, and `AHEncap` / `ESPEncap` exported from
    `packeteer.generate`; new `packeteer.parse.ipsec` module exporting
    `ah_packet_parser` / `esp_packet_parser`.
  - New tests in `test_ipsec.py`.

- **Linux "cooked" capture support (SLL / SLL2)** — packeteer now reads and
  writes the pseudo link-layer framing produced by `tcpdump -i any`:
  `LINKTYPE_LINUX_SLL` (113, the classic 16-byte header) and
  `LINKTYPE_LINUX_SLL2` (276, the modern default).  Previously these whole
  classes of common captures were dropped to an opaque payload by `parse` /
  `file-info` / `sanitise`.

  SLL is a link-layer *framing*, not a protocol, but its Protocol Type field is
  an EtherType, so once the cooked header is decoded the rest of the parse
  (IP / IPv6 / ARP / MPLS / …) is identical to an Ethernet frame.

  - `parse` decodes the cooked header into the new `ParsedPacket.sll` field
    (`SLLHeader` / `SLL2Header`) and emits an `"sll"` / `"sll2"` packet-spec
    section, with `metadata.link_type` recording 113 / 276.
  - `PacketBuilder.sll()` / `.sll2()` author cooked frames (an alternative to
    `.ethernet()`); `packeteer build` reconstructs them, so a cooked capture
    round-trips through `parse` → edit → `build`, and `sanitise` writes an SLL
    capture back out as SLL (rewriting the cooked link-layer address).
  - `packeteer file-info` reports the link type as `linux_sll` / `linux_sll2`,
    counts an `sll` / `sll2` layer, and includes the cooked types in its
    link-type auto-detection.
  - `--link-type` now accepts `linux_sll` / `sll` (113) and `linux_sll2` /
    `sll2` (276) across `parse`, `sanitise`, and `file-info`.
  - New `SLLHeader` / `SLL2Header` dataclasses, `SLL_*` packet-type constants,
    and `LINKTYPE_LINUX_SLL` / `LINKTYPE_LINUX_SLL2` exported from
    `packeteer.generate` / `packeteer.pcap`; new `packeteer.parse.sll` module.
  - New tests in `test_sll.py`.

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
  - `packeteer file-info` reports an `arp` layer count, and no longer prints the
    "no packets contained an IP layer" note for an all-ARP capture (ARP
    legitimately carries no IP layer).
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

### Changed

- **Breaking: `ethernet.pad` defaults to `true`** — Ethernet frames are now
  zero-padded to the IEEE 802.3 minimum of 60 bytes by default in both
  `PacketBuilder` and `packeteer build`.  Set `pad: false` (or
  `.ethernet(pad=False)`) to suppress padding explicitly.

- **Breaking: PII scanning enabled by default** — `SanitiseOptions.scan_pii` now
  defaults to `True`.  `packeteer sanitise` will emit `PersonalDataWarning`
  instances for any email addresses or names found in UTF-8 payloads unless
  `--no-scan-pii` is passed.  Code that calls `sanitise()` directly and does not
  want PII warnings should pass `SanitiseOptions(scan_pii=False)`.

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

---

<!-- Releases before 0.7.0 are either untagged (0.6.1 and the dated entries) or
     tagged with names that predate this convention, so only the entries below
     carry compare links. -->

[Unreleased]: https://github.com/adamkjonsson/packeteer/compare/v0.9.1...HEAD
[0.9.1]: https://github.com/adamkjonsson/packeteer/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/adamkjonsson/packeteer/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/adamkjonsson/packeteer/compare/v0.7...v0.8.0
[0.7.0]: https://github.com/adamkjonsson/packeteer/compare/v0.6.0...v0.7
