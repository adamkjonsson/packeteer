# Defragmenting

A datagram larger than the path MTU is split into fragments, and only the
**first** fragment carries the transport header — the rest are payload bytes
from the middle of it.  Anything working at or above the transport layer
therefore has to reassemble those fragments or account for them: treating each
one as its own packet silently corrupts a stream, because bytes that belong in
the middle of a datagram get read as headers.

`packeteer.parse.defragment` is the counterpart to
{func}`~packeteer.generate.fragmentation.fragment_ipv4` and
{func}`~packeteer.generate.fragmentation.fragment_ipv6`.  Like them it works
in raw frames, so it slots in before parsing:

```python
from packeteer.parse import defragment, parse_packet
from packeteer.pcap import open_pcap

with open_pcap(path="capture.pcap") as reader:
    frames = (record.data for record in reader)
    for frame in defragment(frames, link_type=reader.header.link_type):
        pkt = parse_packet(frame, link_type=reader.header.link_type)
```

Fragments of one datagram are replaced by a single reassembled frame, emitted
where the last fragment arrived.  Frames that are not fragments pass through
untouched and in order, so the result is a drop-in replacement for the
original sequence.  Fragments arriving out of order, and several datagrams
interleaved, are both handled.

`defragment_ipv4` and `defragment_ipv6` restrict reassembly to one IP version,
passing the other through; all three take the same arguments.

## What a fragment looks like before reassembly

`parse_packet` deliberately does **not** decode a transport header from a
non-first fragment, because there isn't one there:

```python
first, *rest = fragments

parse_packet(first).transport      # UDPHeader — the real header
parse_packet(rest[0]).transport    # None
parse_packet(rest[0]).payload      # the fragment's bytes, undisturbed
```

Whether a packet is a fragment is visible on the parsed header — for IPv4 via
`ip.fragment_offset` and the MF bit in `ip.flags`, and for IPv6 via
`ip.fragment`, which holds a `FragmentHeader` (or `None`):

```python
pkt = parse_packet(frame)
if pkt.ip.fragment is not None:            # IPv6
    pkt.ip.fragment.fragment_offset        # in units of 8 bytes
    pkt.ip.fragment.more_fragments
    pkt.ip.fragment.identification
```

## Datagrams that never complete

A capture routinely contains fragments whose siblings were never captured.
Those datagrams are dropped rather than emitted half-assembled — a partial
datagram is bytes that were never sent as a unit.  To see what was lost, drive
the {class}`~packeteer.parse.defragment.Defragmenter` yourself:

```python
from packeteer.parse import Defragmenter

engine = Defragmenter(link_type=reader.header.link_type)
for record in reader:
    for frame in engine.feed(record.data, record.ts_sec):
        pkt = parse_packet(frame, link_type=reader.header.link_type)

engine.flush()          # abandon anything still waiting at end of capture

for lost in engine.incomplete:
    print(f"{lost.src} -> {lost.dst} id={lost.identification} "
          f"{lost.fragments_seen} fragments, {lost.reason}")
```

Each entry is an {class}`~packeteer.parse.defragment.IncompleteDatagram` whose
`reason` is `"timeout"`, `"overlap"`, `"too_large"`, or `"evicted"`.

## Policies

Reassembly involves choices that affect what traffic you end up seeing, so
they are stated rather than left implicit.

**Overlapping fragments.**  When two fragments claim the same byte range,
IPv4 keeps the bytes that arrived first and ignores the later ones (the common
BSD behaviour), while IPv6 discards the entire datagram, as RFC 5722 requires.
Overlap is a classic evasion technique: two reassemblers that resolve it
differently see different traffic, which is exactly what an attacker wants
between a monitor and its target.

**Timeouts.**  A datagram is abandoned once `timeout_s` (default 30) of
*capture* time has passed since its first fragment.  Capture timestamps drive
this rather than wall-clock time, so replaying a capture behaves the same as
reading it live.  Pass timestamps via `Defragmenter.feed(frame, ts)`; the
`defragment()` generator has no timestamps to work with, so it only expires
datagrams at `flush()`.

**Memory limits.**  `max_datagram_bytes` (default 65 535) caps one reassembled
datagram and `max_buffered_bytes` (default 64 MiB) caps everything held at
once; the oldest incomplete datagram is evicted when the total is exceeded.
A capture full of first-fragments-only — whether malicious or just truncated —
therefore cannot exhaust memory.

## Round trip

Fragmenting and reassembling returns the original datagram, which makes a
clean test of both halves:

```python
from packeteer.generate.fragmentation import fragment_ipv4
from packeteer.parse import defragment, parse_packet

fragments = fragment_ipv4(ip_header, transport_data, mtu=576, eth_header=eth)
frame, = defragment(fragments)

parse_packet(frame).payload == original_payload      # True
```

The reassembled IPv4 header has its fragment fields cleared, its Total Length
corrected, and its checksum recomputed.  The reassembled IPv6 header has the
Fragment extension header removed and its Next Header restored to the
transport protocol, so both look exactly like the datagram before it was
fragmented.
