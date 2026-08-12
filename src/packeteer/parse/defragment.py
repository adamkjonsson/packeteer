"""IP defragmentation — the parse-side counterpart to :mod:`packeteer.generate.fragmentation`.

A fragmented datagram arrives as several frames, only the first of which
carries a transport header; the rest are payload bytes from the middle of it.
Anything working at or above the transport layer therefore has to reassemble
them or skip them — silently treating each fragment as its own packet
corrupts a stream.

These functions take raw frames and return raw frames, mirroring
:func:`~packeteer.generate.fragmentation.fragment_ipv4` and
:func:`~packeteer.generate.fragmentation.fragment_ipv6`, which return
``list[bytes]``.  Fragments of one datagram are replaced by a single
reassembled frame carrying the whole payload; frames that are not fragments
pass through untouched, in order.  Feed the result to
:func:`~packeteer.parse.core.parse_packet` as usual::

    from packeteer.pcap import open_pcap
    from packeteer.parse import parse_packet
    from packeteer.parse.defragment import defragment

    with open_pcap(path="capture.pcap") as reader:
        frames = (record.data for record in reader)
        for frame in defragment(frames, link_type=reader.header.link_type):
            pkt = parse_packet(frame, link_type=reader.header.link_type)

Reassembly policies, which are security-relevant and so are stated rather
than left implicit:

- **Overlapping fragments.**  For IPv6 an overlapping fragment discards the
  whole datagram, as RFC 5722 requires.  For IPv4 the first fragment to claim
  a byte range wins and later overlapping bytes are ignored, which is the
  common BSD behaviour.  Overlap is a classic evasion technique — two
  reassemblers that resolve it differently see different traffic.
- **Timeouts.**  A datagram whose fragments stop arriving is abandoned once
  *timeout_s* of capture time has passed since its first fragment.  Capture
  timestamps drive this, not wall-clock time, so a replayed capture behaves
  the same as a live one.
- **Limits.**  Reassembly buffers are capped, both per datagram and in total,
  so a capture full of first-fragments-only cannot exhaust memory.

Incomplete datagrams are dropped from the output rather than emitted
partially assembled.  Use :class:`Defragmenter` directly to see what never
completed, and to attach a token to each frame so a reassembled datagram can
be traced back to the fragments it came from.
"""
from __future__ import annotations

import struct
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from packeteer.generate.ethernet import ETHERTYPE_IPV4, ETHERTYPE_IPV6
from packeteer.generate.ipv6 import IPV6_NEXT_HEADER_FRAGMENT
from packeteer.pcap import LINKTYPE_ETHERNET, LINKTYPE_RAW

#: Default seconds of capture time to wait for a datagram's missing fragments.
DEFAULT_TIMEOUT_S: float = 30.0

#: Default cap on the reassembled size of a single datagram, in bytes.
#: The IPv4 Total Length field cannot exceed this, and an IPv6 datagram beyond
#: it needs a Jumbo Payload option, which cannot be fragmented.
DEFAULT_MAX_DATAGRAM_BYTES: int = 65_535

#: Default cap on the bytes held across all datagrams awaiting reassembly.
DEFAULT_MAX_BUFFERED_BYTES: int = 64 * 1024 * 1024

_IPV4_MIN_HEADER_LEN: int = 20
_IPV6_FIXED_HEADER_LEN: int = 40
_IPV6_FRAGMENT_HEADER_LEN: int = 8
_ETHERNET_HEADER_LEN: int = 14
_VLAN_TAG_LEN: int = 4
_ETHERTYPE_VLAN: int = 0x8100
_ETHERTYPE_QINQ: int = 0x88A8


@dataclass(frozen=True)
class _Key:
    """Identifies the datagram a fragment belongs to."""

    version: int
    src: bytes
    dst: bytes
    identification: int
    protocol: int


@dataclass
class AssembledFrame:
    """One whole frame produced by :meth:`Defragmenter.feed`.

    Carries the tokens of the fragments it was built from, so a caller that
    passed something identifying — a :class:`~packeteer.pcap.PcapRecord`, a
    packet number, a file offset — can say where a reassembled datagram's
    bytes came from.  A reassembled datagram's bytes are spread over several
    discontiguous ranges of the capture, and that set is not recoverable from
    the output frame alone.

    Attributes:
        frame: The whole frame, ready for
            :func:`~packeteer.parse.core.parse_packet`.
        tokens: The *token* argument of every :meth:`Defragmenter.feed` call
            that contributed, in **arrival** order — which for out-of-order
            fragments is not the same as offset order.  A list of one for a
            frame that passed through untouched.
        fragment_count: Number of fragments reassembled into *frame*, or ``1``
            when the frame was not fragmented.  This is the supported way to
            tell a passthrough from a reassembly.

    """

    frame: bytes
    tokens: list[Any]
    fragment_count: int


@dataclass
class IncompleteDatagram:
    """A datagram whose fragments never all arrived.

    Attributes:
        src: Source address, as it appeared in the header.
        dst: Destination address.
        identification: The datagram's identification field.
        protocol: Transport protocol number carried by the datagram.
        fragments_seen: How many fragments were collected.
        bytes_seen: Total payload bytes collected.
        expected_bytes: Total payload length of the datagram, known only once
            the final fragment (the one without the More Fragments flag) has
            arrived; ``None`` otherwise.
        reason: Why it was abandoned — ``"timeout"``, ``"overlap"`` (IPv6
            only, RFC 5722), ``"too_large"``, or ``"evicted"`` when buffer
            limits forced it out.
        tokens: Tokens of the fragments that did arrive, in arrival order —
            the same provenance :class:`AssembledFrame` gives for the frames
            that completed, so a report can name the packets that were lost.

    """

    src: str
    dst: str
    identification: int
    protocol: int
    fragments_seen: int
    bytes_seen: int
    expected_bytes: int | None
    reason: str
    tokens: list[Any] = field(default_factory=list)


@dataclass
class _Pending:
    """Fragments collected so far for one datagram."""

    version: int
    header: bytes                       # frame prefix through the IP header
    ip_header_offset: int               # where the IP header starts in *header*
    protocol: int
    first_seen: float
    chunks: dict[int, bytes] = field(default_factory=dict)   # offset -> data
    tokens: list[Any] = field(default_factory=list)          # in arrival order
    total_length: int | None = None     # known once the last fragment arrives
    bytes_held: int = 0
    overlapped: bool = False

    def covered(self) -> bool:
        """Return ``True`` when the chunks cover the datagram with no holes."""
        if self.total_length is None:
            return False
        position = 0
        for offset in sorted(self.chunks):
            if offset != position:
                return False
            position += len(self.chunks[offset])
        return position == self.total_length

    def assemble(self) -> bytes:
        """Concatenate the chunks in offset order."""
        return b"".join(self.chunks[offset] for offset in sorted(self.chunks))


def _ip_offset(frame: bytes, link_type: int) -> int | None:
    """Return the offset of the IP header within *frame*, or ``None``.

    Only the link layers that can carry a bare IP datagram are handled:
    Ethernet, including one or two VLAN tags, and raw IP.  A frame whose IP
    header cannot be located is passed through untouched by the caller.
    """
    if link_type == LINKTYPE_RAW:
        return 0
    if link_type != LINKTYPE_ETHERNET:
        return None
    if len(frame) < _ETHERNET_HEADER_LEN:
        return None
    offset = _ETHERNET_HEADER_LEN
    (ethertype,) = struct.unpack_from("!H", frame, 12)
    while ethertype in (_ETHERTYPE_VLAN, _ETHERTYPE_QINQ):
        if len(frame) < offset + _VLAN_TAG_LEN:
            return None
        (ethertype,) = struct.unpack_from("!H", frame, offset + 2)
        offset += _VLAN_TAG_LEN
    if ethertype not in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
        return None
    return offset


@dataclass
class _FragmentInfo:
    """The fields needed to place one fragment within its datagram."""

    key: _Key
    offset_bytes: int
    more_fragments: bool
    header_end: int          # end of the frame prefix to keep (through IP header)
    data: bytes
    version: int
    protocol: int


def _examine(frame: bytes, link_type: int) -> _FragmentInfo | None:
    """Return fragment details for *frame*, or ``None`` if it is not a fragment."""
    ip_at = _ip_offset(frame, link_type)
    if ip_at is None or len(frame) <= ip_at:
        return None

    version = frame[ip_at] >> 4
    if version == 4:
        return _examine_ipv4(frame, ip_at)
    if version == 6:
        return _examine_ipv6(frame, ip_at)
    return None


def _examine_ipv4(frame: bytes, ip_at: int) -> _FragmentInfo | None:
    if len(frame) < ip_at + _IPV4_MIN_HEADER_LEN:
        return None
    ihl = (frame[ip_at] & 0x0F) * 4
    if ihl < _IPV4_MIN_HEADER_LEN or len(frame) < ip_at + ihl:
        return None

    total_length, identification, flags_frag = struct.unpack_from(
        "!HHH", frame, ip_at + 2,
    )
    more_fragments = bool(flags_frag & 0x2000)
    offset_bytes = (flags_frag & 0x1FFF) * 8
    if not more_fragments and offset_bytes == 0:
        return None                                  # not fragmented

    protocol = frame[ip_at + 9]
    # Trust the header's length over the frame's, so Ethernet padding on a
    # short final fragment is not reassembled into the payload.
    end = ip_at + total_length if ip_at + total_length <= len(frame) else len(frame)
    return _FragmentInfo(
        key=_Key(4, frame[ip_at + 12: ip_at + 16], frame[ip_at + 16: ip_at + 20],
                 identification, protocol),
        offset_bytes=offset_bytes,
        more_fragments=more_fragments,
        header_end=ip_at + ihl,
        data=frame[ip_at + ihl: end],
        version=4,
        protocol=protocol,
    )


def _examine_ipv6(frame: bytes, ip_at: int) -> _FragmentInfo | None:
    if len(frame) < ip_at + _IPV6_FIXED_HEADER_LEN:
        return None
    if frame[ip_at + 6] != IPV6_NEXT_HEADER_FRAGMENT:
        # Only a Fragment header directly after the fixed header is handled;
        # a datagram with other extension headers first is passed through.
        return None
    frag_at = ip_at + _IPV6_FIXED_HEADER_LEN
    if len(frame) < frag_at + _IPV6_FRAGMENT_HEADER_LEN:
        return None

    payload_length, = struct.unpack_from("!H", frame, ip_at + 4)
    protocol, _, offset_flags, identification = struct.unpack_from(
        "!BBHI", frame, frag_at,
    )
    end = ip_at + _IPV6_FIXED_HEADER_LEN + payload_length
    if payload_length == 0 or end > len(frame):
        end = len(frame)

    return _FragmentInfo(
        key=_Key(6, frame[ip_at + 8: ip_at + 24], frame[ip_at + 24: ip_at + 40],
                 identification, protocol),
        offset_bytes=(offset_flags >> 3) * 8,
        more_fragments=bool(offset_flags & 0x1),
        header_end=frag_at + _IPV6_FRAGMENT_HEADER_LEN,
        data=frame[frag_at + _IPV6_FRAGMENT_HEADER_LEN: end],
        version=6,
        protocol=protocol,
    )


def _rebuild_ipv4(pending: _Pending, payload: bytes) -> bytes:
    """Return a whole IPv4 frame carrying the reassembled *payload*."""
    head = bytearray(pending.header)
    ip_at = pending.ip_header_offset
    ihl = (head[ip_at] & 0x0F) * 4
    struct.pack_into("!H", head, ip_at + 2, ihl + len(payload))   # total length
    struct.pack_into("!H", head, ip_at + 6, 0)                    # flags + offset
    struct.pack_into("!H", head, ip_at + 10, 0)                   # checksum
    checksum = _ones_complement(bytes(head[ip_at: ip_at + ihl]))
    struct.pack_into("!H", head, ip_at + 10, checksum)
    return bytes(head) + payload


def _rebuild_ipv6(pending: _Pending, payload: bytes) -> bytes:
    """Return a whole IPv6 frame carrying the reassembled *payload*.

    The Fragment extension header is removed and the base header's Next
    Header is set to the transport protocol it was shielding, so the result
    is the datagram as it was before fragmentation.
    """
    ip_at = pending.ip_header_offset
    head = bytearray(pending.header[: ip_at + _IPV6_FIXED_HEADER_LEN])
    head[ip_at + 6] = pending.protocol
    struct.pack_into("!H", head, ip_at + 4, len(payload))          # payload length
    return bytes(head) + payload


def _ones_complement(data: bytes) -> int:
    """Return the RFC 1071 checksum of *data*."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class Defragmenter:
    """Reassembles fragmented IP datagrams from a stream of frames.

    Stateful and incremental: feed frames in capture order and take whatever
    each one completes.  :func:`defragment` wraps this for the common case;
    use the class directly when you need to see what never completed.

    .. code-block:: python

        from packeteer.parse.defragment import Defragmenter

        d = Defragmenter()
        for record in reader:
            for frame in d.feed(record.data, record.ts_sec):
                ...
        for frame in d.flush():
            ...
        for lost in d.incomplete:
            print(lost.src, lost.dst, lost.reason)

    Args:
        link_type: Link-layer type of the frames, matching
            :attr:`packeteer.pcap.PcapFileHeader.link_type`.  Ethernet (with
            or without VLAN tags) and raw IP are understood; frames of any
            other link type pass through untouched.
        timeout_s: Seconds of *capture* time to wait for a datagram's missing
            fragments before abandoning it.
        max_datagram_bytes: Cap on one reassembled datagram.  A datagram
            claiming more is abandoned rather than buffered.
        max_buffered_bytes: Cap on the bytes held across all datagrams
            awaiting reassembly.  When exceeded, the oldest incomplete
            datagram is evicted.

    Attributes:
        incomplete: Datagrams abandoned so far, as
            :class:`IncompleteDatagram` records.

    """

    def __init__(
        self,
        *,
        link_type: int = LINKTYPE_ETHERNET,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_datagram_bytes: int = DEFAULT_MAX_DATAGRAM_BYTES,
        max_buffered_bytes: int = DEFAULT_MAX_BUFFERED_BYTES,
    ) -> None:
        self.link_type = link_type
        self.timeout_s = timeout_s
        self.max_datagram_bytes = max_datagram_bytes
        self.max_buffered_bytes = max_buffered_bytes
        self.incomplete: list[IncompleteDatagram] = []
        self._pending: dict[_Key, _Pending] = {}
        self._buffered = 0

    def feed(
        self, frame: bytes, ts: float = 0.0, token: Any = None,
    ) -> list[AssembledFrame]:
        """Feed one frame and return the frames it completes.

        Args:
            frame: Raw frame bytes, as captured.
            ts: Capture time in seconds.  Drives timeouts only; pass the
                record's ``ts_sec`` (plus its fraction, if you have it).
            token: Anything identifying this frame — a
                :class:`~packeteer.pcap.PcapRecord`, a packet number, a byte
                offset.  It is returned on the :class:`AssembledFrame` this
                frame ends up in, and never inspected.

        Returns:
            A list of :class:`AssembledFrame`: one holding *frame* itself when
            it is not a fragment, one holding the reassembled datagram when
            this fragment completed one, or an empty list while a datagram is
            still incomplete.

        """
        self._expire(ts)

        info = _examine(frame, self.link_type)
        if info is None:
            return [AssembledFrame(frame=frame, tokens=[token], fragment_count=1)]

        pending = self._pending.get(info.key)
        if pending is None:
            pending = _Pending(
                version=info.version,
                header=frame[: info.header_end],
                ip_header_offset=_ip_offset(frame, self.link_type) or 0,
                protocol=info.protocol,
                first_seen=ts,
            )
            self._pending[info.key] = pending
        elif pending.overlapped:
            return []                       # datagram already discarded

        if info.offset_bytes == 0:
            # The first fragment carries the transport header, so its frame
            # prefix is the one to rebuild from.
            pending.header = frame[: info.header_end]
            pending.ip_header_offset = _ip_offset(frame, self.link_type) or 0

        # Recorded before _place, so a fragment dropped as overlapping or
        # oversized still shows up in the incomplete report that follows.
        pending.tokens.append(token)

        if not self._place(pending, info):
            self._abandon(info.key, "overlap" if pending.overlapped else "too_large")
            return []

        if not info.more_fragments:
            pending.total_length = info.offset_bytes + len(info.data)

        if pending.covered():
            del self._pending[info.key]
            self._buffered -= pending.bytes_held
            payload = pending.assemble()
            rebuild = _rebuild_ipv4 if pending.version == 4 else _rebuild_ipv6
            return [AssembledFrame(
                frame=rebuild(pending, payload),
                tokens=list(pending.tokens),
                fragment_count=len(pending.chunks),
            )]

        self._evict_if_over_limit()
        return []

    def flush(self) -> list[AssembledFrame]:
        """Abandon every datagram still awaiting fragments.

        Call at end of capture.  Incomplete datagrams are recorded in
        :attr:`incomplete` and produce no frames — a partially assembled
        datagram would be data that was never sent.

        Returns:
            An empty list.  It exists so ``feed`` and ``flush`` can be used
            interchangeably in a loop.

        """
        for key in list(self._pending):
            self._abandon(key, "timeout")
        return []

    def _place(self, pending: _Pending, info: _FragmentInfo) -> bool:
        """Store one fragment's data.  Returns ``False`` if it must be dropped."""
        end = info.offset_bytes + len(info.data)
        if end > self.max_datagram_bytes:
            return False

        for offset, chunk in pending.chunks.items():
            if info.offset_bytes < offset + len(chunk) and offset < end:
                # RFC 5722: an overlapping IPv6 fragment voids the datagram.
                # IPv4 keeps the bytes that arrived first (BSD behaviour).
                if pending.version == 6:
                    pending.overlapped = True
                    return False
                return True

        pending.chunks[info.offset_bytes] = info.data
        pending.bytes_held += len(info.data)
        self._buffered += len(info.data)
        return True

    def _expire(self, now: float) -> None:
        """Abandon datagrams whose first fragment is older than the timeout."""
        if not self._pending:
            return
        stale = [
            key for key, pending in self._pending.items()
            if now - pending.first_seen > self.timeout_s
        ]
        for key in stale:
            self._abandon(key, "timeout")

    def _evict_if_over_limit(self) -> None:
        """Drop the oldest incomplete datagrams until under the buffer cap."""
        while self._buffered > self.max_buffered_bytes and self._pending:
            oldest = min(self._pending, key=lambda k: self._pending[k].first_seen)
            self._abandon(oldest, "evicted")

    def _abandon(self, key: _Key, reason: str) -> None:
        """Record a datagram as incomplete and release its buffer."""
        pending = self._pending.pop(key, None)
        if pending is None:
            return
        self._buffered -= pending.bytes_held
        self.incomplete.append(IncompleteDatagram(
            tokens=list(pending.tokens),
            src=_format_address(key.src),
            dst=_format_address(key.dst),
            identification=key.identification,
            protocol=key.protocol,
            fragments_seen=len(pending.chunks),
            bytes_seen=pending.bytes_held,
            expected_bytes=pending.total_length,
            reason=reason,
        ))


def _format_address(raw: bytes) -> str:
    """Render a packed IPv4 or IPv6 address as a string."""
    import socket
    family = socket.AF_INET if len(raw) == 4 else socket.AF_INET6
    return socket.inet_ntop(family, raw)


def defragment(
    frames: Iterable[bytes],
    *,
    link_type: int = LINKTYPE_ETHERNET,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> Iterator[bytes]:
    """Reassemble fragmented IPv4 and IPv6 datagrams in *frames*.

    Non-fragmented frames pass through untouched and in order; a datagram's
    fragments are replaced by one reassembled frame, emitted where its final
    fragment arrived.  Incomplete datagrams are dropped — use
    :class:`Defragmenter` to see what never completed.

    Args:
        frames: Raw frames in capture order.
        link_type: Link-layer type of the frames.  Ethernet (with or without
            VLAN tags) and raw IP are understood; other link types pass
            through untouched.
        timeout_s: Seconds of capture time to wait for missing fragments.
            Without per-frame timestamps this only bounds nothing, so pass
            timestamps via :class:`Defragmenter` when timeouts matter.

    Yields:
        Whole frames, ready for :func:`~packeteer.parse.core.parse_packet`.

    Example::

        from packeteer.parse.defragment import defragment

        whole = list(defragment(fragments))

    """
    engine = Defragmenter(link_type=link_type, timeout_s=timeout_s)
    for frame in frames:
        for assembled in engine.feed(frame):
            yield assembled.frame
    engine.flush()


def defragment_ipv4(
    frames: Iterable[bytes],
    *,
    link_type: int = LINKTYPE_ETHERNET,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> Iterator[bytes]:
    """Reassemble IPv4 fragments only, passing IPv6 fragments through.

    Same behaviour and arguments as :func:`defragment`, restricted to IPv4 —
    the counterpart to
    :func:`~packeteer.generate.fragmentation.fragment_ipv4`.
    """
    yield from _defragment_version(frames, 4, link_type, timeout_s)


def defragment_ipv6(
    frames: Iterable[bytes],
    *,
    link_type: int = LINKTYPE_ETHERNET,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> Iterator[bytes]:
    """Reassemble IPv6 fragments only, passing IPv4 fragments through.

    Same behaviour and arguments as :func:`defragment`, restricted to IPv6 —
    the counterpart to
    :func:`~packeteer.generate.fragmentation.fragment_ipv6`.
    """
    yield from _defragment_version(frames, 6, link_type, timeout_s)


def _defragment_version(
    frames: Iterable[bytes], version: int, link_type: int, timeout_s: float,
) -> Iterator[bytes]:
    """Reassemble fragments of one IP version, passing everything else through."""
    engine = Defragmenter(link_type=link_type, timeout_s=timeout_s)
    for frame in frames:
        info = _examine(frame, link_type)
        if info is None or info.version != version:
            yield frame
            continue
        for assembled in engine.feed(frame):
            yield assembled.frame
    engine.flush()
