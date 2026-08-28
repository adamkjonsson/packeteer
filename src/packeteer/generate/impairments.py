"""Wire impairments applied to an assembled TCP stream.

A generator builds a clean conversation; the passes here damage it afterwards
— dropping segments, duplicating them, corrupting payloads, cutting the
connection short with a RST, and injecting forged packets.  Keeping them in
one place is what lets every generator offer the same impairments: the
low-level path (:func:`~packeteer.generate.tcp_stream.generate_tcp_stream`)
and the application-payload paths (``--payload http``) share this module
rather than each growing their own copy.

Everything here works on an assembled packet list, so a pass needs no access
to the session state that produced it.  Packets are identified **structurally**
— by payload length, flags and direction — rather than by their labels, since
the two emit paths label packets differently: a data segment is ``DATA[3]`` on
the low-level path and ``GET /api/v1/orders [2/5]`` on the HTTP path.

Packet loss is the exception.  It is applied at emission time via
:func:`drop_packet`, because on a connection the loss of a segment decides
whether an acknowledgement follows it and what that acknowledgement covers —
neither of which a pass over a finished list can work out.

Ordering matters and is fixed: RST, then retransmission, then corruption, then
stray injection.  Each pass consumes randomness, so the order is part of what a
seed reproduces.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from random import Random
from typing import TYPE_CHECKING, Callable

from ._stream_common import _alloc_usec, _build_packet, _pkt_usec, _TCPEndpoint
from .stream_encap import EncapSpec
from .tcp import TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN

if TYPE_CHECKING:  # pragma: no cover - import cycle avoided at runtime
    from .tcp_stream import TCPStreamPacket

_WRAP = 2 ** 32


@dataclass
class ImpairmentConfig:
    """Wire impairments to apply to a generated stream.

    Every probability is per-opportunity and defaults to zero, so an instance
    with no arguments leaves a stream untouched — and draws no randomness at
    all, which is what lets a capture generated without impairments reproduce
    from its seed exactly as it did before this module existed.

    Attributes:
        packet_loss_probability: Probability (0.0–1.0) that a packet is lost
            on the wire.  On a connection, a lost segment is never
            acknowledged and does not advance the receiver's acknowledgement
            number, so the segments after it draw duplicate ACKs; the SYNs are
            exempt.  Nothing retransmits, so the gap is permanent.
        retransmission_probability: Probability (0.0–1.0) that each data
            segment triggers a spurious retransmission.
        retransmission_timeout: Seconds after the original send time at which
            the retransmission timer fires.  Defaults to ``0.2`` (200 ms).
        payload_corruption_probability: Probability (0.0–1.0) that each data
            segment's payload is corrupted in transit (last byte XOR-flipped)
            and then retransmitted cleanly.
        server_rst_probability: Probability (0.0–1.0) that the server
            terminates the connection mid-stream with a TCP RST.
        rst_propagation_delay: Seconds between the server sending the RST and
            the client receiving it.  Data the client sends inside this window
            is still on the wire.
        stray_packet_count: Number of forged TCP-hijacking packets to inject,
            each stealing the sequence and acknowledgement numbers of a real
            data segment.
        stray_timing_window: When set, constrains stray packet timestamps to
            within *N* positions of the stolen reference packet in the
            timestamp-sorted stream.  ``None`` uses the full data-transfer
            window.
        stray_payload_range: ``(min, max)`` payload size for injected stray
            packets.
        retransmit_lost: Whether a lost segment is retransmitted after
            *retransmission_timeout* and delivered, so the connection recovers
            the way a real one does.  Defaults to ``False``, which leaves a
            permanent hole in the byte range — the harsher input, and the one
            a decoder is least likely to survive.

            Distinct from *retransmission_probability*, which duplicates a
            segment that **did** arrive.  One models recovery, the other models
            a spurious retransmission; a capture can contain both.

    """

    packet_loss_probability: float = 0.0
    retransmission_probability: float = 0.0
    retransmission_timeout: float = 0.2
    payload_corruption_probability: float = 0.0
    server_rst_probability: float = 0.0
    rst_propagation_delay: float = 0.0
    stray_packet_count: int = 0
    stray_timing_window: int | None = None
    stray_payload_range: tuple[int, int] = (40, 1460)
    retransmit_lost: bool = False

    @property
    def any_post_pass(self) -> bool:
        """Whether any pass in :func:`apply_impairments` would do something."""
        return bool(
            self.retransmission_probability
            or self.payload_corruption_probability
            or self.server_rst_probability
            or self.stray_packet_count
        )


@dataclass
class FlowEndpoints:
    """The two ends of one connection, as the passes need to forge packets.

    A RST comes from the server and a stray packet from the client, so both
    passes have to assemble packets that the original generator never emitted.

    Attributes:
        client_ip: Client IP address.
        client_port: Client source port.
        client_mac: Client MAC address.
        server_ip: Server IP address.
        server_port: Server destination port.
        server_mac: Server MAC address.
        window: Receive window to advertise on forged packets.
        include_ethernet: Whether the stream carries Ethernet headers.
        ip_ttl: IP TTL / hop limit.
        encap: Encapsulation applied to every packet in the stream.

    """

    client_ip: str
    client_port: int
    client_mac: str
    server_ip: str
    server_port: int
    server_mac: str
    window: int = 65535
    include_ethernet: bool = True
    ip_ttl: int = 64
    encap: EncapSpec = None


# ── Structural packet classification ─────────────────────────────────────────
#
# The passes below must not read labels.  These predicates are what replaces
# them, and they are written so that on the low-level path they select exactly
# the packets the label tests used to: there, data flows client -> server only,
# so "carries payload" and "is a DATA[i] segment" pick out the same list.

#: Matches the low-level generator's data-segment label, whose index a derived
#: label reuses so that ``DATA[3]`` becomes ``RETRANS[3]``.
_DATA_LABEL = re.compile(r"^DATA\[(.+)\]$")


def _derive_label(kind: str, source_label: str) -> str:
    """Name a packet derived from another one, keeping the source identifiable.

    Reading a label to *classify* a packet is what this module avoids; naming
    one after the packet it came from is the opposite direction and is what
    makes an impaired capture readable.  A segment labelled ``DATA[3]`` yields
    ``RETRANS[3]``; an application segment labelled ``GET /api/v1/orders``
    yields ``RETRANS[GET /api/v1/orders]``.
    """
    match = _DATA_LABEL.match(source_label)
    return f"{kind}[{match.group(1) if match else source_label}]"


def _is_data(pkt: "TCPStreamPacket") -> bool:
    """Whether *pkt* carries application payload."""
    return pkt.payload_len > 0


def _is_bare_ack(pkt: "TCPStreamPacket") -> bool:
    """Whether *pkt* is a pure acknowledgement — ACK set, nothing else."""
    return bool(pkt.flags & TCP_ACK) and pkt.payload_len == 0 and not (
        pkt.flags & (TCP_SYN | TCP_FIN | TCP_RST)
    )


def _acked_seq(pkt: "TCPStreamPacket") -> int:
    """Return the acknowledgement number a receiver sends back for *pkt*."""
    return (pkt.seq + pkt.payload_len) % _WRAP


def _ack_positions(packets: list["TCPStreamPacket"]) -> dict[int, int]:
    """Map each data packet's index to the index of the ACK answering it.

    Pairing is by sequence number — the ACK for a segment carries
    ``seq + payload_len`` and travels the other way — rather than by adjacency.
    The two emit paths do send a segment and then its ACK, so adjacency would
    usually work; it stops working once packet loss removes one of them, since
    the survivor then sits next to an unrelated packet and would be mistaken
    for its partner.

    Data packets whose ACK is absent — lost, or removed by an earlier pass —
    are simply not in the result.
    """
    acks_by_key: dict[tuple[str, int], int] = {}
    for i, pkt in enumerate(packets):
        if _is_bare_ack(pkt):
            acks_by_key.setdefault((pkt.direction, pkt.ack), i)
    positions: dict[int, int] = {}
    for i, pkt in enumerate(packets):
        if not _is_data(pkt):
            continue
        reply_dir = "s2c" if pkt.direction == "c2s" else "c2s"
        j = acks_by_key.get((reply_dir, _acked_seq(pkt)))
        if j is not None and j > i:
            positions[i] = j
    return positions


# ── Packet loss ──────────────────────────────────────────────────────────────

def drop_packet(rng: Random, probability: float) -> bool:
    """Whether the packet about to be emitted should be dropped.

    Called from a generator's emit loop rather than as a pass, so that the
    packet never enters the stream.  The sender's sequence number has already
    been advanced — it sent those bytes — which is what makes the loss visible
    downstream as a gap rather than as a renumbered stream.  The caller is
    responsible for the rest of what a loss means on a connection: the receiver
    does not acknowledge what it never got, and its acknowledgement number
    stops advancing at the gap.

    Args:
        rng: Seeded random generator.
        probability: Loss probability (0.0–1.0).  A zero probability draws no
            randomness at all.

    Returns:
        ``True`` if the packet should be dropped.

    """
    return bool(probability) and rng.random() < probability


def _drop_datagrams(
    packets: list, *, rng: Random, probability: float,
) -> list:
    """Drop a share of *packets* after the fact.

    Correct for a **connectionless** flow and nothing else.  A datagram that
    never arrives has no further consequence — nothing acknowledges it, and the
    timeline is unchanged because a capture timestamp comes from a packet's
    position in the emission sequence.

    On a TCP connection the loss of a segment also decides whether an
    acknowledgement is sent and what it acknowledges, which a pass over the
    finished list cannot know.  There it is applied in the emit loop instead —
    see :func:`drop_packet`.

    Args:
        packets: The datagrams to thin out.
        rng: Seeded random generator.
        probability: Loss probability (0.0–1.0).  Zero draws no randomness.

    Returns:
        The surviving datagrams, in their original order.

    """
    if not probability:
        return packets
    return [p for p in packets if not drop_packet(rng, probability)]


def apply_datagram_impairments(
    packets: list, *, rng: Random, config: ImpairmentConfig,
) -> list:
    """Apply the impairments that mean something on a connectionless flow.

    Loss and payload corruption describe what a wire does to a datagram and
    apply to UDP unchanged.  The rest of :class:`ImpairmentConfig` describes
    connection behaviour — a retransmission timer, a RST, a hijacked sequence
    number — and has no UDP equivalent, so it is ignored here rather than
    approximated.

    Args:
        packets: One flow's datagrams, in emission order.
        rng: Seeded random generator.
        config: Impairments to apply; only the loss and corruption fields are
            read.

    Returns:
        The impaired datagram list.

    """
    packets = _drop_datagrams(
        packets, rng=rng, probability=config.packet_loss_probability,
    )
    if config.payload_corruption_probability:
        for i, pkt in enumerate(packets):
            if not _is_data(pkt) or rng.random() >= config.payload_corruption_probability:
                continue
            raw = bytearray(pkt.raw)
            raw[-1] ^= 0xFF
            packets[i] = replace(
                pkt, raw=bytes(raw), label=_derive_label("CORRUPT", pkt.label),
            )
    return packets


# ── Loss recovery ────────────────────────────────────────────────────────────

def _contiguous_ack(
    packets: list["TCPStreamPacket"], direction: str, upto_usec: int, start: int,
) -> int:
    """Return the acknowledgement number for what arrived by *upto_usec*.

    Walks the byte ranges that actually arrived and returns the end of the
    unbroken run beginning at *start*.  A segment that arrived after a gap
    counts only once the gap ahead of it is filled — which is what makes a
    recovering receiver jump forward over everything it had been holding.
    """
    ranges = sorted(
        ((p.seq, (p.seq + p.payload_len) % _WRAP) for p in packets
         if p.direction == direction and p.payload_len
         and _pkt_usec(p) <= upto_usec),
    )
    edge = start
    advanced = True
    while advanced:
        advanced = False
        for begin, end in ranges:
            if begin <= edge < end:
                edge = end
                advanced = True
    return edge


def apply_loss_recovery(
    packets: list["TCPStreamPacket"],
    lost: list["TCPStreamPacket"],
    *,
    config: ImpairmentConfig,
    flow: FlowEndpoints,
    make: Callable[..., "TCPStreamPacket"],
    gap_usec: int,
) -> list["TCPStreamPacket"]:
    """Retransmit segments that were lost, and acknowledge what that recovers.

    Appends only; the duplicate ACKs already emitted while the gap was open are
    part of the record and stay.  Each retransmission is followed by an
    acknowledgement covering everything contiguous the receiver holds by then,
    so a receiver that had been repeating itself jumps forward in one step.

    Args:
        packets: The connection's packets, in emission order.
        lost: The data segments that were dropped, as they would have been
            emitted.
        config: Impairments; ``retransmission_timeout`` sets the delay.
        flow: The connection's endpoints, for building the acknowledgements.
        make: Constructor for a new stream packet.
        gap_usec: Inter-packet gap, used to place an ACK after its segment.

    Returns:
        The packet list with the retransmissions and their ACKs appended.

    """
    if not lost:
        return packets

    rto_usec = int(config.retransmission_timeout * 1_000_000)
    used_ts = {_pkt_usec(p) for p in packets}
    out = list(packets)

    # Where each side's byte stream begins, from the SYN it sent.
    starts = {
        p.direction: (p.seq + 1) % _WRAP
        for p in packets if p.flags & TCP_SYN and not (p.flags & TCP_ACK)
    }
    for p in packets:
        if p.flags & TCP_SYN and p.flags & TCP_ACK:
            starts[p.direction] = (p.seq + 1) % _WRAP

    for pkt in sorted(lost, key=_pkt_usec):
        rt_usec = _alloc_usec(_pkt_usec(pkt) + rto_usec, used_ts)
        rt_sec, rt_frac = divmod(rt_usec, 1_000_000)
        recovered = replace(
            pkt, ts_sec=rt_sec, ts_usec=rt_frac,
            label=_derive_label("RETRANS", pkt.label),
        )
        out.append(recovered)

        ack_dir = "s2c" if pkt.direction == "c2s" else "c2s"
        ack_value = _contiguous_ack(
            out, pkt.direction, rt_usec, starts.get(pkt.direction, pkt.seq),
        )
        reference = max(
            (p for p in out if p.direction == ack_dir and p.flags & TCP_ACK
             and _pkt_usec(p) <= rt_usec),
            key=_pkt_usec, default=None,
        )
        if reference is None:
            continue
        if ack_dir == "s2c":
            src_ip, src_port, src_mac = flow.server_ip, flow.server_port, flow.server_mac
            dst_ip, dst_port, dst_mac = flow.client_ip, flow.client_port, flow.client_mac
        else:
            src_ip, src_port, src_mac = flow.client_ip, flow.client_port, flow.client_mac
            dst_ip, dst_port, dst_mac = flow.server_ip, flow.server_port, flow.server_mac
        src = _TCPEndpoint(ip=src_ip, port=src_port, mac=src_mac,
                           seq=reference.seq, ack=ack_value, window=flow.window)
        dst = _TCPEndpoint(ip=dst_ip, port=dst_port, mac=dst_mac,
                           seq=0, ack=0, window=flow.window)
        ack_sec, ack_frac = divmod(
            _alloc_usec(rt_usec + gap_usec, used_ts), 1_000_000,
        )
        out.append(make(
            raw=_build_packet(src, dst, TCP_ACK, b"", flow.include_ethernet,
                              flow.ip_ttl, None, flow.encap),
            ts_sec=ack_sec, ts_usec=ack_frac, direction=ack_dir, flags=TCP_ACK,
            seq=reference.seq, ack=ack_value, payload_len=0,
            label=_derive_label("ACK-RECOVER", pkt.label),
        ))
    return out


# ── The passes ───────────────────────────────────────────────────────────────

def _apply_server_rst(
    packets: list["TCPStreamPacket"],
    data_idx: list[int],
    rng: Random,
    config: ImpairmentConfig,
    flow: FlowEndpoints,
    make: Callable[..., "TCPStreamPacket"],
) -> list["TCPStreamPacket"]:
    """Cut the connection short with a RST from the server.

    A split point is chosen among the data segments; the acknowledgements after
    it and the whole teardown are removed, a RST is sent from the server at the
    moment the next segment would have gone out, and data still in flight when
    the client learns of it is dropped.
    """
    if len(data_idx) < 2:
        return packets

    k = rng.randint(0, len(data_idx) - 2)
    acks = _ack_positions(packets)
    split_pkt = packets[data_idx[k]]
    ack_k = packets[acks[data_idx[k]]] if data_idx[k] in acks else None

    # Everything the connection acknowledges after the split point goes: the
    # server stops answering there, and the teardown never happens.  The cut is
    # by time rather than by which segment an ACK names, so that an ACK whose
    # segment was lost is treated like its neighbours instead of falling
    # through to be read as part of the teardown.
    cutoff_usec = _pkt_usec(ack_k) if ack_k is not None else _pkt_usec(split_pkt)

    def _keep(pkt: "TCPStreamPacket") -> bool:
        if pkt.flags & TCP_FIN:
            return False
        return not (_is_bare_ack(pkt) and _pkt_usec(pkt) > cutoff_usec)

    packets = [p for p in packets if _keep(p)]

    # Reconstruct the server's sequence state from the last ACK it sent, or
    # from the SYN-ACK when the split falls before any ACK survives.
    ref = ack_k or next(
        p for p in packets if p.flags & TCP_SYN and p.flags & TCP_ACK
    )
    rst_src = _TCPEndpoint(
        ip=flow.server_ip, port=flow.server_port, mac=flow.server_mac,
        seq=ref.seq, ack=ref.ack, window=flow.window,
    )
    rst_dst = _TCPEndpoint(
        ip=flow.client_ip, port=flow.client_port, mac=flow.client_mac,
        seq=0, ack=0, window=flow.window,
    )

    # The RST goes out when the next segment would have; the client only
    # learns of it after the propagation delay.
    next_data = _next_data_after(packets, split_pkt)
    if next_data is None:
        return packets
    rst_send_usec = _pkt_usec(next_data)
    client_learns_usec = rst_send_usec + int(config.rst_propagation_delay * 1_000_000)

    packets = [
        p for p in packets
        if not (
            _is_data(p)
            and _pkt_usec(p) > (
                client_learns_usec if p.direction == "c2s" else rst_send_usec
            )
        )
    ]

    used_ts = {_pkt_usec(p) for p in packets}
    rst_sec, rst_usec = divmod(_alloc_usec(rst_send_usec, used_ts), 1_000_000)
    packets.append(make(
        raw=_build_packet(rst_src, rst_dst, TCP_RST | TCP_ACK, b"",
                          flow.include_ethernet, flow.ip_ttl, None, flow.encap),
        ts_sec=rst_sec,
        ts_usec=rst_usec,
        direction="s2c",
        flags=TCP_RST | TCP_ACK,
        seq=ref.seq,
        ack=ref.ack,
        payload_len=0,
        label="RST",
    ))
    return packets


def _next_data_after(
    packets: list["TCPStreamPacket"], after: "TCPStreamPacket",
) -> "TCPStreamPacket | None":
    """Return the first data packet sent strictly after *after*."""
    cutoff = _pkt_usec(after)
    candidates = [p for p in packets if _is_data(p) and _pkt_usec(p) > cutoff]
    return min(candidates, key=_pkt_usec) if candidates else None


def _apply_retransmission(
    packets: list["TCPStreamPacket"],
    data_idx: list[int],
    rng: Random,
    config: ImpairmentConfig,
    jitter_usec: int,
) -> list["TCPStreamPacket"]:
    """Duplicate a share of the data segments after the retransmission timer."""
    rto_usec = int(config.retransmission_timeout * 1_000_000)
    used_ts = {_pkt_usec(p) for p in packets}
    retransmits: list["TCPStreamPacket"] = []
    for i in data_idx:
        if rng.random() >= config.retransmission_probability:
            continue
        pkt = packets[i]
        delay_usec = rng.randint(0, jitter_usec) if jitter_usec else 0
        rt_sec, rt_usec = divmod(
            _alloc_usec(_pkt_usec(pkt) + rto_usec + delay_usec, used_ts), 1_000_000,
        )
        retransmits.append(replace(
            pkt, ts_sec=rt_sec, ts_usec=rt_usec,
            label=_derive_label("RETRANS", pkt.label),
        ))
    return packets + retransmits


def _apply_corruption(
    packets: list["TCPStreamPacket"],
    data_idx: list[int],
    rng: Random,
    config: ImpairmentConfig,
    jitter_usec: int,
    gap_usec: int,
) -> list["TCPStreamPacket"]:
    """Corrupt a share of the data segments, then retransmit them cleanly.

    The acknowledgement of a corrupted segment is pushed out behind the
    retransmission, since a receiver cannot acknowledge what failed its
    checksum.
    """
    rto_usec = int(config.retransmission_timeout * 1_000_000)
    acks = _ack_positions(packets)
    used_ts = {_pkt_usec(p) for p in packets}
    additions: list["TCPStreamPacket"] = []
    for i in data_idx:
        if rng.random() >= config.payload_corruption_probability:
            continue
        pkt = packets[i]

        raw_corrupt = bytearray(pkt.raw)
        raw_corrupt[-1] ^= 0xFF
        packets[i] = replace(
            pkt, raw=bytes(raw_corrupt), label=_derive_label("CORRUPT", pkt.label),
        )

        delay_usec = rng.randint(0, jitter_usec) if jitter_usec else 0
        rt_usec = _alloc_usec(_pkt_usec(pkt) + rto_usec + delay_usec, used_ts)
        rt_sec, rt_usec_part = divmod(rt_usec, 1_000_000)
        additions.append(replace(
            pkt, ts_sec=rt_sec, ts_usec=rt_usec_part,
            label=_derive_label("RETRANS", pkt.label),
        ))

        if i in acks:
            ack_sec, ack_usec = divmod(
                _alloc_usec(rt_usec + gap_usec, used_ts), 1_000_000,
            )
            packets[acks[i]] = replace(
                packets[acks[i]], ts_sec=ack_sec, ts_usec=ack_usec,
            )
    return packets + additions


def _apply_stray(
    packets: list["TCPStreamPacket"],
    data_idx: list[int],
    rng: Random,
    config: ImpairmentConfig,
    flow: FlowEndpoints,
    make: Callable[..., "TCPStreamPacket"],
) -> list["TCPStreamPacket"]:
    """Inject forged packets that steal a real segment's sequence numbers."""
    data_pkts = [packets[i] for i in data_idx]
    if not data_pkts:
        return packets

    used_ts = {_pkt_usec(p) for p in packets}

    # Sorted view used to resolve the timing window.  Built once; stray packets
    # added later do not shift these bounds.
    sorted_pkts: list["TCPStreamPacket"] = []
    ts_index: dict[int, int] = {}
    if config.stray_timing_window is not None:
        sorted_pkts = sorted(packets, key=lambda p: (p.ts_sec, p.ts_usec))
        ts_index = {_pkt_usec(p): i for i, p in enumerate(sorted_pkts)}

    default_ts_lo = min(_pkt_usec(p) for p in data_pkts)
    default_ts_hi = max(_pkt_usec(p) for p in data_pkts)
    min_payload, max_payload = config.stray_payload_range

    strays: list["TCPStreamPacket"] = []
    for n in range(config.stray_packet_count):
        ref = rng.choice(data_pkts)
        stray_src = _TCPEndpoint(
            ip=flow.client_ip, port=flow.client_port, mac=flow.client_mac,
            seq=ref.seq, ack=ref.ack, window=flow.window,
        )
        stray_dst = _TCPEndpoint(
            ip=flow.server_ip, port=flow.server_port, mac=flow.server_mac,
            seq=0, ack=0, window=flow.window,
        )

        if config.stray_timing_window is not None:
            ref_idx = ts_index[_pkt_usec(ref)]
            lo_idx = max(0, ref_idx - config.stray_timing_window)
            hi_idx = min(len(sorted_pkts) - 1, ref_idx + config.stray_timing_window)
            ts_lo = _pkt_usec(sorted_pkts[lo_idx])
            ts_hi = _pkt_usec(sorted_pkts[hi_idx])
        else:
            ts_lo, ts_hi = default_ts_lo, default_ts_hi

        payload = b"x" * rng.randint(min_payload, max_payload)
        ts_sec, ts_usec = divmod(
            _alloc_usec(rng.randint(ts_lo, ts_hi), used_ts), 1_000_000,
        )
        strays.append(make(
            raw=_build_packet(stray_src, stray_dst, TCP_ACK | TCP_PSH, payload,
                              flow.include_ethernet, flow.ip_ttl, None, flow.encap),
            ts_sec=ts_sec,
            ts_usec=ts_usec,
            direction="c2s",
            flags=TCP_ACK | TCP_PSH,
            seq=ref.seq,
            ack=ref.ack,
            payload_len=len(payload),
            label=f"STRAY[{n}]",
        ))
    return packets + strays


def apply_impairments(
    packets: list["TCPStreamPacket"],
    *,
    rng: Random,
    config: ImpairmentConfig,
    flow: FlowEndpoints,
    make: Callable[..., "TCPStreamPacket"],
    gap_usec: int,
    jitter_usec: int = 0,
) -> list["TCPStreamPacket"]:
    """Apply every configured impairment to one connection's packets.

    Packet loss is not applied here — see :func:`drop_packet`, which a
    generator calls as it emits.

    Args:
        packets: One connection's packets, in emission order.  Passing packets
            from more than one connection would let an impairment reach across
            flows, so callers with several connections apply this per flow.
        rng: Seeded random generator.  A pass whose rate is zero draws nothing.
        config: Which impairments to apply, and how hard.
        flow: The connection's endpoints, for forging RST and stray packets.
        make: Constructor for a new stream packet — normally
            :class:`~packeteer.generate.tcp_stream.TCPStreamPacket`.  Passed in
            rather than imported to keep this module free of a cycle back to
            the generator that owns the type.
        gap_usec: Inter-packet gap in microseconds, used to place an
            acknowledgement after a retransmission.
        jitter_usec: Maximum capture-delay jitter in microseconds.

    Returns:
        The impaired packet list.  Not re-sorted: callers sort by timestamp
        once, after any further stages of their own.

    """
    if not config.any_post_pass:
        return packets

    if config.server_rst_probability and rng.random() < config.server_rst_probability:
        packets = _apply_server_rst(
            packets, [i for i, p in enumerate(packets) if _is_data(p)],
            rng, config, flow, make,
        )

    # Recorded once, after the RST pass has done its filtering and before any
    # pass appends: retransmitted and stray packets carry payload too, and
    # neither is a candidate for being retransmitted, corrupted, or stolen from.
    data_idx = [i for i, p in enumerate(packets) if _is_data(p)]

    if config.retransmission_probability:
        packets = _apply_retransmission(packets, data_idx, rng, config, jitter_usec)

    if config.payload_corruption_probability:
        packets = _apply_corruption(
            packets, data_idx, rng, config, jitter_usec, gap_usec,
        )

    if config.stray_packet_count:
        packets = _apply_stray(packets, data_idx, rng, config, flow, make)

    return packets
