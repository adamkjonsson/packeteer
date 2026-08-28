"""TCP stream generation.

This module generates a realistic sequence of packets representing a complete
TCP connection: three-way handshake, data transfer (client→server), and
four-way teardown.

Sequence and acknowledgement numbers are tracked correctly across both sides,
including 32-bit wrap-around.  Each packet is assembled via
:class:`~packeteer.generate.builder.PacketBuilder`, so all IP and TCP checksums
are computed automatically.

Typical usage::

    from packeteer.generate.tcp_stream import generate_tcp_stream
    from packeteer.pcap import write_pcap

    stream = generate_tcp_stream(
        client_ip="10.0.0.1",
        server_ip="10.0.0.2",
        server_port=80,
        num_data_packets=20,
        payload_distribution="bimodal",
    )
    write_pcap(stream.to_pcap_tuples(), path="out.pcap")
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from random import Random

from ._stream_common import (
    _advance_seq,
    _alloc_usec,
    _build_packet,
    _fragment_ip_raw,
    _payload_sizes,
    _pkt_usec,
    _repeat_payload,
    _TCPEndpoint,
)
from .impairments import (
    FlowEndpoints,
    ImpairmentConfig,
    apply_impairments,
    apply_loss_recovery,
    drop_packet,
)
from .stream_encap import (  # noqa: F401  (StreamEncap needed for Sphinx type resolution)
    EncapSpec,
    StreamEncap,
    _apply_encap,
    _encap_ip_start,
)
from .tcp import TCP_ACK, TCP_FIN, TCP_PSH, TCP_SYN, TCPOptions

_WRAP = 2 ** 32


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class TCPStreamPacket:
    """One packet in a generated TCP stream.

    Attributes:
        raw: Fully-assembled packet bytes, ready for pcap output or further
            manipulation.
        ts_sec: Packet timestamp — whole seconds part.
        ts_usec: Packet timestamp — microseconds part.
        direction: ``"c2s"`` (client→server) or ``"s2c"`` (server→client).
        flags: TCP flags bitmask as sent (e.g. ``TCP_SYN | TCP_ACK``).
        seq: TCP sequence number as sent.
        ack: TCP acknowledgement number as sent (``0`` if ACK flag not set).
        payload_len: Application payload length in bytes.
        label: Human-readable label (e.g. ``"SYN"``, ``"DATA[3]"``,
            ``"FIN-ACK"``).  Useful for targeting specific packets in hooks.

    """

    raw: bytes
    ts_sec: int
    ts_usec: int
    direction: str
    flags: int
    seq: int
    ack: int
    payload_len: int
    label: str


@dataclass
class TCPStream:
    """A complete generated TCP stream.

    Attributes:
        packets: Ordered list of all packets in the stream.  The list is a
            plain :class:`list`, so entries can be freely inserted, removed,
            or reordered for error/anomaly injection before writing to pcap.

    """

    packets: list[TCPStreamPacket]

    def to_pcap_tuples(self) -> list[tuple[bytes, int, int]]:
        """Return packets as ``(raw, ts_sec, ts_usec)`` tuples.

        The returned list is directly compatible with
        :func:`~packeteer.pcap.write_pcap` and
        :func:`~packeteer.pcap.write_pcapng`.
        """
        return [(p.raw, p.ts_sec, p.ts_usec) for p in self.packets]

    def client_packets(self) -> list[TCPStreamPacket]:
        """Return only client→server packets."""
        return [p for p in self.packets if p.direction == "c2s"]

    def server_packets(self) -> list[TCPStreamPacket]:
        """Return only server→client packets."""
        return [p for p in self.packets if p.direction == "s2c"]


@dataclass
class TCPStreamConfig:
    """Optional TCP-stream parameters and anomaly-injection controls.

    Pass an instance as the *config* argument to :func:`generate_tcp_stream`
    to customise timing, anomaly injection, and per-packet hooks without
    widening the function signature.

    Attributes:
        payload_sizes: Explicit list of payload sizes, one per data packet.
            When provided, overrides *min_payload*, *max_payload*, and
            *payload_distribution*.  Must have exactly *num_data_packets*
            entries.
        base_time: Unix timestamp for the first packet in seconds.  Defaults
            to the current time when ``None``.
        gap_jitter: Maximum capture-delay jitter in seconds.  Packet *n* is
            sent at ``base_time + n * inter_packet_gap`` and assigned a
            capture timestamp of ``sent_time + uniform(0, gap_jitter)``.
            Defaults to ``0.0`` (no jitter).
        seed: Integer seed for the random number generator.  When set, two
            calls with identical arguments produce byte-identical output.
            Defaults to ``None`` (non-deterministic).
        psh_probability: Probability (0.0–1.0) that the PSH flag is set on
            each data segment.  Defaults to ``0.5``.
        window: TCP receive-window size advertised by both endpoints.
            Defaults to ``65535``.
        client_options: TCP options encoded on the client SYN only (e.g. MSS,
            window scale, SACK permitted).  ``None`` means no options.
        server_options: TCP options encoded on the server SYN-ACK only.
        packet_loss_probability: Probability (0.0–1.0) that a packet is lost
            on the wire.  Neither the capture point nor the far end sees it, so
            a lost segment is never acknowledged and does not advance the
            receiver's acknowledgement number: the segments after it are
            answered with duplicate ACKs until the gap is filled.  The SYNs are
            exempt — each side learns the other's initial sequence number from
            them.  Nothing retransmits, so a lost segment leaves a permanent
            hole in the byte range.  Defaults to ``0.0`` (no loss).
        retransmission_probability: Probability (0.0–1.0) that each data
            segment triggers a spurious retransmission.  Defaults to ``0.0``.
        retransmission_timeout: Seconds after the original send time at which
            the retransmission timer fires.  Defaults to ``0.2`` (200 ms).
        payload_corruption_probability: Probability (0.0–1.0) that each data
            segment's payload is corrupted in transit (last byte XOR-flipped).
            Defaults to ``0.0`` (no corruption).
        server_rst_probability: Probability (0.0–1.0) that the server
            terminates mid-stream with a TCP RST.  Defaults to ``0.0``.
        rst_propagation_delay: Seconds between the server sending the RST
            and the client receiving it.  Defaults to ``0.0``.
        stray_packet_count: Number of forged TCP-hijacking packets to inject.
            Defaults to ``0``.
        retransmit_lost: Whether a lost segment is retransmitted after
            *retransmission_timeout* and delivered, so the connection recovers.
            Defaults to ``False``, leaving a permanent hole in the byte range.
            Distinct from *retransmission_probability*, which duplicates a
            segment that did arrive.
        stray_timing_window: When set, constrains stray packet timestamps to
            within *N* positions of the stolen reference packet in the
            timestamp-sorted stream.  ``None`` uses the full data-transfer
            window.
        packet_hooks: Optional list of callables applied to each packet after
            it is built.  Signature::

                def hook(pkt: TCPStreamPacket, index: int) -> TCPStreamPacket | None

            Returning ``None`` drops the packet.
        payload_fn: Optional callable invoked once per data packet to supply
            its payload bytes.  Signature::

                def payload_fn(packet_index: int, direction: str) -> bytes

            When provided, *min_payload*, *max_payload*, *payload_distribution*,
            and *payload_sizes* are all ignored.

    """

    payload_sizes: list[int] | None = None
    base_time: float | None = None
    gap_jitter: float = 0.0
    seed: int | None = None
    psh_probability: float = 0.5
    window: int = 65535
    client_options: TCPOptions | None = None
    server_options: TCPOptions | None = None
    packet_loss_probability: float = 0.0
    retransmission_probability: float = 0.0
    retransmission_timeout: float = 0.2
    payload_corruption_probability: float = 0.0
    server_rst_probability: float = 0.0
    rst_propagation_delay: float = 0.0
    stray_packet_count: int = 0
    stray_timing_window: int | None = None
    retransmit_lost: bool = False
    packet_hooks: list[Callable[[TCPStreamPacket, int], TCPStreamPacket | None]] | None = None
    payload_fn: Callable[[int, str], bytes] | None = None


# ── Internal helpers ──────────────────────────────────────────────────────────

# ── IP fragmentation ─────────────────────────────────────────────────────────

def _fragment_packet(
    pkt: TCPStreamPacket,
    mtu: int,
    include_ethernet: bool,
    used_ts: set[int],
    encap: EncapSpec = None,
) -> list[TCPStreamPacket]:
    """Split *pkt* into IP fragments if its IP-layer size exceeds *mtu*.

    Returns a single-element list with the original packet unchanged when no
    fragmentation is needed.  Otherwise returns one :class:`TCPStreamPacket`
    per fragment, labelled ``FRAG[<orig_label>][<n>]``.  Fragment 0 carries
    the TCP header; subsequent fragments carry only payload continuation bytes.

    *used_ts* is updated in place: the original timestamp is removed and each
    new fragment timestamp is added, ensuring global uniqueness.
    """
    ip_start = _encap_ip_start(encap, include_ethernet)
    frag_raws = _fragment_ip_raw(pkt.raw, ip_start, mtu, encap)
    if frag_raws is None:
        return [pkt]

    orig_usec = _pkt_usec(pkt)
    used_ts.discard(orig_usec)

    result: list[TCPStreamPacket] = []
    for i, frag_raw in enumerate(frag_raws):
        ts = _alloc_usec(orig_usec + i, used_ts)
        label = f"FRAG[{pkt.label}][{i}]"
        if i == 0:
            result.append(replace(pkt, raw=frag_raw,
                                  ts_sec=ts // 1_000_000, ts_usec=ts % 1_000_000,
                                  label=label))
        else:
            result.append(TCPStreamPacket(
                raw=frag_raw,
                ts_sec=ts // 1_000_000, ts_usec=ts % 1_000_000,
                direction=pkt.direction,
                flags=0, seq=0, ack=0, payload_len=0,
                label=label,
            ))
    return result


# ── Data-chunk builder ────────────────────────────────────────────────────────

def _data_chunks(
    payload_fn: Callable[[int, str], bytes] | None,
    num: int,
    min_p: int,
    max_p: int,
    distribution: str,
    explicit_sizes: list[int] | None,
    rng: Random,
) -> list[bytes]:
    """Return *num* payload chunks for the data-transfer phase."""
    if payload_fn is not None:
        return [payload_fn(i, "c2s") for i in range(num)]
    sizes = _payload_sizes(num, min_p, max_p, distribution, explicit_sizes, rng)
    payload_data = _repeat_payload(sum(sizes))
    offset = 0
    result: list[bytes] = []
    for size in sizes:
        result.append(payload_data[offset:offset + size])
        offset += size
    return result


# ── Public API ────────────────────────────────────────────────────────────────

def generate_tcp_stream(
    *,
    client_ip: str,
    server_ip: str,
    client_port: int = 54321,
    server_port: int = 80,
    client_mac: str = "00:00:00:00:00:01",
    server_mac: str = "00:00:00:00:00:02",
    num_data_packets: int = 10,
    min_payload: int = 40,
    max_payload: int = 1460,
    payload_distribution: str = "uniform",
    client_isn: int | None = None,
    server_isn: int | None = None,
    include_ethernet: bool = True,
    ip_ttl: int = 64,
    inter_packet_gap: float = 0.001,
    mtu: int | None = None,
    encap: EncapSpec = None,
    config: TCPStreamConfig | None = None,
) -> TCPStream:
    """Generate a complete TCP stream as a sequence of :class:`TCPStreamPacket` objects.

    Produces a realistic exchange in this order:

    1. Three-way handshake: SYN → SYN-ACK → ACK
    2. Data transfer: *num_data_packets* ACK segments (client→server, PSH set
       with probability *psh_probability*), each immediately acknowledged by
       the server
    3. Four-way teardown: FIN-ACK → ACK → FIN-ACK → ACK

    The baseline packet count is ``2 * num_data_packets + 7``.  Anomaly
    parameters (RST, corruption, retransmissions, packet loss) may add or
    remove packets from the final list.

    Args:
        client_ip: Client IP address (IPv4 dotted-decimal or IPv6 colon-hex).
        server_ip: Server IP address (same family as *client_ip*).
        client_port: Client source port.  Defaults to ``54321``.
        server_port: Server destination port.  Defaults to ``80``.
        client_mac: Client MAC address.  Ignored when *include_ethernet* is
            ``False``.
        server_mac: Server MAC address.  Ignored when *include_ethernet* is
            ``False``.
        num_data_packets: Number of PSH+ACK data segments sent by the client.
        min_payload: Minimum data payload in bytes.  Defaults to ``40``.
        max_payload: Maximum data payload in bytes.  Defaults to ``1460``
            (typical Ethernet MSS for IPv4).
        payload_distribution: How to vary payload sizes:

            * ``"uniform"`` — random between *min_payload* and *max_payload*
            * ``"bimodal"`` — 70 % small (near *min_payload*) / 30 % large
              (near *max_payload*), approximating mixed HTTP/TLS traffic
            * ``"fixed"`` — all segments are *max_payload* bytes

            Ignored when ``config.payload_fn`` is set.
        client_isn: Client initial sequence number.  Randomly chosen if
            ``None`` (default), matching real TCP behaviour.
        server_isn: Server initial sequence number.  Randomly chosen if
            ``None``.
        include_ethernet: When ``True`` (default) each packet starts with an
            Ethernet II header.  Set to ``False`` for raw-IP captures.
        ip_ttl: IP TTL / hop limit for all packets.  Defaults to ``64``.
        inter_packet_gap: Seconds between consecutive packets.  Defaults to
            ``0.001`` (1 ms).
        mtu: When set, every packet whose IP-layer size (excluding
            any Ethernet header) exceeds this value is split into IP fragments
            as if it had passed through a middlebox with a limited MTU.
            Fragment packets are labelled ``FRAG[<orig>][<n>]`` where *n*
            starts at zero.  ``None`` (default) disables fragmentation.
        encap: One or more encapsulation layers to wrap every packet in.
            Accepts a single descriptor, a list of descriptors (applied
            outermost first), or ``None`` (default, no encapsulation).
            Available types (all from :mod:`packeteer.generate.stream_encap`).
            **Tag-based** encaps insert layer-2 tags and leave the stream's own
            transport on the wire:

            * :class:`~packeteer.generate.stream_encap.VLANEncap` — 802.1Q tag
            * :class:`~packeteer.generate.stream_encap.QinQEncap` — double 802.1Q tags
            * :class:`~packeteer.generate.stream_encap.MPLSEncap` — MPLS label stack
            * :class:`~packeteer.generate.stream_encap.PPPoEEncap` — PPPoE session frame

            **Tunnel** encaps add their own outer headers and carry the whole
            generated stream as *inner* traffic — so the stream's TCP becomes
            the inner protocol, not the outer transport:

            * :class:`~packeteer.generate.stream_encap.GREEncap` — GRE tunnel
            * :class:`~packeteer.generate.stream_encap.EtherIPEncap` — EtherIP tunnel
            * :class:`~packeteer.generate.stream_encap.IPIPEncap` — IP-in-IP tunnel
            * :class:`~packeteer.generate.stream_encap.VXLANEncap` — VXLAN tunnel;
              the outer transport is always UDP on port 4789 regardless of the
              inner stream protocol
            * :class:`~packeteer.generate.stream_encap.GeneveEncap` — GENEVE
              tunnel; like VXLAN, always UDP (port 6081) regardless of the inner
              stream protocol
            * :class:`~packeteer.generate.stream_encap.GTPUEncap` — GTP-U tunnel
              (UDP port 2152); carries the inner IP directly (no inner Ethernet)

        config: Optional :class:`TCPStreamConfig` supplying timing, anomaly
            injection, per-packet hook settings, and RNG seed.  All fields
            default to their *TCPStreamConfig* defaults when ``None``.

    Returns:
        A :class:`TCPStream` containing all assembled packets in wire order.

    Raises:
        ValueError: If *payload_sizes* (from *config*) length does not match
            *num_data_packets*, or *payload_distribution* is unknown.
        OSError: If an IP address string is invalid.

    Example::

        from packeteer.generate.tcp_stream import generate_tcp_stream, TCPStreamConfig
        from packeteer.generate import TCPOptions
        from packeteer.pcap import write_pcap

        stream = generate_tcp_stream(
            client_ip="10.0.0.1",
            server_ip="10.0.0.2",
            server_port=443,
            num_data_packets=50,
            payload_distribution="bimodal",
            config=TCPStreamConfig(
                client_options=TCPOptions(mss=1460, sack_permitted=True),
            ),
        )
        write_pcap(stream.to_pcap_tuples(), path="tls_session.pcap")

    """
    config = config or TCPStreamConfig()
    rng = Random(config.seed)
    payload_sizes = config.payload_sizes
    psh_probability = config.psh_probability
    window = config.window
    client_options = config.client_options
    server_options = config.server_options
    gap_jitter = config.gap_jitter
    packet_loss_probability = config.packet_loss_probability
    retransmission_probability = config.retransmission_probability
    retransmission_timeout = config.retransmission_timeout
    payload_corruption_probability = config.payload_corruption_probability
    server_rst_probability = config.server_rst_probability
    rst_propagation_delay = config.rst_propagation_delay
    stray_packet_count = config.stray_packet_count
    stray_timing_window = config.stray_timing_window
    retransmit_lost = config.retransmit_lost
    packet_hooks = config.packet_hooks
    payload_fn = config.payload_fn
    base_time = config.base_time if config.base_time is not None else time.time()

    gap_usec = int(inter_packet_gap * 1_000_000)
    jitter_usec = int(gap_jitter * 1_000_000)
    base_usec = int(base_time * 1_000_000)

    client = _TCPEndpoint(
        ip=client_ip, port=client_port, mac=client_mac,
        seq=rng.randint(0, _WRAP - 1) if client_isn is None else client_isn,
        ack=0,
        window=window,
    )
    server = _TCPEndpoint(
        ip=server_ip, port=server_port, mac=server_mac,
        seq=rng.randint(0, _WRAP - 1) if server_isn is None else server_isn,
        ack=0,
        window=window,
    )


    packets: list[TCPStreamPacket] = []
    lost_segments: list[TCPStreamPacket] = []
    global_index = 0

    def emit(
        src: _TCPEndpoint,
        dst: _TCPEndpoint,
        flags: int,
        payload: bytes,
        direction: str,
        label: str,
        options: TCPOptions | None = None,
    ) -> bool:
        """Emit one packet.  Returns whether it reached the far end."""
        nonlocal global_index

        seq_before = src.seq
        ack_before = src.ack

        raw = _build_packet(src, dst, flags, payload, include_ethernet, ip_ttl, options, encap)
        # The sender's sequence number advances whether or not the packet
        # arrives — it sent those bytes.  The receiver's acknowledgement is
        # what depends on delivery, and is updated below only if it arrives.
        _advance_seq(src, flags, len(payload))

        delay_usec = rng.randint(0, jitter_usec) if jitter_usec else 0
        ts_sec, ts_usec = divmod(base_usec + global_index * gap_usec + delay_usec, 1_000_000)
        pkt: TCPStreamPacket | None = TCPStreamPacket(
            raw=raw,
            ts_sec=ts_sec,
            ts_usec=ts_usec,
            direction=direction,
            flags=flags,
            seq=seq_before,
            ack=ack_before if (flags & TCP_ACK) else 0,
            payload_len=len(payload),
            label=label,
        )

        # A SYN is never dropped.  Each side learns the other's initial
        # sequence number from it, so losing one leaves the peer unable to
        # acknowledge anything for the rest of the connection — a capture whose
        # segments carry an acknowledgement number of zero, which is not
        # traffic that could have happened.  Modelling the real outcome, a
        # connection that never establishes, needs setup retransmission the
        # generator does not have.  Everything after the handshake, teardown
        # included, is subject to loss.
        delivered = bool(flags & TCP_SYN) or not drop_packet(
            rng, packet_loss_probability,
        )
        if delivered:
            # Acknowledgements are cumulative, so the receiver's ack number
            # advances only for a segment that arrives *in order* — one
            # starting exactly where the last one ended.  After a loss it stops
            # advancing, and every later acknowledgement repeats the last
            # in-order value, which is what a duplicate ACK is.  A SYN
            # establishes the initial value, there being nothing to follow on
            # from.
            if flags & TCP_SYN or seq_before == dst.ack:
                dst.ack = src.seq
        else:
            if payload:
                lost_segments.append(pkt)
            pkt = None

        if packet_hooks:
            for hook in packet_hooks:
                if pkt is None:
                    break
                pkt = hook(pkt, global_index)

        global_index += 1
        if pkt is not None:
            packets.append(pkt)
        return delivered

    # ── Three-way handshake ───────────────────────────────────────────────────
    emit(client, server, TCP_SYN,           b"", "c2s", "SYN",     options=client_options)
    emit(server, client, TCP_SYN | TCP_ACK, b"", "s2c", "SYN-ACK", options=server_options)
    emit(client, server, TCP_ACK,           b"", "c2s", "ACK")

    # ── Data transfer (client → server, server ACKs each packet) ────────────
    for i, chunk in enumerate(_data_chunks(
        payload_fn, num_data_packets, min_payload, max_payload,
        payload_distribution, payload_sizes, rng,
    )):
        flags = TCP_ACK | (TCP_PSH if rng.random() < psh_probability else 0)
        # A segment that never arrived triggers no acknowledgement: there is
        # nothing at the far end to answer.  The next segment that does arrive
        # is answered with the stale acknowledgement number, which is what a
        # duplicate ACK is.
        if emit(client, server, flags, chunk, "c2s", f"DATA[{i}]"):
            emit(server, client, TCP_ACK, b"", "s2c", f"ACK[{i}]")

    # ── Four-way teardown ─────────────────────────────────────────────────────
    emit(client, server, TCP_FIN | TCP_ACK, b"", "c2s", "FIN-ACK")
    emit(server, client, TCP_ACK,           b"", "s2c", "ACK")
    emit(server, client, TCP_FIN | TCP_ACK, b"", "s2c", "FIN-ACK")
    emit(client, server, TCP_ACK,           b"", "c2s", "ACK")

    # ── Loss recovery ────────────────────────────────────────────────────────
    # Before the passes below, so a recovered segment is a candidate for the
    # same treatment as any other and the timeline is complete when they run.
    if retransmit_lost and lost_segments:
        packets = apply_loss_recovery(
            packets, lost_segments,
            config=ImpairmentConfig(retransmission_timeout=retransmission_timeout),
            flow=FlowEndpoints(
                client_ip=client_ip, client_port=client_port, client_mac=client_mac,
                server_ip=server_ip, server_port=server_port, server_mac=server_mac,
                window=window, include_ethernet=include_ethernet, ip_ttl=ip_ttl,
                encap=encap,
            ),
            make=TCPStreamPacket,
            gap_usec=gap_usec,
        )

    # ── Wire impairments ─────────────────────────────────────────────────────
    # RST, retransmission, corruption and stray injection, in that order.  The
    # passes live in impairments.py so the payload generators can apply the
    # same ones; packet loss is already applied above, inside emit().
    packets = apply_impairments(
        packets,
        rng=rng,
        config=ImpairmentConfig(
            retransmission_probability=retransmission_probability,
            retransmission_timeout=retransmission_timeout,
            payload_corruption_probability=payload_corruption_probability,
            server_rst_probability=server_rst_probability,
            rst_propagation_delay=rst_propagation_delay,
            stray_packet_count=stray_packet_count,
            stray_timing_window=stray_timing_window,
            stray_payload_range=(min_payload, max_payload),
        ),
        flow=FlowEndpoints(
            client_ip=client_ip, client_port=client_port, client_mac=client_mac,
            server_ip=server_ip, server_port=server_port, server_mac=server_mac,
            window=window, include_ethernet=include_ethernet, ip_ttl=ip_ttl,
            encap=encap,
        ),
        make=TCPStreamPacket,
        gap_usec=gap_usec,
        jitter_usec=jitter_usec,
    )


    # ── Middlebox fragmentation ───────────────────────────────────────────────
    if mtu is not None:
        used_ts = {_pkt_usec(p) for p in packets}
        fragmented: list[TCPStreamPacket] = []
        for pkt in packets:
            fragmented.extend(
                _fragment_packet(pkt, mtu, include_ethernet, used_ts, encap)
            )
        packets = fragmented

    packets.sort(key=lambda p: (p.ts_sec, p.ts_usec))
    return TCPStream(packets=packets)
