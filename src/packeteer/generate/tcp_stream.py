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

import random
import time
from dataclasses import dataclass, replace
from collections.abc import Callable

from .builder import PacketBuilder
from ._stream_common import (
    _alloc_usec, _fragment_ip_raw, _payload_sizes, _pkt_usec, _repeat_payload,
)
from .stream_encap import (EncapSpec, StreamEncap,  # noqa: F401  (StreamEncap needed for Sphinx type resolution)
                           _apply_encap, _encap_ip_start)
from .tcp import TCPOptions, TCP_SYN, TCP_ACK, TCP_PSH, TCP_FIN, TCP_RST

_WRAP = 2 ** 32


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class _TCPEndpoint:
    """Mutable per-side connection state (internal only)."""

    ip: str
    port: int
    mac: str
    seq: int    # next sequence number to send
    ack: int    # next sequence number expected from the peer
    window: int = 65535


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
        psh_probability: Probability (0.0–1.0) that the PSH flag is set on
            each data segment.  Defaults to ``0.5``.
        window: TCP receive-window size advertised by both endpoints.
            Defaults to ``65535``.
        client_options: TCP options encoded on the client SYN only (e.g. MSS,
            window scale, SACK permitted).  ``None`` means no options.
        server_options: TCP options encoded on the server SYN-ACK only.
        base_time: Unix timestamp for the first packet in seconds.  Defaults
            to the current time when ``None``.
        gap_jitter: Maximum capture-delay jitter in seconds.  Packet *n* is
            sent at ``base_time + n * inter_packet_gap`` and assigned a
            capture timestamp of ``sent_time + uniform(0, gap_jitter)``.
            Defaults to ``0.0`` (no jitter).
        packet_loss_probability: Probability (0.0–1.0) that any individual
            packet is silently dropped, simulating packet loss on the wire.
            Defaults to ``0.0`` (no loss).
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
        stray_timing_window: When set, constrains stray packet timestamps to
            within *N* positions of the stolen reference packet in the
            timestamp-sorted stream.  ``None`` uses the full data-transfer
            window.
        packet_hooks: Optional list of callables applied to each packet after
            it is built.  Signature::

                def hook(pkt: TCPStreamPacket, index: int) -> TCPStreamPacket | None

            Returning ``None`` drops the packet.

    """

    payload_sizes: list[int] | None = None
    psh_probability: float = 0.5
    window: int = 65535
    client_options: TCPOptions | None = None
    server_options: TCPOptions | None = None
    base_time: float | None = None
    gap_jitter: float = 0.0
    packet_loss_probability: float = 0.0
    retransmission_probability: float = 0.0
    retransmission_timeout: float = 0.2
    payload_corruption_probability: float = 0.0
    server_rst_probability: float = 0.0
    rst_propagation_delay: float = 0.0
    stray_packet_count: int = 0
    stray_timing_window: int | None = None
    packet_hooks: list[Callable[[TCPStreamPacket, int], TCPStreamPacket | None]] | None = None


# ── Internal helpers ──────────────────────────────────────────────────────────

def _advance_seq(ep: _TCPEndpoint, flags: int, payload_len: int) -> None:
    """Advance *ep*.seq by the number of sequence numbers this segment consumes.

    SYN and FIN each consume one sequence number in addition to the payload
    bytes.  32-bit wrap-around is handled with modulo arithmetic.
    """
    consumed = payload_len
    if flags & TCP_SYN:
        consumed += 1
    if flags & TCP_FIN:
        consumed += 1
    ep.seq = (ep.seq + consumed) % _WRAP


def _build_packet(
    src: _TCPEndpoint,
    dst: _TCPEndpoint,
    flags: int,
    payload: bytes,
    include_ethernet: bool,
    ip_ttl: int,
    options: TCPOptions | None,
    encap: EncapSpec = None,
) -> bytes:
    """Assemble one raw packet using PacketBuilder."""
    b = PacketBuilder()
    if include_ethernet:
        b = b.ethernet(src_mac=src.mac, dst_mac=dst.mac)
    b = _apply_encap(b, encap, src.mac, dst.mac)
    b = (b
        .ip(src=src.ip, dst=dst.ip, ttl=ip_ttl)
        .tcp(
            src_port=src.port,
            dst_port=dst.port,
            seq=src.seq,
            ack=src.ack if (flags & TCP_ACK) else 0,
            flags=flags,
            window=src.window,
            options=options,
        )
    )
    if payload:
        b = b.payload(data=payload)
    return b.build()


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
            Available types (all from :mod:`packeteer.generate.stream_encap`):

            * :class:`~packeteer.generate.stream_encap.VLANEncap` — 802.1Q tag
            * :class:`~packeteer.generate.stream_encap.QinQEncap` — double 802.1Q tags
            * :class:`~packeteer.generate.stream_encap.MPLSEncap` — MPLS label stack
            * :class:`~packeteer.generate.stream_encap.PPPoEEncap` — PPPoE session frame
            * :class:`~packeteer.generate.stream_encap.GREEncap` — GRE tunnel
            * :class:`~packeteer.generate.stream_encap.EtherIPEncap` — EtherIP tunnel
            * :class:`~packeteer.generate.stream_encap.IPIPEncap` — IP-in-IP tunnel

        config: Optional :class:`TCPStreamConfig` supplying timing, anomaly
            injection, and per-packet hook settings.  All fields default to
            their *TCPStreamConfig* defaults when ``None``.

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
    packet_hooks = config.packet_hooks
    base_time = config.base_time if config.base_time is not None else time.time()

    gap_usec = int(inter_packet_gap * 1_000_000)
    jitter_usec = int(gap_jitter * 1_000_000)
    base_usec = int(base_time * 1_000_000)

    client = _TCPEndpoint(
        ip=client_ip, port=client_port, mac=client_mac,
        seq=random.randint(0, _WRAP - 1) if client_isn is None else client_isn,
        ack=0,
        window=window,
    )
    server = _TCPEndpoint(
        ip=server_ip, port=server_port, mac=server_mac,
        seq=random.randint(0, _WRAP - 1) if server_isn is None else server_isn,
        ack=0,
        window=window,
    )

    sizes = _payload_sizes(
        num_data_packets, min_payload, max_payload,
        payload_distribution, payload_sizes,
    )

    packets: list[TCPStreamPacket] = []
    global_index = 0

    def emit(
        src: _TCPEndpoint,
        dst: _TCPEndpoint,
        flags: int,
        payload: bytes,
        direction: str,
        label: str,
        options: TCPOptions | None = None,
    ) -> None:
        nonlocal global_index

        seq_before = src.seq
        ack_before = src.ack

        raw = _build_packet(src, dst, flags, payload, include_ethernet, ip_ttl, options, encap)
        _advance_seq(src, flags, len(payload))
        dst.ack = src.seq

        delay_usec = random.randint(0, jitter_usec) if jitter_usec else 0
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

        if packet_loss_probability and random.random() < packet_loss_probability:
            pkt = None

        if packet_hooks:
            for hook in packet_hooks:
                if pkt is None:
                    break
                pkt = hook(pkt, global_index)

        global_index += 1
        if pkt is not None:
            packets.append(pkt)

    # ── Three-way handshake ───────────────────────────────────────────────────
    emit(client, server, TCP_SYN,           b"", "c2s", "SYN",     options=client_options)
    emit(server, client, TCP_SYN | TCP_ACK, b"", "s2c", "SYN-ACK", options=server_options)
    emit(client, server, TCP_ACK,           b"", "c2s", "ACK")

    # ── Data transfer (client → server, server ACKs each packet) ────────────
    # Pre-tile the default payload once across the entire transfer so that
    # consecutive packets carry a continuous byte stream rather than each
    # packet independently restarting from the beginning of the file.
    payload_data = _repeat_payload(sum(sizes))
    payload_offset = 0
    for i, size in enumerate(sizes):
        flags = TCP_ACK | (TCP_PSH if random.random() < psh_probability else 0)
        chunk = payload_data[payload_offset:payload_offset + size]
        emit(client, server, flags, chunk, "c2s", f"DATA[{i}]")
        emit(server, client, TCP_ACK, b"", "s2c", f"ACK[{i}]")
        payload_offset += size

    # ── Four-way teardown ─────────────────────────────────────────────────────
    emit(client, server, TCP_FIN | TCP_ACK, b"", "c2s", "FIN-ACK")
    emit(server, client, TCP_ACK,           b"", "s2c", "ACK")
    emit(server, client, TCP_FIN | TCP_ACK, b"", "s2c", "FIN-ACK")
    emit(client, server, TCP_ACK,           b"", "c2s", "ACK")

    # ── Server RST ───────────────────────────────────────────────────────────
    if server_rst_probability and random.random() < server_rst_probability:
        # Choose a split point: the last normally-ACKed data packet index.
        # Need at least one normal exchange, so k is in [0, n-1).
        data_pkts = [p for p in packets if p.label.startswith("DATA[")]
        if len(data_pkts) >= 2:
            k = random.randint(0, len(data_pkts) - 2)
            split_label = data_pkts[k].label   # e.g. "DATA[3]"
            split_idx   = split_label[5:-1]    # "3"

            # Find the last normal ACK (ACK[k]) to get server seq/ack state
            ack_k = next((p for p in packets if p.label == f"ACK[{split_idx}]"), None)

            # Remove ACKs after the split point and the entire four-way teardown.
            # The handshake ACK (label "ACK", direction "c2s") must be kept;
            # teardown ACKs and FIN-ACKs all come after the first DATA packet.
            first_data_usec = _pkt_usec(data_pkts[0])

            def _keep(p: TCPStreamPacket) -> bool:
                if p.label.startswith("ACK["):
                    return int(p.label[4:-1]) <= k
                if p.label == "FIN-ACK":
                    return False
                return not (p.label == "ACK" and _pkt_usec(p) > first_data_usec)

            packets = [p for p in packets if _keep(p)]

            # Build RST packet: server → client
            # Use ACK[k] fields to reconstruct server state, or fallback to SYN-ACK
            ref = ack_k or next(p for p in packets if p.label == "SYN-ACK")
            rst_src = _TCPEndpoint(
                ip=server_ip, port=server_port, mac=server_mac,
                seq=ref.seq, ack=ref.ack, window=window,
            )
            rst_dst = _TCPEndpoint(
                ip=client_ip, port=client_port, mac=client_mac,
                seq=0, ack=0, window=window,
            )
            # RST is sent by the server at the same moment DATA[k+1] is sent.
            # The client learns about the RST after rst_propagation_delay.
            next_data = data_pkts[k + 1]
            rst_send_usec = next_data.ts_sec * 1_000_000 + next_data.ts_usec
            rst_delay_usec = int(rst_propagation_delay * 1_000_000)
            client_learns_rst_usec = rst_send_usec + rst_delay_usec

            # Remove DATA packets the client sends after it receives the RST,
            # and any server packets (ACKs from server after split already gone).
            packets = [
                p for p in packets
                if not (p.label.startswith("DATA[") and _pkt_usec(p) > client_learns_rst_usec)
            ]

            used_ts_rst: set[int] = {_pkt_usec(p) for p in packets}
            rst_sec, rst_usec_part = divmod(
                _alloc_usec(rst_send_usec, used_ts_rst), 1_000_000
            )
            rst_raw = _build_packet(rst_src, rst_dst, TCP_RST | TCP_ACK, b"",
                                    include_ethernet, ip_ttl, None, encap)
            packets.append(TCPStreamPacket(
                raw=rst_raw,
                ts_sec=rst_sec,
                ts_usec=rst_usec_part,
                direction="s2c",
                flags=TCP_RST | TCP_ACK,
                seq=ref.seq,
                ack=ref.ack,
                payload_len=0,
                label="RST",
            ))

    rto_usec = int(retransmission_timeout * 1_000_000)

    # ── Spurious retransmissions ──────────────────────────────────────────────
    if retransmission_probability:
        retransmits: list[TCPStreamPacket] = []
        used_ts: set[int] = {_pkt_usec(p) for p in packets}
        for pkt in packets:
            if not pkt.label.startswith("DATA["):
                continue
            if random.random() >= retransmission_probability:
                continue
            i = pkt.label[5:-1]  # extract index from "DATA[i]"
            delay_usec = random.randint(0, jitter_usec) if jitter_usec else 0
            rt_sec, rt_usec_part = divmod(
                _alloc_usec(_pkt_usec(pkt) + rto_usec + delay_usec, used_ts),
                1_000_000,
            )
            retransmits.append(replace(pkt, ts_sec=rt_sec, ts_usec=rt_usec_part,
                                       label=f"RETRANS[{i}]"))
        packets.extend(retransmits)

    # ── Payload corruption ────────────────────────────────────────────────────
    if payload_corruption_probability:
        additions: list[TCPStreamPacket] = []
        # Build an index of packets by label for O(1) lookup of both packet and position
        by_label: dict[str, int] = {p.label: idx for idx, p in enumerate(packets)}
        used_ts = {_pkt_usec(p) for p in packets}
        for idx, pkt in enumerate(packets):
            if not pkt.label.startswith("DATA["):
                continue
            if random.random() >= payload_corruption_probability:
                continue
            i = pkt.label[5:-1]  # extract index from "DATA[i]"

            # 1. Corrupt: flip the last byte of the payload in the raw frame
            raw_corrupt = bytearray(pkt.raw)
            raw_corrupt[-1] ^= 0xFF
            packets[idx] = replace(pkt, raw=bytes(raw_corrupt), label=f"CORRUPT[{i}]")

            # 2. Retransmit: clean copy of original, timestamped after RTO
            delay_usec = random.randint(0, jitter_usec) if jitter_usec else 0
            rt_usec = _alloc_usec(_pkt_usec(pkt) + rto_usec + delay_usec, used_ts)
            rt_sec, rt_usec_part = divmod(rt_usec, 1_000_000)
            additions.append(replace(pkt, ts_sec=rt_sec, ts_usec=rt_usec_part,
                                     label=f"RETRANS[{i}]"))

            # 3. Shift the server ACK to follow the retransmit
            ack_label = f"ACK[{i}]"
            if ack_label in by_label:
                ack_sec, ack_usec_part = divmod(
                    _alloc_usec(rt_usec + gap_usec, used_ts), 1_000_000
                )
                ack_idx = by_label[ack_label]
                packets[ack_idx] = replace(packets[ack_idx],
                                           ts_sec=ack_sec, ts_usec=ack_usec_part)
        packets.extend(additions)

    # ── Stray packet injection (TCP hijacking simulation) ─────────────────────
    if stray_packet_count:
        data_pkts = [p for p in packets if p.label.startswith("DATA[")
                     or p.label.startswith("CORRUPT[")]
        if data_pkts:
            used_ts = {_pkt_usec(p) for p in packets}

            # Sorted view used to resolve the timing window (Option B).
            # Built once; stray packets added later do not affect these bounds.
            sorted_pkts: list[TCPStreamPacket] = []
            ts_index: dict[int, int] = {}
            if stray_timing_window is not None:
                sorted_pkts = sorted(packets, key=lambda p: (p.ts_sec, p.ts_usec))
                ts_index = {_pkt_usec(p): i for i, p in enumerate(sorted_pkts)}

            default_ts_lo = min(_pkt_usec(p) for p in data_pkts)
            default_ts_hi = max(_pkt_usec(p) for p in data_pkts)

            strays: list[TCPStreamPacket] = []
            for n in range(stray_packet_count):
                # Steal seq/ack from a randomly chosen data packet
                ref = random.choice(data_pkts)
                stray_src = _TCPEndpoint(
                    ip=client_ip, port=client_port, mac=client_mac,
                    seq=ref.seq, ack=ref.ack, window=window,
                )
                stray_dst = _TCPEndpoint(
                    ip=server_ip, port=server_port, mac=server_mac,
                    seq=0, ack=0, window=window,
                )

                if stray_timing_window is not None:
                    ref_idx = ts_index[_pkt_usec(ref)]
                    lo_idx = max(0, ref_idx - stray_timing_window)
                    hi_idx = min(len(sorted_pkts) - 1, ref_idx + stray_timing_window)
                    ts_lo = _pkt_usec(sorted_pkts[lo_idx])
                    ts_hi = _pkt_usec(sorted_pkts[hi_idx])
                else:
                    ts_lo = default_ts_lo
                    ts_hi = default_ts_hi

                payload = b'x' * random.randint(min_payload, max_payload)
                raw = _build_packet(stray_src, stray_dst, TCP_ACK | TCP_PSH,
                                    payload, include_ethernet, ip_ttl, None, encap)
                ts_sec, ts_usec = divmod(
                    _alloc_usec(random.randint(ts_lo, ts_hi), used_ts), 1_000_000
                )
                strays.append(TCPStreamPacket(
                    raw=raw,
                    ts_sec=ts_sec,
                    ts_usec=ts_usec,
                    direction="c2s",
                    flags=TCP_ACK | TCP_PSH,
                    seq=ref.seq,
                    ack=ref.ack,
                    payload_len=len(payload),
                    label=f"STRAY[{n}]",
                ))
            packets.extend(strays)

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
