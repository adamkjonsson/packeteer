"""TCP stream generation.

This module generates a realistic sequence of packets representing a complete
TCP connection: three-way handshake, data transfer (client→server), and
four-way teardown.

Sequence and acknowledgement numbers are tracked correctly across both sides,
including 32-bit wrap-around.  Each packet is assembled via
:class:`~packet_generator.builder.PacketBuilder`, so all IP and TCP checksums
are computed automatically.

Typical usage::

    from packet_generator.stream import generate_tcp_stream
    from packet_generator import write_pcap

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
from pathlib import Path
from collections.abc import Callable

from .builder import PacketBuilder
from .tcp import TCPOptions, TCP_SYN, TCP_ACK, TCP_PSH, TCP_FIN, TCP_RST

_WRAP = 2 ** 32

_DEFAULT_PAYLOAD = (
    Path(__file__).with_name("default_payload.txt").read_bytes()
)


def _repeat_payload(size: int) -> bytes:
    """Return *size* bytes of the default payload, repeating as needed."""
    if size <= 0:
        return b""
    times, remainder = divmod(size, len(_DEFAULT_PAYLOAD))
    return _DEFAULT_PAYLOAD * times + _DEFAULT_PAYLOAD[:remainder]


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
        :func:`~packet_generator.write_pcap` and
        :func:`~packet_generator.write_pcapng`.
        """
        return [(p.raw, p.ts_sec, p.ts_usec) for p in self.packets]

    def client_packets(self) -> list[TCPStreamPacket]:
        """Return only client→server packets."""
        return [p for p in self.packets if p.direction == "c2s"]

    def server_packets(self) -> list[TCPStreamPacket]:
        """Return only server→client packets."""
        return [p for p in self.packets if p.direction == "s2c"]


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
) -> bytes:
    """Assemble one raw packet using PacketBuilder."""
    b = PacketBuilder()
    if include_ethernet:
        b = b.ethernet(src_mac=src.mac, dst_mac=dst.mac)
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


def _payload_sizes(
    n: int,
    min_payload: int,
    max_payload: int,
    distribution: str,
    explicit: list[int] | None,
) -> list[int]:
    """Return a list of *n* payload sizes according to the requested strategy."""
    if explicit is not None:
        if len(explicit) != n:
            raise ValueError(
                f"payload_sizes has {len(explicit)} entries but "
                f"num_data_packets={n}"
            )
        return list(explicit)

    if distribution == "fixed":
        return [max_payload] * n

    if distribution == "uniform":
        return [random.randint(min_payload, max_payload) for _ in range(n)]

    if distribution == "bimodal":
        # 70% small (near min), 30% large (near max) — approximates mixed
        # HTTP/TLS traffic where small control messages and bulk segments coexist.
        small_hi = min(min_payload + 100, max_payload)
        large_lo = max(max_payload - 100, min_payload)
        sizes = []
        for _ in range(n):
            if random.random() < 0.7:
                sizes.append(random.randint(min_payload, small_hi))
            else:
                sizes.append(random.randint(large_lo, max_payload))
        return sizes

    raise ValueError(
        f"Unknown payload_distribution {distribution!r}; "
        "choose 'uniform', 'bimodal', or 'fixed'"
    )


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
    payload_sizes: list[int] | None = None,
    min_payload: int = 40,
    max_payload: int = 1460,
    payload_distribution: str = "uniform",
    client_isn: int | None = None,
    server_isn: int | None = None,
    client_options: TCPOptions | None = None,
    server_options: TCPOptions | None = None,
    include_ethernet: bool = True,
    ip_ttl: int = 64,
    window: int = 65535,
    base_time: float | None = None,
    inter_packet_gap: float = 0.001,
    gap_jitter: float = 0.0,
    psh_probability: float = 0.5,
    packet_loss_probability: float = 0.0,
    retransmission_probability: float = 0.0,
    retransmission_timeout: float = 0.2,
    payload_corruption_probability: float = 0.0,
    server_rst_probability: float = 0.0,
    rst_propagation_delay: float = 0.0,
    packet_hooks: list[Callable[[TCPStreamPacket, int], TCPStreamPacket | None]] | None = None,
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
        payload_sizes: Explicit list of payload sizes, one per data packet.
            When provided, overrides *min_payload*, *max_payload*, and
            *payload_distribution*.  Must have exactly *num_data_packets*
            entries.
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
        client_options: TCP options encoded on the client SYN only (e.g. MSS,
            window scale, SACK permitted).  ``None`` means no options.
        server_options: TCP options encoded on the server SYN-ACK only.
        include_ethernet: When ``True`` (default) each packet starts with an
            Ethernet II header.  Set to ``False`` for raw-IP captures.
        ip_ttl: IP TTL / hop limit for all packets.  Defaults to ``64``.
        window: TCP receive-window size advertised by both endpoints.
        base_time: Unix timestamp for the first packet in seconds.  Defaults
            to the current time.
        inter_packet_gap: Seconds between consecutive packets.  Defaults to
            ``0.001`` (1 ms).
        gap_jitter: Maximum interception delay in seconds.  Packet *n* is
            sent at ``base_time + n * inter_packet_gap`` and assigned a
            capture timestamp of ``sent_time + uniform(0, gap_jitter)``.
            Because delays are independent, a later packet can overtake an
            earlier one; the final list is sorted by timestamp before being
            returned, matching what a real capture would show.
            Defaults to ``0.0`` (no jitter).
        psh_probability: Probability (0.0–1.0) that the PSH flag is set on
            each data segment.  Real TCP stacks set PSH to signal the receiver
            to flush its buffer, but not on every segment.  Defaults to
            ``0.5``.
        packet_loss_probability: Probability (0.0–1.0) that any individual
            packet is silently dropped from the capture, simulating packet
            loss on the wire.  Sequence and acknowledgement numbers are
            computed as if the packet was sent; only the capture record is
            omitted.  Defaults to ``0.0`` (no loss).
        retransmission_probability: Probability (0.0–1.0) that each data
            segment triggers a spurious retransmission.  A retransmission
            carries the same sequence number, flags, and payload as the
            original but is timestamped at the original send time plus
            *retransmission_timeout*.  Handshake and teardown packets are
            not affected.  Defaults to ``0.0`` (no retransmissions).
        retransmission_timeout: Seconds after the original send time at which
            the retransmission timer fires.  200 ms (the TCP minimum RTO) is
            a realistic starting point.  Defaults to ``0.2``.
        server_rst_probability: Probability (0.0–1.0) that the server
            application terminates mid-stream, causing the OS to send a TCP
            RST.  When triggered, a random split point *k* is chosen among
            the data packets; packets 0…k are exchanged normally with ACKs.
            The server sends ``RST`` at the same moment ``DATA[k+1]`` is
            sent.  The client learns about the RST after
            *rst_propagation_delay* seconds; during that window it keeps
            sending data.  Once the RST arrives all further client and server
            packets are suppressed and the normal four-way teardown is
            omitted.  Defaults to ``0.0`` (no RST).
        rst_propagation_delay: Seconds between the server sending the RST
            and the client receiving it.  During this window the client
            continues to send data.  Defaults to ``0.0`` (RST arrives
            immediately — client sends no extra packets).
        payload_corruption_probability: Probability (0.0–1.0) that each data
            segment's payload is corrupted in transit.  One byte at the end
            of the payload is XOR-flipped, invalidating the TCP checksum so
            the receiver drops the packet without sending an ACK.  The
            corrupted packet appears in the capture as ``CORRUPT[i]``; the
            client retransmits after *retransmission_timeout* as
            ``RETRANS[i]``; the existing ``ACK[i]`` timestamp is shifted to
            follow the retransmit.  Defaults to ``0.0`` (no corruption).
        packet_hooks: Optional list of callables applied to each packet after
            it is built.  Each hook has the signature::

                def hook(packet: TCPStreamPacket, index: int) -> TCPStreamPacket | None

            Hooks are called in order.  Returning ``None`` drops the packet
            from the stream.  This is the primary extensibility seam for
            future error and anomaly injection (e.g. packet drops, duplicates,
            checksum corruption, reordering).

    Returns:
        A :class:`TCPStream` containing all assembled packets in wire order.

    Raises:
        ValueError: If *payload_sizes* length does not match
            *num_data_packets*, or *payload_distribution* is unknown.
        OSError: If an IP address string is invalid.

    Example::

        from packet_generator.tcp_stream import generate_tcp_stream
        from packet_generator import write_pcap, TCPOptions

        stream = generate_tcp_stream(
            client_ip="10.0.0.1",
            server_ip="10.0.0.2",
            server_port=443,
            num_data_packets=50,
            payload_distribution="bimodal",
            client_options=TCPOptions(mss=1460, sack_permitted=True),
        )
        write_pcap(stream.to_pcap_tuples(), path="tls_session.pcap")
    """
    if base_time is None:
        base_time = time.time()

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

        raw = _build_packet(src, dst, flags, payload, include_ethernet, ip_ttl, options)
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
    for i, size in enumerate(sizes):
        flags = TCP_ACK | (TCP_PSH if random.random() < psh_probability else 0)
        emit(client, server, flags, _repeat_payload(size), "c2s", f"DATA[{i}]")
        emit(server, client, TCP_ACK, b"", "s2c", f"ACK[{i}]")

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
            first_data_usec = data_pkts[0].ts_sec * 1_000_000 + data_pkts[0].ts_usec

            def _keep(p: TCPStreamPacket) -> bool:
                ts = p.ts_sec * 1_000_000 + p.ts_usec
                if p.label.startswith("ACK["):
                    return int(p.label[4:-1]) <= k
                if p.label in ("FIN-ACK",):
                    return False
                if p.label == "ACK" and ts > first_data_usec:
                    return False   # teardown ACKs, not the handshake ACK
                return True

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
                if not (p.label.startswith("DATA[")
                        and (p.ts_sec * 1_000_000 + p.ts_usec) > client_learns_rst_usec)
            ]

            used_ts_rst: set[int] = {p.ts_sec * 1_000_000 + p.ts_usec for p in packets}
            rst_usec = rst_send_usec
            while rst_usec in used_ts_rst:
                rst_usec += 1
            rst_sec, rst_usec_part = divmod(rst_usec, 1_000_000)
            rst_raw = _build_packet(rst_src, rst_dst, TCP_RST | TCP_ACK, b"",
                                    include_ethernet, ip_ttl, None)
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

    # ── Spurious retransmissions ──────────────────────────────────────────────
    if retransmission_probability:
        rto_usec = int(retransmission_timeout * 1_000_000)
        retransmits: list[TCPStreamPacket] = []
        used_ts: set[int] = {p.ts_sec * 1_000_000 + p.ts_usec for p in packets}
        for pkt in packets:
            if not pkt.label.startswith("DATA["):
                continue
            if random.random() >= retransmission_probability:
                continue
            i = pkt.label[5:-1]  # extract index from "DATA[i]"
            orig_usec = pkt.ts_sec * 1_000_000 + pkt.ts_usec
            delay_usec = random.randint(0, jitter_usec) if jitter_usec else 0
            rt_usec = orig_usec + rto_usec + delay_usec
            while rt_usec in used_ts:
                rt_usec += 1
            used_ts.add(rt_usec)
            rt_sec, rt_usec_part = divmod(rt_usec, 1_000_000)
            retransmits.append(replace(
                pkt,
                ts_sec=rt_sec,
                ts_usec=rt_usec_part,
                label=f"RETRANS[{i}]",
            ))
        packets.extend(retransmits)

    # ── Payload corruption ────────────────────────────────────────────────────
    if payload_corruption_probability:
        rto_usec = int(retransmission_timeout * 1_000_000)
        additions: list[TCPStreamPacket] = []
        # Build an index of packets by label for O(1) ACK lookup
        by_label: dict[str, TCPStreamPacket] = {p.label: p for p in packets}
        used_ts: set[int] = {p.ts_sec * 1_000_000 + p.ts_usec for p in packets}
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
            orig_usec = pkt.ts_sec * 1_000_000 + pkt.ts_usec
            delay_usec = random.randint(0, jitter_usec) if jitter_usec else 0
            rt_usec = orig_usec + rto_usec + delay_usec
            while rt_usec in used_ts:
                rt_usec += 1
            used_ts.add(rt_usec)
            rt_sec, rt_usec_part = divmod(rt_usec, 1_000_000)
            additions.append(replace(pkt, ts_sec=rt_sec, ts_usec=rt_usec_part,
                                     label=f"RETRANS[{i}]"))

            # 3. Shift the server ACK to follow the retransmit
            ack_label = f"ACK[{i}]"
            if ack_label in by_label:
                ack_pkt = by_label[ack_label]
                ack_usec = rt_usec + gap_usec
                while ack_usec in used_ts:
                    ack_usec += 1
                used_ts.add(ack_usec)
                ack_sec, ack_usec_part = divmod(ack_usec, 1_000_000)
                ack_idx = packets.index(ack_pkt)
                packets[ack_idx] = replace(ack_pkt, ts_sec=ack_sec,
                                           ts_usec=ack_usec_part)
        packets.extend(additions)

    packets.sort(key=lambda p: (p.ts_sec, p.ts_usec))
    return TCPStream(packets=packets)
