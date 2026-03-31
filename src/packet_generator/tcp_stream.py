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

import os
import random
import time
from collections.abc import Callable
from dataclasses import dataclass

from .builder import PacketBuilder
from .tcp import TCPOptions, TCP_SYN, TCP_ACK, TCP_PSH, TCP_FIN

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
    packet_hooks: list[Callable[[TCPStreamPacket, int], TCPStreamPacket | None]] | None = None,
) -> TCPStream:
    """Generate a complete TCP stream as a sequence of :class:`TCPStreamPacket` objects.

    Produces a realistic exchange in this order:

    1. Three-way handshake: SYN → SYN-ACK → ACK
    2. Data transfer: *num_data_packets* PSH+ACK segments (client→server)
    3. Server acknowledgement: one ACK
    4. Four-way teardown: FIN-ACK → ACK → FIN-ACK → ACK

    Total packet count is always ``num_data_packets + 8``.

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

        from packet_generator.stream import generate_tcp_stream
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
    ts_usec_total = int(base_time * 1_000_000)

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
        nonlocal ts_usec_total, global_index

        seq_before = src.seq
        ack_before = src.ack

        raw = _build_packet(src, dst, flags, payload, include_ethernet, ip_ttl, options)
        _advance_seq(src, flags, len(payload))
        dst.ack = src.seq

        ts_sec, ts_usec = divmod(ts_usec_total, 1_000_000)
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

        ts_usec_total += gap_usec

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

    # ── Data transfer (client → server) ───────────────────────────────────────
    for i, size in enumerate(sizes):
        emit(client, server, TCP_PSH | TCP_ACK, os.urandom(size), "c2s", f"DATA[{i}]")

    # ── Server acknowledges all received data ──────────────────────────────────
    emit(server, client, TCP_ACK, b"", "s2c", "ACK")

    # ── Four-way teardown ─────────────────────────────────────────────────────
    emit(client, server, TCP_FIN | TCP_ACK, b"", "c2s", "FIN-ACK")
    emit(server, client, TCP_ACK,           b"", "s2c", "ACK")
    emit(server, client, TCP_FIN | TCP_ACK, b"", "s2c", "FIN-ACK")
    emit(client, server, TCP_ACK,           b"", "c2s", "ACK")

    return TCPStream(packets=packets)
