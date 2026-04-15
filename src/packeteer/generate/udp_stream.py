"""UDP stream generation.

This module generates a sequence of UDP datagrams representing a unidirectional
client-to-server flow — for example a DNS, TFTP, or application-layer session
before a full request/response model is layered on top.

Unlike TCP, UDP has no connection state: there is no handshake, no
acknowledgement, and no teardown.  The stream is simply *num_data_packets*
datagrams with realistic inter-packet timestamps.

The payload is drawn from the same continuous ``default_payload.txt`` source
as the TCP stream generator: the file is tiled once across the total required
bytes, then sliced per datagram, so adjacent datagrams carry a rolling window
of the same byte sequence rather than each restarting at offset 0.

Typical usage::

    from packeteer.generate.udp_stream import generate_udp_stream
    from packeteer.pcap import write_pcap

    stream = generate_udp_stream(
        client_ip="10.0.0.1",
        server_ip="10.0.0.2",
        server_port=53,
        num_data_packets=5,
    )
    write_pcap(stream.to_pcap_tuples(), path="udp_flow.pcap")
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass

from .builder import PacketBuilder
from ._stream_common import (
    _alloc_usec, _fragment_ip_raw, _payload_sizes, _pkt_usec, _repeat_payload,
)
from .stream_encap import (EncapSpec, StreamEncap,  # noqa: F401  (StreamEncap needed for Sphinx type resolution)
                           _apply_encap, _encap_ip_start)


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class UDPStreamPacket:
    """One packet in a generated UDP stream.

    Attributes:
        raw: Fully-assembled packet bytes, ready for pcap output.
        ts_sec: Packet timestamp — whole seconds part.
        ts_usec: Packet timestamp — microseconds part.
        direction: ``"c2s"`` (client→server) or ``"s2c"`` (server→client).
        payload_len: UDP payload length in bytes.
        label: Human-readable label (e.g. ``"DATA[0]"``).
    """
    raw:         bytes
    ts_sec:      int
    ts_usec:     int
    direction:   str
    payload_len: int
    label:       str


@dataclass
class UDPStream:
    """A complete generated UDP stream.

    Attributes:
        packets: Ordered list of all datagrams in the stream.
    """
    packets: list[UDPStreamPacket]

    def to_pcap_tuples(self) -> list[tuple[bytes, int, int]]:
        """Return packets as ``(raw, ts_sec, ts_usec)`` tuples for pcap output."""
        return [(p.raw, p.ts_sec, p.ts_usec) for p in self.packets]

    def client_packets(self) -> list[UDPStreamPacket]:
        """Return only client→server packets."""
        return [p for p in self.packets if p.direction == "c2s"]

    def server_packets(self) -> list[UDPStreamPacket]:
        """Return only server→client packets."""
        return [p for p in self.packets if p.direction == "s2c"]


# ── Internal helpers ──────────────────────────────────────────────────────────


def _build_udp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    src_mac: str,
    dst_mac: str,
    payload: bytes,
    include_ethernet: bool,
    ip_ttl: int,
    encap: EncapSpec = None,
) -> bytes:
    b = PacketBuilder()
    if include_ethernet:
        b = b.ethernet(src_mac=src_mac, dst_mac=dst_mac)
    b = _apply_encap(b, encap, src_mac, dst_mac)
    return (b
        .ip(src=src_ip, dst=dst_ip, ttl=ip_ttl)
        .udp(src_port=src_port, dst_port=dst_port)
        .payload(data=payload)
        .build()
    )


def _fragment_udp_pkt(
    pkt: UDPStreamPacket,
    mtu: int,
    include_ethernet: bool,
    used_ts: set[int],
    encap: EncapSpec = None,
) -> list[UDPStreamPacket]:
    """Split *pkt* into IP fragments if its IP-layer size exceeds *mtu*."""
    ip_start = _encap_ip_start(encap, include_ethernet)
    frag_raws = _fragment_ip_raw(pkt.raw, ip_start, mtu, encap)
    if frag_raws is None:
        return [pkt]

    orig_usec = _pkt_usec(pkt)
    used_ts.discard(orig_usec)
    result: list[UDPStreamPacket] = []
    for i, frag_raw in enumerate(frag_raws):
        ts = _alloc_usec(orig_usec + i, used_ts)
        result.append(UDPStreamPacket(
            raw=frag_raw,
            ts_sec=ts // 1_000_000,
            ts_usec=ts % 1_000_000,
            direction=pkt.direction,
            payload_len=pkt.payload_len,
            label=f"FRAG[{pkt.label}][{i}]",
        ))
    return result


# ── Public generator ──────────────────────────────────────────────────────────

def generate_udp_stream(
    *,
    client_ip: str,
    server_ip: str,
    client_port: int = 54321,
    server_port: int = 80,
    client_mac: str = "00:00:00:00:00:01",
    server_mac: str = "00:00:00:00:00:02",
    num_data_packets: int = 10,
    payload_sizes: list[int] | None = None,
    min_payload: int = 20,
    max_payload: int = 512,
    payload_distribution: str = "uniform",
    include_ethernet: bool = True,
    ip_ttl: int = 64,
    base_time: int | None = None,
    inter_packet_gap: float = 0.001,
    gap_jitter: float = 0.0,
    mtu: int | None = None,
    encap: EncapSpec = None,
) -> UDPStream:
    """Generate a sequence of UDP datagrams from client to server.

    Args:
        client_ip: Client IP address (IPv4 or IPv6).
        server_ip: Server IP address (same family as *client_ip*).
        client_port: Client source port.  Defaults to ``54321``.
        server_port: Server destination port.  Defaults to ``80``.
        client_mac: Client MAC address.  Ignored when *include_ethernet* is
            ``False``.
        server_mac: Server MAC address.  Ignored when *include_ethernet* is
            ``False``.
        num_data_packets: Number of UDP datagrams to generate.
        payload_sizes: Explicit list of *num_data_packets* payload sizes.
            When provided, *min_payload*, *max_payload*, and
            *payload_distribution* are ignored.
        min_payload: Minimum payload size in bytes.  Defaults to ``20``.
        max_payload: Maximum payload size in bytes.  Defaults to ``512``.
        payload_distribution: ``"uniform"`` (default), ``"bimodal"``, or
            ``"fixed"`` (all datagrams carry *max_payload* bytes).
        include_ethernet: When ``True`` (default) each packet includes an
            Ethernet II header.
        ip_ttl: IP TTL / IPv6 Hop Limit.  Defaults to ``64``.
        base_time: Start timestamp (whole seconds).  Defaults to
            ``int(time.time())``.
        inter_packet_gap: Gap between consecutive packets in seconds.
            Defaults to ``0.001`` (1 ms).
        gap_jitter: Maximum additional random delay per gap in seconds.
            Each gap is drawn from ``[inter_packet_gap,
            inter_packet_gap + gap_jitter]`` and packets are re-sorted by
            timestamp.  Defaults to ``0.0`` (no jitter).
        mtu: When set, fragment packets whose IP-layer size exceeds
            this value, simulating a middlebox with a lower MTU.
        encap: One or more encapsulation layers to wrap every packet in.
            Accepts a single descriptor, a list of descriptors (applied
            outermost first), or ``None`` (default, no encapsulation).
            See :mod:`packeteer.generate.stream_encap` for available types
            (VLANEncap, QinQEncap, MPLSEncap, PPPoEEncap, GREEncap,
            EtherIPEncap, IPIPEncap) and combination rules.

    Returns:
        A :class:`UDPStream` whose :attr:`~UDPStream.packets` list contains
        the assembled datagrams in timestamp order.

    Example::

        stream = generate_udp_stream(
            client_ip="10.0.0.1",
            server_ip="10.0.0.2",
            server_port=53,
            num_data_packets=5,
        )
        write_pcap(stream.to_pcap_tuples(), path="dns_flow.pcap")
    """
    if base_time is None:
        base_time = int(time.time())

    sizes = _payload_sizes(
        num_data_packets, min_payload, max_payload,
        payload_distribution, payload_sizes,
    )

    # Continuous payload: tile default_payload.txt across all datagrams
    payload_data = _repeat_payload(sum(sizes))
    offset = 0

    packets: list[UDPStreamPacket] = []
    used_ts: set[int] = set()
    usec_cursor = base_time * 1_000_000

    for i, size in enumerate(sizes):
        gap_usec = int((inter_packet_gap + random.uniform(0, gap_jitter)) * 1_000_000)
        usec_cursor += gap_usec
        ts = _alloc_usec(usec_cursor, used_ts)

        chunk = payload_data[offset:offset + size]
        offset += size

        raw = _build_udp_packet(
            src_ip=client_ip, dst_ip=server_ip,
            src_port=client_port, dst_port=server_port,
            src_mac=client_mac, dst_mac=server_mac,
            payload=chunk,
            include_ethernet=include_ethernet,
            ip_ttl=ip_ttl,
            encap=encap,
        )
        packets.append(UDPStreamPacket(
            raw=raw,
            ts_sec=ts // 1_000_000,
            ts_usec=ts % 1_000_000,
            direction="c2s",
            payload_len=size,
            label=f"DATA[{i}]",
        ))

    # Re-sort if jitter was applied
    if gap_jitter > 0:
        packets.sort(key=lambda p: (p.ts_sec, p.ts_usec))

    # Middlebox fragmentation
    if mtu is not None:
        used_ts = {_pkt_usec(p) for p in packets}
        fragmented: list[UDPStreamPacket] = []
        for pkt in packets:
            fragmented.extend(_fragment_udp_pkt(pkt, mtu, include_ethernet, used_ts, encap))
        packets = fragmented
        packets.sort(key=lambda p: (p.ts_sec, p.ts_usec))

    return UDPStream(packets=packets)
