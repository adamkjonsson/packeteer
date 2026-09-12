"""Shared helpers used by all three stream generators (TCP, UDP, SCTP).

Also holds the TCP endpoint state and packet assembly used by both emit
paths -- :func:`~packeteer.generate.tcp_stream.generate_tcp_stream` and
:class:`~packeteer.generate.session.TCPSession` -- and by the impairment
passes in :mod:`packeteer.generate.impairments`, which need to build RST
and stray packets of their own.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from random import Random

from .builder import PacketBuilder
from .fragmentation import fragment_ipv4, fragment_ipv6
from .ip import IPHeader
from .ipv6 import IPv6Header

#from .stream_encap import EncapSpec, _encap_ip_start, _fix_encap_prefix
from .stream_encap import EncapSpec, _apply_encap, _fix_encap_prefix
from .tcp import TCP_ACK, TCP_FIN, TCP_SYN, TCPOptions

_WRAP = 2 ** 32

#: Bytes a Timestamps option adds to every segment: NOP, NOP, then the
#: 10-byte option (RFC 7323 A.2).  A sender's usable segment is smaller by
#: this much than the MSS its peer advertised.
TCP_TIMESTAMPS_OVERHEAD: int = 12

_DEFAULT_PAYLOAD = Path(__file__).with_name("default_payload.txt").read_bytes()


def _repeat_payload(size: int) -> bytes:
    """Return *size* bytes of the default payload, tiling as needed."""
    if size <= 0:
        return b""
    times, remainder = divmod(size, len(_DEFAULT_PAYLOAD))
    return _DEFAULT_PAYLOAD * times + _DEFAULT_PAYLOAD[:remainder]


def _alloc_usec(start: int, used: set[int]) -> int:
    """Return the smallest integer >= *start* not in *used*, and add it."""
    ts = start
    while ts in used:
        ts += 1
    used.add(ts)
    return ts


def _pkt_usec(pkt: object) -> int:
    """Return the packet timestamp as a single microsecond integer."""
    return pkt.ts_sec * 1_000_000 + pkt.ts_usec  # type: ignore[attr-defined]


# ── TCP packet assembly ──────────────────────────────────────────────────────

@dataclass
class _TimestampClock:
    """One direction's TSval clock (RFC 7323 §3): a 1 ms tick from a start.

    TSval is the sender's notion of time, not the capture's, but a capture is
    the only timeline a generator has — so the value is the packet's own
    timestamp, in milliseconds since the clock's origin, offset by a start
    chosen the way an initial sequence number is.

    Attributes:
        start: TSval at the origin.
        origin_usec: Timestamp the clock reads *start* at.

    """

    start: int
    origin_usec: int

    def at(self, usec: int) -> int:
        """Return the TSval for a segment timestamped *usec*."""
        return (self.start + (usec - self.origin_usec) // 1000) % _WRAP


def _clocks_from(packets: list) -> dict[str, _TimestampClock] | None:
    """Recover both directions' clocks from a connection's handshake.

    A connection that negotiated timestamps has a TSval on its SYN and its
    SYN-ACK, and each is that side's clock reading at that moment — which is
    everything a later pass needs to stamp a packet it builds or rebuilds,
    without the generator having to hand its clocks across.  ``None`` when
    the connection did not negotiate them, in which case a pass copies
    segments verbatim as it always did.

    Args:
        packets: One connection's packets, any order.

    Returns:
        ``{"c2s": clock, "s2c": clock}``, or ``None``.

    """
    syn = synack = None
    for pkt in packets:
        if pkt.flags & TCP_SYN:
            if pkt.flags & TCP_ACK:
                synack = synack or pkt
            else:
                syn = syn or pkt
    if syn is None or synack is None:
        return None
    if syn.timestamps is None or synack.timestamps is None:
        return None
    return {
        "c2s": _TimestampClock(syn.timestamps[0], _pkt_usec(syn)),
        "s2c": _TimestampClock(synack.timestamps[0], _pkt_usec(synack)),
    }


def _tsecr_at(packets: list, direction: str, usec: int) -> int:
    """Return the TSval a *direction* segment sent at *usec* should echo.

    The most recent TSval that arrived from the other side by then (RFC 7323
    §4.3's ``TS.Recent``).  Lost segments are not in *packets*, so a value a
    receiver never saw is never echoed.

    Args:
        packets: The connection's packets.
        direction: ``"c2s"`` or ``"s2c"`` — the segment being built.
        usec: Its timestamp.

    Returns:
        The TSval to put in TSecr, or ``0`` when nothing has arrived yet.

    """
    latest = None
    for pkt in packets:
        if pkt.direction == direction or pkt.timestamps is None:
            continue
        if _pkt_usec(pkt) <= usec and (latest is None or _pkt_usec(pkt) > _pkt_usec(latest)):
            latest = pkt
    return latest.timestamps[0] if latest is not None else 0


@dataclass
class _TCPEndpoint:
    """Mutable per-side connection state (internal only).

    ``ts_clock`` is this side's TSval clock, set when its SYN advertised
    timestamps; ``ts_recent`` is the latest TSval that arrived from the peer
    in order — what this side echoes — and ``ts_last`` the last TSval it
    sent, so the clock never appears to run backwards under capture jitter.
    """

    ip: str
    port: int
    mac: str
    seq: int    # next sequence number to send
    ack: int    # next sequence number expected from the peer
    window: int = 65535
    ts_clock: _TimestampClock | None = None
    ts_recent: int = 0
    ts_last: int | None = None

    def tsval_at(self, usec: int) -> int:
        """Return, and remember, the TSval for a segment sent at *usec*."""
        assert self.ts_clock is not None
        value = self.ts_clock.at(usec)
        # Capture jitter can timestamp a later segment earlier than the one
        # before it; a host's clock does not go backwards, so nor does this.
        if self.ts_last is not None and (value - self.ts_last) % _WRAP > _WRAP // 2:
            value = self.ts_last
        self.ts_last = value
        return value


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


def _tcp_payload(raw: bytes, include_ethernet: bool) -> bytes:
    """Return the TCP payload carried by *raw*, at any encapsulation depth.

    Read back through the parser rather than sliced off the end: a frame
    below the 60-byte Ethernet minimum is padded after the payload, and
    ``raw[-payload_len:]`` would hand back the padding.
    """
    from packeteer.parse import parse_packet
    from packeteer.pcap import LINKTYPE_ETHERNET, LINKTYPE_RAW

    pkt = parse_packet(
        raw, link_type=LINKTYPE_ETHERNET if include_ethernet else LINKTYPE_RAW,
        decode_app=False,
    )
    while pkt.tunneled is not None:
        pkt = pkt.tunneled
    return pkt.payload


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


def _payload_sizes(
    n: int,
    min_payload: int,
    max_payload: int,
    distribution: str,
    explicit: list[int] | None,
    rng: Random,
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
        return [rng.randint(min_payload, max_payload) for _ in range(n)]

    if distribution == "bimodal":
        # 70% small (near min), 30% large (near max) — approximates mixed
        # HTTP/TLS traffic where small control messages and bulk segments coexist.
        small_hi = min(min_payload + 100, max_payload)
        large_lo = max(max_payload - 100, min_payload)
        sizes = []
        for _ in range(n):
            if rng.random() < 0.7:
                sizes.append(rng.randint(min_payload, small_hi))
            else:
                sizes.append(rng.randint(large_lo, max_payload))
        return sizes

    raise ValueError(
        f"Unknown payload_distribution {distribution!r}; "
        "choose 'uniform', 'bimodal', or 'fixed'"
    )


def _fragment_ip_raw(
    raw: bytes,
    ip_start: int,
    mtu: int,
    encap: EncapSpec,
) -> list[bytes] | None:
    """Fragment the IP datagram in *raw* to fit within *mtu* bytes.

    *ip_start* is the byte offset of the IP header within *raw*.  Returns a
    list of complete fragment byte-strings (each prefixed by the bytes before
    the IP header, with PPPoE length patched if present), or ``None`` if the
    packet already fits within *mtu* or the IP version is not 4 or 6.
    """
    if len(raw) - ip_start <= mtu:
        return None

    ip_version = raw[ip_start] >> 4
    prefix = raw[:ip_start]

    if ip_version == 4:
        (_, tos, _, ident, flags_frag, ttl, proto, _,
         src_bytes, dst_bytes) = struct.unpack('!BBHHHBBH4s4s', raw[ip_start:ip_start + 20])
        ip_hdr = IPHeader(
            src=socket.inet_ntoa(src_bytes), dst=socket.inet_ntoa(dst_bytes),
            protocol=proto, ttl=ttl, tos=tos, identification=ident,
            flags=(flags_frag >> 13) & 0x7, fragment_offset=flags_frag & 0x1FFF,
        )
        inner_frags = fragment_ipv4(ip_hdr, raw[ip_start + 20:], mtu, eth_header=None)

    elif ip_version == 6:
        version_tc_fl = struct.unpack('!I', raw[ip_start:ip_start + 4])[0]
        _, next_header, hop_limit = struct.unpack('!HBB', raw[ip_start + 4:ip_start + 8])
        ip_hdr = IPv6Header(
            src=socket.inet_ntop(socket.AF_INET6, raw[ip_start + 8:ip_start + 24]),
            dst=socket.inet_ntop(socket.AF_INET6, raw[ip_start + 24:ip_start + 40]),
            next_header=next_header, hop_limit=hop_limit,
            traffic_class=(version_tc_fl >> 20) & 0xFF,
            flow_label=version_tc_fl & 0xFFFFF,
        )
        inner_frags = fragment_ipv6(ip_hdr, raw[ip_start + 40:], mtu, eth_header=None)

    else:
        return None

    return [_fix_encap_prefix(prefix, encap, len(f)) + f for f in inner_frags]
