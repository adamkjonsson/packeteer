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
class _TCPEndpoint:
    """Mutable per-side connection state (internal only)."""

    ip: str
    port: int
    mac: str
    seq: int    # next sequence number to send
    ack: int    # next sequence number expected from the peer
    window: int = 65535


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
