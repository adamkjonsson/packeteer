"""IP fragmentation — RFC 791 (IPv4) and RFC 8200 §4.5 (IPv6).

IPv4 fragmentation splits the transport-layer payload across multiple
datagrams using the standard Flags / Fragment Offset header fields.

IPv6 fragmentation uses the Fragment Extension Header (next header = 44).
The extension header carries a 13-bit offset, the M (More Fragments) flag,
and a 32-bit identification — it is inserted between the IPv6 base header
and each fragment's data chunk.

Fragment Extension Header layout (8 bytes, RFC 8200 §4.5)::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Next Header  |   Reserved    |Fragment Offset   |Res|M|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Identification                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""
from __future__ import annotations

import random
import struct

from .ethernet import EthernetHeader, build_ethernet_header
from .ip import IPHeader, build_ip_header
from .ipv6 import IPv6Header, build_ipv6_header

_IPV4_HEADER_LEN = 20
_IPV6_HEADER_LEN = 40
_IPV6_FRAG_EXT_LEN = 8   # RFC 8200 §4.5 Fragment Extension Header
_NEXT_HEADER_FRAGMENT = 44  # IPv6 Fragment extension header protocol number


def fragment_ipv4(
    ip_header: IPHeader,
    transport_data: bytes,
    mtu: int = 1500,
    *,
    eth_header: EthernetHeader | None = None,
) -> list[bytes]:
    r"""Fragment an IPv4 datagram into packets no larger than *mtu* bytes.

    Each fragment (except the last) carries a payload that is a multiple of
    8 bytes, as required by RFC 791.  The MF (More Fragments) flag is set on
    all fragments except the last.  The DF (Don't Fragment) flag is always
    cleared on the generated fragments.

    Args:
        ip_header: IPv4 header template.  ``identification`` is used as-is
            when non-zero; a random 16-bit value is generated when it is zero.
        transport_data: The transport layer bytes to fragment (TCP/UDP/ICMP
            header + application payload).
        mtu: Maximum IP packet size in bytes, *excluding* any Ethernet header.
            Defaults to ``1500``.
        eth_header: Optional Ethernet header to prepend to every fragment.

    Returns:
        A list of fully assembled packet bytes, one entry per fragment.
        A single-element list is returned when *transport_data* fits within
        one datagram.

    Raises:
        ValueError: If *mtu* is too small to hold even 8 bytes of fragment
            data (i.e. ``mtu < _IPV4_HEADER_LEN + 8``).

    Example::

        from packeteer.generate.ip import IPHeader
        from packeteer.generate.fragmentation import fragment_ipv4
        import socket

        ip_hdr = IPHeader("10.0.0.1", "10.0.0.2", socket.IPPROTO_UDP, ttl=64)
        fragments = fragment_ipv4(ip_hdr, transport_data=b"\\x00" * 3000, mtu=1500)
        assert len(fragments) == 3

    """
    # Max data bytes per fragment — must be a multiple of 8 (RFC 791 §3.1)
    max_data = (mtu - _IPV4_HEADER_LEN) & ~7
    if max_data < 8:
        raise ValueError(
            f"MTU {mtu} is too small: cannot fit even 8 bytes of fragment data "
            f"(available after IPv4 header: {mtu - _IPV4_HEADER_LEN} bytes)."
        )

    identification = ip_header.identification or random.randint(1, 0xFFFF)
    fragments: list[bytes] = []
    offset = 0  # byte offset into transport_data

    while offset < len(transport_data):
        chunk = transport_data[offset : offset + max_data]
        is_last = (offset + len(chunk)) >= len(transport_data)

        frag_hdr = IPHeader(
            src=ip_header.src,
            dst=ip_header.dst,
            protocol=ip_header.protocol,
            ttl=ip_header.ttl,
            tos=ip_header.tos,
            identification=identification,
            flags=0b000 if is_last else 0b001,  # MF flag (bit 2); DF always 0
            fragment_offset=offset // 8,         # field is in 8-byte units
        )

        ip_bytes = build_ip_header(frag_hdr, chunk)
        pkt = ip_bytes + chunk
        if eth_header is not None:
            pkt = build_ethernet_header(eth_header) + pkt
        fragments.append(pkt)
        offset += len(chunk)

    return fragments


def fragment_ipv6(
    ip_header: IPv6Header,
    transport_data: bytes,
    mtu: int = 1500,
    *,
    eth_header: EthernetHeader | None = None,
) -> list[bytes]:
    r"""Fragment an IPv6 datagram using the Fragment Extension Header (RFC 8200 §4.5).

    A Fragment Extension Header is inserted between the IPv6 base header and
    each chunk of *transport_data*.  The base header's ``next_header`` is set
    to ``44`` (Fragment) for every output packet; the extension header's
    ``next_header`` field carries the original transport protocol number.

    Args:
        ip_header: IPv6 header template.  ``next_header`` must be the
            transport protocol (``6`` TCP, ``17`` UDP, ``58`` ICMPv6); it is
            replaced with ``44`` in every output packet automatically.
        transport_data: The transport layer bytes to fragment (TCP/UDP/ICMPv6
            header + application payload).
        mtu: Maximum IP packet size in bytes, *excluding* any Ethernet header.
            Defaults to ``1500``.
        eth_header: Optional Ethernet header to prepend to every fragment.

    Returns:
        A list of fully assembled packet bytes, one entry per fragment.
        A single-element list is returned when *transport_data* fits within
        one datagram.

    Raises:
        ValueError: If *mtu* is too small to hold even 8 bytes of fragment
            data (i.e. ``mtu < _IPV6_HEADER_LEN + _IPV6_FRAG_EXT_LEN + 8``).

    Example::

        from packeteer.generate.ipv6 import IPv6Header
        from packeteer.generate.fragmentation import fragment_ipv6

        ip_hdr = IPv6Header("::1", "::2", next_header=17, hop_limit=64)
        fragments = fragment_ipv6(ip_hdr, transport_data=b"\\x00" * 3000, mtu=1500)
        assert len(fragments) == 3

    """
    max_data = (mtu - _IPV6_HEADER_LEN - _IPV6_FRAG_EXT_LEN) & ~7
    if max_data < 8:
        raise ValueError(
            f"MTU {mtu} is too small: cannot fit even 8 bytes of fragment data "
            f"(available after IPv6 + fragment extension headers: "
            f"{mtu - _IPV6_HEADER_LEN - _IPV6_FRAG_EXT_LEN} bytes)."
        )

    upper_proto = ip_header.next_header
    identification = random.randint(0, 0xFFFF_FFFF)
    fragments: list[bytes] = []
    offset = 0  # byte offset into transport_data

    while offset < len(transport_data):
        chunk = transport_data[offset : offset + max_data]
        is_last = (offset + len(chunk)) >= len(transport_data)
        m_flag = 0 if is_last else 1

        # Fragment Extension Header (8 bytes):
        #   next_header (1 B) | reserved (1 B) | offset_13b + res_2b + M (2 B) | id (4 B)
        frag_ext = struct.pack(
            "!BBHI",
            upper_proto,                          # next header = real transport protocol
            0,                                    # reserved
            ((offset // 8) << 3) | m_flag,        # 13-bit offset + M flag in low bit
            identification,
        )

        frag_ip = IPv6Header(
            src=ip_header.src,
            dst=ip_header.dst,
            next_header=_NEXT_HEADER_FRAGMENT,    # 44 = Fragment extension header
            hop_limit=ip_header.hop_limit,
            traffic_class=ip_header.traffic_class,
            flow_label=ip_header.flow_label,
        )

        # payload_length = fragment extension header (8) + chunk
        ip_bytes = build_ipv6_header(frag_ip, frag_ext + chunk)
        pkt = ip_bytes + frag_ext + chunk
        if eth_header is not None:
            pkt = build_ethernet_header(eth_header) + pkt
        fragments.append(pkt)
        offset += len(chunk)

    return fragments
