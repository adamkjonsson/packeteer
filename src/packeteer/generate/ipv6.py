"""IPv6 header construction (RFC 8200).

This module builds the fixed 40-byte IPv6 header.  Unlike IPv4, the IPv6
header contains **no checksum** — integrity is delegated entirely to the
transport layer (TCP, UDP) or ICMPv6.  Extension headers are not supported;
the *next_header* field must point directly to the transport protocol.

Header layout (40 bytes)::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version| Traffic Class |           Flow Label                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Payload Length        |  Next Header  |   Hop Limit   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                         Source Address                        +
   |                        (128 bits)                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                      Destination Address                      +
   |                        (128 bits)                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass


@dataclass
class IPv6Header:
    """Fields of a fixed IPv6 header.

    Attributes:
        src: Source IPv6 address in any notation accepted by
            :func:`socket.inet_pton`, e.g. ``"fe80::1"`` or ``"::1"``.
        dst: Destination IPv6 address in the same format as *src*.
        next_header: Protocol number of the header immediately following
            this one.  Common values: ``6`` (TCP), ``17`` (UDP),
            ``58`` (ICMPv6).
        hop_limit: Maximum number of hops (routers) the packet may traverse.
            Equivalent to the IPv4 TTL field.  Defaults to ``64``.
        traffic_class: 8-bit DSCP + ECN field, analogous to the IPv4 TOS
            byte.  Defaults to ``0``.
        flow_label: 20-bit flow label for QoS handling by routers.
            Defaults to ``0``.

    """

    src: str
    dst: str
    next_header: int
    hop_limit: int = 64
    traffic_class: int = 0
    flow_label: int = 0


def build_ipv6_header(hdr: IPv6Header, payload: bytes) -> bytes:
    r"""Build a 40-byte IPv6 fixed header.

    The *payload_length* field is set to ``len(payload)`` and reflects only
    the bytes **after** this 40-byte header (transport header + data).
    No checksum is computed — IPv6 headers do not carry one.

    Args:
        hdr: An :class:`IPv6Header` instance with the desired field values.
        payload: The data that will follow this header (transport header +
            application payload).  Used only to compute *payload_length*;
            its contents are not included in the returned bytes.

    Returns:
        Exactly 40 bytes representing the IPv6 header in network byte order.

    Raises:
        OSError: If *hdr.src* or *hdr.dst* is not a valid IPv6 address
            (raised by :func:`socket.inet_pton`).

    Example:
        >>> from packeteer.generate.ipv6 import IPv6Header, build_ipv6_header
        >>> hdr = IPv6Header("::1", "::2", next_header=6)
        >>> raw = build_ipv6_header(hdr, b"\\x00" * 20)
        >>> len(raw)
        40
        >>> (raw[0] >> 4)  # version nibble
        6

    """
    version_tc_fl = (6 << 28) | (hdr.traffic_class << 20) | (hdr.flow_label & 0xFFFFF)
    src = socket.inet_pton(socket.AF_INET6, hdr.src)
    dst = socket.inet_pton(socket.AF_INET6, hdr.dst)
    return struct.pack('!I', version_tc_fl) + struct.pack(
        '!HBB16s16s',
        len(payload),       # payload length (excludes this 40-byte header)
        hdr.next_header,
        hdr.hop_limit,
        src,
        dst,
    )
