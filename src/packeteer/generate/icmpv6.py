"""ICMPv6 header construction (RFC 4443).

This module builds the 8-byte ICMPv6 Echo Request / Echo Reply header.
Unlike ICMPv4, ICMPv6 checksums are computed over an **IPv6 pseudo-header**
in addition to the ICMP header and payload, and the checksum is **mandatory**
(it may never be omitted).

The IPv6 pseudo-header used for the checksum (40 bytes)::

    Source Address (16) | Destination Address (16)
    | ICMPv6 length (4) | Zeros (3) | Next Header = 58 (1)

Common ICMPv6 type values:

* ``1``   — Destination Unreachable
* ``2``   — Packet Too Big
* ``3``   — Time Exceeded
* ``128`` — Echo Request  *(default)*
* ``129`` — Echo Reply
* ``133`` — Router Solicitation
* ``135`` — Neighbor Solicitation
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

from .checksum import ones_complement_checksum


@dataclass
class ICMPv6Header:
    """Fields of an ICMPv6 message header.

    Attributes:
        type: ICMPv6 message type.  ``128`` = Echo Request,
            ``129`` = Echo Reply.  Defaults to ``128``.
        code: Sub-type code; meaning depends on *type*.  For Echo
            Request/Reply this must be ``0``.  Defaults to ``0``.
        identifier: 16-bit identifier used to match replies to requests.
            Defaults to ``1``.
        sequence: 16-bit sequence number, incremented for each successive
            request.  Defaults to ``1``.
    """

    type: int = 128     # Echo Request (129 = Echo Reply)
    code: int = 0
    identifier: int = 1
    sequence: int = 1


def build_icmpv6_header(
    hdr: ICMPv6Header,
    payload: bytes,
    src_ip: str,
    dst_ip: str,
) -> bytes:
    """Build an 8-byte ICMPv6 header with a correct checksum.

    The checksum is mandatory and covers the ICMPv6 header, *payload*, and
    the IPv6 pseudo-header (source address, destination address, ICMPv6
    length, and Next Header = 58).  This matches the requirement in
    RFC 4443 §2.3 and RFC 8200 §8.1.

    Args:
        hdr: An :class:`ICMPv6Header` instance with the desired field values.
        payload: Data bytes to include in the ICMPv6 message body.  Included
            in the checksum but **not** in the returned bytes.
        src_ip: Source IPv6 address in any notation accepted by
            :func:`socket.inet_pton`, e.g. ``"fe80::1"``.
        dst_ip: Destination IPv6 address in the same format as *src_ip*.

    Returns:
        Exactly 8 bytes representing the ICMPv6 header in network byte order,
        with a valid checksum.

    Raises:
        OSError: If *src_ip* or *dst_ip* is not a valid IPv6 address.

    Example:
        >>> from packet_generator.icmpv6 import ICMPv6Header, build_icmpv6_header
        >>> raw = build_icmpv6_header(ICMPv6Header(), b"ping", "::1", "::2")
        >>> len(raw)
        8
        >>> raw[0]  # type = Echo Request
        128
        >>> raw[1]  # code
        0
    """
    raw = struct.pack('!BBHHH', hdr.type, hdr.code, 0, hdr.identifier, hdr.sequence)
    icmpv6_length = len(raw) + len(payload)

    pseudo = (
        socket.inet_pton(socket.AF_INET6, src_ip)
        + socket.inet_pton(socket.AF_INET6, dst_ip)
        + struct.pack('!I3sB', icmpv6_length, b'\x00\x00\x00', 58)  # 58 = ICMPv6
    )

    checksum = ones_complement_checksum(pseudo + raw + payload)
    return raw[:2] + struct.pack('!H', checksum) + raw[4:]
