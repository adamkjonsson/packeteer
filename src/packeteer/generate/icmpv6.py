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

    The four bytes after the checksum are **type-specific**.  They are named
    *identifier* and *sequence* because that is what an Echo Request or Reply
    puts there, and Echo is what packeteer generates by default — but every
    other message type uses them for something else:

    ==================================  =====================================
    Type                                What the four bytes hold
    ==================================  =====================================
    128, 129 (Echo Request/Reply)       Identifier, then Sequence
    1, 3 (Unreachable, Time Exceeded)   Unused, zero
    2 (Packet Too Big)                  The MTU, as one 32-bit value
    4 (Parameter Problem)               A pointer, as one 32-bit value
    133, 135, 137 (RS, NS, Redirect)    Reserved, zero
    134 (Router Advertisement)          Hop limit, flags, router lifetime
    136 (Neighbour Advertisement)       R/S/O flags, then reserved bits
    ==================================  =====================================

    Use :attr:`rest_of_header` to read or write all four bytes as one value,
    which is what the types above want.  The two halves are kept as the stored
    fields so that a packet spec written against an earlier version still
    builds.

    Attributes:
        type: ICMPv6 message type.  ``128`` = Echo Request,
            ``129`` = Echo Reply.  Defaults to ``128``.
        code: Sub-type code; meaning depends on *type*.  For Echo
            Request/Reply this must be ``0``.  Defaults to ``0``.
        identifier: The **first** two of the four type-specific bytes.  For an
            Echo, the identifier matching replies to requests.  Defaults to
            ``1``.
        sequence: The **second** two.  For an Echo, the sequence number.
            Defaults to ``1``.

    """

    type: int = 128     # Echo Request (129 = Echo Reply)
    code: int = 0
    identifier: int = 1
    sequence: int = 1

    @property
    def rest_of_header(self) -> int:
        """The four type-specific bytes after the checksum, as one value.

        What most message types actually want: an ICMPv6 Packet Too Big's MTU,
        an ICMPv4 Redirect's gateway address, a Parameter Problem's pointer.
        Reading or writing it keeps :attr:`identifier` and :attr:`sequence`
        consistent, since they are its two halves.

        Returns:
            The four bytes as a 32-bit integer.

        """
        return (self.identifier << 16) | self.sequence

    @rest_of_header.setter
    def rest_of_header(self, value: int) -> None:
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError(
                f"rest_of_header must fit in 32 bits, got {value}",
            )
        self.identifier = value >> 16
        self.sequence = value & 0xFFFF


def _build_icmpv6_header(
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
        >>> from packeteer.generate.icmpv6 import ICMPv6Header, _build_icmpv6_header
        >>> raw = _build_icmpv6_header(ICMPv6Header(), b"ping", "::1", "::2")
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
