"""ICMPv4 header construction (RFC 792).

This module builds the 8-byte ICMPv4 Echo Request / Echo Reply header.
Unlike TCP and UDP, ICMPv4 checksums are computed over the ICMP header and
payload **only** — no IP pseudo-header is used.

Common ICMP type values:

* ``0``  — Echo Reply
* ``3``  — Destination Unreachable
* ``8``  — Echo Request  *(default)*
* ``11`` — Time Exceeded
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from .checksum import ones_complement_checksum


@dataclass
class ICMPHeader:
    """Fields of an ICMPv4 message header.

    The four bytes after the checksum are **type-specific**.  They are named
    *identifier* and *sequence* because that is what an Echo Request or Reply
    puts there, and Echo is what packeteer generates by default — but every
    other message type uses them for something else:

    ==================================  =====================================
    Type                                What the four bytes hold
    ==================================  =====================================
    0, 8 (Echo Reply/Request)           Identifier, then Sequence
    3 (Destination Unreachable)         Unused, with the next-hop MTU in the
                                        second half for code 4
    5 (Redirect)                        The gateway address, as one 32-bit
                                        value
    11 (Time Exceeded)                  Unused, zero
    12 (Parameter Problem)              A pointer in the first byte
    ==================================  =====================================

    Use :attr:`rest_of_header` to read or write all four bytes as one value —
    a Redirect's gateway address, for instance.  The two halves are kept as
    the stored fields so that a packet spec written against an earlier version
    still builds.

    Attributes:
        type: ICMP message type.  ``8`` = Echo Request, ``0`` = Echo Reply.
        code: Sub-type code; meaning depends on *type*.
        identifier: The **first** two of the four type-specific bytes.  For an
            Echo, the identifier matching replies to requests.  Defaults to
            ``1``.
        sequence: The **second** two.  For an Echo, the sequence number.
            Defaults to ``1``.

    """

    type: int = 8       # Echo Request
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


def _build_icmp_header(hdr: ICMPHeader, payload: bytes) -> bytes:
    """Build an 8-byte ICMPv4 header with a correct checksum.

    The checksum is computed over the ICMP header and *payload* concatenated.
    No IP pseudo-header is involved (unlike TCP and UDP).

    Args:
        hdr: An :class:`ICMPHeader` instance with the desired field values.
        payload: Data bytes to include in the ICMP message body (e.g. a
            timestamp or padding).  Included in the checksum but **not** in
            the returned bytes.

    Returns:
        Exactly 8 bytes representing the ICMPv4 header in network byte order,
        with a valid checksum.

    Example:
        >>> from packeteer.generate.icmp import ICMPHeader, _build_icmp_header
        >>> raw = _build_icmp_header(ICMPHeader(), b"hello")
        >>> len(raw)
        8
        >>> raw[0]  # type = Echo Request
        8
        >>> raw[1]  # code
        0

    """
    raw = struct.pack('!BBHHH', hdr.type, hdr.code, 0, hdr.identifier, hdr.sequence)
    checksum = ones_complement_checksum(raw + payload)
    return raw[:2] + struct.pack('!H', checksum) + raw[4:]
