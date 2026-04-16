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

    Attributes:
        type: ICMP message type.  ``8`` = Echo Request, ``0`` = Echo Reply.
            Defaults to ``8`` (Echo Request).
        code: Sub-type code; meaning depends on *type*.  For Echo
            Request/Reply this must be ``0``.  Defaults to ``0``.
        identifier: 16-bit identifier used to match replies to requests.
            Defaults to ``1``.
        sequence: 16-bit sequence number, incremented for each successive
            request in a ping session.  Defaults to ``1``.

    """

    type: int = 8       # Echo Request
    code: int = 0
    identifier: int = 1
    sequence: int = 1


def build_icmp_header(hdr: ICMPHeader, payload: bytes) -> bytes:
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
        >>> from packeteer.generate.icmp import ICMPHeader, build_icmp_header
        >>> raw = build_icmp_header(ICMPHeader(), b"hello")
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
