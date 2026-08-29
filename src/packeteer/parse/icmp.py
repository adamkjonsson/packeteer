from __future__ import annotations

import struct

from packeteer.generate.icmp import ICMPHeader


def packet_parser(data: bytes) -> tuple[int, int | None, ICMPHeader | None]:
    """Parse an ICMPv4 header from raw bytes (RFC 792).

    Header layout (8 bytes)::

        Type(1) | Code(1) | Checksum(2) | Type-specific(4)

    The last four bytes are Identifier and Sequence only for an Echo
    Request or Reply; other types put a Reserved field, an MTU, a
    gateway address or flags there.  They are read as two 16-bit halves
    regardless, and reach the header as *identifier* and *sequence*; see
    that class for what each type means by them.

    Args:
        data: Raw bytes starting at the first byte of an ICMPv4 header.

    Returns:
        A tuple of ``(header_size, icmp_type, header)`` where *header_size*
        is always 8, *icmp_type* is the ICMP message type (e.g. 8 = Echo
        Request, 0 = Echo Reply), and *header* is the parsed
        :class:`ICMPHeader` object.  Returns ``(0, None, None)`` if parsing
        fails.

    """
    if len(data) < 8:
        return (0, None, None)

    try:
        icmp_type, code, _, identifier, sequence = struct.unpack(
            "!BBHHH", data[:8]
        )
        hdr = ICMPHeader(type=icmp_type, code=code, identifier=identifier, sequence=sequence)

    except struct.error:
        return (0, None, None)

    return (8, icmp_type, hdr)
