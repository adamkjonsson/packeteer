from __future__ import annotations

import struct

from packeteer.generate.icmpv6 import ICMPv6Header


def packet_parser(data: bytes) -> tuple[int, int | None, ICMPv6Header | None]:
    """Parse an ICMPv6 header from raw bytes (RFC 4443).

    Header layout (8 bytes)::

        Type(1) | Code(1) | Checksum(2) | Identifier(2) | Sequence(2)

    Args:
        data: Raw bytes starting at the first byte of an ICMPv6 header.

    Returns:
        A tuple of ``(header_size, icmp_type, header)`` where *header_size*
        is always 8, *icmp_type* is the ICMPv6 message type (e.g. 128 = Echo
        Request, 129 = Echo Reply), and *header* is the parsed
        :class:`ICMPv6Header` object.  Returns ``(0, None, None)`` if parsing
        fails.

    """
    if len(data) < 8:
        return (0, None, None)

    try:
        icmp_type, code, _, identifier, sequence = struct.unpack(
            "!BBHHH", data[:8]
        )
        hdr = ICMPv6Header(type=icmp_type, code=code, identifier=identifier, sequence=sequence)

    except struct.error:
        return (0, None, None)

    return (8, icmp_type, hdr)
