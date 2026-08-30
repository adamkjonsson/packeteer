from __future__ import annotations

import struct

from packeteer.generate.icmpv6 import ICMPv6Header


def packet_parser(data: bytes) -> tuple[int, int | None, ICMPv6Header | None]:
    """Parse an ICMPv6 header from raw bytes (RFC 4443).

    Header layout (8 bytes)::

        Type(1) | Code(1) | Checksum(2) | Type-specific(4)

    The last four bytes are Identifier and Sequence only for an Echo
    Request or Reply; other types put a Reserved field, an MTU, a
    gateway address or flags there.  They are read as two 16-bit halves
    regardless, and reach the header as *identifier* and *sequence*; see
    that class for what each type means by them.

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
        icmp_type, code, checksum, identifier, sequence = struct.unpack(
            "!BBHHH", data[:8]
        )
        # Captured as it stands; whether it survives into a spec is decided by
        # _clear_derivable_transport_fields, which drops it when a rebuild
        # would arrive at the same value.
        hdr = ICMPv6Header(type=icmp_type, code=code, identifier=identifier,
                    sequence=sequence, checksum=checksum)

    except struct.error:
        return (0, None, None)

    return (8, icmp_type, hdr)
