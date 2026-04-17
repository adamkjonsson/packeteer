from __future__ import annotations

import struct

from packeteer.generate.udp import UDPHeader


def packet_parser(data: bytes) -> tuple[int, int | None, UDPHeader | None]:
    """Parse a UDP header from raw bytes (RFC 768).

    Header layout (8 bytes)::

        Source Port(2) | Destination Port(2) | Length(2) | Checksum(2)

    The *length* field covers the UDP header plus payload; it must be at
    least 8 (header only).

    Args:
        data: Raw bytes starting at the first byte of a UDP header.

    Returns:
        A tuple of ``(header_size, dst_port, header)`` where *header_size* is
        always 8, *dst_port* is the destination port number, and *header* is
        the parsed :class:`UDPHeader` object.  Returns ``(0, None, None)`` if
        parsing fails.

    """
    if len(data) < 8:
        return (0, None, None)

    try:
        src_port, dst_port, length, _ = struct.unpack("!HHHH", data[:8])
        if length < 8:
            return (0, None, None)

        hdr = UDPHeader(src_port=src_port, dst_port=dst_port)

    except struct.error:
        return (0, None, None)

    return (8, dst_port, hdr)
