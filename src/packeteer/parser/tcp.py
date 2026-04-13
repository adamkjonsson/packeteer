from __future__ import annotations

import struct

from packeteer.generator.tcp import TCPHeader


def packet_parser(data: bytes) -> tuple[int, int | None, TCPHeader | None]:
    """Parse a TCP header from raw bytes (RFC 9293).

    Header layout (20+ bytes)::

        Source Port(2) | Destination Port(2) | Sequence Number(4)
        Acknowledgement Number(4) | Data Offset(4b) | Reserved(4b) | Flags(8b)
        Window(2) | Checksum(2) | Urgent Pointer(2)
        [ Options: (Data Offset - 5) * 4 bytes ]

    The Data Offset field (high nibble of byte 12) gives the header length in
    32-bit words; the minimum valid value is 5 (20 bytes).  The ``options``
    field of the returned :class:`TCPHeader` is always ``None`` — option bytes
    are skipped, not decoded.

    Args:
        data: Raw bytes starting at the first byte of a TCP header.

    Returns:
        A tuple of ``(header_size, dst_port, header)`` where *header_size* is
        ``data_offset * 4``, *dst_port* is the destination port number, and
        *header* is the parsed :class:`TCPHeader` object.  Returns
        ``(0, None, None)`` if parsing fails.
    """
    if len(data) < 20:
        return (0, None, None)

    try:
        src_port, dst_port, seq, ack = struct.unpack("!HHII", data[0:12])
        data_offset = (data[12] >> 4) & 0xF
        reserved = data[12] & 0x0F
        flags = data[13]
        window, _, urgent_ptr = struct.unpack("!HHH", data[14:20])

        if data_offset < 5:
            return (0, None, None)

        header_size = data_offset * 4
        if len(data) < header_size:
            return (0, None, None)

        hdr = TCPHeader(
            src_port=src_port, dst_port=dst_port,
            seq=seq, ack=ack,
            reserved=reserved, flags=flags,
            window=window, urgent_ptr=urgent_ptr,
        )

    except Exception:
        return (0, None, None)

    return (header_size, dst_port, hdr)
