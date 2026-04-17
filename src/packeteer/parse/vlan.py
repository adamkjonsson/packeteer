from __future__ import annotations

import struct

from packeteer.generate.ethernet import VLANTag


def packet_parser(data: bytes) -> tuple[int, int | None, VLANTag | None]:
    """Parse an IEEE 802.1Q VLAN tag from raw bytes.

    The tag is expected to start immediately after the 0x8100 TPID field,
    i.e. the first two bytes are the Tag Control Information (TCI) and the
    next two bytes are the inner EtherType.

    Layout::

        TCI (2) | inner EtherType (2)  →  4 bytes

    Args:
        data: Raw bytes starting at the TCI field of a VLAN tag.

    Returns:
        A tuple of ``(header_size, next_protocol, tag)`` where *header_size*
        is always 4, *next_protocol* is the inner EtherType, and *tag* is the
        parsed :class:`VLANTag` object.  Returns ``(0, None, None)`` if
        parsing fails.

    """
    if len(data) < 4:
        return (0, None, None)

    try:
        tci = struct.unpack("!H", data[0:2])[0]
        inner_ethertype = struct.unpack("!H", data[2:4])[0]

        pcp = (tci >> 13) & 0x7
        dei = (tci >> 12) & 0x1
        vid = tci & 0xFFF

        tag = VLANTag(vid=vid, pcp=pcp, dei=dei)

    except struct.error:
        return (0, None, None)

    return (4, inner_ethertype, tag)
