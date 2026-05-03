"""PPPoE header parser (RFC 2516).

Parses one PPPoE frame header, including the 2-byte PPP protocol field for
session frames and TLV tags for discovery frames.
"""
from __future__ import annotations

import struct

from packeteer.generate.ethernet import ETHERTYPE_IPV4, ETHERTYPE_IPV6
from packeteer.generate.pppoe import (
    PPP_IPV4,
    PPP_IPV6,
    PPPOE_CODE_SESSION,
    PPPoEHeader,
    PPPoETag,
)

# Map PPP protocol number -> EtherType so parse_packet can continue to IP
_PPP_TO_ETHERTYPE: dict[int, int] = {
    PPP_IPV4: ETHERTYPE_IPV4,
    PPP_IPV6: ETHERTYPE_IPV6,
}


def _parse_tags(data: bytes) -> list[PPPoETag]:
    """Decode a sequence of TLV tags from raw discovery payload bytes."""
    tags: list[PPPoETag] = []
    offset = 0
    while offset + 4 <= len(data):
        try:
            tag_type, tag_len = struct.unpack("!HH", data[offset:offset + 4])
        except struct.error:
            break
        offset += 4
        tag_data = data[offset:offset + tag_len]
        if len(tag_data) < tag_len:
            break
        tags.append(PPPoETag(type=tag_type, data=tag_data))
        offset += tag_len
    return tags


def packet_parser(data: bytes) -> tuple[int, int | None, PPPoEHeader | None]:
    """Parse a PPPoE header from raw bytes.

    For **session** frames (``code == 0x00``) the 2-byte PPP protocol field
    that follows the 6-byte PPPoE header is consumed and used to determine the
    next layer EtherType (IPv4 or IPv6).

    For **discovery** frames (``code != 0x00``) the TLV tags in the PPPoE
    payload are decoded.  ``next_protocol`` is ``None`` because no standard
    IP layer follows.

    Layout (session)::

        Ver/Type (1) | Code=0x00 (1) | Session ID (2) | Length (2) | PPP proto (2)
        -> consumes 8 bytes

    Layout (discovery)::

        Ver/Type (1) | Code (1) | Session ID (2) | Length (2) | Tags (Length bytes)
        -> consumes 6 + Length bytes

    Args:
        data: Raw bytes starting at the first byte of the PPPoE header
            (immediately after the EtherType field).

    Returns:
        A tuple of ``(header_size, next_protocol, header)``.

        For session frames: ``header_size`` is ``8``, ``next_protocol`` is
        ``ETHERTYPE_IPV4`` (``0x0800``) or ``ETHERTYPE_IPV6`` (``0x86DD``),
        or ``None`` for unrecognised PPP protocols.

        For discovery frames: ``header_size`` is ``6 + tag_bytes_consumed``,
        ``next_protocol`` is ``None``.

        On failure: ``(0, None, None)``.

    """
    if len(data) < 6:
        return (0, None, None)

    try:
        ver_type, code, session_id, length = struct.unpack("!BBHH", data[:6])
    except struct.error:
        return (0, None, None)

    if code == PPPOE_CODE_SESSION:
        # Session frame: consume 2-byte PPP protocol field
        if len(data) < 8:
            return (0, None, None)
        try:
            ppp_proto, = struct.unpack("!H", data[6:8])
        except struct.error:
            return (0, None, None)
        ethertype = _PPP_TO_ETHERTYPE.get(ppp_proto)
        return (8, ethertype, PPPoEHeader(code=code, session_id=session_id))
    # Discovery frame: decode TLV tags from the PPPoE payload
    tag_data = data[6:6 + length]
    tags = _parse_tags(tag_data)
    consumed = min(length, len(tag_data))
    return (6 + consumed, None, PPPoEHeader(code=code, session_id=session_id, tags=tags))
