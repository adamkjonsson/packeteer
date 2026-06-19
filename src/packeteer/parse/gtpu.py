"""Parser for GTP-U tunnel headers (GTPv1-U, 3GPP TS 29.281).

Follows the same ``(header_size, next_layer_id, HeaderObject | None)``
convention as all other ``packet_parser`` modules.

``next_layer_id`` is the GTP-U message type.  The caller uses it to decide how
to treat the payload: a G-PDU (255) carries an inner IP packet; other message
types carry control content that is left in the packet payload.
"""
from __future__ import annotations

import struct

from packeteer.generate.gtpu import GTPUExtensionHeader, GTPUHeader

_BASE = struct.Struct(">BBHI")     # flags, message_type, length, TEID
_OPTIONAL = struct.Struct(">HBB")  # sequence, n_pdu, next_ext_type


def _parse_extension_headers(
    data: bytes, first_type: int,
) -> tuple[int, list[GTPUExtensionHeader]] | None:
    """Parse the extension-header chain starting at *data*.

    Args:
        data: Bytes beginning at the first extension header.
        first_type: The Next-Extension-Header-Type value from the optional block
            (the type of the first extension header).

    Returns:
        ``(consumed_bytes, headers)`` on success, or ``None`` when the chain is
        malformed or truncated.

    """
    headers: list[GTPUExtensionHeader] = []
    offset = 0
    next_type = first_type
    while next_type != 0:
        if offset + 1 > len(data):
            return None
        units = data[offset]
        if units == 0:
            return None
        total = units * 4
        if offset + total > len(data):
            return None
        content = data[offset + 1:offset + total - 1]
        following = data[offset + total - 1]
        headers.append(GTPUExtensionHeader(header_type=next_type, content=content))
        next_type = following
        offset += total
    return (offset, headers)


def packet_parser(data: bytes) -> tuple[int, int | None, GTPUHeader | None]:
    """Parse a GTP-U header (GTPv1-U, 3GPP TS 29.281).

    Args:
        data: Raw bytes starting at the GTP-U header.

    Returns:
        ``(header_size, message_type, GTPUHeader(...))`` on success, where
        *header_size* covers the mandatory header plus any optional block and
        extension headers.  Returns ``(0, None, None)`` when *data* is too short,
        the version is not 1, or the extension-header chain is malformed.

    """
    if len(data) < 8:
        return (0, None, None)
    flags, message_type, _length, teid = _BASE.unpack_from(data, 0)
    if (flags >> 5) != 1:   # version must be 1 (GTPv1)
        return (0, None, None)
    e_flag = bool(flags & 0x04)
    s_flag = bool(flags & 0x02)
    pn_flag = bool(flags & 0x01)

    size = 8
    sequence: int | None = None
    n_pdu: int | None = None
    ext_headers: list[GTPUExtensionHeader] = []

    if e_flag or s_flag or pn_flag:
        if len(data) < size + 4:
            return (0, None, None)
        seq_val, npdu_val, next_ext_type = _OPTIONAL.unpack_from(data, size)
        size += 4
        if s_flag:
            sequence = seq_val
        if pn_flag:
            n_pdu = npdu_val
        if e_flag:
            result = _parse_extension_headers(data[size:], next_ext_type)
            if result is None:
                return (0, None, None)
            consumed, ext_headers = result
            size += consumed

    hdr = GTPUHeader(
        teid=teid,
        message_type=message_type,
        sequence=sequence,
        n_pdu=n_pdu,
        extension_headers=ext_headers,
    )
    return (size, message_type, hdr)
