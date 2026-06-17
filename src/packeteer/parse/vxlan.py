"""Parser for VXLAN tunnel headers (RFC 7348).

Follows the same ``(header_size, next_layer_id, HeaderObject | None)``
convention as all other ``packet_parser`` modules.

``next_layer_id`` is always ``None`` because the inner frame is an Ethernet
frame, identified by restarting Ethernet parsing rather than by a numeric
EtherType or protocol number.
"""
from __future__ import annotations

import struct

from packeteer.generate.vxlan import VXLANHeader

_HEADER = struct.Struct(">BxxxI")   # flags, 3 reserved bytes, (VNI<<8 | reserved)


def packet_parser(data: bytes) -> tuple[int, None, VXLANHeader | None]:
    """Parse an 8-byte VXLAN header (RFC 7348).

    Args:
        data: Raw bytes starting at the VXLAN header.

    Returns:
        ``(8, None, VXLANHeader(...))`` on success.
        ``(0, None, None)`` when *data* is shorter than 8 bytes.

    """
    if len(data) < 8:
        return (0, None, None)
    flags, vni_word = _HEADER.unpack(data[:8])
    return (8, None, VXLANHeader(vni=vni_word >> 8, flags=flags))
