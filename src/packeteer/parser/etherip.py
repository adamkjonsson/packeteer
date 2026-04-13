"""Parser for EtherIP tunnel headers (RFC 3378).

Follows the same ``(header_size, next_layer_id, HeaderObject | None)``
convention as all other ``packet_parser`` modules.

``next_layer_id`` is always ``None`` because the inner frame is an
Ethernet frame, identified by restarting Ethernet parsing rather than by
a numeric EtherType or protocol number.
"""
from __future__ import annotations

import struct

from packeteer.generator.etherip import EtherIPHeader


def packet_parser(data: bytes) -> tuple[int, None, EtherIPHeader | None]:
    """Parse a 2-byte EtherIP header (RFC 3378).

    Args:
        data: Raw bytes starting at the EtherIP header.

    Returns:
        ``(2, None, EtherIPHeader())`` on success.
        ``(0, None, None)`` when *data* is too short or the version field
        is not 3.
    """
    if len(data) < 2:
        return (0, None, None)
    (raw,) = struct.unpack("!H", data[:2])
    if (raw >> 12) != 3:          # version must be 3
        return (0, None, None)
    return (2, None, EtherIPHeader())
