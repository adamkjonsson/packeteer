"""Parser for GRE tunnel headers (RFC 2784 / RFC 2890).

Follows the same ``(header_size, next_layer_id, HeaderObject | None)``
convention as all other ``packet_parser`` modules.

``next_layer_id`` is the GRE Protocol Type (an EtherType value) so callers
can dispatch to ``LINKTYPE_ETHERNET`` for TEB (``0x6558``) or ``LINKTYPE_RAW``
for IPv4 (``0x0800``) and IPv6 (``0x86DD``) inner payloads.
"""
from __future__ import annotations

import struct

from packet_generator.gre import GREHeader


def packet_parser(data: bytes) -> tuple[int, int | None, GREHeader | None]:
    """Parse a GRE header (RFC 2784 / RFC 2890).

    Args:
        data: Raw bytes starting at the GRE header.

    Returns:
        ``(header_size, protocol_type, GREHeader)`` on success.
        ``(0, None, None)`` when *data* is too short or the version field
        is not 0.

        *header_size* is the total number of bytes consumed (4–16 depending
        on which optional fields are present).  *protocol_type* is the
        EtherType value from the GRE header identifying the inner payload.
    """
    if len(data) < 4:
        return (0, None, None)

    flags_ver, proto_type = struct.unpack_from("!HH", data, 0)
    ver = flags_ver & 0x0007
    if ver != 0:
        return (0, None, None)

    c_flag = bool(flags_ver & 0x8000)
    k_flag = bool(flags_ver & 0x2000)
    s_flag = bool(flags_ver & 0x1000)

    offset = 4
    checksum_val: int | None = None
    key: int | None = None
    seq: int | None = None

    if c_flag:
        if len(data) < offset + 4:
            return (0, None, None)
        checksum_val = struct.unpack_from("!H", data, offset)[0]
        offset += 4  # checksum (2) + reserved1 (2)

    if k_flag:
        if len(data) < offset + 4:
            return (0, None, None)
        (key,) = struct.unpack_from("!I", data, offset)
        offset += 4

    if s_flag:
        if len(data) < offset + 4:
            return (0, None, None)
        (seq,) = struct.unpack_from("!I", data, offset)
        offset += 4

    hdr = GREHeader(key=key, seq=seq, checksum=c_flag, protocol_type=proto_type)
    return (offset, proto_type, hdr)
