"""Parsers for Linux cooked-capture pseudo link-layer headers (SLL and SLL2).

Follows the same ``(header_size, next_layer_id, HeaderObject | None)``
convention as all other ``packet_parser`` modules.  ``next_layer_id`` is the
Protocol Type field — an EtherType — so the caller dispatches the next layer
exactly as it does after an Ethernet header.
"""
from __future__ import annotations

import struct

from packeteer.generate.sll import ARPHRD_ETHER, SLL2Header, SLLHeader

_SLL = struct.Struct(">HHH8sH")    # packet_type, arphrd, addr_len, addr(8), protocol
_SLL2 = struct.Struct(">HHIHBB8s")  # protocol, reserved, if_index, arphrd, ptype, addr_len, addr(8)


def _format_address(arphrd: int, addr: bytes, addr_len: int) -> str:
    """Format the link-layer address: a MAC string for 6-byte Ethernet, else hex."""
    valid = addr[:max(0, min(addr_len, 8))]
    if arphrd == ARPHRD_ETHER and addr_len == 6:
        return ":".join(f"{b:02x}" for b in valid)
    return valid.hex()


def sll_packet_parser(data: bytes) -> tuple[int, int | None, SLLHeader | None]:
    """Parse a 16-byte SLL v1 header (``LINKTYPE_LINUX_SLL``).

    Returns ``(16, protocol, SLLHeader(...))`` on success, or ``(0, None, None)``
    when *data* is shorter than 16 bytes.
    """
    if len(data) < 16:
        return (0, None, None)
    packet_type, arphrd, addr_len, addr, protocol = _SLL.unpack_from(data, 0)
    hdr = SLLHeader(
        packet_type=packet_type,
        arphrd_type=arphrd,
        address=_format_address(arphrd, addr, addr_len),
    )
    return (16, protocol, hdr)


def sll2_packet_parser(data: bytes) -> tuple[int, int | None, SLL2Header | None]:
    """Parse a 20-byte SLL2 header (``LINKTYPE_LINUX_SLL2``).

    Returns ``(20, protocol, SLL2Header(...))`` on success, or ``(0, None, None)``
    when *data* is shorter than 20 bytes.
    """
    if len(data) < 20:
        return (0, None, None)
    protocol, _reserved, if_index, arphrd, packet_type, addr_len, addr = _SLL2.unpack_from(data, 0)
    hdr = SLL2Header(
        packet_type=packet_type,
        arphrd_type=arphrd,
        address=_format_address(arphrd, addr, addr_len),
        if_index=if_index,
    )
    return (20, protocol, hdr)
