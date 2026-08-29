"""Parser for BSD loopback framing (DLT_NULL and DLT_LOOP).

Follows the same ``(header_size, next_layer_id, HeaderObject | None)``
convention as every other ``packet_parser`` module.  The *next_layer_id* is an
EtherType rather than the address family, so that the layer after it is
identified exactly as it is after an Ethernet header.
"""
from __future__ import annotations

import struct

from packeteer.generate.loopback import (
    AF_INET,
    AF_INET6_VALUES,
    LoopbackHeader,
)

_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_HEADER_LEN = 4
#: A family this large means the four bytes were read in the wrong order.
_IMPLAUSIBLE = 0xFF


def packet_parser(
    data: bytes, *, big_endian: bool | None = None,
) -> tuple[int, int | None, LoopbackHeader | None]:
    """Parse a four-byte loopback header.

    Args:
        data: Raw bytes starting at the loopback header.
        big_endian: Force a byte order — ``True`` for ``DLT_LOOP``, which is
            always network order.  ``None`` decides from the bytes, which is
            what ``DLT_NULL`` needs: its order is the capturing host's, and a
            file may come from a host of either endianness.

    Returns:
        ``(4, ethertype, LoopbackHeader)`` on success, where *ethertype* is
        ``0x0800`` or ``0x86DD`` so the caller can dispatch as it would after
        an Ethernet header.  ``(0, None, None)`` when *data* is too short or
        the family is not one this reads.

    """
    if len(data) < _HEADER_LEN:
        return (0, None, None)

    if big_endian is None:
        # Address families are small, so the order that yields a plausible
        # value is the order the capturing host used.  A little-endian word
        # puts the value in the first byte; a big-endian one in the last.
        little = struct.unpack("<I", data[:_HEADER_LEN])[0]
        big_endian = little > _IMPLAUSIBLE

    family = struct.unpack(">I" if big_endian else "<I", data[:_HEADER_LEN])[0]
    if family == AF_INET:
        ethertype = _ETHERTYPE_IPV4
    elif family in AF_INET6_VALUES:
        ethertype = _ETHERTYPE_IPV6
    else:
        return (0, None, None)

    return (_HEADER_LEN, ethertype,
            LoopbackHeader(family=family, big_endian=big_endian))
