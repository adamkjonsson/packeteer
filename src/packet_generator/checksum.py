"""RFC 1071 internet checksum utility.

This module provides the one's-complement checksum algorithm used by IPv4,
TCP, UDP, ICMP, and ICMPv6 to detect data corruption in transit.
"""
from __future__ import annotations

import struct


def ones_complement_checksum(data: bytes) -> int:
    """Compute the RFC 1071 internet checksum over *data*.

    The algorithm sums all 16-bit big-endian words, folds any carry bits back
    into the low 16 bits, and returns the one's complement of the result.
    If *data* has an odd number of bytes it is padded with a trailing zero
    byte before summing, as specified by RFC 1071.

    To verify an already-checksummed buffer, append the checksum bytes and
    call this function again — a correct buffer returns ``0``.

    Args:
        data: The bytes to checksum. May be any length (odd or even).

    Returns:
        A 16-bit integer in the range ``[0, 65535]``.  A value of ``0xFFFF``
        indicates that all bits were zero after complementing (all-ones input).

    Example:
        >>> from packet_generator.checksum import ones_complement_checksum
        >>> raw = b'\\x45\\x00\\x00\\x28'  # partial IPv4 header
        >>> cksum = ones_complement_checksum(raw)
        >>> isinstance(cksum, int) and 0 <= cksum <= 0xFFFF
        True
    """
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        total += struct.unpack_from('!H', data, i)[0]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF
