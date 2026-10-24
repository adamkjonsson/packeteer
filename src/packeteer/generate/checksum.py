"""Checksum utilities for network protocols.

This module provides:

* :func:`ones_complement_checksum` — RFC 1071 one's-complement checksum used
  by IPv4, TCP, UDP, ICMP, and ICMPv6.
* :func:`crc32c` — CRC-32c (Castagnoli) checksum used by SCTP (RFC 9260).
"""
from __future__ import annotations


def _make_crc32c_table() -> list[int]:
    """Build the 256-entry lookup table for CRC-32c (Castagnoli polynomial)."""
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x82F63B78
            else:
                crc >>= 1
        table.append(crc)
    return table


_CRC32C_TABLE: list[int] = _make_crc32c_table()


def crc32c(data: bytes) -> int:
    r"""Compute the CRC-32c (Castagnoli) checksum over *data*.

    Uses the Castagnoli polynomial (0x1EDC6F41, reflected form 0x82F63B78).
    This is the checksum algorithm mandated by SCTP (RFC 9260 §6.8).

    Args:
        data: The bytes to checksum.

    Returns:
        A 32-bit unsigned integer in the range ``[0, 2**32 - 1]``.

    Example:
        >>> from packeteer.generate.checksum import crc32c
        >>> crc32c(b'\x00' * 12) != 0
        True

    """
    crc = 0xFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ _CRC32C_TABLE[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFFFFFF


def ones_complement_checksum(data: bytes) -> int:
    r"""Compute the RFC 1071 internet checksum over *data*.

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
        >>> from packeteer.generate.checksum import ones_complement_checksum
        >>> raw = b'\x45\x00\x00\x28'  # partial IPv4 header
        >>> cksum = ones_complement_checksum(raw)
        >>> isinstance(cksum, int) and 0 <= cksum <= 0xFFFF
        True

    """
    if len(data) % 2:
        data += b'\x00'
    # The whole buffer as one big-endian integer is congruent, modulo 0xFFFF,
    # to the sum of its 16-bit words, since 2**16 == 1 (mod 0xFFFF).  So one
    # C-level conversion and one modulo replace a Python loop per word (#213).
    value = int.from_bytes(data, 'big')
    if not value:
        return 0xFFFF           # all zero: the folded sum is 0, complemented
    folded = value % 0xFFFF
    # A non-zero multiple of 0xFFFF folds to 0xFFFF (one's-complement "-0"),
    # not to 0, and its complement is 0.
    return ~folded & 0xFFFF if folded else 0
