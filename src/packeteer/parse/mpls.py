"""MPLS label stack entry parser.

Parses one 4-byte MPLS label stack entry from raw bytes, following RFC 3032.
"""
from __future__ import annotations

import struct

from packeteer.generate.ethernet import ETHERTYPE_IPV4, ETHERTYPE_IPV6
from packeteer.generate.mpls import MPLSLabel, ETHERTYPE_MPLS_UNICAST


def packet_parser(data: bytes) -> tuple[int, int | None, MPLSLabel | None]:
    """Parse one 4-byte MPLS label stack entry.

    Layout (RFC 3032)::

        Label (20) | TC (3) | S (1) | TTL (8)  ->  4 bytes

    When the S (bottom-of-stack) bit is 0, more MPLS labels follow and
    *next_protocol* is :data:`~packet_generator.mpls.ETHERTYPE_MPLS_UNICAST`
    (``0x8847``).  When S=1 this is the last label; the IP version nibble of
    the first byte of the payload is peeked to determine whether the next layer
    is IPv4 (``0x0800``) or IPv6 (``0x86DD``).

    Args:
        data: Raw bytes starting at the first byte of the MPLS label stack
            entry (i.e. immediately after the ``0x8847`` EtherType field or
            after the previous label stack entry).

    Returns:
        A tuple of ``(header_size, next_protocol, label)`` where *header_size*
        is always ``4``, *next_protocol* is the EtherType of the following
        layer, and *label* is the parsed :class:`MPLSLabel`.
        Returns ``(0, None, None)`` if parsing fails.
    """
    if len(data) < 4:
        return (0, None, None)

    try:
        word, = struct.unpack("!I", data[:4])
    except struct.error:
        return (0, None, None)

    label = (word >> 12) & 0xFFFFF
    tc    = (word >> 9)  & 0x7
    s     = (word >> 8)  & 0x1
    ttl   =  word        & 0xFF

    if s == 0:
        next_ethertype: int | None = ETHERTYPE_MPLS_UNICAST
    else:
        # Peek at the IP version nibble to distinguish IPv4 from IPv6.
        if len(data) < 5:
            return (0, None, None)
        version = (data[4] >> 4) & 0xF
        next_ethertype = ETHERTYPE_IPV4 if version == 4 else ETHERTYPE_IPV6

    return (4, next_ethertype, MPLSLabel(label=label, tc=tc, ttl=ttl))
