"""RFC 4385 pseudowire control word parser."""
from __future__ import annotations

import struct

from packeteer.generate.ethernet import ETHERTYPE_IPV4, ETHERTYPE_IPV6
from packeteer.generate.gre import GRE_PROTO_TEB
from packeteer.generate.pseudowire import PseudowireHeader


def packet_parser(
    data: bytes,
) -> tuple[int, int | None, PseudowireHeader | None]:
    """Parse a 4-byte RFC 4385 pseudowire control word.

    The first nibble of the control word must be ``0x0``.  The inner payload
    type is inferred by peeking at the version nibble of the byte immediately
    following the control word:

    - ``4`` → IPv4 (:data:`~packeteer.generate.ethernet.ETHERTYPE_IPV4`)
    - ``6`` → IPv6 (:data:`~packeteer.generate.ethernet.ETHERTYPE_IPV6`)
    - anything else → inner Ethernet frame
      (:data:`~packeteer.generate.gre.GRE_PROTO_TEB`, the same sentinel used
      by the GRE parser for Transparent Ethernet Bridging)

    Args:
        data: Raw bytes starting at the first byte of the control word.

    Returns:
        A tuple of ``(header_size, next_protocol, header)`` where
        *header_size* is ``4``, *next_protocol* identifies the inner payload,
        and *header* is the parsed :class:`PseudowireHeader`.
        Returns ``(0, None, None)`` if parsing fails.

    """
    if len(data) < 4:
        return (0, None, None)

    try:
        word0, sequence = struct.unpack("!HH", data[:4])
    except struct.error:
        return (0, None, None)

    if (word0 >> 12) != 0:
        return (0, None, None)

    flags  = (word0 >> 8) & 0xF
    frag   = (word0 >> 6) & 0x3
    length = word0 & 0x3F

    if len(data) >= 5:
        version = (data[4] >> 4) & 0xF
        if version == 4:
            inner_et: int | None = ETHERTYPE_IPV4
        elif version == 6:
            inner_et = ETHERTYPE_IPV6
        else:
            inner_et = GRE_PROTO_TEB
    else:
        inner_et = GRE_PROTO_TEB

    return (4, inner_et, PseudowireHeader(flags=flags, frag=frag, length=length, sequence=sequence))
