"""MPLS label stack entry construction.

Builds 4-byte MPLS label stack entries as defined in RFC 3032.  The
bottom-of-stack (S) bit is set automatically by :class:`PacketBuilder` based
on whether another MPLS label follows in the layer stack.

Constants:
    ETHERTYPE_MPLS_UNICAST (int): EtherType ``0x8847`` — MPLS unicast.
    ETHERTYPE_MPLS_MULTICAST (int): EtherType ``0x8848`` — MPLS multicast.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

ETHERTYPE_MPLS_UNICAST: int = 0x8847
ETHERTYPE_MPLS_MULTICAST: int = 0x8848


@dataclass
class MPLSLabel:
    """One MPLS label stack entry (RFC 3032).

    The bottom-of-stack (S) bit is *not* stored here; it is computed
    automatically at build time from the position of this entry in the
    layer stack.

    Attributes:
        label: 20-bit label value (0–1048575).
        tc: Traffic Class — 3-bit value (0–7), formerly called EXP.
            Defaults to ``0``.
        ttl: Time-to-Live (0–255).  Defaults to ``64``.

    """

    label: int
    tc: int = 0
    ttl: int = 64

    def __post_init__(self) -> None:
        if not (0 <= self.label <= 0xFFFFF):
            raise ValueError(f"MPLS label must be 0-1048575, got {self.label}")
        if not (0 <= self.tc <= 7):
            raise ValueError(f"MPLS TC must be 0-7, got {self.tc}")
        if not (0 <= self.ttl <= 255):
            raise ValueError(f"MPLS TTL must be 0-255, got {self.ttl}")


def _build_mpls_label(entry: MPLSLabel, bottom_of_stack: bool) -> bytes:
    """Build one 4-byte MPLS label stack entry.

    Layout (RFC 3032)::

        Label (20) | TC (3) | S (1) | TTL (8)  ->  4 bytes

    Args:
        entry: The MPLS label fields.
        bottom_of_stack: When ``True``, the S bit is set to ``1``, indicating
            that this is the last entry in the label stack and the payload
            that follows is an IP packet (or other non-MPLS data).

    Returns:
        4 bytes in network (big-endian) byte order.

    Example::

        >>> from packeteer.generate.mpls import MPLSLabel, _build_mpls_label
        >>> raw = _build_mpls_label(MPLSLabel(label=100, tc=0, ttl=64), bottom_of_stack=True)
        >>> len(raw)
        4
        >>> (int.from_bytes(raw, "big") >> 8) & 1  # S bit
        1

    """
    s = 1 if bottom_of_stack else 0
    word = (entry.label << 12) | (entry.tc << 9) | (s << 8) | entry.ttl
    return struct.pack("!I", word)
