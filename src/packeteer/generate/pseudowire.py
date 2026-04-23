"""RFC 4385 pseudowire control word.

A pseudowire (PW) transports a layer-2 service (typically Ethernet) across an
MPLS or IP network.  The optional 4-byte control word defined in RFC 4385 sits
between the bottom-of-stack MPLS label and the inner payload.  Its first nibble
is always ``0x0``, which distinguishes it from IPv4 (``0x4``) and IPv6
(``0x6``) when peeking at the byte immediately after the last MPLS label.

Wire layout::

     0               1               2               3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |0 0 0 0| Flags |FRG|  Length   |        Sequence Number        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Constants:
    ETHERTYPE_PW_CW (int): Internal sentinel value (``0xFFFE``) used by the
        parse pipeline to signal that a PW control word follows the last MPLS
        label.  This value never appears on the wire.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

#: Internal sentinel — never on the wire; used by the parse pipeline only.
ETHERTYPE_PW_CW: int = 0xFFFE


@dataclass
class PseudowireHeader:
    """RFC 4385 pseudowire control word.

    Attributes:
        flags: 4-bit flags field.  Bit 0 (MSB of nibble) is the L flag
            (local attachment circuit loss); bit 1 is the R flag (remote
            attachment circuit loss); bits 2-3 are reserved and must be 0.
        frag: 2-bit fragmentation field.  ``0b00`` means the payload is not
            fragmented.
        length: 6-bit length field.  Set to ``0`` for Ethernet pseudowires
            (the encapsulating layer carries the length).
        sequence: 16-bit sequence number.  ``0`` means sequencing is not used.

    """

    flags: int = 0
    frag: int = 0
    length: int = 0
    sequence: int = 0

    def __post_init__(self) -> None:
        if not (0 <= self.flags <= 0xF):
            raise ValueError(f"PW flags must be 0–15, got {self.flags}")
        if not (0 <= self.frag <= 3):
            raise ValueError(f"PW frag must be 0–3, got {self.frag}")
        if not (0 <= self.length <= 63):
            raise ValueError(f"PW length must be 0–63, got {self.length}")
        if not (0 <= self.sequence <= 0xFFFF):
            raise ValueError(f"PW sequence must be 0–65535, got {self.sequence}")


def _build_pseudowire_header(hdr: PseudowireHeader, payload: bytes) -> bytes:
    """Prepend the 4-byte RFC 4385 control word to *payload* and return the result.

    The first nibble of the control word is always ``0x0``, which distinguishes
    a pseudowire payload from IPv4 (version nibble ``0x4``) or IPv6 (``0x6``)
    when peeking after the bottom-of-stack MPLS label.

    Args:
        hdr: Control word fields.
        payload: Inner payload bytes (Ethernet frame or IP packet) that follow
            the control word on the wire.

    Returns:
        4-byte control word concatenated with *payload*.

    """
    word0 = ((hdr.flags & 0xF) << 8) | ((hdr.frag & 0x3) << 6) | (hdr.length & 0x3F)
    return struct.pack("!HH", word0, hdr.sequence) + payload
