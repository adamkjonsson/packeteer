"""EtherIP tunnel header (RFC 3378).

EtherIP encapsulates a complete Ethernet frame inside an IP datagram.
The IP protocol number is 97 (``0x61``).  The header is exactly 2 bytes:
the top 4 bits are the version (always 3) and the remaining 12 bits are
reserved (always 0), so the wire representation is always ``0x30 0x00``.

Typical encapsulation::

    Outer Ethernet → Outer IP (proto=97) → EtherIP (2 B) → Inner Ethernet → Inner IP → Transport

Example — build an EtherIP tunnel packet::

    from packeteer.generate import PacketBuilder

    pkt = (PacketBuilder()
        .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .etherip()
        .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
        .ip(src="192.168.1.1", dst="192.168.1.2")
        .tcp(dst_port=80)
        .build()
    )
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

#: IP protocol number for EtherIP (RFC 3378).
IPPROTO_ETHERIP: int = 97


@dataclass
class EtherIPHeader:
    """EtherIP tunnel header (RFC 3378).

    No user-configurable fields.  The version is always 3 and the reserved
    bits are always 0, so the wire representation is always the two bytes
    ``0x30 0x00``.

    """

    pass


def _build_etherip_header() -> bytes:
    r"""Return the 2-byte EtherIP header (version=3, reserved=0).

    Returns:
        Two bytes: ``b"\x30\x00"``.

    """
    return struct.pack("!H", 0x3000)
