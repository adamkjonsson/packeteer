"""VXLAN tunnel header (RFC 7348).

VXLAN (Virtual eXtensible Local Area Network) encapsulates a complete inner
Ethernet frame inside an outer UDP datagram.  Unlike the IP-protocol tunnels
(GRE, EtherIP, IP-in-IP), VXLAN is identified by the **outer UDP destination
port** (IANA-assigned ``4789``) rather than an IP protocol number.

The VXLAN header is exactly 8 bytes::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |R|R|R|R|I|R|R|R|            Reserved                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                VXLAN Network Identifier (VNI) |   Reserved    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The **I** flag (bit 3 of the first byte, value ``0x08``) MUST be set to ``1`` to
indicate that the VNI field is valid; all other flag bits and the reserved
fields are transmitted as ``0`` and ignored on receipt.  The **VNI** is a
24-bit segment identifier carried in the high three octets of the second word.

Typical encapsulation::

    Outer Ethernet → Outer IP → Outer UDP (dst 4789) → VXLAN (8 B)
        → Inner Ethernet → Inner IP → Transport

Example — build a VXLAN packet carrying an inner IPv4/TCP frame::

    from packeteer.generate import PacketBuilder
    from packeteer.generate.vxlan import VXLAN_PORT

    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .udp(dst_port=VXLAN_PORT)
        .vxlan(vni=5000)
        .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
        .ip(src="192.168.1.1", dst="192.168.1.2")
        .tcp(dst_port=80)
        .build()
    )
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

#: IANA-assigned UDP destination port for VXLAN (RFC 7348).
VXLAN_PORT: int = 4789

#: VXLAN flags byte value with the I (VNI valid) bit set.
VXLAN_FLAG_VALID_VNI: int = 0x08

_HEADER = struct.Struct(">BxxxI")   # flags, 3 reserved bytes, (VNI<<8 | reserved)


@dataclass
class VXLANHeader:
    """VXLAN tunnel header (RFC 7348).

    Attributes:
        vni: 24-bit VXLAN Network Identifier (0–16777215).
        flags: 8-bit flags field.  Defaults to :data:`VXLAN_FLAG_VALID_VNI`
            (``0x08``), which sets the I bit marking the VNI as valid.

    """

    vni:   int = 0
    flags: int = VXLAN_FLAG_VALID_VNI


def _build_vxlan_header(hdr: VXLANHeader) -> bytes:
    """Return the 8-byte VXLAN header bytes for *hdr*.

    The VNI occupies the high 24 bits of the final 32-bit word; the low octet
    is reserved and transmitted as ``0``.

    Args:
        hdr: :class:`VXLANHeader` describing the flags and VNI.

    Returns:
        Exactly 8 bytes.

    """
    return _HEADER.pack(hdr.flags & 0xFF, (hdr.vni & 0xFFFFFF) << 8)
