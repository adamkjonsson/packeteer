"""Parser for ARP packets (RFC 826), IPv4 over Ethernet.

Follows the same ``(header_size, next_layer_id, HeaderObject | None)``
convention as all other ``packet_parser`` modules.  ``next_layer_id`` is always
``None`` because ARP is a terminal protocol — nothing follows it.

Only the common Ethernet/IPv4 case (hardware-address length 6, protocol-address
length 4) is decoded; other HLEN/PLEN combinations return ``(0, None, None)`` so
the bytes fall through to the packet payload.
"""
from __future__ import annotations

import socket
import struct

from packeteer.generate.arp import ARPHeader

_HEADER = struct.Struct(">HHBBH")   # htype, ptype, hlen, plen, operation


def packet_parser(data: bytes) -> tuple[int, None, ARPHeader | None]:
    """Parse a 28-byte Ethernet/IPv4 ARP packet (RFC 826).

    Args:
        data: Raw bytes starting at the ARP packet.

    Returns:
        ``(28, None, ARPHeader(...))`` on success.  ``(0, None, None)`` when
        *data* is shorter than 28 bytes or HLEN/PLEN are not 6/4.

    """
    if len(data) < 28:
        return (0, None, None)
    htype, ptype, hlen, plen, operation = _HEADER.unpack_from(data, 0)
    if hlen != 6 or plen != 4:
        return (0, None, None)
    sha = ":".join(f"{b:02x}" for b in data[8:14])
    spa = socket.inet_ntoa(data[14:18])
    tha = ":".join(f"{b:02x}" for b in data[18:24])
    tpa = socket.inet_ntoa(data[24:28])
    hdr = ARPHeader(
        operation=operation,
        sender_mac=sha, sender_ip=spa,
        target_mac=tha, target_ip=tpa,
        hardware_type=htype, protocol_type=ptype,
    )
    return (28, None, hdr)
