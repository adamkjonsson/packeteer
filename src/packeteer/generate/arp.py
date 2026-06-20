"""Address Resolution Protocol (ARP) packet construction (RFC 826).

ARP maps a protocol address (an IPv4 address) to a hardware address (a MAC
address) on a local link.  It is carried directly inside an Ethernet frame with
EtherType ``0x0806`` — there is no IP layer, and nothing follows the ARP packet.

This module models the overwhelmingly common case: ARP for IPv4 over Ethernet,
with hardware-address length 6 and protocol-address length 4.  The sender and
target addresses are expressed as MAC and IPv4 strings.  The ``hardware_type``,
``protocol_type``, and ``operation`` fields are overridable, so RARP (operations
3 / 4), gratuitous ARP, ARP probes, and announcements are all expressible.

Wire layout (28 octets for IPv4-over-Ethernet)::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Hardware Type         |         Protocol Type         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   HLEN = 6    |   PLEN = 4    |           Operation           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                  Sender Hardware Address (6)                  ~
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ~  Sender HW (cont.)  |          Sender Protocol Address (4)    ~
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ~  SPA (cont.)  |             Target Hardware Address (6)       ~
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ~          THA (cont.)          |  Target Protocol Address (4)  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Example — an ARP request asking who has 10.0.0.2::

    from packeteer.generate import PacketBuilder

    pkt = (PacketBuilder()
        .ethernet(src_mac="aa:bb:cc:00:00:01", dst_mac="ff:ff:ff:ff:ff:ff")
        .arp(sender_mac="aa:bb:cc:00:00:01", sender_ip="10.0.0.1",
             target_ip="10.0.0.2")
        .build()
    )
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

from .ethernet import ETHERTYPE_IPV4, _parse_mac

#: ARP operation: request ("who has TPA?").
ARP_OP_REQUEST: int = 1

#: ARP operation: reply ("TPA is at THA").
ARP_OP_REPLY: int = 2

#: RARP operation: request.
ARP_OP_RARP_REQUEST: int = 3

#: RARP operation: reply.
ARP_OP_RARP_REPLY: int = 4

#: ARP hardware type for Ethernet.
ARP_HW_ETHERNET: int = 1

_HEADER = struct.Struct(">HHBBH")   # htype, ptype, hlen, plen, operation


@dataclass
class ARPHeader:
    """An ARP packet for IPv4 over Ethernet (RFC 826).

    Attributes:
        operation: ARP operation code — :data:`ARP_OP_REQUEST` (1),
            :data:`ARP_OP_REPLY` (2), or a RARP code (3 / 4).
        sender_mac: Sender hardware (MAC) address.
        sender_ip: Sender protocol (IPv4) address.
        target_mac: Target hardware (MAC) address.  Conventionally all-zero
            (``"00:00:00:00:00:00"``) in a request, since it is unknown.
        target_ip: Target protocol (IPv4) address.
        hardware_type: Hardware type.  Defaults to :data:`ARP_HW_ETHERNET` (1).
        protocol_type: Protocol type (an EtherType).  Defaults to
            :data:`~packeteer.generate.ethernet.ETHERTYPE_IPV4` (``0x0800``).

    """

    operation:     int = ARP_OP_REQUEST
    sender_mac:    str = "00:00:00:00:00:01"
    sender_ip:     str = "0.0.0.0"
    target_mac:    str = "00:00:00:00:00:00"
    target_ip:     str = "0.0.0.0"
    hardware_type: int = ARP_HW_ETHERNET
    protocol_type: int = ETHERTYPE_IPV4


def _build_arp_header(hdr: ARPHeader) -> bytes:
    """Return the 28-byte ARP packet bytes for *hdr* (IPv4 over Ethernet).

    Args:
        hdr: The :class:`ARPHeader` to encode.

    Returns:
        Exactly 28 bytes in network byte order.

    Raises:
        OSError: If a sender/target IP string is not a valid IPv4 address.

    """
    return (
        _HEADER.pack(hdr.hardware_type, hdr.protocol_type, 6, 4, hdr.operation)
        + _parse_mac(hdr.sender_mac)
        + socket.inet_aton(hdr.sender_ip)
        + _parse_mac(hdr.target_mac)
        + socket.inet_aton(hdr.target_ip)
    )
