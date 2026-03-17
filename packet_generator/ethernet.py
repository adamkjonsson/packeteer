"""Ethernet II frame header construction.

This module builds the 14-byte Ethernet II header that precedes an IP packet
on most wired and Wi-Fi networks.  The header contains destination MAC,
source MAC, and a two-byte EtherType that identifies the network-layer
protocol carried in the frame payload.

Constants:
    ETHERTYPE_IPV4 (int): EtherType ``0x0800`` — IPv4.
    ETHERTYPE_IPV6 (int): EtherType ``0x86DD`` — IPv6.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

ETHERTYPE_IPV4: int = 0x0800
ETHERTYPE_IPV6: int = 0x86DD


@dataclass
class EthernetHeader:
    """Fields of an Ethernet II frame header.

    Attributes:
        dst_mac: Destination MAC address as a colon- or hyphen-separated
            hex string, e.g. ``"aa:bb:cc:dd:ee:ff"`` or
            ``"aa-bb-cc-dd-ee-ff"``.
        src_mac: Source MAC address in the same format as *dst_mac*.
        ethertype: Two-byte EtherType field identifying the payload protocol.
            Use :data:`ETHERTYPE_IPV4` (``0x0800``) for IPv4 or
            :data:`ETHERTYPE_IPV6` (``0x86DD``) for IPv6.
            Defaults to :data:`ETHERTYPE_IPV4`.
    """

    dst_mac: str
    src_mac: str
    ethertype: int = ETHERTYPE_IPV4


def _parse_mac(mac: str) -> bytes:
    """Convert a human-readable MAC address string to 6 raw bytes.

    Args:
        mac: MAC address with ``':'`` or ``'-'`` separators,
            e.g. ``"aa:bb:cc:dd:ee:ff"``.

    Returns:
        Six bytes representing the MAC address in network byte order.
    """
    return bytes.fromhex(mac.replace(':', '').replace('-', ''))


def build_ethernet_header(hdr: EthernetHeader) -> bytes:
    """Build a 14-byte Ethernet II header.

    The returned bytes are ready to prepend directly to an IPv4 or IPv6
    packet to form a complete layer-2 frame.

    Args:
        hdr: An :class:`EthernetHeader` instance specifying the destination
            MAC, source MAC, and EtherType.

    Returns:
        Exactly 14 bytes: 6 (dst MAC) + 6 (src MAC) + 2 (EtherType), all in
        network (big-endian) byte order.

    Example:
        >>> from packet_generator.ethernet import EthernetHeader, build_ethernet_header, ETHERTYPE_IPV4
        >>> hdr = EthernetHeader("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", ETHERTYPE_IPV4)
        >>> raw = build_ethernet_header(hdr)
        >>> len(raw)
        14
        >>> raw[:6].hex()
        'aabbccddeeff'
    """
    return struct.pack(
        '!6s6sH',
        _parse_mac(hdr.dst_mac),
        _parse_mac(hdr.src_mac),
        hdr.ethertype,
    )
