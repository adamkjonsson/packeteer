"""Ethernet II frame header construction.

This module builds the 14-byte Ethernet II header (18 bytes when an IEEE
802.1Q VLAN tag is present) that precedes an IP packet on most wired and
Wi-Fi networks.  The header contains destination MAC, source MAC, an
optional 802.1Q VLAN tag, and a two-byte EtherType that identifies the
network-layer protocol carried in the frame payload.

Constants:
    ETHERTYPE_IPV4 (int): EtherType ``0x0800`` — IPv4.
    ETHERTYPE_IPV6 (int): EtherType ``0x86DD`` — IPv6.
    ETHERTYPE_8021Q (int): Tag Protocol Identifier ``0x8100`` — IEEE 802.1Q.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

ETHERTYPE_IPV4: int = 0x0800
ETHERTYPE_IPV6: int = 0x86DD
ETHERTYPE_8021Q: int = 0x8100

# IEEE 802.3 minimum frame size (excluding the 4-byte FCS that NICs append
# in hardware).  Frames shorter than this must be zero-padded to reach 60 bytes
# of header + payload before the FCS is added by the hardware.
ETHERNET_MIN_FRAME_SIZE: int = 60


@dataclass
class VLANTag:
    """IEEE 802.1Q VLAN tag fields.

    When included in an :class:`EthernetHeader` the tag is inserted between
    the source MAC address and the EtherType, expanding the frame header from
    14 to 18 bytes.  The outer EtherType is set to ``0x8100`` (TPID) and the
    original EtherType becomes the inner EtherType after the TCI.

    Attributes:
        vid: VLAN Identifier — 12-bit value (1–4094) identifying the VLAN.
            ``0`` means the frame carries no specific VLAN (priority tag only).
            ``4095`` (``0xFFF``) is reserved.
        pcp: Priority Code Point — 3-bit value (0–7) carrying IEEE 802.1p
            class-of-service information.  Defaults to ``0``.
        dei: Drop Eligible Indicator — 1-bit flag (0 or 1) indicating the
            frame may be dropped under congestion.  Defaults to ``0``.

    """

    vid: int
    pcp: int = 0
    dei: int = 0

    def __post_init__(self) -> None:
        if not (0 <= self.vid <= 4095):
            raise ValueError(f"VLAN ID must be 0–4095, got {self.vid}")
        if not (0 <= self.pcp <= 7):
            raise ValueError(f"PCP must be 0–7, got {self.pcp}")
        if self.dei not in (0, 1):
            raise ValueError(f"DEI must be 0 or 1, got {self.dei}")

    def tci(self) -> int:
        """Return the 16-bit Tag Control Information field value."""
        return (self.pcp << 13) | (self.dei << 12) | self.vid


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
        vlan_tag: Optional IEEE 802.1Q VLAN tag.  When set, the frame header
            grows from 14 to 18 bytes: the outer EtherType becomes ``0x8100``
            (TPID), followed by the 2-byte TCI, followed by the original
            *ethertype* as the inner EtherType.

    """

    dst_mac: str
    src_mac: str
    ethertype: int = ETHERTYPE_IPV4
    vlan_tag: VLANTag | None = None
    pad: bool = False


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
    """Build an Ethernet II header (14 bytes, or 18 bytes with a VLAN tag).

    The returned bytes are ready to prepend directly to an IPv4 or IPv6
    packet to form a complete layer-2 frame.

    Without a VLAN tag the layout is::

        dst_mac (6) | src_mac (6) | EtherType (2)  →  14 bytes

    With an IEEE 802.1Q VLAN tag the layout is::

        dst_mac (6) | src_mac (6) | TPID=0x8100 (2) | TCI (2) | EtherType (2)  →  18 bytes

    Args:
        hdr: An :class:`EthernetHeader` instance specifying the destination
            MAC, source MAC, optional VLAN tag, and EtherType.

    Returns:
        14 bytes without a VLAN tag, or 18 bytes with one, all in network
        (big-endian) byte order.

    Example:
        >>> from packet_generator.ethernet import (  # noqa: E501
        ...     EthernetHeader, build_ethernet_header, ETHERTYPE_IPV4,
        ... )
        >>> hdr = EthernetHeader("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", ETHERTYPE_IPV4)
        >>> raw = build_ethernet_header(hdr)
        >>> len(raw)
        14
        >>> raw[:6].hex()
        'aabbccddeeff'

    """
    dst = _parse_mac(hdr.dst_mac)
    src = _parse_mac(hdr.src_mac)

    if hdr.vlan_tag is not None:
        return struct.pack(
            '!6s6sHHH',
            dst,
            src,
            ETHERTYPE_8021Q,    # outer EtherType / TPID
            hdr.vlan_tag.tci(), # Tag Control Information
            hdr.ethertype,      # inner EtherType
        )

    return struct.pack(
        '!6s6sH',
        dst,
        src,
        hdr.ethertype,
    )
