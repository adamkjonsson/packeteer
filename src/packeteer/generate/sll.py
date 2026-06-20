"""Linux "cooked" capture pseudo link-layer headers (SLL and SLL2).

`tcpdump -i any` records packets with a synthetic link-layer header instead of
the real Ethernet header, because the capture spans interfaces with potentially
different link layers.  Two formats exist:

* **SLL v1** (``LINKTYPE_LINUX_SLL`` = 113) — a 16-byte header.
* **SLL2** (``LINKTYPE_LINUX_SLL2`` = 276) — a 20-byte header, the default since
  libpcap 1.9 / tcpdump 4.99.

Both end with (SLL) or begin with (SLL2) a **Protocol Type** field that is an
EtherType (``0x0800`` IPv4, ``0x86DD`` IPv6, ``0x0806`` ARP, …), so the layer
that follows the cooked header is identified exactly as it is after an Ethernet
header.  Each carries a single link-layer address — the source MAC for an
Ethernet ``-i any`` capture — and a packet-type field giving the direction.

SLL v1 wire layout::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Packet Type          |         ARPHRD_ Type          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Link-layer Addr Length    |                               ~
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   Link-layer Address (8 bytes) ~
    ~                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        Protocol Type          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

SLL2 wire layout::

    Protocol Type (2) | Reserved (2) | Interface Index (4)
    ARPHRD_ Type (2)  | Packet Type (1) | Addr Length (1) | Address (8)

Example — a cooked-capture IPv4/TCP packet::

    from packeteer.generate import PacketBuilder

    pkt = (PacketBuilder()
        .sll(address="aa:bb:cc:00:00:01")
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .tcp(dst_port=80)
        .build()
    )
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from .ethernet import _parse_mac

#: SLL packet type: unicast addressed to the capturing host.
SLL_HOST: int = 0

#: SLL packet type: broadcast.
SLL_BROADCAST: int = 1

#: SLL packet type: multicast.
SLL_MULTICAST: int = 2

#: SLL packet type: addressed to another host (promiscuous capture).
SLL_OTHERHOST: int = 3

#: SLL packet type: sent by the capturing host.
SLL_OUTGOING: int = 4

#: ARPHRD hardware type for Ethernet.
ARPHRD_ETHER: int = 1

_SLL = struct.Struct(">HHH8sH")    # packet_type, arphrd, addr_len, addr(8), protocol
_SLL2 = struct.Struct(">HHIHBB8s")  # protocol, reserved, if_index, arphrd, ptype, addr_len, addr(8)


def _addr_bytes(address: str) -> tuple[bytes, int]:
    """Return ``(8-byte padded address, address length)`` for a MAC string."""
    if not address:
        return (b"\x00" * 8, 0)
    raw = _parse_mac(address)
    return (raw.ljust(8, b"\x00"), len(raw))


@dataclass
class SLLHeader:
    """Linux cooked-capture v1 pseudo header (``LINKTYPE_LINUX_SLL`` = 113).

    Attributes:
        packet_type: Direction / addressing — one of the ``SLL_*`` constants.
        arphrd_type: ARPHRD link-layer hardware type.  Defaults to
            :data:`ARPHRD_ETHER` (1).
        address: The single link-layer (MAC) address as a string, or ``""`` for
            none.

    """

    packet_type:  int = SLL_HOST
    arphrd_type:  int = ARPHRD_ETHER
    address:      str = "00:00:00:00:00:00"


@dataclass
class SLL2Header:
    """Linux cooked-capture v2 pseudo header (``LINKTYPE_LINUX_SLL2`` = 276).

    Attributes:
        packet_type: Direction / addressing — one of the ``SLL_*`` constants.
        arphrd_type: ARPHRD link-layer hardware type.  Defaults to
            :data:`ARPHRD_ETHER` (1).
        address: The single link-layer (MAC) address as a string, or ``""`` for
            none.
        if_index: Interface index the packet was captured on.  Defaults to ``0``.

    """

    packet_type:  int = SLL_HOST
    arphrd_type:  int = ARPHRD_ETHER
    address:      str = "00:00:00:00:00:00"
    if_index:     int = 0


def _build_sll_header(hdr: SLLHeader, protocol: int) -> bytes:
    """Build a 16-byte SLL v1 header carrying EtherType *protocol*."""
    addr, addr_len = _addr_bytes(hdr.address)
    return _SLL.pack(hdr.packet_type, hdr.arphrd_type, addr_len, addr, protocol)


def _build_sll2_header(hdr: SLL2Header, protocol: int) -> bytes:
    """Build a 20-byte SLL2 header carrying EtherType *protocol*."""
    addr, addr_len = _addr_bytes(hdr.address)
    return _SLL2.pack(
        protocol, 0, hdr.if_index, hdr.arphrd_type,
        hdr.packet_type, addr_len, addr,
    )
