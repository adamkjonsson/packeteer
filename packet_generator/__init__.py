"""packet_generator — build complete raw network packets in pure Python.

This package constructs byte-accurate network packets at all layers:

* **Layer 2** — Ethernet II frames (:class:`EthernetHeader`)
* **Layer 3** — IPv4 (:class:`IPHeader`) and IPv6 (:class:`IPv6Header`)
* **Layer 4** — TCP (:class:`TCPHeader`), UDP (:class:`UDPHeader`),
  ICMPv4 (:class:`ICMPHeader`), ICMPv6 (:class:`ICMPv6Header`)

All IP and transport-layer checksums are computed automatically per their
respective RFCs (RFC 791, RFC 8200, RFC 768, RFC 793, RFC 792, RFC 4443).

Fragmentation is supported via :meth:`PacketBuilder.fragment` (high-level)
or the low-level :func:`fragment_ipv4` and :func:`fragment_ipv6` functions.

The recommended entry point is :class:`PacketBuilder`, which wires all
layers together and exposes a clean, high-level API:

.. code-block:: python

    from packet_generator import PacketBuilder, Protocol

    # IPv4 TCP packet (Ethernet + IP + TCP + 64 random payload bytes)
    pkt = PacketBuilder(
        src_ip="192.168.1.1",
        dst_ip="8.8.8.8",
        protocol=Protocol.TCP,
        payload_size=64,
        dst_port=443,
    ).build()

    # IPv6 UDP packet without Ethernet header
    pkt = PacketBuilder(
        src_ip="fe80::1",
        dst_ip="fe80::2",
        protocol=Protocol.UDP,
        payload_size=20,
        include_ethernet=False,
    ).build()

    # ICMPv6 Echo Request with explicit payload
    pkt = PacketBuilder(
        src_ip="::1",
        dst_ip="::2",
        protocol=Protocol.ICMPv6,
        payload=b"hello ipv6",
    ).build()

Public API:
    PacketBuilder: High-level packet assembly class.
    Protocol: Enum of supported transport protocols (TCP, UDP, ICMP, ICMPv6).
    EthernetHeader: Dataclass for Ethernet II header fields.
    VLANTag: Dataclass for IEEE 802.1Q VLAN tag fields.
    IPHeader: Dataclass for IPv4 header fields.
    IPv6Header: Dataclass for IPv6 header fields.
    TCPHeader: Dataclass for TCP header fields.
    UDPHeader: Dataclass for UDP header fields.
    ICMPHeader: Dataclass for ICMPv4 header fields.
    ICMPv6Header: Dataclass for ICMPv6 header fields.
"""
from __future__ import annotations

from .builder import PacketBuilder, Protocol
from .ethernet import EthernetHeader, VLANTag
from .fragmentation import fragment_ipv4, fragment_ipv6
from .ip import IPHeader
from .ipv6 import IPv6Header
from .tcp import TCPHeader
from .udp import UDPHeader
from .icmp import ICMPHeader
from .icmpv6 import ICMPv6Header

__all__ = [
    "PacketBuilder",
    "Protocol",
    "EthernetHeader",
    "VLANTag",
    "IPHeader",
    "IPv6Header",
    "TCPHeader",
    "UDPHeader",
    "ICMPHeader",
    "ICMPv6Header",
    "fragment_ipv4",
    "fragment_ipv6",
]
