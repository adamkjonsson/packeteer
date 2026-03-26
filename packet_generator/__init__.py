"""packet_generator — build complete raw network packets in pure Python.

This package constructs byte-accurate network packets at all layers:

* **Layer 2** — Ethernet II frames (:class:`EthernetHeader`), IEEE 802.1Q
  VLAN tags (:class:`VLANTag`), PPPoE session and discovery frames
  (:class:`PPPoEHeader`, :class:`PPPoETag`)
* **Layer 2.5** — MPLS label stacks (:class:`MPLSLabel`, RFC 3032)
* **Layer 3** — IPv4 (:class:`IPHeader`) and IPv6 (:class:`IPv6Header`)
* **Layer 4** — TCP (:class:`TCPHeader`), UDP (:class:`UDPHeader`),
  ICMPv4 (:class:`ICMPHeader`), ICMPv6 (:class:`ICMPv6Header`)

All IP and transport-layer checksums are computed automatically per their
respective RFCs (RFC 791, RFC 8200, RFC 768, RFC 793, RFC 792, RFC 4443).

Fragmentation is supported via :meth:`PacketBuilder.fragment` (high-level)
or the low-level :func:`fragment_ipv4` and :func:`fragment_ipv6` functions.

The recommended entry point is :class:`PacketBuilder`, which wires all
layers together and exposes a clean, high-level API.  Each fluent method
**appends** a layer to an ordered stack, so the same method can be called
multiple times to produce advanced encapsulations.

.. code-block:: python

    from packet_generator import PacketBuilder

    # IPv4 TCP packet (Ethernet + IP + TCP + 64 random payload bytes)
    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="192.168.1.1", dst="8.8.8.8")
        .tcp(dst_port=443)
        .payload(size=64)
        .build()
    )

    # IPv6 UDP packet without Ethernet header
    pkt = (PacketBuilder()
        .ip(src="fe80::1", dst="fe80::2")
        .udp()
        .payload(size=20)
        .build()
    )

    # ICMPv6 Echo Request with explicit payload
    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="::1", dst="::2")
        .icmpv6()
        .payload(data=b"hello ipv6")
        .build()
    )

    # QinQ (802.1ad) double-tagged frame — call .vlan() twice
    pkt = (PacketBuilder()
        .ethernet()
        .vlan(vid=100)   # outer VLAN
        .vlan(vid=200)   # inner VLAN
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .udp()
        .build()
    )

    # MPLS label stack — call .mpls() for each label (RFC 3032)
    pkt = (PacketBuilder()
        .ethernet()
        .mpls(label=100)   # outer label (S=0)
        .mpls(label=200)   # inner label (S=1, bottom of stack)
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .udp()
        .build()
    )

    # IP-in-IP tunnel — call .ip() twice
    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="203.0.113.1", dst="203.0.113.2")
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .tcp(dst_port=80)
        .build()
    )

    # PPPoE session carrying IPv4 TCP (RFC 2516)
    pkt = (PacketBuilder()
        .ethernet()
        .pppoe(session_id=0x1234)
        .ip(src="10.0.0.1", dst="8.8.8.8")
        .tcp(dst_port=80)
        .build()
    )

    # PPPoE PADI discovery frame
    from packet_generator import PPPOE_CODE_PADI, PPPoETag, PPPOE_TAG_SERVICE_NAME
    pkt = (PacketBuilder()
        .ethernet(dst_mac="ff:ff:ff:ff:ff:ff")
        .pppoe(code=PPPOE_CODE_PADI, tags=[PPPoETag(PPPOE_TAG_SERVICE_NAME, b"")])
        .build()
    )

Public API:
    PacketBuilder: High-level packet assembly class.
    EthernetHeader: Dataclass for Ethernet II header fields (dst_mac, src_mac, ethertype, vlan_tag, pad).
    VLANTag: Dataclass for IEEE 802.1Q VLAN tag fields.
    MPLSLabel: Dataclass for one MPLS label stack entry (RFC 3032).
    ETHERTYPE_MPLS_UNICAST: EtherType 0x8847 — MPLS unicast.
    ETHERTYPE_MPLS_MULTICAST: EtherType 0x8848 — MPLS multicast.
    PPPoEHeader: Dataclass for a PPPoE frame header (RFC 2516).
    PPPoETag: Dataclass for one PPPoE TLV tag.
    ETHERTYPE_PPPOE_DISCOVERY: EtherType 0x8863 — PPPoE discovery.
    ETHERTYPE_PPPOE_SESSION: EtherType 0x8864 — PPPoE session.
    PPP_IPV4: PPP protocol number 0x0021 — IPv4.
    PPP_IPV6: PPP protocol number 0x0057 — IPv6.
    PPPOE_CODE_SESSION, PPPOE_CODE_PADI, PPPOE_CODE_PADO, PPPOE_CODE_PADR,
        PPPOE_CODE_PADS, PPPOE_CODE_PADT: PPPoE message code constants.
    PPPOE_TAG_SERVICE_NAME, PPPOE_TAG_AC_NAME, PPPOE_TAG_HOST_UNIQ,
        PPPOE_TAG_AC_COOKIE, PPPOE_TAG_GENERIC_ERROR: PPPoE tag type constants.
    IPHeader: Dataclass for IPv4 header fields.
    IPv6Header: Dataclass for IPv6 header fields.
    TCPHeader: Dataclass for TCP header fields.
    TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG, TCP_ECE, TCP_CWR: TCP flag bit-mask constants.
    TCPOptions: Dataclass for TCP header options (MSS, Window Scale, SACK, Timestamps).
    UDPHeader: Dataclass for UDP header fields.
    ICMPHeader: Dataclass for ICMPv4 header fields.
    ICMPv6Header: Dataclass for ICMPv6 header fields.
    write_pcap: Write raw packet bytes to a libpcap (.pcap) file.
    write_pcapng: Write raw packet bytes to a pcapng (.pcapng) file.
    LINKTYPE_ETHERNET: pcap/pcapng link-layer type 1 — Ethernet II.
    LINKTYPE_RAW: pcap/pcapng link-layer type 101 — raw IP (no Ethernet header).
"""
from __future__ import annotations

from .builder import PacketBuilder
from .ethernet import EthernetHeader, VLANTag, ETHERNET_MIN_FRAME_SIZE
from .pcap import write_pcap, write_pcapng, LINKTYPE_ETHERNET, LINKTYPE_RAW
from .fragmentation import fragment_ipv4, fragment_ipv6
from .ip import IPHeader
from .ipv6 import IPv6Header
from .mpls import MPLSLabel, ETHERTYPE_MPLS_UNICAST, ETHERTYPE_MPLS_MULTICAST
from .pppoe import (
    PPPoEHeader, PPPoETag,
    ETHERTYPE_PPPOE_DISCOVERY, ETHERTYPE_PPPOE_SESSION,
    PPP_IPV4, PPP_IPV6,
    PPPOE_CODE_SESSION, PPPOE_CODE_PADI, PPPOE_CODE_PADO,
    PPPOE_CODE_PADR, PPPOE_CODE_PADS, PPPOE_CODE_PADT,
    PPPOE_TAG_SERVICE_NAME, PPPOE_TAG_AC_NAME, PPPOE_TAG_HOST_UNIQ,
    PPPOE_TAG_AC_COOKIE, PPPOE_TAG_GENERIC_ERROR,
)
from .tcp import (
    TCPHeader, TCPOptions,
    TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG, TCP_ECE, TCP_CWR,
)
from .udp import UDPHeader
from .icmp import ICMPHeader
from .icmpv6 import ICMPv6Header

__all__ = [
    "PacketBuilder",
    "EthernetHeader",
    "VLANTag",
    "ETHERNET_MIN_FRAME_SIZE",
    "IPHeader",
    "IPv6Header",
    "TCPHeader",
    "TCPOptions",
    "TCP_FIN",
    "TCP_SYN",
    "TCP_RST",
    "TCP_PSH",
    "TCP_ACK",
    "TCP_URG",
    "TCP_ECE",
    "TCP_CWR",
    "UDPHeader",
    "ICMPHeader",
    "ICMPv6Header",
    "MPLSLabel",
    "ETHERTYPE_MPLS_UNICAST",
    "ETHERTYPE_MPLS_MULTICAST",
    "PPPoEHeader",
    "PPPoETag",
    "ETHERTYPE_PPPOE_DISCOVERY",
    "ETHERTYPE_PPPOE_SESSION",
    "PPP_IPV4",
    "PPP_IPV6",
    "PPPOE_CODE_SESSION",
    "PPPOE_CODE_PADI",
    "PPPOE_CODE_PADO",
    "PPPOE_CODE_PADR",
    "PPPOE_CODE_PADS",
    "PPPOE_CODE_PADT",
    "PPPOE_TAG_SERVICE_NAME",
    "PPPOE_TAG_AC_NAME",
    "PPPOE_TAG_HOST_UNIQ",
    "PPPOE_TAG_AC_COOKIE",
    "PPPOE_TAG_GENERIC_ERROR",
    "fragment_ipv4",
    "fragment_ipv6",
    "write_pcap",
    "write_pcapng",
    "LINKTYPE_ETHERNET",
    "LINKTYPE_RAW",
]
