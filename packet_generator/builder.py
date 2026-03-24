"""High-level packet builder API.

This module exposes :class:`PacketBuilder` — the primary entry point for
constructing and fragmenting complete raw network packets using a fluent,
layer-by-layer API.

Typical usage::

    from packet_generator import PacketBuilder

    # IPv4 TCP packet with Ethernet header and 64 bytes of random payload
    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="192.168.1.10", dst="8.8.8.8")
        .tcp(dst_port=443)
        .payload(size=64)
        .build()
    )

    # IPv6 UDP packet without Ethernet framing
    pkt = (PacketBuilder()
        .ip(src="fe80::1", dst="fe80::2")
        .udp(dst_port=5353)
        .payload(size=20)
        .build()
    )

    # ICMPv6 ping with explicit payload
    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="::1", dst="::2")
        .icmpv6()
        .payload(data=b"hello ipv6")
        .build()
    )
"""
from __future__ import annotations

import os
import socket

from .ethernet import (
    EthernetHeader, VLANTag, ETHERTYPE_IPV4, ETHERTYPE_IPV6,
    ETHERNET_MIN_FRAME_SIZE, build_ethernet_header,
)
from .ip import IPHeader, build_ip_header
from .ipv6 import IPv6Header, build_ipv6_header
from .tcp import TCPHeader, TCPOptions, TCP_ACK, build_tcp_header
from .udp import UDPHeader, build_udp_header
from .icmp import ICMPHeader, build_icmp_header
from .icmpv6 import ICMPv6Header, build_icmpv6_header


def _detect_ip_version(addr: str) -> int:
    """Return ``4`` or ``6`` depending on whether *addr* is IPv4 or IPv6.

    Args:
        addr: An IP address string in any format accepted by the socket
            module (dotted-decimal for IPv4, colon-hex for IPv6).

    Returns:
        ``6`` if *addr* is a valid IPv6 address, otherwise ``4``.

    Raises:
        OSError: If *addr* is neither a valid IPv4 nor a valid IPv6 address.
    """
    try:
        socket.inet_pton(socket.AF_INET6, addr)
        return 6
    except OSError:
        socket.inet_aton(addr)  # raises OSError if invalid IPv4
        return 4


class PacketBuilder:
    """Assembles complete raw network packets layer by layer.

    Call the fluent layer methods in order, then call :meth:`build` or
    :meth:`fragment` to produce the final bytes.  The IP version (4 or 6)
    is detected automatically from the address passed to :meth:`ip`.
    All checksums are computed correctly per their respective RFCs.

    Example::

        from packet_generator import PacketBuilder

        pkt = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .tcp(dst_port=443)
            .payload(size=40)
            .build()
        )
        print(f"Built {len(pkt)}-byte packet")
    """

    def __init__(self) -> None:
        self._eth_src_mac: str = "00:00:00:00:00:01"
        self._eth_dst_mac: str = "00:00:00:00:00:02"
        self._eth: bool = False          # True when .ethernet() has been called
        self._vlan: VLANTag | None = None
        self._pad_ethernet: bool = False
        self._ip: IPHeader | IPv6Header | None = None
        self._transport_hdr: TCPHeader | UDPHeader | ICMPHeader | ICMPv6Header | None = None
        self._payload_size: int = 0
        self._payload_data: bytes | None = None
        self._cached_payload: bytes | None = None

    # ── layer configuration methods ──────────────────────────────────────────

    def ethernet(
        self,
        *,
        src_mac: str = "00:00:00:00:00:01",
        dst_mac: str = "00:00:00:00:00:02",
        pad: bool = False,
    ) -> "PacketBuilder":
        """Add an Ethernet II header to the packet.

        Omitting this call produces a raw IP packet with no layer-2 framing.

        Args:
            src_mac: Source MAC address (colon- or hyphen-separated hex).
            dst_mac: Destination MAC address.
            pad: When ``True``, zero-pad the assembled frame to the IEEE 802.3
                minimum of 60 bytes when the frame would otherwise be shorter.
        """
        self._eth = True
        self._eth_src_mac = src_mac
        self._eth_dst_mac = dst_mac
        self._pad_ethernet = pad
        return self

    def vlan(self, *, vid: int, pcp: int = 0, dei: int = 0) -> "PacketBuilder":
        """Add an IEEE 802.1Q VLAN tag to the Ethernet header.

        Only meaningful when :meth:`ethernet` has also been called.  Inserts a
        4-byte tag (TPID ``0x8100`` + TCI) expanding the Ethernet header from
        14 to 18 bytes.

        Args:
            vid: VLAN ID (1–4094).
            pcp: Priority Code Point (0–7).
            dei: Drop Eligible Indicator (0 or 1).
        """
        self._vlan = VLANTag(vid, pcp, dei)
        return self

    def ip(
        self,
        *,
        src: str,
        dst: str,
        ttl: int = 64,
        # IPv4-specific
        tos: int = 0,
        identification: int = 0,
        flags: int = 0b010,
        fragment_offset: int = 0,
        # IPv6-specific
        traffic_class: int = 0,
        flow_label: int = 0,
    ) -> "PacketBuilder":
        """Add an IP header.  IPv4 or IPv6 is auto-detected from *src*.

        IPv4-specific parameters (``tos``, ``identification``, ``flags``,
        ``fragment_offset``) are ignored when *src* is an IPv6 address, and
        vice versa for IPv6-specific parameters.

        Args:
            src: Source IP address (dotted-decimal IPv4 or colon-hex IPv6).
            dst: Destination IP address in the same format.
            ttl: Time-To-Live (IPv4) or Hop Limit (IPv6).  Defaults to ``64``.
            tos: IPv4 Type of Service / DSCP+ECN byte.
            identification: IPv4 Identification field.
            flags: IPv4 3-bit Flags field (bit 1 = DF).  Defaults to ``0b010``.
            fragment_offset: IPv4 Fragment Offset in 8-byte units.
            traffic_class: IPv6 Traffic Class (DSCP + ECN).
            flow_label: IPv6 Flow Label (20-bit value).

        Raises:
            OSError: If *src* is not a valid IPv4 or IPv6 address.
        """
        if _detect_ip_version(src) == 6:
            self._ip = IPv6Header(
                src, dst, next_header=0,  # filled in by build()/fragment()
                hop_limit=ttl,
                traffic_class=traffic_class,
                flow_label=flow_label,
            )
        else:
            self._ip = IPHeader(
                src, dst, protocol=0,     # filled in by build()/fragment()
                ttl=ttl,
                tos=tos,
                identification=identification,
                flags=flags,
                fragment_offset=fragment_offset,
            )
        return self

    def tcp(
        self,
        *,
        src_port: int = 12345,
        dst_port: int = 80,
        seq: int = 0,
        ack: int = 0,
        flags: int = TCP_ACK,
        window: int = 65535,
        urgent_ptr: int = 0,
        reserved: int = 0,
        options: TCPOptions | None = None,
    ) -> "PacketBuilder":
        """Add a TCP transport header."""
        self._transport_hdr = TCPHeader(
            src_port, dst_port,
            seq=seq, ack=ack, flags=flags,
            window=window, urgent_ptr=urgent_ptr,
            reserved=reserved, options=options,
        )
        return self

    def udp(self, *, src_port: int = 12345, dst_port: int = 80) -> "PacketBuilder":
        """Add a UDP transport header."""
        self._transport_hdr = UDPHeader(src_port, dst_port)
        return self

    def icmp(
        self,
        *,
        type: int = 8,
        code: int = 0,
        identifier: int = 1,
        sequence: int = 1,
    ) -> "PacketBuilder":
        """Add an ICMPv4 transport header.  Requires an IPv4 address in :meth:`ip`."""
        self._transport_hdr = ICMPHeader(
            type=type, code=code, identifier=identifier, sequence=sequence,
        )
        return self

    def icmpv6(
        self,
        *,
        type: int = 128,
        code: int = 0,
        identifier: int = 1,
        sequence: int = 1,
    ) -> "PacketBuilder":
        """Add an ICMPv6 transport header.  Requires an IPv6 address in :meth:`ip`."""
        self._transport_hdr = ICMPv6Header(
            type=type, code=code, identifier=identifier, sequence=sequence,
        )
        return self

    def payload(self, *, size: int = 0, data: bytes | None = None) -> "PacketBuilder":
        """Set the packet payload.

        Args:
            size: Generate this many random bytes as the payload.  Ignored
                when *data* is provided.
            data: Explicit payload bytes.  Takes precedence over *size*.
        """
        self._payload_size = size
        self._payload_data = data
        self._cached_payload = None   # invalidate cache if called again
        return self

    # ── internal helpers ─────────────────────────────────────────────────────

    @property
    def _payload_bytes(self) -> bytes:
        """Lazily generate (and cache) the payload bytes."""
        if self._cached_payload is None:
            self._cached_payload = (
                self._payload_data
                if self._payload_data is not None
                else os.urandom(self._payload_size)
            )
        return self._cached_payload

    def _build_transport(self, data: bytes) -> tuple[bytes, int]:
        """Build the transport header and return ``(header_bytes, proto_num)``.

        *proto_num* is the IP protocol number (6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6).
        """
        assert self._ip is not None  # guaranteed by _validate()
        ip_version = 6 if isinstance(self._ip, IPv6Header) else 4
        src_ip = self._ip.src
        dst_ip = self._ip.dst

        if isinstance(self._transport_hdr, TCPHeader):
            return build_tcp_header(self._transport_hdr, data, src_ip, dst_ip, ip_version), 6
        if isinstance(self._transport_hdr, UDPHeader):
            return build_udp_header(self._transport_hdr, data, src_ip, dst_ip, ip_version), 17
        if isinstance(self._transport_hdr, ICMPHeader):
            return build_icmp_header(self._transport_hdr, data), socket.IPPROTO_ICMP
        if isinstance(self._transport_hdr, ICMPv6Header):
            return build_icmpv6_header(self._transport_hdr, data, src_ip, dst_ip), 58
        raise ValueError(f"Unknown transport type: {type(self._transport_hdr)}")

    def _build_network(self, ip_payload: bytes, proto: int) -> tuple[bytes, int]:
        """Build the IP header and return ``(header_bytes, ethertype)``."""
        assert self._ip is not None  # guaranteed by _validate()
        if isinstance(self._ip, IPv6Header):
            network = build_ipv6_header(
                IPv6Header(
                    self._ip.src, self._ip.dst, proto,
                    hop_limit=self._ip.hop_limit,
                    traffic_class=self._ip.traffic_class,
                    flow_label=self._ip.flow_label,
                ),
                ip_payload,
            )
            return network, ETHERTYPE_IPV6
        else:
            network = build_ip_header(
                IPHeader(
                    self._ip.src, self._ip.dst, proto,
                    ttl=self._ip.ttl,
                    tos=self._ip.tos,
                    identification=self._ip.identification,
                    flags=self._ip.flags,
                    fragment_offset=self._ip.fragment_offset,
                ),
                ip_payload,
            )
            return network, ETHERTYPE_IPV4

    def _validate(self) -> None:
        if self._ip is None:
            raise ValueError("No IP layer configured; call .ip() before .build()/.fragment()")
        if self._transport_hdr is None:
            raise ValueError(
                "No transport layer configured; "
                "call .tcp(), .udp(), .icmp(), or .icmpv6() before .build()/.fragment()"
            )

    # ── assembly ─────────────────────────────────────────────────────────────

    def build(self) -> bytes:
        """Assemble and return the complete packet bytes.

        Assembly order::

            [Ethernet II header — optional, added by .ethernet()]
            [IPv4 (20 B) or IPv6 (40 B) header]
            [TCP / UDP / ICMP / ICMPv6 header]
            [payload]

        All checksums are computed automatically.

        Returns:
            A :class:`bytes` object containing the fully assembled packet.

        Raises:
            ValueError: If :meth:`ip` or a transport method has not been called.
            OSError: If the IP address passed to :meth:`ip` is invalid.

        Example::

            >>> pkt = PacketBuilder().ip(src="1.2.3.4", dst="5.6.7.8").udp().build()
            >>> len(pkt)  # 20 (ip) + 8 (udp)
            28
        """
        self._validate()
        data = self._payload_bytes
        transport, proto = self._build_transport(data)
        ip_payload = transport + data
        network, ethertype = self._build_network(ip_payload, proto)
        packet = network + ip_payload

        if self._eth:
            eth_hdr = build_ethernet_header(
                EthernetHeader(self._eth_dst_mac, self._eth_src_mac, ethertype, self._vlan)
            )
            packet = eth_hdr + packet
            if self._pad_ethernet and len(packet) < ETHERNET_MIN_FRAME_SIZE:
                packet += b'\x00' * (ETHERNET_MIN_FRAME_SIZE - len(packet))

        return packet

    def fragment(self, mtu: int = 1500) -> list[bytes]:
        """Fragment the packet to fit within *mtu* bytes per IP datagram.

        IPv4 uses native Flags / Fragment Offset fragmentation (RFC 791).
        IPv6 inserts a Fragment Extension Header (next header = 44) per
        RFC 8200 §4.5.

        Args:
            mtu: Maximum IP packet size in bytes, *excluding* any Ethernet
                header.  Defaults to ``1500``.

        Returns:
            A list of fully assembled packet bytes, one entry per fragment.
            When the payload fits in a single datagram the list has one element.

        Raises:
            ValueError: If :meth:`ip` or a transport method has not been called,
                or if *mtu* is too small to hold even one 8-byte fragment.
            OSError: If the IP address passed to :meth:`ip` is invalid.

        Example::

            fragments = (PacketBuilder()
                .ip(src="10.0.0.1", dst="10.0.0.2")
                .udp()
                .payload(size=4000)
                .fragment(mtu=1500)
            )
            print(f"{len(fragments)} fragments")
        """
        from .fragmentation import fragment_ipv4, fragment_ipv6

        self._validate()
        assert self._ip is not None  # guaranteed by _validate()
        data = self._payload_bytes
        transport, proto = self._build_transport(data)
        transport_data = transport + data

        eth_header = None
        if self._eth:
            ethertype = ETHERTYPE_IPV6 if isinstance(self._ip, IPv6Header) else ETHERTYPE_IPV4
            eth_header = EthernetHeader(self._eth_dst_mac, self._eth_src_mac, ethertype, self._vlan)

        if isinstance(self._ip, IPv6Header):
            ip_hdr = IPv6Header(
                self._ip.src, self._ip.dst, proto,
                hop_limit=self._ip.hop_limit,
                traffic_class=self._ip.traffic_class,
                flow_label=self._ip.flow_label,
            )
            frags = fragment_ipv6(ip_hdr, transport_data, mtu, eth_header=eth_header)
        else:
            ip_hdr = IPHeader(
                self._ip.src, self._ip.dst, proto,
                ttl=self._ip.ttl,
                tos=self._ip.tos,
                identification=self._ip.identification,
                flags=self._ip.flags,
                fragment_offset=self._ip.fragment_offset,
            )
            frags = fragment_ipv4(ip_hdr, transport_data, mtu, eth_header=eth_header)

        if self._pad_ethernet and self._eth:
            frags = [
                f + b'\x00' * (ETHERNET_MIN_FRAME_SIZE - len(f))
                if len(f) < ETHERNET_MIN_FRAME_SIZE else f
                for f in frags
            ]
        return frags
