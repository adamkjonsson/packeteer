"""High-level packet builder API.

This module exposes :class:`PacketBuilder` and :class:`Protocol` — the
primary entry points for constructing and fragmenting complete raw network
packets.

Typical usage::

    from packet_generator import PacketBuilder, Protocol

    # IPv4 TCP packet with Ethernet header and 64 bytes of random payload
    pkt = PacketBuilder("192.168.1.10", "8.8.8.8", Protocol.TCP, payload_size=64).build()

    # IPv6 UDP packet without Ethernet framing
    pkt = PacketBuilder(
        "fe80::1", "fe80::2", Protocol.UDP, payload_size=20,
        include_ethernet=False,
    ).build()

    # ICMPv6 ping with explicit payload
    pkt = PacketBuilder(
        "::1", "::2", Protocol.ICMPv6,
        payload=b"hello ipv6",
    ).build()
"""
from __future__ import annotations

import os
import socket
from enum import Enum

from .ethernet import EthernetHeader, ETHERTYPE_IPV4, ETHERTYPE_IPV6, build_ethernet_header
from .ip import IPHeader, build_ip_header
from .ipv6 import IPv6Header, build_ipv6_header
from .tcp import TCPHeader, build_tcp_header
from .udp import UDPHeader, build_udp_header
from .icmp import ICMPHeader, build_icmp_header
from .icmpv6 import ICMPv6Header, build_icmpv6_header


class Protocol(Enum):
    """Supported transport-layer protocols.

    Members:
        TCP: Transmission Control Protocol (RFC 9293).  Works with both IPv4
            and IPv6 — the IP version is inferred from the address strings
            passed to :class:`PacketBuilder`.
        UDP: User Datagram Protocol (RFC 768).  Works with both IPv4 and
            IPv6.
        ICMP: Internet Control Message Protocol v4 (RFC 792).  **Requires
            IPv4 addresses.**  Use :attr:`ICMPv6` for IPv6.
        ICMPv6: Internet Control Message Protocol v6 (RFC 4443).  **Requires
            IPv6 addresses.**  The checksum pseudo-header is computed
            automatically.
    """

    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"       # ICMPv4, requires IPv4 addresses
    ICMPv6 = "ICMPv6"   # ICMPv6, requires IPv6 addresses


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

    A :class:`PacketBuilder` combines an optional Ethernet II header, an
    IPv4 or IPv6 header, a transport-layer header (TCP / UDP / ICMP /
    ICMPv6), and a payload into a single :class:`bytes` object that can be
    written to a raw socket or saved to a file.

    The IP version (4 or 6) is detected automatically from *src_ip*.  All
    checksums — IP header, TCP, UDP, ICMPv6 — are computed correctly per
    their respective RFCs.

    Example::

        from packet_generator import PacketBuilder, Protocol

        pkt = PacketBuilder(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            protocol=Protocol.TCP,
            payload_size=40,
            dst_port=443,
        ).build()
        print(f"Built {len(pkt)}-byte packet")
    """

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: Protocol,
        payload_size: int = 0,
        *,
        src_mac: str = "00:00:00:00:00:01",
        dst_mac: str = "00:00:00:00:00:02",
        src_port: int = 12345,
        dst_port: int = 80,
        ttl: int = 64,
        payload: bytes | None = None,
        include_ethernet: bool = True,
    ) -> None:
        """Initialise the builder with packet parameters.

        Args:
            src_ip: Source IP address.  Dotted-decimal for IPv4
                (e.g. ``"192.168.1.1"``) or colon-hex for IPv6
                (e.g. ``"fe80::1"``).  The IP version is auto-detected.
            dst_ip: Destination IP address in the same format as *src_ip*.
            protocol: Transport-layer protocol.  Use :class:`Protocol` enum
                values: ``Protocol.TCP``, ``Protocol.UDP``, ``Protocol.ICMP``
                (IPv4 only), or ``Protocol.ICMPv6`` (IPv6 only).
            payload_size: Number of random payload bytes to generate when
                *payload* is ``None``.  Ignored if *payload* is provided.
                Defaults to ``0`` (empty payload).
            src_mac: Source MAC address for the Ethernet header, as a
                colon- or hyphen-separated hex string.
                Defaults to ``"00:00:00:00:00:01"``.
            dst_mac: Destination MAC address for the Ethernet header.
                Defaults to ``"00:00:00:00:00:02"``.
            src_port: Source port number for TCP/UDP headers.  Ignored for
                ICMP/ICMPv6.  Defaults to ``12345``.
            dst_port: Destination port number for TCP/UDP headers.  Ignored
                for ICMP/ICMPv6.  Defaults to ``80``.
            ttl: Time-To-Live (IPv4) or Hop Limit (IPv6).  Defaults to
                ``64``.
            payload: Explicit payload bytes.  When provided, *payload_size*
                is ignored and these exact bytes are used as the packet body.
                Defaults to ``None`` (generate random bytes).
            include_ethernet: If ``True`` (default), prepend a 14-byte
                Ethernet II header to the packet.  Set to ``False`` to
                produce a raw IP packet without any layer-2 framing.
        """
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.payload_size = payload_size
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.src_port = src_port
        self.dst_port = dst_port
        self.ttl = ttl
        self.include_ethernet = include_ethernet
        self._explicit_payload = payload
        self._payload: bytes | None = None

    @property
    def payload(self) -> bytes:
        """The payload bytes that will be placed after the transport header.

        On the first access the payload is generated (either the explicit
        bytes supplied at construction, or ``os.urandom(payload_size)``).
        The result is cached so that repeated calls to :meth:`build` always
        use the same payload.

        Returns:
            The payload as a :class:`bytes` object.  May be empty (``b""``)
            when *payload_size* is ``0`` and no explicit payload was given.
        """
        if self._payload is None:
            self._payload = (
                self._explicit_payload
                if self._explicit_payload is not None
                else os.urandom(self.payload_size)
            )
        return self._payload

    def build(self) -> bytes:
        """Assemble and return the complete packet bytes.

        Assembly order (outermost to innermost)::

            [Ethernet header (14 B, optional)]
            [IPv4 (20 B) or IPv6 (40 B) header]
            [TCP (20 B) / UDP (8 B) / ICMP (8 B) / ICMPv6 (8 B) header]
            [payload (variable)]

        All checksums are computed automatically.  The Ethernet EtherType is
        set to ``0x0800`` for IPv4 or ``0x86DD`` for IPv6.

        Returns:
            A :class:`bytes` object containing the fully assembled packet.

        Raises:
            OSError: If *src_ip* or *dst_ip* is not a valid IP address.
            ValueError: If the :attr:`protocol` value is not supported
                (should not happen with the public :class:`Protocol` enum).

        Example:
            >>> from packet_generator import PacketBuilder, Protocol
            >>> pkt = PacketBuilder("1.2.3.4", "5.6.7.8", Protocol.UDP, payload_size=0).build()
            >>> len(pkt)  # 14 (eth) + 20 (ip) + 8 (udp)
            42
        """
        data = self.payload
        ip_version = _detect_ip_version(self.src_ip)

        # Build transport layer
        if self.protocol == Protocol.TCP:
            transport = build_tcp_header(
                TCPHeader(self.src_port, self.dst_port),
                data, self.src_ip, self.dst_ip, ip_version,
            )
        elif self.protocol == Protocol.UDP:
            transport = build_udp_header(
                UDPHeader(self.src_port, self.dst_port),
                data, self.src_ip, self.dst_ip, ip_version,
            )
        elif self.protocol == Protocol.ICMP:
            transport = build_icmp_header(ICMPHeader(), data)
        elif self.protocol == Protocol.ICMPv6:
            transport = build_icmpv6_header(ICMPv6Header(), data, self.src_ip, self.dst_ip)
        else:
            raise ValueError(f"Unsupported protocol: {self.protocol}")

        ip_payload = transport + data

        # Build network layer
        if ip_version == 6:
            next_header = {
                Protocol.TCP: 6,
                Protocol.UDP: 17,
                Protocol.ICMPv6: 58,
            }[self.protocol]
            network = build_ipv6_header(
                IPv6Header(self.src_ip, self.dst_ip, next_header, hop_limit=self.ttl),
                ip_payload,
            )
            ethertype = ETHERTYPE_IPV6
        else:
            import socket as _socket
            proto_num = {
                Protocol.TCP: _socket.IPPROTO_TCP,
                Protocol.UDP: _socket.IPPROTO_UDP,
                Protocol.ICMP: _socket.IPPROTO_ICMP,
            }[self.protocol]
            network = build_ip_header(
                IPHeader(self.src_ip, self.dst_ip, proto_num, ttl=self.ttl),
                ip_payload,
            )
            ethertype = ETHERTYPE_IPV4

        packet = network + ip_payload

        if self.include_ethernet:
            eth = build_ethernet_header(
                EthernetHeader(self.dst_mac, self.src_mac, ethertype)
            )
            packet = eth + packet

        return packet

    def fragment(self, mtu: int = 1500) -> list[bytes]:
        """Fragment the packet to fit within *mtu* bytes per IP datagram.

        Builds the complete transport layer (header + payload) and then splits
        it across as many IP datagrams as needed so that no IP packet exceeds
        *mtu* bytes.  Checksums in all transport headers are computed before
        fragmentation, exactly as :meth:`build` would produce them.

        IPv4 uses native Flags / Fragment Offset fragmentation (RFC 791).
        IPv6 inserts a Fragment Extension Header (next header = 44) into each
        output packet per RFC 8200 §4.5.

        Args:
            mtu: Maximum IP packet size in bytes, *excluding* any Ethernet
                header.  Defaults to ``1500`` (standard Ethernet payload).
                Use ``576`` for the IPv4 minimum reassembly buffer (RFC 791)
                or ``1280`` for the IPv6 minimum MTU (RFC 8200).

        Returns:
            A list of fully assembled packet bytes, one entry per fragment.
            When the payload fits within a single datagram the list contains
            exactly one element (equivalent to :meth:`build`).

        Raises:
            OSError: If *src_ip* or *dst_ip* is not a valid IP address.
            ValueError: If *mtu* is too small to hold even one 8-byte
                fragment.

        Example::

            from packet_generator import PacketBuilder, Protocol

            fragments = PacketBuilder(
                "10.0.0.1", "10.0.0.2", Protocol.UDP, payload_size=4000,
            ).fragment(mtu=1500)
            print(f"{len(fragments)} fragments")
        """
        import socket as _socket
        from .fragmentation import fragment_ipv4, fragment_ipv6

        data = self.payload
        ip_version = _detect_ip_version(self.src_ip)

        # Build the complete transport layer identical to build()
        if self.protocol == Protocol.TCP:
            transport = build_tcp_header(
                TCPHeader(self.src_port, self.dst_port),
                data, self.src_ip, self.dst_ip, ip_version,
            )
        elif self.protocol == Protocol.UDP:
            transport = build_udp_header(
                UDPHeader(self.src_port, self.dst_port),
                data, self.src_ip, self.dst_ip, ip_version,
            )
        elif self.protocol == Protocol.ICMP:
            transport = build_icmp_header(ICMPHeader(), data)
        elif self.protocol == Protocol.ICMPv6:
            transport = build_icmpv6_header(ICMPv6Header(), data, self.src_ip, self.dst_ip)
        else:
            raise ValueError(f"Unsupported protocol: {self.protocol}")

        transport_data = transport + data

        eth_header = None
        if self.include_ethernet:
            ethertype = ETHERTYPE_IPV6 if ip_version == 6 else ETHERTYPE_IPV4
            eth_header = EthernetHeader(self.dst_mac, self.src_mac, ethertype)

        if ip_version == 6:
            next_header = {
                Protocol.TCP: 6,
                Protocol.UDP: 17,
                Protocol.ICMPv6: 58,
            }[self.protocol]
            ip_hdr = IPv6Header(
                self.src_ip, self.dst_ip, next_header, hop_limit=self.ttl,
            )
            return fragment_ipv6(ip_hdr, transport_data, mtu, eth_header=eth_header)
        else:
            proto_num = {
                Protocol.TCP: _socket.IPPROTO_TCP,
                Protocol.UDP: _socket.IPPROTO_UDP,
                Protocol.ICMP: _socket.IPPROTO_ICMP,
            }[self.protocol]
            ip_hdr = IPHeader(self.src_ip, self.dst_ip, proto_num, ttl=self.ttl)
            return fragment_ipv4(ip_hdr, transport_data, mtu, eth_header=eth_header)
