"""High-level packet builder API.

This module exposes :class:`PacketBuilder` — the primary entry point for
constructing and fragmenting complete raw network packets using a fluent,
layer-by-layer API.

Typical usage::

    from packeteer.generate import PacketBuilder

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

    # QinQ (double-tagged) IPv4 UDP packet
    pkt = (PacketBuilder()
        .ethernet()
        .vlan(vid=100)   # outer VLAN
        .vlan(vid=200)   # inner VLAN
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .udp()
        .build()
    )

    # MPLS label stack carrying IPv4 UDP (RFC 3032)
    pkt = (PacketBuilder()
        .ethernet()
        .mpls(label=100)   # outer label (S=0)
        .mpls(label=200)   # inner label (S=1, bottom of stack)
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .udp()
        .build()
    )

    # IPv4-in-IPv4 tunnel
    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="203.0.113.1", dst="203.0.113.2")   # outer (tunnel) IP
        .ip(src="10.0.0.1", dst="10.0.0.2")         # inner IP
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
    from packeteer.generate import PPPOE_CODE_PADI, PPPoETag, PPPOE_TAG_SERVICE_NAME
    pkt = (PacketBuilder()
        .ethernet(dst_mac="ff:ff:ff:ff:ff:ff")
        .pppoe(code=PPPOE_CODE_PADI, tags=[PPPoETag(PPPOE_TAG_SERVICE_NAME, b"")])
        .build()
    )

    # EtherIP tunnel — outer Ethernet + outer IP + EtherIP + inner Ethernet + inner IP + TCP
    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .etherip()
        .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
        .ip(src="192.168.1.1", dst="192.168.1.2")
        .tcp(dst_port=80)
        .build()
    )

    # GRE tunnel (RFC 2784) — IPv4-in-GRE with Key (RFC 2890)
    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .gre(key=1234)
        .ip(src="192.168.1.1", dst="192.168.1.2")
        .tcp(dst_port=80)
        .build()
    )
"""
from __future__ import annotations

import os
import socket
import struct

from .dhcp import DHCPMessage, _build_dhcp_message
from .dns import DNSMessage, _build_dns_message, _build_dns_message_tcp
from .etherip import IPPROTO_ETHERIP, EtherIPHeader, _build_etherip_header
from .ethernet import (
    ETHERNET_MIN_FRAME_SIZE,
    ETHERTYPE_8021Q,
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    EthernetHeader,
    VLANTag,
    _build_ethernet_header,
)
from .gre import (
    GRE_PROTO_IPV4,
    GRE_PROTO_IPV6,
    GRE_PROTO_TEB,
    IPPROTO_GRE,
    GREHeader,
    _build_gre_header,
)
from .http import HTTPMessage, _build_http_message
from .icmp import ICMPHeader, _build_icmp_header
from .icmpv6 import ICMPv6Header, _build_icmpv6_header
from .ip import IPHeader, _build_ip_header
from .ipv6 import (
    HBH_NEXT_HEADER,
    HopByHopOptions,
    IPv6Header,
    JumboPayloadOption,
    RawOption,
    RouterAlertOption,
    _build_hop_by_hop_header,
    _build_ipv6_header,
)
from .mpls import ETHERTYPE_MPLS_UNICAST, MPLSLabel, _build_mpls_label
from .pppoe import (
    ETHERTYPE_PPPOE_DISCOVERY,
    ETHERTYPE_PPPOE_SESSION,
    PPP_IPV4,
    PPP_IPV6,
    PPPOE_CODE_SESSION,
    PPPoEHeader,
    PPPoETag,
    _build_pppoe_header,
)
from .pseudowire import PseudowireHeader, _build_pseudowire_header
from .sctp import IPPROTO_SCTP, SCTPChunk, SCTPHeader, _build_sctp_packet
from .tcp import TCP_ACK, TCPHeader, TCPOptions, _build_tcp_header
from .udp import UDPHeader, _build_udp_header

# ── protocol-number helpers ───────────────────────────────────────────────────

_ETHERTYPE_MAP: dict[type, int] = {
    IPHeader:   ETHERTYPE_IPV4,
    IPv6Header: ETHERTYPE_IPV6,
    VLANTag:    ETHERTYPE_8021Q,
    MPLSLabel:  ETHERTYPE_MPLS_UNICAST,
    # PPPoEHeader is handled dynamically in _ethertype_for (session vs discovery)
}

_IP_PROTO_MAP: dict[type, int] = {
    TCPHeader:       6,
    UDPHeader:       17,
    ICMPHeader:      1,
    ICMPv6Header:    58,
    IPHeader:        4,             # IP-in-IP (RFC 2003)
    IPv6Header:      41,            # IPv6-in-IPv4 (RFC 4213)
    EtherIPHeader:   IPPROTO_ETHERIP,  # EtherIP (RFC 3378)
    GREHeader:       IPPROTO_GRE,      # GRE (RFC 2784)
    SCTPHeader:      IPPROTO_SCTP,     # SCTP (RFC 9260)
    HopByHopOptions: HBH_NEXT_HEADER,  # Hop-by-Hop Options (RFC 8200)
}

# EtherType that a GRE header should advertise based on the next layer type
_GRE_PROTO_MAP: dict[type, int] = {
    IPHeader:       GRE_PROTO_IPV4,
    IPv6Header:     GRE_PROTO_IPV6,
    EthernetHeader: GRE_PROTO_TEB,
}

# PPP protocol numbers for the 2-byte PPP header in PPPoE session frames
_PPP_PROTO_MAP: dict[type, int] = {
    IPHeader:   PPP_IPV4,
    IPv6Header: PPP_IPV6,
}


def _ethertype_for(layer: object) -> int:
    """Return EtherType value.

    Return the EtherType value that an enclosing Ethernet/VLAN layer should
    use when *layer* is its direct payload.
    """
    if isinstance(layer, PPPoEHeader):
        return (
            ETHERTYPE_PPPOE_SESSION if layer.code == PPPOE_CODE_SESSION
            else ETHERTYPE_PPPOE_DISCOVERY
        )
    return _ETHERTYPE_MAP.get(type(layer), 0)


def _ip_proto_for(layer: object) -> int:
    """Return IP protocol number.

    Return the IP protocol number that an enclosing IP layer should use when
    *layer* is its direct payload.
    """
    return _IP_PROTO_MAP.get(type(layer), 0)


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


# ── PacketBuilder ─────────────────────────────────────────────────────────────

class PacketBuilder:
    """Assembles complete raw network packets layer by layer.

    Call the fluent layer methods in any order and any number of times, then
    call :meth:`build` or :meth:`fragment` to produce the final bytes.

    Layers are stacked in the order the methods are called — the first call
    becomes the outermost (leftmost) layer.  The IP version (4 or 6) is
    detected automatically from the address string passed to :meth:`ip`.
    All checksums are computed correctly per their respective RFCs.

    Each method appends a layer to an internal ordered list, so the same
    method may be called multiple times to produce advanced encapsulations:

    * Calling :meth:`vlan` twice creates a QinQ (802.1ad) double-tagged frame.
    * Calling :meth:`mpls` multiple times builds an MPLS label stack (RFC 3032).
    * Calling :meth:`ip` twice creates an IP-in-IP tunnel packet.
    * Calling :meth:`pppoe` inserts a PPPoE session or discovery frame (RFC 2516).
    * Calling :meth:`etherip` inserts an EtherIP tunnel header (RFC 3378),
      followed by an inner :meth:`ethernet` + :meth:`ip` + transport chain.
    * Calling :meth:`gre` inserts a GRE tunnel header (RFC 2784 / RFC 2890).
      The GRE Protocol Type is set automatically from the layer that follows.

    The layer list stores the same public dataclasses exported by
    ``packeteer.generate`` (``EthernetHeader``, ``VLANTag``, ``MPLSLabel``,
    ``PPPoEHeader``, ``EtherIPHeader``, ``GREHeader``, ``IPHeader``,
    ``IPv6Header``, ``TCPHeader``, ``UDPHeader``, ``ICMPHeader``,
    ``ICMPv6Header``).  Protocol-number fields that depend on
    the next layer (``ethertype``, ``protocol``, ``next_header``) are set to
    ``0`` when the object is stored and filled in correctly at :meth:`build` /
    :meth:`fragment` time.

    Example::

        from packeteer.generate import PacketBuilder

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
        self._layers: list = []
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
        """Append an Ethernet II header layer.

        Omitting this call produces a raw IP packet with no layer-2 framing.

        Args:
            src_mac: Source MAC address (colon- or hyphen-separated hex).
            dst_mac: Destination MAC address.
            pad: When ``True``, zero-pad the assembled frame to the IEEE 802.3
                minimum of 60 bytes when the frame would otherwise be shorter.

        """
        # ethertype=0 is a placeholder; the correct value is filled in at
        # build time based on whatever layer follows this one.
        self._layers.append(EthernetHeader(dst_mac, src_mac, ethertype=0, pad=pad))
        return self

    def vlan(self, *, vid: int, pcp: int = 0, dei: int = 0) -> "PacketBuilder":
        """Append an IEEE 802.1Q VLAN tag layer.

        Inserts a 4-byte VLAN tag between the enclosing Ethernet header and
        the next layer.  Call twice for QinQ (double-tagged) frames.

        Args:
            vid: VLAN ID (1-4094).
            pcp: Priority Code Point (0-7).
            dei: Drop Eligible Indicator (0 or 1).

        """
        self._layers.append(VLANTag(vid, pcp, dei))
        return self

    def mpls(self, *, label: int, tc: int = 0, ttl: int = 64) -> "PacketBuilder":
        """Append an MPLS label stack entry (RFC 3032).

        The bottom-of-stack (S) bit is set automatically at build time: it is
        ``1`` when the next layer is not another :class:`MPLSLabel`, and ``0``
        when more MPLS labels follow.  Call multiple times to build an MPLS
        label stack.

        Args:
            label: 20-bit MPLS label value (0-1048575).
            tc: Traffic Class (0-7).  Defaults to ``0``.
            ttl: Time-to-Live (0-255).  Defaults to ``64``.

        """
        self._layers.append(MPLSLabel(label=label, tc=tc, ttl=ttl))
        return self

    def pppoe(
        self,
        *,
        code: int = PPPOE_CODE_SESSION,
        session_id: int = 0,
        tags: list[PPPoETag] | None = None,
    ) -> "PacketBuilder":
        """Append a PPPoE header layer (RFC 2516).

        For **session** frames (``code=0x00``, the default) a 2-byte PPP
        protocol field is inserted automatically between the PPPoE header and
        the next IP layer (``0x0021`` for IPv4, ``0x0057`` for IPv6).  The
        Ethernet EtherType is set to ``0x8864`` automatically.

        For **discovery** frames (``code != 0x00``) the ``tags`` list is
        encoded as the PPPoE payload.  The Ethernet EtherType is set to
        ``0x8863`` automatically.  No IP or transport layer is required after
        a discovery PPPoE layer.

        Args:
            code: PPPoE message code.  Use ``PPPOE_CODE_SESSION`` (``0x00``)
                for session data or one of the ``PPPOE_CODE_PAD*`` constants
                for discovery messages.  Defaults to ``PPPOE_CODE_SESSION``.
            session_id: 16-bit session identifier.  Defaults to ``0``.
            tags: TLV tags for discovery frames.  Ignored for session frames.

        """
        self._layers.append(PPPoEHeader(code=code, session_id=session_id, tags=tags or []))
        return self

    def etherip(self) -> "PacketBuilder":
        """Append an EtherIP tunnel header (RFC 3378).

        Call after the outer :meth:`ip` and before the inner :meth:`ethernet`
        layer.  The IP protocol number (97) is set automatically on the
        enclosing IP header.  The 2-byte wire header (version=3, reserved=0,
        i.e. ``0x30 0x00``) is inserted at build time.

        Example — outer Ethernet + outer IP + EtherIP + inner Ethernet + inner IP + TCP::

            pkt = (PacketBuilder()
                .ethernet()
                .ip(src="10.0.0.1", dst="10.0.0.2")
                .etherip()
                .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
                .ip(src="192.168.1.1", dst="192.168.1.2")
                .tcp(dst_port=80)
                .build()
            )
        """
        self._layers.append(EtherIPHeader())
        return self

    def gre(
        self,
        *,
        key: int | None = None,
        seq: int | None = None,
        checksum: bool = False,
    ) -> "PacketBuilder":
        """Append a GRE tunnel header (RFC 2784 / RFC 2890).

        Call after the outer :meth:`ip` and before the inner layer (IP or
        Ethernet for TEB).  The outer IP protocol number (47) is set
        automatically.  The GRE Protocol Type is determined at build time from
        the layer that immediately follows this header:

        * :meth:`ip` with an IPv4 address → ``0x0800`` (IPv4)
        * :meth:`ip` with an IPv6 address → ``0x86DD`` (IPv6)
        * :meth:`ethernet` → ``0x6558`` (Transparent Ethernet Bridging)

        Args:
            key: RFC 2890 32-bit Key field.  When not ``None`` the K flag is
                set and the 4-byte Key field is appended to the header.
            seq: RFC 2890 32-bit Sequence Number field.  When not ``None`` the
                S flag is set and the 4-byte Sequence Number field is appended.
            checksum: When ``True`` the C flag is set, a 4-byte Checksum +
                Reserved1 block is appended, and the 16-bit ones-complement
                checksum (RFC 1071) is computed over the header + payload at
                build time.

        Example — IPv4-in-GRE with Key and Sequence Number::

            pkt = (PacketBuilder()
                .ethernet()
                .ip(src="10.0.0.1", dst="10.0.0.2")
                .gre(key=1234, seq=0)
                .ip(src="192.168.1.1", dst="192.168.1.2")
                .tcp(dst_port=80)
                .build()
            )

        """
        self._layers.append(GREHeader(key=key, seq=seq, checksum=checksum))
        return self

    def pseudowire(
        self,
        *,
        flags: int = 0,
        frag: int = 0,
        length: int = 0,
        sequence: int = 0,
    ) -> "PacketBuilder":
        """Append an RFC 4385 pseudowire control word.

        Call after the bottom-of-stack :meth:`mpls` label and before the inner
        layer (an inner :meth:`ethernet` frame for Ethernet PW, or :meth:`ip`
        for IP PW).  The MPLS bottom-of-stack bit is set automatically because
        :class:`PseudowireHeader` is not an :class:`MPLSLabel`.

        Args:
            flags: 4-bit flags field (L=bit 3, R=bit 2; bits 1-0 reserved).
                Defaults to ``0``.
            frag: 2-bit fragmentation indicator.  ``0`` means not fragmented.
                Defaults to ``0``.
            length: 6-bit payload length.  Must be ``0`` for Ethernet PW.
                Defaults to ``0``.
            sequence: 16-bit sequence number.  ``0`` means sequencing is
                disabled.  Defaults to ``0``.

        Example — MPLS pseudowire carrying an inner Ethernet/IPv4/TCP frame::

            pkt = (PacketBuilder()
                .ethernet()
                .mpls(label=100)
                .pseudowire()
                .ethernet(src_mac="cc:dd:ee:00:00:01", dst_mac="cc:dd:ee:00:00:02")
                .ip(src="10.0.0.1", dst="10.0.0.2")
                .tcp(dst_port=80)
                .build()
            )

        """
        self._layers.append(
            PseudowireHeader(flags=flags, frag=frag, length=length, sequence=sequence)
        )
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
        """Append an IP header layer.  IPv4 or IPv6 is auto-detected from *src*.

        IPv4-specific parameters (``tos``, ``identification``, ``flags``,
        ``fragment_offset``) are ignored when *src* is an IPv6 address, and
        vice versa for IPv6-specific parameters.

        Call twice to create an IP-in-IP tunnel packet.

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
        # protocol / next_header = 0 is a placeholder filled in at build time.
        if _detect_ip_version(src) == 6:
            self._layers.append(IPv6Header(
                src, dst, next_header=0,
                hop_limit=ttl,
                traffic_class=traffic_class,
                flow_label=flow_label,
            ))
        else:
            self._layers.append(IPHeader(
                src, dst, protocol=0,
                ttl=ttl, tos=tos,
                identification=identification,
                flags=flags,
                fragment_offset=fragment_offset,
            ))
        return self

    def hop_by_hop_options(
        self,
        options: list[RouterAlertOption | JumboPayloadOption | RawOption] | None = None,
    ) -> "PacketBuilder":
        """Append an IPv6 Hop-by-Hop Options extension header (RFC 8200 §4.3).

        Must be called immediately after :meth:`ip` when *src* is an IPv6
        address, and before the transport layer method.  The enclosing
        IPv6 header's *next_header* field is set to ``0`` automatically.

        Args:
            options: List of :class:`RouterAlertOption`,
                :class:`JumboPayloadOption`, or :class:`RawOption` objects to
                encode.  Padding is added automatically to reach the required
                8-byte alignment.  Defaults to an empty list (all-padding
                header, rarely useful on its own).

        Example::

            from packeteer.generate import PacketBuilder, RouterAlertOption

            pkt = (PacketBuilder()
                .ip(src="::1", dst="::2")
                .hop_by_hop_options([RouterAlertOption(value=0)])  # MLD
                .udp(dst_port=9999)
                .build()
            )

        """
        self._layers.append(HopByHopOptions(options=list(options) if options else []))
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
        """Append a TCP transport header layer."""
        self._layers.append(TCPHeader(
            src_port, dst_port,
            seq=seq, ack=ack, flags=flags,
            window=window, urgent_ptr=urgent_ptr,
            reserved=reserved, options=options,
        ))
        return self

    def udp(self, *, src_port: int = 12345, dst_port: int = 80) -> "PacketBuilder":
        """Append a UDP transport header layer."""
        self._layers.append(UDPHeader(src_port, dst_port))
        return self

    def icmp(
        self,
        *,
        type: int = 8,
        code: int = 0,
        identifier: int = 1,
        sequence: int = 1,
    ) -> "PacketBuilder":
        """Append an ICMPv4 transport header layer.  Requires an IPv4 layer above it."""
        self._layers.append(ICMPHeader(
            type=type, code=code, identifier=identifier, sequence=sequence,
        ))
        return self

    def icmpv6(
        self,
        *,
        type: int = 128,
        code: int = 0,
        identifier: int = 1,
        sequence: int = 1,
    ) -> "PacketBuilder":
        """Append an ICMPv6 transport header layer.  Requires an IPv6 layer above it."""
        self._layers.append(ICMPv6Header(
            type=type, code=code, identifier=identifier, sequence=sequence,
        ))
        return self

    def sctp(
        self,
        *,
        src_port: int = 0,
        dst_port: int = 0,
        verification_tag: int = 0,
        chunks: list[SCTPChunk] | None = None,
    ) -> "PacketBuilder":
        """Append an SCTP transport header and chunk list (RFC 9260).

        Unlike TCP and UDP, SCTP carries its data inside typed *chunks* rather
        than as a separate payload layer.  Set :attr:`~.SCTPDataChunk.data` on
        each :class:`~.SCTPDataChunk` directly; do **not** call
        :meth:`payload` after :meth:`sctp`.

        The CRC-32c checksum (Castagnoli, RFC 9260 §6.8) is computed
        automatically at :meth:`build` time.

        Args:
            src_port: Source port number.
            dst_port: Destination port number.
            verification_tag: 32-bit Verification Tag negotiated during
                the handshake.  Defaults to ``0``.
            chunks: List of :data:`~.SCTPChunk` objects to encode.  When
                ``None`` a single empty :class:`~.SCTPDataChunk` is used.

        Example::

            from packeteer.generate import PacketBuilder
            from packeteer.generate import SCTPDataChunk

            pkt = (PacketBuilder()
                .ethernet()
                .ip(src="10.0.0.1", dst="10.0.0.2")
                .sctp(
                    src_port=1234,
                    dst_port=9999,
                    verification_tag=0xDEADBEEF,
                    chunks=[SCTPDataChunk(tsn=1, data=b"hello sctp")],
                )
                .build()
            )

        """
        self._layers.append(SCTPHeader(
            src_port=src_port,
            dst_port=dst_port,
            verification_tag=verification_tag,
            chunks=chunks or [],
        ))
        return self

    def dns(self, msg: DNSMessage, *, tcp: bool = False) -> "PacketBuilder":
        """Set the payload to a serialised DNS message.

        A convenience wrapper around :meth:`payload` for DNS traffic.  Pass
        ``tcp=True`` when building a DNS-over-TCP packet to include the
        mandatory 2-byte length prefix (RFC 1035 §4.2.2).

        Args:
            msg: The :class:`~packeteer.generate.dns.DNSMessage` to encode.
            tcp: When ``True``, prefix the encoded message with a 2-byte
                big-endian length field as required by DNS-over-TCP.

        """
        data = _build_dns_message_tcp(msg) if tcp else _build_dns_message(msg)
        return self.payload(data=data)

    def dhcp(self, msg: DHCPMessage) -> "PacketBuilder":
        """Set the payload to a serialised DHCP message.

        A convenience wrapper around :meth:`payload` for DHCP traffic.
        DHCP runs over UDP only; use :meth:`udp` with
        :data:`~packeteer.generate.dhcp.DHCP_PORT_SERVER` (67) and
        :data:`~packeteer.generate.dhcp.DHCP_PORT_CLIENT` (68) before calling
        this method.

        Args:
            msg: The :class:`~packeteer.generate.dhcp.DHCPMessage` to encode.

        """
        return self.payload(data=_build_dhcp_message(msg))

    def http(self, msg: HTTPMessage) -> "PacketBuilder":  # type: ignore[valid-type]
        """Set the payload to a serialised HTTP/1.x message.

        A convenience wrapper around :meth:`payload` for HTTP traffic.
        Use :meth:`tcp` with :data:`~packeteer.generate.http.HTTP_PORT`
        (80) or :data:`~packeteer.generate.http.HTTP_ALT_PORT` (8080)
        before calling this method.

        Args:
            msg: An :class:`~packeteer.generate.http.HTTPRequest` or
                :class:`~packeteer.generate.http.HTTPResponse` to encode.

        """
        return self.payload(data=_build_http_message(msg))

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

    def _find_ip_before(self, i: int) -> IPHeader | IPv6Header:
        """Return the nearest IP layer to the left of index *i*.

        Raises:
            ValueError: If no IP layer exists at any index less than *i*.

        """
        for layer in reversed(self._layers[:i]):
            if isinstance(layer, (IPHeader, IPv6Header)):
                return layer
        raise ValueError(
            "No IP layer found to the left of a transport layer; "
            "call .ip() before .tcp(), .udp(), .icmp(), or .icmpv6()"
        )

    def _ip_context(self, i: int) -> tuple[str, str, int]:
        """Return ``(src, dst, ip_version)`` from the nearest IP layer left of *i*."""
        ip = self._find_ip_before(i)
        return ip.src, ip.dst, (6 if isinstance(ip, IPv6Header) else 4)

    @staticmethod
    def _clone_ip(layer: IPHeader, proto: int) -> IPHeader:
        """Return a copy of *layer* with ``protocol`` set to *proto*."""
        return IPHeader(
            layer.src, layer.dst, proto,
            ttl=layer.ttl, tos=layer.tos,
            identification=layer.identification,
            flags=layer.flags,
            fragment_offset=layer.fragment_offset,
        )

    @staticmethod
    def _clone_ipv6(layer: IPv6Header, proto: int) -> IPv6Header:
        """Return a copy of *layer* with ``next_header`` set to *proto*."""
        return IPv6Header(
            layer.src, layer.dst, proto,
            hop_limit=layer.hop_limit,
            traffic_class=layer.traffic_class,
            flow_label=layer.flow_label,
        )

    def _assemble_range(self, start: int, end: int, data: bytes) -> bytes:
        """Assemble layers[start:end] right-to-left over *data*.

        The 'next layer' for protocol-number lookups is always taken from the
        full self._layers list (using i+1), so layers at the boundary of a
        sub-range correctly see the layer just outside the range.
        """
        for i in range(end - 1, start - 1, -1):
            layer = self._layers[i]
            next_layer = self._layers[i + 1] if i + 1 < len(self._layers) else None

            if isinstance(layer, TCPHeader):
                src, dst, ver = self._ip_context(i)
                data = _build_tcp_header(layer, data, src, dst, ver) + data

            elif isinstance(layer, UDPHeader):
                src, dst, ver = self._ip_context(i)
                data = _build_udp_header(layer, data, src, dst, ver) + data

            elif isinstance(layer, ICMPHeader):
                data = _build_icmp_header(layer, data) + data

            elif isinstance(layer, ICMPv6Header):
                ip = self._find_ip_before(i)
                data = _build_icmpv6_header(layer, data, ip.src, ip.dst) + data

            elif isinstance(layer, SCTPHeader):
                # SCTP data lives inside chunks; ignore downstream payload bytes.
                data = _build_sctp_packet(layer)

            elif isinstance(layer, IPHeader):
                proto = _ip_proto_for(next_layer) if next_layer else 0
                data = _build_ip_header(self._clone_ip(layer, proto), data) + data

            elif isinstance(layer, IPv6Header):
                proto = _ip_proto_for(next_layer) if next_layer else 0
                data = _build_ipv6_header(self._clone_ipv6(layer, proto), data) + data

            elif isinstance(layer, HopByHopOptions):
                transport_proto = _ip_proto_for(next_layer) if next_layer else 0
                data = _build_hop_by_hop_header(layer, transport_proto) + data

            elif isinstance(layer, PPPoEHeader):
                if layer.code == PPPOE_CODE_SESSION:
                    # Insert 2-byte PPP protocol field between PPPoE and IP
                    ppp_proto = _PPP_PROTO_MAP.get(type(next_layer), 0)
                    payload = struct.pack("!H", ppp_proto) + data
                else:
                    # Discovery: encode tags as payload; ignore upstream data
                    payload = b"".join(
                        struct.pack("!HH", t.type, len(t.data)) + t.data
                        for t in layer.tags
                    )
                data = _build_pppoe_header(layer, payload) + payload

            elif isinstance(layer, EtherIPHeader):
                data = _build_etherip_header() + data

            elif isinstance(layer, GREHeader):
                proto_type = _GRE_PROTO_MAP.get(type(next_layer), 0)
                hdr = GREHeader(
                    key=layer.key, seq=layer.seq,
                    checksum=layer.checksum, protocol_type=proto_type,
                )
                data = _build_gre_header(hdr, data) + data

            elif isinstance(layer, PseudowireHeader):
                data = _build_pseudowire_header(layer, data)

            elif isinstance(layer, MPLSLabel):
                bos = not isinstance(next_layer, MPLSLabel)
                data = _build_mpls_label(layer, bos) + data

            elif isinstance(layer, VLANTag):
                ethertype = _ethertype_for(next_layer) if next_layer else 0
                tci = (layer.pcp << 13) | (layer.dei << 12) | layer.vid
                data = struct.pack("!HH", tci, ethertype) + data

            elif isinstance(layer, EthernetHeader):
                ethertype = _ethertype_for(next_layer) if next_layer else 0
                eth = EthernetHeader(layer.dst_mac, layer.src_mac, ethertype)
                data = _build_ethernet_header(eth) + data

        return data

    def _apply_eth_padding(self, data: bytes) -> bytes:
        """Add padding after short ethernet frame.

        Pad *data* to the Ethernet minimum frame size if the outermost layer
        is an :class:`EthernetHeader` with ``pad=True``.
        """
        if (self._layers
                and isinstance(self._layers[0], EthernetHeader)
                and self._layers[0].pad
                and len(data) < ETHERNET_MIN_FRAME_SIZE):
            data += b'\x00' * (ETHERNET_MIN_FRAME_SIZE - len(data))
        return data

    def _validate(self) -> None:
        # PPPoE discovery frames carry only tags — no IP or transport required.
        has_pppoe_discovery = any(
            isinstance(layer, PPPoEHeader) and layer.code != PPPOE_CODE_SESSION
            for layer in self._layers
        )
        if has_pppoe_discovery:
            if not any(isinstance(layer, EthernetHeader) for layer in self._layers):
                raise ValueError(
                    "PPPoE discovery frames require an Ethernet header; "
                    "call .ethernet() before .pppoe()"
                )
            return

        has_ip = any(isinstance(layer, (IPHeader, IPv6Header)) for layer in self._layers)
        has_transport = any(
            isinstance(layer, (TCPHeader, UDPHeader, ICMPHeader, ICMPv6Header, SCTPHeader))
            for layer in self._layers
        )
        if not has_ip:
            raise ValueError("No IP layer configured; call .ip() before .build()/.fragment()")
        if not has_transport:
            raise ValueError(
                "No transport layer configured; "
                "call .tcp(), .udp(), .icmp(), or .icmpv6() before .build()/.fragment()"
            )

    # ── assembly ─────────────────────────────────────────────────────────────

    def build(self) -> bytes:
        """Assemble and return the complete packet bytes.

        Layers are assembled from innermost (payload) to outermost, with all
        checksums computed automatically.

        Returns:
            A :class:`bytes` object containing the fully assembled packet.

        Raises:
            ValueError: If no IP layer or no transport layer has been added.
            OSError: If an IP address string is invalid.

        Example::

            >>> pkt = PacketBuilder().ip(src="1.2.3.4", dst="5.6.7.8").udp().build()
            >>> len(pkt)  # 20 (ip) + 8 (udp)
            28

        """
        self._validate()
        data = self._assemble_range(0, len(self._layers), self._payload_bytes)
        return self._apply_eth_padding(data)

    def fragment(self, mtu: int = 1500) -> list[bytes]:
        """Fragment the packet to fit within *mtu* bytes per IP datagram.

        The first IP layer in the stack is used as the fragmentation point.
        Everything to its left (Ethernet, VLAN, outer IP) becomes a prefix
        prepended to every fragment; everything to its right (inner IP if any,
        transport, payload) becomes the transport data that is fragmented.

        IPv4 uses native Flags / Fragment Offset fragmentation (RFC 791).
        IPv6 inserts a Fragment Extension Header (next header = 44) per
        RFC 8200 §4.5.

        Args:
            mtu: Maximum IP packet size in bytes, *excluding* any prefix
                headers (e.g. Ethernet).  Defaults to ``1500``.

        Returns:
            A list of fully assembled packet bytes, one entry per fragment.
            When the payload fits in a single datagram the list has one element.

        Raises:
            ValueError: If no IP layer or no transport layer has been added,
                or if *mtu* is too small to hold even one 8-byte fragment.
            OSError: If an IP address string is invalid.

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

        # Find the first (outermost) IP layer.
        k = next(
            i for i, layer in enumerate(self._layers)
            if isinstance(layer, (IPHeader, IPv6Header))
        )
        ip_layer = self._layers[k]

        # Build everything to the right of the IP layer (transport + payload,
        # including any inner IP layers in an IP-in-IP stack).
        transport_data = self._assemble_range(k + 1, len(self._layers), self._payload_bytes)

        # Fragment the IP layer.
        next_layer = self._layers[k + 1] if k + 1 < len(self._layers) else None
        proto = _ip_proto_for(next_layer) if next_layer else 0

        if isinstance(ip_layer, IPv6Header):
            frags = fragment_ipv6(self._clone_ipv6(ip_layer, proto),
                                  transport_data, mtu, eth_header=None)
        else:
            frags = fragment_ipv4(self._clone_ip(ip_layer, proto),
                                  transport_data, mtu, eth_header=None)

        # Build the prefix (everything to the left of the IP layer).
        # _assemble_range uses self._layers[k] as the 'next_layer' context for
        # layers at index k-1, so ethertype/proto values are set correctly.
        prefix = self._assemble_range(0, k, b"")

        result = [prefix + frag for frag in frags]
        return [self._apply_eth_padding(f) for f in result]
