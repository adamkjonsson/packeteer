"""High-level packet parser.

Parses a raw ``bytes`` object as a complete network packet by chaining the
individual layer parsers, using the ``next_layer_id`` returned by each one to
select the next parser automatically.

Example — single raw packet::

    from .core import parse_packet
    from packeteer.generate import PacketBuilder
    from packeteer.pcap import LINKTYPE_RAW

    raw = PacketBuilder().ip(src="10.0.0.1", dst="10.0.0.2").tcp(dst_port=443).build()
    pkt = parse_packet(raw, link_type=LINKTYPE_RAW)

    print(pkt.ip.src, "->", pkt.ip.dst)
    print("dst_port:", pkt.transport.dst_port)
    print("payload:", pkt.payload.hex())

Example — reading from a pcap file::

    from packeteer.pcap import read_pcap
    from .core import parse_pcap_packet

    pcap = read_pcap(path="capture.pcap")
    for record in pcap.packets:
        pkt = parse_pcap_packet(record, pcap.header)
        if pkt.transport:
            print(f"{pkt.ts_sec}.{pkt.ts_frac:06d}  "
                  f"{pkt.ip.src} -> {pkt.ip.dst}:{pkt.transport.dst_port}")
"""
from __future__ import annotations

import io
import os
import socket
import struct
import warnings
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from packeteer.filter import PacketFilter
from packeteer.generate.arp import ARPHeader
from packeteer.generate.dhcp import DHCPMessage
from packeteer.generate.dns import DNSMessage
from packeteer.generate.etherip import IPPROTO_ETHERIP, EtherIPHeader
from packeteer.generate.ethernet import (
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    EthernetHeader,
)
from packeteer.generate.geneve import GENEVE_PORT, GENEVE_PROTO_TEB, GeneveHeader
from packeteer.generate.gre import GRE_PROTO_TEB, IPPROTO_GRE, GREHeader
from packeteer.generate.gtpu import GTPU_MSG_G_PDU, GTPU_PORT, GTPUHeader
from packeteer.generate.http import HTTPMessage
from packeteer.generate.icmp import ICMPHeader
from packeteer.generate.icmpv6 import ICMPv6Header
from packeteer.generate.ip import IPHeader
from packeteer.generate.ipsec import IPPROTO_AH, IPPROTO_ESP, AHHeader, ESPHeader
from packeteer.generate.ipv6 import IPv6Header
from packeteer.generate.mpls import ETHERTYPE_MPLS_MULTICAST, ETHERTYPE_MPLS_UNICAST, MPLSLabel
from packeteer.generate.pppoe import ETHERTYPE_PPPOE_DISCOVERY, ETHERTYPE_PPPOE_SESSION, PPPoEHeader
from packeteer.generate.pseudowire import ETHERTYPE_PW_CW, PseudowireHeader
from packeteer.generate.sctp import SCTPHeader
from packeteer.generate.sll import SLL2Header, SLLHeader
from packeteer.generate.tcp import TCPHeader
from packeteer.generate.udp import UDPHeader
from packeteer.generate.vxlan import VXLAN_PORT, VXLANHeader
from packeteer.pcap import (
    LINKTYPE_ETHERNET,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    LINKTYPE_RAW,
    PcapFileHeader,
    read_pcap,
)

from .arp import packet_parser as _arp_parser
from .dns import parse_dns_tcp as _parse_dns_tcp
from .dns import parse_dns_udp as _parse_dns_udp
from .etherip import packet_parser as _etherip_parser
from .ethernet import packet_parser as _ethernet_parser
from .geneve import packet_parser as _geneve_parser
from .gre import packet_parser as _gre_parser
from .gtpu import packet_parser as _gtpu_parser
from .icmp import packet_parser as _icmp_parser
from .icmpv6 import packet_parser as _icmpv6_parser
from .ip import packet_parser as _ip_parser
from .ipsec import ah_packet_parser as _ah_parser
from .ipsec import esp_packet_parser as _esp_parser
from .mpls import packet_parser as _mpls_parser
from .pppoe import packet_parser as _pppoe_parser
from .pseudowire import packet_parser as _pw_parser
from .sctp import packet_parser as _sctp_parser
from .sll import sll2_packet_parser as _sll2_parser
from .sll import sll_packet_parser as _sll_parser
from .tcp import packet_parser as _tcp_parser
from .to_config import apply_tunneled, to_json_string, to_packet_spec, update_config
from .udp import packet_parser as _udp_parser
from .vxlan import packet_parser as _vxlan_parser


class UnsupportedIPProtocolWarning(UserWarning):
    """Emitted when an IP protocol number is not recognised by the parser.

    The numeric protocol number is available on the :attr:`protocol` attribute
    so callers can filter or inspect it without parsing the message string.

    Attributes:
        protocol: The unrecognised IP protocol number.

    Example:

        .. code-block:: python

            import warnings
            from packeteer.parse import parse_packet, UnsupportedIPProtocolWarning
            from packeteer.pcap import LINKTYPE_RAW

            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                pkt = parse_packet(raw, link_type=LINKTYPE_RAW)

            for w in caught:
                if issubclass(w.category, UnsupportedIPProtocolWarning):
                    print(f"protocol {w.message.protocol} not supported")

    """

    protocol: int

    def __init__(self, message: str, protocol: int) -> None:
        super().__init__(message)
        self.protocol = protocol


class TimestampResolutionWarning(UserWarning):
    """Emitted when a capture's timestamp resolution cannot be expressed exactly.

    A packet spec records sub-second timestamps as either ``timestamp_us`` or
    ``timestamp_ns``, but a pcapng interface may declare any resolution via
    ``if_tsresol`` — milliseconds, or a binary ``2**n``.  Such timestamps are
    converted to the nearest representable unit, which can lose precision.
    The capture's own resolution is available on :attr:`tick_hz`.

    Attributes:
        tick_hz: The capture's timestamp resolution in ticks per second.

    """

    tick_hz: int

    def __init__(self, message: str, tick_hz: int) -> None:
        super().__init__(message)
        self.tick_hz = tick_hz


_TRANSPORT_PARSERS = {
    socket.IPPROTO_TCP:    _tcp_parser,
    socket.IPPROTO_UDP:    _udp_parser,
    socket.IPPROTO_ICMP:   _icmp_parser,
    socket.IPPROTO_ICMPV6: _icmpv6_parser,
    socket.IPPROTO_SCTP:   _sctp_parser,
}


@dataclass
class ParsedPacket:
    """All layers parsed from a single raw packet.

    Each field is ``None`` when the corresponding layer was absent or could not
    be parsed.  ``payload`` holds any bytes that follow the deepest recognised
    header.  ``ts_sec`` and ``ts_frac`` are only populated when the packet
    originates from a pcap record (via :func:`parse_pcap_packet`).

    Attributes:
        ethernet: Parsed Ethernet II header (includes VLAN tag when present).
        sll: Parsed Linux cooked-capture pseudo header (``SLLHeader`` for
            ``LINKTYPE_LINUX_SLL``, ``SLL2Header`` for ``LINKTYPE_LINUX_SLL2``),
            or ``None``.  Present instead of :attr:`ethernet`; its Protocol Type
            (an EtherType) drives the rest of the parse just like Ethernet.
        arp: Parsed ARP packet (RFC 826), or ``None`` when absent.  An ARP
            frame is terminal: when this is set, :attr:`ip`, :attr:`transport`,
            and the tunnel fields are all ``None``.
        mpls: List of parsed MPLS label stack entries, outermost first.
            Empty when no MPLS labels are present.
        pppoe: Parsed PPPoE header, or ``None`` when absent.
        ip: Parsed IPv4 or IPv6 header.
        ipip: ``True`` when the outer IP's protocol field is ``4``
            (IPv4-in-IP, RFC 2003) or ``41`` (IPv6-in-IP, RFC 4213).
            When set, :attr:`tunneled` holds the inner IP packet (no
            inner Ethernet frame).  Mutually exclusive with
            :attr:`gre` and :attr:`etherip`.
        gre: Parsed GRE tunnel header (RFC 2784 / RFC 2890), or ``None``
            when absent.  When set, :attr:`tunneled` contains the inner
            packet.  For TEB (``protocol_type == 0x6558``) the inner
            packet has an Ethernet header; for IP-in-GRE it does not.
            Mutually exclusive with :attr:`ipip` and :attr:`etherip`.
        etherip: Parsed EtherIP tunnel header, or ``None`` when absent.
            When set, :attr:`tunneled` contains the inner frame as a
            :class:`ParsedPacket`.
        pseudowire: Parsed RFC 4385 pseudowire control word, or ``None``
            when absent.  Found after the bottom-of-stack MPLS label.
            When set, :attr:`tunneled` contains the inner frame.
        vxlan: Parsed VXLAN tunnel header (RFC 7348), or ``None`` when absent.
            Recognised by the outer UDP destination port (4789), so unlike the
            IP-protocol tunnels :attr:`transport` remains the outer
            :class:`~packeteer.generate.udp.UDPHeader` when this is set.
            :attr:`tunneled` contains the inner Ethernet frame.
        geneve: Parsed GENEVE tunnel header (RFC 8926), or ``None`` when absent.
            Like :attr:`vxlan`, recognised by the outer UDP destination port
            (6081), so :attr:`transport` remains the outer UDP header.  The
            GENEVE Protocol Type selects the inner payload, so :attr:`tunneled`
            holds an inner Ethernet frame (TEB) or a raw IP packet.
        gtpu: Parsed GTP-U tunnel header (3GPP TS 29.281), or ``None`` when
            absent.  Recognised by the outer UDP destination port (2152), so
            :attr:`transport` remains the outer UDP header.  For a G-PDU
            message :attr:`tunneled` holds the inner IP packet (no Ethernet);
            for other message types :attr:`tunneled` is ``None`` and any
            content remains in :attr:`payload`.
        ah: Parsed IPsec Authentication Header (RFC 4302), or ``None``.  AH is
            transparent (integrity only), so the protected content is decoded
            normally — :attr:`transport` in transport mode, or
            :attr:`tunneled` in tunnel mode.
        esp: Parsed IPsec ESP header (RFC 4303), or ``None``.  Only SPI +
            Sequence Number are decoded; the encrypted remainder is opaque and
            kept in :attr:`payload` (ESP is terminal without the key).
        tunneled: Inner packet parsed recursively when :attr:`ipip` is
            ``True``, :attr:`gre` is set, :attr:`etherip` is set,
            :attr:`pseudowire` is set, or :attr:`vxlan` is set, otherwise
            ``None``.  May itself have a non-``None`` :attr:`gre`,
            :attr:`ipip`, or :attr:`etherip` for double-nested tunnels.
        transport: Parsed TCP, UDP, ICMPv4, or ICMPv6 header.
        dns: Parsed DNS or mDNS message when the transport port is 53 or
            5353, otherwise ``None``.  Populated from the payload bytes; on
            parse failure the raw bytes remain in :attr:`payload` and this
            field is ``None``.
        dhcp: Parsed DHCP message when the transport is UDP on port 67 or 68,
            otherwise ``None``.  On parse failure the raw bytes remain in
            :attr:`payload` and this field is ``None``.
        http: Parsed HTTP/1.x request or response when the transport is TCP
            on port 80 or 8080, otherwise ``None``.  On parse failure the
            raw bytes remain in :attr:`payload` and this field is ``None``.
        payload: Bytes remaining after all parsed headers.
        ts_sec: Capture timestamp — whole seconds (from pcap record).
        ts_frac: Capture timestamp — sub-second fraction (microseconds or
            nanoseconds depending on the pcap file's magic number).

    """

    ethernet:    EthernetHeader | None = None
    sll:         SLLHeader | SLL2Header | None = None
    arp:         ARPHeader | None = None
    mpls:        list[MPLSLabel] = field(default_factory=list)
    pppoe:       PPPoEHeader | None = None
    ip:          IPHeader | IPv6Header | None = None
    ipip:        bool = False
    gre:         GREHeader | None = None
    etherip:     EtherIPHeader | None = None
    pseudowire:  PseudowireHeader | None = None
    vxlan:       VXLANHeader | None = None
    geneve:      GeneveHeader | None = None
    gtpu:        GTPUHeader | None = None
    ah:          AHHeader | None = None
    esp:         ESPHeader | None = None
    tunneled:    "ParsedPacket | None" = None
    transport: TCPHeader | UDPHeader | ICMPHeader | ICMPv6Header | SCTPHeader | None = None
    dns:       DNSMessage | None = None
    dhcp:      DHCPMessage | None = None
    http:      HTTPMessage | None = None  # type: ignore[valid-type]
    payload:   bytes = field(default=b"")
    ts_sec:    int = 0
    ts_frac:   int = 0


def _parse_link_layer(
    pkt: ParsedPacket, data: bytes, link_type: int,
) -> tuple[bytes, int | None] | None:
    """Parse the link layer and return ``(remaining, ethertype)`` or ``None`` on stop.

    Returns ``None`` when parsing should stop (payload already set on *pkt*).

    Args:
        pkt: Packet object to fill in.
        data: Raw bytes from the start of the frame.
        link_type: Link-layer type constant.

    Returns:
        ``(remaining_bytes, ethertype)`` or ``None`` when parsing is complete.

    """
    _KNOWN_ETHERTYPES = (
        ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_ARP,
        ETHERTYPE_MPLS_UNICAST, ETHERTYPE_MPLS_MULTICAST,
        ETHERTYPE_PPPOE_DISCOVERY, ETHERTYPE_PPPOE_SESSION,
    )
    def _after_l2(size: int, ethertype: int | None) -> tuple[bytes, int | None] | None:
        # Shared tail for Ethernet/SLL: stop on a parse failure or an unknown
        # EtherType; otherwise hand the remaining bytes + EtherType downstream.
        if size == 0:
            pkt.payload = data
            return None
        remaining = data[size:]
        if ethertype not in _KNOWN_ETHERTYPES:
            pkt.payload = remaining
            return None
        return remaining, ethertype

    if link_type == LINKTYPE_ETHERNET:
        eth_size, ethertype, eth_hdr = _ethernet_parser(data)
        pkt.ethernet = eth_hdr
        return _after_l2(eth_size, ethertype)
    if link_type == LINKTYPE_LINUX_SLL:
        s_size, ethertype, s_hdr = _sll_parser(data)
        pkt.sll = s_hdr
        return _after_l2(s_size, ethertype)
    if link_type == LINKTYPE_LINUX_SLL2:
        s_size, ethertype, s_hdr = _sll2_parser(data)
        pkt.sll = s_hdr
        return _after_l2(s_size, ethertype)
    if link_type == LINKTYPE_RAW:
        return data, None   # raw IP — skip MPLS loop below
    pkt.payload = data
    return None


def _parse_pppoe_and_mpls(
    pkt: ParsedPacket, data: bytes, ethertype: int | None, decode_app: bool = True,
) -> tuple[bytes, int | None] | None:
    """Parse MPLS labels and PPPoE header.

    Returns ``(remaining, ip_ethertype)`` or ``None`` when parsing is complete.

    Args:
        pkt: Packet object to fill in.
        data: Remaining bytes after the Ethernet header.
        ethertype: EtherType from the Ethernet layer, or ``None`` for raw IP.
        decode_app: Forwarded to the recursive parse of a pseudowire's inner
            frame.  See :func:`parse_packet`.

    Returns:
        ``(remaining_bytes, ethertype)`` or ``None`` when parsing is complete.

    """
    remaining = data
    while ethertype in (ETHERTYPE_MPLS_UNICAST, ETHERTYPE_MPLS_MULTICAST):
        m_size, ethertype, m_hdr = _mpls_parser(remaining)
        if m_size == 0 or m_hdr is None:
            pkt.payload = remaining
            return None
        pkt.mpls.append(m_hdr)
        remaining = remaining[m_size:]

    if ethertype in (ETHERTYPE_PPPOE_DISCOVERY, ETHERTYPE_PPPOE_SESSION):
        p_size, ethertype, pppoe_hdr = _pppoe_parser(remaining)
        if p_size == 0 or pppoe_hdr is None:
            pkt.payload = remaining
            return None
        pkt.pppoe = pppoe_hdr
        remaining = remaining[p_size:]
        if ethertype is None:  # discovery frame — no IP follows
            pkt.payload = remaining
            return None

    if ethertype == ETHERTYPE_PW_CW:
        pw_size, inner_et, pw_hdr = _pw_parser(remaining)
        if pw_size == 0 or pw_hdr is None:
            pkt.payload = remaining
            return None
        pkt.pseudowire = pw_hdr
        remaining = remaining[pw_size:]
        inner_lt = LINKTYPE_ETHERNET if inner_et == GRE_PROTO_TEB else LINKTYPE_RAW
        pkt.tunneled = parse_packet(remaining, link_type=inner_lt, decode_app=decode_app)
        return None

    if ethertype == ETHERTYPE_ARP:
        a_size, _, a_hdr = _arp_parser(remaining)
        if a_size > 0 and a_hdr is not None:
            pkt.arp = a_hdr
        else:
            pkt.payload = remaining
        return None

    if ethertype is not None and ethertype not in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
        pkt.payload = remaining
        return None
    return remaining, ethertype


_IPV6_FIXED_HEADER_LEN: int = 40

# Timestamp resolutions the packet spec can express, in ticks per second
_US_PER_SECOND: int = 1_000_000
_NS_PER_SECOND: int = 1_000_000_000

_DNS_PORTS:  frozenset[int] = frozenset({53, 5353})
_DHCP_PORTS: frozenset[int] = frozenset({67, 68})
_HTTP_PORTS: frozenset[int] = frozenset({80, 8080})


def _try_parse_dns(pkt: ParsedPacket, payload: bytes) -> bytes:
    """Attempt to decode *payload* as DNS/mDNS if the transport port is 53 or 5353.

    On success, sets ``pkt.dns`` and returns ``b""``.
    On failure (wrong port or parse error), returns *payload* unchanged.
    """
    t = pkt.transport
    if t is None or not isinstance(t, (TCPHeader, UDPHeader)):
        return payload
    if t.src_port not in _DNS_PORTS and t.dst_port not in _DNS_PORTS:
        return payload
    if not payload:
        return payload
    try:
        if isinstance(t, TCPHeader):
            pkt.dns = _parse_dns_tcp(payload)
        else:
            pkt.dns = _parse_dns_udp(payload)
        return b""
    except (ValueError, struct.error):
        return payload


def _try_parse_dhcp(pkt: ParsedPacket, payload: bytes) -> bytes:
    """Attempt to decode *payload* as DHCP if the transport is UDP on port 67/68.

    On success, sets ``pkt.dhcp`` and returns ``b""``.
    On failure (wrong port/protocol or parse error), returns *payload* unchanged.
    """
    t = pkt.transport
    if not isinstance(t, UDPHeader):
        return payload
    if t.src_port not in _DHCP_PORTS and t.dst_port not in _DHCP_PORTS:
        return payload
    if not payload:
        return payload
    try:
        from .dhcp import parse_dhcp
        pkt.dhcp = parse_dhcp(payload)
        return b""
    except (ValueError, struct.error):
        return payload


def _try_parse_http(pkt: ParsedPacket, payload: bytes) -> bytes:
    """Attempt to decode *payload* as HTTP if the transport is TCP on port 80/8080.

    On success, sets ``pkt.http`` and returns ``b""``.
    On failure (wrong port/protocol or parse error), returns *payload* unchanged.
    """
    t = pkt.transport
    if not isinstance(t, TCPHeader):
        return payload
    if t.src_port not in _HTTP_PORTS and t.dst_port not in _HTTP_PORTS:
        return payload
    if not payload:
        return payload
    try:
        from .http import parse_http
        pkt.http = parse_http(payload)
        return b""
    except (ValueError, UnicodeDecodeError):
        return payload


def _try_parse_vxlan(pkt: ParsedPacket, payload: bytes, decode_app: bool = True) -> bool:
    """Attempt to decode *payload* as VXLAN if the transport is UDP on port 4789.

    On success, sets ``pkt.vxlan`` and ``pkt.tunneled`` (the inner Ethernet
    frame parsed recursively) and returns ``True``.  Returns ``False`` (leaving
    *pkt* untouched) on wrong port/protocol or when the header is too short.

    *decode_app* is forwarded to the inner parse.  VXLAN itself is framing,
    not application content, so it is decoded either way.
    """
    t = pkt.transport
    if not isinstance(t, UDPHeader):
        return False
    if VXLAN_PORT not in (t.dst_port, t.src_port):
        return False
    v_size, _, v_hdr = _vxlan_parser(payload)
    if v_size == 0 or v_hdr is None:
        return False
    pkt.vxlan = v_hdr
    pkt.tunneled = parse_packet(
        payload[v_size:], link_type=LINKTYPE_ETHERNET, decode_app=decode_app,
    )
    return True


def _try_parse_geneve(pkt: ParsedPacket, payload: bytes, decode_app: bool = True) -> bool:
    """Attempt to decode *payload* as GENEVE if the transport is UDP on port 6081.

    On success, sets ``pkt.geneve`` and ``pkt.tunneled`` (the inner frame parsed
    recursively — Ethernet for TEB, raw IP otherwise) and returns ``True``.
    Returns ``False`` (leaving *pkt* untouched) on wrong port/protocol or when
    the header is malformed.

    *decode_app* is forwarded to the inner parse.  GENEVE itself is framing,
    not application content, so it is decoded either way.
    """
    t = pkt.transport
    if not isinstance(t, UDPHeader):
        return False
    if GENEVE_PORT not in (t.dst_port, t.src_port):
        return False
    g_size, proto_type, g_hdr = _geneve_parser(payload)
    if g_size == 0 or g_hdr is None:
        return False
    pkt.geneve = g_hdr
    inner_lt = LINKTYPE_ETHERNET if proto_type == GENEVE_PROTO_TEB else LINKTYPE_RAW
    pkt.tunneled = parse_packet(payload[g_size:], link_type=inner_lt, decode_app=decode_app)
    return True


def _try_parse_gtpu(pkt: ParsedPacket, payload: bytes, decode_app: bool = True) -> bytes | None:
    """Attempt to decode *payload* as GTP-U if the transport is UDP on port 2152.

    On success, sets ``pkt.gtpu``.  For a G-PDU message the inner IP packet is
    parsed recursively into ``pkt.tunneled`` and ``b""`` is returned; for other
    message types ``pkt.tunneled`` is left ``None`` and the leftover bytes are
    returned (to become ``pkt.payload``).  Returns ``None`` (leaving *pkt*
    untouched) on wrong port/protocol or a malformed header.

    *decode_app* is forwarded to the inner parse.  GTP-U itself is framing,
    not application content, so it is decoded either way.
    """
    t = pkt.transport
    if not isinstance(t, UDPHeader):
        return None
    if GTPU_PORT not in (t.dst_port, t.src_port):
        return None
    g_size, message_type, g_hdr = _gtpu_parser(payload)
    if g_size == 0 or g_hdr is None:
        return None
    pkt.gtpu = g_hdr
    rest = payload[g_size:]
    if message_type == GTPU_MSG_G_PDU and rest:
        pkt.tunneled = parse_packet(rest, link_type=LINKTYPE_RAW, decode_app=decode_app)
        return b""
    return rest


def _spec_timestamp_unit(tick_hz: int) -> tuple[str, int]:
    """Choose the packet spec's timestamp key and unit for a capture resolution.

    A spec expresses sub-second timestamps as either ``timestamp_us`` or
    ``timestamp_ns``, so a capture using neither resolution — legal in pcapng
    via ``if_tsresol`` — has to be converted.  The finer unit is chosen for
    anything more precise than microseconds, which keeps the conversion
    lossless whenever the resolution divides a nanosecond evenly.

    Args:
        tick_hz: The capture's resolution in ticks per second.

    Returns:
        A ``(key, spec_hz)`` tuple: the metadata key to write, and the ticks
        per second that key implies.  Convert a fraction with
        ``ts_frac * spec_hz // tick_hz``.

    Warns:
        TimestampResolutionWarning: When *tick_hz* is neither microseconds nor
            nanoseconds, so the spec cannot state the source resolution.

    """
    if tick_hz == _US_PER_SECOND:
        return ("timestamp_us", _US_PER_SECOND)
    if tick_hz == _NS_PER_SECOND:
        return ("timestamp_ns", _NS_PER_SECOND)

    spec_hz = _NS_PER_SECOND if tick_hz > _US_PER_SECOND else _US_PER_SECOND
    unit = "nanoseconds" if spec_hz == _NS_PER_SECOND else "microseconds"
    warnings.warn(
        TimestampResolutionWarning(
            f"Capture timestamp resolution is {tick_hz} ticks/s, which a packet "
            f"spec cannot express; timestamps were converted to {unit} and may "
            f"lose precision",
            tick_hz,
        ),
        stacklevel=3,
    )
    return (("timestamp_ns" if spec_hz == _NS_PER_SECOND else "timestamp_us"), spec_hz)


def _is_non_first_fragment(ip_hdr: IPHeader | IPv6Header | None) -> bool:
    """Return ``True`` when *ip_hdr* describes a fragment other than the first.

    Only the first fragment of a datagram carries the transport header; the
    rest carry payload bytes from the middle of it.  Decoding those bytes as
    a transport header produces a plausible-looking header made of payload —
    for a stream reassembler, ports and sequence numbers invented out of user
    data.

    Args:
        ip_hdr: Parsed IPv4 or IPv6 header.

    Returns:
        ``True`` if the packet's data starts partway into the datagram.

    """
    if isinstance(ip_hdr, IPHeader):
        return ip_hdr.fragment_offset > 0
    if isinstance(ip_hdr, IPv6Header):
        return ip_hdr.fragment is not None and ip_hdr.fragment.fragment_offset > 0
    return False


def _ip_payload_size(ip_hdr: IPHeader | IPv6Header | None, ip_size: int) -> int | None:
    """Return the datagram's declared payload size, or ``None`` when unknown.

    The result is the number of bytes the IP header says follow it, so a
    caller can discard anything beyond that — most importantly the zero
    padding a sender adds to reach the 60-byte Ethernet minimum, which is part
    of the frame but not part of the datagram.

    Args:
        ip_hdr: Parsed IPv4 or IPv6 header.
        ip_size: Bytes consumed by the header, including IPv4 options or the
            IPv6 extension headers already decoded into *ip_hdr*.

    Returns:
        Declared payload size in bytes, or ``None`` when the header does not
        state one usably — a builder-constructed header, an IPv6 Jumbo Payload
        (length ``0``, RFC 2675), or a length shorter than the header itself.

    """
    if isinstance(ip_hdr, IPHeader):
        if ip_hdr.total_length is None or ip_hdr.total_length < ip_size:
            return None
        return ip_hdr.total_length - ip_size
    if isinstance(ip_hdr, IPv6Header):
        # payload_length covers everything after the 40-byte fixed header,
        # including any extension headers already consumed by the parser.
        if not ip_hdr.payload_length:
            return None
        ext_size = ip_size - _IPV6_FIXED_HEADER_LEN
        if ip_hdr.payload_length < ext_size:
            return None
        return ip_hdr.payload_length - ext_size
    return None


def _parse_ip_protocol(
    pkt: ParsedPacket, remaining: bytes, ip_proto: int | None, decode_app: bool = True,
) -> bytes:
    """Parse the IP protocol layer (transport or tunnel).

    Fills in transport/tunnel fields on *pkt* and returns the remaining
    (payload) bytes.

    Args:
        pkt: Packet object to fill in.
        remaining: Bytes after the IP header.
        ip_proto: IP protocol number, or ``None`` when unknown.
        decode_app: When ``False``, skip the DNS/DHCP/HTTP decoders so the
            transport payload is returned as it appeared on the wire.  See
            :func:`parse_packet`.

    Returns:
        Remaining bytes after consuming transport/tunnel headers.

    """
    transport_parser = _TRANSPORT_PARSERS.get(ip_proto) if ip_proto is not None else None
    if transport_parser is not None:
        t_size, _, t_hdr = transport_parser(remaining)
        if t_size > 0:
            pkt.transport = t_hdr
            remaining = remaining[t_size:]
            if _try_parse_vxlan(pkt, remaining, decode_app):
                return b""
            if _try_parse_geneve(pkt, remaining, decode_app):
                return b""
            gtpu_payload = _try_parse_gtpu(pkt, remaining, decode_app)
            if gtpu_payload is not None:
                return gtpu_payload
            if decode_app:
                remaining = _try_parse_dns(pkt, remaining)
                remaining = _try_parse_dhcp(pkt, remaining)
                remaining = _try_parse_http(pkt, remaining)
    elif ip_proto in (4, 41):
        pkt.ipip = True
        pkt.tunneled = parse_packet(remaining, link_type=LINKTYPE_RAW, decode_app=decode_app)
        return b""
    elif ip_proto == IPPROTO_GRE:
        g_size, proto_type, g_hdr = _gre_parser(remaining)
        if g_size > 0 and g_hdr is not None:
            pkt.gre = g_hdr
            inner_lt = LINKTYPE_ETHERNET if proto_type == GRE_PROTO_TEB else LINKTYPE_RAW
            pkt.tunneled = parse_packet(
                remaining[g_size:], link_type=inner_lt, decode_app=decode_app,
            )
            return b""
    elif ip_proto == IPPROTO_ETHERIP:
        ei_size, _, ei_hdr = _etherip_parser(remaining)
        if ei_size > 0 and ei_hdr is not None:
            pkt.etherip = ei_hdr
            pkt.tunneled = parse_packet(
                remaining[ei_size:], link_type=LINKTYPE_ETHERNET, decode_app=decode_app,
            )
            return b""
    elif ip_proto == IPPROTO_AH:
        ah_size, next_header, ah_hdr = _ah_parser(remaining)
        if ah_size > 0 and ah_hdr is not None:
            pkt.ah = ah_hdr
            # AH is transparent: continue parsing the protected content.
            return _parse_ip_protocol(pkt, remaining[ah_size:], next_header, decode_app)
    elif ip_proto == IPPROTO_ESP:
        e_size, _, e_hdr = _esp_parser(remaining)
        if e_size > 0 and e_hdr is not None:
            pkt.esp = e_hdr
            # ESP payload is encrypted/opaque without the key.
            return remaining[e_size:]
    elif ip_proto is not None:
        warnings.warn(
            UnsupportedIPProtocolWarning(
                f"IP protocol {ip_proto} is not supported; "
                "bytes after the IP header are stored in ParsedPacket.payload",
                ip_proto,
            ),
            stacklevel=3,
        )
    return remaining


def parse_packet(
    data: bytes, *, link_type: int = LINKTYPE_ETHERNET, decode_app: bool = True,
) -> ParsedPacket:
    """Parse *data* as a complete network packet.

    Parses each layer in turn, using the ``next_layer_id`` returned by each
    parser to select the next one:

    - **Ethernet** (``link_type=LINKTYPE_ETHERNET``, default): The EtherType
      drives layer selection.  IEEE 802.1Q VLAN tags are decoded inside the
      Ethernet parser; ``next_layer_id`` is already the inner EtherType.
    - **MPLS** (EtherType ``0x8847``/``0x8848``): Zero or more label stack
      entries are decoded into :attr:`ParsedPacket.mpls`.  Parsing continues
      until the bottom-of-stack label is consumed and the next byte is an IP
      version nibble.
    - **PPPoE** (EtherType ``0x8863``/``0x8864``): The 6-byte PPPoE header is
      decoded into :attr:`ParsedPacket.pppoe`.  For session frames the 2-byte
      PPP protocol field is consumed and used to determine whether an IPv4 or
      IPv6 header follows.  For discovery frames parsing stops after the tags
      (no IP layer follows).
    - **ARP** (EtherType ``0x0806``, RFC 826): The ARP packet is decoded into
      :attr:`ParsedPacket.arp` and parsing stops (ARP is terminal — no IP layer
      follows).
    - **Linux cooked** (``link_type=LINKTYPE_LINUX_SLL`` / ``LINKTYPE_LINUX_SLL2``):
      The 16-byte (SLL) or 20-byte (SLL2) pseudo header produced by
      ``tcpdump -i any`` is decoded into :attr:`ParsedPacket.sll`.  Its Protocol
      Type field is an EtherType, so layer selection then proceeds exactly as
      after an Ethernet header.
    - **Raw IP** (``link_type=LINKTYPE_RAW``): Ethernet parsing is skipped;
      IP-version detection starts immediately.
    - **IP**: The protocol/next-header field selects the transport parser.
    - **IP-in-IP** (IP protocol ``4`` or ``41``, RFC 2003 / RFC 4213):
      ``parse_packet`` is called recursively with ``LINKTYPE_RAW`` on the
      remaining bytes.  :attr:`ParsedPacket.ipip` is set to ``True`` and the
      result is stored in :attr:`ParsedPacket.tunneled`.  Arbitrary nesting is
      supported.  Mutually exclusive with GRE and EtherIP.
    - **GRE** (IP protocol ``47``, RFC 2784 / RFC 2890): The variable-length
      GRE header is decoded into :attr:`ParsedPacket.gre`.  For TEB payloads
      (Protocol Type ``0x6558``) ``parse_packet`` is called recursively with
      ``LINKTYPE_ETHERNET``; for IPv4/IPv6 payloads ``LINKTYPE_RAW`` is used.
      The result is stored in :attr:`ParsedPacket.tunneled`.  Arbitrary
      nesting is supported.  Mutually exclusive with IP-in-IP and EtherIP.
    - **EtherIP** (IP protocol ``97``): The 2-byte EtherIP header is decoded
      into :attr:`ParsedPacket.etherip` and ``parse_packet`` is called
      recursively on the inner Ethernet frame.  The result is stored in
      :attr:`ParsedPacket.tunneled`.  Arbitrary nesting is supported.
    - **IPsec AH** (IP protocol ``51``, RFC 4302): The Authentication Header is
      decoded into :attr:`ParsedPacket.ah`.  AH provides integrity only, so its
      Next Header field is followed and the protected content is parsed in full
      (transport header in transport mode, inner IP in tunnel mode).
    - **IPsec ESP** (IP protocol ``50``, RFC 4303): The SPI + Sequence-Number
      prefix is decoded into :attr:`ParsedPacket.esp`; the encrypted remainder
      is opaque and stored in :attr:`ParsedPacket.payload`.
    - **VXLAN** (UDP destination port ``4789``, RFC 7348): After the UDP header
      is parsed, the 8-byte VXLAN header is decoded into
      :attr:`ParsedPacket.vxlan` and ``parse_packet`` is called recursively
      with ``LINKTYPE_ETHERNET`` on the inner Ethernet frame, stored in
      :attr:`ParsedPacket.tunneled`.  The outer :attr:`ParsedPacket.transport`
      remains the UDP header.
    - **GENEVE** (UDP destination port ``6081``, RFC 8926): After the UDP
      header is parsed, the GENEVE header (8 bytes plus TLV options) is decoded
      into :attr:`ParsedPacket.geneve`.  Its Protocol Type selects the inner
      parse: ``0x6558`` (TEB) recurses with ``LINKTYPE_ETHERNET``, otherwise
      ``LINKTYPE_RAW``.  The result is stored in :attr:`ParsedPacket.tunneled`
      and the outer :attr:`ParsedPacket.transport` remains the UDP header.
    - **GTP-U** (UDP destination port ``2152``, 3GPP TS 29.281): After the UDP
      header is parsed, the GTP-U header (mandatory 8 bytes plus optional
      sequence / N-PDU fields and extension headers) is decoded into
      :attr:`ParsedPacket.gtpu`.  For a G-PDU message the inner IP packet is
      parsed recursively with ``LINKTYPE_RAW`` into
      :attr:`ParsedPacket.tunneled`; other message types leave the content in
      :attr:`ParsedPacket.payload`.  The outer
      :attr:`ParsedPacket.transport` remains the UDP header.
    - **Transport**: TCP, UDP, ICMPv4, or ICMPv6.
    - **Payload**: Any bytes after the last parsed header.

    Args:
        data: Raw packet bytes (from a pcap record, socket, or
            :meth:`PacketBuilder.build`).
        link_type: Link-layer type.  Use :data:`LINKTYPE_ETHERNET` (``1``,
            default) when an Ethernet header is present, or
            :data:`LINKTYPE_RAW` (``101``) for raw IP packets.
        decode_app: When ``True`` (default), payloads on the well-known DNS,
            DHCP, and HTTP ports are decoded into :attr:`ParsedPacket.dns`,
            :attr:`~ParsedPacket.dhcp`, and :attr:`~ParsedPacket.http`, and
            :attr:`~ParsedPacket.payload` is left empty.  Pass ``False`` to
            skip those decoders and get the transport payload exactly as it
            appeared on the wire — re-encoding a decoded message is not
            byte-exact, since header casing, ordering, and whitespace are
            normalised away.  The setting applies to every layer of a
            tunnelled packet.  Tunnel decoders (VXLAN, GENEVE, GTP-U) are
            framing rather than application content and always run.

    Returns:
        A :class:`ParsedPacket` with each successfully parsed layer filled in.
        Layers that are absent or fail to parse are ``None``.

    """
    pkt = ParsedPacket()

    link_result = _parse_link_layer(pkt, data, link_type)
    if link_result is None:
        return pkt
    remaining, ethertype = link_result

    layer_result = _parse_pppoe_and_mpls(pkt, remaining, ethertype, decode_app)
    if layer_result is None:
        return pkt
    remaining, _ = layer_result

    # ── IP ────────────────────────────────────────────────────────────────────
    ip_size, ip_proto, ip_hdr = _ip_parser(remaining)
    if ip_size == 0:
        pkt.payload = remaining
        return pkt
    pkt.ip = ip_hdr
    remaining = remaining[ip_size:]

    # Discard anything past the end of the IP datagram — for a frame below the
    # 60-byte Ethernet minimum that is the sender's zero padding, which is not
    # part of the datagram and must not reach the payload.  When the declared
    # size exceeds what was captured (a snaplen-truncated record) keep every
    # captured byte instead.
    declared = _ip_payload_size(ip_hdr, ip_size)
    if declared is not None and declared < len(remaining):
        remaining = remaining[:declared]

    if _is_non_first_fragment(ip_hdr):
        # Payload bytes from the middle of a datagram — there is no header
        # here to parse.  Reassemble with packeteer.parse.defragment first.
        pkt.payload = remaining
        return pkt

    pkt.payload = _parse_ip_protocol(pkt, remaining, ip_proto, decode_app)
    return pkt


def parse_pcap_packet(
    record: tuple[bytes, int, int],
    file_header: PcapFileHeader,
    *,
    decode_app: bool = True,
) -> ParsedPacket:
    """Parse one pcap packet record into a :class:`ParsedPacket`.

    Uses the link-layer type from *file_header* to drive layer selection,
    and copies the capture timestamp from the record into the returned object.

    Args:
        record: A ``(data, ts_sec, ts_frac)`` tuple as produced by
            :func:`packeteer.pcap.read_pcap` — one element of
            :attr:`PcapFile.packets`.
        file_header: The global pcap header from the same file.  Provides the
            link-layer type and the timestamp resolution flag.
        decode_app: Passed through to :func:`parse_packet`.  Pass ``False`` to
            keep DNS/DHCP/HTTP payloads as raw bytes.

    Returns:
        A :class:`ParsedPacket` with all recognised layers filled in and
        ``ts_sec`` / ``ts_frac`` set from the record.  ``ts_frac`` is in
        microseconds when ``file_header.nanoseconds`` is ``False``, or
        nanoseconds when it is ``True``.

    """
    data, ts_sec, ts_frac = record
    pkt = parse_packet(data, link_type=file_header.link_type, decode_app=decode_app)
    pkt.ts_sec  = ts_sec
    pkt.ts_frac = ts_frac
    return pkt


def _packet_to_spec(pkt: ParsedPacket) -> dict[str, Any]:
    """Convert every parsed layer of *pkt* into a packet spec dict.

    Args:
        pkt: A parsed packet.

    Returns:
        A spec dict holding one section per layer present, in the order
        ``packeteer build`` expects.  The ``packet_metadata`` section is added
        by the caller.

    """
    cfg: dict[str, Any] = {}
    if pkt.ethernet is not None:
        update_config(cfg, pkt.ethernet)
    if pkt.sll is not None:
        update_config(cfg, pkt.sll)
    if pkt.arp is not None:
        update_config(cfg, pkt.arp)
    for mpls_label in pkt.mpls:
        update_config(cfg, mpls_label)
    if pkt.pppoe is not None:
        update_config(cfg, pkt.pppoe)
    if pkt.ip is not None:
        update_config(cfg, pkt.ip)

    if (pkt.ah is not None or pkt.esp is not None
            or pkt.ipip or pkt.gre is not None
            or pkt.etherip is not None or pkt.pseudowire is not None
            or pkt.vxlan is not None or pkt.geneve is not None
            or pkt.gtpu is not None):
        apply_tunneled(cfg, pkt)
    elif pkt.transport is not None:
        update_config(cfg, pkt.transport)
        if pkt.dns is not None:
            update_config(cfg, pkt.dns)
        elif pkt.dhcp is not None:
            update_config(cfg, pkt.dhcp)
        elif pkt.http is not None:
            update_config(cfg, pkt.http)
        elif pkt.payload:
            update_config(cfg, pkt.payload)
    elif pkt.payload:
        # No transport header, but bytes to record: a later fragment, or an IP
        # protocol the parser does not decode.  Without this the spec would
        # silently drop them.
        update_config(cfg, pkt.payload)
    return cfg


def parse_pcap_file(
    *,
    path: str | os.PathLike | None = None,
    file_object: io.RawIOBase | io.BufferedIOBase | None = None,
    output: dict[str, Any] | None = None,
    packet_filter: PacketFilter | None = None,
    link_type: int | None = None,
    decode_app: bool = True,
) -> str:
    """Parse every packet in a pcap file and return a packet spec string.

    Reads the file with :func:`packeteer.pcap.read_pcap`, parses each
    record with :func:`parse_pcap_packet`, converts the layers to a config dict
    with :func:`packeteer.parse.to_config.update_config`, and serialises the
    result with :func:`packeteer.parse.to_config.to_json_string`.

    The per-packet ``metadata`` block is populated with ``timestamp_s`` and
    either ``timestamp_us`` or ``timestamp_ns`` (depending on the file's
    timestamp resolution).  When the source file uses nanosecond timestamps,
    ``"nanoseconds": true`` is added to the top-level ``output`` block so that
    the config can be replayed with matching precision.

    Args:
        path: Path to the ``.pcap`` file.
        file_object: Readable binary file-like object positioned at the start
            of the pcap data.
        output: Extra fields to merge into the top-level ``metadata``
            block (e.g. ``{"from_file": "capture.pcap", "type": "pcap"}``).
            ``"nanoseconds"`` and ``"link_type"`` are set automatically from
            the source file and must not be supplied here.
        packet_filter: Optional :class:`~packeteer.filter.PacketFilter`.
            When supplied, only packets whose spec dict satisfies
            :meth:`~packeteer.filter.PacketFilter.matches` are included in
            the output.
        link_type: When given, override the link-layer type recorded in the
            file header (e.g. :data:`~packeteer.pcap.LINKTYPE_ETHERNET` or
            :data:`~packeteer.pcap.LINKTYPE_RAW`).  Use this when a capture
            declares the wrong link type and the recorded value would
            otherwise drive incorrect parsing.
        decode_app: When ``False``, DNS, DHCP, and HTTP payloads are left as
            raw bytes in the spec's ``payload`` section instead of being
            decoded into ``dns`` / ``dhcp`` / ``http`` sections.  Use it when
            the byte-exact payload matters more than the decoded view.

    Returns:
        A JSON string whose top-level structure matches the format accepted by
        ``packeteer build``.

    Raises:
        ValueError: If neither or both of *path* / *file_object* are given, or
            if the pcap data is malformed.
        OSError: If *path* cannot be opened for reading.

    """
    pcap = read_pcap(path=path, file_object=file_object, link_type=link_type)
    ts_frac_key, spec_hz = _spec_timestamp_unit(pcap.header.tick_hz)
    tick_hz = pcap.header.tick_hz

    packet_configs: list[dict[str, Any]] = []
    unsupported: Counter[int] = Counter()

    with warnings.catch_warnings(record=True) as _caught:
        warnings.filterwarnings("always", category=UnsupportedIPProtocolWarning)
        for packet_num, record in enumerate(pcap.packets, 1):
            pkt = parse_pcap_packet(record, pcap.header, decode_app=decode_app)
            cfg = _packet_to_spec(pkt)
            cfg["packet_metadata"] = {
                "packet_num": packet_num,
                "timestamp_s": pkt.ts_sec,
                ts_frac_key: pkt.ts_frac * spec_hz // tick_hz,
            }
            if packet_filter is None or packet_filter.matches(cfg):
                packet_configs.append(cfg)

    for w in _caught:
        if issubclass(w.category, UnsupportedIPProtocolWarning):
            assert isinstance(w.message, UnsupportedIPProtocolWarning)
            unsupported[w.message.protocol] += 1
        else:
            warnings.warn_explicit(
                w.message, w.category, w.filename, w.lineno, source=w.source,
            )

    if unsupported:
        file_hint = f" in {str(path)!r}" if path is not None else ""
        for proto, count in sorted(unsupported.items()):
            n = f"{count} packet{'s' if count != 1 else ''}"
            warnings.warn(
                UnsupportedIPProtocolWarning(
                    f"IP protocol {proto} is not supported; "
                    f"encountered in {n}{file_hint}. "
                    "Bytes after each IP header are stored in the payload field.",
                    proto,
                ),
                stacklevel=2,
            )

    global_output: dict[str, Any] = dict(output) if output is not None else {}
    global_output.setdefault("nanoseconds", pcap.header.nanoseconds)
    global_output.setdefault("link_type", pcap.header.link_type)
    # version_major 1 = pcapng, 2 = pcap
    file_type = "pcapng" if pcap.header.version_major == 1 else "pcap"
    global_output.setdefault("type", file_type)
    if path is not None:
        global_output.setdefault("from_file", str(path))

    return to_json_string(to_packet_spec(packet_configs, metadata=global_output))
