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
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from packeteer import protocols
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
from packeteer.generate.tcp import TCPHeader, _build_tcp_header
from packeteer.generate.udp import UDPHeader, _build_udp_header
from packeteer.generate.vxlan import VXLAN_PORT, VXLANHeader
from packeteer.pcap import (
    LINKTYPE_ETHERNET,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    LINKTYPE_RAW,
    PcapFile,
    PcapFileHeader,
    PcapReader,
    PcapRecord,
    open_pcap,
    read_pcap,
)

from .arp import packet_parser as _arp_parser
from .defragment import Defragmenter, IncompleteDatagram
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


# Timestamp resolutions, in ticks per second
_US_PER_SECOND: int = 1_000_000
_NS_PER_SECOND: int = 1_000_000_000

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
        app: The decoded application-layer message, whichever protocol
            produced it — including the three above, which are also set.  A
            protocol registered with :func:`packeteer.protocols.register`
            lands here and nowhere else.  ``None`` when no registered protocol
            claimed the transport ports, when the one that did rejected the
            bytes, or when ``decode_app`` was ``False``.
        app_protocol: The :attr:`~packeteer.protocols.AppProtocol.name` of the
            protocol that decoded :attr:`app` — also the packet-spec section
            it is written to — or ``None`` alongside an ``None`` :attr:`app`.
        payload: Bytes remaining after all parsed headers.
        payload_offset: Index of ``payload[0]`` within the frame passed to
            :func:`parse_packet`, or ``None`` when :attr:`payload` is empty.
            Added to :attr:`packeteer.pcap.PcapRecord.data_offset` it gives
            the payload's byte offset within the capture file.  It cannot be
            derived as ``len(frame) - len(payload)``: a frame padded to the
            60-byte Ethernet minimum has padding after the IP datagram, which
            the parser trims out of :attr:`payload`, so that arithmetic
            silently lands inside the padding.  For a tunnelled packet the
            offset on a nested :attr:`tunneled` packet is relative to the
            **outer** frame as well, so one addition works at any depth.
        ts_sec: Capture timestamp — whole seconds (from pcap record).
        ts_frac: Capture timestamp — sub-second fraction, in units of
            :attr:`tick_hz`.
        tick_hz: Ticks per second that *ts_frac* is expressed in, carried
            here so a timestamp is never separated from its unit.  Set from
            the capture by :func:`parse_pcap_packet` and :func:`iter_packets`;
            microseconds by default for a packet parsed from bare bytes,
            which has no timestamp anyway.
        source_records: Capture records this packet came from, populated by
            :func:`iter_packets` and empty otherwise.  One record for an
            ordinary packet; for a reassembled datagram, every fragment that
            contributed, in arrival order.

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
    app:          object | None = None
    app_protocol: str | None = None
    payload:   bytes = field(default=b"")
    payload_offset: int | None = None
    ts_sec:    int = 0
    ts_frac:   int = 0
    tick_hz:   int = _US_PER_SECOND
    source_records: list[PcapRecord] = field(default_factory=list)

    @property
    def timestamp(self) -> float:
        """Capture time in seconds since the Unix epoch.

        Convenience for ``ts_sec + ts_frac / tick_hz``.  A float cannot hold a
        modern epoch to nanosecond precision — roughly the last three digits
        of a nanosecond timestamp are lost — so use *ts_sec*, *ts_frac* and
        *tick_hz* where exactness matters.
        """
        return self.ts_sec + self.ts_frac / self.tick_hz


def _set_payload(pkt: ParsedPacket, payload: bytes, offset: int) -> None:
    """Record *payload* on *pkt* along with where it starts in the frame.

    Every payload assignment goes through here so the offset cannot drift from
    the bytes, and so the "``None`` when empty" rule is stated once.

    Args:
        pkt: Packet object to fill in.
        payload: The payload bytes.
        offset: Index of ``payload[0]`` within the frame being parsed.

    """
    pkt.payload = payload
    pkt.payload_offset = offset if payload else None


def _shift_offsets(pkt: ParsedPacket, delta: int) -> None:
    """Rebase a tunnelled packet's offsets onto the enclosing frame.

    A recursive :func:`parse_packet` sees only the inner frame, so its offsets
    start at zero.  Adding the inner frame's position within the outer one
    makes every offset relative to the outermost frame, at any nesting depth.

    Also clears the inner frame's ``pad`` mark.  Padding to the 60-byte
    minimum is a property of what went out on the wire, which is the *outer*
    frame; an encapsulated frame shorter than that is ordinary and is not
    padded by the sender or by a rebuild.  The Ethernet parser cannot tell the
    two apart — it is handed a frame and measures it — so the correction
    belongs here, at the one point that knows a frame was nested.

    Args:
        pkt: Packet parsed from the inner frame.
        delta: Offset of that inner frame within the enclosing frame.

    """
    while pkt is not None:
        if pkt.payload_offset is not None:
            pkt.payload_offset += delta
        if pkt.ethernet is not None:
            pkt.ethernet.pad = True
        pkt = pkt.tunneled


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
            _set_payload(pkt, data, 0)
            return None
        remaining = data[size:]
        if ethertype not in _KNOWN_ETHERTYPES:
            _set_payload(pkt, remaining, size)
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
    _set_payload(pkt, data, 0)
    return None


def _parse_pppoe_and_mpls(
    pkt: ParsedPacket, data: bytes, ethertype: int | None, decode_app: bool = True,
    base: int = 0,
) -> tuple[bytes, int | None, int] | None:
    """Parse MPLS labels and PPPoE header.

    Returns ``(remaining, ip_ethertype, offset)`` or ``None`` when parsing is
    complete.

    Args:
        pkt: Packet object to fill in.
        data: Remaining bytes after the Ethernet header.
        ethertype: EtherType from the Ethernet layer, or ``None`` for raw IP.
        decode_app: Forwarded to the recursive parse of a pseudowire's inner
            frame.  See :func:`parse_packet`.
        base: Offset of *data* within the frame being parsed, so payload and
            tunnel offsets can be reported relative to that frame.

    Returns:
        ``(remaining_bytes, ethertype, offset_of_remaining)`` or ``None`` when
        parsing is complete.

    """
    remaining = data
    offset = base
    while ethertype in (ETHERTYPE_MPLS_UNICAST, ETHERTYPE_MPLS_MULTICAST):
        m_size, ethertype, m_hdr = _mpls_parser(remaining)
        if m_size == 0 or m_hdr is None:
            _set_payload(pkt, remaining, offset)
            return None
        pkt.mpls.append(m_hdr)
        remaining = remaining[m_size:]
        offset += m_size

    if ethertype in (ETHERTYPE_PPPOE_DISCOVERY, ETHERTYPE_PPPOE_SESSION):
        p_size, ethertype, pppoe_hdr = _pppoe_parser(remaining)
        if p_size == 0 or pppoe_hdr is None:
            _set_payload(pkt, remaining, offset)
            return None
        pkt.pppoe = pppoe_hdr
        remaining = remaining[p_size:]
        offset += p_size
        if ethertype is None:  # discovery frame — no IP follows
            _set_payload(pkt, remaining, offset)
            return None

    if ethertype == ETHERTYPE_PW_CW:
        pw_size, inner_et, pw_hdr = _pw_parser(remaining)
        if pw_size == 0 or pw_hdr is None:
            _set_payload(pkt, remaining, offset)
            return None
        pkt.pseudowire = pw_hdr
        remaining = remaining[pw_size:]
        offset += pw_size
        inner_lt = LINKTYPE_ETHERNET if inner_et == GRE_PROTO_TEB else LINKTYPE_RAW
        inner = parse_packet(remaining, link_type=inner_lt, decode_app=decode_app)
        _shift_offsets(inner, offset)
        pkt.tunneled = inner
        return None

    if ethertype == ETHERTYPE_ARP:
        a_size, _, a_hdr = _arp_parser(remaining)
        if a_size > 0 and a_hdr is not None:
            pkt.arp = a_hdr
        else:
            _set_payload(pkt, remaining, offset)
        return None

    if ethertype is not None and ethertype not in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
        _set_payload(pkt, remaining, offset)
        return None
    return remaining, ethertype, offset


_IPV6_FIXED_HEADER_LEN: int = 40


# ParsedPacket.dns / .dhcp / .http predate the registry and remain part of the
# public API, so a built-in lands on its own attribute as well as on .app.
# Nothing else does; drop this at 1.0.
_LEGACY_APP_ATTRS: frozenset[str] = frozenset({"dns", "dhcp", "http"})


def _try_parse_app(pkt: ParsedPacket, payload: bytes) -> bytes:
    """Attempt to decode *payload* as whichever protocol claims the port.

    Looks the transport ports up in :mod:`packeteer.protocols`, destination
    first.  On success sets :attr:`ParsedPacket.app` and
    :attr:`ParsedPacket.app_protocol` — and, for a built-in, the attribute
    named after it — then returns ``b""`` because the payload has been
    consumed.

    A port claim is a weak signal, so a decoder that rejects the bytes is not
    an error: the payload is returned unchanged and stays an opaque payload.
    That is what makes it safe for a caller to claim a port someone else uses.

    Args:
        pkt: Packet to fill in.  Its transport header supplies the ports.
        payload: Bytes after the transport header.

    Returns:
        ``b""`` when a protocol decoded *payload*, otherwise *payload*.

    """
    t = pkt.transport
    if not isinstance(t, (TCPHeader, UDPHeader)) or not payload:
        return payload
    transport = "tcp" if isinstance(t, TCPHeader) else "udp"
    proto = (protocols.for_port(t.dst_port, transport)
             or protocols.for_port(t.src_port, transport))
    if proto is None:
        return payload
    try:
        message = proto.decode(payload, transport)
    except (ValueError, struct.error):
        return payload
    pkt.app = message
    pkt.app_protocol = proto.name
    if proto.name in _LEGACY_APP_ATTRS:
        setattr(pkt, proto.name, message)
    return b""


def _try_parse_vxlan(
    pkt: ParsedPacket, payload: bytes, decode_app: bool = True, base: int = 0,
) -> bool:
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
    inner = parse_packet(
        payload[v_size:], link_type=LINKTYPE_ETHERNET, decode_app=decode_app,
    )
    _shift_offsets(inner, base + v_size)
    pkt.tunneled = inner
    return True


def _try_parse_geneve(
    pkt: ParsedPacket, payload: bytes, decode_app: bool = True, base: int = 0,
) -> bool:
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
    inner = parse_packet(payload[g_size:], link_type=inner_lt, decode_app=decode_app)
    _shift_offsets(inner, base + g_size)
    pkt.tunneled = inner
    return True


def _try_parse_gtpu(
    pkt: ParsedPacket, payload: bytes, decode_app: bool = True, base: int = 0,
) -> tuple[bytes, int] | None:
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
        inner = parse_packet(rest, link_type=LINKTYPE_RAW, decode_app=decode_app)
        _shift_offsets(inner, base + g_size)
        pkt.tunneled = inner
        return (b"", base + g_size)
    return (rest, base + g_size)


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


def _clear_derivable_transport_fields(
    pkt: ParsedPacket, hdr: object, payload: bytes, truncated: bool = False,
) -> None:
    """Drop a captured length or checksum that a rebuild would derive anyway.

    ``TCPHeader.checksum`` and ``UDPHeader.length`` / ``UDPHeader.checksum``
    are overrides: set, they are written out verbatim; ``None``, they are
    computed from the bytes beside them.  The parser captures both
    unconditionally, and this clears whichever the builder would have arrived
    at on its own.

    What survives is exactly what a rebuild could not work out for itself — a
    checksum that was wrong on the wire, and the length and checksum of a
    fragmented datagram's first fragment, which describe the whole datagram
    rather than the fragment carrying them.  Keeping the fields only in that
    case is what stops every packet spec growing two redundant keys.

    A *truncated* payload clears both instead of comparing them.  The derived
    values would be computed from fewer bytes than the sender used, so keeping
    the captured ones would say "wrong on the wire" about every packet of a
    snaplen-limited capture; and a rebuild of a truncated packet does not
    reproduce the original either way, so there is nothing for them to
    preserve.  The cost is that corruption cannot be reported at all in a
    truncated capture — the bytes the sender checksummed are not in the file,
    so "unknown" is the only honest answer.

    Does nothing when the IP header is missing, since the derived values
    cannot be computed at all.

    Args:
        pkt: Packet the header belongs to; supplies the IP addresses the
            transport checksum's pseudo-header needs.
        hdr: Parsed transport header, modified in place.
        payload: Bytes after the transport header, as captured.
        truncated: Whether *payload* is shorter than the IP header declares —
            see :func:`_ip_payload_size`.

    """
    if not isinstance(hdr, (TCPHeader, UDPHeader)) or pkt.ip is None:
        return
    if truncated:
        hdr.checksum = None
        if isinstance(hdr, UDPHeader):
            hdr.length = None
        return
    src, dst = pkt.ip.src, pkt.ip.dst
    version = 6 if isinstance(pkt.ip, IPv6Header) else 4

    if isinstance(hdr, UDPHeader):
        captured_length, captured_checksum = hdr.length, hdr.checksum
        hdr.length = hdr.checksum = None
        if captured_length != 8 + len(payload):
            hdr.length = captured_length
        try:
            derived = _build_udp_header(hdr, payload, src, dst, version)
        except OSError:
            hdr.length, hdr.checksum = captured_length, captured_checksum
            return
        if captured_checksum != struct.unpack("!H", derived[6:8])[0]:
            hdr.checksum = captured_checksum
        return

    captured_checksum = hdr.checksum
    hdr.checksum = None
    try:
        derived = _build_tcp_header(hdr, payload, src, dst, version)
    except OSError:
        hdr.checksum = captured_checksum
        return
    if captured_checksum != struct.unpack("!H", derived[16:18])[0]:
        hdr.checksum = captured_checksum


def _parse_ip_protocol(
    pkt: ParsedPacket, remaining: bytes, ip_proto: int | None, decode_app: bool = True,
    base: int = 0, truncated: bool = False,
) -> tuple[bytes, int]:
    """Parse the IP protocol layer (transport or tunnel).

    Fills in transport/tunnel fields on *pkt* and returns the remaining
    (payload) bytes together with where they start.

    Args:
        pkt: Packet object to fill in.
        remaining: Bytes after the IP header.
        ip_proto: IP protocol number, or ``None`` when unknown.
        decode_app: When ``False``, skip the DNS/DHCP/HTTP decoders so the
            transport payload is returned as it appeared on the wire.  See
            :func:`parse_packet`.
        base: Offset of *remaining* within the frame being parsed.
        truncated: Whether the capture holds fewer bytes than the IP header
            declares, as from a snaplen.  Passed to
            :func:`_clear_derivable_transport_fields`.

    Returns:
        ``(payload, offset)`` — the bytes after every consumed header, and the
        offset of the first of them within the frame.

    """
    transport_parser = _TRANSPORT_PARSERS.get(ip_proto) if ip_proto is not None else None
    if transport_parser is not None:
        t_size, _, t_hdr = transport_parser(remaining)
        if t_size > 0:
            pkt.transport = t_hdr
            _clear_derivable_transport_fields(
                pkt, t_hdr, remaining[t_size:], truncated,
            )
            remaining = remaining[t_size:]
            base += t_size
            if _try_parse_vxlan(pkt, remaining, decode_app, base):
                return (b"", base)
            if _try_parse_geneve(pkt, remaining, decode_app, base):
                return (b"", base)
            gtpu_result = _try_parse_gtpu(pkt, remaining, decode_app, base)
            if gtpu_result is not None:
                return gtpu_result
            if decode_app:
                remaining = _try_parse_app(pkt, remaining)
    elif ip_proto in (4, 41):
        pkt.ipip = True
        inner = parse_packet(remaining, link_type=LINKTYPE_RAW, decode_app=decode_app)
        _shift_offsets(inner, base)
        pkt.tunneled = inner
        return (b"", base)
    elif ip_proto == IPPROTO_GRE:
        g_size, proto_type, g_hdr = _gre_parser(remaining)
        if g_size > 0 and g_hdr is not None:
            pkt.gre = g_hdr
            inner_lt = LINKTYPE_ETHERNET if proto_type == GRE_PROTO_TEB else LINKTYPE_RAW
            inner = parse_packet(
                remaining[g_size:], link_type=inner_lt, decode_app=decode_app,
            )
            _shift_offsets(inner, base + g_size)
            pkt.tunneled = inner
            return (b"", base + g_size)
    elif ip_proto == IPPROTO_ETHERIP:
        ei_size, _, ei_hdr = _etherip_parser(remaining)
        if ei_size > 0 and ei_hdr is not None:
            pkt.etherip = ei_hdr
            inner = parse_packet(
                remaining[ei_size:], link_type=LINKTYPE_ETHERNET, decode_app=decode_app,
            )
            _shift_offsets(inner, base + ei_size)
            pkt.tunneled = inner
            return (b"", base + ei_size)
    elif ip_proto == IPPROTO_AH:
        ah_size, next_header, ah_hdr = _ah_parser(remaining)
        if ah_size > 0 and ah_hdr is not None:
            pkt.ah = ah_hdr
            # AH is transparent: continue parsing the protected content.
            return _parse_ip_protocol(
                pkt, remaining[ah_size:], next_header, decode_app, base + ah_size,
                truncated,
            )
    elif ip_proto == IPPROTO_ESP:
        e_size, _, e_hdr = _esp_parser(remaining)
        if e_size > 0 and e_hdr is not None:
            pkt.esp = e_hdr
            # ESP payload is encrypted/opaque without the key.
            return (remaining[e_size:], base + e_size)
    elif ip_proto is not None:
        warnings.warn(
            UnsupportedIPProtocolWarning(
                f"IP protocol {ip_proto} is not supported; "
                "bytes after the IP header are stored in ParsedPacket.payload",
                ip_proto,
            ),
            stacklevel=3,
        )
    return (remaining, base)


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
    # Only whole headers have been removed from the front so far, so the
    # length difference is the offset.  That stops being true below, once the
    # IP datagram's declared length can trim bytes off the end.
    offset = len(data) - len(remaining)

    layer_result = _parse_pppoe_and_mpls(pkt, remaining, ethertype, decode_app, offset)
    if layer_result is None:
        return pkt
    remaining, _, offset = layer_result

    # ── IP ────────────────────────────────────────────────────────────────────
    ip_size, ip_proto, ip_hdr = _ip_parser(remaining)
    if ip_size == 0:
        _set_payload(pkt, remaining, offset)
        return pkt
    pkt.ip = ip_hdr
    remaining = remaining[ip_size:]
    offset += ip_size

    # Discard anything past the end of the IP datagram — for a frame below the
    # 60-byte Ethernet minimum that is the sender's zero padding, which is not
    # part of the datagram and must not reach the payload.  When the declared
    # size exceeds what was captured (a snaplen-truncated record) keep every
    # captured byte instead.
    declared = _ip_payload_size(ip_hdr, ip_size)
    truncated = declared is not None and declared > len(remaining)
    if declared is not None and declared < len(remaining):
        remaining = remaining[:declared]

    if _is_non_first_fragment(ip_hdr):
        # Payload bytes from the middle of a datagram — there is no header
        # here to parse.  Reassemble with packeteer.parse.defragment first.
        _set_payload(pkt, remaining, offset)
        return pkt

    payload, payload_at = _parse_ip_protocol(
        pkt, remaining, ip_proto, decode_app, offset, truncated,
    )
    _set_payload(pkt, payload, payload_at)
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
    pkt.tick_hz = file_header.tick_hz
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


def _defragmented_records(
    pcap: PcapFile,
) -> Iterator[tuple[bytes, int, int]]:
    """Yield a capture's records with fragmented datagrams reassembled.

    Each reassembled datagram takes the timestamp of the fragment that
    completed it.  Incomplete datagrams are dropped.
    """
    engine = Defragmenter(link_type=pcap.header.link_type)
    tick_hz = pcap.header.tick_hz
    for data, ts_sec, ts_frac in pcap.packets:
        when = ts_sec + ts_frac / tick_hz
        for assembled in engine.feed(data, when, token=(ts_sec, ts_frac)):
            last_sec, last_frac = assembled.tokens[-1]
            yield (assembled.frame, last_sec, last_frac)
    engine.flush()


def parse_pcap_file(
    *,
    path: str | os.PathLike | None = None,
    file_object: io.RawIOBase | io.BufferedIOBase | None = None,
    output: dict[str, Any] | None = None,
    packet_filter: PacketFilter | None = None,
    link_type: int | None = None,
    decode_app: bool = True,
    defragment: bool = False,
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
        defragment: When ``True``, fragmented datagrams are reassembled and
            each appears once, as a whole packet.  Off by default because a
            spec is the round-trip format: a fragmented capture parses and
            rebuilds byte-for-byte as it is, whereas reassembling first means
            ``packeteer build`` emits unfragmented packets and the capture no
            longer round-trips.  Datagrams whose fragments never all arrive
            are dropped.  For analysis rather than round-tripping, prefer
            :func:`iter_packets`, where reassembly is the default.

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

    records: Iterable[tuple[bytes, int, int]] = pcap.packets
    if defragment:
        records = _defragmented_records(pcap)

    with warnings.catch_warnings(record=True) as _caught:
        warnings.filterwarnings("always", category=UnsupportedIPProtocolWarning)
        for packet_num, record in enumerate(records, 1):
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


class PacketReader:
    """Streaming reader over a capture's whole, parsed packets.

    Returned by :func:`iter_packets`.  Iterate it for
    :class:`ParsedPacket` objects; the file-level facts a consumer needs
    alongside them — the capture's header, and what reassembly discarded —
    are attributes here rather than being withheld.

    .. code-block:: python

        from packeteer.parse import iter_packets

        with iter_packets(path="capture.pcap") as capture:
            print(capture.header.tick_hz)      # before the first packet
            for pkt in capture:
                ...
            for lost in capture.incomplete:    # after iteration
                ...

    The file is opened when the reader is created, so :attr:`header` is
    available immediately and a malformed capture raises there rather than on
    first iteration.  It is closed when iteration finishes, or when the
    generator is discarded — so stopping early is safe.  A reader that is
    never iterated at all, though, holds the file until it is collected, the
    same as :class:`~packeteer.pcap.PcapReader`: use a ``with`` block, or call
    :meth:`close`, whenever the packets might not all be read.

    :attr:`header` is what makes a packet's ``ts_frac`` interpretable and
    names the link type; :attr:`incomplete` is what reassembly discarded.
    Both are needed by anything doing real work with a capture, and neither is
    reachable from a bare stream of packets.

    """

    def __init__(
        self,
        reader: PcapReader,
        engine: Defragmenter | None,
        decode_app: bool,
    ) -> None:
        self._reader = reader
        self._engine = engine
        self._decode_app = decode_app

    @property
    def header(self) -> PcapFileHeader:
        """The capture's file header, available before the first packet.

        Its ``link_type`` and ``tick_hz`` are file-level facts: ``tick_hz``
        states what a packet's ``ts_frac`` is counted in, without which a
        fraction of ``250`` could be milliseconds, microseconds, or
        nanoseconds.
        """
        return self._reader.header

    @property
    def incomplete(self) -> list[IncompleteDatagram]:
        """Datagrams reassembly gave up on and dropped.

        Grows as datagrams are abandoned, so it is only complete once
        iteration has finished — the same contract
        :attr:`~packeteer.parse.defragment.Defragmenter.incomplete` has.
        Always empty when ``defragment=False``, since nothing is dropped.
        """
        return self._engine.incomplete if self._engine is not None else []

    def __iter__(self) -> Iterator[ParsedPacket]:
        """Yield one :class:`ParsedPacket` per whole packet."""
        return self._packets()

    def __enter__(self) -> PacketReader:
        """Enter the context manager, returning this reader."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Close the underlying capture."""
        self.close()

    def close(self) -> None:
        """Close the capture, if this reader opened it from a path.

        Safe to call more than once.  A capture supplied as a *file_object* is
        never closed — the caller owns it.
        """
        self._reader.close()

    def _packets(self) -> Iterator[ParsedPacket]:
        """Read, reassemble, and parse, closing the capture when exhausted."""
        link_type = self._reader.header.link_type
        tick_hz = self._reader.header.tick_hz
        with self._reader:
            if self._engine is None:
                for record in self._reader:
                    yield _packet_from_records(
                        record.data, link_type, self._decode_app, [record],
                    )
                return
            for record in self._reader:
                when = record.ts_sec + record.ts_frac / tick_hz
                for assembled in self._engine.feed(record.data, when, token=record):
                    yield _packet_from_records(
                        assembled.frame, link_type, self._decode_app, assembled.tokens,
                    )
            self._engine.flush()


def iter_packets(
    *,
    path: str | os.PathLike | None = None,
    file_object: io.RawIOBase | io.BufferedIOBase | None = None,
    link_type: int | None = None,
    decode_app: bool = True,
    defragment: bool = True,
) -> PacketReader:
    """Read a capture as whole, parsed packets.

    The convenient front door: it opens the file, reassembles fragmented
    datagrams, and parses each result, which is the three-step sequence a
    consumer otherwise writes by hand.  Packets stream one at a time, so a
    capture larger than memory is fine.

    .. code-block:: python

        from packeteer.parse import iter_packets

        for pkt in iter_packets(path="capture.pcap"):
            if pkt.transport is not None:
                print(pkt.ip.src, "->", pkt.ip.dst, len(pkt.payload))

    Fragments are reassembled by default because a caller asking for packets
    almost never wants the pieces: a fragmented datagram would otherwise
    arrive as several packets, only the first with a transport header.  Pass
    ``defragment=False`` to see the capture's records exactly as they are.

    Each packet carries :attr:`ParsedPacket.source_records`, the capture
    records behind it — one for an ordinary packet, several for a reassembled
    datagram.  With :attr:`~packeteer.pcap.PcapRecord.data_offset` and
    :attr:`ParsedPacket.payload_offset` that is enough to cite where a
    payload's bytes live in the file.

    The returned :class:`PacketReader` also exposes the two file-level facts
    that hiding the records would otherwise cost a caller — the capture's
    header, and the datagrams reassembly gave up on:

    .. code-block:: python

        with iter_packets(path="capture.pcap") as capture:
            print(capture.header.tick_hz, capture.header.link_type)
            for pkt in capture:
                ...
            for lost in capture.incomplete:
                print("dropped:", lost.src, lost.dst, lost.reason)

    Exactly one of *path* or *file_object* must be supplied.

    Args:
        path: Path to the ``.pcap`` or ``.pcapng`` file.
        file_object: Readable binary file-like object positioned at the start
            of the capture.  It is not closed.
        link_type: Override the link-layer type recorded in the file header.
        decode_app: Passed to :func:`parse_packet`.  ``False`` keeps DNS,
            DHCP, and HTTP payloads as raw bytes.
        defragment: When ``True`` (default), fragments are reassembled and a
            datagram is yielded once, where its final fragment arrived.  A
            datagram whose fragments never all arrive is dropped and recorded
            in :attr:`PacketReader.incomplete`.

    Returns:
        A :class:`PacketReader`, iterating :class:`ParsedPacket` objects.
        Each packet's ``ts_sec`` / ``ts_frac`` come from the record that
        completed it, so for a reassembled datagram they are the last
        contributing fragment's; ``source_records[0]`` has the first
        fragment's time, and ``timestamp`` gives seconds directly.

    Raises:
        ValueError: If neither or both of *path* / *file_object* are given, or
            the capture is malformed.
        OSError: If *path* cannot be opened for reading.

    """
    reader = open_pcap(path=path, file_object=file_object, link_type=link_type)
    try:
        engine = Defragmenter(link_type=reader.header.link_type) if defragment else None
        return PacketReader(reader, engine, decode_app)
    except BaseException:
        reader.close()
        raise


def _packet_from_records(
    frame: bytes, link_type: int, decode_app: bool, records: list[PcapRecord],
) -> ParsedPacket:
    """Parse *frame* and attach the capture records it came from."""
    pkt = parse_packet(frame, link_type=link_type, decode_app=decode_app)
    last = records[-1]
    pkt.ts_sec = last.ts_sec
    pkt.ts_frac = last.ts_frac
    pkt.tick_hz = last.tick_hz
    pkt.source_records = list(records)
    return pkt
