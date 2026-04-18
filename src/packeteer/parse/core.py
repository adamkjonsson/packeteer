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

import os
import io
import socket
import struct
from dataclasses import dataclass, field
from typing import Any

from packeteer.generate.ethernet import (
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    EthernetHeader,
)
from packeteer.generate.ip import IPHeader
from packeteer.generate.ipv6 import IPv6Header
from packeteer.generate.etherip import EtherIPHeader, IPPROTO_ETHERIP
from packeteer.generate.gre import GREHeader, IPPROTO_GRE, GRE_PROTO_TEB
from packeteer.generate.mpls import MPLSLabel, ETHERTYPE_MPLS_UNICAST, ETHERTYPE_MPLS_MULTICAST
from packeteer.generate.pppoe import PPPoEHeader, ETHERTYPE_PPPOE_DISCOVERY, ETHERTYPE_PPPOE_SESSION
from packeteer.generate.tcp import TCPHeader
from packeteer.generate.udp import UDPHeader
from packeteer.generate.icmp import ICMPHeader
from packeteer.generate.icmpv6 import ICMPv6Header
from packeteer.generate.sctp import SCTPHeader
from packeteer.generate.dns import DNSMessage
from packeteer.generate.dhcp import DHCPMessage
from packeteer.pcap import LINKTYPE_ETHERNET, LINKTYPE_RAW, PcapFileHeader, read_pcap
from .to_config import update_config, to_packet_spec, to_json_string, apply_tunneled

from .ethernet import packet_parser as _ethernet_parser
from .etherip import packet_parser as _etherip_parser
from .gre import packet_parser as _gre_parser
from .mpls import packet_parser as _mpls_parser
from .pppoe import packet_parser as _pppoe_parser
from .ip import packet_parser as _ip_parser
from .tcp import packet_parser as _tcp_parser
from .udp import packet_parser as _udp_parser
from .icmp import packet_parser as _icmp_parser
from .icmpv6 import packet_parser as _icmpv6_parser
from .sctp import packet_parser as _sctp_parser
from .dns import parse_dns_udp as _parse_dns_udp, parse_dns_tcp as _parse_dns_tcp

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
        tunneled: Inner packet parsed recursively when :attr:`ipip` is
            ``True``, :attr:`gre` is set, or :attr:`etherip` is set,
            otherwise ``None``.  May itself have a non-``None``
            :attr:`gre`, :attr:`ipip`, or :attr:`etherip` for
            double-nested tunnels.
        transport: Parsed TCP, UDP, ICMPv4, or ICMPv6 header.
        dns: Parsed DNS or mDNS message when the transport port is 53 or
            5353, otherwise ``None``.  Populated from the payload bytes; on
            parse failure the raw bytes remain in :attr:`payload` and this
            field is ``None``.
        dhcp: Parsed DHCP message when the transport is UDP on port 67 or 68,
            otherwise ``None``.  On parse failure the raw bytes remain in
            :attr:`payload` and this field is ``None``.
        payload: Bytes remaining after all parsed headers.
        ts_sec: Capture timestamp — whole seconds (from pcap record).
        ts_frac: Capture timestamp — sub-second fraction (microseconds or
            nanoseconds depending on the pcap file's magic number).

    """

    ethernet:  EthernetHeader | None = None
    mpls:      list[MPLSLabel] = field(default_factory=list)
    pppoe:     PPPoEHeader | None = None
    ip:        IPHeader | IPv6Header | None = None
    ipip:      bool = False
    gre:       GREHeader | None = None
    etherip:   EtherIPHeader | None = None
    tunneled:  "ParsedPacket | None" = None
    transport: TCPHeader | UDPHeader | ICMPHeader | ICMPv6Header | SCTPHeader | None = None
    dns:       DNSMessage | None = None
    dhcp:      DHCPMessage | None = None
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
        ETHERTYPE_IPV4, ETHERTYPE_IPV6,
        ETHERTYPE_MPLS_UNICAST, ETHERTYPE_MPLS_MULTICAST,
        ETHERTYPE_PPPOE_DISCOVERY, ETHERTYPE_PPPOE_SESSION,
    )
    if link_type == LINKTYPE_ETHERNET:
        eth_size, ethertype, eth_hdr = _ethernet_parser(data)
        if eth_size == 0:
            pkt.payload = data
            return None
        pkt.ethernet = eth_hdr
        remaining = data[eth_size:]
        if ethertype not in _KNOWN_ETHERTYPES:
            pkt.payload = remaining
            return None
        return remaining, ethertype
    if link_type == LINKTYPE_RAW:
        return data, None   # raw IP — skip MPLS loop below
    pkt.payload = data
    return None


def _parse_pppoe_and_mpls(
    pkt: ParsedPacket, data: bytes, ethertype: int | None,
) -> tuple[bytes, int | None] | None:
    """Parse MPLS labels and PPPoE header.

    Returns ``(remaining, ip_ethertype)`` or ``None`` when parsing is complete.

    Args:
        pkt: Packet object to fill in.
        data: Remaining bytes after the Ethernet header.
        ethertype: EtherType from the Ethernet layer, or ``None`` for raw IP.

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

    if ethertype is not None and ethertype not in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
        pkt.payload = remaining
        return None
    return remaining, ethertype


_DNS_PORTS:  frozenset[int] = frozenset({53, 5353})
_DHCP_PORTS: frozenset[int] = frozenset({67, 68})


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


def _parse_ip_protocol(
    pkt: ParsedPacket, remaining: bytes, ip_proto: int | None,
) -> bytes:
    """Parse the IP protocol layer (transport or tunnel).

    Fills in transport/tunnel fields on *pkt* and returns the remaining
    (payload) bytes.

    Args:
        pkt: Packet object to fill in.
        remaining: Bytes after the IP header.
        ip_proto: IP protocol number, or ``None`` when unknown.

    Returns:
        Remaining bytes after consuming transport/tunnel headers.

    """
    transport_parser = _TRANSPORT_PARSERS.get(ip_proto) if ip_proto is not None else None
    if transport_parser is not None:
        t_size, _, t_hdr = transport_parser(remaining)
        if t_size > 0:
            pkt.transport = t_hdr
            remaining = remaining[t_size:]
            remaining = _try_parse_dns(pkt, remaining)
            remaining = _try_parse_dhcp(pkt, remaining)
    elif ip_proto in (4, 41):
        pkt.ipip = True
        pkt.tunneled = parse_packet(remaining, link_type=LINKTYPE_RAW)
        return b""
    elif ip_proto == IPPROTO_GRE:
        g_size, proto_type, g_hdr = _gre_parser(remaining)
        if g_size > 0 and g_hdr is not None:
            pkt.gre = g_hdr
            inner_lt = LINKTYPE_ETHERNET if proto_type == GRE_PROTO_TEB else LINKTYPE_RAW
            pkt.tunneled = parse_packet(remaining[g_size:], link_type=inner_lt)
            return b""
    elif ip_proto == IPPROTO_ETHERIP:
        ei_size, _, ei_hdr = _etherip_parser(remaining)
        if ei_size > 0 and ei_hdr is not None:
            pkt.etherip = ei_hdr
            pkt.tunneled = parse_packet(remaining[ei_size:], link_type=LINKTYPE_ETHERNET)
            return b""
    return remaining


def parse_packet(data: bytes, *, link_type: int = LINKTYPE_ETHERNET) -> ParsedPacket:
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
    - **Transport**: TCP, UDP, ICMPv4, or ICMPv6.
    - **Payload**: Any bytes after the last parsed header.

    Args:
        data: Raw packet bytes (from a pcap record, socket, or
            :meth:`PacketBuilder.build`).
        link_type: Link-layer type.  Use :data:`LINKTYPE_ETHERNET` (``1``,
            default) when an Ethernet header is present, or
            :data:`LINKTYPE_RAW` (``101``) for raw IP packets.

    Returns:
        A :class:`ParsedPacket` with each successfully parsed layer filled in.
        Layers that are absent or fail to parse are ``None``.

    """
    pkt = ParsedPacket()

    link_result = _parse_link_layer(pkt, data, link_type)
    if link_result is None:
        return pkt
    remaining, ethertype = link_result

    layer_result = _parse_pppoe_and_mpls(pkt, remaining, ethertype)
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

    pkt.payload = _parse_ip_protocol(pkt, remaining, ip_proto)
    return pkt


def parse_pcap_packet(
    record: tuple[bytes, int, int],
    file_header: PcapFileHeader,
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

    Returns:
        A :class:`ParsedPacket` with all recognised layers filled in and
        ``ts_sec`` / ``ts_frac`` set from the record.  ``ts_frac`` is in
        microseconds when ``file_header.nanoseconds`` is ``False``, or
        nanoseconds when it is ``True``.

    """
    data, ts_sec, ts_frac = record
    pkt = parse_packet(data, link_type=file_header.link_type)
    pkt.ts_sec  = ts_sec
    pkt.ts_frac = ts_frac
    return pkt


def parse_pcap_file(
    *,
    path: str | os.PathLike | None = None,
    file_object: io.RawIOBase | io.BufferedIOBase | None = None,
    output: dict[str, Any] | None = None,
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
            ``"nanoseconds"`` is set automatically from the source file and
            must not be supplied here.

    Returns:
        A JSON string whose top-level structure matches the format accepted by
        ``packeteer build``.

    Raises:
        ValueError: If neither or both of *path* / *file_object* are given, or
            if the pcap data is malformed.
        OSError: If *path* cannot be opened for reading.

    """
    pcap = read_pcap(path=path, file_object=file_object)
    ts_frac_key = "timestamp_ns" if pcap.header.nanoseconds else "timestamp_us"

    packet_configs: list[dict[str, Any]] = []
    for record in pcap.packets:
        pkt = parse_pcap_packet(record, pcap.header)
        cfg: dict[str, Any] = {}
        if pkt.ethernet is not None:
            update_config(cfg, pkt.ethernet)
        for mpls_label in pkt.mpls:
            update_config(cfg, mpls_label)
        if pkt.pppoe is not None:
            update_config(cfg, pkt.pppoe)
        if pkt.ip is not None:
            update_config(cfg, pkt.ip)
        if pkt.ipip or pkt.gre is not None or pkt.etherip is not None:
            apply_tunneled(cfg, pkt)
        elif pkt.transport is not None:
            update_config(cfg, pkt.transport)
            if pkt.dns is not None:
                update_config(cfg, pkt.dns)
            elif pkt.dhcp is not None:
                update_config(cfg, pkt.dhcp)
            elif pkt.payload:
                update_config(cfg, pkt.payload)
        cfg["packet_metadata"] = {"timestamp_s": pkt.ts_sec, ts_frac_key: pkt.ts_frac}
        packet_configs.append(cfg)

    global_output: dict[str, Any] = dict(output) if output is not None else {}
    global_output.setdefault("nanoseconds", pcap.header.nanoseconds)
    if output is not None:
        # version_major 1 = pcapng, 2 = pcap
        file_type = "pcapng" if pcap.header.version_major == 1 else "pcap"
        global_output.setdefault("type", file_type)

    return to_json_string(to_packet_spec(packet_configs, metadata=global_output))
