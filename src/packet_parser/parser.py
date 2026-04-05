"""High-level packet parser.

Parses a raw ``bytes`` object as a complete network packet by chaining the
individual layer parsers, using the ``next_layer_id`` returned by each one to
select the next parser automatically.

Example — single raw packet::

    from packet_parser.parser import parse_packet
    from packet_generator import PacketBuilder
    from packet_generator.pcap import LINKTYPE_RAW

    raw = PacketBuilder().ip(src="10.0.0.1", dst="10.0.0.2").tcp(dst_port=443).build()
    pkt = parse_packet(raw, link_type=LINKTYPE_RAW)

    print(pkt.ip.src, "->", pkt.ip.dst)
    print("dst_port:", pkt.transport.dst_port)
    print("payload:", pkt.payload.hex())

Example — reading from a pcap file::

    from packet_parser.pcap import read_pcap
    from packet_parser.parser import parse_pcap_packet

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
from dataclasses import dataclass, field
from typing import Any

from packet_generator.ethernet import (
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    EthernetHeader,
    VLANTag,
)
from packet_generator.ip import IPHeader
from packet_generator.ipv6 import IPv6Header
from packet_generator.etherip import EtherIPHeader, IPPROTO_ETHERIP
from packet_generator.gre import GREHeader, IPPROTO_GRE, GRE_PROTO_TEB
from packet_generator.mpls import MPLSLabel, ETHERTYPE_MPLS_UNICAST, ETHERTYPE_MPLS_MULTICAST
from packet_generator.pppoe import PPPoEHeader, ETHERTYPE_PPPOE_DISCOVERY, ETHERTYPE_PPPOE_SESSION
from packet_generator.tcp import TCPHeader
from packet_generator.udp import UDPHeader
from packet_generator.icmp import ICMPHeader
from packet_generator.icmpv6 import ICMPv6Header
from packet_generator.sctp import SCTPHeader
from packet_generator.pcap import LINKTYPE_ETHERNET, LINKTYPE_RAW

from packet_parser.pcap import PcapFileHeader, read_pcap
from packet_parser.to_config import update_config, to_json_config, to_json_string, _apply_etherip, _apply_ipip, _apply_gre

from packet_parser.ethernet import packet_parser as _ethernet_parser
from packet_parser.etherip import packet_parser as _etherip_parser
from packet_parser.gre import packet_parser as _gre_parser
from packet_parser.mpls import packet_parser as _mpls_parser
from packet_parser.pppoe import packet_parser as _pppoe_parser
from packet_parser.ip import packet_parser as _ip_parser
from packet_parser.tcp import packet_parser as _tcp_parser
from packet_parser.udp import packet_parser as _udp_parser
from packet_parser.icmp import packet_parser as _icmp_parser
from packet_parser.icmpv6 import packet_parser as _icmpv6_parser
from packet_parser.sctp import packet_parser as _sctp_parser

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
    payload:   bytes = field(default=b"")
    ts_sec:    int = 0
    ts_frac:   int = 0


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
    remaining = data

    # ── Ethernet ──────────────────────────────────────────────────────────────
    if link_type == LINKTYPE_ETHERNET:
        eth_size, ethertype, eth_hdr = _ethernet_parser(remaining)
        if eth_size == 0:
            pkt.payload = remaining
            return pkt
        pkt.ethernet = eth_hdr
        remaining = remaining[eth_size:]
        # ethertype is the inner EtherType (VLAN already unwrapped by the parser)
        if ethertype not in (ETHERTYPE_IPV4, ETHERTYPE_IPV6,
                             ETHERTYPE_MPLS_UNICAST, ETHERTYPE_MPLS_MULTICAST,
                             ETHERTYPE_PPPOE_DISCOVERY, ETHERTYPE_PPPOE_SESSION):
            pkt.payload = remaining
            return pkt
    elif link_type != LINKTYPE_RAW:
        pkt.payload = remaining
        return pkt
    else:
        ethertype = None   # raw IP — skip MPLS loop below

    # ── MPLS ──────────────────────────────────────────────────────────────────
    while ethertype in (ETHERTYPE_MPLS_UNICAST, ETHERTYPE_MPLS_MULTICAST):
        m_size, ethertype, m_hdr = _mpls_parser(remaining)
        if m_size == 0 or m_hdr is None:
            pkt.payload = remaining
            return pkt
        pkt.mpls.append(m_hdr)
        remaining = remaining[m_size:]

    # ── PPPoE ─────────────────────────────────────────────────────────────────
    if ethertype in (ETHERTYPE_PPPOE_DISCOVERY, ETHERTYPE_PPPOE_SESSION):
        p_size, ethertype, pppoe_hdr = _pppoe_parser(remaining)
        if p_size == 0 or pppoe_hdr is None:
            pkt.payload = remaining
            return pkt
        pkt.pppoe = pppoe_hdr
        remaining = remaining[p_size:]
        if ethertype is None:  # discovery frame — no IP follows
            pkt.payload = remaining
            return pkt

    if ethertype is not None and ethertype not in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
        pkt.payload = remaining
        return pkt

    # ── IP ────────────────────────────────────────────────────────────────────
    ip_size, ip_proto, ip_hdr = _ip_parser(remaining)
    if ip_size == 0:
        pkt.payload = remaining
        return pkt
    pkt.ip = ip_hdr
    remaining = remaining[ip_size:]

    # ── Transport ─────────────────────────────────────────────────────────────
    transport_parser = _TRANSPORT_PARSERS.get(ip_proto) if ip_proto is not None else None
    if transport_parser is not None:
        t_size, _, t_hdr = transport_parser(remaining)
        if t_size > 0:
            pkt.transport = t_hdr
            remaining = remaining[t_size:]

    # ── IP-in-IP (RFC 2003 / RFC 4213) ───────────────────────────────────────
    elif ip_proto in (4, 41):
        pkt.ipip    = True
        pkt.tunneled = parse_packet(remaining, link_type=LINKTYPE_RAW)
        pkt.payload  = b""
        return pkt

    # ── GRE (RFC 2784 / RFC 2890) ─────────────────────────────────────────────
    elif ip_proto == IPPROTO_GRE:
        g_size, proto_type, g_hdr = _gre_parser(remaining)
        if g_size > 0 and g_hdr is not None:
            pkt.gre = g_hdr
            if proto_type == GRE_PROTO_TEB:
                pkt.tunneled = parse_packet(remaining[g_size:], link_type=LINKTYPE_ETHERNET)
            else:
                pkt.tunneled = parse_packet(remaining[g_size:], link_type=LINKTYPE_RAW)
            pkt.payload = b""
            return pkt

    # ── EtherIP ───────────────────────────────────────────────────────────────
    elif ip_proto == IPPROTO_ETHERIP:
        ei_size, _, ei_hdr = _etherip_parser(remaining)
        if ei_size > 0 and ei_hdr is not None:
            pkt.etherip = ei_hdr
            pkt.tunneled = parse_packet(remaining[ei_size:], link_type=LINKTYPE_ETHERNET)
            pkt.payload = b""
            return pkt

    pkt.payload = remaining
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
            :func:`packet_parser.pcap.read_pcap` — one element of
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
    """Parse every packet in a pcap file and return a JSON config string.

    Reads the file with :func:`packet_parser.pcap.read_pcap`, parses each
    record with :func:`parse_pcap_packet`, converts the layers to a config dict
    with :func:`packet_parser.to_config.update_config`, and serialises the
    result with :func:`packet_parser.to_config.to_json_string`.

    The per-packet ``metadata`` block is populated with ``timestamp_s`` and
    either ``timestamp_us`` or ``timestamp_ns`` (depending on the file's
    timestamp resolution).  When the source file uses nanosecond timestamps,
    ``"nanoseconds": true`` is added to the top-level ``output`` block so that
    the config can be replayed with matching precision.

    Args:
        path: Path to the ``.pcap`` file.
        file_object: Readable binary file-like object positioned at the start
            of the pcap data.
        output: Extra fields to merge into the top-level ``file_metadata``
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
        if pkt.ipip and pkt.tunneled is not None:
            _apply_ipip(cfg, pkt.tunneled)
        elif pkt.gre is not None and pkt.tunneled is not None:
            _apply_gre(cfg, pkt.gre, pkt.tunneled)
        elif pkt.etherip is not None and pkt.tunneled is not None:
            _apply_etherip(cfg, pkt.etherip, pkt.tunneled)
        elif pkt.transport is not None:
            update_config(cfg, pkt.transport)
            if pkt.payload:
                update_config(cfg, pkt.payload)
        cfg["metadata"] = {"timestamp_s": pkt.ts_sec, ts_frac_key: pkt.ts_frac}
        packet_configs.append(cfg)

    global_output: dict[str, Any] = dict(output) if output is not None else {}
    global_output.setdefault("nanoseconds", pcap.header.nanoseconds)
    if output is not None:
        # version_major 1 = pcapng, 2 = pcap
        file_type = "pcapng" if pcap.header.version_major == 1 else "pcap"
        global_output.setdefault("type", file_type)

    # Include the output block when the caller explicitly provided one (even
    # empty), or when it has content added automatically (e.g. nanoseconds).
    include_output = output is not None or bool(global_output)
    return to_json_string(to_json_config(packet_configs, file_metadata=global_output if include_output else None))
