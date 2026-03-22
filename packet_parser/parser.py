"""High-level packet parser.

Parses a raw ``bytes`` object as a complete network packet by chaining the
individual layer parsers, using the ``next_layer_id`` returned by each one to
select the next parser automatically.

Example — single raw packet::

    from packet_parser.parser import parse_packet, ParsedPacket
    from packet_generator import PacketBuilder, Protocol

    raw = PacketBuilder("10.0.0.1", "10.0.0.2", Protocol.TCP, dst_port=443).build()
    pkt = parse_packet(raw)

    print(pkt.ip.src, "→", pkt.ip.dst)
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
                  f"{pkt.ip.src} → {pkt.ip.dst}:{pkt.transport.dst_port}")
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
from packet_generator.tcp import TCPHeader
from packet_generator.udp import UDPHeader
from packet_generator.icmp import ICMPHeader
from packet_generator.icmpv6 import ICMPv6Header
from packet_generator.pcap import LINKTYPE_ETHERNET, LINKTYPE_RAW

from packet_parser.pcap import PcapFileHeader, read_pcap
from packet_parser.to_config import update_config, to_json_config, to_json_string

from packet_parser.ethernet import packet_parser as _ethernet_parser
from packet_parser.ip import packet_parser as _ip_parser
from packet_parser.tcp import packet_parser as _tcp_parser
from packet_parser.udp import packet_parser as _udp_parser
from packet_parser.icmp import packet_parser as _icmp_parser
from packet_parser.icmpv6 import packet_parser as _icmpv6_parser

_TRANSPORT_PARSERS = {
    socket.IPPROTO_TCP:    _tcp_parser,
    socket.IPPROTO_UDP:    _udp_parser,
    socket.IPPROTO_ICMP:   _icmp_parser,
    socket.IPPROTO_ICMPV6: _icmpv6_parser,
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
        ip: Parsed IPv4 or IPv6 header.
        transport: Parsed TCP, UDP, ICMPv4, or ICMPv6 header.
        payload: Bytes remaining after all parsed headers.
        ts_sec: Capture timestamp — whole seconds (from pcap record).
        ts_frac: Capture timestamp — sub-second fraction (microseconds or
            nanoseconds depending on the pcap file's magic number).
    """

    ethernet:  EthernetHeader | None = None
    ip:        IPHeader | IPv6Header | None = None
    transport: TCPHeader | UDPHeader | ICMPHeader | ICMPv6Header | None = None
    payload:   bytes = field(default=b"")
    ts_sec:    int = 0
    ts_frac:   int = 0


def parse_packet(data: bytes, *, link_type: int = LINKTYPE_ETHERNET) -> ParsedPacket:
    """Parse *data* as a complete network packet.

    Parses each layer in turn, using the ``next_layer_id`` returned by each
    parser to select the next one:

    - **Ethernet** (``link_type=LINKTYPE_ETHERNET``, default): The EtherType
      drives IP-layer selection.  IEEE 802.1Q VLAN tags are decoded inside the
      Ethernet parser; the returned ``EthernetHeader.vlan_tag`` carries the
      tag fields and ``next_layer_id`` is already the inner EtherType.
    - **Raw IP** (``link_type=LINKTYPE_RAW``): Ethernet parsing is skipped;
      IP-version detection starts immediately.
    - **IP**: The protocol/next-header field selects the transport parser.
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
        if ethertype not in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
            pkt.payload = remaining
            return pkt
    elif link_type != LINKTYPE_RAW:
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

    The per-packet ``output`` block is populated with ``timestamp_s`` and
    either ``timestamp_us`` or ``timestamp_ns`` (depending on the file's
    timestamp resolution).  When the source file uses nanosecond timestamps,
    ``"nanoseconds": true`` is added to the top-level ``output`` block so that
    the config can be replayed with matching precision.

    Args:
        path: Path to the ``.pcap`` file.
        file_object: Readable binary file-like object positioned at the start
            of the pcap data.
        output: Extra fields to merge into the top-level ``output`` block
            (e.g. ``{"pcap": "replay.pcap"}``).  ``"nanoseconds"`` is set
            automatically from the source file and must not be supplied here.

    Returns:
        A JSON string whose top-level structure matches the format accepted by
        ``cli.py --config``.

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
        for layer in (pkt.ethernet, pkt.ip, pkt.transport):
            if layer is not None:
                update_config(cfg, layer)
        if pkt.payload:
            update_config(cfg, pkt.payload)
        cfg["output"] = {"timestamp_s": pkt.ts_sec, ts_frac_key: pkt.ts_frac}
        packet_configs.append(cfg)

    global_output: dict[str, Any] = dict(output) if output is not None else {}
    if pcap.header.nanoseconds:
        global_output.setdefault("nanoseconds", True)

    return to_json_string(to_json_config(packet_configs, output=global_output or None))
