from __future__ import annotations

import socket
import struct

from packeteer.generate.ip import IPHeader
from packeteer.generate.ipv6 import IPv6Header


def packet_parser(data: bytes) -> tuple[int, int | None, IPHeader | IPv6Header | None]:
    """Parse an IPv4 or IPv6 header from raw bytes.

    Detects the IP version from the high nibble of the first byte and
    dispatches to the appropriate parser.

    IPv4 layout (20+ bytes)::

        Version(4b) | IHL(4b) | TOS(1) | Total Length(2) | ...
        TTL(1) | Protocol(1) | Checksum(2) | Src(4) | Dst(4)
        [ Options: (IHL-5)*4 bytes ]

    IPv6 layout (40 bytes fixed)::

        Version(4b) | Traffic Class(8b) | Flow Label(20b)
        Payload Length(2) | Next Header(1) | Hop Limit(1)
        Src(16) | Dst(16)

    Args:
        data: Raw bytes starting at the first byte of an IP header.

    Returns:
        A tuple of ``(header_size, next_protocol, header)`` where
        *header_size* is the number of bytes consumed, *next_protocol* is the
        protocol number of the encapsulated transport layer, and *header* is
        the parsed :class:`IPHeader` or :class:`IPv6Header` object.  Returns
        ``(0, None, None)`` if parsing fails.

    """
    if len(data) < 1:
        return (0, None, None)

    version = data[0] >> 4

    if version == 4:
        return _parse_ipv4(data)
    if version == 6:
        return _parse_ipv6(data)
    return (0, None, None)


def _parse_ipv4(data: bytes) -> tuple[int, int | None, IPHeader | None]:
    if len(data) < 20:
        return (0, None, None)

    try:
        ihl = data[0] & 0x0F
        if ihl < 5:
            return (0, None, None)
        header_size = ihl * 4
        if len(data) < header_size:
            return (0, None, None)

        tos = data[1]
        identification = struct.unpack("!H", data[4:6])[0]
        flags_frag = struct.unpack("!H", data[6:8])[0]
        flags = (flags_frag >> 13) & 0x7
        fragment_offset = flags_frag & 0x1FFF
        ttl = data[8]
        protocol = data[9]
        src = socket.inet_ntoa(data[12:16])
        dst = socket.inet_ntoa(data[16:20])

        hdr = IPHeader(
            src=src, dst=dst, protocol=protocol,
            ttl=ttl, tos=tos,
            identification=identification,
            flags=flags, fragment_offset=fragment_offset,
        )

    except struct.error:
        return (0, None, None)

    return (header_size, protocol, hdr)


def _parse_ipv6(data: bytes) -> tuple[int, int | None, IPv6Header | None]:
    if len(data) < 40:
        return (0, None, None)

    try:
        version_tc_fl = struct.unpack("!I", data[0:4])[0]
        traffic_class = (version_tc_fl >> 20) & 0xFF
        flow_label = version_tc_fl & 0xFFFFF
        next_header = data[6]
        hop_limit = data[7]
        src = socket.inet_ntop(socket.AF_INET6, data[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, data[24:40])

        hdr = IPv6Header(
            src=src, dst=dst, next_header=next_header,
            hop_limit=hop_limit,
            traffic_class=traffic_class,
            flow_label=flow_label,
        )

    except struct.error:
        return (0, None, None)

    return (40, next_header, hdr)
