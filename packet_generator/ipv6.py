import socket
import struct
from dataclasses import dataclass


@dataclass
class IPv6Header:
    src: str
    dst: str
    next_header: int
    hop_limit: int = 64
    traffic_class: int = 0
    flow_label: int = 0


def build_ipv6_header(hdr: IPv6Header, payload: bytes) -> bytes:
    """Build a 40-byte IPv6 header (no checksum in the header itself)."""
    version_tc_fl = (6 << 28) | (hdr.traffic_class << 20) | (hdr.flow_label & 0xFFFFF)
    src = socket.inet_pton(socket.AF_INET6, hdr.src)
    dst = socket.inet_pton(socket.AF_INET6, hdr.dst)
    return struct.pack('!I', version_tc_fl) + struct.pack(
        '!HBB16s16s',
        len(payload),       # payload length (excludes this 40-byte header)
        hdr.next_header,
        hdr.hop_limit,
        src,
        dst,
    )
