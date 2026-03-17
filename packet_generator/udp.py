import socket
import struct
from dataclasses import dataclass

from .checksum import ones_complement_checksum


@dataclass
class UDPHeader:
    src_port: int
    dst_port: int


def _pseudo_header_v4(src_ip: str, dst_ip: str, udp_length: int) -> bytes:
    return (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack('!BBH', 0, 17, udp_length)
    )


def _pseudo_header_v6(src_ip: str, dst_ip: str, udp_length: int) -> bytes:
    return (
        socket.inet_pton(socket.AF_INET6, src_ip)
        + socket.inet_pton(socket.AF_INET6, dst_ip)
        + struct.pack('!I3sB', udp_length, b'\x00\x00\x00', 17)
    )


def build_udp_header(
    hdr: UDPHeader,
    payload: bytes,
    src_ip: str,
    dst_ip: str,
    ip_version: int = 4,
) -> bytes:
    """Build an 8-byte UDP header with correct checksum."""
    udp_length = 8 + len(payload)
    raw = struct.pack('!HHHH', hdr.src_port, hdr.dst_port, udp_length, 0)

    if ip_version == 6:
        pseudo = _pseudo_header_v6(src_ip, dst_ip, udp_length)
    else:
        pseudo = _pseudo_header_v4(src_ip, dst_ip, udp_length)

    checksum = ones_complement_checksum(pseudo + raw + payload)
    # Per RFC 768: a computed zero must be sent as 0xFFFF
    if checksum == 0:
        checksum = 0xFFFF
    return raw[:6] + struct.pack('!H', checksum)
