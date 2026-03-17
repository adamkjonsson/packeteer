import socket
import struct
from dataclasses import dataclass

from .checksum import ones_complement_checksum


@dataclass
class TCPHeader:
    src_port: int
    dst_port: int
    seq: int = 0
    ack: int = 0
    flags: int = 0x002      # SYN
    window: int = 65535
    urgent_ptr: int = 0


def _pseudo_header_v4(src_ip: str, dst_ip: str, tcp_length: int) -> bytes:
    return (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack('!BBH', 0, 6, tcp_length)
    )


def _pseudo_header_v6(src_ip: str, dst_ip: str, tcp_length: int) -> bytes:
    return (
        socket.inet_pton(socket.AF_INET6, src_ip)
        + socket.inet_pton(socket.AF_INET6, dst_ip)
        + struct.pack('!I3sB', tcp_length, b'\x00\x00\x00', 6)
    )


def build_tcp_header(
    hdr: TCPHeader,
    payload: bytes,
    src_ip: str,
    dst_ip: str,
    ip_version: int = 4,
) -> bytes:
    """Build a 20-byte TCP header with correct checksum."""
    data_offset_reserved = (5 << 4)  # 20-byte header, no options
    tcp_length = 20 + len(payload)

    raw = struct.pack(
        '!HHIIBBHHH',
        hdr.src_port,
        hdr.dst_port,
        hdr.seq,
        hdr.ack,
        data_offset_reserved,
        hdr.flags,
        hdr.window,
        0,                  # checksum placeholder
        hdr.urgent_ptr,
    )

    if ip_version == 6:
        pseudo = _pseudo_header_v6(src_ip, dst_ip, tcp_length)
    else:
        pseudo = _pseudo_header_v4(src_ip, dst_ip, tcp_length)

    checksum = ones_complement_checksum(pseudo + raw + payload)
    return raw[:16] + struct.pack('!H', checksum) + raw[18:]
