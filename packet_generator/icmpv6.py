import socket
import struct
from dataclasses import dataclass

from .checksum import ones_complement_checksum


@dataclass
class ICMPv6Header:
    type: int = 128     # Echo Request (129 = Echo Reply)
    code: int = 0
    identifier: int = 1
    sequence: int = 1


def build_icmpv6_header(
    hdr: ICMPv6Header,
    payload: bytes,
    src_ip: str,
    dst_ip: str,
) -> bytes:
    """Build an 8-byte ICMPv6 header with checksum over IPv6 pseudo-header."""
    raw = struct.pack('!BBHHH', hdr.type, hdr.code, 0, hdr.identifier, hdr.sequence)
    icmpv6_length = len(raw) + len(payload)

    pseudo = (
        socket.inet_pton(socket.AF_INET6, src_ip)
        + socket.inet_pton(socket.AF_INET6, dst_ip)
        + struct.pack('!I3sB', icmpv6_length, b'\x00\x00\x00', 58)  # 58 = ICMPv6
    )

    checksum = ones_complement_checksum(pseudo + raw + payload)
    return raw[:2] + struct.pack('!H', checksum) + raw[4:]
