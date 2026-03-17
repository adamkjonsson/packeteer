import struct
from dataclasses import dataclass

from .checksum import ones_complement_checksum


@dataclass
class ICMPHeader:
    type: int = 8       # Echo Request
    code: int = 0
    identifier: int = 1
    sequence: int = 1


def build_icmp_header(hdr: ICMPHeader, payload: bytes) -> bytes:
    """Build an 8-byte ICMPv4 header with correct checksum (no pseudo-header)."""
    raw = struct.pack('!BBHHH', hdr.type, hdr.code, 0, hdr.identifier, hdr.sequence)
    checksum = ones_complement_checksum(raw + payload)
    return raw[:2] + struct.pack('!H', checksum) + raw[4:]
