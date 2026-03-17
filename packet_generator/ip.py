import socket
import struct
from dataclasses import dataclass, field

from .checksum import ones_complement_checksum


@dataclass
class IPHeader:
    src: str
    dst: str
    protocol: int
    ttl: int = 64
    tos: int = 0
    identification: int = 0
    flags: int = 0b010       # DF bit
    fragment_offset: int = 0


def build_ip_header(hdr: IPHeader, payload: bytes) -> bytes:
    """Build a 20-byte IPv4 header with correct checksum."""
    total_length = 20 + len(payload)
    flags_frag = (hdr.flags << 13) | hdr.fragment_offset
    src = socket.inet_aton(hdr.src)
    dst = socket.inet_aton(hdr.dst)

    # Pack with checksum = 0
    raw = struct.pack(
        '!BBHHHBBH4s4s',
        (4 << 4) | 5,       # version + IHL
        hdr.tos,
        total_length,
        hdr.identification,
        flags_frag,
        hdr.ttl,
        hdr.protocol,
        0,                  # checksum placeholder
        src,
        dst,
    )
    checksum = ones_complement_checksum(raw)
    # Repack with the computed checksum
    return raw[:10] + struct.pack('!H', checksum) + raw[12:]
