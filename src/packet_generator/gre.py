"""GRE tunnel header (RFC 2784 / RFC 2890).

GRE (Generic Routing Encapsulation) wraps any network-layer payload inside an
outer IP datagram.  The outer IP protocol number is 47.

The minimum GRE header is 4 bytes.  RFC 2890 adds optional **Key** (K flag)
and **Sequence Number** (S flag) fields (4 bytes each).  RFC 2784 adds an
optional **Checksum** field (C flag, 4 bytes: 2-byte checksum + 2-byte
reserved).

Wire layout::

     0               1               2               3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |C|0|K|S| Reserved0       | Ver |         Protocol Type         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Checksum (optional)      |       Reserved1               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Key (optional)                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                   Sequence Number (optional)                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The Protocol Type is an EtherType value that identifies the encapsulated
payload (``0x0800`` for IPv4, ``0x86DD`` for IPv6, ``0x6558`` for TEB).

Example — build a GRE packet carrying IPv4 TCP with a Key::

    from packet_generator import PacketBuilder

    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .gre(key=1234)
        .ip(src="192.168.1.1", dst="192.168.1.2")
        .tcp(dst_port=80)
        .build()
    )
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from .checksum import ones_complement_checksum

#: IP protocol number for GRE (RFC 2784).
IPPROTO_GRE: int = 47

#: GRE Protocol Type for IPv4 payload.
GRE_PROTO_IPV4: int = 0x0800

#: GRE Protocol Type for IPv6 payload.
GRE_PROTO_IPV6: int = 0x86DD

#: GRE Protocol Type for Transparent Ethernet Bridging (TEB) — inner Ethernet frame.
GRE_PROTO_TEB: int = 0x6558


@dataclass
class GREHeader:
    """GRE tunnel header (RFC 2784 / RFC 2890).

    Attributes:
        key: RFC 2890 32-bit flow/session identifier.  When not ``None`` the
            K flag is set and the Key field is included in the header.
        seq: RFC 2890 32-bit packet sequence number.  When not ``None`` the S
            flag is set and the Sequence Number field is included.
        checksum: When ``True`` the C flag is set, a 4-byte Checksum + Reserved1
            block is included, and the checksum is computed over the GRE header
            plus the payload (RFC 1071 ones-complement).
        protocol_type: EtherType of the encapsulated payload.  Set automatically
            at build time from the layer that follows the GRE header.
    """

    key:           int | None = None
    seq:           int | None = None
    checksum:      bool = False
    protocol_type: int = 0  # filled at build time


def build_gre_header(hdr: GREHeader, payload: bytes) -> bytes:
    """Build a GRE header from *hdr* and return its bytes (without *payload*).

    The checksum (when enabled) is computed over the full GRE header bytes
    concatenated with *payload*, then written back into bytes 4–5.

    Args:
        hdr: :class:`GREHeader` describing the desired flags and optional fields.
            ``protocol_type`` must already be set to the correct EtherType for
            the encapsulated payload.
        payload: The payload that will follow this header on the wire (used only
            for checksum computation when ``hdr.checksum`` is ``True``).

    Returns:
        The encoded GRE header bytes (4 to 16 bytes depending on flags).
    """
    c_flag = int(hdr.checksum)
    k_flag = int(hdr.key is not None)
    s_flag = int(hdr.seq is not None)

    # Flags word: bits 15=C, 13=K, 12=S, bits 2-0=Ver (must be 0)
    flags_ver = (c_flag << 15) | (k_flag << 13) | (s_flag << 12)
    result = bytearray(struct.pack("!HH", flags_ver, hdr.protocol_type))

    if c_flag:
        result += b'\x00\x00\x00\x00'  # checksum placeholder + reserved1
    if k_flag:
        result += struct.pack("!I", hdr.key)
    if s_flag:
        result += struct.pack("!I", hdr.seq)

    if c_flag:
        cksum = ones_complement_checksum(bytes(result) + payload)
        struct.pack_into("!H", result, 4, cksum)

    return bytes(result)
