"""IPv4 header construction (RFC 791).

This module builds the standard 20-byte IPv4 header (no options) and
automatically computes the RFC 1071 header checksum.  The header is
immediately suitable for use as the network layer of a raw packet.

Header layout (20 bytes)::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |    DSCP/TOS   |         Total Length          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|    Fragment Offset      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |        Header Checksum        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Source Address                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Destination Address                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

from .checksum import ones_complement_checksum


@dataclass
class IPHeader:
    """Fields of an IPv4 header (no options).

    Attributes:
        src: Source IPv4 address in dotted-decimal notation,
            e.g. ``"192.168.1.1"``.
        dst: Destination IPv4 address in dotted-decimal notation.
        protocol: IP protocol number for the encapsulated transport layer.
            Common values: ``6`` (TCP), ``17`` (UDP), ``1`` (ICMP).
            Use ``socket.IPPROTO_TCP`` etc. for readability.
        ttl: Time-To-Live — decremented by each router; packet is discarded
            when it reaches zero.  Defaults to ``64``.
        tos: Type of Service / DSCP byte.  Defaults to ``0``.
        identification: 16-bit packet identifier used for reassembly of
            fragmented datagrams.  Defaults to ``0``.
        flags: 3-bit flags field.  Bit 1 is the *Don't Fragment* (DF) bit.
            Defaults to ``0b010`` (DF set, no fragmentation).
        fragment_offset: 13-bit offset (in 8-byte units) of this fragment
            within the original datagram.  Defaults to ``0``.

    """

    src: str
    dst: str
    protocol: int
    ttl: int = 64
    tos: int = 0
    identification: int = 0
    flags: int = 0b010       # DF bit
    fragment_offset: int = 0


def _build_ip_header(hdr: IPHeader, payload: bytes) -> bytes:
    r"""Build a 20-byte IPv4 header with a correct header checksum.

    The ``total_length`` field is derived automatically from *payload*.
    The header checksum is computed per RFC 1071 and written into the
    returned bytes — no additional processing is required by the caller.

    Args:
        hdr: An :class:`IPHeader` instance containing the desired field
            values.
        payload: The data that will follow this header (transport header +
            application payload).  Used only to compute ``total_length``;
            its contents are not included in the returned bytes.

    Returns:
        Exactly 20 bytes representing the IPv4 header in network byte order,
        with a valid checksum.

    Raises:
        OSError: If *hdr.src* or *hdr.dst* is not a valid IPv4 address
            (raised by :func:`socket.inet_aton`).

    """
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
