"""IPv6 header construction (RFC 8200).

This module builds the fixed 40-byte IPv6 header and the Hop-by-Hop Options
extension header (next_header=0, RFC 8200 §4.3).  Unlike IPv4, the IPv6
header contains **no checksum** — integrity is delegated entirely to the
transport layer (TCP, UDP) or ICMPv6.

Fixed header layout (40 bytes)::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version| Traffic Class |           Flow Label                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Payload Length        |  Next Header  |   Hop Limit   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                         Source Address                        +
   |                        (128 bits)                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                      Destination Address                      +
   |                        (128 bits)                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Hop-by-Hop Options extension header layout (variable, multiple of 8 bytes)::

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - - - - - - - -+
    |  Next Header  |  Hdr Ext Len  |          Options …           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - - - - - - - -+

    Total length = (Hdr Ext Len + 1) × 8.  Options are TLV-encoded.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

# ── Hop-by-Hop extension header constants ─────────────────────────────────────

HBH_NEXT_HEADER: int = 0
"""next_header value that signals a Hop-by-Hop Options extension header."""

HBH_OPT_ROUTER_ALERT: int = 0x05
"""Option type for the Router Alert option (RFC 2711)."""

HBH_OPT_JUMBO_PAYLOAD: int = 0xC2
"""Option type for the Jumbo Payload option (RFC 2675)."""

# ── Hop-by-Hop option dataclasses ─────────────────────────────────────────────


@dataclass
class RouterAlertOption:
    """Router Alert Hop-by-Hop option (RFC 2711).

    Signals to all routers on the path that the packet contents require special
    handling.  The 2-byte *value* identifies the type of content:

    Attributes:
        value: Alert value.  ``0`` = MLD datagram, ``1`` = RSVP message,
            ``2`` = Active Networks, and so on (IANA registry).

    """

    value: int = 0


@dataclass
class JumboPayloadOption:
    """Jumbo Payload Hop-by-Hop option (RFC 2675).

    Allows IPv6 packets larger than 65 535 bytes (jumbograms).

    Attributes:
        jumbo_length: Actual payload length in bytes.  Must exceed 65 535.

    """

    jumbo_length: int


@dataclass
class RawOption:
    """An unrecognised or custom Hop-by-Hop option encoded as raw bytes.

    Attributes:
        option_type: The 1-byte option type value.
        data: Option value bytes (the portion after the type and length bytes).

    """

    option_type: int
    data: bytes


HBHOption = RouterAlertOption | JumboPayloadOption | RawOption


@dataclass
class HopByHopOptions:
    """Container for zero or more Hop-by-Hop Options (RFC 8200 §4.3).

    Padding (Pad1 / PadN) is computed automatically by
    :func:`_build_hop_by_hop_header` and is not stored here.

    Attributes:
        options: List of options to encode, in order.

    """

    options: list[HBHOption] = field(default_factory=list)


# ── IPv6 fixed header ─────────────────────────────────────────────────────────


@dataclass
class IPv6Header:
    """Fields of a fixed IPv6 header.

    Attributes:
        src: Source IPv6 address in any notation accepted by
            :func:`socket.inet_pton`, e.g. ``"fe80::1"`` or ``"::1"``.
        dst: Destination IPv6 address in the same format as *src*.
        next_header: Protocol number of the header immediately following
            this one.  Common values: ``6`` (TCP), ``17`` (UDP),
            ``58`` (ICMPv6), ``0`` (Hop-by-Hop Options).
        hop_limit: Maximum number of hops (routers) the packet may traverse.
            Equivalent to the IPv4 TTL field.  Defaults to ``64``.
        traffic_class: 8-bit DSCP + ECN field, analogous to the IPv4 TOS
            byte.  Defaults to ``0``.
        flow_label: 20-bit flow label for QoS handling by routers.
            Defaults to ``0``.
        hop_by_hop: Hop-by-Hop Options extension header immediately following
            the fixed header, or ``None`` when absent.  When set, the wire
            value of *next_header* is ``0`` (HBH); this field stores the
            parsed or requested options, and *next_header* reflects the actual
            transport protocol (e.g. ``6`` for TCP).  Defaults to ``None``.

    """

    src: str
    dst: str
    next_header: int
    hop_limit: int = 64
    traffic_class: int = 0
    flow_label: int = 0
    hop_by_hop: HopByHopOptions | None = None


def _build_ipv6_header(hdr: IPv6Header, payload: bytes) -> bytes:
    r"""Build a 40-byte IPv6 fixed header.

    The *payload_length* field is set to ``len(payload)`` and reflects only
    the bytes **after** this 40-byte header (transport header + data).
    No checksum is computed — IPv6 headers do not carry one.

    Args:
        hdr: An :class:`IPv6Header` instance with the desired field values.
        payload: The data that will follow this header (transport header +
            application payload).  Used only to compute *payload_length*;
            its contents are not included in the returned bytes.

    Returns:
        Exactly 40 bytes representing the IPv6 header in network byte order.

    Raises:
        OSError: If *hdr.src* or *hdr.dst* is not a valid IPv6 address
            (raised by :func:`socket.inet_pton`).

    """
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


def _build_hop_by_hop_header(hbh: HopByHopOptions, next_proto: int) -> bytes:
    r"""Build a variable-length Hop-by-Hop Options extension header.

    Encodes each option in *hbh.options* as a TLV, then pads the result to
    the next 8-byte boundary with a PadN option (or a single Pad1 byte when
    only 1 byte of padding is needed).

    Wire layout::

        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - - - - - - - -+
        |  Next Header  |  Hdr Ext Len  |          Options …           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - - - - - - - -+

        Total = (Hdr Ext Len + 1) × 8 bytes (minimum 8).

    Args:
        hbh: :class:`HopByHopOptions` containing the options to encode.
        next_proto: Protocol number of the header that follows this one
            (placed in the *Next Header* field, e.g. ``6`` for TCP).

    Returns:
        Bytes for the complete Hop-by-Hop extension header.

    """
    # Encode all options into a flat byte string.
    body = bytearray()
    for opt in hbh.options:
        if isinstance(opt, RouterAlertOption):
            body += bytes([HBH_OPT_ROUTER_ALERT, 2]) + struct.pack("!H", opt.value)
        elif isinstance(opt, JumboPayloadOption):
            body += bytes([HBH_OPT_JUMBO_PAYLOAD, 4]) + struct.pack("!I", opt.jumbo_length)
        else:  # RawOption
            body += bytes([opt.option_type, len(opt.data)]) + opt.data

    # The first 2 bytes of the header (next_proto + hdr_ext_len) are not
    # counted in hdr_ext_len.  Total must be a multiple of 8; minimum is 8.
    # Options occupy bytes 2 … total-1 → available = total - 2.
    used = 2 + len(body)
    remainder = used % 8
    if remainder != 0:
        pad_needed = 8 - remainder
        if pad_needed == 1:
            body += b"\x00"           # Pad1
        else:
            body += bytes([0x01, pad_needed - 2]) + b"\x00" * (pad_needed - 2)  # PadN

    total = 2 + len(body)
    assert total % 8 == 0  # noqa: S101 — guaranteed by the padding logic above
    hdr_ext_len = total // 8 - 1
    return bytes([next_proto, hdr_ext_len]) + bytes(body)
