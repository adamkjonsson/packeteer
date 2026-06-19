"""GENEVE tunnel header (RFC 8926).

GENEVE (Generic Network Virtualization Encapsulation) carries an inner frame
over an outer UDP datagram, like VXLAN, but adds two things: a **Protocol Type**
field (an EtherType, so the payload may be an inner Ethernet frame *or* IPv4 /
IPv6 directly) and a list of **variable-length TLV options**.  GENEVE is
identified by the outer UDP destination port (IANA-assigned ``6081``).

The base header is 8 bytes, followed by ``Opt Len`` 32-bit words of options::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        Virtual Network Identifier (VNI)       |    Reserved   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Variable-Length Options                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

``Ver`` is 0.  ``Opt Len`` is the total options length in 4-byte units.  ``O``
marks an OAM packet; ``C`` is set automatically when any *critical* option is
present.  ``Protocol Type`` is the EtherType of the payload (``0x6558`` for an
inner Ethernet frame — the common overlay case — or ``0x0800`` / ``0x86DD``).

Each option is itself a TLV::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Option Class         |      Type     |R|R|R| Length  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Variable-Length Option Data              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The high bit of ``Type`` is the per-option critical bit; ``Length`` is the
option *data* length in 4-byte units (not counting the 4-byte option header), so
option data is always a multiple of 4 bytes.

Typical encapsulation::

    Outer Ethernet → Outer IP → Outer UDP (dst 6081) → GENEVE
        → Inner Ethernet → Inner IP → Transport

Example — build a GENEVE packet carrying an inner IPv4/TCP frame::

    from packeteer.generate import PacketBuilder

    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .udp()                 # destination port defaults to 6081 before .geneve()
        .geneve(vni=5000)
        .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
        .ip(src="192.168.1.1", dst="192.168.1.2")
        .tcp(dst_port=80)
        .build()
    )
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

#: IANA-assigned UDP destination port for GENEVE (RFC 8926).
GENEVE_PORT: int = 6081

#: GENEVE Protocol Type for an inner IPv4 payload.
GENEVE_PROTO_IPV4: int = 0x0800

#: GENEVE Protocol Type for an inner IPv6 payload.
GENEVE_PROTO_IPV6: int = 0x86DD

#: GENEVE Protocol Type for Transparent Ethernet Bridging (inner Ethernet frame).
GENEVE_PROTO_TEB: int = 0x6558

_BASE = struct.Struct(">BBHI")   # ver/optlen, flags, protocol_type, (VNI<<8 | reserved)
_OPT_HDR = struct.Struct(">HBB")  # option_class, type, rsvd/length


@dataclass
class GeneveOption:
    """One GENEVE variable-length TLV option (RFC 8926 §3.5).

    Attributes:
        option_class: 16-bit IANA-assigned Option Class (namespace).
        type: 7-bit option type within the class (0–127).  The critical bit is
            carried separately in :attr:`critical`.
        critical: Whether the option's critical bit is set.  When any option on
            a header is critical, the header's C flag is set automatically.
        data: Option data bytes.  Must be a multiple of 4 bytes; the wire
            Length field is ``len(data) // 4``.

    """

    option_class: int
    type:         int
    critical:     bool = False
    data:         bytes = b""


@dataclass
class GeneveHeader:
    """GENEVE tunnel header (RFC 8926).

    Attributes:
        vni: 24-bit Virtual Network Identifier (0–16777215).
        protocol_type: EtherType of the encapsulated payload.  Set automatically
            at build time from the layer that follows the GENEVE header
            (``0x6558`` for an inner Ethernet frame, ``0x0800`` / ``0x86DD`` for
            IPv4 / IPv6).
        options: List of :class:`GeneveOption` TLVs (default: none).
        oam: Whether the O (OAM) flag is set.  Defaults to ``False``.
        version: Protocol version.  Defaults to ``0`` (the only version defined).

    """

    vni:           int = 0
    protocol_type: int = 0  # filled at build time
    options:       list[GeneveOption] = field(default_factory=list)
    oam:           bool = False
    version:       int = 0


def _build_geneve_option(opt: GeneveOption) -> bytes:
    """Encode one :class:`GeneveOption` TLV.

    Args:
        opt: The option to encode.  ``opt.data`` must be a multiple of 4 bytes.

    Returns:
        The 4-byte option header followed by the option data.

    Raises:
        ValueError: If ``opt.data`` is not a multiple of 4 bytes or exceeds the
            5-bit Length field (124 bytes).

    """
    if len(opt.data) % 4 != 0:
        raise ValueError(
            f"GENEVE option data must be a multiple of 4 bytes, got {len(opt.data)}"
        )
    length = len(opt.data) // 4
    if length > 0x1F:
        raise ValueError(
            f"GENEVE option data too long: {len(opt.data)} bytes (max 124)"
        )
    type_byte = (opt.type & 0x7F) | (0x80 if opt.critical else 0)
    return _OPT_HDR.pack(opt.option_class, type_byte, length) + opt.data


def _build_geneve_header(hdr: GeneveHeader) -> bytes:
    """Build a GENEVE header (base + options) and return its bytes.

    The ``Opt Len`` field and the C (critical-options-present) flag are computed
    from *hdr.options*.

    Args:
        hdr: :class:`GeneveHeader` describing the VNI, options, and flags.
            ``protocol_type`` must already be set to the payload's EtherType.

    Returns:
        The encoded GENEVE header bytes (8 bytes plus any options).

    Raises:
        ValueError: If the total options length exceeds the 6-bit Opt Len field
            (252 bytes), or an option is malformed.

    """
    options_bytes = b"".join(_build_geneve_option(o) for o in hdr.options)
    opt_len = len(options_bytes) // 4
    if opt_len > 0x3F:
        raise ValueError(
            f"GENEVE options too long: {len(options_bytes)} bytes (max 252)"
        )
    ver_optlen = ((hdr.version & 0x3) << 6) | (opt_len & 0x3F)
    critical = any(o.critical for o in hdr.options)
    flags = (0x80 if hdr.oam else 0) | (0x40 if critical else 0)
    base = _BASE.pack(ver_optlen, flags, hdr.protocol_type, (hdr.vni & 0xFFFFFF) << 8)
    return base + options_bytes
