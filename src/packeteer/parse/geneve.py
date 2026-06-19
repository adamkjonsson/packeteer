"""Parser for GENEVE tunnel headers (RFC 8926).

Follows the same ``(header_size, next_layer_id, HeaderObject | None)``
convention as all other ``packet_parser`` modules.

``next_layer_id`` is the GENEVE Protocol Type (an EtherType): ``0x6558`` for an
inner Ethernet frame (TEB), ``0x0800`` / ``0x86DD`` for IPv4 / IPv6.  The caller
uses it to choose how to parse the inner payload.
"""
from __future__ import annotations

import struct

from packeteer.generate.geneve import GeneveHeader, GeneveOption

_BASE = struct.Struct(">BBHI")    # ver/optlen, flags, protocol_type, (VNI<<8 | reserved)
_OPT_HDR = struct.Struct(">HBB")  # option_class, type, rsvd/length


def _parse_options(data: bytes) -> list[GeneveOption] | None:
    """Decode *data* (exactly the options region) into a list of options.

    Returns ``None`` if an option claims more bytes than remain.
    """
    options: list[GeneveOption] = []
    offset = 0
    while offset < len(data):
        if offset + 4 > len(data):
            return None
        opt_class, type_byte, length_field = _OPT_HDR.unpack_from(data, offset)
        data_len = (length_field & 0x1F) * 4
        start = offset + 4
        if start + data_len > len(data):
            return None
        options.append(GeneveOption(
            option_class=opt_class,
            type=type_byte & 0x7F,
            critical=bool(type_byte & 0x80),
            data=data[start:start + data_len],
        ))
        offset = start + data_len
    return options


def packet_parser(data: bytes) -> tuple[int, int | None, GeneveHeader | None]:
    """Parse a GENEVE header (RFC 8926): 8-byte base plus variable options.

    Args:
        data: Raw bytes starting at the GENEVE header.

    Returns:
        ``(total_size, protocol_type, GeneveHeader(...))`` on success, where
        *total_size* is ``8 + options_bytes*`` and *protocol_type* is the
        EtherType of the inner payload.  Returns ``(0, None, None)`` when *data*
        is too short or the options are malformed.

    """
    if len(data) < 8:
        return (0, None, None)
    ver_optlen, flags, protocol_type, vni_word = _BASE.unpack_from(data, 0)
    opt_bytes = (ver_optlen & 0x3F) * 4
    total = 8 + opt_bytes
    if len(data) < total:
        return (0, None, None)
    options = _parse_options(data[8:total])
    if options is None:
        return (0, None, None)
    hdr = GeneveHeader(
        vni=vni_word >> 8,
        protocol_type=protocol_type,
        options=options,
        oam=bool(flags & 0x80),
        version=ver_optlen >> 6,
    )
    return (total, protocol_type, hdr)
