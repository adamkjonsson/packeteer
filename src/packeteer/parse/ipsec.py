"""Parsers for IPsec AH (RFC 4302) and ESP (RFC 4303).

Follows the same ``(header_size, next_layer_id, HeaderObject | None)``
convention as all other ``packet_parser`` modules.

* AH is transparent: ``next_layer_id`` is the Next Header field (an IP protocol
  number), and the caller continues parsing the cleartext protected content.
* ESP is opaque: only the SPI + Sequence-Number prefix is decoded, so
  ``next_layer_id`` is ``None`` and the remaining bytes are the (encrypted)
  payload.
"""
from __future__ import annotations

import struct

from packeteer.generate.ipsec import AHHeader, ESPHeader

_AH_FIXED = struct.Struct(">BBHII")   # next_header, payload_len, reserved, spi, sequence
_ESP_FIXED = struct.Struct(">II")     # spi, sequence


def ah_packet_parser(data: bytes) -> tuple[int, int | None, AHHeader | None]:
    """Parse an IPsec Authentication Header (RFC 4302).

    Args:
        data: Raw bytes starting at the AH.

    Returns:
        ``(total_size, next_header, AHHeader(...))`` on success, where
        *total_size* is ``(payload_len + 2) * 4`` and *next_header* is the IP
        protocol number of the protected content.  Returns ``(0, None, None)``
        when *data* is too short.

    """
    if len(data) < _AH_FIXED.size:
        return (0, None, None)
    next_header, payload_len, _reserved, spi, sequence = _AH_FIXED.unpack_from(data, 0)
    total = (payload_len + 2) * 4
    if len(data) < total:
        return (0, None, None)
    icv = data[_AH_FIXED.size:total]
    hdr = AHHeader(spi=spi, sequence=sequence, icv=icv, next_header=next_header)
    return (total, next_header, hdr)


def esp_packet_parser(data: bytes) -> tuple[int, None, ESPHeader | None]:
    """Parse the cleartext prefix of an IPsec ESP header (RFC 4303).

    Only SPI + Sequence Number are decoded; the remaining (encrypted) bytes are
    left for the caller to store as the opaque payload.

    Args:
        data: Raw bytes starting at the ESP header.

    Returns:
        ``(8, None, ESPHeader(...))`` on success, or ``(0, None, None)`` when
        *data* is shorter than 8 bytes.

    """
    if len(data) < _ESP_FIXED.size:
        return (0, None, None)
    spi, sequence = _ESP_FIXED.unpack_from(data, 0)
    return (8, None, ESPHeader(spi=spi, sequence=sequence))
