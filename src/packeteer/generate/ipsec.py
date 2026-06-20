"""IPsec headers — Authentication Header (RFC 4302) and ESP (RFC 4303).

packeteer performs **no cryptography**, which shapes how the two IPsec protocols
are modelled:

* **AH** provides integrity only — it does *not* encrypt.  Its Next Header field
  points at the (cleartext) protected content, so AH packets are built and
  parsed in full, inner layers and all.  The Integrity Check Value (ICV) is
  opaque authentication data; here it is random bytes of a configurable length.

* **ESP** encrypts everything after the 8-byte SPI + Sequence-Number prefix.
  Without the Security Association key, the IV, ciphertext, padding,
  pad-length, next-header, and ICV are all indistinguishable, so ESP is modelled
  as SPI + Sequence Number followed by an **opaque payload** — exactly what a
  capture without the key looks like.

AH header (RFC 4302 §2)::

     0                   1                   2                   3
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Next Header   |  Payload Len  |          Reserved             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |               Security Parameters Index (SPI)                 |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Sequence Number                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ~          Integrity Check Value (ICV, variable)               ~
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

``Payload Len`` is the length of the whole AH in 32-bit words, minus 2, so the
ICV length is recoverable on parse.

ESP header (RFC 4303 §2), parseable prefix only::

    SPI (4) | Sequence Number (4)
        | [ encrypted: IV + ciphertext + pad + pad-len + next-header + ICV ]

Example — AH transport mode protecting TCP::

    from packeteer.generate import PacketBuilder

    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .ah(spi=0x1000, sequence=1)
        .tcp(dst_port=80)
        .build()
    )

Example — ESP with an opaque (encrypted) payload::

    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .esp(spi=0x2000, sequence=1, size=64)
        .build()
    )
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass

#: IP protocol number for the Authentication Header (RFC 4302).
IPPROTO_AH: int = 51

#: IP protocol number for the Encapsulating Security Payload (RFC 4303).
IPPROTO_ESP: int = 50

#: ICV length for HMAC-SHA1-96 (the classic default), in bytes.
AH_ICV_LEN_SHA1_96: int = 12

#: ICV length for HMAC-SHA256-128, in bytes.
AH_ICV_LEN_SHA256_128: int = 16

_AH_FIXED = struct.Struct(">BBHII")   # next_header, payload_len, reserved, spi, sequence
_ESP_FIXED = struct.Struct(">II")     # spi, sequence


@dataclass
class AHHeader:
    """IPsec Authentication Header (RFC 4302).

    Attributes:
        spi: 32-bit Security Parameters Index.
        sequence: 32-bit anti-replay sequence number.
        icv: Integrity Check Value bytes.  When empty, *icv_len* random bytes are
            generated at build time.  Padded so the whole AH is a multiple of 4
            bytes.
        next_header: IP protocol number of the protected content.  Set
            automatically at build time from the layer that follows.
        icv_len: ICV length used when *icv* is empty.  Defaults to
            :data:`AH_ICV_LEN_SHA1_96` (12).

    """

    spi:         int
    sequence:    int = 0
    icv:         bytes = b""
    next_header: int = 0       # filled at build time
    icv_len:     int = AH_ICV_LEN_SHA1_96


@dataclass
class ESPHeader:
    """IPsec Encapsulating Security Payload header (RFC 4303).

    Only the cleartext SPI + Sequence-Number prefix is modelled; everything else
    is opaque (encrypted) data.

    Attributes:
        spi: 32-bit Security Parameters Index.
        sequence: 32-bit sequence number.
        payload: Opaque "encrypted" payload bytes.  When the builder appends
            inner layers after ``.esp()`` those assembled bytes are used instead.
        icv_len: Extra opaque trailer bytes (a stand-in for the ICV) appended
            after the payload at build time.  Defaults to ``0``.

    """

    spi:      int
    sequence: int = 0
    payload:  bytes = b""
    icv_len:  int = 0


def _build_ah_header(hdr: AHHeader, next_header: int) -> bytes:
    """Build an Authentication Header carrying IP protocol *next_header*.

    The ICV is *hdr.icv* (or ``os.urandom(hdr.icv_len)`` when empty), zero-padded
    so the whole AH is a multiple of 4 bytes.  ``Payload Len`` is set to the AH
    length in 32-bit words minus 2.
    """
    icv = hdr.icv if hdr.icv else os.urandom(hdr.icv_len)
    total = _AH_FIXED.size + len(icv)
    pad = (-total) % 4
    icv = icv + b"\x00" * pad
    total += pad
    payload_len = total // 4 - 2
    return _AH_FIXED.pack(
        next_header & 0xFF, payload_len & 0xFF, 0,
        hdr.spi & 0xFFFFFFFF, hdr.sequence & 0xFFFFFFFF,
    ) + icv


def _build_esp_header(hdr: ESPHeader) -> bytes:
    """Build the ESP SPI + Sequence prefix followed by the opaque payload.

    The opaque tail is *hdr.payload* plus ``os.urandom(hdr.icv_len)`` (a stand-in
    for the trailing ICV).
    """
    tail = hdr.payload + (os.urandom(hdr.icv_len) if hdr.icv_len else b"")
    return _ESP_FIXED.pack(hdr.spi & 0xFFFFFFFF, hdr.sequence & 0xFFFFFFFF) + tail
