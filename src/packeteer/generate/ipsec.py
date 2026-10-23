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

import hashlib
import random
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
        icv: Integrity Check Value bytes.  When empty, *icv_len* bytes standing
            in for one are derived at build time from the header and what AH
            protects, so the same packet always gets the same ICV.  Padded so
            the whole AH is a multiple of 4 bytes.
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
        opaque_random: When ``True``, the payload is replaced at build time with
            high-entropy bytes that are a stable function of its content (see
            :func:`_scramble`).  Real ESP ciphertext is indistinguishable from
            random, so this makes a *generated* ESP packet look encrypted —
            scrambling the whole inner stack, not just the application data.
            Off by default so hand-authored / parsed payloads stay byte-exact.

    """

    spi:           int
    sequence:      int = 0
    payload:       bytes = b""
    icv_len:       int = 0
    opaque_random: bool = False


def _build_ah_header(hdr: AHHeader, next_header: int, protected: bytes = b"") -> bytes:
    """Build an Authentication Header carrying IP protocol *next_header*.

    The ICV is *hdr.icv*, or when that is empty a stand-in of ``hdr.icv_len``
    bytes derived from the header and *protected*, the bytes AH covers (see
    :func:`_icv_stand_in`).  It is zero-padded so the whole AH is a multiple of
    4 bytes.  ``Payload Len`` is set to the AH length in 32-bit words minus 2.
    """
    length = len(hdr.icv) if hdr.icv else hdr.icv_len
    total = _AH_FIXED.size + length
    pad = (-total) % 4
    total += pad
    payload_len = total // 4 - 2
    fixed = _AH_FIXED.pack(
        next_header & 0xFF, payload_len & 0xFF, 0,
        hdr.spi & 0xFFFFFFFF, hdr.sequence & 0xFFFFFFFF,
    )
    icv = hdr.icv if hdr.icv else _icv_stand_in(fixed + protected, length)
    return fixed + icv + b"\x00" * pad


def _scramble(data: bytes) -> bytes:
    """Return ``len(data)`` high-entropy bytes derived deterministically from *data*.

    A stand-in for ESP encryption: packeteer has no cryptography, but real ESP
    ciphertext is indistinguishable from random, so we emit pseudo-random bytes
    keyed by a stable hash of the plaintext.  Being a pure function of the input
    keeps ``--seed`` stream reproducibility and ``parse`` → ``build`` round-trips
    intact, while scrambling the *whole* inner stack (inner IP / transport /
    payload) so no structured headers leak into the "encrypted" region.
    """
    if not data:
        return data
    seed = int.from_bytes(hashlib.blake2b(data, digest_size=8).digest(), "big")
    return random.Random(seed).randbytes(len(data))


def _icv_stand_in(covered: bytes, length: int) -> bytes:
    """Return *length* bytes standing in for an ICV over *covered*.

    packeteer computes no real ICV, since it holds no keys, so this is
    high-entropy bytes derived deterministically from what a real ICV would
    authenticate, as :func:`_scramble` derives ESP's ciphertext.  A pure
    function of the packet, so a seeded stream and a ``parse`` → ``build``
    round trip are byte-identical, and two packets with different content
    still get different ICVs (#201).  Keyed apart from :func:`_scramble`, so
    an ICV is never a prefix of the scrambled bytes beside it.
    """
    if not length:
        return b""
    digest = hashlib.blake2b(covered, digest_size=8, person=b"packeteer-icv")
    return random.Random(int.from_bytes(digest.digest(), "big")).randbytes(length)


def _build_esp_header(hdr: ESPHeader) -> bytes:
    """Build the ESP SPI + Sequence prefix followed by the opaque payload.

    When *hdr.opaque_random* is set the payload is scrambled (see
    :func:`_scramble`) so a generated packet looks encrypted.  The opaque tail is
    that payload plus ``hdr.icv_len`` bytes standing in for the ICV, derived
    from the SPI, sequence and payload that a real ICV covers (see
    :func:`_icv_stand_in`).
    """
    payload = _scramble(hdr.payload) if hdr.opaque_random else hdr.payload
    fixed = _ESP_FIXED.pack(hdr.spi & 0xFFFFFFFF, hdr.sequence & 0xFFFFFFFF)
    return fixed + payload + _icv_stand_in(fixed + payload, hdr.icv_len)
