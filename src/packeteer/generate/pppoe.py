"""PPPoE (Point-to-Point Protocol over Ethernet) header construction.

Implements RFC 2516.  PPPoE operates in two phases:

* **Discovery** (EtherType ``0x8863``) — client and server exchange
  PADI/PADO/PADR/PADS/PADT messages carrying TLV tags to negotiate a session.
* **Session** (EtherType ``0x8864``) — once a session is established, IP
  packets are encapsulated in PPPoE frames followed by a 2-byte PPP protocol
  field.

The 6-byte PPPoE header layout (RFC 2516 §6)::

    Ver/Type (1) | Code (1) | Session ID (2) | Length (2)

Ver and Type are always ``1``; they are packed into a single byte as
``0x11``.  Length covers the payload only — the 6-byte PPPoE header is
excluded.

Constants:
    ETHERTYPE_PPPOE_DISCOVERY (int): EtherType ``0x8863``.
    ETHERTYPE_PPPOE_SESSION (int): EtherType ``0x8864``.
    PPP_IPV4 (int): PPP protocol number ``0x0021`` — IPv4.
    PPP_IPV6 (int): PPP protocol number ``0x0057`` — IPv6.
    PPPOE_CODE_SESSION (int): Code ``0x00`` — session data.
    PPPOE_CODE_PADI (int): Code ``0x09`` — Active Discovery Initiation.
    PPPOE_CODE_PADO (int): Code ``0x07`` — Active Discovery Offer.
    PPPOE_CODE_PADR (int): Code ``0x19`` — Active Discovery Request.
    PPPOE_CODE_PADS (int): Code ``0x65`` — Active Discovery Session-confirmation.
    PPPOE_CODE_PADT (int): Code ``0xa7`` — Active Discovery Terminate.
    PPPOE_TAG_SERVICE_NAME (int): Tag type ``0x0101``.
    PPPOE_TAG_AC_NAME (int): Tag type ``0x0102``.
    PPPOE_TAG_HOST_UNIQ (int): Tag type ``0x0103``.
    PPPOE_TAG_AC_COOKIE (int): Tag type ``0x0104``.
    PPPOE_TAG_GENERIC_ERROR (int): Tag type ``0x0203``.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

# ── EtherTypes ────────────────────────────────────────────────────────────────

ETHERTYPE_PPPOE_DISCOVERY: int = 0x8863
ETHERTYPE_PPPOE_SESSION:   int = 0x8864

# ── PPP protocol numbers ──────────────────────────────────────────────────────

PPP_IPV4: int = 0x0021
PPP_IPV6: int = 0x0057

# ── Discovery message codes ───────────────────────────────────────────────────

PPPOE_CODE_SESSION: int = 0x00   # session data (not a discovery message)
PPPOE_CODE_PADI:    int = 0x09   # Active Discovery Initiation
PPPOE_CODE_PADO:    int = 0x07   # Active Discovery Offer
PPPOE_CODE_PADR:    int = 0x19   # Active Discovery Request
PPPOE_CODE_PADS:    int = 0x65   # Active Discovery Session-confirmation
PPPOE_CODE_PADT:    int = 0xa7   # Active Discovery Terminate

# ── Tag types (RFC 2516 §5) ───────────────────────────────────────────────────

PPPOE_TAG_SERVICE_NAME:  int = 0x0101
PPPOE_TAG_AC_NAME:       int = 0x0102
PPPOE_TAG_HOST_UNIQ:     int = 0x0103
PPPOE_TAG_AC_COOKIE:     int = 0x0104
PPPOE_TAG_GENERIC_ERROR: int = 0x0203


@dataclass
class PPPoETag:
    """One PPPoE TLV tag (RFC 2516 §5).

    Tags appear in the payload of PPPoE discovery frames.  Each tag is a
    type–length–value (TLV) triple: a 2-byte type, a 2-byte length, and
    *length* bytes of value data.

    Attributes:
        type: 16-bit tag type identifier (see ``PPPOE_TAG_*`` constants).
        data: Tag value bytes.  May be empty (e.g. Service-Name in PADI).

    """

    type: int
    data: bytes = b""


@dataclass
class PPPoEHeader:
    """PPPoE frame header (RFC 2516 §6).

    The Ver and Type nibbles are always ``1`` and are not stored as separate
    fields.  The Length field is computed automatically at build time.

    For **session** frames (``code=0x00``) the builder inserts a 2-byte PPP
    protocol field (``0x0021`` for IPv4, ``0x0057`` for IPv6) immediately
    after the 6-byte PPPoE header.

    For **discovery** frames (``code != 0x00``) the ``tags`` list is encoded
    as the payload; no IP or transport layer is required.

    Attributes:
        code: PPPoE message code.  Use ``PPPOE_CODE_SESSION`` (``0x00``) for
            session data, or one of the ``PPPOE_CODE_PAD*`` constants for
            discovery messages.
        session_id: 16-bit session identifier.  ``0`` for PADI/PADR; assigned
            by the AC in PADS.
        tags: TLV tags carried in discovery frames.  Ignored for session frames.

    """

    code: int = PPPOE_CODE_SESSION
    session_id: int = 0
    tags: list[PPPoETag] = field(default_factory=list)


def build_pppoe_header(hdr: PPPoEHeader, payload: bytes) -> bytes:
    r"""Build a 6-byte PPPoE header with the correct Length field.

    The returned bytes contain only the PPPoE header (6 bytes).  The caller
    is responsible for prepending the PPP protocol field (for session frames)
    and concatenating the full payload.

    The Length field is set to ``len(payload)`` which must already include
    any PPP protocol bytes or encoded tags.

    Layout::

        Ver/Type (1) | Code (1) | Session ID (2) | Length (2)

    Args:
        hdr: PPPoE header fields.
        payload: The assembled payload that will follow the PPPoE header in
            the frame.  Used solely to compute the Length field.

    Returns:
        6 bytes in network (big-endian) byte order.

    Example::

        >>> from packet_generator.pppoe import PPPoEHeader, build_pppoe_header
        >>> raw = build_pppoe_header(PPPoEHeader(session_id=0x1234), b"\\x00" * 22)
        >>> len(raw)
        6
        >>> raw[0]  # Ver=1, Type=1 packed as 0x11
        17

    """
    ver_type = 0x11  # Ver=1, Type=1
    return struct.pack("!BBHH", ver_type, hdr.code, hdr.session_id, len(payload))
