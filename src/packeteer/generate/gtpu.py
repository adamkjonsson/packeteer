"""GTP-U tunnel header (GPRS Tunnelling Protocol, user plane; 3GPP TS 29.281).

GTP-U (GTPv1-U) carries user-plane traffic across mobile (4G/5G) networks over
an outer UDP datagram on destination port 2152.  For the user-data message,
**G-PDU** (message type 255), the payload (T-PDU) is an inner **IP** packet —
so, unlike VXLAN/GENEVE which wrap an inner Ethernet frame, GTP-U is an
IP-in-tunnel like GRE/IP-in-IP.

Mandatory 8-byte header::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Ver|P|*|E|S|N| Message Type  |             Length            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                  Tunnel Endpoint Identifier (TEID)            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

* Octet 1: Version (3 bits, =1), Protocol Type (1 bit, =1 for GTP), a spare bit
  (0), then the **E** (extension header), **S** (sequence number), and **PN**
  (N-PDU number) flags.
* Message Type: ``255`` = G-PDU (user data).  Others are control messages
  (Echo Request/Response, Error Indication, End Marker).
* Length: the number of octets *following* the mandatory 8-byte header — i.e.
  the optional block + extension headers + payload.  Computed at build time.
* TEID: the 32-bit Tunnel Endpoint Identifier.

When **any** of E/S/PN is set, a 4-byte optional block follows the TEID::

    Sequence Number (16 bits) | N-PDU Number (8 bits) | Next Ext Hdr Type (8 bits)

When **E** is set, a chain of extension headers follows the optional block.
Each extension header is::

    Length (1 octet, in 4-octet units) | Content | Next Ext Hdr Type (1 octet)

The Length counts the whole extension header (including the Length and
Next-Type octets), so each is a multiple of 4 octets and the content length
satisfies ``(2 + len(content)) % 4 == 0``.  The chain ends with a Next
Extension Header Type of 0.

Example — build a GTP-U G-PDU carrying an inner IPv4/TCP packet::

    from packeteer.generate import PacketBuilder

    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .udp()              # destination port defaults to 2152 before .gtpu()
        .gtpu(teid=0x1234)
        .ip(src="192.168.1.1", dst="192.168.1.2")
        .tcp(dst_port=80)
        .build()
    )
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

#: IANA / 3GPP UDP destination port for GTP-U.
GTPU_PORT: int = 2152

#: GTP-U message type: G-PDU (carries a user-plane T-PDU / inner IP packet).
GTPU_MSG_G_PDU: int = 255

#: GTP-U message type: Echo Request.
GTPU_MSG_ECHO_REQUEST: int = 1

#: GTP-U message type: Echo Response.
GTPU_MSG_ECHO_RESPONSE: int = 2

#: GTP-U message type: Error Indication.
GTPU_MSG_ERROR_INDICATION: int = 26

#: GTP-U message type: End Marker.
GTPU_MSG_END_MARKER: int = 254

_BASE = struct.Struct(">BBHI")   # flags, message_type, length, TEID
_OPTIONAL = struct.Struct(">HBB")  # sequence, n_pdu, next_ext_type


@dataclass
class GTPUExtensionHeader:
    """One GTP-U extension header (3GPP TS 29.281 §5.2).

    Attributes:
        header_type: The 8-bit type identifying *this* extension header (for
            example ``0x85`` for the 5G PDU Session Container).  The chaining
            "next extension header type" pointers are derived from the order of
            the headers at build time.
        content: The extension header content — the bytes between the Length
            octet and the trailing Next-Extension-Header-Type octet.  Its length
            must satisfy ``(2 + len(content)) % 4 == 0`` so the whole extension
            header is a multiple of 4 octets.

    """

    header_type: int
    content:     bytes = b""


@dataclass
class GTPUHeader:
    """GTP-U tunnel header (GTPv1-U, 3GPP TS 29.281).

    Attributes:
        teid: 32-bit Tunnel Endpoint Identifier.
        message_type: GTP-U message type.  Defaults to
            :data:`GTPU_MSG_G_PDU` (255), which carries an inner IP packet.
        sequence: Optional 16-bit sequence number.  When not ``None`` the S flag
            is set and the field is included.
        n_pdu: Optional 8-bit N-PDU number.  When not ``None`` the PN flag is set
            and the field is included.
        extension_headers: List of :class:`GTPUExtensionHeader`.  When non-empty
            the E flag is set and the chain is appended.
        version: Protocol version.  Defaults to ``1`` (GTPv1).

    """

    teid:              int = 0
    message_type:      int = GTPU_MSG_G_PDU
    sequence:          int | None = None
    n_pdu:             int | None = None
    extension_headers: list[GTPUExtensionHeader] = field(default_factory=list)
    version:           int = 1


def _build_extension_headers(headers: list[GTPUExtensionHeader]) -> bytes:
    """Encode the extension-header chain (without the leading next-type pointer).

    Each header's trailing Next-Extension-Header-Type octet points at the
    following header's :attr:`~GTPUExtensionHeader.header_type`, or ``0`` for the
    last header.

    Raises:
        ValueError: If a header's content length does not make the whole
            extension header a multiple of 4 octets, or it is too long for the
            8-bit Length field.

    """
    out = bytearray()
    for i, eh in enumerate(headers):
        total = 2 + len(eh.content)
        if total % 4 != 0:
            raise ValueError(
                "GTP-U extension header content must satisfy (2 + len) % 4 == 0, "
                f"got content length {len(eh.content)}"
            )
        units = total // 4
        if units > 0xFF:
            raise ValueError(f"GTP-U extension header too long: {total} octets")
        next_type = headers[i + 1].header_type if i + 1 < len(headers) else 0
        out += struct.pack(">B", units) + eh.content + struct.pack(">B", next_type)
    return bytes(out)


def _build_gtpu_header(hdr: GTPUHeader, payload: bytes) -> bytes:
    """Build a GTP-U header and return its bytes (without *payload*).

    The Length field, the E/S/PN flags, and the extension-header chaining
    pointers are all derived from *hdr* and ``len(payload)``.

    Args:
        hdr: :class:`GTPUHeader` describing the message.
        payload: The bytes that will follow this header on the wire (the T-PDU
            for a G-PDU); used only to compute the Length field.

    Returns:
        The encoded GTP-U header bytes (8, 12, or more, depending on flags).

    """
    e_flag = bool(hdr.extension_headers)
    s_flag = hdr.sequence is not None
    pn_flag = hdr.n_pdu is not None
    has_optional = e_flag or s_flag or pn_flag

    ext_bytes = _build_extension_headers(hdr.extension_headers) if e_flag else b""

    optional = b""
    if has_optional:
        first_ext_type = hdr.extension_headers[0].header_type if e_flag else 0
        optional = _OPTIONAL.pack(
            (hdr.sequence or 0) & 0xFFFF, (hdr.n_pdu or 0) & 0xFF, first_ext_type,
        )

    flags = (
        ((hdr.version & 0x7) << 5) | (1 << 4)  # version + PT (GTP)
        | (0x04 if e_flag else 0)
        | (0x02 if s_flag else 0)
        | (0x01 if pn_flag else 0)
    )
    length = len(optional) + len(ext_bytes) + len(payload)
    base = _BASE.pack(flags, hdr.message_type & 0xFF, length & 0xFFFF, hdr.teid & 0xFFFFFFFF)
    return base + optional + ext_bytes
