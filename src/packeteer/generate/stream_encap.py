"""Encapsulation descriptors for stream generators.

Each dataclass describes one encapsulation type that can be layered on top of a
generated TCP / UDP / SCTP stream.  Pass the chosen descriptor as the *encap*
keyword argument of :func:`~packeteer.generate.tcp_stream.generate_tcp_stream`,
:func:`~packeteer.generate.udp_stream.generate_udp_stream`, or
:func:`~packeteer.generate.sctp_stream.generate_sctp_stream`.

Supported encapsulations
------------------------

=============  ============================================================
Type           Description
=============  ============================================================
VLANEncap      Single IEEE 802.1Q VLAN tag between Ethernet and IP.
QinQEncap      Double 802.1Q tags (QinQ / 802.1ad).
MPLSEncap      One or more MPLS label stack entries (RFC 3032).
PPPoEEncap     PPPoE session frame (RFC 2516); requires Ethernet.
GREEncap       GRE tunnel; stream IP becomes inner; outer IP is supplied.
EtherIPEncap   EtherIP tunnel (RFC 3378); stream traffic becomes inner.
IPIPEncap      IP-in-IP tunnel (RFC 2003 / RFC 4213).
VXLANEncap     VXLAN tunnel (RFC 7348) over UDP:4789; stream becomes inner.
GeneveEncap    GENEVE tunnel (RFC 8926) over UDP:6081; stream becomes inner.
GTPUEncap      GTP-U tunnel (TS 29.281) over UDP:2152; stream IP becomes inner.
AHEncap        IPsec AH tunnel (RFC 4302); stream IP becomes inner (cleartext).
ESPEncap       IPsec ESP tunnel (RFC 4303); stream IP becomes opaque ciphertext.
=============  ============================================================

There are two categories, and the distinction matters when reading the result:

* **Tag-based** (``VLANEncap``, ``QinQEncap``, ``MPLSEncap``, ``PPPoEEncap``)
  insert layer-2 tags between the Ethernet header and the IP header.  The
  stream's own transport (TCP / UDP / SCTP) is unchanged and remains the
  outer transport on the wire.

* **Tunnel** (``GREEncap``, ``EtherIPEncap``, ``IPIPEncap``, ``VXLANEncap``,
  ``GeneveEncap``, ``GTPUEncap``, ``AHEncap``, ``ESPEncap``) add their own outer
  headers and carry the entire generated stream as *inner* traffic.  This is why
  any stream generator accepts any tunnel: a ``generate_tcp_stream(...,
  encap=VXLANEncap(...))`` call tunnels the TCP conversation *inside* VXLAN — the
  TCP becomes the inner protocol.  ``VXLANEncap``, ``GeneveEncap``, and
  ``GTPUEncap`` always use an outer **UDP** datagram (port 4789 / 6081 / 2152)
  regardless of the inner stream protocol.  ``AHEncap`` (integrity-only) keeps
  the inner stream visible, while ``ESPEncap`` carries it as opaque
  ("encrypted") bytes that do not decode on parse.

Example::

    from packeteer.generate.stream_encap import VLANEncap, GREEncap
    from packeteer.generate.tcp_stream import generate_tcp_stream

    # Single VLAN-tagged stream
    stream = generate_tcp_stream(
        client_ip="10.0.0.1", server_ip="10.0.0.2",
        encap=VLANEncap(vid=100),
    )

    # GRE-tunnelled stream — stream IPs become inner; outer IPs wrap them
    stream = generate_tcp_stream(
        client_ip="10.0.0.1", server_ip="10.0.0.2",
        encap=GREEncap(src_ip="203.0.113.1", dst_ip="203.0.113.2"),
    )
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Union

from .builder import PacketBuilder
from .geneve import GENEVE_PORT, GeneveOption
from .gtpu import GTPU_PORT, GTPUExtensionHeader
from .ipsec import AH_ICV_LEN_SHA1_96
from .vxlan import VXLAN_PORT

# ── Encap descriptor dataclasses ──────────────────────────────────────────────

@dataclass
class VLANEncap:
    """Single IEEE 802.1Q VLAN tag.

    Attributes:
        vid: VLAN ID (1–4094).
        pcp: Priority Code Point (0–7).  Defaults to ``0``.
        dei: Drop Eligible Indicator (0 or 1).  Defaults to ``0``.

    """

    vid: int
    pcp: int = 0
    dei: int = 0


@dataclass
class QinQEncap:
    """Double IEEE 802.1Q VLAN tags (QinQ / 802.1ad).

    Attributes:
        outer_vid: Outer (service provider) VLAN ID.
        inner_vid: Inner (customer) VLAN ID.
        outer_pcp: Outer tag Priority Code Point.  Defaults to ``0``.
        outer_dei: Outer tag Drop Eligible Indicator.  Defaults to ``0``.
        inner_pcp: Inner tag Priority Code Point.  Defaults to ``0``.
        inner_dei: Inner tag Drop Eligible Indicator.  Defaults to ``0``.

    """

    outer_vid: int
    inner_vid: int
    outer_pcp: int = 0
    outer_dei: int = 0
    inner_pcp: int = 0
    inner_dei: int = 0


@dataclass
class MPLSEncap:
    """MPLS label stack (RFC 3032).

    Attributes:
        labels: List of 20-bit MPLS label values, outermost first.
        tc: Traffic Class for all labels (0–7).  Defaults to ``0``.
        ttl: TTL for all labels (0–255).  Defaults to ``64``.

    """

    labels: list[int] = field(default_factory=list)
    tc: int = 0
    ttl: int = 64


@dataclass
class PPPoEEncap:
    """PPPoE session frame (RFC 2516).

    Requires Ethernet framing (``include_ethernet=True``, the default).

    Attributes:
        session_id: 16-bit PPPoE session identifier.  Defaults to ``1``.

    """

    session_id: int = 1


@dataclass
class GREEncap:
    """GRE tunnel (RFC 2784 / RFC 2890).

    The stream's client/server IPs become the inner IP addresses; the
    outer IP header uses *src_ip* / *dst_ip* to identify the tunnel endpoints.

    Attributes:
        src_ip: Outer IP source address (tunnel ingress).
        dst_ip: Outer IP destination address (tunnel egress).
        key: Optional RFC 2890 32-bit GRE Key.  ``None`` (default) omits
            the Key field.
        ttl: Outer IP TTL.  Defaults to ``64``.

    """

    src_ip: str
    dst_ip: str
    key: int | None = None
    ttl: int = 64


@dataclass
class EtherIPEncap:
    """EtherIP tunnel (RFC 3378).

    The generated stream traffic is wrapped inside an inner Ethernet frame
    which is then carried inside the EtherIP datagram.  The outer IP header
    uses *src_ip* / *dst_ip*.

    Attributes:
        src_ip: Outer IP source address (tunnel ingress).
        dst_ip: Outer IP destination address (tunnel egress).
        ttl: Outer IP TTL.  Defaults to ``64``.

    """

    src_ip: str
    dst_ip: str
    ttl: int = 64


@dataclass
class IPIPEncap:
    """IP-in-IP tunnel (RFC 2003 / RFC 4213).

    The stream's inner IP is wrapped inside an outer IP header whose
    addresses are *src_ip* / *dst_ip*.

    Attributes:
        src_ip: Outer IP source address (tunnel ingress).
        dst_ip: Outer IP destination address (tunnel egress).
        ttl: Outer IP TTL.  Defaults to ``64``.

    """

    src_ip: str
    dst_ip: str
    ttl: int = 64


@dataclass
class VXLANEncap:
    """VXLAN tunnel (RFC 7348) over UDP.

    The generated stream traffic is wrapped inside an inner Ethernet frame
    which is carried inside a VXLAN datagram on outer UDP destination port
    4789.  The outer IP header uses *src_ip* / *dst_ip*.

    Attributes:
        vni: 24-bit VXLAN Network Identifier.
        src_ip: Outer IP source address (tunnel ingress / source VTEP).
        dst_ip: Outer IP destination address (tunnel egress / destination VTEP).
        ttl: Outer IP TTL.  Defaults to ``64``.
        udp_src_port: Outer UDP source port.  In real deployments this carries
            per-flow entropy; here it defaults to a fixed, reproducible value
            (:data:`~packeteer.generate.vxlan.VXLAN_PORT`).

    """

    vni:          int
    src_ip:       str
    dst_ip:       str
    ttl:          int = 64
    udp_src_port: int = VXLAN_PORT


@dataclass
class GeneveEncap:
    """GENEVE tunnel (RFC 8926) over UDP.

    The generated stream traffic is wrapped inside an inner Ethernet frame
    carried inside a GENEVE datagram on outer UDP destination port 6081.  The
    outer IP header uses *src_ip* / *dst_ip*.

    Attributes:
        vni: 24-bit Virtual Network Identifier.
        src_ip: Outer IP source address (tunnel ingress).
        dst_ip: Outer IP destination address (tunnel egress).
        ttl: Outer IP TTL.  Defaults to ``64``.
        udp_src_port: Outer UDP source port.  Defaults to a fixed, reproducible
            value (:data:`~packeteer.generate.geneve.GENEVE_PORT`).
        options: GENEVE TLV options to include on every packet.  Defaults to
            none.

    """

    vni:          int
    src_ip:       str
    dst_ip:       str
    ttl:          int = 64
    udp_src_port: int = GENEVE_PORT
    options:      list[GeneveOption] = field(default_factory=list)


@dataclass
class GTPUEncap:
    """GTP-U tunnel (3GPP TS 29.281) over UDP.

    The generated stream's IP packets become the inner IP carried by the GTP-U
    G-PDU message; the outer IP header uses *src_ip* / *dst_ip* and the outer
    UDP destination port is 2152.  Unlike the Ethernet-wrapping tunnels
    (EtherIP / VXLAN / GENEVE), GTP-U carries IP directly, so there is no inner
    Ethernet frame.

    Attributes:
        teid: 32-bit Tunnel Endpoint Identifier.
        src_ip: Outer IP source address (tunnel ingress).
        dst_ip: Outer IP destination address (tunnel egress).
        ttl: Outer IP TTL.  Defaults to ``64``.
        udp_src_port: Outer UDP source port.  Defaults to
            :data:`~packeteer.generate.gtpu.GTPU_PORT`.
        sequence: Optional GTP-U sequence number applied to every packet.
        n_pdu: Optional GTP-U N-PDU number applied to every packet.
        extension_headers: GTP-U extension headers applied to every packet.
            Defaults to none.

    """

    teid:              int
    src_ip:            str
    dst_ip:            str
    ttl:               int = 64
    udp_src_port:      int = GTPU_PORT
    sequence:          int | None = None
    n_pdu:             int | None = None
    extension_headers: list[GTPUExtensionHeader] = field(default_factory=list)


@dataclass
class AHEncap:
    """IPsec Authentication Header tunnel (RFC 4302).

    The generated stream's IP packets become the inner content protected by AH
    in tunnel mode (outer IP / AH / inner IP / transport).  AH provides integrity
    only, so the inner traffic stays in cleartext and decodes normally on parse.

    Attributes:
        spi: 32-bit Security Parameters Index.
        src_ip: Outer IP source address (tunnel ingress).
        dst_ip: Outer IP destination address (tunnel egress).
        sequence: AH sequence number applied to every packet.  Defaults to ``0``.
        ttl: Outer IP TTL.  Defaults to ``64``.
        icv_len: ICV length in bytes (random auth data, since packeteer computes
            no real ICV).  Defaults to ``12`` (HMAC-SHA1-96).

    """

    spi:      int
    src_ip:   str
    dst_ip:   str
    sequence: int = 0
    ttl:      int = 64
    icv_len:  int = AH_ICV_LEN_SHA1_96


@dataclass
class ESPEncap:
    """IPsec ESP tunnel (RFC 4303).

    The generated stream's IP packets become the ESP payload (outer IP / ESP /
    inner bytes).  ESP encrypts its payload and packeteer has no cryptography, so
    the inner content is carried as opaque bytes that do **not** decode on parse
    — matching a real ESP capture taken without the key.

    Attributes:
        spi: 32-bit Security Parameters Index.
        src_ip: Outer IP source address (tunnel ingress).
        dst_ip: Outer IP destination address (tunnel egress).
        sequence: ESP sequence number applied to every packet.  Defaults to ``0``.
        ttl: Outer IP TTL.  Defaults to ``64``.
        icv_len: Extra opaque trailer bytes (an ICV stand-in) appended after the
            payload.  Defaults to ``0``.

    """

    spi:      int
    src_ip:   str
    dst_ip:   str
    sequence: int = 0
    ttl:      int = 64
    icv_len:  int = 0


#: One encapsulation layer.
StreamEncap = Union[VLANEncap, QinQEncap, MPLSEncap, PPPoEEncap,
                    GREEncap, EtherIPEncap, IPIPEncap, VXLANEncap, GeneveEncap,
                    GTPUEncap, AHEncap, ESPEncap]

#: One or more encapsulation layers to stack (outermost first).
#: Using a list allows combining tag-based and tunnel encapsulations,
#: e.g. ``[MPLSEncap(labels=[100]), IPIPEncap("203.0.113.1", "203.0.113.2")]``
#: produces:  eth → MPLS → outer-IP → inner-IP → transport.
EncapSpec = Union[StreamEncap, "list[StreamEncap]", None]


def _as_list(encap: EncapSpec) -> list[StreamEncap]:
    """Normalise *encap* to a list (possibly empty)."""
    if encap is None:
        return []
    if isinstance(encap, list):
        return encap
    return [encap]


# ── PacketBuilder integration ─────────────────────────────────────────────────

def _apply_single(
    b: PacketBuilder,
    encap: StreamEncap,
    src_mac: str,
    dst_mac: str,
) -> PacketBuilder:
    """Apply one encapsulation layer to *b* (returns *b* unchanged if unhandled)."""
    if isinstance(encap, VLANEncap):
        b = b.vlan(vid=encap.vid, pcp=encap.pcp, dei=encap.dei)
    elif isinstance(encap, QinQEncap):
        b = (b
            .vlan(vid=encap.outer_vid, pcp=encap.outer_pcp, dei=encap.outer_dei)
            .vlan(vid=encap.inner_vid, pcp=encap.inner_pcp, dei=encap.inner_dei)
        )
    elif isinstance(encap, MPLSEncap):
        for label in encap.labels:
            b = b.mpls(label=label, tc=encap.tc, ttl=encap.ttl)
    elif isinstance(encap, PPPoEEncap):
        b = b.pppoe(session_id=encap.session_id)
    elif isinstance(encap, GREEncap):
        b = b.ip(src=encap.src_ip, dst=encap.dst_ip, ttl=encap.ttl)
        b = b.gre(key=encap.key) if encap.key is not None else b.gre()
    elif isinstance(encap, EtherIPEncap):
        b = (b
            .ip(src=encap.src_ip, dst=encap.dst_ip, ttl=encap.ttl)
            .etherip()
            .ethernet(src_mac=src_mac, dst_mac=dst_mac)
        )
    elif isinstance(encap, IPIPEncap):
        b = b.ip(src=encap.src_ip, dst=encap.dst_ip, ttl=encap.ttl)
    elif isinstance(encap, VXLANEncap):
        b = (b
            .ip(src=encap.src_ip, dst=encap.dst_ip, ttl=encap.ttl)
            .udp(src_port=encap.udp_src_port, dst_port=VXLAN_PORT)
            .vxlan(vni=encap.vni)
            .ethernet(src_mac=src_mac, dst_mac=dst_mac)
        )
    elif isinstance(encap, GeneveEncap):
        b = (b
            .ip(src=encap.src_ip, dst=encap.dst_ip, ttl=encap.ttl)
            .udp(src_port=encap.udp_src_port, dst_port=GENEVE_PORT)
            .geneve(vni=encap.vni, options=encap.options)
            .ethernet(src_mac=src_mac, dst_mac=dst_mac)
        )
    elif isinstance(encap, GTPUEncap):
        # GTP-U carries IP directly — no inner Ethernet frame.
        b = (b
            .ip(src=encap.src_ip, dst=encap.dst_ip, ttl=encap.ttl)
            .udp(src_port=encap.udp_src_port, dst_port=GTPU_PORT)
            .gtpu(
                teid=encap.teid, sequence=encap.sequence, n_pdu=encap.n_pdu,
                extension_headers=encap.extension_headers,
            )
        )
    elif isinstance(encap, AHEncap):
        # IPsec AH tunnel mode — inner IP stays visible (integrity only).
        b = (b
            .ip(src=encap.src_ip, dst=encap.dst_ip, ttl=encap.ttl)
            .ah(spi=encap.spi, sequence=encap.sequence, icv_len=encap.icv_len)
        )
    elif isinstance(encap, ESPEncap):
        # IPsec ESP tunnel mode — inner IP becomes the opaque payload.
        b = (b
            .ip(src=encap.src_ip, dst=encap.dst_ip, ttl=encap.ttl)
            .esp(spi=encap.spi, sequence=encap.sequence, icv_len=encap.icv_len)
        )
    return b


def _apply_encap(
    b: PacketBuilder,
    encap: EncapSpec,
    src_mac: str,
    dst_mac: str,
) -> PacketBuilder:
    """Insert encapsulation layers into *b* after the outer Ethernet header.

    Accepts a single encapsulation descriptor, a list of descriptors (applied
    left-to-right, outermost first), or ``None``.  Layers are appended to *b*
    in order before the inner IP layer that the caller adds next.

    Typical stacking examples:

    * ``[VLANEncap(100), GREEncap("203.0.113.1", "203.0.113.2")]`` →
      eth + vlan(100) + outer-IP + GRE + inner-IP + transport
    * ``[MPLSEncap([100, 200]), IPIPEncap("203.0.113.1", "203.0.113.2")]`` →
      eth + MPLS(100) + MPLS(200) + outer-IP + inner-IP + transport

    For **tag-based** encapsulations (VLAN, QinQ, MPLS, PPPoE) layers are
    inserted between the Ethernet header and the next layer.

    For **tunnel** encapsulations (GRE, EtherIP, IPIP, VXLAN, GENEVE, GTP-U,
    IPsec AH/ESP) an outer IP header plus tunnel header is inserted.
    :class:`EtherIPEncap`, :class:`VXLANEncap`, and :class:`GeneveEncap` also
    insert an inner Ethernet header (using *src_mac* / *dst_mac*) before the
    inner IP; :class:`VXLANEncap`, :class:`GeneveEncap`, and :class:`GTPUEncap`
    additionally insert an outer UDP header (port 4789 / 6081 / 2152).
    :class:`GTPUEncap`, :class:`AHEncap`, and :class:`ESPEncap` carry the inner
    IP directly (no inner Ethernet).

    The caller is responsible for adding the inner IP and transport layers
    after this function returns.

    Args:
        b: A :class:`~packeteer.generate.builder.PacketBuilder` with the outer
            Ethernet header already appended (when ``include_ethernet=True``).
        encap: One descriptor, a list of descriptors, or ``None``.
        src_mac: Source MAC address (used for the EtherIP inner Ethernet).
        dst_mac: Destination MAC address (used for the EtherIP inner Ethernet).

    Returns:
        The (possibly extended) :class:`~packeteer.generate.builder.PacketBuilder`.

    """
    for layer in _as_list(encap):
        b = _apply_single(b, layer, src_mac, dst_mac)
    return b


def _encap_ip_start(encap: EncapSpec, include_ethernet: bool) -> int:
    """Return the byte offset of the IP header to use for fragmentation.

    Walks through the encap list accumulating the byte sizes of tag-based
    layers (VLAN, QinQ, MPLS, PPPoE).  Stops at the first tunnel layer
    (GRE, EtherIP, IPIP, VXLAN, GENEVE, GTP-U, AH, ESP) because the **outer** IP
    header at that position is the correct fragmentation point — fragmenting the
    outer datagram keeps the tunnel headers intact.

    Examples:
    * No encap, with Ethernet → 14
    * ``VLANEncap(100)`` with Ethernet → 18  (14 + 4)
    * ``[VLANEncap(100), GREEncap(...)]`` with Ethernet → 18  (outer IP at 18)
    * ``[MPLSEncap([100,200]), IPIPEncap(...)]`` with Ethernet → 22  (14 + 8)
    * ``PPPoEEncap(1)`` with Ethernet → 22  (14 + 6 + 2)

    Args:
        encap: One descriptor, a list of descriptors, or ``None``.
        include_ethernet: Whether the packet starts with a 14-byte Ethernet header.

    Returns:
        Byte offset (integer ≥ 0).

    """
    offset = 14 if include_ethernet else 0
    for layer in _as_list(encap):
        if isinstance(layer, VLANEncap):
            offset += 4
        elif isinstance(layer, QinQEncap):
            offset += 8
        elif isinstance(layer, MPLSEncap):
            offset += 4 * len(layer.labels)
        elif isinstance(layer, PPPoEEncap):
            offset += 8   # PPPoE header (6) + PPP protocol field (2)
        else:
            # Tunnel type: outer IP is now at *offset*; stop accumulating.
            break
    return offset


def _fix_encap_prefix(
    prefix: bytes,
    encap: EncapSpec,
    ip_frag_len: int,
) -> bytes:
    """Return *prefix* with any encap length fields updated for *ip_frag_len*.

    Currently only PPPoE requires this: the 2-byte payload length field in the
    PPPoE session header must equal ``2 (PPP) + len(IP_fragment)``.

    The PPPoE header is always the last L2 encap before the IP header (i.e. it
    immediately precedes the fragmented IP), so its start offset is always
    ``len(prefix) - 8`` regardless of what L2 tags precede it.

    Args:
        prefix: Raw bytes preceding the IP header.
        encap: The encapsulation descriptor(s) used to build this packet.
        ip_frag_len: Length in bytes of the IP fragment that follows *prefix*.

    Returns:
        *prefix* unchanged unless a :class:`PPPoEEncap` is present, in which
        case a copy with an updated PPPoE payload length field is returned.

    """
    has_pppoe = any(isinstance(layer, PPPoEEncap) for layer in _as_list(encap))
    if not has_pppoe:
        return prefix
    # PPPoE session header (6 bytes) starts at (len(prefix) - 8):
    #   byte 0: 0x11 (ver=1, type=1)
    #   byte 1: 0x00 (session code)
    #   byte 2-3: session_id
    #   byte 4-5: payload_length  ← update to 2 + ip_frag_len
    # followed by 2-byte PPP protocol field, then the IP fragment.
    pppoe_start = len(prefix) - 8
    pppoe_payload_len = 2 + ip_frag_len
    return (
        prefix[:pppoe_start + 4]
        + struct.pack("!H", pppoe_payload_len)
        + prefix[pppoe_start + 6:]
    )
