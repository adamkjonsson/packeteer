"""High-level packet builder API.

This module exposes :class:`PacketBuilder` — the primary entry point for
constructing and fragmenting complete raw network packets using a fluent,
layer-by-layer API.

Typical usage::

    from packet_generator import PacketBuilder

    # IPv4 TCP packet with Ethernet header and 64 bytes of random payload
    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="192.168.1.10", dst="8.8.8.8")
        .tcp(dst_port=443)
        .payload(size=64)
        .build()
    )

    # IPv6 UDP packet without Ethernet framing
    pkt = (PacketBuilder()
        .ip(src="fe80::1", dst="fe80::2")
        .udp(dst_port=5353)
        .payload(size=20)
        .build()
    )

    # ICMPv6 ping with explicit payload
    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="::1", dst="::2")
        .icmpv6()
        .payload(data=b"hello ipv6")
        .build()
    )

    # QinQ (double-tagged) IPv4 UDP packet
    pkt = (PacketBuilder()
        .ethernet()
        .vlan(vid=100)   # outer VLAN
        .vlan(vid=200)   # inner VLAN
        .ip(src="10.0.0.1", dst="10.0.0.2")
        .udp()
        .build()
    )

    # IPv4-in-IPv4 tunnel
    pkt = (PacketBuilder()
        .ethernet()
        .ip(src="203.0.113.1", dst="203.0.113.2")   # outer (tunnel) IP
        .ip(src="10.0.0.1", dst="10.0.0.2")         # inner IP
        .tcp(dst_port=80)
        .build()
    )
"""
from __future__ import annotations

import os
import socket
import struct

from .ethernet import (
    EthernetHeader, VLANTag, ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_8021Q,
    ETHERNET_MIN_FRAME_SIZE, build_ethernet_header,
)
from .ip import IPHeader, build_ip_header
from .ipv6 import IPv6Header, build_ipv6_header
from .tcp import TCPHeader, TCPOptions, TCP_ACK, build_tcp_header
from .udp import UDPHeader, build_udp_header
from .icmp import ICMPHeader, build_icmp_header
from .icmpv6 import ICMPv6Header, build_icmpv6_header

# ── protocol-number helpers ───────────────────────────────────────────────────

_ETHERTYPE_MAP: dict[type, int] = {
    IPHeader:   ETHERTYPE_IPV4,
    IPv6Header: ETHERTYPE_IPV6,
    VLANTag:    ETHERTYPE_8021Q,
}

_IP_PROTO_MAP: dict[type, int] = {
    TCPHeader:    6,
    UDPHeader:    17,
    ICMPHeader:   1,
    ICMPv6Header: 58,
    IPHeader:     4,   # IP-in-IP (RFC 2003)
    IPv6Header:   41,  # IPv6-in-IPv4 (RFC 4213)
}


def _ethertype_for(layer: object) -> int:
    """Return the EtherType value that an enclosing Ethernet/VLAN layer should
    use when *layer* is its direct payload."""
    return _ETHERTYPE_MAP.get(type(layer), 0)


def _ip_proto_for(layer: object) -> int:
    """Return the IP protocol number that an enclosing IP layer should use when
    *layer* is its direct payload."""
    return _IP_PROTO_MAP.get(type(layer), 0)


def _detect_ip_version(addr: str) -> int:
    """Return ``4`` or ``6`` depending on whether *addr* is IPv4 or IPv6.

    Args:
        addr: An IP address string in any format accepted by the socket
            module (dotted-decimal for IPv4, colon-hex for IPv6).

    Returns:
        ``6`` if *addr* is a valid IPv6 address, otherwise ``4``.

    Raises:
        OSError: If *addr* is neither a valid IPv4 nor a valid IPv6 address.
    """
    try:
        socket.inet_pton(socket.AF_INET6, addr)
        return 6
    except OSError:
        socket.inet_aton(addr)  # raises OSError if invalid IPv4
        return 4


# ── PacketBuilder ─────────────────────────────────────────────────────────────

class PacketBuilder:
    """Assembles complete raw network packets layer by layer.

    Call the fluent layer methods in any order and any number of times, then
    call :meth:`build` or :meth:`fragment` to produce the final bytes.

    Layers are stacked in the order the methods are called — the first call
    becomes the outermost (leftmost) layer.  The IP version (4 or 6) is
    detected automatically from the address string passed to :meth:`ip`.
    All checksums are computed correctly per their respective RFCs.

    Each method appends a layer to an internal ordered list, so the same
    method may be called multiple times to produce advanced encapsulations:

    * Calling :meth:`vlan` twice creates a QinQ (802.1ad) double-tagged frame.
    * Calling :meth:`ip` twice creates an IP-in-IP tunnel packet.

    The layer list stores the same public dataclasses exported by
    ``packet_generator`` (``EthernetHeader``, ``VLANTag``, ``IPHeader``,
    ``IPv6Header``, ``TCPHeader``, ``UDPHeader``, ``ICMPHeader``,
    ``ICMPv6Header``).  Protocol-number fields that depend on the next layer
    (``ethertype``, ``protocol``, ``next_header``) are set to ``0`` when the
    object is stored and filled in correctly at :meth:`build` / :meth:`fragment`
    time.

    Example::

        from packet_generator import PacketBuilder

        pkt = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .tcp(dst_port=443)
            .payload(size=40)
            .build()
        )
        print(f"Built {len(pkt)}-byte packet")
    """

    def __init__(self) -> None:
        self._layers: list = []
        self._payload_size: int = 0
        self._payload_data: bytes | None = None
        self._cached_payload: bytes | None = None

    # ── layer configuration methods ──────────────────────────────────────────

    def ethernet(
        self,
        *,
        src_mac: str = "00:00:00:00:00:01",
        dst_mac: str = "00:00:00:00:00:02",
        pad: bool = False,
    ) -> "PacketBuilder":
        """Append an Ethernet II header layer.

        Omitting this call produces a raw IP packet with no layer-2 framing.

        Args:
            src_mac: Source MAC address (colon- or hyphen-separated hex).
            dst_mac: Destination MAC address.
            pad: When ``True``, zero-pad the assembled frame to the IEEE 802.3
                minimum of 60 bytes when the frame would otherwise be shorter.
        """
        # ethertype=0 is a placeholder; the correct value is filled in at
        # build time based on whatever layer follows this one.
        self._layers.append(EthernetHeader(dst_mac, src_mac, ethertype=0, pad=pad))
        return self

    def vlan(self, *, vid: int, pcp: int = 0, dei: int = 0) -> "PacketBuilder":
        """Append an IEEE 802.1Q VLAN tag layer.

        Inserts a 4-byte VLAN tag between the enclosing Ethernet header and
        the next layer.  Call twice for QinQ (double-tagged) frames.

        Args:
            vid: VLAN ID (1–4094).
            pcp: Priority Code Point (0–7).
            dei: Drop Eligible Indicator (0 or 1).
        """
        self._layers.append(VLANTag(vid, pcp, dei))
        return self

    def ip(
        self,
        *,
        src: str,
        dst: str,
        ttl: int = 64,
        # IPv4-specific
        tos: int = 0,
        identification: int = 0,
        flags: int = 0b010,
        fragment_offset: int = 0,
        # IPv6-specific
        traffic_class: int = 0,
        flow_label: int = 0,
    ) -> "PacketBuilder":
        """Append an IP header layer.  IPv4 or IPv6 is auto-detected from *src*.

        IPv4-specific parameters (``tos``, ``identification``, ``flags``,
        ``fragment_offset``) are ignored when *src* is an IPv6 address, and
        vice versa for IPv6-specific parameters.

        Call twice to create an IP-in-IP tunnel packet.

        Args:
            src: Source IP address (dotted-decimal IPv4 or colon-hex IPv6).
            dst: Destination IP address in the same format.
            ttl: Time-To-Live (IPv4) or Hop Limit (IPv6).  Defaults to ``64``.
            tos: IPv4 Type of Service / DSCP+ECN byte.
            identification: IPv4 Identification field.
            flags: IPv4 3-bit Flags field (bit 1 = DF).  Defaults to ``0b010``.
            fragment_offset: IPv4 Fragment Offset in 8-byte units.
            traffic_class: IPv6 Traffic Class (DSCP + ECN).
            flow_label: IPv6 Flow Label (20-bit value).

        Raises:
            OSError: If *src* is not a valid IPv4 or IPv6 address.
        """
        # protocol / next_header = 0 is a placeholder filled in at build time.
        if _detect_ip_version(src) == 6:
            self._layers.append(IPv6Header(
                src, dst, next_header=0,
                hop_limit=ttl,
                traffic_class=traffic_class,
                flow_label=flow_label,
            ))
        else:
            self._layers.append(IPHeader(
                src, dst, protocol=0,
                ttl=ttl, tos=tos,
                identification=identification,
                flags=flags,
                fragment_offset=fragment_offset,
            ))
        return self

    def tcp(
        self,
        *,
        src_port: int = 12345,
        dst_port: int = 80,
        seq: int = 0,
        ack: int = 0,
        flags: int = TCP_ACK,
        window: int = 65535,
        urgent_ptr: int = 0,
        reserved: int = 0,
        options: TCPOptions | None = None,
    ) -> "PacketBuilder":
        """Append a TCP transport header layer."""
        self._layers.append(TCPHeader(
            src_port, dst_port,
            seq=seq, ack=ack, flags=flags,
            window=window, urgent_ptr=urgent_ptr,
            reserved=reserved, options=options,
        ))
        return self

    def udp(self, *, src_port: int = 12345, dst_port: int = 80) -> "PacketBuilder":
        """Append a UDP transport header layer."""
        self._layers.append(UDPHeader(src_port, dst_port))
        return self

    def icmp(
        self,
        *,
        type: int = 8,
        code: int = 0,
        identifier: int = 1,
        sequence: int = 1,
    ) -> "PacketBuilder":
        """Append an ICMPv4 transport header layer.  Requires an IPv4 layer above it."""
        self._layers.append(ICMPHeader(
            type=type, code=code, identifier=identifier, sequence=sequence,
        ))
        return self

    def icmpv6(
        self,
        *,
        type: int = 128,
        code: int = 0,
        identifier: int = 1,
        sequence: int = 1,
    ) -> "PacketBuilder":
        """Append an ICMPv6 transport header layer.  Requires an IPv6 layer above it."""
        self._layers.append(ICMPv6Header(
            type=type, code=code, identifier=identifier, sequence=sequence,
        ))
        return self

    def payload(self, *, size: int = 0, data: bytes | None = None) -> "PacketBuilder":
        """Set the packet payload.

        Args:
            size: Generate this many random bytes as the payload.  Ignored
                when *data* is provided.
            data: Explicit payload bytes.  Takes precedence over *size*.
        """
        self._payload_size = size
        self._payload_data = data
        self._cached_payload = None   # invalidate cache if called again
        return self

    # ── internal helpers ─────────────────────────────────────────────────────

    @property
    def _payload_bytes(self) -> bytes:
        """Lazily generate (and cache) the payload bytes."""
        if self._cached_payload is None:
            self._cached_payload = (
                self._payload_data
                if self._payload_data is not None
                else os.urandom(self._payload_size)
            )
        return self._cached_payload

    def _find_ip_before(self, i: int) -> IPHeader | IPv6Header:
        """Return the nearest IP layer to the left of index *i*.

        Raises:
            ValueError: If no IP layer exists at any index less than *i*.
        """
        for layer in reversed(self._layers[:i]):
            if isinstance(layer, (IPHeader, IPv6Header)):
                return layer
        raise ValueError(
            "No IP layer found to the left of a transport layer; "
            "call .ip() before .tcp(), .udp(), .icmp(), or .icmpv6()"
        )

    def _assemble_range(self, start: int, end: int, data: bytes) -> bytes:
        """Assemble layers[start:end] right-to-left over *data*.

        The 'next layer' for protocol-number lookups is always taken from the
        full self._layers list (using i+1), so layers at the boundary of a
        sub-range correctly see the layer just outside the range.
        """
        for i in range(end - 1, start - 1, -1):
            layer = self._layers[i]
            next_layer = self._layers[i + 1] if i + 1 < len(self._layers) else None

            if isinstance(layer, TCPHeader):
                ip = self._find_ip_before(i)
                ip_version = 6 if isinstance(ip, IPv6Header) else 4
                data = build_tcp_header(layer, data, ip.src, ip.dst, ip_version) + data

            elif isinstance(layer, UDPHeader):
                ip = self._find_ip_before(i)
                ip_version = 6 if isinstance(ip, IPv6Header) else 4
                data = build_udp_header(layer, data, ip.src, ip.dst, ip_version) + data

            elif isinstance(layer, ICMPHeader):
                data = build_icmp_header(layer, data) + data

            elif isinstance(layer, ICMPv6Header):
                ip = self._find_ip_before(i)
                data = build_icmpv6_header(layer, data, ip.src, ip.dst) + data

            elif isinstance(layer, IPHeader):
                proto = _ip_proto_for(next_layer) if next_layer else 0
                hdr = IPHeader(
                    layer.src, layer.dst, proto,
                    ttl=layer.ttl, tos=layer.tos,
                    identification=layer.identification,
                    flags=layer.flags,
                    fragment_offset=layer.fragment_offset,
                )
                data = build_ip_header(hdr, data) + data

            elif isinstance(layer, IPv6Header):
                proto = _ip_proto_for(next_layer) if next_layer else 0
                hdr = IPv6Header(
                    layer.src, layer.dst, proto,
                    hop_limit=layer.hop_limit,
                    traffic_class=layer.traffic_class,
                    flow_label=layer.flow_label,
                )
                data = build_ipv6_header(hdr, data) + data

            elif isinstance(layer, VLANTag):
                ethertype = _ethertype_for(next_layer) if next_layer else 0
                tci = (layer.pcp << 13) | (layer.dei << 12) | layer.vid
                data = struct.pack("!HH", tci, ethertype) + data

            elif isinstance(layer, EthernetHeader):
                ethertype = _ethertype_for(next_layer) if next_layer else 0
                eth = EthernetHeader(layer.dst_mac, layer.src_mac, ethertype)
                data = build_ethernet_header(eth) + data

        return data

    def _apply_eth_padding(self, data: bytes) -> bytes:
        """Pad *data* to the Ethernet minimum frame size if the outermost layer
        is an :class:`EthernetHeader` with ``pad=True``."""
        if (self._layers
                and isinstance(self._layers[0], EthernetHeader)
                and self._layers[0].pad
                and len(data) < ETHERNET_MIN_FRAME_SIZE):
            data += b'\x00' * (ETHERNET_MIN_FRAME_SIZE - len(data))
        return data

    def _validate(self) -> None:
        has_ip = any(isinstance(l, (IPHeader, IPv6Header)) for l in self._layers)
        has_transport = any(
            isinstance(l, (TCPHeader, UDPHeader, ICMPHeader, ICMPv6Header))
            for l in self._layers
        )
        if not has_ip:
            raise ValueError("No IP layer configured; call .ip() before .build()/.fragment()")
        if not has_transport:
            raise ValueError(
                "No transport layer configured; "
                "call .tcp(), .udp(), .icmp(), or .icmpv6() before .build()/.fragment()"
            )

    # ── assembly ─────────────────────────────────────────────────────────────

    def build(self) -> bytes:
        """Assemble and return the complete packet bytes.

        Layers are assembled from innermost (payload) to outermost, with all
        checksums computed automatically.

        Returns:
            A :class:`bytes` object containing the fully assembled packet.

        Raises:
            ValueError: If no IP layer or no transport layer has been added.
            OSError: If an IP address string is invalid.

        Example::

            >>> pkt = PacketBuilder().ip(src="1.2.3.4", dst="5.6.7.8").udp().build()
            >>> len(pkt)  # 20 (ip) + 8 (udp)
            28
        """
        self._validate()
        data = self._assemble_range(0, len(self._layers), self._payload_bytes)
        return self._apply_eth_padding(data)

    def fragment(self, mtu: int = 1500) -> list[bytes]:
        """Fragment the packet to fit within *mtu* bytes per IP datagram.

        The first IP layer in the stack is used as the fragmentation point.
        Everything to its left (Ethernet, VLAN, outer IP) becomes a prefix
        prepended to every fragment; everything to its right (inner IP if any,
        transport, payload) becomes the transport data that is fragmented.

        IPv4 uses native Flags / Fragment Offset fragmentation (RFC 791).
        IPv6 inserts a Fragment Extension Header (next header = 44) per
        RFC 8200 §4.5.

        Args:
            mtu: Maximum IP packet size in bytes, *excluding* any prefix
                headers (e.g. Ethernet).  Defaults to ``1500``.

        Returns:
            A list of fully assembled packet bytes, one entry per fragment.
            When the payload fits in a single datagram the list has one element.

        Raises:
            ValueError: If no IP layer or no transport layer has been added,
                or if *mtu* is too small to hold even one 8-byte fragment.
            OSError: If an IP address string is invalid.

        Example::

            fragments = (PacketBuilder()
                .ip(src="10.0.0.1", dst="10.0.0.2")
                .udp()
                .payload(size=4000)
                .fragment(mtu=1500)
            )
            print(f"{len(fragments)} fragments")
        """
        from .fragmentation import fragment_ipv4, fragment_ipv6

        self._validate()

        # Find the first (outermost) IP layer.
        k = next(
            i for i, l in enumerate(self._layers)
            if isinstance(l, (IPHeader, IPv6Header))
        )
        ip_layer = self._layers[k]

        # Build everything to the right of the IP layer (transport + payload,
        # including any inner IP layers in an IP-in-IP stack).
        transport_data = self._assemble_range(k + 1, len(self._layers), self._payload_bytes)

        # Fragment the IP layer.
        next_layer = self._layers[k + 1] if k + 1 < len(self._layers) else None
        proto = _ip_proto_for(next_layer) if next_layer else 0

        if isinstance(ip_layer, IPv6Header):
            ip_hdr = IPv6Header(
                ip_layer.src, ip_layer.dst, proto,
                hop_limit=ip_layer.hop_limit,
                traffic_class=ip_layer.traffic_class,
                flow_label=ip_layer.flow_label,
            )
            frags = fragment_ipv6(ip_hdr, transport_data, mtu, eth_header=None)
        else:
            ip_hdr = IPHeader(
                ip_layer.src, ip_layer.dst, proto,
                ttl=ip_layer.ttl, tos=ip_layer.tos,
                identification=ip_layer.identification,
                flags=ip_layer.flags,
                fragment_offset=ip_layer.fragment_offset,
            )
            frags = fragment_ipv4(ip_hdr, transport_data, mtu, eth_header=None)

        # Build the prefix (everything to the left of the IP layer).
        # _assemble_range uses self._layers[k] as the 'next_layer' context for
        # layers at index k-1, so ethertype/proto values are set correctly.
        prefix = self._assemble_range(0, k, b"")

        result = [prefix + frag for frag in frags]
        return [self._apply_eth_padding(f) for f in result]
