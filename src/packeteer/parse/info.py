"""High-level reporting on the contents of a pcap or pcapng capture.

This module powers ``packeteer file-info``.  :func:`pcap_info` reads a capture
once and returns a :class:`PcapInfo` summary: packet count, number of
directional sessions (unique ordered 5-tuples), and per-protocol-layer
statistics.

When the link-layer type recorded in the file header would produce garbage
(for instance a raw-IP capture mislabelled as Ethernet), :func:`pcap_info`
re-scores the declared type against the supported alternatives and parses with
whichever yields the cleanest result.  Pass an explicit ``link_type`` or set
``auto_link_type=False`` to disable that heuristic.
"""
from __future__ import annotations

import io
import os
import warnings
from dataclasses import dataclass, field
from struct import error as _StructError
from typing import Any

from packeteer.generate.icmp import ICMPHeader
from packeteer.generate.icmpv6 import ICMPv6Header
from packeteer.generate.ip import IPHeader
from packeteer.generate.ipv6 import IPv6Header
from packeteer.generate.sctp import SCTPHeader
from packeteer.generate.tcp import TCPHeader
from packeteer.generate.udp import UDPHeader
from packeteer.pcap import LINKTYPE_ETHERNET, LINKTYPE_RAW, read_pcap

from .core import ParsedPacket, parse_packet

# Auto link-type detection tuning.  An alternative link type is only adopted
# when it parses meaningfully better than the declared one *and* the declared
# one already looks like garbage — this avoids overriding unusual-but-valid or
# non-IP captures (e.g. ARP-only), which score near zero for every candidate.
_LT_SCORE_MARGIN: float = 0.2
_LT_SCORE_THRESHOLD: float = 0.5

# Ordered layer labels — controls the order rows appear in the text report.
_LAYER_ORDER: tuple[str, ...] = (
    "ethernet", "vlan", "arp", "mpls", "pppoe",
    "ipv4", "ipv6", "ipip", "gre", "etherip", "pseudowire", "vxlan", "geneve", "gtpu",
    "tcp", "udp", "icmp", "icmpv6", "sctp",
    "dns", "dhcp", "http", "payload",
)

# Transport header type → layer label.
_TRANSPORT_LABELS: dict[type, str] = {
    TCPHeader:    "tcp",
    UDPHeader:    "udp",
    ICMPHeader:   "icmp",
    ICMPv6Header: "icmpv6",
    SCTPHeader:   "sctp",
}

# ParsedPacket attributes whose presence (not None) implies a tunnel layer of
# the same label.
_TUNNEL_ATTRS: tuple[str, ...] = (
    "gre", "etherip", "pseudowire", "vxlan", "geneve", "gtpu",
)

_LINKTYPE_NAMES: dict[int, str] = {
    LINKTYPE_ETHERNET: "ethernet",
    LINKTYPE_RAW: "raw",
}


@dataclass
class PcapInfo:
    """Summary statistics describing a pcap or pcapng capture.

    Attributes:
        path: Source file path, or ``None`` when read from a file object.
        file_type: ``"pcap"`` or ``"pcapng"``.
        declared_link_type: Link-layer type recorded in the file header.
        link_type: Link-layer type actually used for parsing.  Differs from
            *declared_link_type* when auto-correction or an explicit override
            took effect.
        link_type_overridden: ``True`` when *link_type* differs from
            *declared_link_type*.
        nanoseconds: ``True`` when timestamps are in nanoseconds.
        packet_count: Number of packet records analysed.  Equal to the total in
            the file unless *packet_limit* capped it.
        session_count: Number of unique directional 5-tuples
            ``(src, dst, src_port, dst_port, protocol)``.  Only packets with an
            IP layer contribute; ``A->B`` and ``B->A`` count separately.
        layer_counts: Mapping of protocol-layer label to the number of packets
            in which that layer was seen, counted at any depth — for tunnelled
            packets the outer layers, the tunnel type (``gre``, ``etherip``,
            ``ipip``, ``pseudowire``, ``vxlan``, ``geneve``, ``gtpu``), and the
            inner frame's layers all contribute.  A layer present at multiple
            depths in one packet counts that packet once.
        capture_duration_s: Wall-clock span between the first and last packet
            timestamp in seconds, or ``None`` for fewer than two packets.
        packet_limit: The cap requested via ``num`` / ``--num``, or ``None`` for
            an unlimited scan.  When set, only the first *packet_limit* packets
            were read and every other field reflects that subset.

    """

    path: str | None
    file_type: str
    declared_link_type: int
    link_type: int
    link_type_overridden: bool
    nanoseconds: bool
    packet_count: int
    session_count: int
    layer_counts: dict[str, int] = field(default_factory=dict)
    capture_duration_s: float | None = None
    packet_limit: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict of every field.

        Returns:
            A plain ``dict`` mirroring the dataclass attributes, suitable for
            ``json.dumps``.

        """
        return {
            "path": self.path,
            "file_type": self.file_type,
            "declared_link_type": self.declared_link_type,
            "link_type": self.link_type,
            "link_type_overridden": self.link_type_overridden,
            "nanoseconds": self.nanoseconds,
            "packet_count": self.packet_count,
            "session_count": self.session_count,
            "layer_counts": dict(self.layer_counts),
            "capture_duration_s": self.capture_duration_s,
            "packet_limit": self.packet_limit,
        }


def _packet_layers(pkt: ParsedPacket) -> list[str]:
    """Return the protocol-layer labels present in *pkt*, recursing into tunnels.

    The full stack is reported: a tunnelled packet contributes its outer layers,
    the tunnel-type label, **and** the inner frame's layers (parsed recursively
    from :attr:`~packeteer.parse.core.ParsedPacket.tunneled`).  The caller
    de-duplicates per packet, so each label counts the *number of packets* in
    which that protocol appears at any depth.
    """
    labels: list[str] = []
    if pkt.ethernet is not None:
        labels.append("ethernet")
        if pkt.ethernet.vlan_tag is not None:
            labels.append("vlan")
    if pkt.arp is not None:
        labels.append("arp")
    if pkt.mpls:
        labels.append("mpls")
    if pkt.pppoe is not None:
        labels.append("pppoe")
    if isinstance(pkt.ip, IPHeader):
        labels.append("ipv4")
    elif isinstance(pkt.ip, IPv6Header):
        labels.append("ipv6")
    if pkt.ipip:
        labels.append("ipip")
    labels.extend(attr for attr in _TUNNEL_ATTRS if getattr(pkt, attr) is not None)
    transport_label = _TRANSPORT_LABELS.get(type(pkt.transport))
    if transport_label is not None:
        labels.append(transport_label)
    for attr in ("dns", "dhcp", "http"):
        if getattr(pkt, attr) is not None:
            labels.append(attr)
    if pkt.payload:
        labels.append("payload")
    if pkt.tunneled is not None:
        labels.extend(_packet_layers(pkt.tunneled))
    return labels


def _session_key(pkt: ParsedPacket) -> tuple[str, str, int | None, int | None, str] | None:
    """Return the directional 5-tuple for *pkt*, or ``None`` without an IP layer."""
    if pkt.ip is None:
        return None
    transport = pkt.transport
    src_port: int | None = None
    dst_port: int | None = None
    if isinstance(transport, (TCPHeader, UDPHeader, SCTPHeader)):
        src_port = transport.src_port
        dst_port = transport.dst_port
        proto = type(transport).__name__.replace("Header", "").lower()
    elif isinstance(transport, ICMPHeader):
        proto = "icmp"
    elif isinstance(transport, ICMPv6Header):
        proto = "icmpv6"
    elif pkt.gre is not None:
        proto = "gre"
    elif pkt.ipip:
        proto = "ipip"
    elif pkt.etherip is not None:
        proto = "etherip"
    elif pkt.pseudowire is not None:
        proto = "pseudowire"
    else:
        proto = "ip"
    return (str(pkt.ip.src), str(pkt.ip.dst), src_port, dst_port, proto)


def _score_link_type(records: list[tuple[bytes, int, int]], link_type: int) -> float:
    """Return the fraction of *records* that parse to a valid IP header."""
    if not records:
        return 0.0
    ok = 0
    for data, _, _ in records:
        try:
            pkt = parse_packet(data, link_type=link_type)
        except (ValueError, IndexError, _StructError):
            continue
        if pkt.ip is not None:
            ok += 1
    return ok / len(records)


def _choose_link_type(
    records: list[tuple[bytes, int, int]], declared: int,
) -> int:
    """Pick the link type that parses *records* cleanest, biased toward *declared*."""
    candidates = {declared, LINKTYPE_ETHERNET, LINKTYPE_RAW}
    scores = {lt: _score_link_type(records, lt) for lt in candidates}
    declared_score = scores[declared]
    alternatives = [lt for lt in candidates if lt != declared]
    if not alternatives:
        return declared
    best_alt = max(alternatives, key=lambda lt: scores[lt])
    if (scores[best_alt] > declared_score + _LT_SCORE_MARGIN
            and declared_score < _LT_SCORE_THRESHOLD):
        return best_alt
    return declared


def _capture_duration(
    records: list[tuple[bytes, int, int]], nanoseconds: bool,
) -> float | None:
    """Return the span between the first and last timestamp in seconds."""
    if len(records) < 2:
        return None
    resolution = 1_000_000_000 if nanoseconds else 1_000_000
    times = [sec + frac / resolution for _, sec, frac in records]
    return max(times) - min(times)


def pcap_info(
    *,
    path: str | os.PathLike | None = None,
    file_object: io.RawIOBase | io.BufferedIOBase | None = None,
    link_type: int | None = None,
    auto_link_type: bool = True,
    num: int | None = None,
) -> PcapInfo:
    """Summarise a pcap or pcapng capture.

    Reads the file once with :func:`packeteer.pcap.read_pcap`, parses every
    packet, and returns a :class:`PcapInfo` with the packet count, the number
    of directional sessions (unique ordered 5-tuples), and per-layer packet
    counts.

    Exactly one of *path* or *file_object* must be supplied.

    Args:
        path: Path to the ``.pcap`` or ``.pcapng`` file.
        file_object: Readable binary file-like object positioned at the start
            of the capture data.
        link_type: Force a specific link-layer type, ignoring the file header
            and disabling auto-correction.  Use :data:`~packeteer.pcap.LINKTYPE_ETHERNET`
            or :data:`~packeteer.pcap.LINKTYPE_RAW`.
        auto_link_type: When ``True`` (default) and *link_type* is not given,
            score the declared link type against the supported alternatives and
            parse with whichever is cleanest.  Set ``False`` to always trust the
            file header.
        num: When given, analyse only the first *num* packets.  Reading stops
            early without loading the rest of the file, so this makes link-type
            detection fast on very large captures.  Every field in the result
            reflects the analysed subset.

    Returns:
        A :class:`PcapInfo` describing the capture.

    Raises:
        ValueError: If neither or both of *path* / *file_object* are given, if
            *num* is negative, or if the capture data is malformed.
        OSError: If *path* cannot be opened for reading.

    """
    pcap = read_pcap(path=path, file_object=file_object, max_packets=num)
    declared = pcap.header.link_type
    records = pcap.packets

    if link_type is not None:
        used_link_type = link_type
    elif auto_link_type:
        used_link_type = _choose_link_type(records, declared)
    else:
        used_link_type = declared

    layer_counts: dict[str, int] = dict.fromkeys(_LAYER_ORDER, 0)
    sessions: set[tuple[str, str, int | None, int | None, str]] = set()

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for data, _, _ in records:
            try:
                pkt = parse_packet(data, link_type=used_link_type)
            except (ValueError, IndexError, _StructError):
                continue
            # De-duplicate per packet: a layer present at multiple depths
            # (e.g. inner and outer IPv4) still counts the packet once.
            for label in dict.fromkeys(_packet_layers(pkt)):
                layer_counts[label] += 1
            key = _session_key(pkt)
            if key is not None:
                sessions.add(key)

    layer_counts = {label: n for label, n in layer_counts.items() if n}

    return PcapInfo(
        path=str(path) if path is not None else None,
        file_type="pcapng" if pcap.header.version_major == 1 else "pcap",
        declared_link_type=declared,
        link_type=used_link_type,
        link_type_overridden=used_link_type != declared,
        nanoseconds=pcap.header.nanoseconds,
        packet_count=len(records),
        session_count=len(sessions),
        layer_counts=layer_counts,
        capture_duration_s=_capture_duration(records, pcap.header.nanoseconds),
        packet_limit=num,
    )


def _link_type_label(link_type: int) -> str:
    """Render a link type as ``name (value)`` or just ``value`` when unknown."""
    name = _LINKTYPE_NAMES.get(link_type)
    return f"{name} ({link_type})" if name is not None else str(link_type)


def format_pcap_info(info: PcapInfo) -> str:
    """Render a :class:`PcapInfo` as a human-readable multi-line report.

    Args:
        info: The summary returned by :func:`pcap_info`.

    Returns:
        A printable report string (no trailing newline).

    """
    lines: list[str] = []
    lines.append(f"File:      {info.path if info.path is not None else '<stream>'}")
    lines.append(f"Type:      {info.file_type}")
    if info.link_type_overridden:
        lines.append(
            f"Link-type: {_link_type_label(info.link_type)}"
            f"  [auto-corrected from {_link_type_label(info.declared_link_type)}]"
        )
    else:
        lines.append(f"Link-type: {_link_type_label(info.link_type)}")
    limited = info.packet_limit is not None and info.packet_count >= info.packet_limit
    pkt_suffix = f"  (limited to first {info.packet_limit})" if limited else ""
    lines.append(f"Packets:   {info.packet_count}{pkt_suffix}")
    lines.append(f"Sessions:  {info.session_count}  (directional 5-tuples)")
    if info.capture_duration_s is not None:
        lines.append(f"Duration:  {info.capture_duration_s:.6f} s")

    lines.append("Layers:")
    total = info.packet_count
    if info.layer_counts and total:
        width = max(len(label) for label in info.layer_counts)
        for label in _LAYER_ORDER:
            count = info.layer_counts.get(label)
            if not count:
                continue
            pct = 100.0 * count / total
            lines.append(f"  {label:<{width}}  {count:>8}  ({pct:5.1f}%)")
    else:
        lines.append("  (none)")

    ip_packets = info.layer_counts.get("ipv4", 0) + info.layer_counts.get("ipv6", 0)
    if info.packet_count and ip_packets == 0:
        lines.append(
            "Note: no packets contained an IP layer — the capture may be "
            "malformed or the link-type wrong (try --link-type)."
        )

    return "\n".join(lines)
