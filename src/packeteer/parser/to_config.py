"""Convert parsed packet header objects to a packet spec dict.

The produced dict matches the packet spec format accepted by ``packeteer build``,
so a parsed capture can be saved and replayed directly.

Build up a spec one protocol layer at a time using :func:`update_config`,
then wrap multiple packets into a top-level spec with :func:`to_packet_spec`
and serialise with :func:`to_json_string`.

Typical usage::

    from packet_parser import ethernet_packet_parser, ip_packet_parser, tcp_packet_parser
    from .pcap import read_pcap
    from .to_config import update_config, to_packet_spec, to_json_string

    pcap = read_pcap(path="capture.pcap")
    packet_configs = []
    for raw, ts_sec, ts_frac in pcap.packets:
        cfg = {}
        eth_size, _, eth_hdr = ethernet_packet_parser(raw)
        update_config(cfg, eth_hdr)
        ip_size,  _, ip_hdr  = ip_packet_parser(raw[eth_size:])
        update_config(cfg, ip_hdr)
        tcp_size, _, tcp_hdr = tcp_packet_parser(raw[eth_size + ip_size:])
        update_config(cfg, tcp_hdr)
        payload = raw[eth_size + ip_size + tcp_size:]
        if payload:
            update_config(cfg, payload)
        cfg.setdefault("packet_metadata", {}).update({"timestamp_s": ts_sec, "timestamp_us": ts_frac})
        packet_configs.append(cfg)

    print(to_json_string(to_packet_spec(packet_configs, metadata={"from_file": "capture.pcap", "type": "pcap"})))
"""
from __future__ import annotations

import json
import socket
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .core import ParsedPacket

from packeteer.generator.ethernet import EthernetHeader
from packeteer.generator.etherip import EtherIPHeader, IPPROTO_ETHERIP
from packeteer.generator.gre import GREHeader
from packeteer.generator.ip import IPHeader
from packeteer.generator.ipv6 import IPv6Header
from packeteer.generator.mpls import MPLSLabel
from packeteer.generator.pppoe import PPPoEHeader, PPPOE_CODE_SESSION
from packeteer.generator.tcp import TCPHeader, TCPOptions
from packeteer.generator.udp import UDPHeader
from packeteer.generator.icmp import ICMPHeader
from packeteer.generator.icmpv6 import ICMPv6Header
from packeteer.generator.sctp import (
    SCTPHeader,
    SCTPDataChunk,
    SCTPInitChunk,
    SCTPInitAckChunk,
    SCTPSackChunk,
    SCTPHeartbeatChunk,
    SCTPHeartbeatAckChunk,
    SCTPAbortChunk,
    SCTPShutdownChunk,
    SCTPShutdownAckChunk,
    SCTPErrorChunk,
    SCTPCookieEchoChunk,
    SCTPCookieAckChunk,
    SCTPShutdownCompleteChunk,
    SCTPGenericChunk,
    SCTPChunk,
)

_PROTO_TO_STR: dict[int, str] = {
    socket.IPPROTO_TCP:      "tcp",       # 6
    socket.IPPROTO_UDP:      "udp",       # 17
    socket.IPPROTO_ICMP:     "icmp",      # 1
    socket.IPPROTO_ICMPV6:   "icmpv6",    # 58
    IPPROTO_ETHERIP:         "etherip",   # 97
    socket.IPPROTO_GRE:      "gre",       # 47
    socket.IPPROTO_SCTP:     "sctp",      # 132
    socket.IPPROTO_IPV4:     "ipip",      # 4  — IPv4-in-IP (RFC 2003)
    socket.IPPROTO_IPV6:     "ipip",      # 41 — IPv6-in-IP (RFC 4213)
}

# ── SCTP chunk serialisation ──────────────────────────────────────────────────

_CHUNK_TYPE_TO_STR: dict[int, str] = {
    0:  "data",
    1:  "init",
    2:  "init_ack",
    3:  "sack",
    4:  "heartbeat",
    5:  "heartbeat_ack",
    6:  "abort",
    7:  "shutdown",
    8:  "shutdown_ack",
    9:  "error",
    10: "cookie_echo",
    11: "cookie_ack",
    14: "shutdown_complete",
}


def _serialise_sctp_chunk(chunk: SCTPChunk) -> dict[str, Any]:
    """Serialise one SCTP chunk to a JSON-compatible dict."""
    if isinstance(chunk, SCTPDataChunk):
        return {
            "type":       "data",
            "flags":      chunk.flags,
            "tsn":        chunk.tsn,
            "stream_id":  chunk.stream_id,
            "stream_seq": chunk.stream_seq,
            "ppid":       chunk.ppid,
            "data":       chunk.data.hex(),
        }
    if isinstance(chunk, (SCTPInitChunk, SCTPInitAckChunk)):
        d: dict[str, Any] = {
            "type":             "init" if isinstance(chunk, SCTPInitChunk) else "init_ack",
            "initiate_tag":     chunk.initiate_tag,
            "a_rwnd":           chunk.a_rwnd,
            "outbound_streams": chunk.outbound_streams,
            "inbound_streams":  chunk.inbound_streams,
            "initial_tsn":      chunk.initial_tsn,
        }
        if chunk.params:
            d["params"] = chunk.params.hex()
        return d
    if isinstance(chunk, SCTPSackChunk):
        return {
            "type":            "sack",
            "cum_tsn_ack":     chunk.cum_tsn_ack,
            "a_rwnd":          chunk.a_rwnd,
            "gap_ack_blocks":  [[s, e] for s, e in chunk.gap_ack_blocks],
            "dup_tsns":        list(chunk.dup_tsns),
        }
    if isinstance(chunk, (SCTPHeartbeatChunk, SCTPHeartbeatAckChunk)):
        return {
            "type": "heartbeat" if isinstance(chunk, SCTPHeartbeatChunk) else "heartbeat_ack",
            "info": chunk.info.hex(),
        }
    if isinstance(chunk, SCTPAbortChunk):
        d = {"type": "abort", "flags": chunk.flags}
        if chunk.causes:
            d["causes"] = chunk.causes.hex()
        return d
    if isinstance(chunk, SCTPShutdownChunk):
        return {"type": "shutdown", "cum_tsn_ack": chunk.cum_tsn_ack}
    if isinstance(chunk, SCTPShutdownAckChunk):
        return {"type": "shutdown_ack"}
    if isinstance(chunk, SCTPErrorChunk):
        d = {"type": "error"}
        if chunk.causes:
            d["causes"] = chunk.causes.hex()
        return d
    if isinstance(chunk, SCTPCookieEchoChunk):
        return {"type": "cookie_echo", "cookie": chunk.cookie.hex()}
    if isinstance(chunk, SCTPCookieAckChunk):
        return {"type": "cookie_ack"}
    if isinstance(chunk, SCTPShutdownCompleteChunk):
        return {"type": "shutdown_complete", "flags": chunk.flags}
    # SCTPGenericChunk
    return {
        "type":       "generic",
        "chunk_type": chunk.chunk_type,
        "flags":      chunk.flags,
        "value":      chunk.value.hex(),
    }


def _apply_ethernet(config: dict[str, Any], hdr: EthernetHeader) -> None:
    section: dict[str, Any] = {
        "src_mac": hdr.src_mac,
        "dst_mac": hdr.dst_mac,
        "enabled": True,
    }
    if hdr.vlan_tag is not None:
        section["vlan"] = {
            "id": hdr.vlan_tag.vid,
            "pcp": hdr.vlan_tag.pcp,
            "dei": hdr.vlan_tag.dei,
        }
    config["ethernet"] = section


def _apply_ip(config: dict[str, Any], hdr: IPHeader | IPv6Header) -> None:
    section: dict[str, Any] = {
        "src": hdr.src,
        "dst": hdr.dst,
    }
    if isinstance(hdr, IPHeader):
        proto_str = _PROTO_TO_STR.get(hdr.protocol)
        if proto_str is not None:
            section["protocol"] = proto_str
        section["ttl"] = hdr.ttl
        if hdr.tos != 0:
            section["tos"] = hdr.tos
        if hdr.identification != 0:
            section["identification"] = hdr.identification
        if hdr.flags != 0b010:
            section["flags"] = hdr.flags
        if hdr.fragment_offset != 0:
            section["fragment_offset"] = hdr.fragment_offset
    else:  # IPv6Header
        proto_str = _PROTO_TO_STR.get(hdr.next_header)
        if proto_str is not None:
            section["protocol"] = proto_str
        section["ttl"] = hdr.hop_limit
        if hdr.traffic_class != 0:
            section["traffic_class"] = hdr.traffic_class
        if hdr.flow_label != 0:
            section["flow_label"] = hdr.flow_label
    config["network"] = section


def _tcp_options_section(opts: TCPOptions) -> dict[str, Any]:
    section: dict[str, Any] = {}
    if opts.mss is not None:
        section["mss"] = opts.mss
    if opts.window_scale is not None:
        section["window_scale"] = opts.window_scale
    if opts.sack_permitted:
        section["sack_permitted"] = True
    if opts.sack_blocks:
        section["sack"] = [list(b) for b in opts.sack_blocks]
    if opts.timestamps is not None:
        section["timestamps"] = list(opts.timestamps)
    return section


def _apply_transport(config: dict[str, Any], hdr: TCPHeader | UDPHeader | ICMPHeader | ICMPv6Header | SCTPHeader) -> None:
    if isinstance(hdr, TCPHeader):
        section: dict[str, Any] = {
            "src_port": hdr.src_port,
            "dst_port": hdr.dst_port,
            "seq": hdr.seq,
            "ack": hdr.ack,
            "flags": hdr.flags,
            "window": hdr.window,
        }
        if hdr.reserved != 0:
            section["reserved"] = hdr.reserved
        if hdr.urgent_ptr != 0:
            section["urgent_ptr"] = hdr.urgent_ptr
        if hdr.options is not None:
            opts = _tcp_options_section(hdr.options)
            if opts:
                section["options"] = opts
    elif isinstance(hdr, UDPHeader):
        section = {
            "src_port": hdr.src_port,
            "dst_port": hdr.dst_port,
        }
    elif isinstance(hdr, SCTPHeader):
        section = {
            "src_port":         hdr.src_port,
            "dst_port":         hdr.dst_port,
            "verification_tag": hdr.verification_tag,
            "chunks":           [_serialise_sctp_chunk(c) for c in hdr.chunks],
        }
    else:  # ICMPHeader or ICMPv6Header
        section = {
            "type": hdr.type,
            "code": hdr.code,
            "identifier": hdr.identifier,
            "sequence": hdr.sequence,
        }
    config["transport"] = section


def _apply_pppoe(config: dict[str, Any], hdr: PPPoEHeader) -> None:
    section: dict[str, Any] = {"session_id": hdr.session_id}
    if hdr.code != PPPOE_CODE_SESSION:
        section["code"] = hdr.code
    if hdr.tags:
        section["tags"] = [
            {"type": t.type, "data": t.data.hex()}
            for t in hdr.tags
        ]
    config["pppoe"] = section


def _apply_mpls(config: dict[str, Any], label: MPLSLabel) -> None:
    entry: dict[str, Any] = {"label": label.label}
    if label.tc != 0:
        entry["tc"] = label.tc
    entry["ttl"] = label.ttl
    config.setdefault("mpls", []).append(entry)


def _apply_inner_tail(inner: dict[str, Any], tunneled: ParsedPacket) -> None:
    """Write transport + payload into *inner* when there is no nested tunnel.

    Shared by :func:`_apply_etherip` and :func:`_apply_ipip` for the
    terminal (non-recursive) case.
    """
    if tunneled.transport is not None:
        _apply_transport(inner, tunneled.transport)
        if tunneled.payload:
            _apply_payload(inner, tunneled.payload)


def _apply_etherip(config: dict[str, Any], hdr: EtherIPHeader, tunneled: ParsedPacket) -> None:
    """Serialise *hdr* and the recursively-parsed inner frame *tunneled* into
    ``config["etherip"]``.  Called recursively for double-nested EtherIP."""
    inner: dict[str, Any] = {}
    if tunneled.ethernet is not None:
        _apply_ethernet(inner, tunneled.ethernet)
    for label in tunneled.mpls:
        _apply_mpls(inner, label)
    if tunneled.pppoe is not None:
        _apply_pppoe(inner, tunneled.pppoe)
    if tunneled.ip is not None:
        _apply_ip(inner, tunneled.ip)
    if tunneled.etherip is not None and tunneled.tunneled is not None:
        _apply_etherip(inner, tunneled.etherip, tunneled.tunneled)  # recurse
    else:
        _apply_inner_tail(inner, tunneled)
    config["etherip"] = inner


def _apply_ipip(config: dict[str, Any], tunneled: "ParsedPacket") -> None:
    """Serialise inner IP-in-IP frame into ``config["ipip"]`` (no ethernet)."""
    inner: dict[str, Any] = {}
    if tunneled.ip is not None:
        _apply_ip(inner, tunneled.ip)
    if tunneled.ipip and tunneled.tunneled is not None:
        _apply_ipip(inner, tunneled.tunneled)  # recurse for nested IP-in-IP
    else:
        _apply_inner_tail(inner, tunneled)
    config["ipip"] = inner


def _apply_gre(config: dict[str, Any], hdr: GREHeader, tunneled: "ParsedPacket") -> None:
    """Serialise *hdr* and the recursively-parsed inner payload *tunneled* into
    ``config["gre"]``.  Called recursively for nested GRE."""
    inner: dict[str, Any] = {}
    # RFC 2890 / RFC 2784 optional fields
    if hdr.key is not None:
        inner["key"] = hdr.key
    if hdr.seq is not None:
        inner["seq"] = hdr.seq
    if hdr.checksum:
        inner["checksum"] = True
    # Inner payload layers (TEB has ethernet; IP-in-GRE does not)
    if tunneled.ethernet is not None:
        _apply_ethernet(inner, tunneled.ethernet)
    for label in tunneled.mpls:
        _apply_mpls(inner, label)
    if tunneled.pppoe is not None:
        _apply_pppoe(inner, tunneled.pppoe)
    if tunneled.ip is not None:
        _apply_ip(inner, tunneled.ip)
    if tunneled.gre is not None and tunneled.tunneled is not None:
        _apply_gre(inner, tunneled.gre, tunneled.tunneled)   # recurse
    elif tunneled.etherip is not None and tunneled.tunneled is not None:
        _apply_etherip(inner, tunneled.etherip, tunneled.tunneled)
    elif tunneled.ipip and tunneled.tunneled is not None:
        _apply_ipip(inner, tunneled.tunneled)
    else:
        _apply_inner_tail(inner, tunneled)
    config["gre"] = inner


def _apply_payload(config: dict[str, Any], payload: bytes) -> None:
    config["payload"] = {"data": payload.hex()}


def update_config(
    config: dict[str, Any],
    layer: EthernetHeader | PPPoEHeader | MPLSLabel | IPHeader | IPv6Header | TCPHeader | UDPHeader | ICMPHeader | ICMPv6Header | SCTPHeader | bytes,
) -> dict[str, Any]:
    """Add a parsed protocol layer to *config* and return it.

    Dispatches on the type of *layer*:

    - :class:`~packet_generator.ethernet.EthernetHeader` → ``ethernet`` section
    - :class:`~packet_generator.mpls.MPLSLabel` → appended to the ``mpls`` array
    - :class:`~packet_generator.pppoe.PPPoEHeader` → ``pppoe`` section
    - :class:`~packet_generator.ip.IPHeader` / :class:`~packet_generator.ipv6.IPv6Header` → ``network`` section
    - :class:`~packet_generator.etherip.EtherIPHeader` / GRE /
      IP-in-IP → use :func:`apply_tunneled` instead; tunnel serialisation
      requires the inner :class:`~packeteer.parser.core.ParsedPacket` as
      additional context and cannot be dispatched through ``update_config``
      alone.
    - :class:`~packet_generator.tcp.TCPHeader` → ``transport`` section (TCP fields)
    - :class:`~packet_generator.udp.UDPHeader` → ``transport`` section (UDP fields)
    - :class:`~packet_generator.icmp.ICMPHeader` / :class:`~packet_generator.icmpv6.ICMPv6Header` → ``transport`` section (ICMP fields)
    - :class:`bytes` → ``payload`` section (encoded as a hex string)

    Modifies *config* in-place and returns it so calls can be chained::

        cfg = update_config(update_config(update_config({}, eth_hdr), ip_hdr), tcp_hdr)

    Args:
        config: The packet config dict to update.
        layer: A parsed header object or raw payload bytes.

    Returns:
        The same *config* dict, updated with the new layer.

    Raises:
        TypeError: If *layer* is not a recognised header type or bytes.
    """
    if isinstance(layer, EthernetHeader):
        _apply_ethernet(config, layer)
    elif isinstance(layer, PPPoEHeader):
        _apply_pppoe(config, layer)
    elif isinstance(layer, MPLSLabel):
        _apply_mpls(config, layer)
    elif isinstance(layer, (IPHeader, IPv6Header)):
        _apply_ip(config, layer)
    elif isinstance(layer, (TCPHeader, UDPHeader, ICMPHeader, ICMPv6Header, SCTPHeader)):
        _apply_transport(config, layer)
    elif isinstance(layer, bytes):
        _apply_payload(config, layer)
    else:
        raise TypeError(f"update_config: unrecognised layer type {type(layer).__name__!r}")
    return config


def apply_tunneled(config: dict[str, Any], pkt: "ParsedPacket") -> None:
    """Serialise the tunnel layers of *pkt* into *config*.

    Handles all three tunnel types — IP-in-IP, GRE, and EtherIP — by
    dispatching to the appropriate private helper.  Call this after the
    outer IP layer has been written via :func:`update_config` whenever
    :attr:`~packeteer.parser.core.ParsedPacket.ipip`,
    :attr:`~packeteer.parser.core.ParsedPacket.gre`, or
    :attr:`~packeteer.parser.core.ParsedPacket.etherip` is set on *pkt*.

    Modifies *config* in place.  Does nothing when *pkt* carries no tunnel.

    Args:
        config: The packet config dict to update (same dict passed to
            :func:`update_config` for the outer layers).
        pkt: The parsed packet whose tunnel fields should be serialised.
    """
    if pkt.ipip and pkt.tunneled is not None:
        _apply_ipip(config, pkt.tunneled)
    elif pkt.gre is not None and pkt.tunneled is not None:
        _apply_gre(config, pkt.gre, pkt.tunneled)
    elif pkt.etherip is not None and pkt.tunneled is not None:
        _apply_etherip(config, pkt.etherip, pkt.tunneled)


def to_packet_spec(
    packets: list[dict[str, Any]],
    *,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Wrap a list of per-packet dicts into a top-level packet spec dict.

    The top-level ``metadata`` block is always written.  ``nanoseconds``
    defaults to ``False`` when not supplied by the caller.

    Args:
        packets: List of per-packet dicts built with :func:`update_config`.
        metadata: Extra fields to merge into the top-level ``metadata`` block
            (e.g. ``{"from_file": "capture.pcap", "type": "pcap",
            "nanoseconds": False}``).  ``nanoseconds`` is added automatically
            when absent.

    Returns:
        A packet spec dict accepted by ``packeteer build``.
    """
    cfg: dict[str, Any] = {}
    top_meta: dict[str, Any] = dict(metadata) if metadata is not None else {}
    top_meta.setdefault("nanoseconds", False)
    cfg["metadata"] = top_meta
    cfg["packets"] = packets
    return cfg


def to_json_string(config: dict[str, Any], *, indent: int = 2) -> str:
    """Serialise a packet spec dict to a JSON string.

    Args:
        config: Dict produced by :func:`to_packet_spec` or a single packet
            dict produced by :func:`update_config`.
        indent: Indentation width for pretty-printing (default: ``2``).

    Returns:
        A UTF-8 JSON string.
    """
    return json.dumps(config, indent=indent)
