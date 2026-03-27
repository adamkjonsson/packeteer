"""Convert parsed packet header objects to a JSON config dict.

The produced dict matches the JSON format accepted by ``packet_lab.py build``,
so a parsed capture can be saved and replayed directly.

Build up a config one protocol layer at a time using :func:`update_config`,
then wrap multiple packets into a top-level config with :func:`to_json_config`
and serialise with :func:`to_json_string`.

Typical usage::

    from packet_parser import ethernet_packet_parser, ip_packet_parser, tcp_packet_parser
    from packet_parser.pcap import read_pcap
    from packet_parser.to_config import update_config, to_json_config, to_json_string

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
        cfg.setdefault("metadata", {}).update({"timestamp_s": ts_sec, "timestamp_us": ts_frac})
        packet_configs.append(cfg)

    print(to_json_string(to_json_config(packet_configs, file_metadata={"from_file": "capture.pcap", "type": "pcap"})))
"""
from __future__ import annotations

import json
import socket
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from packet_parser.parser import ParsedPacket

from packet_generator.ethernet import EthernetHeader
from packet_generator.etherip import EtherIPHeader, IPPROTO_ETHERIP
from packet_generator.ip import IPHeader
from packet_generator.ipv6 import IPv6Header
from packet_generator.mpls import MPLSLabel
from packet_generator.pppoe import PPPoEHeader, PPPOE_CODE_SESSION
from packet_generator.tcp import TCPHeader, TCPOptions
from packet_generator.udp import UDPHeader
from packet_generator.icmp import ICMPHeader
from packet_generator.icmpv6 import ICMPv6Header

_PROTO_TO_STR: dict[int, str] = {
    socket.IPPROTO_TCP:  "tcp",
    socket.IPPROTO_UDP:  "udp",
    socket.IPPROTO_ICMP: "icmp",
    socket.IPPROTO_ICMPV6: "icmpv6",
    IPPROTO_ETHERIP:     "etherip",
    4:                   "ipip",   # IPv4-in-IP (RFC 2003)
    41:                  "ipip",   # IPv6-in-IP (RFC 4213)
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


def _apply_transport(config: dict[str, Any], hdr: TCPHeader | UDPHeader | ICMPHeader | ICMPv6Header) -> None:
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


def _apply_payload(config: dict[str, Any], payload: bytes) -> None:
    config["payload"] = {"data": payload.hex()}


def update_config(
    config: dict[str, Any],
    layer: EthernetHeader | PPPoEHeader | MPLSLabel | IPHeader | IPv6Header | TCPHeader | UDPHeader | ICMPHeader | ICMPv6Header | bytes,
) -> dict[str, Any]:
    """Add a parsed protocol layer to *config* and return it.

    Dispatches on the type of *layer*:

    - :class:`~packet_generator.ethernet.EthernetHeader` → ``ethernet`` section
    - :class:`~packet_generator.mpls.MPLSLabel` → appended to the ``mpls`` array
    - :class:`~packet_generator.pppoe.PPPoEHeader` → ``pppoe`` section
    - :class:`~packet_generator.ip.IPHeader` / :class:`~packet_generator.ipv6.IPv6Header` → ``network`` section
    - :class:`~packet_generator.etherip.EtherIPHeader` → handled via
      :func:`_apply_etherip` in :func:`~packet_parser.parser.parse_pcap_file`
      (requires the inner :class:`~packet_parser.parser.ParsedPacket` as a
      second argument — not dispatchable through ``update_config`` alone)
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
    elif isinstance(layer, (TCPHeader, UDPHeader, ICMPHeader, ICMPv6Header)):
        _apply_transport(config, layer)
    elif isinstance(layer, bytes):
        _apply_payload(config, layer)
    else:
        raise TypeError(f"update_config: unrecognised layer type {type(layer).__name__!r}")
    return config


def to_json_config(
    packets: list[dict[str, Any]],
    *,
    file_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Wrap a list of packet config dicts into a top-level config dict.

    Args:
        packets: List of per-packet dicts built with :func:`update_config`.
        file_metadata: Top-level ``file_metadata`` block (e.g.
            ``{"from_file": "capture.pcap", "type": "pcap"}``).
            Omitted when ``None``.

    Returns:
        A dict matching the top-level JSON config format accepted by
        ``cli.py --config``.
    """
    cfg: dict[str, Any] = {}
    if file_metadata is not None:
        cfg["file_metadata"] = file_metadata
    cfg["packets"] = packets
    return cfg


def to_json_string(config: dict[str, Any], *, indent: int = 2) -> str:
    """Serialise a config dict to a JSON string.

    Args:
        config: Dict produced by :func:`to_json_config` or a single packet
            dict produced by :func:`update_config`.
        indent: Indentation width for pretty-printing (default: ``2``).

    Returns:
        A UTF-8 JSON string.
    """
    return json.dumps(config, indent=indent)
