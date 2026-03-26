#!/usr/bin/env python3
"""
packet_lab — build and parse raw network packets.

Subcommands:
  build   Build packets from a JSON config file and write to a pcap or pcapng file
  parse   Parse a pcap or pcapng file and produce a JSON config

Examples:
  python packet_lab.py build packets.json --pcap out.pcap
  python packet_lab.py build packets.json --pcapng out.pcapng
  python packet_lab.py parse capture.pcap
  python packet_lab.py parse capture.pcap --output replay.json --replay-pcap replayed.pcap
"""
import argparse
import json
import sys
from packet_generator import PacketBuilder
from packet_generator.tcp import TCPOptions
from packet_generator.pcap import write_pcap, write_pcapng, LINKTYPE_ETHERNET, LINKTYPE_RAW
from packet_generator.pppoe import PPPoETag, PPPOE_CODE_SESSION
from packet_parser.parser import parse_pcap_file


def _parse_tcp_options(spec: dict | None) -> TCPOptions | None:
    """Convert a JSON ``transport.options`` object to a :class:`TCPOptions`."""
    if not spec:
        return None
    sack_raw = spec.get("sack", [])
    return TCPOptions(
        mss=spec.get("mss"),
        window_scale=spec.get("window_scale"),
        sack_permitted=spec.get("sack_permitted", False),
        sack_blocks=[tuple(b) for b in sack_raw],
        timestamps=tuple(spec["timestamps"]) if "timestamps" in spec else None,
    )


def _apply_spec_to_builder(
    b: "PacketBuilder",
    spec: dict,
    packet_num: int,
) -> tuple["PacketBuilder", bool]:
    """Append all protocol layers from *spec* to *b*.

    Returns ``(b, is_terminal)`` where ``is_terminal`` is ``True`` for
    packets that end without an IP/transport layer (e.g. PPPoE discovery).
    Called recursively for the inner frame when ``protocol`` is ``"etherip"``.
    """
    eth          = spec.get("ethernet", {})
    vlan         = eth.get("vlan", {})
    mpls_labels  = spec.get("mpls", [])
    pppoe_spec   = spec.get("pppoe")
    etherip_inner = spec.get("etherip")   # inner frame spec when protocol="etherip"
    net          = spec.get("network", {})
    transport    = spec.get("transport", {})
    payload_spec = spec.get("payload", {})

    src          = net.get("src")
    dst          = net.get("dst")
    protocol_str = net.get("protocol")

    is_pppoe_discovery = (
        pppoe_spec is not None
        and pppoe_spec.get("code", PPPOE_CODE_SESSION) != PPPOE_CODE_SESSION
    )
    is_etherip = bool(protocol_str) and protocol_str.lower() == "etherip"

    if not is_pppoe_discovery and not is_etherip and (not src or not dst or not protocol_str):
        print(
            f"Error: packet {packet_num} missing network.src, network.dst, or network.protocol",
            file=sys.stderr,
        )
        sys.exit(1)

    if is_etherip and etherip_inner is None:
        print(
            f"Error: packet {packet_num} protocol is 'etherip' but 'etherip' spec is missing",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── Ethernet ─────────────────────────────────────────────────────────────
    if eth.get("enabled", True):
        b = b.ethernet(
            src_mac=eth.get("src_mac", "00:00:00:00:00:01"),
            dst_mac=eth.get("dst_mac", "00:00:00:00:00:02"),
            pad=eth.get("pad", False),
        )
        if vlan:
            b = b.vlan(vid=vlan["id"], pcp=vlan.get("pcp", 0), dei=vlan.get("dei", 0))

    # ── MPLS ─────────────────────────────────────────────────────────────────
    for mpls_entry in mpls_labels:
        b = b.mpls(
            label=mpls_entry["label"],
            tc=mpls_entry.get("tc", 0),
            ttl=mpls_entry.get("ttl", 64),
        )

    # ── PPPoE ────────────────────────────────────────────────────────────────
    if pppoe_spec is not None:
        try:
            tags = [
                PPPoETag(
                    type=t["type"],
                    data=bytes.fromhex(t.get("data", "")),
                )
                for t in pppoe_spec.get("tags", [])
            ]
        except (KeyError, ValueError) as e:
            print(f"Error: packet {packet_num} pppoe tag error: {e}", file=sys.stderr)
            sys.exit(1)
        b = b.pppoe(
            code=pppoe_spec.get("code", PPPOE_CODE_SESSION),
            session_id=pppoe_spec.get("session_id", 0),
            tags=tags,
        )

    if is_pppoe_discovery:
        return b, True

    # ── IP ───────────────────────────────────────────────────────────────────
    b = b.ip(
        src=src, dst=dst,
        ttl=net.get("ttl", 64),
        tos=net.get("tos", 0),
        identification=net.get("identification", 0),
        flags=net.get("flags", 0b010),
        fragment_offset=net.get("fragment_offset", 0),
        traffic_class=net.get("traffic_class", 0),
        flow_label=net.get("flow_label", 0),
    )

    # ── Protocol dispatch ────────────────────────────────────────────────────
    proto_lower = protocol_str.lower()

    if proto_lower == "etherip":
        b = b.etherip()
        b, _ = _apply_spec_to_builder(b, etherip_inner, packet_num)  # recurse
        return b, False

    if proto_lower == "tcp":
        b = b.tcp(
            src_port=transport.get("src_port", 12345),
            dst_port=transport.get("dst_port", 80),
            seq=transport.get("seq", 0),
            ack=transport.get("ack", 0),
            flags=transport.get("flags", 0x002),
            window=transport.get("window", 65535),
            urgent_ptr=transport.get("urgent_ptr", 0),
            reserved=transport.get("reserved", 0),
            options=_parse_tcp_options(transport.get("options")),
        )
    elif proto_lower == "udp":
        b = b.udp(
            src_port=transport.get("src_port", 12345),
            dst_port=transport.get("dst_port", 80),
        )
    elif proto_lower == "icmp":
        b = b.icmp(
            type=transport.get("type", 8),
            code=transport.get("code", 0),
            identifier=transport.get("identifier", 1),
            sequence=transport.get("sequence", 1),
        )
    elif proto_lower == "icmpv6":
        b = b.icmpv6(
            type=transport.get("type", 128),
            code=transport.get("code", 0),
            identifier=transport.get("identifier", 1),
            sequence=transport.get("sequence", 1),
        )
    else:
        print(f"Error: packet {packet_num} unknown protocol '{protocol_str}'", file=sys.stderr)
        sys.exit(1)

    # ── Payload ──────────────────────────────────────────────────────────────
    explicit_payload: bytes | None = None
    if "data" in payload_spec:
        try:
            explicit_payload = bytes.fromhex(payload_spec["data"])
        except ValueError as e:
            print(f"Error: packet {packet_num} payload.data is not valid hex: {e}", file=sys.stderr)
            sys.exit(1)

    if explicit_payload is not None:
        b = b.payload(data=explicit_payload)
    elif payload_spec.get("size", 0):
        b = b.payload(size=payload_spec["size"])

    return b, False


def _run_multi_packet(cfg: dict, pcap_path: str | None = None, pcapng_path: str | None = None) -> None:
    """Build and output all packets defined in a JSON config."""
    file_metadata = cfg.get("file_metadata", {})
    nanoseconds: bool = file_metadata.get("nanoseconds", False)

    if "packets" not in cfg:
        print("Error: config file must have a top-level 'packets' array", file=sys.stderr)
        sys.exit(1)

    specs = cfg["packets"]
    if not specs:
        print("Error: 'packets' array is empty", file=sys.stderr)
        sys.exit(1)

    # Use LINKTYPE_RAW only when every packet disables ethernet
    all_no_eth = all(not spec.get("ethernet", {}).get("enabled", True) for spec in specs)
    link_type = LINKTYPE_RAW if all_no_eth else LINKTYPE_ETHERNET

    # collected: list of (pkt_bytes, ts_sec, ts_frac)
    collected: list[tuple[bytes, int, int]] = []

    for i, spec in enumerate(specs, 1):
        out = spec.get("metadata", {})
        try:
            b, is_terminal = _apply_spec_to_builder(PacketBuilder(), spec, i)
            if is_terminal:
                pkts = [b.build()]
            else:
                mtu = out.get("mtu")
                pkts = b.fragment(mtu=mtu) if mtu is not None else [b.build()]
        except (OSError, ValueError) as e:
            print(f"Error building packet {i}: {e}", file=sys.stderr)
            sys.exit(1)

        ts_sec: int = out.get("timestamp_s", 0)
        ts_frac: int = out.get("timestamp_ns" if nanoseconds else "timestamp_us", 0)
        for pkt in pkts:
            collected.append((pkt, ts_sec, ts_frac))

    if pcap_path:
        write_pcap(collected, path=pcap_path, link_type=link_type, nanoseconds=nanoseconds)
        print(f"Wrote {len(collected)} packet(s) to {pcap_path} (link type: {link_type})")
    else:
        write_pcapng(collected, path=pcapng_path, link_type=link_type, nanoseconds=nanoseconds)
        print(f"Wrote {len(collected)} packet(s) to {pcapng_path} (link type: {link_type})")


def _cmd_build(args: argparse.Namespace) -> None:
    try:
        with open(args.config) as f:
            raw_cfg = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"Error loading config '{args.config}': {e}", file=sys.stderr)
        sys.exit(1)
    _run_multi_packet(raw_cfg, pcap_path=args.pcap, pcapng_path=args.pcapng)


def _cmd_parse(args: argparse.Namespace) -> None:
    output_block: dict = {"from_file": args.pcap}
    if args.replay_pcap:
        output_block["type"] = "pcap"
    elif args.replay_pcapng:
        output_block["type"] = "pcapng"

    try:
        json_str = parse_pcap_file(path=args.pcap, output=output_block)
    except (OSError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(json_str)
                f.write("\n")
        except OSError as e:
            print(f"Error writing '{args.output}': {e}", file=sys.stderr)
            sys.exit(1)
        print(f"Wrote JSON config to {args.output}")
    else:
        print(json_str)


def main():
    parser = argparse.ArgumentParser(
        description="Build and parse raw network packets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── build subcommand ──────────────────────────────────────────────────────
    build_parser = subparsers.add_parser(
        "build",
        help="Build packets from a JSON config file",
        description="Build packets from a JSON config file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    build_parser.add_argument("config", metavar="FILE", help="JSON config file with a 'packets' array")
    build_out = build_parser.add_mutually_exclusive_group(required=True)
    build_out.add_argument("--pcap", metavar="FILE", help="Write packets to a libpcap (.pcap) file")
    build_out.add_argument("--pcapng", metavar="FILE", help="Write packets to a pcapng (.pcapng) file")
    build_parser.set_defaults(func=_cmd_build)

    # ── parse subcommand ──────────────────────────────────────────────────────
    parse_parser = subparsers.add_parser(
        "parse",
        help="Parse a pcap or pcapng file and produce a JSON config",
        description="Parse a pcap or pcapng file and produce a JSON config that can be replayed with 'build --config'",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parse_parser.add_argument(
        "pcap",
        metavar="FILE",
        help="Input .pcap or .pcapng file to parse",
    )
    parse_parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write JSON config to FILE instead of stdout",
    )
    replay_group = parse_parser.add_mutually_exclusive_group()
    replay_group.add_argument(
        "--replay-pcap",
        metavar="FILE",
        help="Set type=pcap in the generated file_metadata so the config can be replayed as a pcap",
    )
    replay_group.add_argument(
        "--replay-pcapng",
        metavar="FILE",
        help="Set type=pcapng in the generated file_metadata so the config can be replayed as a pcapng",
    )
    parse_parser.set_defaults(func=_cmd_parse)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
