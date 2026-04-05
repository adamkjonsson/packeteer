#!/usr/bin/env python3
"""
packeteer — build, parse, sanitise, and generate raw network packets.

Subcommands:
  build     Build packets from a JSON config file and write to a pcap or pcapng file
  parse     Parse a pcap or pcapng file and produce a JSON config
  sanitise  Replace sensitive fields in a JSON config with synthetic data
  stream    Generate a synthetic TCP stream and write to a pcap or pcapng file

Examples:
  packeteer build packets.json --pcap out.pcap
  packeteer build packets.json --pcapng out.pcapng
  packeteer parse capture.pcap
  packeteer parse capture.pcap --output replay.json --replay-pcap replayed.pcap
  packeteer sanitise capture.json --output clean.json
  packeteer sanitise capture.json --ports --payload --output clean.json
  packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 --packets 50 --pcap out.pcap
  packeteer stream --client-ip 10.0.0.1 --server-ip 10.0.0.2 --server-port 443 --distribution bimodal --pcapng tls.pcapng
"""
# This module is the entry point for the `packeteer` CLI command.
# The mapping is declared in pyproject.toml: [project.scripts] packeteer = "packeteer_cli:main"
import argparse
import configparser
import json
import sys
from packet_generator import PacketBuilder
from packet_generator.tcp import TCPOptions
from packet_generator.pcap import write_pcap, write_pcapng, LINKTYPE_ETHERNET, LINKTYPE_RAW
from packet_generator.tcp_stream import generate_tcp_stream
from packet_generator.pppoe import PPPoETag, PPPOE_CODE_SESSION
from packet_parser.parser import parse_pcap_file
from replacer import SanitiseOptions, sanitise


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


def _build_ip_layer(b: "PacketBuilder", net: dict) -> "PacketBuilder":
    """Append an IP layer from a ``network`` spec dict to *b*."""
    return b.ip(
        src=net["src"], dst=net["dst"],
        ttl=net.get("ttl", 64),
        tos=net.get("tos", 0),
        identification=net.get("identification", 0),
        flags=net.get("flags", 0b010),
        fragment_offset=net.get("fragment_offset", 0),
        traffic_class=net.get("traffic_class", 0),
        flow_label=net.get("flow_label", 0),
    )


def _dispatch_transport(
    b: "PacketBuilder",
    proto_lower: str,
    transport: dict,
    packet_num: int,
    context: str = "",
) -> "PacketBuilder":
    """Append the transport layer for *proto_lower* to *b* and return it.

    *context* is a short prefix (e.g. ``"ipip inner "``) used in error messages.
    """
    if proto_lower == "tcp":
        return b.tcp(
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
    if proto_lower == "udp":
        return b.udp(
            src_port=transport.get("src_port", 12345),
            dst_port=transport.get("dst_port", 80),
        )
    if proto_lower == "icmp":
        return b.icmp(
            type=transport.get("type", 8),
            code=transport.get("code", 0),
            identifier=transport.get("identifier", 1),
            sequence=transport.get("sequence", 1),
        )
    if proto_lower == "icmpv6":
        return b.icmpv6(
            type=transport.get("type", 128),
            code=transport.get("code", 0),
            identifier=transport.get("identifier", 1),
            sequence=transport.get("sequence", 1),
        )
    print(
        f"Error: packet {packet_num} {context}unknown protocol '{proto_lower}'",
        file=sys.stderr,
    )
    sys.exit(1)


def _apply_payload_spec(
    b: "PacketBuilder",
    payload_spec: dict,
    packet_num: int,
    context: str = "",
) -> "PacketBuilder":
    """Append a payload layer from *payload_spec* to *b* (if any) and return it.

    *context* is a short prefix (e.g. ``"ipip inner "``) used in error messages.
    """
    if "data" in payload_spec:
        try:
            data = bytes.fromhex(payload_spec["data"])
        except ValueError as e:
            print(
                f"Error: packet {packet_num} {context}payload.data is not valid hex: {e}",
                file=sys.stderr,
            )
            sys.exit(1)
        return b.payload(data=data)
    if payload_spec.get("size", 0):
        return b.payload(size=payload_spec["size"])
    return b


def _build_pppoe(
    b: "PacketBuilder",
    pppoe_spec: dict,
    packet_num: int,
) -> "PacketBuilder":
    """Append a PPPoE layer from *pppoe_spec* to *b* and return it."""
    try:
        tags = [
            PPPoETag(type=t["type"], data=bytes.fromhex(t.get("data", "")))
            for t in pppoe_spec.get("tags", [])
        ]
    except (KeyError, ValueError) as e:
        print(f"Error: packet {packet_num} pppoe tag error: {e}", file=sys.stderr)
        sys.exit(1)
    return b.pppoe(
        code=pppoe_spec.get("code", PPPOE_CODE_SESSION),
        session_id=pppoe_spec.get("session_id", 0),
        tags=tags,
    )


def _apply_ip_chain(
    b: "PacketBuilder",
    spec: dict,
    packet_num: int,
) -> "PacketBuilder":
    """Append IP + transport layers from an IP-in-IP inner spec to *b*.

    No ethernet/VLAN/MPLS/PPPoE — the inner spec contains only
    ``network``, ``transport``, ``payload``, and optionally a nested
    ``ipip`` key for double-tunnelled packets.  Called recursively.
    """
    net          = spec.get("network", {})
    protocol_str = net.get("protocol")

    if not net.get("src") or not net.get("dst") or not protocol_str:
        print(
            f"Error: packet {packet_num} ipip inner spec missing "
            "network.src, network.dst, or network.protocol",
            file=sys.stderr,
        )
        sys.exit(1)

    b = _build_ip_layer(b, net)
    proto_lower = protocol_str.lower()

    if proto_lower == "ipip":
        ipip_inner = spec.get("ipip")
        if ipip_inner is None:
            print(
                f"Error: packet {packet_num} ipip inner protocol is "
                "'ipip' but nested 'ipip' spec is missing",
                file=sys.stderr,
            )
            sys.exit(1)
        return _apply_ip_chain(b, ipip_inner, packet_num)

    if proto_lower == "gre":
        gre_inner = spec.get("gre")
        if gre_inner is None:
            print(
                f"Error: packet {packet_num} inner protocol is "
                "'gre' but nested 'gre' spec is missing",
                file=sys.stderr,
            )
            sys.exit(1)
        b = b.gre(
            key=gre_inner.get("key"),
            seq=gre_inner.get("seq"),
            checksum=gre_inner.get("checksum", False),
        )
        return _apply_ip_chain(b, gre_inner, packet_num)

    b = _dispatch_transport(b, proto_lower, spec.get("transport", {}), packet_num, "ipip inner ")
    return _apply_payload_spec(b, spec.get("payload", {}), packet_num, "ipip inner ")


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
    mpls_labels  = spec.get("mpls", [])
    pppoe_spec   = spec.get("pppoe")
    net          = spec.get("network", {})

    src          = net.get("src")
    dst          = net.get("dst")
    protocol_str = net.get("protocol")

    is_pppoe_discovery = (
        pppoe_spec is not None
        and pppoe_spec.get("code", PPPOE_CODE_SESSION) != PPPOE_CODE_SESSION
    )
    is_etherip = bool(protocol_str) and protocol_str.lower() == "etherip"
    is_ipip    = bool(protocol_str) and protocol_str.lower() == "ipip"
    is_gre     = bool(protocol_str) and protocol_str.lower() == "gre"

    if not is_pppoe_discovery and not is_etherip and not is_ipip and not is_gre and \
            (not src or not dst or not protocol_str):
        print(
            f"Error: packet {packet_num} missing network.src, network.dst, or network.protocol",
            file=sys.stderr,
        )
        sys.exit(1)

    if is_ipip and spec.get("ipip") is None:
        print(
            f"Error: packet {packet_num} protocol is 'ipip' but 'ipip' spec is missing",
            file=sys.stderr,
        )
        sys.exit(1)

    if is_etherip and spec.get("etherip") is None:
        print(
            f"Error: packet {packet_num} protocol is 'etherip' but 'etherip' spec is missing",
            file=sys.stderr,
        )
        sys.exit(1)

    if is_gre and spec.get("gre") is None:
        print(
            f"Error: packet {packet_num} protocol is 'gre' but 'gre' spec is missing",
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
        vlan = eth.get("vlan", {})
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
        b = _build_pppoe(b, pppoe_spec, packet_num)

    if is_pppoe_discovery:
        return b, True

    # ── IP ───────────────────────────────────────────────────────────────────
    b = _build_ip_layer(b, net)

    # ── Protocol dispatch ────────────────────────────────────────────────────
    proto_lower = protocol_str.lower()

    if proto_lower == "etherip":
        b = b.etherip()
        b, _ = _apply_spec_to_builder(b, spec["etherip"], packet_num)
        return b, False

    if proto_lower == "ipip":
        b = _apply_ip_chain(b, spec["ipip"], packet_num)
        return b, False

    if proto_lower == "gre":
        gre_spec = spec["gre"]
        b = b.gre(
            key=gre_spec.get("key"),
            seq=gre_spec.get("seq"),
            checksum=gre_spec.get("checksum", False),
        )
        if "ethernet" in gre_spec:
            # TEB: inner spec includes an Ethernet layer
            b, _ = _apply_spec_to_builder(b, gre_spec, packet_num)
        else:
            # IP-in-GRE or nested GRE: no inner Ethernet
            b = _apply_ip_chain(b, gre_spec, packet_num)
        return b, False

    b = _dispatch_transport(b, proto_lower, spec.get("transport", {}), packet_num)
    b = _apply_payload_spec(b, spec.get("payload", {}), packet_num)
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


def _cmd_sanitise(args: argparse.Namespace) -> None:
    try:
        with open(args.input) as f:
            config = json.load(f)
    except OSError as e:
        print(f"Error reading '{args.input}': {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in '{args.input}': {e}", file=sys.stderr)
        sys.exit(1)

    opts = SanitiseOptions(
        ips=not args.no_ips,
        macs=not args.no_macs,
        ports=args.ports,
        payload=args.payload,
        timestamps=args.timestamps,
    )

    try:
        result = sanitise(config, opts)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    output_str = json.dumps(result, indent=2)

    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(output_str)
                f.write("\n")
        except OSError as e:
            print(f"Error writing '{args.output}': {e}", file=sys.stderr)
            sys.exit(1)
        print(f"Wrote sanitised config to {args.output}")
    else:
        print(output_str)


# ── stream config-file support ────────────────────────────────────────────────

# Maps config-file key → (argparse dest attr, type converter).
# Keys use underscores; values are cast with the given callable.
_STREAM_CONFIG_KEYS: dict[str, tuple[str, type]] = {
    "client_ip":          ("client_ip",               str),
    "server_ip":          ("server_ip",               str),
    "client_port":        ("client_port",             int),
    "server_port":        ("server_port",             int),
    "client_mac":         ("client_mac",              str),
    "server_mac":         ("server_mac",              str),
    "packets":            ("packets",                 int),
    "min_payload":        ("min_payload",             int),
    "max_payload":        ("max_payload",             int),
    "distribution":       ("distribution",            str),
    "ttl":                ("ttl",                     int),
    "window":             ("window",                  int),
    "gap":                ("gap",                     float),
    "gap_jitter":         ("gap_jitter",              float),
    "psh_probability":    ("psh_probability",         float),
    "packet_loss":                ("packet_loss_probability",    float),
    "retransmission_probability":   ("retransmission_probability",   float),
    "retransmission_timeout":       ("retransmission_timeout",       float),
    "payload_corruption_probability": ("payload_corruption_probability", float),
    "server_rst_probability":         ("server_rst_probability",         float),
    "rst_propagation_delay":          ("rst_propagation_delay",          float),
    "middlebox_mtu":                  ("middlebox_mtu",                  int),
    "stray_packet_count":             ("stray_packet_count",             int),
    "stray_timing_window":            ("stray_timing_window",            int),
    "no_ethernet":                ("no_ethernet",                bool),
    "pcap":               ("pcap",                    str),
    "pcapng":             ("pcapng",                  str),
}

_STREAM_DEFAULTS = {
    "client_port":             54321,
    "server_port":             80,
    "client_mac":              "00:00:00:00:00:01",
    "server_mac":              "00:00:00:00:00:02",
    "packets":                 10,
    "min_payload":             40,
    "max_payload":             1460,
    "distribution":            "uniform",
    "ttl":                     64,
    "window":                  65535,
    "gap":                     0.001,
    "gap_jitter":              0.0,
    "psh_probability":         0.5,
    "packet_loss_probability":    0.0,
    "retransmission_probability":    0.0,
    "retransmission_timeout":        0.2,
    "payload_corruption_probability": 0.0,
    "server_rst_probability":         0.0,
    "rst_propagation_delay":          0.0,
    "middlebox_mtu":                  None,
    "stray_packet_count":             0,
    "stray_timing_window":            None,
    "no_ethernet":                False,
    "pcap":                    None,
    "pcapng":                  None,
}


def _load_stream_config(path: str) -> dict:
    """Parse *path* as a configparser INI file and return a dict of stream args.

    Raises ``SystemExit`` on any error (file not found, missing section,
    unknown key, or bad value type).
    """
    cp = configparser.ConfigParser()
    try:
        with open(path) as f:
            cp.read_file(f)
    except OSError as e:
        print(f"Error reading config file '{path}': {e}", file=sys.stderr)
        sys.exit(1)

    if "stream" not in cp:
        print(f"Error: config file '{path}' has no [stream] section", file=sys.stderr)
        sys.exit(1)

    section = cp["stream"]
    result = {}
    for key, raw in section.items():
        if key not in _STREAM_CONFIG_KEYS:
            print(f"Warning: unknown key '{key}' in config file '{path}' — ignored",
                  file=sys.stderr)
            continue
        dest, cast = _STREAM_CONFIG_KEYS[key]
        try:
            if cast is bool:
                value = cp.getboolean("stream", key)
            else:
                value = cast(raw)
        except (ValueError, configparser.Error):
            print(
                f"Error: invalid value for '{key}' in config file '{path}': {raw!r}",
                file=sys.stderr,
            )
            sys.exit(1)
        result[dest] = value
    return result


def _apply_stream_defaults(args: argparse.Namespace) -> None:
    """Fill *args* from config file (if given) then from built-in defaults.

    Called after ``parse_args()``.  Modifies *args* in place.
    """
    config: dict = {}
    if args.config:
        config = _load_stream_config(args.config)

    for dest, value in config.items():
        if getattr(args, dest, None) is None:
            setattr(args, dest, value)

    for dest, value in _STREAM_DEFAULTS.items():
        if getattr(args, dest, None) is None:
            setattr(args, dest, value)


def _cmd_stream(args: argparse.Namespace) -> None:
    _apply_stream_defaults(args)

    # Validate required fields that may come from CLI or config file
    missing = [f for f in ("client_ip", "server_ip") if not getattr(args, f, None)]
    if missing:
        print(
            f"Error: missing required option(s): {', '.join('--' + f.replace('_', '-') for f in missing)}. "
            "Provide them on the command line or in the config file.",
            file=sys.stderr,
        )
        sys.exit(1)
    if not args.pcap and not args.pcapng:
        print(
            "Error: one of --pcap or --pcapng is required (on the command line or in the config file).",
            file=sys.stderr,
        )
        sys.exit(1)
    if args.pcap and args.pcapng:
        print("Error: --pcap and --pcapng are mutually exclusive.", file=sys.stderr)
        sys.exit(1)

    try:
        stream = generate_tcp_stream(
            client_ip=args.client_ip,
            server_ip=args.server_ip,
            client_port=args.client_port,
            server_port=args.server_port,
            client_mac=args.client_mac,
            server_mac=args.server_mac,
            num_data_packets=args.packets,
            min_payload=args.min_payload,
            max_payload=args.max_payload,
            payload_distribution=args.distribution,
            ip_ttl=args.ttl,
            window=args.window,
            inter_packet_gap=args.gap,
            gap_jitter=args.gap_jitter,
            psh_probability=args.psh_probability,
            packet_loss_probability=args.packet_loss_probability,
            retransmission_probability=args.retransmission_probability,
            retransmission_timeout=args.retransmission_timeout,
            payload_corruption_probability=args.payload_corruption_probability,
            server_rst_probability=args.server_rst_probability,
            rst_propagation_delay=args.rst_propagation_delay,
            middlebox_mtu=args.middlebox_mtu,
            stray_packet_count=args.stray_packet_count,
            stray_timing_window=args.stray_timing_window,
            include_ethernet=not args.no_ethernet,
        )
    except (ValueError, OSError) as e:
        print(f"Error generating stream: {e}", file=sys.stderr)
        sys.exit(1)

    tuples = stream.to_pcap_tuples()
    link_type = LINKTYPE_RAW if args.no_ethernet else LINKTYPE_ETHERNET

    try:
        if args.pcap:
            write_pcap(tuples, path=args.pcap, link_type=link_type)
            print(f"Wrote {len(tuples)} packet(s) to {args.pcap} (link type: {link_type})")
        else:
            write_pcapng(tuples, path=args.pcapng, link_type=link_type)
            print(f"Wrote {len(tuples)} packet(s) to {args.pcapng} (link type: {link_type})")
    except OSError as e:
        print(f"Error writing output: {e}", file=sys.stderr)
        sys.exit(1)


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

    # ── sanitise subcommand ───────────────────────────────────────────────────
    san_parser = subparsers.add_parser(
        "sanitise",
        help="Replace sensitive fields in a JSON config with synthetic data",
        description=(
            "Replace sensitive fields (IP addresses, MACs, ports, payload, timestamps) "
            "in a JSON config with synthetic data drawn from IANA-reserved ranges. "
            "The same original value always maps to the same synthetic value, so the "
            "communication structure is preserved."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    san_parser.add_argument("input", metavar="FILE", help="Input JSON config file")
    san_parser.add_argument(
        "--output", "-o", metavar="FILE",
        help="Write sanitised JSON to FILE instead of stdout",
    )
    san_parser.add_argument(
        "--no-ips", action="store_true",
        help="Do not replace IP addresses (default: replaced)",
    )
    san_parser.add_argument(
        "--no-macs", action="store_true",
        help="Do not replace MAC addresses (default: replaced)",
    )
    san_parser.add_argument(
        "--ports", action="store_true",
        help="Replace TCP/UDP port numbers (default: kept)",
    )
    san_parser.add_argument(
        "--payload", action="store_true",
        help="Zero out payload data (default: kept)",
    )
    san_parser.add_argument(
        "--timestamps", action="store_true",
        help="Zero out packet timestamps (default: kept)",
    )
    san_parser.set_defaults(func=_cmd_sanitise)

    # ── stream subcommand ─────────────────────────────────────────────────────
    stream_parser = subparsers.add_parser(
        "stream",
        help="Generate a synthetic TCP stream",
        description=(
            "Generate a realistic TCP stream — three-way handshake, data transfer, "
            "and four-way teardown — and write it to a pcap or pcapng file. "
            "Sequence and acknowledgement numbers are computed correctly for all packets."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Config file (optional — CLI flags take precedence over config values)
    stream_parser.add_argument("--config", metavar="FILE",
                               help="INI config file with a [stream] section; CLI flags override file values")
    # Required endpoints (may also be provided via --config)
    stream_parser.add_argument("--client-ip", default=None, metavar="IP",
                               help="Client IP address (IPv4 or IPv6)")
    stream_parser.add_argument("--server-ip", default=None, metavar="IP",
                               help="Server IP address (same family as --client-ip)")
    # Optional endpoint fields
    stream_parser.add_argument("--client-port", type=int, default=None, metavar="PORT",
                               help="Client source port (default: 54321)")
    stream_parser.add_argument("--server-port", type=int, default=None, metavar="PORT",
                               help="Server destination port (default: 80)")
    stream_parser.add_argument("--client-mac", default=None, metavar="MAC",
                               help="Client MAC address (default: 00:00:00:00:00:01)")
    stream_parser.add_argument("--server-mac", default=None, metavar="MAC",
                               help="Server MAC address (default: 00:00:00:00:00:02)")
    # Stream shape
    stream_parser.add_argument("--packets", type=int, default=None, metavar="N",
                               help="Number of data packets sent by the client (default: 10)")
    stream_parser.add_argument("--min-payload", type=int, default=None, metavar="BYTES",
                               help="Minimum payload size in bytes (default: 40)")
    stream_parser.add_argument("--max-payload", type=int, default=None, metavar="BYTES",
                               help="Maximum payload size in bytes (default: 1460)")
    stream_parser.add_argument("--distribution", default=None,
                               choices=["uniform", "bimodal", "fixed"],
                               help="Payload size distribution (default: uniform)")
    # IP / TCP tuning
    stream_parser.add_argument("--ttl", type=int, default=None, metavar="N",
                               help="IP TTL / hop limit (default: 64)")
    stream_parser.add_argument("--window", type=int, default=None, metavar="BYTES",
                               help="TCP receive window size (default: 65535)")
    stream_parser.add_argument("--gap", type=float, default=None, metavar="SECONDS",
                               help="Inter-packet gap in seconds (default: 0.001)")
    stream_parser.add_argument("--gap-jitter", type=float, default=None, metavar="SECONDS",
                               help="Max additional delay per gap; each gap is drawn from [gap, gap+jitter] and packets are re-sorted by timestamp (default: 0.0)")
    stream_parser.add_argument("--psh-probability", type=float, default=None, metavar="PROB",
                               help="Probability (0.0-1.0) that PSH is set on each data segment (default: 0.5)")
    stream_parser.add_argument("--packet-loss", type=float, default=None, metavar="PROB",
                               dest="packet_loss_probability",
                               help="Probability (0.0-1.0) that any packet is dropped from the capture (default: 0.0)")
    stream_parser.add_argument("--retransmission-probability", type=float, default=None, metavar="PROB",
                               help="Probability (0.0-1.0) that each data segment gets a spurious retransmission (default: 0.0)")
    stream_parser.add_argument("--retransmission-timeout", type=float, default=None, metavar="SECONDS",
                               help="Seconds after original send that the retransmission timer fires (default: 0.2)")
    stream_parser.add_argument("--payload-corruption", type=float, default=None, metavar="PROB",
                               dest="payload_corruption_probability",
                               help="Probability (0.0-1.0) that each data segment's payload is corrupted in transit (default: 0.0)")
    stream_parser.add_argument("--server-rst", type=float, default=None, metavar="PROB",
                               dest="server_rst_probability",
                               help="Probability (0.0-1.0) that the server terminates mid-stream with a RST (default: 0.0)")
    stream_parser.add_argument("--rst-propagation-delay", type=float, default=None, metavar="SECONDS",
                               help="Seconds for the RST to reach the client; client sends data during this window (default: 0.0)")
    stream_parser.add_argument("--middlebox-mtu", type=int, default=None, metavar="BYTES",
                               help="Fragment packets as if they passed through a middlebox with this IP MTU (e.g. 576, 1280, 1400). Default: no fragmentation")
    stream_parser.add_argument("--stray-packets", type=int, default=None, metavar="N",
                               dest="stray_packet_count",
                               help="Number of forged TCP hijack packets to inject (default: 0)")
    stream_parser.add_argument("--stray-timing-window", type=int, default=None, metavar="N",
                               dest="stray_timing_window",
                               help="Constrain each stray packet timestamp to within N packets of its reference DATA packet (default: full data-transfer window)")
    stream_parser.add_argument("--no-ethernet", action="store_true", default=False,
                               help="Omit Ethernet headers (write raw IP packets)")
    # Output (may also be provided via --config; mutual exclusivity enforced in _cmd_stream)
    stream_parser.add_argument("--pcap", default=None, metavar="FILE",
                               help="Write to a libpcap (.pcap) file")
    stream_parser.add_argument("--pcapng", default=None, metavar="FILE",
                               help="Write to a pcapng (.pcapng) file")
    stream_parser.set_defaults(func=_cmd_stream)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
