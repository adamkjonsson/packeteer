#!/usr/bin/env python3
"""
Build and inspect raw network packets.

Examples:
  python cli.py --src 192.168.1.1 --dst 8.8.8.8 --protocol tcp --size 20
  python cli.py --src ::1 --dst ::2 --protocol udp --size 10
  python cli.py --src fe80::1 --dst fe80::2 --protocol icmpv6 --size 0 --no-ethernet
  python cli.py --src 10.0.0.1 --dst 10.0.0.2 --protocol icmp --size 4 --output packet.bin
  python cli.py --src 10.0.0.1 --dst 10.0.0.2 --protocol tcp --size 64 --pcap capture.pcap
  python cli.py --config packets.json
"""
import argparse
import json
import struct
import sys
import time
from packet_generator import PacketBuilder, Protocol

# PCAP link-layer types
_LINKTYPE_ETHERNET = 1    # Ethernet II (with header)
_LINKTYPE_RAW      = 101  # Raw IP (no Ethernet header)


def _write_pcap(
    f,
    packets: list[bytes],
    link_type: int,
    ts_sec: int | None = None,
    ts_usec: int = 0,
) -> None:
    """Write packets to *f* in libpcap format (little-endian, µs timestamps).

    Global header layout (24 bytes):
        magic (4) | major (2) | minor (2) | thiszone (4) |
        sigfigs (4) | snaplen (4) | network (4)

    Per-packet record (16 bytes + data):
        ts_sec (4) | ts_usec (4) | incl_len (4) | orig_len (4) | data
    """
    # Global header
    f.write(struct.pack(
        '<IHHiIII',
        0xA1B2C3D4,  # magic — little-endian, microsecond timestamps
        2, 4,        # version 2.4
        0,           # UTC (no timezone offset)
        0,           # timestamp accuracy (always 0)
        65535,       # snaplen
        link_type,
    ))
    if ts_sec is None:
        ts = time.time()
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
    for pkt in packets:
        length = len(pkt)
        f.write(struct.pack('<IIII', ts_sec, ts_usec, length, length))
        f.write(pkt)



def _run_multi_packet(cfg: dict) -> None:
    """Build and output all packets defined in a JSON config."""
    global_output = cfg.get("output", {})
    pcap_path = global_output.get("pcap")
    file_path = global_output.get("file")

    if pcap_path and file_path:
        print("Error: output.pcap and output.file are mutually exclusive", file=sys.stderr)
        sys.exit(1)

    if "packets" not in cfg:
        print("Error: config file must have a top-level 'packets' array", file=sys.stderr)
        sys.exit(1)

    specs = cfg["packets"]
    if not specs:
        print("Error: 'packets' array is empty", file=sys.stderr)
        sys.exit(1)

    # Use LINKTYPE_RAW only when every packet disables ethernet
    all_no_eth = all(not spec.get("ethernet", {}).get("enabled", True) for spec in specs)
    link_type = _LINKTYPE_RAW if all_no_eth else _LINKTYPE_ETHERNET

    # collected: list of (pkt_bytes, ts_sec | None, ts_usec)
    collected: list[tuple[bytes, int | None, int]] = []

    for i, spec in enumerate(specs, 1):
        net = spec.get("network", {})
        src = net.get("src")
        dst = net.get("dst")
        protocol_str = net.get("protocol")

        if not src or not dst or not protocol_str:
            print(
                f"Error: packet {i} missing network.src, network.dst, or network.protocol",
                file=sys.stderr,
            )
            sys.exit(1)

        try:
            proto = Protocol[protocol_str.upper()]
        except KeyError:
            print(f"Error: packet {i} unknown protocol '{protocol_str}'", file=sys.stderr)
            sys.exit(1)

        eth = spec.get("ethernet", {})
        vlan = eth.get("vlan", {})
        transport = spec.get("transport", {})
        payload_spec = spec.get("payload", {})
        out = spec.get("output", {})

        explicit_payload: bytes | None = None
        if "data" in payload_spec:
            try:
                explicit_payload = bytes.fromhex(payload_spec["data"])
            except ValueError as e:
                print(f"Error: packet {i} payload.data is not valid hex: {e}", file=sys.stderr)
                sys.exit(1)

        try:
            builder = PacketBuilder(
                src_ip=src,
                dst_ip=dst,
                protocol=proto,
                payload_size=payload_spec.get("size", 0),
                payload=explicit_payload,
                src_mac=eth.get("src_mac", "00:00:00:00:00:01"),
                dst_mac=eth.get("dst_mac", "00:00:00:00:00:02"),
                src_port=transport.get("src_port", 12345),
                dst_port=transport.get("dst_port", 80),
                ttl=net.get("ttl", 64),
                include_ethernet=eth.get("enabled", True),
                tcp_seq=transport.get("seq", 0),
                vlan_id=vlan.get("id"),
                vlan_pcp=vlan.get("pcp", 0),
                vlan_dei=vlan.get("dei", 0),
            )
            mtu = out.get("mtu")
            pkts = builder.fragment(mtu=mtu) if mtu is not None else [builder.build()]
        except (OSError, ValueError) as e:
            print(f"Error building packet {i}: {e}", file=sys.stderr)
            sys.exit(1)

        ts_sec: int | None = out.get("timestamp_s")
        ts_usec: int = out.get("timestamp_us", 0)
        for pkt in pkts:
            collected.append((pkt, ts_sec, ts_usec))

    if pcap_path:
        # Resolve None timestamps to the current time, consistent within this call
        now: tuple[int, int] | None = None
        with open(pcap_path, "wb") as f:
            f.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type))
            for pkt, ts_sec, ts_usec in collected:
                if ts_sec is None:
                    if now is None:
                        t = time.time()
                        now = (int(t), int((t - int(t)) * 1_000_000))
                    sec, usec = now
                else:
                    sec, usec = ts_sec, ts_usec
                length = len(pkt)
                f.write(struct.pack('<IIII', sec, usec, length, length))
                f.write(pkt)
        print(f"Wrote {len(collected)} packet(s) to {pcap_path} (link type: {link_type})")
    elif file_path:
        with open(file_path, "wb") as f:
            for pkt, _, _ in collected:
                f.write(pkt)
        total = sum(len(p) for p, _, _ in collected)
        print(f"Wrote {len(collected)} packet(s) ({total} bytes total) to {file_path}")
    else:
        for idx, (pkt, _, _) in enumerate(collected):
            print(f"Packet {idx + 1}/{len(collected)} ({len(pkt)} bytes):")
            for i in range(0, len(pkt), 16):
                chunk = pkt[i:i + 16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                print(f"  {i:04x}  {hex_part}")


def main():
    parser = argparse.ArgumentParser(
        description="Build a raw network packet (Ethernet + IP + transport + payload)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--config", metavar="FILE", help="JSON config file with a 'packets' array; builds all packets and writes to the configured output")
    parser.add_argument("--src", help="Source IP address (IPv4 or IPv6)")
    parser.add_argument("--dst", help="Destination IP address (IPv4 or IPv6)")
    parser.add_argument(
        "--protocol",
        choices=["tcp", "udp", "icmp", "icmpv6"],
        help="Transport protocol",
    )
    parser.add_argument("--size", type=int, default=0, help="Payload size in bytes (default: 0)")
    parser.add_argument(
        "--payload-data", metavar="HEX",
        help="Explicit payload as a hex string (e.g. 48656c6c6f); overrides --size",
    )
    parser.add_argument("--src-port", type=int, default=12345, help="Source port (TCP/UDP)")
    parser.add_argument("--dst-port", type=int, default=80, help="Destination port (TCP/UDP)")
    parser.add_argument("--tcp-seq", type=int, default=0, help="TCP sequence number (default: 0)")
    parser.add_argument(
        "--vlan-id", type=int, default=None,
        help="IEEE 802.1Q VLAN ID (1–4094). Adds a 4-byte 802.1Q tag to the Ethernet header.",
    )
    parser.add_argument("--vlan-pcp", type=int, default=0, help="VLAN Priority Code Point 0–7 (default: 0)")
    parser.add_argument("--vlan-dei", type=int, default=0, help="VLAN Drop Eligible Indicator 0 or 1 (default: 0)")
    parser.add_argument("--src-mac", default="00:00:00:00:00:01", help="Source MAC address")
    parser.add_argument("--dst-mac", default="00:00:00:00:00:02", help="Destination MAC address")
    parser.add_argument("--ttl", type=int, default=64, help="TTL / Hop Limit (default: 64)")
    parser.add_argument("--no-ethernet", action="store_true", help="Omit Ethernet header")
    parser.add_argument(
        "--mtu", type=int, default=None,
        help=(
            "Fragment the packet so each IP datagram is at most MTU bytes "
            "(excludes Ethernet header). Common values: 1500 (Ethernet), "
            "576 (IPv4 minimum, RFC 791), 1280 (IPv6 minimum, RFC 8200)."
        ),
    )
    parser.add_argument("--output", help="Write raw bytes to file (default: print hex to stdout)")
    parser.add_argument("--pcap", metavar="FILE", help="Write packets to a libpcap (.pcap) file")
    parser.add_argument(
        "--timestamp-s", type=int, default=None, metavar="SEC",
        help="Capture timestamp seconds (ts_sec in pcap record; default: current time)",
    )
    parser.add_argument(
        "--timestamp-us", type=int, default=0, metavar="USEC",
        help="Capture timestamp microseconds fraction 0–999999 (ts_usec in pcap record; default: 0)",
    )

    # Pre-parse to detect --config before full argument parsing
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--config", metavar="FILE")
    pre_args, _ = pre_parser.parse_known_args()

    if pre_args.config:
        try:
            with open(pre_args.config) as f:
                raw_cfg = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"Error loading config '{pre_args.config}': {e}", file=sys.stderr)
            sys.exit(1)
        _run_multi_packet(raw_cfg)
        return

    args = parser.parse_args()

    if not args.src or not args.dst or not args.protocol:
        parser.error("--src, --dst, and --protocol are required (or provide them via --config)")

    if args.output and args.pcap:
        print("Error: --output and --pcap are mutually exclusive", file=sys.stderr)
        sys.exit(1)

    try:
        proto = Protocol[args.protocol.upper()]
    except KeyError:
        print(f"Unknown protocol: {args.protocol}", file=sys.stderr)
        sys.exit(1)

    explicit_payload: bytes | None = None
    if args.payload_data is not None:
        try:
            explicit_payload = bytes.fromhex(args.payload_data)
        except ValueError as e:
            print(f"Error: --payload-data is not valid hex: {e}", file=sys.stderr)
            sys.exit(1)

    try:
        builder = PacketBuilder(
            src_ip=args.src,
            dst_ip=args.dst,
            protocol=proto,
            payload_size=args.size,
            payload=explicit_payload,
            src_mac=args.src_mac,
            dst_mac=args.dst_mac,
            src_port=args.src_port,
            dst_port=args.dst_port,
            ttl=args.ttl,
            include_ethernet=not args.no_ethernet,
            tcp_seq=args.tcp_seq,
            vlan_id=args.vlan_id,
            vlan_pcp=args.vlan_pcp,
            vlan_dei=args.vlan_dei,
        )
        if args.mtu is not None:
            packets = builder.fragment(mtu=args.mtu)
        else:
            packets = [builder.build()]
    except (OSError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.pcap:
        link_type = _LINKTYPE_RAW if args.no_ethernet else _LINKTYPE_ETHERNET
        with open(args.pcap, "wb") as f:
            _write_pcap(f, packets, link_type, ts_sec=args.timestamp_s, ts_usec=args.timestamp_us)
        print(f"Wrote {len(packets)} packet(s) to {args.pcap} (link type: {link_type})")
    elif args.output:
        with open(args.output, "wb") as f:
            for pkt in packets:
                f.write(pkt)
        total = sum(len(p) for p in packets)
        if len(packets) > 1:
            print(f"Wrote {len(packets)} fragments ({total} bytes total) to {args.output}")
        else:
            print(f"Wrote {total} bytes to {args.output}")
    else:
        for idx, pkt in enumerate(packets):
            if len(packets) > 1:
                print(f"Fragment {idx + 1}/{len(packets)} ({len(pkt)} bytes):")
            else:
                print(f"Packet ({len(pkt)} bytes):")
            for i in range(0, len(pkt), 16):
                chunk = pkt[i:i + 16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                print(f"  {i:04x}  {hex_part}")


if __name__ == "__main__":
    main()
