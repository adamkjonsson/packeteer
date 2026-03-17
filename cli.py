#!/usr/bin/env python3
"""
Build and inspect raw network packets.

Examples:
  python cli.py --src 192.168.1.1 --dst 8.8.8.8 --protocol tcp --size 20
  python cli.py --src ::1 --dst ::2 --protocol udp --size 10
  python cli.py --src fe80::1 --dst fe80::2 --protocol icmpv6 --size 0 --no-ethernet
  python cli.py --src 10.0.0.1 --dst 10.0.0.2 --protocol icmp --size 4 --output packet.bin
"""
import argparse
import sys
from packet_generator import PacketBuilder, Protocol


def main():
    parser = argparse.ArgumentParser(
        description="Build a raw network packet (Ethernet + IP + transport + payload)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--src", required=True, help="Source IP address (IPv4 or IPv6)")
    parser.add_argument("--dst", required=True, help="Destination IP address (IPv4 or IPv6)")
    parser.add_argument(
        "--protocol", required=True,
        choices=["tcp", "udp", "icmp", "icmpv6"],
        help="Transport protocol",
    )
    parser.add_argument("--size", type=int, default=0, help="Payload size in bytes (default: 0)")
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
    args = parser.parse_args()

    try:
        proto = Protocol[args.protocol.upper()]
    except KeyError:
        print(f"Unknown protocol: {args.protocol}", file=sys.stderr)
        sys.exit(1)

    try:
        builder = PacketBuilder(
            src_ip=args.src,
            dst_ip=args.dst,
            protocol=proto,
            payload_size=args.size,
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

    if args.output:
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
