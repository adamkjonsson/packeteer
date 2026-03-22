#!/usr/bin/env python3
"""
Parse a pcap file and produce a JSON config that can be replayed with build_cli.py.

Examples:
  python parse_cli.py capture.pcap
  python parse_cli.py capture.pcap --output replay.json
  python parse_cli.py capture.pcap --output replay.json --replay-pcap replayed.pcap
  python parse_cli.py capture.pcap --replay-pcap replayed.pcap | python build_cli.py --config /dev/stdin
"""
import argparse
import sys

from packet_parser.parser import parse_pcap_file


def main():
    parser = argparse.ArgumentParser(
        description="Parse a pcap file and produce a JSON config for build_cli.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "pcap",
        metavar="FILE",
        help="Input pcap file to parse",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write JSON config to FILE instead of stdout",
    )
    parser.add_argument(
        "--replay-pcap",
        metavar="FILE",
        help="Set output.pcap in the generated config to FILE, "
             "so the config can be replayed directly with build_cli.py --config",
    )

    args = parser.parse_args()

    output_block = {}
    if args.replay_pcap:
        output_block["pcap"] = args.replay_pcap

    try:
        json_str = parse_pcap_file(
            path=args.pcap,
            output=output_block or None,
        )
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


if __name__ == "__main__":
    main()
