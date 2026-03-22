#!/usr/bin/env python3
"""
Parse a pcap or pcapng file and produce a JSON config that can be replayed
with build_cli.py.  Both formats are accepted transparently.

Examples:
  python parse_cli.py capture.pcap
  python parse_cli.py capture.pcapng
  python parse_cli.py capture.pcap --output replay.json
  python parse_cli.py capture.pcap --output replay.json --replay-pcap replayed.pcap
  python parse_cli.py capture.pcapng --output replay.json --replay-pcapng replayed.pcapng
  python parse_cli.py capture.pcap --replay-pcap replayed.pcap | python build_cli.py --config /dev/stdin
"""
import argparse
import sys

from packet_parser.parser import parse_pcap_file


def main():
    parser = argparse.ArgumentParser(
        description="Parse a pcap or pcapng file and produce a JSON config for build_cli.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "pcap",
        metavar="FILE",
        help="Input .pcap or .pcapng file to parse",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write JSON config to FILE instead of stdout",
    )
    replay_group = parser.add_mutually_exclusive_group()
    replay_group.add_argument(
        "--replay-pcap",
        metavar="FILE",
        help="Set output.pcap in the generated config to FILE, "
             "so the config can be replayed directly with build_cli.py --config",
    )
    replay_group.add_argument(
        "--replay-pcapng",
        metavar="FILE",
        help="Set output.pcapng in the generated config to FILE, "
             "so the config can be replayed directly with build_cli.py --config",
    )

    args = parser.parse_args()

    output_block: dict = {"from_file": args.pcap}
    if args.replay_pcap:
        output_block["type"] = "pcap"
    elif args.replay_pcapng:
        output_block["type"] = "pcapng"

    try:
        json_str = parse_pcap_file(
            path=args.pcap,
            output=output_block,
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
