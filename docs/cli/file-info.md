# packeteer file-info

```
packeteer file-info <capture> [--json] [--link-type TYPE] [--no-auto-link-type]
```

Reads a pcap or pcapng file and prints a summary of its contents: the packet
count, the number of directional sessions (unique 5-tuples), and per-protocol-layer
statistics.  By default the report is human-readable text; add `--json` for a
machine-readable version.

This is a read-only reporting command — it never modifies the capture.

## Arguments

| Argument | Description |
|----------|-------------|
| `capture` | *(required)* Path to a `.pcap` or `.pcapng` file |
| `--json` | Emit the report as JSON instead of human-readable text |
| `--link-type TYPE` | Force the link-layer type, disabling auto-detection (`ethernet`, `raw`, or an integer) |
| `--no-auto-link-type` | Trust the file header's link-layer type instead of auto-detecting |

## What gets reported

| Field | Meaning |
|-------|---------|
| Packets | Total number of packet records in the file |
| Sessions | Number of unique **directional** 5-tuples `(src, dst, src_port, dst_port, protocol)`.  `A→B` and `B→A` count as two sessions.  Only packets with an IP layer contribute; portless protocols (ICMP, GRE) use empty ports |
| Duration | Wall-clock span between the first and last packet timestamp (omitted for fewer than two packets) |
| Layers | For each protocol layer seen, the number of packets containing it and the percentage of all packets |

Layer statistics cover the outermost layers of each packet: `ethernet`, `vlan`,
`mpls`, `pppoe`, `ipv4`, `ipv6`, `ipip`, `gre`, `etherip`, `pseudowire`, `tcp`,
`udp`, `icmp`, `icmpv6`, `sctp`, `dns`, `dhcp`, `http`, and `payload`.

## Link-type auto-correction

The link-layer type recorded in a capture's header drives parsing.  Some
captures declare the wrong value, which would otherwise produce garbage.  By
default `file-info` scores the declared type against the supported alternatives
(`ethernet` and `raw`) by measuring how many packets parse to a valid IP header,
and uses whichever is cleanest.

The heuristic is conservative: an alternative is adopted only when it parses
meaningfully better than the declared type **and** the declared type already
looks like garbage.  Unusual-but-valid or non-IP captures (e.g. ARP-only) are
left on their declared type.

When auto-correction changes the link type, the report notes it:

```
Link-type: raw (101)  [auto-corrected from ethernet (1)]
```

Pass `--link-type` to force a specific type (which disables auto-detection), or
`--no-auto-link-type` to always trust the file header.

## Examples

**Print a text summary:**

```bash
packeteer file-info capture.pcap
```

```
File:      capture.pcap
Type:      pcap
Link-type: ethernet (1)
Packets:   1240
Sessions:  87  (directional 5-tuples)
Duration:  42.531000 s
Layers:
  ethernet      1240  (100.0%)
  ipv4          1212  ( 97.7%)
  tcp            980  ( 79.0%)
  udp            232  ( 18.7%)
  dns            120  (  9.7%)
  payload        870  ( 70.2%)
```

**Machine-readable output:**

```bash
packeteer file-info capture.pcap --json
```

**Inspect a capture with a wrong link-type, forcing raw IP:**

```bash
packeteer file-info capture.pcap --link-type raw
```

## Python API

The same information is available from {func}`packeteer.parse.info.pcap_info`,
which returns a {class}`~packeteer.parse.info.PcapInfo` dataclass:

```python
from packeteer.parse import pcap_info, format_pcap_info

info = pcap_info(path="capture.pcap")
print(info.packet_count, info.session_count)
print(info.layer_counts)

# Render the same text report the CLI prints:
print(format_pcap_info(info))
```
