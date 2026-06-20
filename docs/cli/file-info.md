# packeteer file-info

```
packeteer file-info <capture> [--json] [--num N]
                              [--link-type TYPE] [--no-auto-link-type]
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
| `--num N` / `-n N` | Analyse only the first `N` packets (reading stops early) |
| `--link-type TYPE` | Force the link-layer type, disabling auto-detection (`ethernet`, `raw`, or an integer) |
| `--no-auto-link-type` | Trust the file header's link-layer type instead of auto-detecting |

## What gets reported

| Field | Meaning |
|-------|---------|
| Packets | Total number of packet records in the file |
| Sessions | Number of unique **directional** 5-tuples `(src, dst, src_port, dst_port, protocol)`.  `A→B` and `B→A` count as two sessions.  Only packets with an IP layer contribute; portless protocols (ICMP, GRE) use empty ports |
| Duration | Wall-clock span between the first and last packet timestamp (omitted for fewer than two packets) |
| Layers | For each protocol layer seen, the number of packets containing it and the percentage of all packets |

Layer statistics cover the full protocol stack of each packet: `ethernet`,
`vlan`, `arp`, `mpls`, `pppoe`, `ipv4`, `ipv6`, `ipip`, `gre`, `etherip`,
`pseudowire`, `vxlan`, `geneve`, `gtpu`, `tcp`, `udp`, `icmp`, `icmpv6`, `sctp`,
`dns`, `dhcp`, `http`, and `payload`.

Tunnelled packets are reported comprehensively: the outer layers, the tunnel
type (`gre`, `etherip`, `ipip`, `pseudowire`, `vxlan`, `geneve`, `gtpu`), **and**
the inner frame's layers all contribute.  A layer that appears at more than one
depth in a single packet (for example the inner and outer IPv4 of a GTP-U
packet) counts that packet once.

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

## Limiting to the first N packets

`--num N` analyses only the first `N` packets.  Reading stops as soon as `N`
records have been collected, so the rest of the file is never loaded — this
makes the command fast even on multi-gigabyte captures.

This pairs naturally with link-type auto-correction: the true link-type can
usually be determined from a small sample, so a quick `--num` scan tells you
how to parse a large file without reading all of it.

```bash
packeteer file-info huge.pcap --num 100
```

Every figure in the report (packet count, sessions, layer stats, duration)
then reflects just that sample, and the packet line notes the cap:

```
Packets:   100  (limited to first 100)
```

(If the file holds fewer than `N` packets, the whole file is read and no cap
note is shown.)

## Malformed captures

A file that cannot be read as pcap/pcapng — bad magic number, short header, or a
truncated packet record — produces an error on stderr and a non-zero exit code.

A structurally valid file whose individual packets are garbage does not error:
undecodable packets are skipped, and the report reflects only what could be
parsed.  When none of the packets contain an IP layer, the text report ends with
a note, since that usually means the capture is corrupt or the link-type is
wrong:

```
Note: no packets contained an IP layer — the capture may be malformed or the
link-type wrong (try --link-type).
```

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

**Quickly determine the link-type of a huge capture from a small sample:**

```bash
packeteer file-info huge.pcap --num 100
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

# Analyse only the first 100 packets (reading stops early):
info = pcap_info(path="huge.pcap", num=100)
```

The underlying {func}`packeteer.pcap.read_pcap` also accepts a `max_packets`
argument, which stops reading after that many packet records.
