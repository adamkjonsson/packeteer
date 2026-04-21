# `packeteer parse` — CLI

```
packeteer parse <capture> [--output FILE]
                          [--proto PROTO] [--port PORTS] [--src-port PORTS] [--dst-port PORTS]
                          [--src ADDR] [--dst ADDR] [--host ADDR] [--app APP]
```

Reads every packet in a pcap or pcapng file, decodes each one through all
recognised protocol layers, and writes a packet spec to stdout or a file.  The
file format (pcap vs. pcapng, microsecond vs. nanosecond timestamps) is
auto-detected from the first four bytes — no flags or file extensions required.

The produced JSON is directly replayable with `packeteer build` and editable
by hand or programmatically before rebuilding.

## Arguments

| Argument | Description |
|----------|-------------|
| `capture` | *(required)* Path to a `.pcap` or `.pcapng` file |
| `--output FILE` / `-o FILE` | Write JSON to FILE instead of printing to stdout |

## Filtering

`packeteer parse` can discard unwanted packets during parsing so that only the
traffic you care about appears in the output.  All filter flags are optional and
are **AND-combined** — a packet must satisfy every flag you supply to be kept.

### Filter flags

| Flag | Argument | Description |
|------|----------|-------------|
| `--proto` | `PROTO` | IP protocol name: `tcp`, `udp`, `sctp`, `icmp`, `icmpv6` |
| `--port` | `PORTS` | Source-**or**-destination port; comma-separated for multiple values |
| `--src-port` | `PORTS` | Source port only |
| `--dst-port` | `PORTS` | Destination port only |
| `--src` | `ADDR` | Source IP address or CIDR prefix |
| `--dst` | `ADDR` | Destination IP address or CIDR prefix |
| `--host` | `ADDR` | Source-**or**-destination IP address or CIDR prefix |
| `--app` | `APP` | Application layer present: `dns`, `dhcp`, or `http` |

### Negation with `!`

Prefix any value with `!` to negate the criterion — keeping packets that do
**not** match instead of those that do:

```bash
# Keep all packets except TCP
packeteer parse capture.pcap --proto '!tcp'

# Keep all packets except those to/from port 80
packeteer parse capture.pcap --port '!80'
```

For comma-separated lists, all values must be consistently positive or
consistently negative:

```bash
# Keep packets with destination port 80 or 443
packeteer parse capture.pcap --dst-port 80,443

# Keep packets whose destination port is neither 80 nor 443
packeteer parse capture.pcap --dst-port '!80,!443'
```

Mixing positive and negative values in the same list (e.g. `80,!443`) is an
error.

### Address and CIDR matching

`--src`, `--dst`, and `--host` accept any IPv4 or IPv6 address, or a CIDR
prefix.  A host address without a prefix length is treated as a /32 (IPv4) or
/128 (IPv6) and matches only that exact address:

```bash
# Source is anywhere in 10.0.0.0/8
packeteer parse capture.pcap --src 10.0.0.0/8

# Destination is not in the RFC 1918 private range
packeteer parse capture.pcap --dst '!192.168.0.0/16'

# Either endpoint is an IPv6 documentation address
packeteer parse capture.pcap --host 2001:db8::/32
```

### Tunnelled packets

For tunnelled packets (GRE, EtherIP, IP-in-IP), filtering is applied to the
**outer** layer only.  The inner IP addresses and ports inside a tunnel are not
inspected by the filter.

### Examples

**Extract only DNS traffic:**

```bash
packeteer parse capture.pcap --app dns
```

**Extract HTTP and HTTPS:**

```bash
packeteer parse capture.pcap --proto tcp --port 80,443
```

**Extract traffic from a specific host:**

```bash
packeteer parse capture.pcap --host 192.168.1.100
```

**Extract all traffic within a subnet, excluding a noisy host:**

```bash
packeteer parse capture.pcap --src 10.0.0.0/24 --dst '!10.0.0.1'
```

**Extract TCP traffic to port 443 from a specific source subnet:**

```bash
packeteer parse capture.pcap --proto tcp --dst-port 443 --src 10.0.0.0/16
```

**Drop all ICMP and write the rest to a new pcap:**

```bash
packeteer parse capture.pcap --proto '!icmp' --output filtered.json
packeteer build filtered.json --pcap filtered.pcap
```

**Extract non-DNS UDP traffic:**

```bash
packeteer parse capture.pcap --proto udp --app '!dns'
```

## What gets parsed

Every packet is decoded layer by layer.  Recognised layers are written as
named keys in the per-packet JSON object:

| Detected layer | JSON key | Notes |
|----------------|----------|-------|
| Ethernet II | `ethernet` | Includes VLAN tag as `ethernet.vlan` when present |
| MPLS label stack | `mpls` | Array of entries, outermost first |
| PPPoE | `pppoe` | Discovery and session frames |
| IPv4 / IPv6 | `network` | Auto-detected from the IP version nibble |
| TCP | `transport` | Full header including options (MSS, window scale, SACK, timestamps) |
| UDP | `transport` | Ports and length |
| ICMP / ICMPv6 | `transport` | Type, code, identifier, sequence |
| SCTP | `transport` | Per-chunk objects with all fields |
| IP-in-IP | `ipip` | Inner spec nested recursively; no inner `ethernet` key |
| GRE | `gre` | Key, sequence, checksum flags preserved; TEB has inner `ethernet` |
| EtherIP | `etherip` | Inner Ethernet frame nested recursively |
| HTTP/1.x request or response | `http` | Parsed when transport is TCP on port 80 or 8080; see {doc}`../packet-spec/format` for the JSON schema |
| Payload | `payload` | Raw bytes encoded as a hex string |

Bytes that follow the last recognised header are captured in `payload.data`.
Unrecognised EtherTypes and IP protocol numbers stop layer parsing early —
remaining bytes go into `payload`.

Checksums are decoded from the wire but not stored in the JSON (they are
recomputed from scratch on rebuild).

## Output format

Each packet becomes one object in the top-level `"packets"` array.  A
`"packet_metadata"` object records the capture timestamp.  The top-level
`"metadata"` block is always present and always contains `"nanoseconds"`.
`"from_file"` and `"type"` are always present — auto-detected from the file
header:

```json
{
  "metadata": {
    "from_file": "capture.pcap",
    "type": "pcap",
    "nanoseconds": false
  },
  "packets": [
    {
      "ethernet": {
        "src_mac": "00:11:22:33:44:55",
        "dst_mac": "66:77:88:99:aa:bb",
        "enabled": true
      },
      "network": {
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "protocol": "tcp",
        "ttl": 64
      },
      "transport": {
        "src_port": 54321,
        "dst_port": 80,
        "seq": 3639743571,
        "ack": 0,
        "flags": 2,
        "window": 65535
      },
      "packet_metadata": {
        "timestamp_s": 1700000000,
        "timestamp_us": 123456
      }
    }
  ]
}
```

See {doc}`../packet-spec/format` for the complete field reference.

## Examples

**Print JSON to stdout:**

```bash
packeteer parse capture.pcap
```

**Save to a file:**

```bash
packeteer parse capture.pcap --output config.json
```

**Parse a pcapng file (auto-detected):**

```bash
packeteer parse capture.pcapng --output config.json
```

**Round-trip: parse → rebuild:**

```bash
packeteer parse capture.pcap --output config.json
packeteer build config.json --pcap replayed.pcap
```

**Parse → edit → rebuild:**

```bash
# Step 1: capture to JSON
packeteer parse capture.pcap --output config.json

# Step 2: edit config.json — change IPs, ports, payloads, add a VLAN tag, etc.

# Step 3: rebuild
packeteer build config.json --pcap modified.pcap
```

**Parse → sanitise → rebuild (shareable capture):**

```bash
packeteer parse capture.pcap --output raw.json
packeteer sanitise raw.json --ports --payload --output clean.json
packeteer build clean.json --pcap clean.pcap
```
