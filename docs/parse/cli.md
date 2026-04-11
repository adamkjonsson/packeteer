# `packeteer parse` — CLI

```
packeteer parse <capture> [--output FILE] [--replay-pcap FILE | --replay-pcapng FILE]
```

Reads every packet in a pcap or pcapng file, decodes each one through all
recognised protocol layers, and writes a JSON config to stdout or a file.  The
file format (pcap vs. pcapng, microsecond vs. nanosecond timestamps) is
auto-detected from the first four bytes — no flags or file extensions required.

The produced JSON is directly replayable with `packeteer build` and editable
by hand or programmatically before rebuilding.

## Arguments

| Argument | Description |
|----------|-------------|
| `capture` | *(required)* Path to a `.pcap` or `.pcapng` file |
| `--output FILE` / `-o FILE` | Write JSON to FILE instead of printing to stdout |
| `--replay-pcap FILE` | Add `"type": "pcap"` and `"from_file"` to the top-level `metadata` block |
| `--replay-pcapng FILE` | Add `"type": "pcapng"` and `"from_file"` to the top-level `metadata` block (mutually exclusive with `--replay-pcap`) |

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
`"from_file"` and `"type"` are added when `--replay-pcap` or `--replay-pcapng`
is given:

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

See {doc}`../json-config` for the complete field reference.

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
