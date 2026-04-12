# `packeteer build` — CLI

```
packeteer build <config.json> (--pcap FILE | --pcapng FILE)
```

Reads a packet spec file, assembles every packet described in it, and writes
the results to a pcap or pcapng file.  All checksums are recomputed
automatically — you never need to calculate them by hand.

## Arguments

| Argument | Description |
|----------|-------------|
| `config.json` | JSON file with a top-level `"packets"` array |
| `--pcap FILE` | Write to a libpcap (`.pcap`) file |
| `--pcapng FILE` | Write to a pcapng (`.pcapng`) file |

`--pcap` and `--pcapng` are mutually exclusive; exactly one is required.

## packet spec structure

Each element of the `"packets"` array describes one packet as a set of
protocol-layer objects.  Layers are specified in order from outermost to
innermost; missing layers are simply omitted.

```json
{
  "metadata": { "nanoseconds": false },
  "packets": [
    {
      "ethernet":  { "src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02" },
      "network":   { "src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "tcp", "ttl": 64 },
      "transport": { "src_port": 54321, "dst_port": 80, "flags": 2 },
      "packet_metadata":  { "timestamp_s": 1700000000, "timestamp_us": 0 }
    }
  ]
}
```

The `"packet_metadata"` object carries the capture timestamp and an optional
`"mtu"` field for per-packet fragmentation (see {doc}`fragmentation`).

See {doc}`../packet-spec/format` for the complete field reference for every layer.

## Supported layers

Any combination of these layers can be stacked:

| JSON key | Layer |
|----------|-------|
| `ethernet` | Ethernet II header (MACs, optional VLAN tag) |
| `mpls` | MPLS label stack — array of entries, outermost first |
| `pppoe` | PPPoE session or discovery frame |
| `network` | IPv4 or IPv6 header — auto-detected from `src` |
| `transport` | TCP, UDP, ICMP, ICMPv6, or SCTP |
| `etherip` | EtherIP tunnel inner frame (set `network.protocol = "etherip"`) |
| `ipip` | IP-in-IP tunnel inner spec (set `network.protocol = "ipip"`) |
| `gre` | GRE tunnel inner spec (set `network.protocol = "gre"`) |
| `payload` | Raw payload — `"size"` (random bytes) or `"data"` (hex string) |

## Fragmentation

Set `"mtu"` in a packet's `"packet_metadata"` object to trigger IP
fragmentation.  The packet is split so that each IP datagram (header + payload)
is at most `mtu` bytes.  The Ethernet header, if present, is replicated on each
fragment but does not count against the MTU.

```json
{
  "metadata": { "nanoseconds": false },
  "packets": [
    {
      "ethernet":  { "src_mac": "aa:bb:cc:dd:ee:01", "dst_mac": "aa:bb:cc:dd:ee:02" },
      "network":   { "src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "udp" },
      "transport": { "dst_port": 5000 },
      "payload":   { "size": 4000 },
      "packet_metadata":  { "timestamp_s": 0, "timestamp_us": 0, "mtu": 1500 }
    }
  ]
}
```

IPv4 uses the Flags/Fragment Offset fields (RFC 791); IPv6 uses the Fragment
Extension Header (RFC 8200 §4.5).  See {doc}`fragmentation` for full details.

## Examples

**Simple TCP SYN:**

```bash
cat > syn.json << 'EOF'
{
  "metadata": { "nanoseconds": false },
  "packets": [{
    "ethernet":  { "src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02" },
    "network":   { "src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "tcp" },
    "transport": { "dst_port": 443, "flags": 2 },
    "packet_metadata":  { "timestamp_s": 0, "timestamp_us": 0 }
  }]
}
EOF
packeteer build syn.json --pcap syn.pcap
```

**IPv6 UDP with payload:**

```json
{
  "metadata": { "nanoseconds": false },
  "packets": [{
    "ethernet":  { "src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02" },
    "network":   { "src": "2001:db8::1", "dst": "2001:db8::2", "protocol": "udp" },
    "transport": { "dst_port": 5353 },
    "payload":   { "data": "48656c6c6f" },
    "packet_metadata":  { "timestamp_s": 0, "timestamp_us": 0 }
  }]
}
```

**MPLS label stack:**

```json
{
  "metadata": { "nanoseconds": false },
  "packets": [{
    "ethernet":  { "src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02" },
    "mpls":      [{ "label": 100, "ttl": 64 }, { "label": 200, "ttl": 64 }],
    "network":   { "src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "tcp" },
    "transport": { "dst_port": 80, "flags": 2 },
    "packet_metadata":  { "timestamp_s": 0, "timestamp_us": 0 }
  }]
}
```

**GRE tunnel:**

```json
{
  "metadata": { "nanoseconds": false },
  "packets": [{
    "ethernet": { "src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02" },
    "network":  { "src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "gre", "ttl": 64 },
    "gre": {
      "key": 12345,
      "network":   { "src": "192.168.1.1", "dst": "192.168.1.2", "protocol": "tcp", "ttl": 64 },
      "transport": { "dst_port": 80, "flags": 2 }
    },
    "packet_metadata": { "timestamp_s": 0, "timestamp_us": 0 }
  }]
}
```

**Multi-packet file with timestamps:**

```json
{
  "metadata": { "nanoseconds": false },
  "packets": [
    {
      "ethernet":  { "src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02" },
      "network":   { "src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "tcp" },
      "transport": { "dst_port": 80, "flags": 2, "seq": 1000 },
      "packet_metadata":  { "timestamp_s": 1700000000, "timestamp_us": 0 }
    },
    {
      "ethernet":  { "src_mac": "00:00:00:00:00:02", "dst_mac": "00:00:00:00:00:01" },
      "network":   { "src": "10.0.0.2", "dst": "10.0.0.1", "protocol": "tcp" },
      "transport": { "dst_port": 54321, "flags": 18, "seq": 5000, "ack": 1001 },
      "packet_metadata":  { "timestamp_s": 1700000000, "timestamp_us": 500 }
    }
  ]
}
```

**Parse → edit → rebuild workflow:**

```bash
# Capture live traffic and convert it to an editable config
packeteer parse capture.pcap --output config.json

# Edit config.json — change IPs, ports, payloads, add layers, etc.

# Rebuild the edited config as a new pcap
packeteer build config.json --pcap modified.pcap
```
