# packeteer build

```
packeteer build <spec.json> (--pcap FILE | --pcapng FILE)
```

Reads a packet spec file, assembles every packet described in it, and writes
the results to a pcap or pcapng file.  All checksums are recomputed
automatically.

## Arguments

| Argument | Description |
|----------|-------------|
| `spec.json` | JSON file with a top-level `"packets"` array |
| `--pcap FILE` | Write to a libpcap (`.pcap`) file |
| `--pcapng FILE` | Write to a pcapng (`.pcapng`) file |

`--pcap` and `--pcapng` are mutually exclusive; exactly one is required.

## Packet spec structure

Each element of the `"packets"` array describes one packet as a set of
protocol-layer objects.  Layers are specified outermost first; unused layers
are simply omitted.

```json
{
  "metadata": { "nanoseconds": false },
  "packets": [
    {
      "ethernet":       { "src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02" },
      "network":        { "src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "tcp", "ttl": 64 },
      "transport":      { "src_port": 54321, "dst_port": 80, "flags": 2 },
      "packet_metadata": { "timestamp_s": 1700000000, "timestamp_us": 0 }
    }
  ]
}
```

## Supported layers

| JSON key | Layer |
|----------|-------|
| `ethernet` | Ethernet II header |
| `mpls` | MPLS label stack — array of entries, outermost first |
| `pppoe` | PPPoE session or discovery frame |
| `network` | IPv4 or IPv6 — auto-detected from `src` address family |
| `transport` | TCP, UDP, ICMP, ICMPv6, or SCTP |
| `dns` | DNS message (RFC 1035) |
| `dhcp` | DHCP message (RFC 2131) |
| `http` | HTTP/1.x request or response (RFC 7230) |
| `etherip` | EtherIP tunnel inner frame (`network.protocol = "etherip"`) |
| `ipip` | IP-in-IP tunnel inner spec (`network.protocol = "ipip"`) |
| `gre` | GRE tunnel inner spec (`network.protocol = "gre"`) |
| `pseudowire` | RFC 4385 control word + inner frame; placed after `mpls`, no outer `network` key required |
| `payload` | Raw bytes — `"size"` for random, or `"data"` with optional `"encoding"` (`"hex"` default or `"utf8"`) |

See {doc}`../packet-spec/format` for the complete field reference for every
layer.

## IP fragmentation

Set `"mtu"` in a packet's `"packet_metadata"` to split it into IP fragments.
Each IP datagram (header + payload) will be at most `mtu` bytes.  The Ethernet
header is replicated on each fragment but does not count against the MTU.

```json
{
  "packet_metadata": { "timestamp_s": 0, "timestamp_us": 0, "mtu": 1500 }
}
```

IPv4 uses the Flags/Fragment Offset fields (RFC 791); IPv6 uses the Fragment
Extension Header (RFC 8200 §4.5).

## Examples

**Simple TCP SYN:**

```bash
cat > syn.json << 'EOF'
{
  "metadata": { "nanoseconds": false },
  "packets": [{
    "ethernet":       { "src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02" },
    "network":        { "src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "tcp" },
    "transport":      { "dst_port": 443, "flags": 2 },
    "packet_metadata": { "timestamp_s": 0, "timestamp_us": 0 }
  }]
}
EOF
packeteer build syn.json --pcap syn.pcap
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
      "network":   { "src": "192.168.1.1", "dst": "192.168.1.2", "protocol": "tcp" },
      "transport": { "dst_port": 80, "flags": 2 }
    },
    "packet_metadata": { "timestamp_s": 0, "timestamp_us": 0 }
  }]
}
```

**MPLS pseudowire (Ethernet over MPLS with RFC 4385 control word):**

```json
{
  "metadata": { "nanoseconds": false },
  "packets": [{
    "ethernet": { "src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02" },
    "mpls": [{ "label": 100, "ttl": 64 }],
    "pseudowire": {
      "sequence": 1,
      "ethernet": { "src_mac": "cc:dd:ee:00:00:01", "dst_mac": "cc:dd:ee:00:00:02" },
      "network":  { "src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "tcp" },
      "transport": { "dst_port": 80, "flags": 2 }
    },
    "packet_metadata": { "timestamp_s": 0, "timestamp_us": 0 }
  }]
}
```

**DNS query:**

```json
{
  "metadata": { "nanoseconds": false },
  "packets": [{
    "ethernet":  { "src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02" },
    "network":   { "src": "192.168.1.1", "dst": "8.8.8.8", "protocol": "udp" },
    "transport": { "src_port": 54321, "dst_port": 53 },
    "dns": {
      "id": 4660,
      "flags": { "qr": false, "rd": true },
      "questions": [{ "name": "example.com.", "qtype": 1, "qclass": 1 }],
      "answers": [], "authority": [], "additional": []
    },
    "packet_metadata": { "timestamp_s": 0, "timestamp_us": 0 }
  }]
}
```

**Parse → edit → rebuild:**

```bash
packeteer parse capture.pcap --output spec.json
# edit spec.json — change IPs, ports, payloads, add layers …
packeteer build spec.json --pcap modified.pcap
```
