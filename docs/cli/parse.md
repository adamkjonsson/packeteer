# packeteer parse

```
packeteer parse <capture> [--output FILE] [--link-type TYPE]
                          [--proto PROTO] [--port PORTS] [--src-port PORTS] [--dst-port PORTS]
                          [--src ADDR] [--dst ADDR] [--host ADDR] [--app APP]
```

Reads every packet in a pcap or pcapng file, decodes each one through all
recognised protocol layers, and writes a packet spec to stdout or a file.  The
file format (pcap vs. pcapng, microsecond vs. nanosecond timestamps) is
auto-detected from the first four bytes — no flags or extensions required.

The packet spec is directly replayable with `packeteer build` and editable
by hand or programmatically before rebuilding.

## Arguments

| Argument | Description |
|----------|-------------|
| `capture` | *(required)* Path to a `.pcap` or `.pcapng` file |
| `--output FILE` / `-o FILE` | Write packet spec to FILE instead of stdout |
| `--link-type TYPE` | Override the link-layer type in the file header (see below) |

### Overriding the link-layer type

The link-layer type recorded in a capture's header drives layer selection —
`ethernet` (`1`) parses an Ethernet header first, `raw` (`101`) treats the
packet as raw IP with no Ethernet header.  Some captures declare the wrong
value, which produces garbled output.  Pass `--link-type` to ignore the
header's value and parse with the type you specify:

```bash
packeteer parse capture.pcap --link-type raw
```

`TYPE` accepts the names `ethernet`, `raw`, `linux_sll` (Linux cooked v1),
`linux_sll2` (cooked v2), or any integer (e.g. `1`,
`101`).  The override also replaces `metadata.link_type` in the output, so the
resulting spec rebuilds with the corrected type.

## Filtering

All filter flags are optional and **AND-combined** — a packet must satisfy
every flag supplied to be kept.

| Flag | Argument | Description |
|------|----------|-------------|
| `--proto` | `PROTO` | IP protocol: `tcp`, `udp`, `sctp`, `icmp`, `icmpv6` |
| `--port` | `PORTS` | Source-**or**-destination port; comma-separated for multiple |
| `--src-port` | `PORTS` | Source port only |
| `--dst-port` | `PORTS` | Destination port only |
| `--src` | `ADDR` | Source IP address or CIDR prefix |
| `--dst` | `ADDR` | Destination IP address or CIDR prefix |
| `--host` | `ADDR` | Source-**or**-destination IP or CIDR prefix |
| `--app` | `APP` | Application layer present: `dns`, `dhcp`, or `http` |

Prefix any value with `!` to negate it — keeping packets that do **not**
match:

```bash
packeteer parse capture.pcap --proto '!tcp'
packeteer parse capture.pcap --dst-port '!80,!443'
```

`--src`, `--dst`, and `--host` accept IPv4/IPv6 addresses and CIDR prefixes.
For tunnelled packets (GRE, EtherIP, IP-in-IP, pseudowire, VXLAN, GENEVE,
GTP-U, IPsec AH/ESP), filtering applies to the outer layer only.

## What gets parsed

| Detected layer | JSON key | Notes |
|----------------|----------|-------|
| Ethernet II | `ethernet` | Includes VLAN tag as `ethernet.vlan` when present |
| Linux cooked (SLL/SLL2) | `sll` / `sll2` | `tcpdump -i any` pseudo header; the EtherType drives the rest, so IP/ARP/etc. decode as usual |
| ARP | `arp` | RFC 826 (IPv4 over Ethernet); operation + sender/target MAC and IP.  Terminal — no IP/transport |
| MPLS label stack | `mpls` | Array of entries, outermost first |
| PPPoE | `pppoe` | Discovery and session frames |
| IPv4 / IPv6 | `network` | Auto-detected from IP version nibble |
| TCP | `transport` | Full header including MSS, window scale, SACK, timestamps options |
| UDP | `transport` | Ports and length |
| ICMP / ICMPv6 | `transport` | Type, code, identifier, sequence |
| SCTP | `transport` | Per-chunk objects with all fields |
| IP-in-IP | `ipip` | Inner spec nested recursively |
| GRE | `gre` | Key, sequence, checksum flags preserved |
| EtherIP | `etherip` | Inner Ethernet frame nested recursively |
| VXLAN | `vxlan` | UDP port 4789; VNI plus inner Ethernet frame nested recursively |
| GENEVE | `geneve` | UDP port 6081; VNI, TLV options, plus inner frame (Ethernet or IP) nested recursively |
| GTP-U | `gtpu` | UDP port 2152; TEID, sequence/N-PDU, extension headers, plus the inner IP packet (G-PDU) nested recursively |
| IPsec AH | `ah` | IP protocol 51 (RFC 4302); SPI, sequence, ICV, plus the cleartext protected content (transport or inner IP) nested recursively |
| IPsec ESP | `esp` | IP protocol 50 (RFC 4303); SPI, sequence, and the remaining **opaque** (encrypted) payload — not decrypted |
| Pseudowire (RFC 4385) | `pseudowire` | Control word after MPLS BOS label; inner frame nested recursively |
| DNS | `dns` | UDP/TCP port 53 and 5353 (mDNS) |
| DHCP | `dhcp` | UDP ports 67 and 68 |
| HTTP/1.x | `http` | TCP ports 80 and 8080 |
| Payload | `payload` | Remaining bytes — hex string, or a UTF-8 string with `"encoding": "utf8"` for printable ASCII payloads |

Checksums are read from the wire but not stored; they are recomputed on
rebuild.

### Unsupported IP protocol numbers

If a packet carries an IP protocol number that is not in the table above,
`packeteer parse` prints a warning to stderr and continues.  The warning
is consolidated — one line per unique protocol number, with the count of
affected packets and the file name:

```
UserWarning: IP protocol 89 is not supported; encountered in 3 packets
in 'capture.pcap'. Bytes after each IP header are stored in the payload field.
```

Those packets still appear in the output.  The `network.protocol` field
contains the raw integer (`"protocol": 89`) instead of a name string, and
the bytes after the IP header are stored in `payload.data` (hex-encoded, since unsupported-protocol payloads are binary).

## Output format

The top-level `"metadata"` block is always present.  `"type"` (`"pcap"` or
`"pcapng"`), `"from_file"`, `"nanoseconds"`, and `"link_type"` are
auto-detected from the file header.

```json
{
  "metadata": {
    "from_file": "capture.pcap",
    "type": "pcap",
    "nanoseconds": false,
    "link_type": 1
  },
  "packets": [
    {
      "ethernet":  { "src_mac": "00:11:22:33:44:55", "dst_mac": "66:77:88:99:aa:bb", "enabled": true },
      "network":   { "src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "tcp", "ttl": 64 },
      "transport": { "src_port": 54321, "dst_port": 80, "seq": 1000, "ack": 0, "flags": 2, "window": 65535 },
      "packet_metadata": { "packet_num": 1, "timestamp_s": 1700000000, "timestamp_us": 123456 }
    }
  ]
}
```

See {doc}`../packet-spec/format` for the complete field reference.

## Examples

**Print packet spec to stdout:**

```bash
packeteer parse capture.pcap
```

**Save to a file:**

```bash
packeteer parse capture.pcap --output spec.json
```

**Extract only DNS traffic:**

```bash
packeteer parse capture.pcap --app dns --output dns.json
```

**Extract HTTP and HTTPS:**

```bash
packeteer parse capture.pcap --proto tcp --port 80,443
```

**Extract traffic from a specific subnet, excluding one host:**

```bash
packeteer parse capture.pcap --src 10.0.0.0/24 --dst '!10.0.0.1'
```

**Round-trip — parse then rebuild:**

```bash
packeteer parse capture.pcap --output spec.json
packeteer build spec.json --pcap replayed.pcap
```

**Parse → sanitise → rebuild:**

```bash
packeteer parse capture.pcap --output raw.json
packeteer sanitise raw.json --ports --payload --output clean.json
packeteer build clean.json --pcap clean.pcap
```
