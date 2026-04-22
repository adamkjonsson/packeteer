# packeteer sanitise

```
packeteer sanitise <FILE> [--output FILE] [--pcap FILE] [--pcapng FILE]
                          [--no-ips] [--no-macs]
                          [--ports] [--payload] [--timestamps]
                          [--dns-ids] [--dhcp-xids] [--http-headers]
```

Replaces sensitive field values with synthetic equivalents, producing a
structurally faithful capture that contains no real addressing information.

`FILE` may be a JSON packet spec **or** a pcap/pcapng capture file.  When a
capture is given it is parsed automatically — no separate `packeteer parse`
step is needed.  The file type is detected from its magic number, not its
extension.

## Output options

`--output`, `--pcap`, and `--pcapng` are independent and may be combined.
When none are given, the sanitised packet spec is printed to stdout.

| Flag | Effect |
|------|--------|
| `--output FILE` / `-o FILE` | Write sanitised packet spec (JSON) to FILE |
| `--pcap FILE` | Build sanitised packets and write to a libpcap file |
| `--pcapng FILE` | Build sanitised packets and write to a pcapng file |

## What gets replaced

| Field | Default | Flag to change |
|-------|---------|----------------|
| IP `src` / `dst` | **replaced** | `--no-ips` to keep |
| Ethernet `src_mac` / `dst_mac` | **replaced** | `--no-macs` to keep |
| TCP/UDP port numbers | kept | `--ports` to replace |
| `payload.data` | kept | `--payload` to zero (same byte length) |
| `packet_metadata` timestamps | kept | `--timestamps` to zero |
| DNS transaction IDs | kept | `--dns-ids` to zero |
| DHCP transaction IDs (`xid`) | kept | `--dhcp-xids` to zero |
| Sensitive HTTP header values | kept | `--http-headers` to redact |

Replacements are **consistent within a single run**: the same original value
always maps to the same synthetic value across all packets and tunnel nesting
levels.

## What is never changed

Protocol names, TCP flags, window size, sequence numbers, TTL, DSCP, VLAN
IDs, MPLS labels, GRE keys, packet count and order.

## Application-layer sanitisation

**DNS** — applied automatically when a `dns` section is present.  Domain name
labels are replaced consistently (`label0`, `label1`, …); A/AAAA RDATA
addresses use the same replacement pool as IP headers.

**DHCP** — applied automatically when a `dhcp` section is present.  IP fields
(`ciaddr`, `yiaddr`, `siaddr`, `giaddr`) and `chaddr` (MAC portion) are
replaced.

**HTTP** — header values are kept by default.  Add `--http-headers` to redact
the values of `Host`, `Cookie`, `Set-Cookie`, `Authorization`, `Location`,
`Referer`, and `Origin`.

## Examples

**One step from capture to clean pcap:**

```bash
packeteer sanitise capture.pcap --pcap clean.pcap
```

**Produce both a clean pcap and a packet spec:**

```bash
packeteer sanitise capture.pcap --pcap clean.pcap --output clean.json
```

**Sanitise with ports and payload zeroed:**

```bash
packeteer sanitise capture.pcap --ports --payload --pcap clean.pcap
```

**Sanitise DNS traffic including transaction IDs:**

```bash
packeteer sanitise dns-capture.pcap --dns-ids --pcap clean.pcap
```

**Redact sensitive HTTP headers:**

```bash
packeteer sanitise http-capture.pcap --http-headers --pcap clean.pcap
```

**Classic three-step workflow from packet spec:**

```bash
packeteer parse capture.pcap --output raw.json
packeteer sanitise raw.json --output clean.json
packeteer build clean.json --pcap clean.pcap
```
