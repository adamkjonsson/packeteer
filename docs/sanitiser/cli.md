# `packeteer sanitise` — CLI

```
packeteer sanitise <FILE> [--output <output.json>]
                          [--pcap <output.pcap>] [--pcapng <output.pcapng>]
                          [--no-ips] [--no-macs]
                          [--ports] [--payload] [--timestamps]
                          [--dns-ids] [--dhcp-xids]
```

`FILE` may be a JSON packet spec **or** a pcap/pcapng capture file.  When a
capture file is given, it is parsed automatically before sanitising — no
separate `packeteer parse` step is needed.  The file type is detected from its
magic number, not its extension.

## Options

| Flag | Effect |
|------|--------|
| `--output FILE` / `-o FILE` | Write sanitised packet spec (JSON) to FILE (default: stdout) |
| `--pcap FILE` | Build sanitised packets and write to a libpcap file |
| `--pcapng FILE` | Build sanitised packets and write to a pcapng file |
| `--no-ips` | Keep original IP addresses |
| `--no-macs` | Keep original MAC addresses |
| `--ports` | Replace TCP/UDP port numbers |
| `--payload` | Zero out payload bytes |
| `--timestamps` | Zero out packet timestamps |
| `--dns-ids` | Zero out DNS transaction IDs (default: kept) |
| `--dhcp-xids` | Zero out DHCP transaction IDs / `xid` fields (default: kept) |

`--output`, `--pcap`, and `--pcapng` are independent and may be combined.
When none are given the sanitised packet spec is printed to stdout.

## DHCP sanitisation

DHCP IP fields and the client hardware address are sanitised automatically
whenever a `dhcp` section is present — no extra flag is needed.  The
following replacements are applied:

- **Fixed IP fields** — `ciaddr`, `yiaddr`, `siaddr`, `giaddr` (skipped when
  `"0.0.0.0"`).
- **Client hardware address** (`chaddr`) — first six bytes treated as MAC;
  replaced consistently with other MAC addresses.  Pass `--no-macs` to keep
  it unchanged.
- **Option IPs** — subnet mask, requested IP, server ID, routers list, DNS
  servers list.  Pass `--no-ips` to keep all DHCP addresses unchanged.
- **Transaction ID** (`xid`) — kept by default; add `--dhcp-xids` to zero it.

## DNS sanitisation

DNS fields are sanitised automatically whenever a `dns` section is present —
no extra flag is needed.  The following replacements are applied:

- **Domain names** — every label in every name (questions, RR names, and
  name-bearing RDATA such as CNAME, NS, PTR, MX exchange, SOA mname/rname)
  is replaced with a consistent synthetic label of the form `label0`,
  `label1`, …  Labels are shared across all packets and sections, so
  `mail.example.com.` and `www.example.com.` will end up with the same
  synthetic parent labels.
- **A/AAAA RDATA addresses** — replaced using the same pool and mapping table
  as IP addresses in the `network` section, so a DNS A record for an address
  that also appears as an IP source or destination will always receive the
  same replacement.  Pass `--no-ips` to keep RDATA addresses unchanged.
- **Transaction IDs** — kept by default; add `--dns-ids` to zero them.

## Examples

One-step sanitise from a capture to a clean pcap:

```bash
packeteer sanitise capture.pcap --pcap clean.pcap
```

Sanitise a capture and produce both a clean pcap and a packet spec:

```bash
packeteer sanitise capture.pcap --pcap clean.pcap --output clean.json
```

Sanitise DNS traffic including transaction IDs:

```bash
packeteer sanitise dns-capture.pcap --dns-ids --pcap clean.pcap
```

Sanitise from a packet spec (classic two-step workflow):

```bash
packeteer parse capture.pcap --output capture.json
packeteer sanitise capture.json --output clean.json
packeteer build clean.json --pcap clean.pcap
```

Full sanitisation (replace everything), input from a capture file:

```bash
packeteer sanitise capture.pcap \
    --ports --payload --timestamps --dns-ids \
    --pcap fully-clean.pcap
```

Keep IPs, replace everything else:

```bash
packeteer sanitise capture.json \
    --no-ips --ports --payload --timestamps \
    --output clean.json
```
