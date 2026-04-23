# Sanitising Captures

Before sharing a pcap — with a vendor, in a bug report, or as test data — you
usually want to remove real IP addresses, MAC addresses, and other identifying
information while keeping the packet structure intact.
{func}`packeteer.sanitise.sanitise` does this consistently: the same original
value always maps to the same synthetic replacement within a single run, so
flow relationships are preserved.

## One-step sanitise from a capture file

The `packeteer sanitise` command handles the parse → sanitise → write pipeline
in a single step.  For the equivalent in Python, parse the file first, then
sanitise the resulting packet spec dict:

```python
import json
from packeteer.parse import parse_pcap_file
from packeteer.sanitise import sanitise

spec = json.loads(parse_pcap_file(path="capture.pcap"))
clean = sanitise(spec)

with open("clean.json", "w") as f:
    json.dump(clean, f, indent=2)
```

## Default behaviour

By default `sanitise` replaces IP addresses and MAC addresses; everything else
is kept:

| Field | Default |
|-------|---------|
| IP `src` / `dst` | replaced with synthetic RFC 5737 addresses |
| Ethernet `src_mac` / `dst_mac` | replaced with synthetic MACs |
| Ports, payload, timestamps | unchanged |
| DNS names and addresses | replaced automatically when `dns` section present |
| DHCP IPs and client MAC | replaced automatically when `dhcp` section present |
| HTTP header values | unchanged |

## Enabling optional replacements

Pass a {class}`packeteer.sanitise.SanitiseOptions` instance to control what
gets replaced:

```python
from packeteer.sanitise import sanitise, SanitiseOptions

# Zero port numbers too
clean = sanitise(spec, SanitiseOptions(ports=True))

# Zero payload bytes (same length preserved)
clean = sanitise(spec, SanitiseOptions(payload=True))

# Zero all timestamps
clean = sanitise(spec, SanitiseOptions(timestamps=True))

# Redact sensitive HTTP header values
clean = sanitise(spec, SanitiseOptions(http_headers=True))

# Zero DNS transaction IDs
clean = sanitise(spec, SanitiseOptions(dns_ids=True))

# Keep IPs; replace everything else
clean = sanitise(spec, SanitiseOptions(ips=False))
```

Options combine freely:

```python
clean = sanitise(spec, SanitiseOptions(
    ports=True,
    payload=True,
    timestamps=True,
))
```

## Writing the sanitised spec

After sanitising, write the packet spec to JSON and then pass it to
`packeteer build` to produce a pcap:

```python
import json
from packeteer.parse import parse_pcap_file
from packeteer.sanitise import sanitise

spec = json.loads(parse_pcap_file(path="capture.pcap"))
clean = sanitise(spec)

with open("clean.json", "w") as f:
    json.dump(clean, f, indent=2)
```

```bash
packeteer build clean.json --pcap clean.pcap
```

Or run the whole pipeline in one CLI step:

```bash
packeteer sanitise capture.pcap --pcap clean.pcap
```

## Application-layer sanitisation

**DNS** — sanitised automatically when a `dns` section is present.  Domain
name labels are replaced consistently (`label0`, `label1`, …), and A/AAAA
RDATA addresses share the same replacement pool as network-layer IPs.
Transaction IDs are kept by default; set `dns_ids=True` to zero them.

**DHCP** — sanitised automatically when a `dhcp` section is present.  The IP
fields (`ciaddr`, `yiaddr`, `siaddr`, `giaddr`) and the client hardware
address (`chaddr`) are replaced using the same mapping tables as all other
IP and MAC fields.

**HTTP** — header values are kept by default.  Set `http_headers=True` to
redact the values of `Host`, `Cookie`, `Set-Cookie`, `Authorization`,
`Location`, `Referer`, and `Origin`.  The header keys and non-sensitive headers
are always kept unchanged.

## Tunnel handling

Nested tunnel specs (`gre`, `ipip`, `etherip`, `pseudowire`) are walked
recursively.  The same mapping tables are shared at all nesting levels, so an
IP address that appears as both an outer tunnel endpoint and an inner address
will always receive the same synthetic replacement.

## Post-filtering with PacketFilter

You can combine sanitisation with filtering to produce a clean, focused
subset of a capture:

```python
import json
from packeteer.filter import PacketFilter
from packeteer.parse import parse_pcap_file
from packeteer.sanitise import sanitise

spec = json.loads(parse_pcap_file(
    path="capture.pcap",
    packet_filter=PacketFilter(proto="tcp", dst_port=["443"]),
))
clean = sanitise(spec, SanitiseOptions(ports=True))
```

## Next steps

- {doc}`generating` — create synthetic captures from scratch
- {doc}`../api/sanitiser` — full `SanitiseOptions` parameter reference
