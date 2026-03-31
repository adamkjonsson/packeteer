# Sanitising captures

The `sanitise` workflow lets you replace sensitive field values in a JSON
config with synthetic equivalents, then rebuild the pcap.  The result is a
structurally faithful capture that contains no real addressing information.

```
pcap  ──parse──▶  JSON  ──sanitise──▶  clean JSON  ──build──▶  clean pcap
```

---

## What gets replaced

| Field | Default | Notes |
|-------|---------|-------|
| IP `src` / `dst` | **on** | Replaced with RFC 5737 documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) for IPv4; 2001:db8::/32 for IPv6 |
| Ethernet `src_mac` / `dst_mac` | **on** | Replaced with locally-administered unicast addresses (02:00:00:xx:xx:xx) |
| TCP/UDP `src_port` / `dst_port` | off | Enable with `--ports` |
| `payload.data` | off | Enable with `--payload`; zeroed to same byte length |
| `metadata` timestamps | off | Enable with `--timestamps`; set to zero |

Replacements are **consistent within a single run**: the same original value
always produces the same synthetic value across all packets and all tunnel
nesting levels.  This means you can still trace which host communicated with
which — you just cannot tell who they really are.

---

## CLI

```
packeteer sanitise <input.json> [--output <output.json>]
                       [--no-ips] [--no-macs]
                       [--ports] [--payload] [--timestamps]
```

### Options

| Flag | Effect |
|------|--------|
| `--output FILE` / `-o FILE` | Write result to FILE (default: stdout) |
| `--no-ips` | Keep original IP addresses |
| `--no-macs` | Keep original MAC addresses |
| `--ports` | Replace port numbers |
| `--payload` | Zero out payload bytes |
| `--timestamps` | Zero out packet timestamps |

### Examples

Replace IPs and MACs only (defaults):

```bash
packeteer parse capture.pcap --output capture.json
packeteer sanitise capture.json --output clean.json
packeteer build clean.json --pcap clean.pcap
```

Full sanitisation (replace everything):

```bash
packeteer sanitise capture.json \
    --ports --payload --timestamps \
    --output fully-clean.json
```

Keep IPs, replace everything else:

```bash
packeteer sanitise capture.json \
    --no-ips --ports --payload --timestamps \
    --output clean.json
```

---

## Python API

```python
from replacer import sanitise, SanitiseOptions

with open("capture.json") as f:
    config = json.load(f)

# Default: replace IPs and MACs
clean = sanitise(config)

# Replace everything
clean = sanitise(config, SanitiseOptions(
    ports=True,
    payload=True,
    timestamps=True,
))

# Replace only IPs, keep MACs
clean = sanitise(config, SanitiseOptions(macs=False))
```

```{eval-rst}
.. autoclass:: replacer.SanitiseOptions
   :members:
```

```{eval-rst}
.. autofunction:: replacer.sanitise
```

---

## Tunnel handling

Nested tunnel specs (`ipip`, `gre`, `etherip`) are walked recursively.  The
same mapping table is shared across all nesting levels, so an IP address that
appears as both an outer tunnel endpoint and an inner address will always
receive the same synthetic replacement.

Example — GRE tunnel before and after sanitising:

**Before:**
```json
{
  "network": { "src": "203.0.113.5", "dst": "203.0.113.10", "protocol": "gre" },
  "gre": {
    "network": { "src": "10.0.1.1", "dst": "10.0.1.2", "protocol": "tcp" },
    "transport": { "src_port": 55123, "dst_port": 443 }
  }
}
```

**After** (`sanitise` with defaults):
```json
{
  "network": { "src": "192.0.2.1", "dst": "192.0.2.2", "protocol": "gre" },
  "gre": {
    "network": { "src": "192.0.2.3", "dst": "192.0.2.4", "protocol": "tcp" },
    "transport": { "src_port": 55123, "dst_port": 443 }
  }
}
```

Ports are unchanged because `--ports` was not given.

---

## What is NOT changed

- Protocol names (`tcp`, `udp`, `gre`, …)
- TCP flags, window size, sequence numbers, TTL, DSCP/TOS
- VLAN IDs, MPLS labels, GRE keys
- Packet count and order
- `file_metadata` block

Checksums are not stored in the JSON config — they are always recomputed from
scratch when the config is rebuilt with `packeteer build`.
