# Sanitising Captures

The `sanitise` workflow lets you replace sensitive field values in a JSON
config with synthetic equivalents, then rebuild the pcap.  The result is a
structurally faithful capture that contains no real addressing information.

```
pcap  --parse--→  JSON  --sanitise--→  clean JSON  --build--→  clean pcap
```

## What gets replaced

| Field | Default | Notes |
|-------|---------|-------|
| IP `src` / `dst` | **on** | Replaced with RFC 5737 documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) for IPv4; 2001:db8::/32 for IPv6 |
| Ethernet `src_mac` / `dst_mac` | **on** | Replaced with locally-administered unicast addresses (02:00:00:xx:xx:xx) |
| TCP/UDP `src_port` / `dst_port` | off | Enable with `--ports` |
| `payload.data` | off | Enable with `--payload`; zeroed to same byte length |
| `packet_metadata` timestamps | off | Enable with `--timestamps`; set to zero |

Replacements are **consistent within a single run**: the same original value
always produces the same synthetic value across all packets and all tunnel
nesting levels.  This means you can still trace which host communicated with
which — you just cannot tell who they really are.

## What is NOT changed

- Protocol names (`tcp`, `udp`, `gre`, …)
- TCP flags, window size, sequence numbers, TTL, DSCP/TOS
- VLAN IDs, MPLS labels, GRE keys
- Packet count and order
- top-level `metadata` block

Checksums are not stored in the packet spec — they are always recomputed from
scratch when the config is rebuilt with `packeteer build`.

```{toctree}
:maxdepth: 1

cli
python-api
```
