# packeteer

A pure-Python library for building, fragmenting, and parsing complete,
byte-accurate raw network packets. No external dependencies — Python 3.10+
and the standard library only.

## Features

- **Ethernet II** framing with configurable MACs and automatic EtherType
- **IEEE 802.1Q VLAN** tagging — single tag or QinQ (802.1ad) double-tagged
- **MPLS** label stacks (RFC 3032) — arbitrary depth, S bit set automatically
- **PPPoE** session and discovery frames (RFC 2516)
- **IPv4** (RFC 791) and **IPv6** (RFC 8200) with automatic header checksums
- **TCP** (RFC 9293), **UDP** (RFC 768), **ICMPv4** (RFC 792), **ICMPv6** (RFC 4443) with correct pseudo-header checksums
- **IP-in-IP** tunnels (RFC 2003 / RFC 4213) — no extra header bytes
- **EtherIP** tunnels (RFC 3378) — inner Ethernet frame inside IP
- **GRE** tunnels (RFC 2784 / RFC 2890) — optional Key, Sequence Number, and Checksum fields; TEB (Transparent Ethernet Bridging) supported
- **IPv4 and IPv6 fragmentation** (RFC 791 / RFC 8200 §4.5)
- **pcap and pcapng** file I/O — read and write with microsecond or nanosecond timestamps
- **TCP stream generation** — produce a complete connection (handshake, data, teardown) with correct sequence numbers and configurable payload distribution
- **CLI** (`packeteer`) — build packets from a JSON config, parse captures back to JSON, sanitise configs, or generate synthetic TCP streams

## In this documentation

```{toctree}
:maxdepth: 1

installation
quickstart
overview
sanitiser
cli
json-config
fragmentation
stream
api/index
reference/packet-sizes
reference/rfc-references
```
