# Parser

**Import:** All classes and functions on this page are exported from `packeteer.parse`, e.g. `from packeteer.parse import parse_packet, ParsedPacket, update_config, ethernet_packet_parser`.

`packeteer.parse` decodes raw bytes back into the same header dataclasses used
by {doc}`../api/header-dataclasses`.  The high-level entry points are
{func}`~packeteer.parse.core.parse_packet` and
{func}`~packeteer.parse.core.parse_pcap_file`.

---

## High-level interface

```{eval-rst}
.. autoclass:: packeteer.parse.core.ParsedPacket
   :members:
```

```{eval-rst}
.. autofunction:: packeteer.parse.core.parse_packet
```

```{eval-rst}
.. autofunction:: packeteer.parse.core.parse_pcap_packet
```

```{eval-rst}
.. autofunction:: packeteer.parse.core.parse_pcap_file
```

---

## Packet spec serialisation

These functions convert {class}`~packeteer.parse.core.ParsedPacket` objects
(or individual header dataclasses) into the packet spec dict format consumed
by `packeteer build`.

```{eval-rst}
.. autofunction:: packeteer.parse.to_config.update_config
```

```{eval-rst}
.. autofunction:: packeteer.parse.to_config.apply_tunneled
```

```{eval-rst}
.. autofunction:: packeteer.parse.to_config.to_packet_spec
```

```{eval-rst}
.. autofunction:: packeteer.parse.to_config.to_json_string
```

---

## Per-protocol parser functions

Each parser follows the same convention:

```python
def packet_parser(data: bytes) -> tuple[int, int | None, HeaderType | None]:
    ...
```

| Return position | Type | Meaning |
|-----------------|------|---------|
| `[0]` | `int` | Bytes consumed.  `0` means parse failed. |
| `[1]` | `int \| None` | Next-layer identifier (EtherType, IP protocol number, …) |
| `[2]` | dataclass \| `None` | Parsed header object, or `None` on failure |

| Imported name | Module | Header type |
|---------------|--------|-------------|
| `ethernet_packet_parser` | `packeteer.parse.ethernet` | `EthernetHeader` |
| `mpls_packet_parser` | `packeteer.parse.mpls` | `MPLSLabel` |
| `pppoe_packet_parser` | `packeteer.parse.pppoe` | `PPPoEHeader` |
| `ip_packet_parser` | `packeteer.parse.ip` | `IPHeader` / `IPv6Header` |
| `tcp_packet_parser` | `packeteer.parse.tcp` | `TCPHeader` |
| `udp_packet_parser` | `packeteer.parse.udp` | `UDPHeader` |
| `icmp_packet_parser` | `packeteer.parse.icmp` | `ICMPHeader` |
| `icmpv6_packet_parser` | `packeteer.parse.icmpv6` | `ICMPv6Header` |
| `etherip_packet_parser` | `packeteer.parse.etherip` | `EtherIPHeader` |
| `gre_packet_parser` | `packeteer.parse.gre` | `GREHeader` |

All names are exported from `packeteer.parse` (the top-level package).
