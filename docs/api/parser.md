# Parser

`packet_parser` decodes raw bytes back into the same header dataclasses used
by {doc}`../api/header-dataclasses`.  The high-level entry points are
{func}`~packet_parser.parser.parse_packet` and
{func}`~packet_parser.parser.parse_pcap_file`.

---

## High-level interface

```{eval-rst}
.. autoclass:: packet_parser.parser.ParsedPacket
   :members:
```

```{eval-rst}
.. autofunction:: packet_parser.parser.parse_packet
```

```{eval-rst}
.. autofunction:: packet_parser.parser.parse_pcap_packet
```

```{eval-rst}
.. autofunction:: packet_parser.parser.parse_pcap_file
```

---

## Config serialisation

These functions convert {class}`~packet_parser.parser.ParsedPacket` objects
(or individual header dataclasses) into the JSON config dict format consumed
by `packet_lab.py build`.

```{eval-rst}
.. autofunction:: packet_parser.to_config.update_config
```

```{eval-rst}
.. autofunction:: packet_parser.to_config.to_json_config
```

```{eval-rst}
.. autofunction:: packet_parser.to_config.to_json_string
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
| `ethernet_packet_parser` | `packet_parser.ethernet` | `EthernetHeader` |
| `mpls_packet_parser` | `packet_parser.mpls` | `MPLSLabel` |
| `pppoe_packet_parser` | `packet_parser.pppoe` | `PPPoEHeader` |
| `ip_packet_parser` | `packet_parser.ip` | `IPHeader` / `IPv6Header` |
| `tcp_packet_parser` | `packet_parser.tcp` | `TCPHeader` |
| `udp_packet_parser` | `packet_parser.udp` | `UDPHeader` |
| `icmp_packet_parser` | `packet_parser.icmp` | `ICMPHeader` |
| `icmpv6_packet_parser` | `packet_parser.icmpv6` | `ICMPv6Header` |
| `etherip_packet_parser` | `packet_parser.etherip` | `EtherIPHeader` |
| `gre_packet_parser` | `packet_parser.gre` | `GREHeader` |

All names are exported from `packet_parser` (the top-level package).
