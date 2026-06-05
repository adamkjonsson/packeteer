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

## Capture summary

{func}`~packeteer.parse.info.pcap_info` reports on a whole capture — packet
count, the number of directional sessions (unique 5-tuples), and per-layer
statistics — and auto-corrects a wrong link-layer type.  It powers the
`packeteer file-info` command.  {func}`~packeteer.parse.info.format_pcap_info`
renders the same human-readable report the CLI prints.

```{eval-rst}
.. autofunction:: packeteer.parse.info.pcap_info
```

```{eval-rst}
.. autoclass:: packeteer.parse.info.PcapInfo
   :members:
```

```{eval-rst}
.. autofunction:: packeteer.parse.info.format_pcap_info
```

---

## Unsupported IP protocol numbers

packeteer recognises the following IP protocol numbers at the transport layer:
TCP (6), UDP (17), ICMPv4 (1), ICMPv6 (58), SCTP (132), GRE (47), EtherIP
(97), and IP-in-IP (4 / 41).  When a packet carries any other protocol number,
two things happen:

1. **An {class}`~packeteer.parse.core.UnsupportedIPProtocolWarning` is
   emitted** — a `UserWarning` subclass whose `.protocol` attribute holds the
   unrecognised number.  The bytes following the IP header are stored in
   {attr}`~packeteer.parse.core.ParsedPacket.payload`.

   When calling {func}`~packeteer.parse.core.parse_packet` directly you get
   one warning per call:

   ```python
   import warnings
   from packeteer.parse import parse_packet, UnsupportedIPProtocolWarning
   from packeteer.pcap import LINKTYPE_RAW

   with warnings.catch_warnings(record=True) as caught:
       warnings.simplefilter("always")
       pkt = parse_packet(ospf_raw_bytes, link_type=LINKTYPE_RAW)

   print(caught[0].message.protocol)  # 89
   print(pkt.transport)               # None
   print(pkt.payload.hex())           # raw bytes after the IP header
   ```

   When calling {func}`~packeteer.parse.core.parse_pcap_file` (including via
   `packeteer parse` and `packeteer sanitise`), per-packet warnings are
   consolidated into **one summary warning per unique protocol**, with the
   packet count and file path included:

   ```
   UserWarning: IP protocol 89 is not supported; encountered in 47 packets
   in 'capture.pcap'. Bytes after each IP header are stored in the payload field.
   ```

2. **The packet spec `"protocol"` field is the raw integer** — when
   {func}`~packeteer.parse.to_config.update_config` serialises an IP header
   with an unknown protocol, it emits the numeric value instead of a name
   string:

   ```json
   { "network": { "src": "10.0.0.1", "dst": "224.0.0.5", "protocol": 89, "ttl": 1 } }
   ```

   Known protocols always produce a string (`"tcp"`, `"udp"`, etc.).

```{eval-rst}
.. autoclass:: packeteer.parse.core.UnsupportedIPProtocolWarning
   :members:
```

To suppress the warning for protocols you intentionally ignore:

```python
import warnings
from packeteer.parse import UnsupportedIPProtocolWarning

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=UnsupportedIPProtocolWarning)
    pkt = parse_packet(data)
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
