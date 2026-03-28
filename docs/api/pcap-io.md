# PCAP I/O

Functions and dataclasses for reading and writing libpcap (`.pcap`) and
pcapng (`.pcapng`) files.  Both formats are detected automatically on read.

---

## Writing

```{eval-rst}
.. autofunction:: packet_generator.pcap.write_pcap
```

```{eval-rst}
.. autofunction:: packet_generator.pcap.write_pcapng
```

---

## Reading

```{eval-rst}
.. autofunction:: packet_parser.pcap.read_pcap
```

```{eval-rst}
.. autoclass:: packet_parser.pcap.PcapFile
   :members:
```

```{eval-rst}
.. autoclass:: packet_parser.pcap.PcapFileHeader
   :members:
```

---

## Link-layer type constants

| Constant | Value | Description |
|----------|-------|-------------|
| `LINKTYPE_ETHERNET` | `1` | Ethernet II — use when packets include an Ethernet header |
| `LINKTYPE_RAW` | `101` | Raw IP — use for packets with no Ethernet header |

Both constants are exported from `packet_generator.pcap` and re-exported
from `packet_generator`.
