# PCAP I/O

Functions and dataclasses for reading and writing libpcap (`.pcap`) and
pcapng (`.pcapng`) files.  Both formats are detected automatically on read.

---

## Writing

```{eval-rst}
.. autofunction:: packeteer.generator.pcap.write_pcap
```

```{eval-rst}
.. autofunction:: packeteer.generator.pcap.write_pcapng
```

---

## Reading

```{eval-rst}
.. autofunction:: packeteer.parser.pcap.read_pcap
```

```{eval-rst}
.. autoclass:: packeteer.parser.pcap.PcapFile
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.parser.pcap.PcapFileHeader
   :members:
```

---

## Link-layer type constants

| Constant | Value | Description |
|----------|-------|-------------|
| `LINKTYPE_ETHERNET` | `1` | Ethernet II — use when packets include an Ethernet header |
| `LINKTYPE_RAW` | `101` | Raw IP — use for packets with no Ethernet header |

Both constants are exported from `packeteer.generator.pcap` and re-exported
from `packeteer.generator`.
