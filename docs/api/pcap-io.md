# PCAP I/O

Functions and dataclasses for reading and writing libpcap (`.pcap`) and
pcapng (`.pcapng`) files.  Both formats are detected automatically on read.

---

## Writing

```{eval-rst}
.. autofunction:: packeteer.pcap.write_pcap
```

```{eval-rst}
.. autofunction:: packeteer.pcap.write_pcapng
```

---

## Reading

```{eval-rst}
.. autofunction:: packeteer.pcap.read_pcap
```

```{eval-rst}
.. autoclass:: packeteer.pcap.PcapFile
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.pcap.PcapFileHeader
   :members:
```

---

## Timestamp conversion

`write_pcap` / `write_pcapng` take timestamps as a `(ts_sec, ts_frac)` pair and
`read_pcap` returns them the same way.  When you are working with
`datetime.datetime` objects, use these helpers to convert in either direction.
Naive datetimes are treated as UTC; `datetime` resolution is microseconds, so
nanosecond timestamps round-trip on a microsecond grid.

```{eval-rst}
.. autofunction:: packeteer.pcap.datetime_to_pcap_ts
```

```{eval-rst}
.. autofunction:: packeteer.pcap.pcap_ts_to_datetime
```

---

## Link-layer type constants

| Constant | Value | Description |
|----------|-------|-------------|
| `LINKTYPE_ETHERNET` | `1` | Ethernet II — use when packets include an Ethernet header |
| `LINKTYPE_RAW` | `101` | Raw IP — use for packets with no Ethernet header |
| `LINKTYPE_LINUX_SLL` | `113` | Linux "cooked" capture v1 (`tcpdump -i any`) |
| `LINKTYPE_LINUX_SLL2` | `276` | Linux "cooked" capture v2 (modern `-i any` default) |

All four constants live in `packeteer.pcap`.
