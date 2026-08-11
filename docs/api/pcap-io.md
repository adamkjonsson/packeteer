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

## Streaming

`read_pcap` materialises every packet in a list.  `open_pcap` reads the same
files one record at a time, so a capture larger than memory can be processed,
and each record carries its byte offset within the file.

Because records are decoded as they are iterated, the reader holds the file
open — it is the one object in this module with a lifetime to manage.  Use a
`with` block, or call `close()` from a `finally`:

```python
with open_pcap(path="capture.pcap") as reader:
    for record in reader:
        ...
```

A reader opened from a `path` closes that file; one given a `file_object`
never closes it.  Exhausting the records does not close the file, and neither
does an error raised during iteration — see
[Closing the reader](../guide/pcap.md#closing-the-reader) in the guide.

```{eval-rst}
.. autofunction:: packeteer.pcap.open_pcap
```

```{eval-rst}
.. autoclass:: packeteer.pcap.PcapReader
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.pcap.PcapRecord
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
