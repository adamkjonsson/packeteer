# Reading and Writing pcap Files

All pcap I/O lives in {mod}`packeteer.pcap`.  The module handles both libpcap
(`.pcap`) and pcapng (`.pcapng`) formats, with microsecond and nanosecond
timestamp variants detected automatically on read.

## Writing a pcap file

{func}`packeteer.pcap.write_pcap` takes a sequence of `(raw_bytes, ts_sec,
ts_usec)` tuples and writes them to a libpcap file.  The `to_pcap_tuples()`
method on any stream object produces this format:

```python
from packeteer.generate import TCPSession
from packeteer.pcap import write_pcap

stream = (TCPSession(client_ip="10.0.0.1", server_ip="10.0.0.2")
    .send(b"hello")
    .build()
)
write_pcap(stream.to_pcap_tuples(), path="out.pcap")
```

Pass `nanoseconds=True` for nanosecond-precision timestamps:

```python
write_pcap(stream.to_pcap_tuples(), path="out.pcap", nanoseconds=True)
```

Use {func}`packeteer.pcap.write_pcapng` to write the pcapng format instead.
The calling convention is identical:

```python
from packeteer.pcap import write_pcapng

write_pcapng(stream.to_pcap_tuples(), path="out.pcapng")
```

You can also write a list of raw `bytes` objects directly — supply timestamps
of `(0, 0)` if they don't matter:

```python
from packeteer.generate import PacketBuilder, TCP_SYN
from packeteer.pcap import write_pcap

pkts = [
    (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
        .tcp(dst_port=80, flags=TCP_SYN).build(),
     0, 0),
]
write_pcap(pkts, path="syn.pcap")
```

### Timestamps from `datetime` objects

pcap records store time as a `(ts_sec, ts_frac)` pair, but you will often have
timestamps as {class}`datetime.datetime` objects.  Use
{func}`packeteer.pcap.datetime_to_pcap_ts` to convert — unpack its result
straight into the tuple:

```python
from datetime import datetime, timezone
from packeteer.pcap import write_pcap, datetime_to_pcap_ts

when = datetime(2024, 1, 1, 12, 0, 0, 500_000, tzinfo=timezone.utc)
write_pcap([(raw, *datetime_to_pcap_ts(when))], path="out.pcap")
```

A naive datetime (no `tzinfo`) is assumed to be UTC, matching the pcap
convention.  Pass `nanoseconds=True` to both the converter and the writer for a
nanosecond-resolution file — though note `datetime` only has microsecond
resolution, so the nanosecond part is always a multiple of 1000:

```python
write_pcap(
    [(raw, *datetime_to_pcap_ts(when, nanoseconds=True))],
    path="out.pcap", nanoseconds=True,
)
```

## Reading a pcap file

{func}`packeteer.pcap.read_pcap` reads a libpcap or pcapng file and returns a
{class}`packeteer.pcap.PcapFile` object.  The file type and timestamp precision
are detected from the file header — no flags needed:

```python
from packeteer.pcap import read_pcap

pcap = read_pcap(path="capture.pcap")
print(pcap.header.nanoseconds)   # True / False
print(len(pcap.packets))         # number of records
```

Each element of `pcap.packets` is a `(data, ts_sec, ts_frac)` tuple.  Iterate
and parse with {func}`packeteer.parse.core.parse_pcap_packet`:

```python
from packeteer.parse import parse_pcap_packet

for record in pcap.packets:
    pkt = parse_pcap_packet(record, pcap.header)
    if pkt.ip is not None:
        print(pkt.ip.src, "->", pkt.ip.dst)
```

To turn a record's timestamp back into a {class}`datetime.datetime`, use
{func}`packeteer.pcap.pcap_ts_to_datetime` (the inverse of
`datetime_to_pcap_ts`).  It returns a timezone-aware UTC datetime; pass
`nanoseconds=` from the file header so the fraction is interpreted correctly:

```python
from packeteer.pcap import pcap_ts_to_datetime

for data, ts_sec, ts_frac in pcap.packets:
    when = pcap_ts_to_datetime(ts_sec, ts_frac, nanoseconds=pcap.header.nanoseconds)
    print(when.isoformat())
```

## Link-layer type constants

Some APIs require a link-layer type constant to know whether packets start with
an Ethernet header:

| Constant | Value | When to use |
|----------|-------|-------------|
| `LINKTYPE_ETHERNET` | `1` | Packets include an Ethernet II header |
| `LINKTYPE_RAW` | `101` | Packets start directly with an IP header |

```python
from packeteer.pcap import LINKTYPE_ETHERNET, LINKTYPE_RAW
from packeteer.parse import parse_packet

# Packet with Ethernet header
pkt = parse_packet(raw, link_type=LINKTYPE_ETHERNET)

# Raw IP packet (no Ethernet)
pkt = parse_packet(raw, link_type=LINKTYPE_RAW)
```

The `link_type` field on `PcapFileHeader` tells you which to use for packets
read from a file:

```python
pcap = read_pcap(path="capture.pcap")
print(pcap.header.link_type)   # 1 for Ethernet, 101 for raw IP
```

### Overriding a wrong link-layer type

Some captures declare the wrong link type in their header, which drives
incorrect parsing.  Pass `link_type` to `read_pcap` to override the recorded
value — the returned `PcapFileHeader` reflects the override, so everything
downstream parses with the corrected type:

```python
from packeteer.pcap import read_pcap, LINKTYPE_RAW

pcap = read_pcap(path="capture.pcap", link_type=LINKTYPE_RAW)
print(pcap.header.link_type)   # 101, regardless of what the header said
```

{func}`packeteer.parse.core.parse_pcap_file` accepts the same `link_type`
keyword and forwards it to `read_pcap`.

## Next steps

- {doc}`parsing` — decode packets into typed dataclasses
- {doc}`../api/pcap-io` — full `write_pcap`, `write_pcapng`, and `read_pcap`
  parameter reference
