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
print(pcap.header.tick_hz)       # 1_000_000, 1_000_000_000, 1_000, …
print(pcap.header.nanoseconds)   # True / False
print(len(pcap.packets))         # number of records
```

### Streaming a large capture

`read_pcap` builds a list of every packet, so a multi-gigabyte capture costs
multi-gigabyte memory.  {func}`packeteer.pcap.open_pcap` reads the same files
record by record instead:

```python
from packeteer.pcap import open_pcap
from packeteer.parse import parse_packet

with open_pcap(path="huge.pcap") as reader:
    print(reader.header.link_type)          # available before the first record
    for record in reader:
        pkt = parse_packet(record.data, link_type=reader.header.link_type)
        ...
```

Each {class}`~packeteer.pcap.PcapRecord` also carries its position in the file:

```python
record.offset        # start of the record header / pcapng block
record.data_offset   # first captured packet byte — the offset to cite
record.orig_len      # on-wire length; > len(record.data) if snaplen-truncated
```

For classic pcap those offsets are derivable externally (a 24-byte global
header, then `16 + caplen` per record), but for pcapng they are not: blocks
are variable-length and option padding is invisible in the decoded data.
Reading them here is the only reliable way to refer to a byte range of the
capture afterwards.

The first three fields unpack like the tuples `read_pcap` returns, so existing
code moves over with little change:

```python
for data, ts_sec, ts_frac in reader:
    ...
```

### Closing the reader

`read_pcap` hands back a finished result and holds nothing open.  `open_pcap`
is different in kind: records are decoded lazily as you iterate, so the file
stays open until you close it, and **the reader is yours to close.**

Use it as a context manager and this takes care of itself:

```python
with open_pcap(path="huge.pcap") as reader:
    for record in reader:
        if record.ts_sec > deadline:
            break               # file is closed on the way out
```

Who closes what:

| Opened with | Closed by |
|-------------|-----------|
| `path=` | the reader — on `close()` or context-manager exit |
| `file_object=` | you, always.  The reader never closes an object you passed in |

`close()` is safe to call more than once, so an explicit call inside a `with`
block does no harm.

Three things are easy to get wrong without a `with` block:

- **Dropping a reader without closing it** leaks the handle.  CPython reclaims
  it when the object is collected and emits a `ResourceWarning`, which is an
  error under `python -W error::ResourceWarning`; other Python
  implementations may not close it promptly at all.
- **Running out of records does not close the file.**  `list(reader)` reads
  every record and still leaves the handle open.
- **An error part-way through does not close the file.**  A malformed record
  raises during iteration, at which point closing is on you.

Failures while *opening* are handled for you: a bad magic number or truncated
file header raises from `open_pcap` itself, which closes the file before the
exception propagates.  There is nothing to clean up, because you never
received a reader.

```python
reader = open_pcap(path="capture.pcap")   # no `with`
try:
    for record in reader:
        ...
finally:
    reader.close()                        # required
```

### Timestamp resolution

`ts_frac` is a count of *ticks*, and `header.tick_hz` says how many ticks make
a second.  Classic pcap is always microseconds or nanoseconds, selected by the
magic number, but a pcapng interface declares its own resolution via
`if_tsresol` — milliseconds and binary (`2**n`) resolutions are both legal and
do occur.  Use `tick_hz` for any arithmetic:

```python
seconds = ts_sec + ts_frac / pcap.header.tick_hz
```

`header.nanoseconds` remains as a convenience view (`tick_hz == 1_000_000_000`)
and drives the writers, which emit microseconds or nanoseconds only.  It is
`False` for a millisecond capture, so a program that branches on it alone
would read such a capture's fractions as microseconds — a factor of 1000 out.

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
| `LINKTYPE_LINUX_SLL` | `113` | Linux "cooked" v1 (`tcpdump -i any`) |
| `LINKTYPE_LINUX_SLL2` | `276` | Linux "cooked" v2 (modern `-i any`) |

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
